//! Tests for the `ExternalEnvSource::Ide` consumer that bridges
//! `locket run` to the agent's `IdeEnvSession` + `ResolveReference`
//! RPCs.
//!
//! These tests drive the consumer directly via the test seams exposed
//! on `commands::exec::run` rather than through the full `locket run`
//! pipeline; the env var `LOCKET_IDE_ENV_SESSION` is read from
//! `parent_env` first and from `std::env::var` only as a fallback, so
//! injecting a session id into the test path does not require mutating
//! the live process environment.
#![cfg(unix)]
#[allow(unused_imports)]
use super::*;

/// Spawns an in-process agent against the CLI test context's socket
/// path and exposes the IDE env-session registry so tests can pre-seed
/// entries without going through the (unlock-gated)
/// `RegisterIdeEnvSession` RPC.
struct IdeTestAgent {
    shutdown: Arc<tokio::sync::Notify>,
    handle: std::thread::JoinHandle<Result<(), String>>,
    ide_registry: locket_agent::IdeEnvSessionRegistry,
}

impl IdeTestAgent {
    fn start(context: &RuntimeContext) -> Result<Self, Box<dyn std::error::Error>> {
        let socket_path = crate::agent_socket_path(context);
        let config = locket_agent::AgentSocketConfig::new(socket_path, "test-agent".to_owned());
        let passphrase_store = Arc::new(context.passphrase_store.clone());
        let state = locket_agent::AgentSocketState::with_stores(
            "test-agent",
            locket_agent::current_process_uid(),
            context.key_store.clone(),
            passphrase_store,
        );
        let ide_registry = state.ide_env_sessions.clone();
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let shutdown_signal = shutdown.clone();
        let (ready_sender, ready_receiver) =
            std::sync::mpsc::channel::<Result<(), locket_agent::SocketServerError>>();
        let handle = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            runtime.block_on(async move {
                let listener = match locket_agent::bind_socket_listener(&config) {
                    Ok(listener) => {
                        let _ignored = ready_sender.send(Ok(()));
                        listener
                    }
                    Err(error) => {
                        let _ignored = ready_sender.send(Err(error));
                        return Ok(());
                    }
                };
                loop {
                    tokio::select! {
                        () = shutdown_signal.notified() => return Ok(()),
                        accepted = listener.accept() => {
                            let (stream, _addr) = accepted.map_err(|error| error.to_string())?;
                            let connection_state = state.clone();
                            tokio::spawn(async move {
                                let _outcome = locket_agent::handle_connection(
                                    stream,
                                    connection_state,
                                ).await;
                            });
                        }
                    }
                }
            })
        });
        ready_receiver.recv()??;
        Ok(Self { shutdown, handle, ide_registry })
    }

    fn insert_entry(
        &self,
        session_id: &str,
        entry: locket_agent::IdeEnvSessionEntry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = self.ide_registry.clone();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async move {
            let mut guard = registry.lock().await;
            guard.insert(session_id.to_owned(), entry);
        });
        Ok(())
    }

    fn seed_ide_session(
        &self,
        session_id: &str,
        project_id: &str,
        env_names: Vec<String>,
        ttl_seconds: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i128::try_from(d.as_nanos()).unwrap_or(0));
        let entry = locket_agent::IdeEnvSessionEntry {
            project_id: project_id.to_owned(),
            env_names,
            expires_at_unix_nanos: now_nanos
                .saturating_add(i128::from(ttl_seconds).saturating_mul(1_000_000_000)),
        };
        self.insert_entry(session_id, entry)
    }

    fn seed_expired_ide_session(
        &self,
        session_id: &str,
        project_id: &str,
        env_names: Vec<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entry = locket_agent::IdeEnvSessionEntry {
            project_id: project_id.to_owned(),
            env_names,
            expires_at_unix_nanos: 1,
        };
        self.insert_entry(session_id, entry)
    }

    fn stop(self) -> Result<(), Box<dyn std::error::Error>> {
        self.shutdown.notify_waiters();
        self.handle.join().map_err(|_| "agent thread panicked")??;
        Ok(())
    }
}

fn tighten_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[test]
fn agent_run_delivers_path_scoped_secret_from_cached_passphrase_unlock()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = fixture(&directory)?;
    let project = crate::require_project(&context)?;
    let path = directory.path().join("locket.toml");
    let source = std::fs::read_to_string(&path)?;
    let source = source
        .replace(
            "external_env_sources = [\"ide\"]",
            "external_env_sources = [\"ide\"]\nrequire_agent = true",
        )
        .replace("required_secrets = [\"DATABASE_URL\"]", "");
    std::fs::write(
        &path,
        format!(
            "{source}\n[paths.'apps/api']\nrequired_secrets=['DATABASE_URL']\n[secrets.DATABASE_URL]\nallow_commands=['ide_run']\nallow_paths=['apps/api/**']\n"
        ),
    )?;
    crate::commands::policy::refresh_command_policy_for_run(&context, &project, "ide_run")?;
    let master = context.key_store.load_master_key(project.config.project_id.as_str())?;
    context.passphrase_store.store_master_key(
        project.config.project_id.as_str(),
        &master,
        b"test passphrase",
        100,
    )?;
    context.key_store.delete_master_key(project.config.project_id.as_str())?;
    let api = directory.path().join("apps/api");
    std::fs::create_dir_all(&api)?;
    let context = RuntimeContext { cwd: api, ..context };
    let agent = IdeTestAgent::start(&context)?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let _: serde_json::Value = crate::commands::exec::run::agent_invoke(
            &context,
            locket_agent::AgentMethod::Unlock,
            &serde_json::json!({"project_id":project.config.project_id,"passphrase":"test passphrase","ttl_seconds":30,"method":"Passphrase"}),
            "test passphrase unlock",
        )?;
        let effective = crate::load_effective_command_policy(&project, "ide_run", &context.cwd)?;
        assert!(
            effective.policy.allowed_secrets.iter().any(|name| name.as_str() == "DATABASE_URL")
        );
        let store = crate::open_store(&context)?;
        let profile = crate::default_profile(&store, &project.config)?;
        let access = crate::prepare_agent_policy_access_for_tests(
            &context,
            &project,
            &profile,
            &effective.policy,
        )?;
        let session_id = "path-passphrase";
        agent.seed_ide_session(
            session_id,
            project.config.project_id.as_str(),
            vec!["DATABASE_URL".into()],
            30,
        )?;
        let ide_context = crate::ide_env_source_context_for_tests(
            &context,
            &project,
            &profile,
            &effective.policy,
            &access,
        );
        let env = crate::resolve_external_env_ide_with_session_id(&ide_context, session_id)?;
        assert_eq!(
            env.get("DATABASE_URL").map(|value| value.as_str()),
            Some("postgres://localhost/app")
        );
        Ok(())
    })();
    agent.stop()?;
    result
}

/// Builds the project + secret + policy fixture shared by every IDE
/// consumer test.
fn fixture(directory: &tempfile::TempDir) -> Result<RuntimeContext, Box<dyn std::error::Error>> {
    let context = test_context(directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "ide_run", "--", "/bin/sh", "-c", "true"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "require", "ide_run", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(b"external_env_sources = [\"ide\"]\n")?;
    tighten_directory(directory.path())?;
    Ok(context)
}

#[test]
fn ide_env_source_resolves_names_through_agent_round_trip() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = fixture(&directory)?;
    let agent = IdeTestAgent::start(&context)?;

    let resolved = crate::require_project(&context)?;
    let policy = crate::load_command_policy(&resolved, "ide_run")?;
    let mut store = crate::open_store(&context)?;
    crate::ensure_trusted_project_root(&store, &resolved)?;
    let profile = crate::default_profile(&store, &resolved.config)?;
    let _ = &mut store;

    let project_id = resolved.config.project_id.to_string();
    let session_id = "lk-ide-session-test-roundtrip";
    agent.seed_ide_session(session_id, &project_id, vec!["DATABASE_URL".to_owned()], 60)?;

    let agent_access =
        crate::prepare_agent_policy_access_for_tests(&context, &resolved, &profile, &policy)?;
    let ide_ctx = crate::ide_env_source_context_for_tests(
        &context,
        &resolved,
        &profile,
        &policy,
        &agent_access,
    );
    let env = crate::resolve_external_env_ide_with_session_id(&ide_ctx, session_id)?;

    agent.stop()?;

    assert_eq!(env.get("DATABASE_URL").map(|v| v.as_str()), Some("postgres://localhost/app"));
    assert_eq!(env.len(), 1);
    Ok(())
}

#[test]
fn ide_env_source_expired_session_returns_typed_error() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = fixture(&directory)?;
    let agent = IdeTestAgent::start(&context)?;

    let resolved = crate::require_project(&context)?;
    let policy = crate::load_command_policy(&resolved, "ide_run")?;
    let store = crate::open_store(&context)?;
    crate::ensure_trusted_project_root(&store, &resolved)?;
    let profile = crate::default_profile(&store, &resolved.config)?;

    let project_id = resolved.config.project_id.to_string();
    let session_id = "lk-ide-session-test-expired";
    agent.seed_expired_ide_session(session_id, &project_id, vec!["DATABASE_URL".to_owned()])?;

    let agent_access =
        crate::prepare_agent_policy_access_for_tests(&context, &resolved, &profile, &policy)?;
    let ide_ctx = crate::ide_env_source_context_for_tests(
        &context,
        &resolved,
        &profile,
        &policy,
        &agent_access,
    );
    let result = crate::resolve_external_env_ide_with_session_id(&ide_ctx, session_id);

    agent.stop()?;

    let Err(error) = result else {
        return Err("expired ide session must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::IdeEnvSessionUnavailable.exit_code());
    assert!(error.to_string().contains("IdeEnvSessionUnavailable"));
    assert!(error.to_string().contains("expired"));
    Ok(())
}

#[test]
fn ide_env_source_missing_session_id_returns_typed_error() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = fixture(&directory)?;
    let agent = IdeTestAgent::start(&context)?;

    let resolved = crate::require_project(&context)?;
    let policy = crate::load_command_policy(&resolved, "ide_run")?;
    let store = crate::open_store(&context)?;
    crate::ensure_trusted_project_root(&store, &resolved)?;
    let profile = crate::default_profile(&store, &resolved.config)?;

    let agent_access =
        crate::prepare_agent_policy_access_for_tests(&context, &resolved, &profile, &policy)?;
    let ide_ctx = crate::ide_env_source_context_for_tests(
        &context,
        &resolved,
        &profile,
        &policy,
        &agent_access,
    );
    let result = crate::resolve_external_env_ide_with_session_id(&ide_ctx, "");

    agent.stop()?;

    let Err(error) = result else {
        return Err("missing session id must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::IdeEnvSessionUnavailable.exit_code());
    assert!(error.to_string().contains("LOCKET_IDE_ENV_SESSION not set"));
    Ok(())
}

#[test]
fn ide_env_source_missing_agent_returns_typed_error() -> Result<(), Box<dyn std::error::Error>> {
    // No IdeTestAgent is started: the consumer cannot connect to the
    // local socket and must fail with a typed AgentUnavailable error.
    let directory = tempdir()?;
    let context = fixture(&directory)?;
    tighten_directory(directory.path())?;

    // Skip prepare_agent_policy_access (which would itself fail trying
    // to unlock); construct a minimal AgentPolicyAccess so the IDE
    // consumer reaches the IdeEnvSession RPC and surfaces the socket
    // error directly.
    let resolved = crate::require_project(&context)?;
    let policy = crate::load_command_policy(&resolved, "ide_run")?;
    let store = crate::open_store(&context)?;
    crate::ensure_trusted_project_root(&store, &resolved)?;
    let profile = crate::default_profile(&store, &resolved.config)?;

    // prepare_agent_policy_access needs a live agent, so we expect this
    // helper itself to fail with AgentUnavailable when no agent socket
    // is bound.
    let result =
        crate::prepare_agent_policy_access_for_tests(&context, &resolved, &profile, &policy);
    let Err(error) = result else {
        return Err("missing agent must fail before reaching IdeEnvSession".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::AgentUnavailable.exit_code());
    assert!(error.to_string().contains("AgentUnavailable"));
    Ok(())
}
