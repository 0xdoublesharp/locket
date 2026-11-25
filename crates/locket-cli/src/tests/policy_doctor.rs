//! Tests for `locket policy doctor` agent-driven validation.
#![cfg(unix)]
#[allow(unused_imports)]
use super::*;

/// Spawns an in-process agent against the CLI test context's socket
/// path so the doctor can issue real `PrepareExec` / `ResolveReference`
/// calls during the test.
struct DoctorTestAgent {
    shutdown: Arc<tokio::sync::Notify>,
    handle: std::thread::JoinHandle<Result<(), String>>,
    command_policies: Arc<tokio::sync::Mutex<Vec<locket_agent::CommandPolicySnapshot>>>,
}

impl DoctorTestAgent {
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
        let command_policies = state.command_policies.clone();
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
        Ok(Self { shutdown, handle, command_policies })
    }

    fn seed_policies(
        &self,
        snapshots: Vec<locket_agent::CommandPolicySnapshot>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let registry = self.command_policies.clone();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async move {
            let mut guard = registry.lock().await;
            *guard = snapshots;
        });
        Ok(())
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

/// Drives the agent through an Unlock so `PrepareExec` / `ResolveReference`
/// can pass the unlock-cache gate. Mirrors the unlock invocation
/// `locket run` issues internally.
fn unlock_via_agent(context: &RuntimeContext) -> Result<(), Box<dyn std::error::Error>> {
    let resolved = crate::require_project(context)?;
    let payload = serde_json::json!({
        "project_id": resolved.config.project_id.as_str(),
        "passphrase": serde_json::Value::Null,
        "ttl_seconds": 60_u64,
        "method": locket_agent::UnlockMethod::OsKeychain,
    });
    let _: serde_json::Value = crate::commands::exec::run::agent_invoke(
        context,
        locket_agent::AgentMethod::Unlock,
        &payload,
        "unlock for doctor test",
    )?;
    Ok(())
}

/// Prime the agent's metadata-only policy registry with snapshots
/// derived from the project's `locket.toml`. Production callers do
/// this through audit-driven paths; the test path mutates the
/// agent-shared registry directly via a handle returned by
/// `IdeTestAgent`.
fn seed_command_policies(
    agent: &DoctorTestAgent,
    context: &RuntimeContext,
) -> Result<(), Box<dyn std::error::Error>> {
    use locket_core::PolicyDocument;
    let resolved = crate::require_project(context)?;
    let policy_text = std::fs::read_to_string(resolved.root.join("locket.toml"))?;
    let document = PolicyDocument::from_toml_str(&policy_text)?;
    let project_id = resolved.config.project_id.to_string();
    let snapshots: Vec<locket_agent::CommandPolicySnapshot> = document
        .commands
        .values()
        .map(|policy| {
            locket_agent::CommandPolicySnapshot::from_policy(project_id.clone(), policy, 0)
        })
        .collect();
    agent.seed_policies(snapshots)?;
    Ok(())
}

#[test]
fn policy_doctor_happy_path_two_policies_pass() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    let api_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &api_args, "sk-test-value", "manual", 2_000)?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "policy",
            "add",
            "deploy",
            "--",
            "echo",
            "lk://dev/DATABASE_URL",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "require", "deploy", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "ship", "--", "echo", "lk://dev/API_KEY"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "require", "ship", "API_KEY"])?,
        &context,
        &mut Vec::new(),
    )?;

    tighten_directory(directory.path())?;
    let agent = DoctorTestAgent::start(&context)?;
    unlock_via_agent(&context)?;
    seed_command_policies(&agent, &context)?;

    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "policy", "doctor"])?,
        &context,
        &mut output,
    );
    agent.stop()?;
    let output_text = String::from_utf8(output)?;
    if let Err(error) = &result {
        return Err(format!(
            "doctor must pass when policies + secrets are seeded: {error}; output={output_text}"
        )
        .into());
    }
    assert!(output_text.contains("policy_doctor: ok"), "{output_text}");
    assert!(output_text.contains("policy: deploy"), "missing per-policy report: {output_text}");
    assert!(output_text.contains("policy: ship"), "missing per-policy report: {output_text}");
    assert!(output_text.contains("references_failed: none"), "{output_text}");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let doctor_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DOCTOR' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&doctor_metadata)?;
    assert_eq!(metadata["action"], "DOCTOR");
    let names: Vec<String> = metadata["check_names"]
        .as_array()
        .ok_or("check_names must be array")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_owned())
        .collect();
    assert!(names.iter().any(|name| name == "policy.deploy"), "names: {names:?}");
    assert!(names.iter().any(|name| name == "policy.ship"), "names: {names:?}");
    Ok(())
}

#[test]
fn policy_doctor_failed_reference_marks_policy_failed_and_exits_nonzero()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    // Reference a secret that has never been set; ResolveReference
    // must surface a typed error and the doctor must report it under
    // `references_failed`.
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "policy",
            "add",
            "deploy",
            "--",
            "echo",
            "lk://dev/UNSET_SECRET",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "require", "deploy", "UNSET_SECRET"])?,
        &context,
        &mut Vec::new(),
    )?;

    tighten_directory(directory.path())?;
    let agent = DoctorTestAgent::start(&context)?;
    unlock_via_agent(&context)?;
    seed_command_policies(&agent, &context)?;

    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "policy", "doctor"])?,
        &context,
        &mut output,
    );
    agent.stop()?;
    let output_text = String::from_utf8(output)?;
    let Err(error) = result else {
        return Err(
            format!("doctor with unresolvable reference must fail; output={output_text}").into()
        );
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::PolicyValidationIncomplete.exit_code());
    assert!(output_text.contains("policy_doctor: incomplete"), "{output_text}");
    assert!(
        output_text.contains("references_failed: lk://dev/UNSET_SECRET"),
        "expected the failed reference to be surfaced: {output_text}"
    );
    Ok(())
}

#[test]
fn policy_doctor_locked_vault_returns_unlock_required() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "policy",
            "add",
            "deploy",
            "--",
            "echo",
            "lk://dev/DATABASE_URL",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    tighten_directory(directory.path())?;
    let agent = DoctorTestAgent::start(&context)?;
    seed_command_policies(&agent, &context)?;
    // Intentionally skip `unlock_via_agent`: the agent is up but the
    // unlock cache is empty, so PrepareExec returns UnlockRequired.

    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "policy", "doctor"])?,
        &context,
        &mut output,
    );
    agent.stop()?;

    let Err(error) = result else {
        return Err("locked vault must surface an UnlockRequired error".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UnlockRequired.exit_code());
    let output_text = String::from_utf8(output)?;
    assert!(
        output_text.contains("status: skipped (UnlockRequired)")
            || output_text.contains("UnlockRequired"),
        "expected unlock-required marker, got: {output_text}"
    );
    Ok(())
}

#[test]
fn policy_doctor_no_agent_falls_back_to_legacy_ok_without_lk_references()
-> Result<(), Box<dyn std::error::Error>> {
    // No agent is started. A policy with no lk:// references must
    // still pass — the doctor degrades to its legacy scanner-only
    // checks rather than failing closed.
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "noop", "--", "/usr/bin/true"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "policy", "doctor"])?, &context, &mut output)?;
    let output_text = String::from_utf8(output)?;
    assert!(output_text.contains("policy_doctor: ok"), "{output_text}");
    Ok(())
}

#[test]
fn policy_doctor_no_agent_with_lk_references_returns_agent_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.uses_reference]
argv = ["echo", "lk://dev/DATABASE_URL"]
override = "preserve"
"#,
        )?;
    approve_test_policy(&context, "uses_reference")?;

    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "policy", "doctor"])?,
        &context,
        &mut output,
    );
    let Err(error) = result else {
        return Err("doctor must fail with AgentUnavailable when lk:// is present".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::AgentUnavailable.exit_code());
    let output_text = String::from_utf8(output)?;
    assert!(output_text.contains("policy_doctor: incomplete"), "{output_text}");
    assert!(
        output_text.contains("warning: lk:// validation skipped because agent is unavailable"),
        "{output_text}"
    );
    Ok(())
}
