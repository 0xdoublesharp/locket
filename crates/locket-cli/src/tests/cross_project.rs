use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

use clap::Parser;
use locket_core::LocketError;
use locket_crypto::{KeyBytes, KeyPurpose};
use locket_platform::{MasterKeyStore, MemoryLocalUserVerifier, PlatformError};
use locket_store::Store;
use serde_json::{Value, json};
use tempfile::tempdir;
use zeroize::Zeroizing;

use crate::{Cli, CliError, RuntimeContext, run_with_context};

use super::{
    context_with_confirmation, context_with_user_verifier, run_git, test_context_with_secret_value,
};

const CANARY: &str = "cross-project-fixture-value-673";

#[derive(Default)]
struct ProjectKeys(Mutex<BTreeMap<String, Zeroizing<KeyBytes>>>);

impl MasterKeyStore for ProjectKeys {
    fn store_master_key(&self, id: &str, key: &KeyBytes) -> Result<(), PlatformError> {
        self.0
            .lock()
            .map_err(|_| PlatformError::MemoryPoisoned)?
            .insert(id.to_owned(), Zeroizing::new(*key));
        Ok(())
    }

    fn load_master_key(&self, id: &str) -> Result<Zeroizing<KeyBytes>, PlatformError> {
        self.0
            .lock()
            .map_err(|_| PlatformError::MemoryPoisoned)?
            .get(id)
            .cloned()
            .ok_or(PlatformError::MasterKeyNotFound)
    }

    fn delete_master_key(&self, id: &str) -> Result<(), PlatformError> {
        self.0.lock().map_err(|_| PlatformError::MemoryPoisoned)?.remove(id);
        Ok(())
    }
}

fn run(context: &RuntimeContext, args: &[&str]) -> Result<(u8, String), Box<dyn Error>> {
    let mut output = Vec::new();
    let cli = Cli::try_parse_from(std::iter::once("locket").chain(args.iter().copied()))?;
    let code = run_with_context(cli, context, &mut output)?;
    Ok((code, String::from_utf8(output)?))
}

fn json_run(context: &RuntimeContext, args: &[&str]) -> Result<(u8, Value), Box<dyn Error>> {
    let (code, text) = run(context, args)?;
    assert!(!text.contains(CANARY));
    Ok((code, serde_json::from_str(&text)?))
}

fn init(context: &RuntimeContext, name: &str) -> Result<(), Box<dyn Error>> {
    run(context, &["init", "--name", name, "--profile", "dev", "--no-device", "--no-passkey"])?;
    Ok(())
}

#[test]
fn shared_commands_manage_global_secrets_from_outside_a_project() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    let (_, vault) = json_run(&context, &["shared", "init", "--json"])?;
    let (_, created) = json_run(
        &context,
        &["shared", "set", "GLOBAL_TOKEN", "--description", "Global API token", "--json"],
    )?;
    assert_eq!(created["project_id"], vault["project_id"]);
    assert_eq!(created["version"], 1);
    let store = crate::open_store(&context)?;
    let project_id = vault["project_id"].as_str().ok_or("missing shared project id")?;
    let profile = store.get_profile_by_name(project_id, "default")?.ok_or("missing profile")?;
    let (_, updated) =
        json_run(&context, &["shared", "set", "GLOBAL_TOKEN", "--upsert", "--json"])?;
    assert_eq!(updated["operation"], "rotate");
    assert_eq!(updated["version"], 2);
    assert_eq!(
        run(&context, &["shared", "get", "GLOBAL_TOKEN"])?,
        run(&context, &["get", "GLOBAL_TOKEN", "--project", "@shared"])?
    );
    let (_, revealed) = run(&context, &["shared", "get", "GLOBAL_TOKEN", "--reveal", "--force"])?;
    assert_eq!(revealed.trim_end(), CANARY);
    assert!(Cli::try_parse_from(["locket", "shared", "get", "GLOBAL_TOKEN", "--force"]).is_err());

    let dotenv = "GLOBAL_TOKEN=${literal}\nSKIP=ignore-this\n";
    fs::write(directory.path().join(".env"), dotenv)?;
    let import = [
        "shared",
        "import",
        ".env",
        "--overwrite",
        "--literal",
        "--only",
        "GLOBAL_TOKEN,SKIP",
        "--exclude",
        "SKIP",
        "--json",
    ];
    let mut preview_args = import.to_vec();
    preview_args.push("--dry-run");
    let (_, preview) = json_run(&context, &preview_args)?;
    assert_eq!(preview["dry_run"], true);
    assert_eq!(preview["overwritten_names"], json!(["GLOBAL_TOKEN"]));
    assert_eq!(preview["filtered_out_names"], json!(["SKIP"]));
    let (_, listed) = run(&context, &["shared", "list"])?;
    assert_eq!(listed, "GLOBAL_TOKEN source=user-local version=2 state=active\n");
    assert_eq!(listed, run(&context, &["list", "--project", "@shared"])?.1);
    let (_, imported) = json_run(&context, &import)?;
    assert_eq!(imported["project_id"], vault["project_id"]);
    assert_eq!(imported["overwritten"], 1);
    assert!(!imported.to_string().contains("${literal}"));
    assert_eq!(fs::read_to_string(directory.path().join(".env"))?, dotenv);

    let (_, rotated) = run(&context, &["shared", "rotate", "GLOBAL_TOKEN"])?;
    assert!(rotated.contains("version=4"), "{rotated}");
    assert!(store.set_profile_dangerous(project_id, "default", true)?);
    for args in [
        &["shared", "get", "GLOBAL_TOKEN", "--copy"][..],
        &["shared", "rotate", "GLOBAL_TOKEN"],
        &["shared", "rm", "GLOBAL_TOKEN"],
    ] {
        let error = run(&context, args).err().ok_or("dangerous operation must be denied")?;
        assert!(error.to_string().contains("dangerous"), "{error}");
    }
    assert!(store.set_profile_dangerous(project_id, "default", false)?);
    run(&context, &["shared", "rm", "GLOBAL_TOKEN"])?;
    assert_eq!(run(&context, &["shared", "list"])?.1, "no secrets\n");
    assert!(run(&context, &["shared", "list", "--all"])?.1.contains("state=deleted"));
    let rows = store.list_audit_rows_since(project_id, &profile.id, 0)?;
    let successful_writes = rows
        .iter()
        .filter(|row| row.status == "SUCCESS" && row.secret_name.as_deref() == Some("GLOBAL_TOKEN"))
        .filter_map(|row| match row.action.as_str() {
            action @ ("SET" | "ROTATE" | "DELETE") => Some(action),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(successful_writes, ["SET", "ROTATE", "ROTATE", "ROTATE", "DELETE"]);
    Ok(())
}

#[test]
fn set_duplicate_error_suggests_upsert_and_rotate() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    init(&context, "app")?;
    run(&context, &["set", "API_TOKEN"])?;
    let (code, result) = json_run(&context, &["set", "API_TOKEN", "--json"])?;
    assert_eq!(code, LocketError::SecretAlreadyExists.exit_code());
    let message = result["error"]["message"].as_str().ok_or("missing error message")?;
    assert!(message.contains("already exists"), "{message}");
    assert!(message.contains("locket set API_TOKEN --upsert"), "{message}");
    assert!(message.contains("locket rotate API_TOKEN"), "{message}");
    Ok(())
}

#[test]
fn policy_refresh_reviews_metadata_before_confirming_new_and_changed_approvals()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    init(&context, "app")?;
    run(&context, &["set", "API_TOKEN"])?;
    let path = directory.path().join("locket.toml");
    let mut source = fs::read_to_string(&path)?;
    source.push_str(
        r#"
[commands.serve]
argv = ["node", "server file.js", "lk://dev/API_TOKEN", "github_pat_sampleTokenValue123"]
required_secrets = ["API_TOKEN"]
optional_secrets = ["DEBUG_TOKEN"]
shared_secrets = ["GLOBAL_TOKEN"]
env_mode = "strict"
override = "error"
confirm = true
require_user_verification = true
require_agent = true

[paths."apps/web"]
required_secrets = ["WEB_TOKEN"]
"#,
    );
    fs::write(&path, &source)?;
    let confirmed = context_with_confirmation(&context, "serve\n");
    let (_, first) = run(&confirmed, &["policy", "refresh", "serve"])?;
    let prompt = first.find("type 'serve' to confirm policy refresh").ok_or("missing prompt")?;
    for line in [
        "status: new approval",
        r#"argv: ["node","server file.js","lk://dev/API_TOKEN","#,
        "required_secret_names: API_TOKEN",
        "optional_secret_names: DEBUG_TOKEN",
        "allowed_secret_names: API_TOKEN DEBUG_TOKEN",
        "shared_secret_names: GLOBAL_TOKEN",
        "env_mode: strict",
        "override: error",
        "path_scopes:",
        "apps/web",
        "WEB_TOKEN",
        "confirm: true",
        "require_user_verification: true",
        "require_agent: true",
        "metadata_only: yes",
    ] {
        assert!(first[..prompt].contains(line), "missing {line:?} in {first}");
    }
    assert!(!first.contains(CANARY));
    assert!(!first.contains("github_pat_sampleTokenValue123"));
    fs::write(&path, source.replace("server file.js", "other.js"))?;
    let cli = Cli::try_parse_from(["locket", "policy", "refresh", "serve"])?;
    let mut output = Vec::new();
    let error =
        run_with_context(cli, &context, &mut output).err().ok_or("wrong confirmation must fail")?;
    assert_eq!(error.exit_code(), LocketError::ConfirmationFailed.exit_code());
    let declined = String::from_utf8(output)?;
    assert!(declined.contains("status: changed since last approval"), "{declined}");
    assert!(declined.contains("other.js"));
    let (_, changed) = run(&confirmed, &["policy", "refresh", "serve"])?;
    assert!(changed.contains("status: changed since last approval"), "{changed}");
    Ok(())
}

#[test]
fn status_json_reports_project_metadata() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    init(&context, "app")?;
    run(&context, &["set", "PROJECT_TOKEN"])?;
    run(&context, &["set", "PROJECT_TOKEN", "--source", "machine-local"])?;
    run(&context, &["policy", "add", "test", "--", "npm", "test"])?;
    let (_, shared) = json_run(&context, &["shared", "init", "--json"])?;
    let project = crate::require_project(&context)?;

    let (code, status) = json_run(&context, &["status", "--json"])?;
    assert_eq!(code, 0);
    assert_eq!(
        status,
        json!({
            "has_locket_config": true,
            "project_id": project.config.project_id,
            "project_name": "app",
            "profile": "dev",
            "has_shared_vault": true,
            "shared_project_id": shared["project_id"],
            "agent_running": false,
            "vault_unlocked": null,
            "secret_count": 1,
            "policy_names": ["test"],
            "metadata_only": true,
        })
    );
    Ok(())
}

#[test]
fn status_json_works_outside_projects_with_or_without_shared_vault() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    let mut expected = json!({
        "has_locket_config": false,
        "project_id": null,
        "project_name": null,
        "profile": null,
        "has_shared_vault": false,
        "shared_project_id": null,
        "agent_running": false,
        "secret_count": 0,
        "policy_names": [],
        "metadata_only": true,
    });
    assert_eq!(json_run(&context, &["status", "--json"])?, (0, expected.clone()));
    assert!(!context.store_path.exists());

    let (_, shared) = json_run(&context, &["shared", "init", "--json"])?;
    run(&context, &["set", "GLOBAL_TOKEN", "--project", "@shared"])?;
    expected["has_shared_vault"] = json!(true);
    expected["shared_project_id"] = shared["project_id"].clone();
    assert_eq!(json_run(&context, &["status", "--json"])?, (0, expected));
    Ok(())
}

#[test]
fn exec_injects_shared_secret_from_outside_a_project() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = RuntimeContext {
        key_store: Arc::new(ProjectKeys::default()),
        ..test_context_with_secret_value(&directory, CANARY)
    };
    run(&context, &["shared", "init"])?;
    run(&context, &["set", "GLOBAL_TOKEN", "--project", "@shared"])?;
    assert!(!directory.path().join("locket.toml").exists());
    let (code, output) = run(
        &context,
        &[
            "exec",
            "--project",
            "@shared",
            "--profile",
            "default",
            "--secret",
            "GLOBAL_TOKEN",
            "--",
            super::test_shell(),
            "-c",
            &format!("test \"$GLOBAL_TOKEN\" = '{CANARY}'"),
        ],
    )?;
    assert_eq!(code, 0);
    assert!(!output.contains(CANARY));
    let store = crate::open_store(&context)?;
    let (project_id, metadata): (String, String) = store.connection().query_row(
        "SELECT project_id, metadata_json FROM audit_log WHERE action = 'EXEC'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert!(project_id.starts_with("lk_proj_shared_"));
    assert!(metadata.contains("GLOBAL_TOKEN"));
    assert!(!metadata.contains(CANARY));
    Ok(())
}

#[test]
fn explicit_exec_uses_the_selected_profile_and_enforces_project_acls_from_outside()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let outside = test_context_with_secret_value(&directory, CANARY);
    let root = outside.cwd.join("work");
    fs::create_dir(&root)?;
    let inside = RuntimeContext { cwd: root.clone(), ..outside.clone() };
    init(&inside, "PrivateApp")?;
    run(&inside, &["profile", "create", "ci"])?;
    run(&outside, &["set", "TOKEN", "--project", "PrivateApp", "--profile", "ci"])?;
    let command = format!("test \"$TOKEN\" = '{CANARY}' && test ! -e locket.toml");
    let args = [
        "exec",
        "--project",
        "PrivateApp",
        "--profile",
        "ci",
        "--secret",
        "TOKEN",
        "--",
        super::test_shell(),
        "-c",
        &command,
    ];
    assert_eq!(run(&outside, &args)?.0, 0);
    fs::OpenOptions::new()
        .append(true)
        .open(root.join("locket.toml"))?
        .write_all(b"\n[secrets.TOKEN]\nallow_paths=['**']\n")?;
    assert!(run(&outside, &args).is_err_and(|error| error.to_string().contains("ACL denied")));
    Ok(())
}

#[test]
fn run_and_inspect_resolve_required_shared_secrets_from_the_global_vault()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let outside = RuntimeContext {
        key_store: Arc::new(ProjectKeys::default()),
        ..test_context_with_secret_value(&directory, CANARY)
    };
    let root = outside.cwd.join("work");
    fs::create_dir(&root)?;
    let inside = RuntimeContext { cwd: root.clone(), ..outside.clone() };
    init(&inside, "PrivateApp")?;
    crate::set_secret_value(
        &inside,
        &super::test_secret_write_args("LOCAL_TOKEN"),
        "project-fixture",
        "manual",
        1000,
    )?;
    crate::set_secret_value(
        &inside,
        &super::test_secret_write_args("GLOBAL_TOKEN"),
        "wrong-vault",
        "manual",
        2000,
    )?;
    let file = root.join("locket.toml");
    let initial = fs::read_to_string(&file)?;
    let script =
        format!("test \"$GLOBAL_TOKEN\" = '{CANARY}' && test \"$LOCAL_TOKEN\" = 'project-fixture'");
    let argv = toml::Value::try_from(vec![super::test_shell(), "-c", &script])?;
    fs::write(
        &file,
        format!(
            "{initial}
[commands.check]
argv={argv}
required_secrets=['LOCAL_TOKEN']
shared_secrets=['GLOBAL_TOKEN']
[variables.GLOBAL_TOKEN]
classification='public'
default='wrong-fallback'
"
        ),
    )?;

    super::approve_test_policy(&inside, "check")?;
    let (_, missing) = run(&inside, &["env", "inspect", "--policy", "check"])?;
    assert!(missing.contains("configuration GLOBAL_TOKEN state=Missing source=none"));
    assert!(missing.contains("locket set GLOBAL_TOKEN --project @shared"));
    let error = run(&inside, &["run", "check"]).err().ok_or("expected missing shared secret")?;
    assert!(error.to_string().contains("missing from @shared: GLOBAL_TOKEN"));
    assert!(!error.to_string().contains("wrong-vault"));

    run(&outside, &["shared", "init"])?;
    run(&outside, &["set", "GLOBAL_TOKEN", "--project", "@shared"])?;
    let (_, readiness) = run(&inside, &["env", "inspect", "--policy", "check"])?;
    assert!(readiness.contains("configuration GLOBAL_TOKEN state=Ready source=@shared"));
    assert!(!readiness.contains(CANARY));
    assert!(!readiness.contains("wrong-vault"));
    assert_eq!(run(&inside, &["run", "check"])?.0, 0);

    #[cfg(unix)]
    assert_locked_shared_execution_is_refused(&inside)?;

    let store = crate::open_store(&inside)?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY' AND status = 'SUCCESS'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains(r#""selected_source":"@shared""#));
    assert!(!metadata.contains(CANARY));

    fs::OpenOptions::new()
        .append(true)
        .open(file)?
        .write_all(b"\n[secrets.GLOBAL_TOKEN]\nallow_commands=['other']\n")?;
    super::approve_test_policy(&inside, "check")?;
    for args in [&["env", "inspect", "--policy", "check"][..], &["run", "check"][..]] {
        assert!(run(&inside, args).is_err_and(|error| error.to_string().contains("ACL denied")));
    }
    Ok(())
}

#[cfg(unix)]
fn assert_locked_shared_execution_is_refused(
    context: &RuntimeContext,
) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    let directory = tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let context =
        RuntimeContext { agent_data_dir: Some(directory.path().into()), ..context.clone() };
    let project_id = crate::require_project(&context)?.config.project_id.into_string();
    let document = crate::read_policy_document(&context.cwd.join("locket.toml"))?;
    let policy = document
        .effective_command("check", &context.cwd, &context.cwd)
        .ok_or("missing check policy")?;
    let policy = locket_agent::CommandPolicySnapshot::from_policy(&project_id, &policy, 0);
    let now = i128::from(crate::now_unix_nanos()?);
    let listener = UnixListener::bind(crate::agent_socket_path(&context))?;
    listener.set_nonblocking(true)?;
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            let listener = tokio::net::UnixListener::from_std(listener)?;
            let state = locket_agent::AgentSocketState::locked("test");
            state.command_policies.lock().await.push(policy);
            state.unlock_cache.lock().await.insert(
                project_id,
                locket_agent::UnlockEntry::new(
                    vec![7; 32],
                    now,
                    std::time::Duration::from_secs(60),
                    locket_agent::UnlockMethod::OsKeychain,
                ),
            );
            for _ in 0..2 {
                let (stream, _) =
                    tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept())
                        .await??;
                let _ = locket_agent::handle_connection(stream, state.clone()).await;
            }
            Ok(())
        })
    });

    let policy = run(&context, &["run", "check"]);
    let exec = run(
        &context,
        &[
            "exec",
            "--project",
            "@shared",
            "--secret",
            "GLOBAL_TOKEN",
            "--",
            super::test_shell(),
            "-c",
            "exit 0",
        ],
    );
    let fixture_status = server.join().map_err(|_| "status fixture panicked")?;
    for result in [policy, exec] {
        let error = result.err().ok_or("a locked Global Vault must reject execution")?;
        assert!(
            matches!(
                error.downcast_ref::<CliError>(),
                Some(CliError::Typed { kind: LocketError::UnlockRequired, .. })
            ),
            "unexpected refusal: {error}"
        );
    }
    fixture_status?;
    Ok(())
}

#[test]
fn mcp_value_file_requires_trusted_project_root() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let outside = tempdir()?;
    let context = test_context_with_secret_value(&directory, "test-value");
    init(&context, "app")?;
    let outside_file = outside.path().join("input");
    let inside_file = directory.path().join("input");
    fs::write(&outside_file, "outside fixture")?;
    fs::write(&inside_file, "inside fixture")?;

    let outside_reply = mcp_exchange(
        &context,
        &[rpc(
            1,
            "locket_store_secret",
            &json!({
                "project":"app", "name":"OUTSIDE", "value_file":outside_file,
            }),
        )],
    )?;
    assert_eq!(serde_json::from_str::<Value>(outside_reply.trim())?["result"]["isError"], true);

    #[cfg(unix)]
    {
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&outside_file, &link)?;
        let reply = mcp_exchange(
            &context,
            &[rpc(
                2,
                "locket_store_secret",
                &json!({
                    "project":"app", "name":"LINK", "value_file":link,
                }),
            )],
        )?;
        assert_eq!(serde_json::from_str::<Value>(reply.trim())?["result"]["isError"], true);
    }

    let inside_reply = mcp_exchange(
        &context,
        &[rpc(
            3,
            "locket_store_secret",
            &json!({
                "project":"app", "name":"INSIDE", "value_file":inside_file,
            }),
        )],
    )?;
    assert_eq!(serde_json::from_str::<Value>(inside_reply.trim())?["result"]["isError"], false);
    Ok(())
}

#[test]
fn configured_reveal_and_copy_require_verification_without_flags() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    init(&context, "app")?;
    run(&context, &["set", "TOKEN"])?;
    let context =
        context_with_user_verifier(&context, Arc::new(MemoryLocalUserVerifier::denying()));
    for (action, args) in [
        ("reveal", &["get", "TOKEN", "--reveal", "--force"][..]),
        ("copy", &["get", "TOKEN", "--copy"][..]),
    ] {
        run(
            &context,
            &["config", "set", &format!("user_verification_required_for.{action}"), "true"],
        )?;
        let mut output = Vec::new();
        let cli = Cli::try_parse_from(std::iter::once("locket").chain(args.iter().copied()))?;
        let result = run_with_context(cli, &context, &mut output);
        assert!(matches!(
            result,
            Err(CliError::Typed { kind: LocketError::UserVerificationFailed, .. })
        ));
        assert_eq!(output, [] as [u8; 0]);
    }
    Ok(())
}

#[test]
fn set_and_partial_rotate_persist_metadata_and_reject_secret_like_fields()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    init(&context, "app")?;
    run(
        &context,
        &[
            "set",
            "TOKEN",
            "--description",
            "First description",
            "--owner",
            "Platform",
            "--tag",
            "ops",
            "--required",
        ],
    )?;
    run(&context, &["rotate", "TOKEN", "--description", "Updated description"])?;
    let (_, rows) = json_run(&context, &["discover", "--name", "TOKEN", "--json"])?;
    assert_eq!(rows[0]["description"], "Updated description");
    assert_eq!(rows[0]["owner"], "Platform");
    assert_eq!(rows[0]["tags"], json!(["ops"]));
    assert_eq!(rows[0]["required"], true);
    assert_eq!(rows[0]["version"], 2);
    for option in ["--description", "--owner", "--tag"] {
        let token = "sk_test_fixtureSensitiveExample123";
        for args in [vec!["set", "REJECTED", option, token], vec!["rotate", "TOKEN", option, token]]
        {
            let error = run(&context, &args).err().ok_or("accepted secret-like metadata")?;
            assert!(!error.to_string().contains(token));
            assert!(
                error.downcast_ref::<CliError>().is_some_and(
                    |e| e.exit_code() == LocketError::MetadataLooksLikeSecret.exit_code()
                )
            );
        }
    }
    let (_, rows) = json_run(&context, &["discover", "--json"])?;
    assert_eq!(rows.as_array().ok_or("expected rows")?.len(), 1);
    assert_eq!(rows[0]["version"], 2);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)] // Exercise these commands against the same detached store.
fn outside_workspace_shared_discovery_storage_generation_and_parity() -> Result<(), Box<dyn Error>>
{
    let directory = tempdir()?;
    let outside = RuntimeContext {
        key_store: Arc::new(ProjectKeys::default()),
        ..test_context_with_secret_value(&directory, CANARY)
    };
    let root = directory.path().join("work");
    fs::create_dir(&root)?;
    let inside = RuntimeContext { cwd: root.clone(), ..outside.clone() };
    init(&inside, "PrivateApp")?;
    run(&inside, &["profile", "create", "prod"])?;
    run(&context_with_confirmation(&inside, "prod\n"), &["profile", "mark-dangerous", "prod"])?;

    let (_, shared) = json_run(&outside, &["shared", "init", "--json"])?;
    let (_, again) = json_run(&outside, &["shared", "init", "--json"])?;
    assert_eq!(shared["created"], true);
    assert_eq!(again["created"], false);
    assert_eq!(shared["project_id"], again["project_id"]);
    assert!(!outside.cwd.join("locket.toml").exists());

    let (_, projects) = json_run(&outside, &["project", "list", "--json"])?;
    assert_eq!(projects[0]["name"], "@shared");
    assert_eq!(projects[1]["name"], "PrivateApp");
    assert_eq!(projects[1]["profiles"][1]["dangerous"], true);
    let reported_root = projects[1]["trusted_roots"][0].as_str().ok_or("missing trusted root")?;
    assert_eq!(std::path::Path::new(reported_root).canonicalize()?, root.canonicalize()?);

    let args = ["set", "PRIVATE_TOKEN", "--project", "work", "--profile", "prod", "--json"];
    let (code, denied) = json_run(&outside, &args)?;
    assert_eq!(code, LocketError::DangerousProfileConfirmationRequired.exit_code());
    assert!(denied.get("error").is_some());
    let mut allowed = args.to_vec();
    allowed.extend(["--use-dangerous", "--description", "Production token"]);
    let (code, created) = json_run(&outside, &allowed)?;
    assert_eq!(code, 0, "{created}");
    assert_eq!(created["version"], 1);
    allowed.extend(["--upsert", "--owner", "Platform", "--tag", "service"]);
    let (_, updated) = json_run(&outside, &allowed)?;
    assert_eq!(updated["operation"], "rotate");
    assert_eq!(updated["version"], 2);
    assert_eq!(updated["reference"], "lk://prod/PRIVATE_TOKEN");

    let (_, generated) = json_run(
        &outside,
        &[
            "generate",
            "SHARED_TOKEN",
            "--project",
            "@shared",
            "--format",
            "hex",
            "--bytes",
            "24",
            "--json",
        ],
    )?;
    let id = shared["project_id"].as_str().ok_or("missing shared id")?;
    let store = Store::open_read_only(&outside.store_path)?;
    let profile = store.get_profile_by_name(id, "default")?.ok_or("missing profile")?;
    let secret = store
        .get_active_secret(id, &profile.id, "SHARED_TOKEN", "user-local")?
        .ok_or("missing generated secret")?;
    let value = crate::support::secret_helpers::decrypt_secret_version(
        &outside,
        &store,
        id,
        &profile.id,
        &secret,
        1,
    )?;
    let (_, revealed) =
        run(&inside, &["get", "SHARED_TOKEN", "--project", "@shared", "--reveal", "--force"])?;
    assert_eq!(revealed.trim_end(), value.as_str());
    assert_eq!(value.len(), 48);
    assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(!generated.to_string().contains(value.as_str()));
    assert_eq!(secret.origin, "manual");
    assert_eq!(generated["origin_detail"], "generated");
    let (_, regenerated) = json_run(
        &outside,
        &["generate", "SHARED_TOKEN", "--project", "@shared", "--upsert", "--json"],
    )?;
    assert_eq!(regenerated["operation"], "rotate");
    assert_eq!(regenerated["origin_detail"], "generated");
    let generated_audits: i64 = store.connection().query_row(
        "SELECT count(*) FROM audit_log WHERE project_id = ?1 AND command = 'generate'
         AND action IN ('SET', 'ROTATE') AND json_extract(metadata_json, '$.command') = 'generate'",
        [id],
        |row| row.get(0),
    )?;
    assert_eq!(generated_audits, 2);
    let audit = crate::load_project_key(&outside, &store, id, KeyPurpose::Audit)?;
    assert!(store.verify_audit_chain_read_only(id, audit.as_ref())?.hmac_ok);

    let (_, rows) = json_run(
        &outside,
        &[
            "discover",
            "token",
            "--name",
            "PRIVATE_*",
            "--tag",
            "service",
            "--owner",
            "plat",
            "--source",
            "user-local",
            "--profile",
            "prod",
            "--limit",
            "1",
            "--json",
        ],
    )?;
    assert_eq!(rows.as_array().ok_or("expected rows")?.len(), 1);
    assert_eq!(rows[0]["description"], "Production token");
    assert_eq!(rows[0]["reference"], "lk://prod/PRIVATE_TOKEN");
    let (_, rows) = json_run(&outside, &["discover", "--project", "@shared", "--json"])?;
    assert_eq!(rows[0]["reference"], "lk://default/SHARED_TOKEN");
    let (_, rows) = json_run(&outside, &["discover", "--redact-names", "--json"])?;
    for hidden in ["PRIVATE_TOKEN", "SHARED_TOKEN", "PrivateApp", "@shared", "Production token"] {
        assert!(!rows.to_string().contains(hidden));
    }
    let (_, projects) = json_run(&outside, &["project", "list", "--redact-names", "--json"])?;
    assert!(!projects.to_string().contains("PrivateApp"));
    assert!(!projects.to_string().contains(root.to_string_lossy().as_ref()));
    assert_eq!(
        json_run(&outside, &["discover", "--project", "missing", "--json"])?.0,
        LocketError::ProjectNotFound.exit_code()
    );

    fs::write(root.join(".env.local"), format!("PRIVATE_TOKEN={CANARY}\nOTHER_NAME=another\n"))?;
    fs::write(root.join(".env.example"), "PRIVATE_TOKEN=placeholder\n")?;
    let (_, parity) = json_run(
        &outside,
        &[
            "parity",
            "--project",
            "PrivateApp",
            "--check-plaintext",
            "--max-age-days",
            "0",
            "--json",
        ],
    )?;
    assert_eq!(parity["profiles"][0]["missing"], json!(["PRIVATE_TOKEN"]));
    assert_eq!(parity["profiles"][1]["stale"], json!(["PRIVATE_TOKEN"]));
    assert_eq!(parity["plaintext_drift"], json!([{"file": ".env.local", "overlap_count": 1}]));
    Ok(())
}

#[test]
fn git_scan_hooks_default_to_pre_commit_and_preserve_unmanaged_hooks() -> Result<(), Box<dyn Error>>
{
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    run_git(directory.path(), &["init"])?;
    let hooks = directory.path().join(".git/hooks");
    let commit = hooks.join("pre-commit");
    let push = hooks.join("pre-push");
    assert!(run(&context, &["hook", "status"])?.1.contains("pre-commit: missing"));
    fs::write(&commit, "#!/bin/sh\necho custom\n")?;
    assert!(run(&context, &["hook", "install", "--pre-commit", "--pre-push"]).is_err());
    assert_eq!(fs::read_to_string(&commit)?, "#!/bin/sh\necho custom\n");
    assert!(!push.exists());
    run(&context, &["hook", "install", "--force"])?;
    assert!(fs::read_to_string(&commit)?.contains("locket scan --staged"));
    assert!(!push.exists());
    run(&context, &["hook", "install", "--pre-push"])?;
    assert!(fs::read_to_string(&push)?.contains("locket hook scan-push"));
    let (_, status) = run(&context, &["hook", "status"])?;
    assert!(status.contains("pre-commit: installed"));
    assert!(status.contains("pre-push: installed"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&commit)?.permissions().mode() & 0o777, 0o700);
    }
    Ok(())
}

#[test]
fn scan_hooks_block_index_and_pushed_commit_without_displaying_known_value()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "fixture-671");
    run_git(directory.path(), &["init"])?;
    init(&context, "app")?;
    run(&context, &["set", "TOKEN"])?;
    fs::write(directory.path().join("leak.txt"), "value=fixture-671\n")?;
    run_git(directory.path(), &["add", "leak.txt"])?;

    let mut output = Vec::new();
    let cli = Cli::try_parse_from(["locket", "scan", "--staged", "--known-if-unlocked"])?;
    let result = run_with_context(cli, &context, &mut output);
    assert!(matches!(result, Err(CliError::Typed { kind: LocketError::ScanFindingBlocked, .. })));
    let output = String::from_utf8(output)?;
    assert!(output.contains("known-secret"));
    assert!(!output.contains("fixture-671"));

    run_git(
        directory.path(),
        &[
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Locket Test",
            "-c",
            "user.email=locket@example.invalid",
            "commit",
            "-m",
            "test fixture",
        ],
    )?;
    let oid = crate::commands::scan::scanner::git_output(directory.path(), ["rev-parse", "HEAD"])?;
    let oid = std::str::from_utf8(&oid)?.trim_end();
    let mut input =
        Cursor::new(format!("refs/heads/test {oid} refs/heads/test {}\n", "0".repeat(oid.len())));
    let mut output = Vec::new();
    let result = crate::commands::scan::scanner::scan_push(
        &context,
        &mut output,
        directory.path(),
        &mut input,
    );
    assert!(matches!(result, Err(CliError::Typed { kind: LocketError::ScanFindingBlocked, .. })));
    let output = String::from_utf8(output)?;
    assert!(output.contains("known-secret"));
    assert!(!output.contains("fixture-671"));
    Ok(())
}

#[test]
fn set_upsert_rejects_deleted_target_and_plaintext_argv() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    init(&context, "app")?;
    run(&context, &["set", "TOKEN"])?;
    run(&context, &["rm", "TOKEN"])?;
    let (code, _) = json_run(&context, &["set", "TOKEN", "--upsert", "--json"])?;
    assert_eq!(code, LocketError::SecretDeleted.exit_code());
    assert!(Cli::try_parse_from(["locket", "set", "TOKEN", CANARY]).is_err());
    let (_, deleted) = json_run(&context, &["discover", "--all", "--json"])?;
    assert_eq!(deleted[0]["state"], "deleted");
    Ok(())
}

fn rpc(id: u64, name: &str, arguments: &Value) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
}

fn mcp_exchange(context: &RuntimeContext, requests: &[Value]) -> Result<String, Box<dyn Error>> {
    let mut input =
        Cursor::new(requests.iter().map(Value::to_string).collect::<Vec<_>>().join("\n"));
    let mut output = Vec::new();
    crate::commands::mcp::serve(&mut input, &mut output, context)?;
    let output = String::from_utf8(output)?;
    Ok(output)
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the complete exchange in one session.
fn mcp_roundtrip_lists_tools_and_never_returns_values() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    init(&context, "app")?;
    run(&context, &["profile", "create", "prod"])?;
    run(&context_with_confirmation(&context, "prod\n"), &["profile", "mark-dangerous", "prod"])?;
    run(&context, &["policy", "add", "check", "--", "echo", "safe"])?;
    run(&context, &["policy", "require", "check", "TOKEN"])?;
    let path = directory.path().join("private-input");
    let file_canary = "fixture-value-from-file-404";
    fs::write(&path, format!("{file_canary}\n"))?;
    let rejected = "ghp_exampleSensitiveCanary456";
    let requests = [
        json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        rpc(2, "locket_list_projects", &json!({})),
        rpc(
            3,
            "locket_store_secret",
            &json!({"project":"app","name":"TOKEN","value":CANARY,"description":"First description","required":true}),
        ),
        rpc(
            4,
            "locket_store_secret",
            &json!({"project":"app","name":"TOKEN","value":CANARY,"upsert":true,"owner":"Platform"}),
        ),
        rpc(
            5,
            "locket_discover_secrets",
            &json!({"project":"app","name_glob":"TO?EN","owner":"platform"}),
        ),
        rpc(6, "locket_get_secret_metadata", &json!({"project":"app","name":"TOKEN"})),
        rpc(
            7,
            "locket_update_secret_metadata",
            &json!({"project":"app","name":"TOKEN","tags":["service"],"required":false}),
        ),
        rpc(8, "locket_list_project_policies", &json!({"project":"app"})),
        rpc(
            9,
            "locket_generate_secret",
            &json!({"project":"app","name":"RANDOM","profile":"prod","confirm_dangerous_profile":"Prod"}),
        ),
        rpc(
            10,
            "locket_generate_secret",
            &json!({"project":"app","name":"RANDOM","profile":"prod","confirm_dangerous_profile":"prod","format":"uuid"}),
        ),
        rpc(
            11,
            "locket_update_secret_metadata",
            &json!({"project":"app","name":"TOKEN","owner":rejected}),
        ),
        rpc(
            12,
            "locket_update_secret_metadata",
            &json!({"project":"app","name":"TOKEN","description":CANARY}),
        ),
        rpc(
            13,
            "locket_store_secret",
            &json!({"project":"app","name":"FROM_FILE","value_file":path}),
        ),
        json!({"jsonrpc":"2.0","id":14,"method":"ping"}),
        json!({"jsonrpc":"2.0","id":15,"method":"tools/call","params":7}),
    ];
    let output = mcp_exchange(&context, &requests)?;
    for canary in [CANARY, file_canary, rejected] {
        assert!(!output.contains(canary));
    }
    let replies =
        output.lines().map(serde_json::from_str::<Value>).collect::<Result<Vec<_>, _>>()?;
    assert_eq!(replies.len(), 16);
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-03-26");
    let tools = replies[1]["result"]["tools"].as_array().ok_or("expected tools")?;
    assert_eq!(tools.len(), 11);
    for name in [
        "locket_inspect_env_keys",
        "locket_scan_env_files",
        "locket_import_env",
        "locket_detect_commands",
    ] {
        assert!(tools.iter().any(|tool| tool["name"] == name), "missing {name}");
    }
    let payload = |id: usize| -> Result<Value, Box<dyn Error>> {
        Ok(serde_json::from_str(
            replies[id]["result"]["content"][0]["text"].as_str().ok_or("missing MCP text")?,
        )?)
    };
    assert_eq!(payload(2)?[0]["name"], "app");
    assert_eq!(payload(3)?["operation"], "set");
    assert_eq!(payload(4)?["operation"], "rotate");
    assert_eq!(payload(5)?[0]["reference"], "lk://dev/TOKEN");
    assert_eq!(payload(6)?["required"], true);
    assert_eq!(payload(6)?["versions"].as_array().ok_or("expected versions")?.len(), 2);
    assert_eq!(payload(7)?["tags"], json!(["service"]));
    let invocation = &payload(8)?["policies"][0]["invocation"];
    assert_eq!(invocation, &json!(["locket", "run", "--redact-output", "check"]));
    assert!(payload(8)?["execution_guidance"].to_string().contains("--egress-host SECRET=host"));
    assert_eq!(replies[9]["result"]["isError"], true);
    let generated = payload(10)?;
    assert_eq!(generated["reference"], "lk://prod/RANDOM", "{generated}");
    assert_eq!(generated["origin_detail"], "generated");
    assert_eq!(replies[11]["result"]["isError"], true);
    assert_eq!(replies[12]["result"]["isError"], true);
    assert_eq!(payload(13)?["reference"], "lk://dev/FROM_FILE");
    assert_eq!(replies[14]["result"], json!({}));
    assert_eq!(replies[15]["error"]["code"], -32602);
    Ok(())
}

fn mcp_call(
    context: &RuntimeContext,
    tool: &str,
    args: &Value,
    error: Option<LocketError>,
) -> Result<Value, Box<dyn Error>> {
    let output = mcp_exchange(context, &[rpc(1, tool, args)])?;
    assert!(!output.contains(CANARY), "{tool} leaked a value");
    let reply = serde_json::from_str::<Value>(&output)?;
    let result = &reply["result"];
    assert_eq!(result["isError"], error.is_some(), "{output}");
    let payload: Value =
        serde_json::from_str(result["content"][0]["text"].as_str().ok_or("missing MCP text")?)?;
    if let Some(kind) = error {
        assert_eq!(payload["error"]["code"], format!("{kind:?}"));
    }
    Ok(payload)
}

#[test]
fn mcp_detects_commands_inside_cwd_and_trusted_projects() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let trusted = tempdir()?;
    let outside = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    let trusted_context = RuntimeContext { cwd: trusted.path().to_path_buf(), ..context.clone() };
    let nested = directory.path().join("nested");
    fs::create_dir(&nested)?;
    for root in [directory.path(), &nested, trusted.path(), outside.path()] {
        fs::write(
            root.join("package.json"),
            json!({"scripts": {"test": format!("echo {CANARY} > ran.txt")}}).to_string(),
        )?;
    }
    let tool = "locket_detect_commands";
    let expected = |root: &std::path::Path, already_configured| -> Result<Value, Box<dyn Error>> {
        Ok(json!({
            "root": root.canonicalize()?,
            "commands": [{
                "name": "test", "argv": ["npm", "run", "test"], "command_preview": "npm run test",
                "source_file": "package.json", "already_configured": already_configured,
            }],
            "metadata_only": true,
        }))
    };
    assert_eq!(mcp_call(&context, tool, &json!({}), None)?, expected(directory.path(), false)?);
    assert_eq!(
        mcp_call(&context, tool, &json!({"path": "nested"}), None)?,
        expected(&nested, false)?
    );
    assert!(!context.store_path.exists());
    mcp_call(&context, tool, &json!({"path": trusted.path()}), Some(LocketError::AccessDenied))?;
    init(&trusted_context, "trusted")?;
    run(&trusted_context, &["policy", "add", "test", "--", "npm", "run", "test"])?;
    let report = expected(trusted.path(), true)?;
    assert_eq!(mcp_call(&context, tool, &json!({"project": "trusted"}), None)?, report);
    assert_eq!(mcp_call(&context, tool, &json!({"path": trusted.path()}), None)?, report);
    mcp_call(&context, tool, &json!({"path": outside.path()}), Some(LocketError::AccessDenied))?;
    run(&context, &["shared", "init"])?;
    mcp_call(
        &context,
        tool,
        &json!({"project": "@shared"}),
        Some(LocketError::ProjectRootUntrusted),
    )?;
    mcp_call(
        &context,
        tool,
        &json!({"project": "trusted", "path": "."}),
        Some(LocketError::MetadataInvalid),
    )?;
    for root in [directory.path(), &nested, trusted.path(), outside.path()] {
        assert!(!root.join("ran.txt").exists());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn mcp_command_detection_stays_inside_the_allowed_root() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let directory = tempdir()?;
    let outside = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    fs::create_dir(outside.path().join("nested"))?;
    fs::write(outside.path().join("package.json"), r#"{"scripts":{"test":"would leak"}}"#)?;
    symlink(outside.path(), directory.path().join("foreign"))?;
    symlink(outside.path().join("package.json"), directory.path().join("package.json"))?;

    let tool = "locket_detect_commands";
    mcp_call(&context, tool, &json!({"path": "foreign/nested"}), Some(LocketError::AccessDenied))?;
    let result = mcp_call(&context, tool, &json!({}), None)?;
    assert_eq!(result["commands"], json!([]));
    Ok(())
}

#[test]
fn mcp_env_discovery_respects_cwd_and_registered_roots() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let trusted = tempdir()?;
    let outside = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    let trusted_context = RuntimeContext { cwd: trusted.path().to_path_buf(), ..context.clone() };
    for root in [&directory, &trusted, &outside] {
        fs::write(root.path().join(".env.prod"), format!("OPENAI_API_KEY={CANARY}\n"))?;
    }
    let inspect = "locket_inspect_env_keys";
    let scan = "locket_scan_env_files";
    let keys = mcp_call(&context, inspect, &json!({"path": ".env.prod"}), None)?;
    assert_eq!(keys["keys"], json!(["OPENAI_API_KEY"]));
    assert_eq!(keys["metadata_only"], true);

    let nested = directory.path().join("nested");
    fs::create_dir(&nested)?;
    fs::write(nested.join(".env"), format!("NESTED_KEY={CANARY}\n"))?;
    let report = mcp_call(&context, scan, &json!({}), None)?;
    assert_eq!(report["total_files"], 2);
    assert_eq!(report["files"][0]["keys"], json!(["OPENAI_API_KEY"]));
    assert_eq!(report["files"][0]["suggested_profile"], "prod");
    assert_eq!(report["shared_candidates"][0]["key"], "OPENAI_API_KEY");
    let shallow = mcp_call(&context, scan, &json!({"max_depth": 0}), None)?;
    assert_eq!(shallow["total_files"], 1);
    let deep = directory.path().join(["nested"; 9].join("/"));
    fs::create_dir_all(deep.join("too-deep"))?;
    fs::write(deep.join(".env"), format!("AT_LIMIT={CANARY}\n"))?;
    fs::write(deep.join("too-deep/.env"), format!("OVER_LIMIT={CANARY}\n"))?;
    let capped = mcp_call(&context, scan, &json!({"max_depth": 50}), None)?;
    assert_eq!(capped["total_files"], 3);
    assert!(capped.to_string().contains("AT_LIMIT"));
    assert!(!capped.to_string().contains("OVER_LIMIT"));

    assert!(!context.store_path.exists());
    init(&trusted_context, "trusted")?;
    mcp_call(&context, inspect, &json!({"path": trusted.path().join(".env.prod")}), None)?;
    mcp_call(&context, scan, &json!({"path": trusted.path()}), None)?;
    for (tool, path) in [(inspect, outside.path().join(".env.prod")), (scan, outside.path().into())]
    {
        mcp_call(&context, tool, &json!({"path": path}), Some(LocketError::AccessDenied))?;
    }
    Ok(())
}

#[test]
#[cfg(unix)]
fn mcp_env_discovery_rejects_symlink_inputs_and_skips_scan_links() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let directory = tempdir()?;
    let outside = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    fs::write(directory.path().join(".env"), format!("LOCAL={CANARY}\n"))?;
    fs::write(outside.path().join(".env"), format!("EXTERNAL={CANARY}\n"))?;
    symlink(directory.path().join(".env"), directory.path().join(".env.link"))?;
    symlink(outside.path(), directory.path().join("foreign"))?;

    let inspect = "locket_inspect_env_keys";
    let scan = "locket_scan_env_files";
    mcp_call(&context, inspect, &json!({"path": ".env.link"}), Some(LocketError::MetadataInvalid))?;
    mcp_call(&context, inspect, &json!({"path": "foreign/.env"}), Some(LocketError::AccessDenied))?;
    mcp_call(&context, scan, &json!({"path": "foreign/."}), Some(LocketError::MetadataInvalid))?;
    let report = mcp_call(&context, scan, &json!({}), None)?;
    assert_eq!(report["total_files"], 1);
    assert_eq!(report["files"][0]["keys"], json!(["LOCAL"]));
    Ok(())
}

#[test]
fn mcp_env_import_shared_filters_and_dry_run_leaves_store_unchanged() -> Result<(), Box<dyn Error>>
{
    let directory = tempdir()?;
    let outside = tempdir()?;
    let context = RuntimeContext {
        key_store: Arc::new(ProjectKeys::default()),
        ..test_context_with_secret_value(&directory, CANARY)
    };
    let detached = RuntimeContext { cwd: outside.path().to_path_buf(), ..context.clone() };
    let (_, shared) = json_run(&context, &["shared", "init", "--json"])?;
    let path = directory.path().join(".env");
    fs::write(&path, format!("KEEP={CANARY}-keep\nOMIT={CANARY}-omit\n"))?;
    fs::write(directory.path().join("invalid.env"), format!("BROKEN=\"{CANARY}\n"))?;
    let tool = "locket_import_env";
    let mut args = json!({"project": "@shared", "path": ".env", "only": ["KEEP"], "dry_run": true});
    let planned = mcp_call(&context, tool, &args, None)?;
    assert_eq!(planned["dry_run"], true);
    assert_eq!(planned["imported_names"], json!(["KEEP"]));
    assert_eq!(planned["filtered_out_names"], json!(["OMIT"]));
    let mut detached_args = args.clone();
    detached_args["path"] = json!(path);
    mcp_call(&detached, tool, &detached_args, Some(LocketError::AccessDenied))?;
    init(&context, "trusted")?;
    let store = Store::open_read_only(&context.store_path)?;
    let id = shared["project_id"].as_str().ok_or("missing shared id")?;
    let profile = store.get_profile_by_name(id, "default")?.ok_or("missing profile")?;
    assert!(store.get_active_secret(id, &profile.id, "KEEP", "user-local")?.is_none());

    args["dry_run"] = json!(false);
    let mut rejected = args.clone();
    rejected["value"] = json!(CANARY);
    mcp_call(&context, tool, &rejected, Some(LocketError::MetadataInvalid))?;
    rejected.as_object_mut().ok_or("missing arguments")?.remove("value");
    rejected["path"] = json!("invalid.env");
    mcp_call(&context, tool, &rejected, Some(LocketError::MetadataInvalid))?;
    detached_args["dry_run"] = json!(false);
    let imported = mcp_call(&detached, tool, &detached_args, None)?;
    assert_eq!(imported["imported_names"], json!(["KEEP"]));
    assert_eq!(imported["metadata_only"], true);
    assert!(path.is_file());
    assert!(store.get_active_secret(id, &profile.id, "KEEP", "user-local")?.is_some());
    assert!(store.get_active_secret(id, &profile.id, "OMIT", "user-local")?.is_none());
    Ok(())
}

#[test]
fn mcp_env_import_project_requires_its_root_and_confirms_dangerous_overwrite()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    let root = directory.path().join("project");
    fs::create_dir(&root)?;
    let inside = RuntimeContext { cwd: root.clone(), ..context.clone() };
    init(&inside, "app")?;
    run(&inside, &["profile", "create", "prod"])?;
    run(&context_with_confirmation(&inside, "prod\n"), &["profile", "mark-dangerous", "prod"])?;
    let tool = "locket_import_env";
    fs::write(directory.path().join(".env"), format!("TOKEN={CANARY}-outside\n"))?;
    fs::write(root.join(".env"), format!("TOKEN={CANARY}-initial\n"))?;
    let mut args =
        json!({"project": "app", "profile": "prod", "path": ".env", "source": "machine-local"});
    mcp_call(&context, tool, &args, Some(LocketError::AccessDenied))?;
    args["project"] = json!(root);
    args["path"] = json!("project/.env");
    let created = mcp_call(&context, tool, &args, None)?;
    assert_eq!(created["imported_names"], json!(["TOKEN"]));
    assert_eq!(created["source"], "machine-local");

    args["project"] = created["project_id"].clone();
    fs::write(root.join(".env"), format!("TOKEN={CANARY}-updated\n"))?;
    args["overwrite"] = json!(true);
    args["dry_run"] = json!(true);
    let planned = mcp_call(&context, tool, &args, None)?;
    assert_eq!(planned["overwritten_names"], json!(["TOKEN"]));
    args["dry_run"] = json!(false);
    mcp_call(&context, tool, &args, Some(LocketError::DangerousProfileConfirmationRequired))?;

    let id = created["project_id"].as_str().ok_or("missing project id")?;
    let store = Store::open_read_only(&context.store_path)?;
    let profile = store.get_profile_by_name(id, "prod")?.ok_or("missing profile")?;
    let version = || -> Result<_, Box<dyn Error>> {
        Ok(store
            .get_active_secret(id, &profile.id, "TOKEN", "machine-local")?
            .ok_or("missing token")?
            .current_version)
    };
    assert_eq!(version()?, 1);
    args["confirm_dangerous"] = json!(true);
    let updated = mcp_call(&context, tool, &args, None)?;
    assert_eq!(updated["overwritten_names"], json!(["TOKEN"]));
    assert_eq!(version()?, 2);
    Ok(())
}

#[test]
fn explicit_profile_get_resolves_only_the_selected_project_profile_and_source()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    init(&context, "app")?;
    run(&context, &["profile", "create", "staging"])?;
    for source in ["user-local", "machine-local"] {
        run(&context, &["set", "SHARED_NAME", "--profile", "staging", "--source", source])?;
    }
    let project = crate::require_project(&context)?;
    let id = project.config.project_id.as_str();
    let (_, out) = run(&context, &["get", "--project", id, "--profile", "staging", "SHARED_NAME"])?;
    assert_eq!(out, "SHARED_NAME source=machine-local version=1\n");
    let (_, out) =
        run(&context, &["get", "--profile", "staging", "SHARED_NAME", "--source", "user-local"])?;
    assert_eq!(out, "SHARED_NAME source=user-local version=1\n");

    for (args, expected) in [
        (
            vec!["get", "--project", id, "--profile", "staging", "bad name"],
            LocketError::InvalidSecretName,
        ),
        (
            vec!["get", "--project", id, "--profile", "dev", "SHARED_NAME"],
            LocketError::SecretNotFound,
        ),
        (
            vec!["get", "--project", "missing-vault", "--profile", "staging", "SHARED_NAME"],
            LocketError::ProjectNotFound,
        ),
        (
            vec![
                "get",
                "--project",
                id,
                "--profile",
                "staging",
                "SHARED_NAME",
                "--source",
                "team-managed",
            ],
            LocketError::SecretNotFound,
        ),
    ] {
        let mut out = Vec::new();
        let result = run_with_context(
            Cli::try_parse_from(std::iter::once("locket").chain(args))?,
            &context,
            &mut out,
        );
        let error = result.err().ok_or("invalid scope accepted")?;
        assert_eq!(error.exit_code(), expected.exit_code());
        assert_eq!(out, b"");
        assert!(!error.to_string().contains(CANARY));
    }
    let store = crate::open_store(&context)?;
    let profile = store.get_profile_by_name(id, "staging")?.ok_or("missing profile")?;
    store.connection().execute(
        "UPDATE secrets SET state='deleted' WHERE project_id=?1 AND profile_id=?2 AND source='machine-local'",
        [id, &profile.id],
    )?;
    let mut out = Vec::new();
    let cli = Cli::try_parse_from([
        "locket",
        "get",
        "--profile",
        "staging",
        "SHARED_NAME",
        "--source",
        "machine-local",
    ])?;
    let error = run_with_context(cli, &context, &mut out).err().ok_or("deleted source returned")?;
    assert_eq!(error.exit_code(), LocketError::SecretDeleted.exit_code());
    assert_eq!(out, b"");
    let (_, out) = run(&context, &["get", "--profile", "staging", "SHARED_NAME"])?;
    assert_eq!(out, "SHARED_NAME source=user-local version=1\n");
    Ok(())
}

#[test]
fn discovery_human_output_marks_dangerous_profiles_and_ambiguous_projects_fail_closed()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let a = directory.path().join("project-a");
    let b = directory.path().join("project-b");
    fs::create_dir(&a)?;
    fs::create_dir(&b)?;
    let context = RuntimeContext {
        key_store: Arc::new(ProjectKeys::default()),
        ..test_context_with_secret_value(&directory, CANARY)
    };
    let a = RuntimeContext { cwd: a, ..context.clone() };
    let b = RuntimeContext { cwd: b, ..context.clone() };
    init(&a, "app")?;
    init(&b, "app")?;
    run(&a, &["set", "TOKEN_A"])?;
    run(&b, &["set", "TOKEN_B"])?;
    let project = crate::require_project(&a)?;
    let id = project.config.project_id.as_str();
    let store = Store::open(&context.store_path)?;
    store.connection().execute("UPDATE profiles SET dangerous=1 WHERE project_id=?1", [id])?;

    let (_, list) = run(&context, &["project", "list"])?;
    assert!(list.contains("profile dev [dangerous]"));
    assert!(list.contains("project-a"));
    assert!(list.contains("project-b"));
    assert!(!list.contains(CANARY));
    let (_, matches) = run(&context, &["discover", "--project", "project-a", "--name", "TOKEN_*"])?;
    assert!(matches.contains("TOKEN_A"));
    assert!(matches.contains("[dangerous]"));
    assert!(!matches.contains("TOKEN_B"));
    assert!(!matches.contains(CANARY));

    let (code, error) = json_run(&context, &["discover", "--project", "app", "--json"])?;
    assert_eq!(code, LocketError::InvalidReference.exit_code());
    assert_eq!(error["error"]["code"], "InvalidReference");
    assert_eq!(error["error"]["message"], "project selector is ambiguous; select by project id");
    Ok(())
}

#[test]
fn parity_checks_plaintext_only_on_explicit_request_and_uses_trusted_root()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let root = directory.path().join("trusted");
    let clone = directory.path().join("untrusted");
    fs::create_dir(&root)?;
    fs::create_dir(&clone)?;
    let context =
        RuntimeContext { cwd: root.clone(), ..test_context_with_secret_value(&directory, CANARY) };
    init(&context, "app")?;
    run(&context, &["set", "PRIVATE_TOKEN"])?;
    fs::write(root.join(".env.dev"), format!("PRIVATE_TOKEN={CANARY}\n"))?;
    fs::write(clone.join(".env.clone"), format!("PRIVATE_TOKEN={CANARY}\n"))?;
    fs::copy(root.join("locket.toml"), clone.join("locket.toml"))?;
    let project = crate::require_project(&context)?;
    let id = project.config.project_id.as_str();
    let outside = RuntimeContext { cwd: clone, ..context.clone() };
    for (context, args) in [
        (&context, vec!["parity", "--json"]),
        (&context, vec!["parity", "--project", id, "--json"]),
        (&outside, vec!["parity", "--project", id, "--json"]),
    ] {
        let (code, report) = json_run(context, &args)?;
        assert_eq!(code, 0);
        assert_eq!(report["plaintext_checked"], false);
        assert_eq!(report["plaintext_drift"], json!([]));
    }

    let (code, rejected) = json_run(&outside, &["parity", "--check-plaintext", "--json"])?;
    assert_eq!(code, LocketError::ProjectRootUntrusted.exit_code());
    assert_eq!(rejected["error"]["code"], "ProjectRootUntrusted");
    let (code, checked) =
        json_run(&outside, &["parity", "--project", id, "--check-plaintext", "--json"])?;
    assert_eq!(code, 0);
    assert_eq!(checked["plaintext_checked"], true);
    assert_eq!(checked["plaintext_drift"], json!([{"file": ".env.dev", "overlap_count": 1}]));
    let (_, human) = run(&context, &["parity", "--check-plaintext"])?;
    assert!(human.contains("dev: missing []"));
    assert!(human.contains("plaintext drift: .env.dev (1 overlapping keys)"));
    assert!(!human.contains(CANARY));
    Ok(())
}

#[test]
fn mcp_command_detection_preserves_command_metadata_for_local_manifests()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, CANARY);
    let root = directory.path();
    fs::write(
        root.join("package.json"),
        json!({"scripts": {"dev": CANARY, "db:migrate": CANARY, "build": ""}}).to_string(),
    )?;
    fs::write(root.join("pnpm-lock.yaml"), "")?;
    fs::write(root.join("Cargo.toml"), "[package]\nname = 'fixture'\n")?;
    fs::create_dir(root.join("src"))?;
    fs::write(root.join("src/main.rs"), "fn main() {}\n")?;
    fs::write(root.join("Makefile"), "lint:\n\t@true\nrun::=fixture\n")?;
    fs::write(root.join("pyproject.toml"), "")?;
    fs::write(root.join("uv.lock"), "")?;
    let expected = crate::commands::project::detect::detect_policy_commands(root, false)?;
    let response = mcp_call(&context, "locket_detect_commands", &json!({}), None)?;
    assert_eq!(response["commands"], serde_json::to_value(expected)?);
    assert!(!response.to_string().contains(CANARY));
    Ok(())
}
