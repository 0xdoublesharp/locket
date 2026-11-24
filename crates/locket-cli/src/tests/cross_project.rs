use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::Cursor;
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
    assert_eq!(projects[1]["trusted_roots"][0], root.canonicalize()?.to_string_lossy().as_ref());

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
fn mcp_roundtrip_has_seven_tools_and_never_returns_values() -> Result<(), Box<dyn Error>> {
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
    assert_eq!(replies[1]["result"]["tools"].as_array().ok_or("expected tools")?.len(), 7);
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
