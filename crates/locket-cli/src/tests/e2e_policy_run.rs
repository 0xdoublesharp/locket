//! End-to-end golden-path and failure-path tests for `locket run`.
//!
//! Covers: policy creation via CLI, `policy doctor`, `locket run` argv path
//! with required/optional secrets, deny path (missing policy, missing required
//! secret), confirm gate, and user-verification gate.
#![allow(clippy::literal_string_with_formatting_args)]
#[allow(unused_imports)]
use super::*;

/// Full golden path: create secrets via CLI, add policy via CLI,
/// run `policy doctor`, then run `locket run` and confirm secrets are injected.
#[test]
fn e2e_policy_run_golden_path_required_and_optional_secrets()
-> Result<(), Box<dyn std::error::Error>> {
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

    // Create policy via CLI commands
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "policy",
            "add",
            "deploy",
            "--",
            test_shell(),
            "-c",
            "printf 'DB=%s\\nAPI=%s\\n' \"${DATABASE_URL:+present}\" \"${API_KEY:+present}\" > run-presence.txt",
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
        Cli::try_parse_from(["locket", "policy", "allow", "deploy", "API_KEY"])?,
        &context,
        &mut Vec::new(),
    )?;

    // Policy doctor reports ok
    let mut doctor_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "doctor"])?,
        &context,
        &mut doctor_output,
    )?;
    let doctor_output = String::from_utf8(doctor_output)?;
    assert!(doctor_output.contains("policy_doctor: ok"), "doctor must pass: {doctor_output}");

    // Run the policy
    run_with_context(Cli::try_parse_from(["locket", "run", "deploy"])?, &context, &mut Vec::new())?;

    let presence = std::fs::read_to_string(directory.path().join("run-presence.txt"))?;
    assert_eq!(presence, "DB=present\nAPI=present\n");
    assert!(!presence.contains("postgres://localhost/app"), "run must not leak secret values");
    assert!(!presence.contains("sk-test-value"), "run must not leak secret values");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let (policy_name, exit_status): (Option<String>, Option<i32>) = store.connection().query_row(
        "SELECT policy_name, exit_status FROM runtime_sessions ORDER BY rowid DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(policy_name.as_deref(), Some("deploy"));
    assert_eq!(exit_status, Some(0));
    Ok(())
}

/// Deny path: `locket run` with a non-existent policy exits `PolicyNotFound`.
#[test]
fn e2e_policy_run_missing_policy_exits_policy_not_found() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "run", "nonexistent-policy"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("run with missing policy must fail".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::PolicyNotFound.exit_code(),
        "PolicyNotFound is exit 64"
    );
    assert!(error.to_string().contains("command policy not found: nonexistent-policy"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let run_count: i64 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM runtime_sessions", [], |row| row.get(0))?;
    assert_eq!(run_count, 0, "failed policy lookup must not create a runtime session");

    // Even though the policy could not be loaded, a metadata-only DENIED
    // audit row must be written so the rejection is visible in the chain.
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY' AND status = 'DENIED'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "DENIED");
    assert_eq!(metadata_json["failure_reason"], "policy_not_found");
    assert_eq!(metadata_json["policy_id"], "nonexistent-policy");
    assert_eq!(metadata_json["command"], "run");
    Ok(())
}

/// Deny path: `locket run` when a required secret is not set exits `InvalidPolicy`.
#[test]
fn e2e_policy_run_missing_required_secret_exits_invalid_policy()
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
            (r#"
[commands.deploy]
argv = ["/usr/bin/true"]
required_secrets = ["MISSING_SECRET"]
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "run", "deploy"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("run with missing required secret must fail".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::InvalidPolicy.exit_code(),
        "InvalidPolicy is exit 65"
    );
    assert!(error.to_string().contains("MISSING_SECRET"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let run_count: i64 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM runtime_sessions", [], |row| row.get(0))?;
    assert_eq!(run_count, 0, "failed required-secret lookup must not create a runtime session");

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY' AND status = 'DENIED'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "DENIED");
    assert_eq!(metadata_json["failure_reason"], "missing_required_secret");
    assert_eq!(metadata_json["policy_id"], "deploy");
    assert_eq!(metadata_json["required_secret_names"], json!(["MISSING_SECRET"]));
    // Audit must never include secret values.
    assert!(!metadata.contains("postgres"), "audit row must not embed values");
    Ok(())
}

/// Deny path: `locket run` whose policy declares an invalid external env file
/// path emits a metadata-only DENIED `RUN_POLICY` audit row before any spawn.
#[test]
fn e2e_policy_run_external_env_source_failure_emits_denial_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    // The path is project-relative but escapes the project root via `..`,
    // so external env file resolution fails before spawn with InvalidPolicy
    // per runtime.md (paths failing validation cause policy execution to fail
    // with `InvalidPolicy`).
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.deploy]
argv = ["/usr/bin/true"]
external_env_sources = [{ file = "../escape.env" }]
env_mode = "strict"
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "run", "deploy"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("run with bad external env file must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidPolicy.exit_code());

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let run_count: i64 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM runtime_sessions", [], |row| row.get(0))?;
    assert_eq!(run_count, 0, "external-source failure must not create a runtime session");

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY' AND status = 'DENIED'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "DENIED");
    assert_eq!(metadata_json["failure_reason"], "external_source_metadata_invalid");
    assert_eq!(metadata_json["policy_id"], "deploy");
    Ok(())
}

/// Deny path: `locket run` whose policy embeds an unparseable `lk://` reference
/// emits a metadata-only DENIED `RUN_POLICY` audit row before any spawn.
#[cfg(unix)]
#[test]
fn e2e_policy_run_invalid_lk_reference_emits_denial_audit() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    // An argv argument that contains `lk://` triggers reference resolution but
    // is not a valid URI; reference parsing fails before spawn.
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.deploy]
argv = ["/usr/bin/true", "lk://"]
env_mode = "strict"
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    std::fs::set_permissions(
        directory.path(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )?;
    let agent = TestAgent::start(&context)?;
    let result = run_with_context(
        Cli::try_parse_from(["locket", "run", "deploy"])?,
        &context,
        &mut Vec::new(),
    );
    agent.stop()?;

    let Err(error) = result else {
        return Err("run with invalid lk:// reference must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidReference.exit_code());

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let run_count: i64 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM runtime_sessions", [], |row| row.get(0))?;
    assert_eq!(run_count, 0, "lk reference failure must not create a runtime session");

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY' AND status = 'DENIED'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "DENIED");
    assert_eq!(metadata_json["failure_reason"], "invalid_lk_reference");
    assert_eq!(metadata_json["policy_id"], "deploy");
    Ok(())
}

/// Agent-gated path: `require_agent = true` fails closed before spawning
/// when the local agent is unavailable.
#[test]
fn e2e_policy_run_require_agent_exits_agent_unavailable_before_spawn()
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
            (r#"
[commands.agent_only]
argv = ["/bin/sh", "-c", "touch should-not-spawn"]
require_agent = true
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "run", "agent_only"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("agent-gated run without daemon must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::AgentUnavailable.exit_code());
    assert!(error.to_string().contains("AgentUnavailable"));
    assert!(!directory.path().join("should-not-spawn").exists());

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let run_count: i64 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM runtime_sessions", [], |row| row.get(0))?;
    assert_eq!(run_count, 0, "agent-gated failure must not create a runtime session");
    Ok(())
}

/// Agent-gated golden path: required policy secrets are resolved through
/// the local agent before the child process is spawned.
#[cfg(unix)]
#[test]
fn e2e_policy_run_require_agent_resolves_required_secret_via_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "policy",
            "add",
            "deploy",
            "--",
            test_shell(),
            "-c",
            "printf 'DB=%s\\n' \"${DATABASE_URL:+present}\" > agent-run-presence.txt",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "require", "deploy", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(b"require_agent = true\n")?;

    std::fs::set_permissions(
        directory.path(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )?;
    let agent = TestAgent::start(&context)?;
    run_with_context(Cli::try_parse_from(["locket", "run", "deploy"])?, &context, &mut Vec::new())?;
    agent.stop()?;

    let presence = std::fs::read_to_string(directory.path().join("agent-run-presence.txt"))?;
    assert_eq!(presence, "DB=present\n");
    assert!(!presence.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata_rows = {
        let mut statement =
            store.connection().prepare("SELECT metadata_json FROM audit_log ORDER BY sequence")?;
        statement.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?
    };
    assert!(metadata_rows.iter().any(|row| row.contains("DATABASE_URL")));
    assert!(!metadata_rows.iter().any(|row| row.contains("postgres://localhost/app")));
    Ok(())
}

/// Confirm gate: `locket run` with `confirm = true` rejects wrong confirmation.
#[test]
fn e2e_policy_run_confirm_gate_rejects_wrong_confirmation() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "wrong\n");
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.sensitive]
argv = ["/usr/bin/true"]
confirm = true
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "run", "sensitive"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("wrong confirmation must fail".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::ConfirmationFailed.exit_code(),
        "ConfirmationFailed is exit 68"
    );
    assert!(error.to_string().contains("confirmation did not match run scope"));
    Ok(())
}

/// Confirm gate: `locket run` with `confirm = true` accepts the correct confirmation.
#[test]
fn e2e_policy_run_confirm_gate_accepts_correct_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "run sensitive\n");
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.sensitive]
argv = ["/usr/bin/true"]
confirm = true
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "run", "sensitive"])?, &context, &mut output)?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("type 'run sensitive' to confirm run"));
    Ok(())
}

/// User-verification gate: `locket run` with `require_user_verification = true`
/// fails when the verifier denies.
#[test]
fn e2e_policy_run_user_verification_gate_fails_when_verifier_denies()
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
            (r#"
[commands.protected]
argv = ["/usr/bin/true"]
require_user_verification = true
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let denying_context =
        context_with_user_verifier(&context, Arc::new(MemoryLocalUserVerifier::denying()));
    let result = run_with_context(
        Cli::try_parse_from(["locket", "run", "protected"])?,
        &denying_context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("denied user verification must fail".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::UserVerificationFailed.exit_code(),
        "UserVerificationFailed is exit 74"
    );
    Ok(())
}

/// External env metadata: a successful `locket run` records the names sourced
/// from `external_env_sources` in `external_env_names` (metadata-only, never
/// values).
#[test]
fn e2e_policy_run_records_external_env_names_in_audit_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    // External env file under the project root supplies one allowed name.
    std::fs::write(
        directory.path().join(".env.local"),
        "DATABASE_URL=postgres://external/app\nNOT_ALLOWED=hidden\n",
    )?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.deploy]
argv = ["/usr/bin/true"]
optional_secrets = ["DATABASE_URL"]
external_env_sources = [{ file = ".env.local" }]
env_mode = "strict"
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    run_with_context(Cli::try_parse_from(["locket", "run", "deploy"])?, &context, &mut Vec::new())?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY' AND status = 'SUCCESS'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "SUCCESS");
    assert_eq!(metadata_json["external_env_names"], json!(["DATABASE_URL"]));
    // The unauthorized name must never appear in metadata.
    assert!(!metadata.contains("NOT_ALLOWED"));
    // No values may be embedded.
    assert!(!metadata.contains("postgres://external/app"));
    Ok(())
}

/// Merge mode: parent environment is inherited and Locket secrets overlay it.
/// The audit row records `env_mode = "merge"`.
#[test]
fn e2e_policy_run_env_mode_merge_inherits_parent_and_overlays_secrets()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.merge_check]
argv = ["/bin/sh", "-c", "printf 'PATH=%s\nDB=%s\n' \"${PATH:+present}\" \"${DATABASE_URL:+present}\" > merge-presence.txt"]
required_secrets = ["DATABASE_URL"]
env_mode = "merge"
"#.replace("/bin/sh", test_shell()).replace("/usr/bin/true", test_true())).as_bytes(),
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "merge_check"])?,
        &context,
        &mut Vec::new(),
    )?;

    // Parent PATH is inherited because merge starts from parent env, and the
    // Locket secret is overlaid on the merged child env.
    let presence = std::fs::read_to_string(directory.path().join("merge-presence.txt"))?;
    assert_eq!(presence, "PATH=present\nDB=present\n");
    assert!(
        !presence.contains("postgres://localhost/app"),
        "merge run must not leak secret values"
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["env_mode"], "merge");
    assert_eq!(metadata_json["status"], "SUCCESS");
    assert_eq!(metadata_json["policy_id"], "merge_check");
    assert_eq!(metadata_json["secret_names"], json!(["DATABASE_URL"]));
    Ok(())
}

/// Passthrough mode: parent environment passes through and Locket secrets
/// authorized for the policy are still injected. The audit row records
/// `env_mode = "passthrough"`.
#[test]
fn e2e_policy_run_env_mode_passthrough_preserves_parent_environment()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let api_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &api_args, "sk-test-value", "manual", 1_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.passthrough_check]
argv = ["/bin/sh", "-c", "printf 'PATH=%s\nAPI=%s\n' \"${PATH:+present}\" \"${API_KEY:+present}\" > passthrough-presence.txt"]
optional_secrets = ["API_KEY"]
env_mode = "passthrough"
"#.replace("/bin/sh", test_shell()).replace("/usr/bin/true", test_true())).as_bytes(),
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "passthrough_check"])?,
        &context,
        &mut Vec::new(),
    )?;

    // Parent PATH is passed through to the child process under passthrough mode.
    let presence = std::fs::read_to_string(directory.path().join("passthrough-presence.txt"))?;
    assert_eq!(presence, "PATH=present\nAPI=present\n");
    assert!(!presence.contains("sk-test-value"), "passthrough run must not leak secret values");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["env_mode"], "passthrough");
    assert_eq!(metadata_json["status"], "SUCCESS");
    assert_eq!(metadata_json["policy_id"], "passthrough_check");
    Ok(())
}

#[cfg(unix)]
struct TestAgent {
    shutdown: Arc<tokio::sync::Notify>,
    handle: std::thread::JoinHandle<Result<(), String>>,
}

#[cfg(unix)]
impl TestAgent {
    fn start(context: &RuntimeContext) -> Result<Self, Box<dyn std::error::Error>> {
        let socket_path = crate::agent_socket_path(context);
        let config = locket_agent::AgentSocketConfig::new(socket_path, "test-agent".to_owned());
        // Share the CLI runtime's master-key store with the agent so
        // the agent can find the master key that `locket init` wrote.
        let passphrase_store = Arc::new(context.passphrase_store.clone());
        let state = locket_agent::AgentSocketState::with_stores(
            "test-agent",
            locket_agent::current_process_uid(),
            context.key_store.clone(),
            passphrase_store,
        );
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
        Ok(Self { shutdown, handle })
    }

    fn stop(self) -> Result<(), Box<dyn std::error::Error>> {
        self.shutdown.notify_waiters();
        self.handle.join().map_err(|_| "agent thread panicked")??;
        Ok(())
    }
}
