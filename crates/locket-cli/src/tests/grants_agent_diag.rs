#[allow(unused_imports)]
use super::*;

#[test]
fn allow_and_deny_manage_profile_scoped_directory_grants() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut allow_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut allow_output)?;
    let allow_output = String::from_utf8(allow_output)?;
    assert!(allow_output.contains("directory grant allowed"));
    assert!(allow_output.contains("metadata_only: yes"));
    assert!(!allow_output.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let grant_count: u32 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
    assert_eq!(grant_count, 1);
    let dev_profile_id: String =
        store
            .connection()
            .query_row("SELECT profile_id FROM directory_grants", [], |row| row.get(0))?;

    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;

    let mut staging_deny_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "deny"])?, &context, &mut staging_deny_output)?;
    assert!(String::from_utf8(staging_deny_output)?.contains("directory grant not found"));
    let grant_count_after_staging_deny: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM directory_grants WHERE profile_id = ?1",
        [dev_profile_id.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(grant_count_after_staging_deny, 1);

    let mut deny_all_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "deny", "--all"])?,
        &context,
        &mut deny_all_output,
    )?;
    let deny_all_output = String::from_utf8(deny_all_output)?;
    assert!(deny_all_output.contains("directory grants revoked: 1"));
    assert!(!deny_all_output.contains("postgres://localhost/app"));
    // Soft-revoke: row survives with revoked_at set, so no active grants
    // remain but the audit-bound row stays.
    let active_remaining: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM directory_grants WHERE revoked_at IS NULL",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(active_remaining, 0);
    let total_rows: u32 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
    assert_eq!(total_rows, 1);
    Ok(())
}

#[test]
fn hook_install_requires_active_profile_directory_grant_after_use()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;

    let mut dev_hook_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "hook", "--install"])?,
        &context,
        &mut dev_hook_output,
    )?;
    let dev_hook_output = String::from_utf8(dev_hook_output)?;
    assert!(dev_hook_output.contains("hook install: durable directory grant present"));
    assert!(dev_hook_output.contains("metadata_only: yes"));

    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut staging_hook_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "hook", "--install"])?,
        &context,
        &mut staging_hook_output,
    );
    let Err(error) = result else {
        return Err("hook install must require a grant after switching profiles".into());
    };
    assert_eq!(error.exit_code(), 73);
    assert!(error.to_string().contains("GrantRequired"));
    let staging_hook_output = String::from_utf8(staging_hook_output)?;
    assert!(staging_hook_output.contains("grant_required: yes"));
    assert!(staging_hook_output.contains("reason: no directory grant for the active profile"));
    assert!(staging_hook_output.contains("metadata_only: yes"));

    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;
    let mut granted_staging_hook_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "hook", "--install"])?,
        &context,
        &mut granted_staging_hook_output,
    )?;
    assert!(
        String::from_utf8(granted_staging_hook_output)?
            .contains("hook install: durable directory grant present")
    );

    Ok(())
}

#[test]
fn allow_writes_allow_directory_audit_row() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'ALLOW_DIRECTORY' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"ALLOW_DIRECTORY\""));
    assert!(metadata.contains("\"status\":\"SUCCESS\""));
    assert!(metadata.contains("\"grant_id\":"));
    assert!(metadata.contains("\"grant_scope\":\"project-root\""));
    assert!(metadata.contains("\"root_hash\":"));
    assert!(metadata.contains("\"directory_hash\":"));
    assert!(metadata.contains("\"prior_grant\":null"));
    assert!(metadata.contains("\"result_state\":\"created\""));

    // Re-allow records prior_grant metadata and result_state = "replaced".
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;
    let metadata2: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'ALLOW_DIRECTORY' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata2.contains("\"result_state\":\"replaced\""));
    assert!(metadata2.contains("\"prior_grant\":{"));
    assert!(metadata2.contains("\"grant_id\":"));
    assert!(metadata2.contains("\"created_at\":"));
    Ok(())
}

#[test]
fn deny_writes_deny_directory_audit_row_with_prior_grant() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;

    run_with_context(Cli::try_parse_from(["locket", "deny"])?, &context, &mut Vec::new())?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DENY_DIRECTORY' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"DENY_DIRECTORY\""));
    assert!(metadata.contains("\"status\":\"SUCCESS\""));
    assert!(metadata.contains("\"grant_scope\":\"project-root\""));
    assert!(metadata.contains("\"prior_grant\":{"));
    // Soft-revoke records granted_by from the prior row and the new
    // revoked_at timestamp.
    assert!(metadata.contains("\"granted_by\":"));
    assert!(metadata.contains("\"revoked_at\":"));
    assert!(metadata.contains("\"result_state\":\"removed\""));

    // Deny again with no grant present records absent state and null prior_grant.
    run_with_context(Cli::try_parse_from(["locket", "deny"])?, &context, &mut Vec::new())?;
    let metadata2: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DENY_DIRECTORY' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata2.contains("\"result_state\":\"absent\""));
    // After a soft-revoke, the prior row is still present in the table
    // (revoked_at IS NOT NULL). get_directory_grant_any_state surfaces it
    // so re-deny audit still records prior_grant for forensics.
    assert!(metadata2.contains("\"prior_grant\":{"));
    Ok(())
}

#[test]
fn deny_all_writes_deny_directory_audit_row_with_revoked_count()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;

    run_with_context(Cli::try_parse_from(["locket", "deny", "--all"])?, &context, &mut Vec::new())?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DENY_DIRECTORY' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["action"], "DENY_DIRECTORY");
    assert_eq!(metadata["command"], "deny");
    assert_eq!(metadata["grant_scope"], "all");
    assert_eq!(metadata["revoked_count"], 2);
    assert_eq!(metadata["result_state"], "all");
    assert!(metadata["revoked_at"].is_i64());
    assert!(!metadata.to_string().contains("postgres://localhost/app"));
    // Soft-revoke leaves both rows with revoked_at set.
    let active_remaining: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM directory_grants WHERE revoked_at IS NULL",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(active_remaining, 0);
    Ok(())
}

#[test]
fn allow_requires_trusted_project_root() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
"#,
        )?;

    let mut roots_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "list-roots"])?,
        &context,
        &mut roots_output,
    )?;
    let root_hash = String::from_utf8(roots_output)?
        .lines()
        .find_map(|line| line.strip_prefix("root_hash: "))
        .ok_or("root hash should be listed")?
        .to_owned();
    let mut untrust_output = Vec::new();
    let untrust_context = context_with_confirmation(&context, &format!("{root_hash}\n"));
    run_with_context(
        Cli::try_parse_from(["locket", "project", "untrust-root", root_hash.as_str()])?,
        &untrust_context,
        &mut untrust_output,
    )?;

    let mut allow_output = Vec::new();
    let Err(error) =
        run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut allow_output)
    else {
        return Err("allow should fail for untrusted roots".into());
    };
    assert_eq!(error.exit_code(), 71);
    assert!(error.to_string().contains("ProjectRootNotTrusted"));

    let mut list_output = Vec::new();
    let list_result =
        run_with_context(Cli::try_parse_from(["locket", "list"])?, &context, &mut list_output);
    assert_error_contains(list_result, "ProjectRootNotTrusted");

    let mut get_output = Vec::new();
    let get_result = run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut get_output,
    );
    assert_error_contains(get_result, "ProjectRootNotTrusted");

    let missing_args = test_secret_write_args("API_KEY");
    assert_error_contains(
        crate::set_secret_value(&context, &missing_args, "sk_test", "manual", 2_000),
        "ProjectRootNotTrusted",
    );

    let mut run_output = Vec::new();
    let run_result = run_with_context(
        Cli::try_parse_from(["locket", "run", "env_check"])?,
        &context,
        &mut run_output,
    );
    assert_error_contains(run_result, "ProjectRootNotTrusted");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let grant_count: u32 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
    assert_eq!(grant_count, 0);

    // The spec says `locket allow` must fail before any grant happens —
    // including before any audit row. Confirm no `ALLOW_DIRECTORY` row
    // was written for the failed run, so denial state can't be confused
    // with a successful grant in the audit chain.
    let allow_audit_count: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'ALLOW_DIRECTORY'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(allow_audit_count, 0, "untrusted-root allow must not append ALLOW_DIRECTORY");
    Ok(())
}

#[test]
fn untrust_root_requires_hash_confirmation_and_revokes_directory_grants()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let mut allow_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut allow_output)?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let grant_count: u32 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
    assert_eq!(grant_count, 1);

    let mut roots_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "list-roots"])?,
        &context,
        &mut roots_output,
    )?;
    let root_hash = String::from_utf8(roots_output)?
        .lines()
        .find_map(|line| line.strip_prefix("root_hash: "))
        .ok_or("root hash should be listed")?
        .to_owned();

    let failed_context = context_with_confirmation(&context, "wrong\n");
    let mut failed_output = Vec::new();
    let failed = run_with_context(
        Cli::try_parse_from(["locket", "project", "untrust-root", root_hash.as_str()])?,
        &failed_context,
        &mut failed_output,
    );
    assert_error_contains(failed, "confirmation did not match root hash");
    let grant_count_after_failed_confirm: u32 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
    assert_eq!(grant_count_after_failed_confirm, 1);

    let untrust_context = context_with_confirmation(&context, &format!("{root_hash}\n"));
    let mut untrust_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "untrust-root", root_hash.as_str()])?,
        &untrust_context,
        &mut untrust_output,
    )?;
    let untrust_output = String::from_utf8(untrust_output)?;
    assert!(untrust_output.contains("directory_grants_revoked: 1"));
    // Soft-revoke: row stays so audit chain references stay valid; only
    // active grants drop to zero.
    let active_remaining: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM directory_grants WHERE revoked_at IS NULL",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(active_remaining, 0);
    Ok(())
}

#[test]
fn agent_status_and_stop_report_stopped_when_no_daemon_is_running()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    let mut status_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "status"])?,
        &context,
        &mut status_output,
    )?;
    let status_output = String::from_utf8(status_output)?;
    assert!(status_output.contains("agent: stopped"), "{status_output}");
    assert!(status_output.contains("running: no"), "{status_output}");
    assert!(status_output.contains("last_known_pid: -"), "{status_output}");
    assert!(status_output.contains("socket:"), "{status_output}");

    // Seed a stale pid file so `agent stop` exercises the cleanup path.
    let pid_path = crate::agent_pid_path(&context);
    crate::prepare_agent_log_dir(&context)?;
    fs::write(&pid_path, "999999999\n")?;

    let mut stop_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "stop"])?,
        &context,
        &mut stop_output,
    )?;
    let stop_output = String::from_utf8(stop_output)?;
    assert!(stop_output.contains("agent: stopped"), "{stop_output}");
    assert!(stop_output.contains("running: no"), "{stop_output}");
    assert!(stop_output.contains("removed_stale_pid: yes"), "{stop_output}");
    assert!(!pid_path.exists(), "stop should remove stale pid file");

    // After stop without a pid file, the next stop reports a clean
    // no-op without flagging removed_stale_pid.
    let mut second_stop_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "stop"])?,
        &context,
        &mut second_stop_output,
    )?;
    let second_stop_output = String::from_utf8(second_stop_output)?;
    assert!(second_stop_output.contains("agent: stopped"), "{second_stop_output}");
    assert!(second_stop_output.contains("removed_stale_pid: no"), "{second_stop_output}");

    let mut logs_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "logs"])?,
        &context,
        &mut logs_output,
    )?;
    let logs_output = String::from_utf8(logs_output)?;
    assert!(logs_output.contains("\"action\":\"stop\""), "{logs_output}");
    assert!(!logs_output.contains("secret"));

    let mut limited_logs_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "logs", "--lines", "1"])?,
        &context,
        &mut limited_logs_output,
    )?;
    let limited_logs_output = String::from_utf8(limited_logs_output)?;
    assert!(limited_logs_output.contains("\"action\":\"stop\""), "{limited_logs_output}");
    Ok(())
}

#[test]
fn agent_logs_filter_redact_rotate_and_harden_local_files() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let base = 1_700_000_000_i64 * crate::NANOS_PER_SECOND;
    crate::prepare_agent_log_dir(&context)?;
    let log_path = crate::agent_log_path(&context);
    let old_path = crate::agent_rotated_log_path(&context, 1);
    for index in 2..=crate::AGENT_LOG_RETAINED_FILES {
        fs::write(
            crate::agent_rotated_log_path(&context, index),
            format!(
                "{}\n",
                json!({
                    "timestamp": base,
                    "action": format!("rotated-{index}"),
                    "message": "retained",
                })
            ),
        )?;
    }
    fs::write(
        &old_path,
        format!(
            "{}\n",
            json!({
                "timestamp": base,
                "action": "old",
                "message": "older",
            })
        ),
    )?;
    fs::write(
        &log_path,
        format!(
            "{}\n{}\n",
            json!({
                "timestamp": base + crate::NANOS_PER_SECOND,
                "action": "token",
                "message": "sk_test_sampleTokenValue123",
                "path": directory.path().join("project/.env").display().to_string(),
                "grant_token": "grant-token-value",
                "env": {"DATABASE_URL": "postgres://localhost/app"},
            }),
            json!({
                "timestamp": "2024-01-01T00:00:02Z",
                "action": "new",
                "message": "done",
            }),
        ),
    )?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "logs", "--since", "2023-11-14T22:13:21Z"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(!output.contains("\"action\":\"old\""));
    assert!(output.contains("\"action\":\"token\""));
    assert!(output.contains("\"action\":\"new\""));
    assert!(output.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(output.contains("path_hash"));
    assert!(!output.contains("sk_test_sampleTokenValue123"));
    assert!(!output.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!output.contains("grant-token-value"));
    assert!(!output.contains("postgres://localhost/app"));

    let mut unix_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "logs", "--since", "1700000001"])?,
        &context,
        &mut unix_output,
    )?;
    assert!(!String::from_utf8(unix_output)?.contains("\"action\":\"old\""));

    fs::write(&log_path, "x".repeat(usize::try_from(crate::AGENT_LOG_MAX_BYTES)? + 1))?;
    crate::append_agent_log(&context, "rotated", "ok", "safe")?;
    assert!(crate::agent_rotated_log_path(&context, 1).exists());
    assert!(crate::agent_rotated_log_path(&context, crate::AGENT_LOG_RETAINED_FILES).exists());
    assert!(
        !crate::agent_data_dir(&context)
            .join(format!("agent.log.{}", crate::AGENT_LOG_RETAINED_FILES + 1))
            .exists()
    );
    assert!(fs::read_to_string(&log_path)?.contains("\"action\":\"rotated\""));
    assert!(
        fs::read_to_string(crate::agent_rotated_log_path(
            &context,
            crate::AGENT_LOG_RETAINED_FILES
        ))?
        .contains("\"action\":\"rotated-4\"")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&log_path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(crate::agent_data_dir(&context))?.permissions().mode() & 0o777,
            0o700
        );
    }
    Ok(())
}

#[test]
fn agent_logs_rejects_excessive_line_count() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "agent", "logs", "--lines", "10001"])?,
        &context,
        &mut output,
    );
    let Err(error) = result else {
        return Err("agent logs --lines over cap should fail".into());
    };
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("capped at 10000"));

    let mut since_output = Vec::new();
    let since_result = run_with_context(
        Cli::try_parse_from(["locket", "agent", "logs", "--since", "not-a-timestamp"])?,
        &context,
        &mut since_output,
    );
    let Err(since_error) = since_result else {
        return Err("invalid agent logs --since should fail".into());
    };
    assert_eq!(since_error.exit_code(), 64);
    assert!(since_error.to_string().contains("RFC3339 UTC or Unix seconds"));
    Ok(())
}

#[test]
fn doctor_reports_locked_safe_diagnostics_and_exit_codes() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);

    let mut missing_output = Vec::new();
    let code = run_with_context(
        Cli::try_parse_from(["locket", "doctor"])?,
        &context,
        &mut missing_output,
    )?;
    assert_eq!(code, 1);
    let missing_output = String::from_utf8(missing_output)?;
    assert!(missing_output.contains("fail project_resolution"));
    assert!(missing_output.contains("pass store_open_schema_bootstrap"));

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    run_git(directory.path(), &["init"])?;
    let mut hook_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut hook_output,
    )?;

    let mut doctor_output = Vec::new();
    let code =
        run_with_context(Cli::try_parse_from(["locket", "doctor"])?, &context, &mut doctor_output)?;
    assert_eq!(code, 0);
    let doctor_output = String::from_utf8(doctor_output)?;
    assert!(doctor_output.contains("pass locket_toml_parseability"));
    assert!(doctor_output.contains("pass sqlite_integrity"));
    assert!(doctor_output.contains("pass bundle_conflict_index"));
    assert!(doctor_output.contains("pass trusted_roots"));
    assert!(doctor_output.contains("pass schema_migration_backups"));
    assert!(doctor_output.contains("skip audit_hmac_verification"));
    #[cfg(not(windows))]
    assert!(doctor_output.contains("skip agent_socket_path_spec"));
    #[cfg(windows)]
    assert!(doctor_output.contains("pass agent_socket_path_spec"));
    // The hardening check must surface every shipped mitigation. Tests
    // run as a child of cargo, so both helpers have been called at
    // process startup; the line is
    // `pass hardening: core_dumps=active memory_lock=active` on Unix
    // when both succeed and `warn` otherwise.
    let Some(hardening_line) = doctor_output.lines().find(|line| line.contains(" hardening:"))
    else {
        return Err("doctor must include a hardening check".into());
    };
    assert!(hardening_line.contains("core_dumps="));
    assert!(hardening_line.contains("memory_lock="));
    assert!(doctor_output.contains("summary:"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let doctor_metadata = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DOCTOR'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let doctor_metadata: serde_json::Value = serde_json::from_str(&doctor_metadata)?;
    assert_eq!(doctor_metadata["action"], "DOCTOR");
    assert_eq!(doctor_metadata["status"], "SUCCESS");
    assert_eq!(doctor_metadata["fail_count"], 0);
    // Windows validates its named-pipe path above; Unix skips the socket check
    // when this isolated test has no agent data directory.
    assert_eq!(doctor_metadata["skip_count"], if cfg!(windows) { 5 } else { 6 });
    assert!(
        doctor_metadata["check_names"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name == "sqlite_integrity"))
    );
    assert!(
        doctor_metadata["check_names"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name == "bundle_conflict_index"))
    );
    assert!(
        doctor_metadata["check_names"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name == "degraded_audit_log"))
    );
    assert!(
        doctor_metadata["check_names"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name == "agent_socket_path_spec"))
    );
    assert!(!doctor_metadata.to_string().contains(directory.path().to_string_lossy().as_ref()));
    assert!(doctor_output.contains("pass degraded_audit_log: absent"));
    Ok(())
}

#[test]
fn doctor_warns_when_degraded_audit_log_is_non_empty() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    run_git(directory.path(), &["init"])?;

    // Seed the degraded-audit log with two metadata-only refusal rows.
    // Write at 0600 to mirror the production logger; otherwise the
    // `degraded_audit_log_perms` check would `fail` (non-critical) and
    // trip the exit code, masking the warn-only behavior under test.
    let degraded_log = directory.path().join(locket_platform::DEGRADED_AUDIT_LOG_FILENAME);
    fs::write(
        &degraded_log,
        "{\"schema_version\":1,\"action\":\"REVEAL\",\"status\":\"DENIED_LOCKED\",\"ts_unix_nanos\":1700000000000000000,\"failure_reason\":\"vault_locked\",\"command\":\"get --reveal\"}\n\
         {\"schema_version\":1,\"action\":\"COPY\",\"status\":\"DENIED_LOCKED\",\"ts_unix_nanos\":1700000000000000001,\"failure_reason\":\"vault_locked\",\"command\":\"agent.Copy\"}\n",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&degraded_log)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&degraded_log, perms)?;
    }
    let bytes = fs::metadata(&degraded_log)?.len();

    let mut doctor_output = Vec::new();
    let code =
        run_with_context(Cli::try_parse_from(["locket", "doctor"])?, &context, &mut doctor_output)?;
    // `warn` alone does not trip the exit code; without other failures
    // `doctor` exits 0.
    assert_eq!(code, 0);
    let doctor_output = String::from_utf8(doctor_output)?;
    assert!(doctor_output.contains("warn degraded_audit_log:"));
    assert!(doctor_output.contains(&format!("bytes={bytes}")));
    assert!(doctor_output.contains("lines=2"));
    Ok(())
}

#[test]
fn open_store_backs_up_legacy_store_and_doctor_reports_latest_backup()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let store_path = directory.path().join("store.db");
    {
        let legacy = locket_store::Store::open(&store_path)?;
        legacy.connection().execute("CREATE TABLE legacy_metadata(id TEXT PRIMARY KEY)", [])?;
    }
    let recovery_dir = directory.path().join(".locket").join("recovery");
    fs::create_dir_all(&recovery_dir)?;
    fs::write(recovery_dir.join("kdf.toml"), "schema_version = 1\n")?;
    fs::write(recovery_dir.join("envelope.bin"), b"wrapped-envelope")?;

    let store = crate::open_store(&context)?;
    assert_eq!(store.current_schema_version()?, Some(i64::from(locket_store::SCHEMA_VERSION)));

    let backup_root = directory.path().join("pre-migration-backups");
    let backup_dirs = fs::read_dir(&backup_root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(backup_dirs.len(), 1);
    let backup_dir = &backup_dirs[0];
    assert!(backup_dir.join("store.db").exists());
    assert_eq!(
        fs::read_to_string(backup_dir.join("recovery").join("kdf.toml"))?,
        "schema_version = 1\n"
    );
    assert_eq!(fs::read(backup_dir.join("recovery").join("envelope.bin"))?, b"wrapped-envelope");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let root_mode = fs::metadata(&backup_root)?.permissions().mode() & 0o777;
        let store_mode = fs::metadata(backup_dir.join("store.db"))?.permissions().mode() & 0o777;
        let kdf_mode =
            fs::metadata(backup_dir.join("recovery").join("kdf.toml"))?.permissions().mode()
                & 0o777;
        assert_eq!(root_mode, 0o700);
        assert_eq!(store_mode, 0o600);
        assert_eq!(kdf_mode, 0o600);
    }

    let mut doctor_output = Vec::new();
    let code =
        run_with_context(Cli::try_parse_from(["locket", "doctor"])?, &context, &mut doctor_output)?;
    assert_eq!(code, 1);
    let doctor_output = String::from_utf8(doctor_output)?;
    assert!(doctor_output.contains("pass schema_migration_backups"));
    assert!(doctor_output.contains("backup_skipped=0"));
    assert!(
        doctor_output
            .contains(&format!("latest_backup=pre-migration-backups{}", std::path::MAIN_SEPARATOR))
    );
    assert!(!doctor_output.contains(directory.path().to_string_lossy().as_ref()));
    Ok(())
}

fn insert_expired_runtime_session_for_doctor(
    context: &RuntimeContext,
    root: &Path,
) -> Result<locket_store::Store, Box<dyn std::error::Error>> {
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let store = locket_store::Store::open(root.join("store.db"))?;
    let profile = store
        .get_profile_by_name(resolved.config.project_id.as_str(), "dev")?
        .ok_or("default profile should exist")?;
    store.insert_runtime_session(&locket_store::RuntimeSessionRecord {
        id: "lk_sess_expired_cli".to_owned(),
        project_id: resolved.config.project_id.to_string(),
        profile_id: profile.id,
        policy_name: Some("env_check".to_owned()),
        process_id: 42,
        process_start_time: 90,
        started_at: 1_000,
        ended_at: Some(2_000),
        exit_status: Some(0),
        secret_names: vec!["DATABASE_URL".to_owned()],
        spawn_audit_sequence: Some(1),
        completion_audit_sequence: Some(2),
    })?;
    Ok(store)
}

#[derive(Debug, Eq, PartialEq)]
struct ExpiredRuntimeSessionFields {
    policy_name: String,
    process_id: u32,
    process_start_time: i64,
    started_at: i64,
    ended_at: i64,
    exit_status: i32,
    secret_names_json: String,
    spawn_audit_sequence: u64,
    completion_audit_sequence: u64,
}

fn expired_runtime_session_preserved_fields(
    store: &locket_store::Store,
) -> Result<ExpiredRuntimeSessionFields, Box<dyn std::error::Error>> {
    Ok(store.connection().query_row(
        "SELECT policy_name, process_id, process_start_time, started_at, ended_at, exit_status,
                secret_names_json, spawn_audit_sequence, completion_audit_sequence
         FROM runtime_sessions
         WHERE id = 'lk_sess_expired_cli'",
        [],
        |row| {
            Ok(ExpiredRuntimeSessionFields {
                policy_name: row.get(0)?,
                process_id: row.get(1)?,
                process_start_time: row.get(2)?,
                started_at: row.get(3)?,
                ended_at: row.get(4)?,
                exit_status: row.get(5)?,
                secret_names_json: row.get(6)?,
                spawn_audit_sequence: row.get::<_, i64>(7)?.cast_unsigned(),
                completion_audit_sequence: row.get::<_, i64>(8)?.cast_unsigned(),
            })
        },
    )?)
}

#[test]
fn doctor_reports_and_prunes_expired_runtime_session_secret_names()
-> Result<(), Box<dyn std::error::Error>> {
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
            "config",
            "set",
            "runtime.session_secret_name_retention",
            "1s",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let store = insert_expired_runtime_session_for_doctor(&context, directory.path())?;

    let mut report_output = Vec::new();
    let report_code =
        run_with_context(Cli::try_parse_from(["locket", "doctor"])?, &context, &mut report_output)?;
    assert_eq!(report_code, 0);
    let report_output = String::from_utf8(report_output)?;
    assert!(
        report_output
            .contains("warn runtime_session_secret_name_retention: expired_secret_name_rows=1"),
        "{report_output}"
    );
    assert!(
        report_output.contains("prune_with=locket doctor --prune-runtime-session-secret-names")
    );
    assert!(!report_output.contains("DATABASE_URL"));

    let retained: String = store.connection().query_row(
        "SELECT secret_names_json FROM runtime_sessions WHERE id = 'lk_sess_expired_cli'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(retained, r#"["DATABASE_URL"]"#);

    let mut prune_output = Vec::new();
    let prune_code = run_with_context(
        Cli::try_parse_from(["locket", "doctor", "--prune-runtime-session-secret-names"])?,
        &context,
        &mut prune_output,
    )?;
    assert_eq!(prune_code, 0);
    let prune_output = String::from_utf8(prune_output)?;
    assert!(
        prune_output.contains(
            "pass runtime_session_secret_name_retention: expired_secret_name_rows=1 pruned_secret_name_rows=1"
        ),
        "{prune_output}"
    );
    assert!(!prune_output.contains("DATABASE_URL"));

    let preserved = expired_runtime_session_preserved_fields(&store)?;
    assert_eq!(
        preserved,
        ExpiredRuntimeSessionFields {
            policy_name: "env_check".to_owned(),
            process_id: 42,
            process_start_time: 90,
            started_at: 1_000,
            ended_at: 2_000,
            exit_status: 0,
            secret_names_json: "[]".to_owned(),
            spawn_audit_sequence: 1,
            completion_audit_sequence: 2,
        }
    );

    let doctor_metadata = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DOCTOR' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let doctor_metadata: serde_json::Value = serde_json::from_str(&doctor_metadata)?;
    assert!(doctor_metadata["check_names"].as_array().is_some_and(|names| {
        names.iter().any(|name| name == "runtime_session_secret_name_retention")
    }));
    assert!(!doctor_metadata.to_string().contains("DATABASE_URL"));
    Ok(())
}

#[test]
fn doctor_prunes_expired_automation_client_nonces() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let project_id = resolved.config.project_id.to_string();
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    store.insert_automation_client(&locket_store::AutomationClientRecord {
        id: "lk_client_doctor".to_owned(),
        project_id,
        name: "ci".to_owned(),
        public_key: vec![7; 32],
        fingerprint: "fingerprint".to_owned(),
        storage: "external".to_owned(),
        allowed_actions: vec!["run-policy".to_owned()],
        allowed_policies: vec!["test".to_owned()],
        created_at: 100,
        last_used_at: None,
        revoked_at: None,
    })?;
    store.insert_automation_client_nonce(&locket_store::AutomationClientNonceRecord {
        client_id: "lk_client_doctor".to_owned(),
        nonce: [9; 24],
        request_timestamp: 0,
        seen_at: 0,
        expires_at: 1,
    })?;
    let nonce_count: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM automation_client_nonces",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(nonce_count, 1);
    drop(store);

    let mut doctor_output = Vec::new();
    let code =
        run_with_context(Cli::try_parse_from(["locket", "doctor"])?, &context, &mut doctor_output)?;
    assert_eq!(code, 0);
    let doctor_output = String::from_utf8(doctor_output)?;
    assert!(
        doctor_output.contains("pass automation_client_nonces_pruning: pruned_nonce_rows=1"),
        "{doctor_output}"
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let remaining: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM automation_client_nonces",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(remaining, 0);

    let doctor_metadata = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DOCTOR' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let doctor_metadata: serde_json::Value = serde_json::from_str(&doctor_metadata)?;
    assert!(doctor_metadata["check_names"].as_array().is_some_and(|names| {
        names.iter().any(|name| name == "automation_client_nonces_pruning")
    }));
    assert_eq!(doctor_metadata["status"], "SUCCESS");
    Ok(())
}

#[test]
fn doctor_reports_zero_pruned_when_no_expired_nonces() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut doctor_output = Vec::new();
    let code =
        run_with_context(Cli::try_parse_from(["locket", "doctor"])?, &context, &mut doctor_output)?;
    assert_eq!(code, 0);
    let doctor_output = String::from_utf8(doctor_output)?;
    assert!(
        doctor_output.contains("pass automation_client_nonces_pruning: pruned_nonce_rows=0"),
        "{doctor_output}"
    );
    Ok(())
}

#[test]
fn debug_bundle_redacted_writes_metadata_only_summary() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let output_path = directory.path().join("bundle.tar.gz");

    let mut bundle_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "debug",
            "bundle",
            "--redacted",
            "--output",
            output_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut bundle_output,
    )?;
    assert!(String::from_utf8(bundle_output)?.contains("redacted: yes"));

    let bundle = read_debug_bundle_json(&output_path)?;
    assert!(bundle.contains("\"redacted\": true"));
    assert!(bundle.contains("\"project\""));
    assert!(bundle.contains("\"diagnostics\""));
    assert!(bundle.contains("\"store_path_hash\""));
    assert!(!bundle.contains(directory.path().to_string_lossy().as_ref()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(&output_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    Ok(())
}

#[test]
fn debug_bundle_uses_privacy_aliases_when_configured() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let mut config_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut config_output,
    )?;
    let output_path = directory.path().join("private-bundle.tar.gz");

    let mut bundle_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "debug",
            "bundle",
            "--redacted",
            "--output",
            output_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut bundle_output,
    )?;

    let bundle = read_debug_bundle_json(&output_path)?;
    assert!(bundle.contains("project-"));
    assert!(bundle.contains("profile-"));
    assert!(!bundle.contains("\"app\""));
    assert!(!bundle.contains("\"dev\""));
    assert!(!bundle.contains("name=app"));
    assert!(!bundle.contains("name=dev"));
    Ok(())
}

#[test]
fn debug_bundle_default_output_uses_user_diagnostics_dir() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    let mut bundle_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "debug", "bundle", "--redacted"])?,
        &context,
        &mut bundle_output,
    )?;
    let bundle_output = String::from_utf8(bundle_output)?;
    let path_line = bundle_output
        .lines()
        .find_map(|line| line.strip_prefix("debug_bundle: "))
        .ok_or("missing debug bundle path")?;
    let output_path = PathBuf::from(path_line);
    assert!(output_path.starts_with(directory.path().join("diagnostics")));
    assert_eq!(output_path.extension().and_then(OsStr::to_str), Some("gz"));
    assert!(!output_path.starts_with(directory.path().join(".git")));
    assert!(bundle_output.contains("redacted: yes"));

    let bundle = read_debug_bundle_json(&output_path)?;
    assert!(bundle.contains("\"redacted\": true"));
    assert!(!bundle.contains(directory.path().to_string_lossy().as_ref()));
    Ok(())
}

#[test]
fn debug_bundle_refuses_to_overwrite_existing_output() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let output_path = directory.path().join("existing.tar.gz");
    fs::write(&output_path, "existing")?;

    let mut bundle_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "debug",
            "bundle",
            "--redacted",
            "--output",
            output_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut bundle_output,
    );
    assert_error_contains(result.map(|_| ()), "debug bundle output already exists");
    assert_eq!(fs::read_to_string(output_path)?, "existing");
    Ok(())
}
