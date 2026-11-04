#[allow(unused_imports)]
use super::*;

fn setup_two_source_secret(
    context: &RuntimeContext,
    key: &str,
    user_local_value: &str,
    machine_local_value: &str,
    base_ts: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let ul_args = test_secret_write_args_for_source(key, crate::SecretSourceArg::UserLocal);
    crate::set_secret_value(context, &ul_args, user_local_value, "manual", base_ts)?;
    let ml_args = test_secret_write_args_for_source(key, crate::SecretSourceArg::MachineLocal);
    crate::set_secret_value(context, &ml_args, machine_local_value, "manual", base_ts + 1)?;
    Ok(())
}

#[test]
fn get_resolves_highest_precedence_source_without_explicit_source()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "API_KEY", "user-value", "machine-value", 1_000)?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "get", "API_KEY"])?, &context, &mut output)?;
    let output = String::from_utf8(output)?;
    assert!(
        output.contains("source=machine-local"),
        "get must resolve machine-local over user-local: {output}"
    );
    Ok(())
}

#[test]
fn get_reveal_returns_highest_precedence_value() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "SECRET", "user-secret", "machine-secret", 1_000)?;

    let mut reveal = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "SECRET", "--reveal", "--force"])?,
        &context,
        &mut reveal,
    )?;
    assert_eq!(String::from_utf8(reveal)?, "machine-secret\n");
    Ok(())
}

#[test]
fn get_with_explicit_source_returns_selected_source_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "API_KEY", "user-value", "machine-value", 1_000)?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "API_KEY", "--source", "user-local"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(
        output.contains("source=user-local"),
        "get --source must select user-local metadata: {output}"
    );
    assert!(
        !output.contains("source=machine-local"),
        "get --source must not fall back to the higher-precedence source: {output}"
    );
    assert!(!output.contains("user-value"));
    assert!(!output.contains("machine-value"));
    Ok(())
}

#[test]
fn get_reveal_with_explicit_source_returns_selected_value() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "SECRET", "user-secret", "machine-secret", 1_000)?;

    let mut reveal = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "get",
            "SECRET",
            "--source",
            "user-local",
            "--reveal",
            "--force",
        ])?,
        &context,
        &mut reveal,
    )?;
    assert_eq!(String::from_utf8(reveal)?, "user-secret\n");
    Ok(())
}

#[test]
fn get_copy_with_explicit_source_uses_selected_source_and_audit_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "SECRET", "user-secret", "machine-secret", 1_000)?;

    let copy_args = crate::GetArgs {
        key: "SECRET".to_owned(),
        source: crate::SourceArg { source: Some(crate::SecretSourceArg::UserLocal) },
        reveal: false,
        force: false,
        copy: true,
        verify_user: false,
        use_dangerous: false,
    };
    let mut copy_output = Vec::new();
    let mut copy_stderr = Vec::new();
    let mut clipboard = crate::MemoryClipboard::clearing_supported();
    crate::get_command_with_clipboard_and_limit(
        &context,
        &mut copy_output,
        &mut copy_stderr,
        &copy_args,
        |value| crate::ClipboardBackend::copy(&mut clipboard, value),
        crate::ClipboardClearLimit::DirectCli,
    )?;
    assert_eq!(clipboard.value(), Some("user-secret"));

    let copy_output = String::from_utf8(copy_output)?;
    assert!(
        copy_output.contains("source=user-local"),
        "copy output must report selected source: {copy_output}"
    );
    assert!(!copy_output.contains("user-secret"));
    assert!(!copy_output.contains("machine-secret"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'COPY' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["secret_name"], "SECRET");
    assert_eq!(metadata["source"], "user-local");
    assert_eq!(metadata["action"], "COPY");
    assert_eq!(metadata["status"], "SUCCESS");
    let metadata_text = metadata.to_string();
    assert!(!metadata_text.contains("user-secret"));
    assert!(!metadata_text.contains("machine-secret"));
    Ok(())
}

#[test]
fn list_shows_each_source_as_separate_entry() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "DB_URL", "user-db", "machine-db", 1_000)?;

    let mut list_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "list"])?, &context, &mut list_output)?;
    let list_output = String::from_utf8(list_output)?;

    let user_local_line = list_output.lines().find(|l| l.contains("source=user-local"));
    let machine_local_line = list_output.lines().find(|l| l.contains("source=machine-local"));
    assert!(user_local_line.is_some(), "list must show user-local source: {list_output}");
    assert!(machine_local_line.is_some(), "list must show machine-local source: {list_output}");
    assert!(
        user_local_line.is_some_and(|l| l.contains("DB_URL")),
        "user-local line must include the key"
    );
    assert!(
        machine_local_line.is_some_and(|l| l.contains("DB_URL")),
        "machine-local line must include the key"
    );
    assert!(!list_output.contains("user-db"), "list must not reveal values");
    assert!(!list_output.contains("machine-db"), "list must not reveal values");
    Ok(())
}

#[test]
fn rotate_without_source_when_multiple_sources_exist_requires_explicit_source()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "new-value");
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "TOKEN", "user-token", "machine-token", 1_000)?;

    let rotate_args = crate::RotateArgs {
        key: "TOKEN".to_owned(),
        source: crate::SourceArg { source: None },
        metadata: crate::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
        grace_ttl: None,
    };
    let result = crate::rotate_secret_value(&context, &rotate_args, "new-value", 2_000, None);
    assert_error_contains(result.map(|_| ()), "multiple sources");
    Ok(())
}

#[test]
fn rotate_with_explicit_source_rotates_only_that_source() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "machine-rotated");
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "TOKEN", "user-token-v1", "machine-token-v1", 1_000)?;

    let rotate_args = crate::RotateArgs {
        key: "TOKEN".to_owned(),
        source: crate::SourceArg { source: Some(crate::SecretSourceArg::MachineLocal) },
        metadata: crate::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
        grace_ttl: None,
    };
    let (source, version) =
        crate::rotate_secret_value(&context, &rotate_args, "machine-rotated", 2_000, None)?;
    assert_eq!(source, "machine-local");
    assert_eq!(version, 2);

    // get still resolves machine-local (highest precedence)
    let mut reveal = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "TOKEN", "--reveal", "--force"])?,
        &context,
        &mut reveal,
    )?;
    assert_eq!(String::from_utf8(reveal)?, "machine-rotated\n");
    Ok(())
}

#[test]
fn rm_without_source_requires_explicit_source_when_multiple_sources_exist()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "CREDENTIAL", "user-cred", "machine-cred", 1_000)?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "rm", "CREDENTIAL"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "pass --source");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let profile_id: String =
        store.connection().query_row("SELECT id FROM profiles LIMIT 1", [], |row| row.get(0))?;
    assert!(
        store.get_active_secret(&project_id, &profile_id, "CREDENTIAL", "user-local")?.is_some()
    );
    assert!(
        store.get_active_secret(&project_id, &profile_id, "CREDENTIAL", "machine-local")?.is_some()
    );
    let delete_count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'DELETE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(delete_count, 0);
    Ok(())
}

#[test]
fn rm_without_source_targets_the_only_active_source() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let ml_args =
        test_secret_write_args_for_source("CREDENTIAL", crate::SecretSourceArg::MachineLocal);
    crate::set_secret_value(&context, &ml_args, "machine-cred", "manual", 1_000)?;

    let mut rm_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "rm", "CREDENTIAL"])?,
        &context,
        &mut rm_output,
    )?;
    let rm_output = String::from_utf8(rm_output)?;
    assert!(
        rm_output.contains("machine-local"),
        "rm without --source must report the selected source: {rm_output}"
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DELETE' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["secret_name"], "CREDENTIAL");
    assert_eq!(metadata["source"], "machine-local");
    assert_eq!(metadata["action"], "DELETE");
    assert_eq!(metadata["status"], "SUCCESS");
    Ok(())
}

#[test]
fn rm_with_source_targets_machine_local() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "CRED", "user-val", "machine-val", 1_000)?;

    let mut rm_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "rm", "CRED", "--source", "machine-local"])?,
        &context,
        &mut rm_output,
    )?;
    let rm_output = String::from_utf8(rm_output)?;
    assert!(
        rm_output.contains("machine-local"),
        "rm --source machine-local must confirm machine-local: {rm_output}"
    );

    // user-local remains; get returns it
    let mut get_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "get", "CRED"])?, &context, &mut get_output)?;
    assert!(
        String::from_utf8(get_output)?.contains("source=user-local"),
        "user-local must survive rm of machine-local"
    );
    Ok(())
}

#[test]
fn history_without_source_shows_both_sources() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "KEY", "user-v", "machine-v", 1_000)?;

    let mut history_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "KEY"])?,
        &context,
        &mut history_output,
    )?;
    let history_output = String::from_utf8(history_output)?;
    assert!(
        history_output.contains("source=user-local"),
        "history must include user-local source: {history_output}"
    );
    assert!(
        history_output.contains("source=machine-local"),
        "history must include machine-local source: {history_output}"
    );
    assert!(!history_output.contains("user-v"), "history must not reveal values");
    assert!(!history_output.contains("machine-v"), "history must not reveal values");
    Ok(())
}

#[test]
fn history_with_source_filter_shows_only_that_source() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "KEY", "user-v", "machine-v", 1_000)?;

    let mut history_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "KEY", "--source", "user-local"])?,
        &context,
        &mut history_output,
    )?;
    let history_output = String::from_utf8(history_output)?;
    assert!(history_output.contains("source=user-local"));
    assert!(
        !history_output.contains("source=machine-local"),
        "filtered history must not include other source: {history_output}"
    );
    Ok(())
}

#[test]
fn set_stores_into_specified_source_and_set_audit_records_source()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "machine-value");
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut set_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "set", "MY_VAR", "--source", "machine-local"])?,
        &context,
        &mut set_output,
    )?;
    let set_output = String::from_utf8(set_output)?;
    // set output format: "set MY_VAR (machine-local)"
    assert!(
        set_output.contains("machine-local"),
        "set must report the written source: {set_output}"
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let profile_id: String =
        store.connection().query_row("SELECT id FROM profiles LIMIT 1", [], |row| row.get(0))?;
    let secret = store
        .get_secret_by_source(&project_id, &profile_id, "MY_VAR", "machine-local")?
        .ok_or("expected machine-local secret")?;
    assert_eq!(secret.source, "machine-local");
    assert_eq!(secret.state, "active");

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SET' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(
        metadata.contains("\"source\":\"machine-local\""),
        "SET audit must record source: {metadata}"
    );
    Ok(())
}

#[test]
fn purge_resolves_explicit_source_for_version_purge() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "user-rotated");
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    // user-local with v1 (deprecated after rotate)
    let ul_args = test_secret_write_args_for_source("DB_PASS", crate::SecretSourceArg::UserLocal);
    crate::set_secret_value(&context, &ul_args, "user-pass-v1", "manual", 1_000)?;
    let rotate_args = crate::RotateArgs {
        key: "DB_PASS".to_owned(),
        source: crate::SourceArg { source: Some(crate::SecretSourceArg::UserLocal) },
        metadata: crate::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
        grace_ttl: None,
    };
    crate::rotate_secret_value(&context, &rotate_args, "user-rotated", 2_000, None)?;

    let mut purge_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "purge",
            "DB_PASS",
            "--source",
            "user-local",
            "--version",
            "1",
            "--force",
        ])?,
        &context,
        &mut purge_output,
    )?;
    let purge_output = String::from_utf8(purge_output)?;
    assert!(purge_output.contains("user-local"), "purge must confirm the source: {purge_output}");
    assert!(purge_output.contains("versions=1"), "purge must confirm the version: {purge_output}");
    Ok(())
}

#[test]
fn purge_without_source_requires_explicit_source_when_multiple_sources_exist()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "DB_PASS", "user-pass", "machine-pass", 1_000)?;

    let mut purge_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "purge", "DB_PASS", "--version", "1", "--force"])?,
        &context,
        &mut purge_output,
    );
    assert_error_contains(result, "pass --source");
    assert_eq!(String::from_utf8(purge_output)?, "");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let purge_count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PURGE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(purge_count, 0);
    Ok(())
}

#[test]
fn exec_injects_highest_precedence_source_value_and_records_source_in_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    setup_two_source_secret(&context, "DB_URL", "user-db-url", "machine-db-url", 1_000)?;

    run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--secret",
            "DB_URL",
            "--",
            test_shell(),
            "-c",
            "test \"$DB_URL\" = \"machine-db-url\"",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'EXEC' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(
        metadata["secret_sources"]["DB_URL"], "machine-local",
        "EXEC audit must record machine-local as selected source: {metadata}"
    );
    Ok(())
}
