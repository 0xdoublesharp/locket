//! End-to-end tests for the dangerous-profile read gate.
//!
//! Each `get` mode (metadata-only / `--reveal` / `--copy`) gets four cases:
//!   1. non-dangerous profile + no `--use-dangerous` flag → succeeds (regression).
//!   2. non-dangerous profile + `--use-dangerous`         → succeeds.
//!   3. dangerous profile     + no flag                   → fails with
//!      `DangerousProfileConfirmationRequired`, denial audit row written.
//!   4. dangerous profile     + flag                      → succeeds.
#![allow(clippy::too_many_lines)]

#[allow(unused_imports)]
use super::*;

fn mark_default_profile_dangerous(
    directory: &tempfile::TempDir,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let config = crate::read_project_config(&directory.path().join(crate::LOCKET_TOML))?;
    let project_id = config.project_id.as_str();
    let profile_name = config.default_profile.as_str();
    let updated = store.set_profile_dangerous(project_id, profile_name, true)?;
    assert!(updated, "default profile should exist");
    Ok(())
}

fn assert_no_value_access_audit_rows(
    directory: &tempfile::TempDir,
    action: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = ?1",
        [action],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0, "no {action} audit row expected");
    Ok(())
}

fn assert_dangerous_denial_audit_row(
    directory: &tempfile::TempDir,
    action: &str,
    expected_access_mode: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = ?1 ORDER BY sequence DESC LIMIT 1",
        [action],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["status"], "DENIED", "denial row must record DENIED status");
    assert_eq!(
        metadata["failure_reason"], "dangerous_profile_unconfirmed",
        "denial row failure_reason must be dangerous_profile_unconfirmed"
    );
    assert_eq!(metadata["access_mode"], expected_access_mode);
    assert_eq!(metadata["secret_name"], "DATABASE_URL");
    assert!(metadata.get("profile_id").is_some(), "profile_id required");
    assert!(metadata.get("source").is_some(), "source required");
    assert!(!metadata.to_string().contains("postgres://localhost/app"));
    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
fn build_get_args(reveal: bool, force: bool, copy: bool, use_dangerous: bool) -> crate::GetArgs {
    crate::GetArgs {
        project: None,
        profile: None,
        key: "DATABASE_URL".to_owned(),
        source: crate::SourceArg { source: None },
        reveal,
        force,
        copy,
        verify_user: false,
        use_dangerous,
    }
}

fn init_and_seed_secret(
    directory: &tempfile::TempDir,
) -> Result<RuntimeContext, Box<dyn std::error::Error>> {
    let context = test_context(directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    Ok(context)
}

// ---- get (metadata-only) ----

#[test]
fn get_metadata_safe_profile_without_flag_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    let args = build_get_args(false, false, false, false);
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |_, _, _| Ok(crate::ClipboardCopyStatus::clearing_scheduled()),
        crate::ClipboardClearLimit::Supported,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("DATABASE_URL"));
    assert_no_value_access_audit_rows(&directory, "GET")?;
    Ok(())
}

#[test]
fn get_metadata_safe_profile_with_flag_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    let args = build_get_args(false, false, false, true);
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |_, _, _| Ok(crate::ClipboardCopyStatus::clearing_scheduled()),
        crate::ClipboardClearLimit::Supported,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("DATABASE_URL"));
    assert_no_value_access_audit_rows(&directory, "GET")?;
    Ok(())
}

#[test]
fn get_metadata_dangerous_profile_without_flag_fails_and_audits()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    mark_default_profile_dangerous(&directory)?;

    let args = build_get_args(false, false, false, false);
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    let result = crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |_, _, _| Ok(crate::ClipboardCopyStatus::clearing_scheduled()),
        crate::ClipboardClearLimit::Supported,
    );
    let Err(error) = result else {
        return Err("dangerous profile read without --use-dangerous must fail".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::DangerousProfileConfirmationRequired.exit_code()
    );
    let crate::CliError::Typed { kind, .. } = error else {
        return Err("expected typed error".into());
    };
    assert_eq!(kind, locket_core::LocketError::DangerousProfileConfirmationRequired);
    assert_eq!(String::from_utf8(output)?, "");
    assert_dangerous_denial_audit_row(&directory, "GET", "get")?;
    Ok(())
}

#[test]
fn get_metadata_dangerous_profile_with_flag_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    mark_default_profile_dangerous(&directory)?;

    let args = build_get_args(false, false, false, true);
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |_, _, _| Ok(crate::ClipboardCopyStatus::clearing_scheduled()),
        crate::ClipboardClearLimit::Supported,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("DATABASE_URL"));
    Ok(())
}

// ---- reveal ----

#[test]
fn reveal_safe_profile_without_flag_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    let args = build_get_args(true, true, false, false);
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |_, _, _| Ok(crate::ClipboardCopyStatus::clearing_scheduled()),
        crate::ClipboardClearLimit::Supported,
    )?;
    assert_eq!(String::from_utf8(output)?, "postgres://localhost/app\n");
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REVEAL'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"status\":\"SUCCESS\""));
    assert!(!metadata.contains("dangerous_profile_unconfirmed"));
    Ok(())
}

#[test]
fn reveal_safe_profile_with_flag_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    let args = build_get_args(true, true, false, true);
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |_, _, _| Ok(crate::ClipboardCopyStatus::clearing_scheduled()),
        crate::ClipboardClearLimit::Supported,
    )?;
    assert_eq!(String::from_utf8(output)?, "postgres://localhost/app\n");
    Ok(())
}

#[test]
fn reveal_dangerous_profile_without_flag_fails_and_audits() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    mark_default_profile_dangerous(&directory)?;

    let args = build_get_args(true, true, false, false);
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    let result = crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |_, _, _| Ok(crate::ClipboardCopyStatus::clearing_scheduled()),
        crate::ClipboardClearLimit::Supported,
    );
    let Err(error) = result else {
        return Err("dangerous reveal without flag must fail".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::DangerousProfileConfirmationRequired.exit_code()
    );
    let output = String::from_utf8(output)?;
    assert!(output.is_empty(), "no value bytes may be emitted on refusal");
    assert!(!output.contains("postgres://localhost/app"));
    assert_dangerous_denial_audit_row(&directory, "REVEAL", "stdout")?;
    Ok(())
}

#[test]
fn reveal_dangerous_profile_with_flag_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    mark_default_profile_dangerous(&directory)?;

    let args = build_get_args(true, true, false, true);
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |_, _, _| Ok(crate::ClipboardCopyStatus::clearing_scheduled()),
        crate::ClipboardClearLimit::Supported,
    )?;
    assert_eq!(String::from_utf8(output)?, "postgres://localhost/app\n");
    Ok(())
}

// ---- copy (clipboard) ----

#[test]
fn copy_safe_profile_without_flag_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    let args = build_get_args(false, false, true, false);
    let mut clipboard = crate::MemoryClipboard::clearing_supported();
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |value, ttl, _| {
            crate::ClipboardBackend::copy(&mut clipboard, value)?;
            crate::ClipboardBackend::schedule_clear_after_ttl(&mut clipboard, value, ttl)
        },
        crate::ClipboardClearLimit::Supported,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("metadata_only=yes"));
    Ok(())
}

#[test]
fn copy_safe_profile_with_flag_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    let args = build_get_args(false, false, true, true);
    let mut clipboard = crate::MemoryClipboard::clearing_supported();
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |value, ttl, _| {
            crate::ClipboardBackend::copy(&mut clipboard, value)?;
            crate::ClipboardBackend::schedule_clear_after_ttl(&mut clipboard, value, ttl)
        },
        crate::ClipboardClearLimit::Supported,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("metadata_only=yes"));
    Ok(())
}

#[test]
fn copy_dangerous_profile_without_flag_fails_and_audits() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    mark_default_profile_dangerous(&directory)?;

    let args = build_get_args(false, false, true, false);
    let mut clipboard = crate::MemoryClipboard::clearing_supported();
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    let result = crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |value, ttl, _| {
            crate::ClipboardBackend::copy(&mut clipboard, value)?;
            crate::ClipboardBackend::schedule_clear_after_ttl(&mut clipboard, value, ttl)
        },
        crate::ClipboardClearLimit::Supported,
    );
    let Err(error) = result else {
        return Err("dangerous copy without flag must fail".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::DangerousProfileConfirmationRequired.exit_code()
    );
    assert!(clipboard.value().is_none(), "clipboard must remain untouched on refusal");
    assert_eq!(String::from_utf8(output)?, "");
    assert_dangerous_denial_audit_row(&directory, "COPY", "clipboard")?;
    Ok(())
}

#[test]
fn copy_dangerous_profile_with_flag_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = init_and_seed_secret(&directory)?;
    mark_default_profile_dangerous(&directory)?;

    let args = build_get_args(false, false, true, true);
    let mut clipboard = crate::MemoryClipboard::clearing_supported();
    let mut output = Vec::new();
    let mut stderr = Vec::new();
    crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut output,
        &mut stderr,
        &args,
        |value, ttl, _| {
            crate::ClipboardBackend::copy(&mut clipboard, value)?;
            crate::ClipboardBackend::schedule_clear_after_ttl(&mut clipboard, value, ttl)
        },
        crate::ClipboardClearLimit::Supported,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("metadata_only=yes"));
    Ok(())
}

#[test]
fn reveal_and_clipboard_aliases_enforce_dangerous_scope_before_value_access()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "alias-synthetic-canary");
    for args in [
        vec!["locket", "init", "--name", "app", "--no-device", "--no-passkey"],
        vec!["locket", "set", "DATABASE_URL"],
    ] {
        run_with_context(Cli::try_parse_from(args)?, &context, &mut Vec::new())?;
    }
    mark_default_profile_dangerous(&directory)?;
    for (args, audit_action, access_mode) in [
        (vec!["locket", "reveal", "DATABASE_URL", "--force"], "REVEAL", "stdout"),
        (vec!["locket", "cp", "DATABASE_URL"], "COPY", "clipboard"),
    ] {
        let mut output = Vec::new();
        let error = run_with_context(Cli::try_parse_from(args)?, &context, &mut output)
            .err()
            .ok_or("alias bypassed dangerous profile confirmation")?;
        assert_eq!(
            error.exit_code(),
            locket_core::LocketError::DangerousProfileConfirmationRequired.exit_code(),
        );
        assert_eq!(output, b"");
        assert!(!error.to_string().contains("alias-synthetic-canary"));
        assert_dangerous_denial_audit_row(&directory, audit_action, access_mode)?;
    }
    Ok(())
}
