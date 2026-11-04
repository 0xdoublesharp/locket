#[allow(unused_imports)]
use super::*;

#[test]
fn cli_error_exit_codes_follow_reserved_spec_ranges() {
    assert_eq!(crate::invalid_reference_error("bad input").exit_code(), 64);
    assert_eq!(crate::CliError::ChildExit(42).exit_code(), 42);
    assert_eq!(
        crate::CliError::Crypto(locket_crypto::CryptoError::InvalidSecretValue).exit_code(),
        64
    );
    assert_eq!(
        crate::CliError::Crypto(locket_crypto::CryptoError::InvalidWrappedKey).exit_code(),
        90
    );
    assert_eq!(
        crate::CliError::Store(locket_store::StoreError::UnsupportedSchema {
            found: 2,
            supported: 1,
        })
        .exit_code(),
        92
    );
    assert_eq!(
        crate::CliError::Store(locket_store::StoreError::AuditIntegrity {
            sequence: 1,
            reason: "row hmac mismatch".to_owned(),
        })
        .exit_code(),
        93
    );
    assert_eq!(
        crate::CliError::Platform(locket_platform::PlatformError::MasterKeyNotFound).exit_code(),
        72
    );
    assert_eq!(
        crate::CliError::Platform(locket_platform::PlatformError::LocalUserVerificationFailed)
            .exit_code(),
        74
    );
    assert_eq!(
        crate::CliError::Platform(locket_platform::PlatformError::InvalidPassphrase).exit_code(),
        72
    );
}

#[test]
fn exec_prepare_environment_conflict_exits_66() -> Result<(), Box<dyn std::error::Error>> {
    let mut request = locket_exec::ExecutionRequest::strict(vec!["tool".to_owned()]);
    request.external_env =
        std::iter::once(("DATABASE_URL".to_owned(), locket_exec::env_value("external"))).collect();
    request.locket_env =
        std::iter::once(("DATABASE_URL".to_owned(), locket_exec::env_value("locket"))).collect();
    request.override_mode = locket_exec::EnvOverrideMode::Error;

    let Err(error) =
        locket_exec::prepare_execution(&request).map_err(crate::runtime::error::exec_prepare_error)
    else {
        return Err("environment conflict should fail before spawn".into());
    };

    assert_eq!(error.exit_code(), 66);
    assert!(error.to_string().contains("environment variable conflict"));
    Ok(())
}

#[test]
fn metadata_invalid_errors_exit_64() {
    let error = crate::metadata_invalid_error(
        "metadata field tag contains control characters; refusing to store it",
    );

    assert_eq!(error.exit_code(), 64);
    assert_eq!(
        error.to_string(),
        "metadata field tag contains control characters; refusing to store it"
    );
}

#[test]
fn invalid_reference_errors_exit_64() {
    let error = crate::invalid_reference_error("diff requires two profile names");

    assert_eq!(error.exit_code(), 64);
    assert_eq!(error.to_string(), "diff requires two profile names");
}

#[test]
fn metadata_looks_like_secret_errors_exit_66() {
    let error = crate::metadata_looks_like_secret_error(
        "metadata field description looks like a secret; refusing to store it",
    );

    assert_eq!(error.exit_code(), 66);
    assert_eq!(
        error.to_string(),
        "metadata field description looks like a secret; refusing to store it"
    );
}

#[test]
fn exec_prepare_empty_command_uses_typed_invalid_reference()
-> Result<(), Box<dyn std::error::Error>> {
    let request = locket_exec::ExecutionRequest::strict(Vec::new());

    let Err(error) =
        locket_exec::prepare_execution(&request).map_err(crate::runtime::error::exec_prepare_error)
    else {
        return Err("empty command should fail before spawn".into());
    };

    assert_eq!(error.exit_code(), 64);
    let crate::CliError::Typed { kind, message } = error else {
        return Err("empty command should return a typed error".into());
    };
    assert_eq!(kind, locket_core::LocketError::InvalidReference);
    assert_eq!(message, "empty command");
    Ok(())
}

#[test]
fn secret_deleted_errors_exit_76() {
    let error = crate::secret_deleted_error("secret source is deleted");

    assert_eq!(error.exit_code(), 76);
    assert_eq!(error.to_string(), "secret source is deleted");
}

#[test]
fn secret_already_exists_errors_exit_67() {
    let error = crate::secret_already_exists_error("secret exists; use rotate");

    assert_eq!(error.exit_code(), 67);
    assert_eq!(error.to_string(), "secret exists; use rotate");
}

#[test]
fn project_root_untrusted_exits_71() {
    let error = crate::project_root_untrusted_error();

    assert_eq!(error.exit_code(), 71);
    assert!(error.to_string().contains("ProjectRootNotTrusted"));
}

#[test]
fn project_not_found_errors_exit_64() {
    let error = crate::project_not_found_error();

    assert_eq!(error.exit_code(), 64);
    assert_eq!(error.to_string(), "project not found");
}

#[test]
fn require_project_without_project_uses_project_not_found() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);

    let Err(error) = crate::require_project(&context) else {
        return Err("require_project should fail outside a Locket project".into());
    };
    assert_eq!(error.exit_code(), 64);
    let crate::CliError::Typed { kind, message } = error else {
        return Err("require_project should return a typed error".into());
    };
    assert_eq!(kind, locket_core::LocketError::ProjectNotFound);
    assert_eq!(message, "project not found");
    Ok(())
}

#[test]
fn confirmation_failed_errors_exit_68() {
    let error = crate::confirmation_failed_error("confirmation did not match project name");

    assert_eq!(error.exit_code(), 68);
    assert_eq!(error.to_string(), "confirmation did not match project name");
}

#[test]
fn tty_required_errors_exit_68() {
    let error = crate::runtime::error::tty_required_error(
        "passphrase fallback setup requires an interactive TTY",
    );

    assert_eq!(error.exit_code(), 68);
    assert_eq!(error.to_string(), "passphrase fallback setup requires an interactive TTY");
}

#[test]
fn prompt_tty_required_paths_exit_68() -> Result<(), Box<dyn std::error::Error>> {
    let confirmation_error =
        crate::runtime::prompts::read_stdin_confirmation("profile deletion", false);
    let Err(confirmation_error) = confirmation_error else {
        return Err("non-TTY stdin confirmation should fail closed".into());
    };
    assert_eq!(confirmation_error.exit_code(), 68);
    assert!(confirmation_error.to_string().contains("requires interactive confirmation"));

    let passphrase_error = crate::runtime::prompts::require_interactive_passphrase_with(
        "passphrase fallback setup",
        false,
        false,
    );
    let Err(passphrase_error) = passphrase_error else {
        return Err("non-TTY passphrase setup should fail closed".into());
    };
    assert_eq!(passphrase_error.exit_code(), 68);
    assert!(passphrase_error.to_string().contains("requires an interactive TTY"));

    Ok(())
}

#[test]
fn secret_not_found_errors_exit_77() {
    let error = crate::secret_not_found_error("secret not found");

    assert_eq!(error.exit_code(), 77);
    assert_eq!(error.to_string(), "secret not found");
}

#[test]
fn secret_version_overflow_errors_exit_90() -> Result<(), Box<dyn std::error::Error>> {
    let Err(error) = crate::next_secret_version(u32::MAX) else {
        return Err("max u32 secret version should fail before wrapping".into());
    };

    assert_eq!(error.exit_code(), 90);
    assert_eq!(error.to_string(), "secret version overflow");
    Ok(())
}

#[test]
fn exec_without_secret_selection_uses_typed_invalid_reference()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let result = run_with_context(
        Cli::try_parse_from(["locket", "exec", "--", "/bin/true"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("exec without --all or --secret should fail".into());
    };

    assert_eq!(error.exit_code(), 64);
    let crate::CliError::Typed { kind, message } = error else {
        return Err("exec argument validation should return a typed error".into());
    };
    assert_eq!(kind, locket_core::LocketError::InvalidReference);
    assert_eq!(message, "exec requires --all or at least one --secret");
    Ok(())
}

#[test]
fn profile_not_found_errors_exit_78() {
    let error = crate::profile_not_found_error("profile not found");

    assert_eq!(error.exit_code(), 78);
    assert_eq!(error.to_string(), "profile not found");
}

#[test]
fn policy_not_found_errors_exit_64() {
    let error = crate::policy_not_found_error("command policy not found: missing");

    assert_eq!(error.exit_code(), 64);
    assert_eq!(error.to_string(), "command policy not found: missing");
}

#[test]
fn missing_profile_via_diff_command_exits_78() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "diff", "dev", "missing-profile"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("diff against a missing profile should fail".into());
    };

    assert_eq!(error.exit_code(), 78);
    assert!(error.to_string().contains("second profile not found"));
    Ok(())
}

#[test]
fn invalid_secret_name_errors_exit_64() {
    let error = crate::invalid_secret_name_error("invalid secret name");

    assert_eq!(error.exit_code(), 64);
    assert_eq!(error.to_string(), "invalid secret name");
}

#[test]
fn invalid_profile_name_errors_exit_64() {
    let error = crate::invalid_profile_name_error("invalid profile name");

    assert_eq!(error.exit_code(), 64);
    assert_eq!(error.to_string(), "invalid profile name");
}

#[test]
fn unsupported_config_key_via_config_get_exits_64() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "config", "get", "not.a.real.key"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("config get with unsupported key should fail".into());
    };
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("unsupported config key"));
    Ok(())
}

#[test]
fn invalid_iso_date_via_diff_command_exits_64() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "diff", "dev", "dev", "--since", "not-an-iso-date"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("diff --since with invalid ISO date should fail".into());
    };
    assert_eq!(error.exit_code(), 64);
    Ok(())
}

#[test]
fn invalid_secret_name_via_history_command_exits_64() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "history", "bad-name-with-dash"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("history with invalid secret name should fail".into());
    };
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("invalid secret name"));
    Ok(())
}

#[test]
fn invalid_profile_name_via_use_command_exits_64() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "use", "bad name with spaces"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("use with invalid profile name should fail".into());
    };
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("invalid profile name"));
    Ok(())
}

#[test]
fn secret_not_found_via_meta_command_exits_77() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "meta", "MISSING_SECRET", "--description", "x"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("meta on missing secret should fail".into());
    };
    assert_eq!(error.exit_code(), 77);
    assert!(error.to_string().contains("secret not found"));
    Ok(())
}

#[test]
fn profile_not_found_via_use_command_exits_78() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "use", "missing-profile"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("use on missing profile should fail".into());
    };
    assert_eq!(error.exit_code(), 78);
    assert!(error.to_string().contains("profile not found"));
    Ok(())
}

#[test]
fn confirmation_failed_via_init_recovery_exits_68() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "wrong-name\n");

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--recovery-code",
            "--name",
            "the-real-name",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("init with wrong recovery confirmation should fail".into());
    };
    assert_eq!(error.exit_code(), 68);
    assert!(error.to_string().contains("confirmation did not match"));
    Ok(())
}

#[test]
fn audit_key_load_failure_is_fatal_for_audit_helpers() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let resolved = crate::require_project(&context)?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    store.connection().execute(
        "DELETE FROM keys WHERE project_id = ?1 AND purpose = ?2",
        (resolved.config.project_id.as_str(), locket_crypto::KeyPurpose::Audit.as_str()),
    )?;

    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "agent.autostart", "true"])?,
        &context,
        &mut output,
    );
    let Err(error) = result else {
        return Err("config audit should fail when the audit key is missing".into());
    };

    assert_eq!(error.exit_code(), 93);
    assert!(error.to_string().contains("project project-audit key is missing"));
    let audit_rows: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'CONFIG_UPDATE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(audit_rows, 0);
    Ok(())
}

#[test]
fn exec_passthrough_preserves_child_exit_code() -> Result<(), Box<dyn std::error::Error>> {
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

    let mut exec_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--secret",
            "DATABASE_URL",
            "--",
            test_shell(),
            "-c",
            "exit 7",
        ])?,
        &context,
        &mut exec_output,
    );

    let Err(error) = result else {
        return Err("exec should return the child exit status as an error".into());
    };
    assert_eq!(error.exit_code(), 7);
    assert!(matches!(error, crate::CliError::ChildExit(7)));
    Ok(())
}
