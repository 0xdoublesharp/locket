#[allow(unused_imports)]
use super::*;

#[test]
fn passphrase_fallback_covers_init_unlock_and_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_key_store(&directory, Arc::new(UnavailableMasterKeyStore));

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--recovery-code",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut init_output,
    )?;
    assert!(String::from_utf8(init_output)?.contains("master_key_source: passphrase-fallback"));
    let fallback_files = std::fs::read_dir(directory.path().join("passphrase-fallback"))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(fallback_files.len(), 1);

    let mut unlock_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "unlock"])?, &context, &mut unlock_output)?;
    let unlock_output = String::from_utf8(unlock_output)?;
    assert!(unlock_output.contains("unlock_method: Passphrase"));

    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/app\n");
    Ok(())
}

#[test]
fn passphrase_fallback_covers_stale_os_key_material() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fallback_context =
        test_context_with_key_store(&directory, Arc::new(UnavailableMasterKeyStore));

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--recovery-code",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &fallback_context,
        &mut init_output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&fallback_context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let stale_context =
        test_context_with_key_store(&directory, Arc::new(StaleLoadingMasterKeyStore));

    let mut unlock_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "unlock"])?,
        &stale_context,
        &mut unlock_output,
    )?;
    assert!(String::from_utf8(unlock_output)?.contains("unlock_method: Passphrase"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &stale_context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/app\n");

    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "prod"])?,
        &stale_context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "prod"])?,
        &fallback_context,
        &mut use_output,
    )?;
    let args = test_secret_write_args("API_TOKEN");
    crate::set_secret_value(&fallback_context, &args, "prod-token", "manual", 2_000)?;

    let mut prod_reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "API_TOKEN", "--reveal", "--force"])?,
        &fallback_context,
        &mut prod_reveal_output,
    )?;
    assert_eq!(String::from_utf8(prod_reveal_output)?, "prod-token\n");
    Ok(())
}

#[test]
fn recovery_rotate_creates_envelope_and_recover_restores_master_key()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let original_key_store = Arc::new(MemoryMasterKeyStore::default());
    let context = test_context_with_key_store(&directory, original_key_store);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--recovery-code",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut init_output,
    )?;
    let init_output = String::from_utf8(init_output)?;
    let initial_recovery_code = recovery_code_from_output(&init_output)?.to_owned();
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let rotate_context = context_with_recovery_code(&context, &initial_recovery_code);
    let mut rotate_output = Vec::new();
    crate::recovery_rotate_command(&rotate_context, &mut rotate_output)?;
    let rotate_output = String::from_utf8(rotate_output)?;
    assert!(rotate_output.contains("recovery_code_rotate: success"));
    assert!(rotate_output.contains("shown once"));
    assert!(rotate_output.contains("metadata_only: yes"));
    assert!(!rotate_output.contains("postgres://localhost/app"));
    let recovery_code = recovery_code_from_output(&rotate_output)?;
    let recovery_code_bytes = locket_crypto::recovery_code_decode(recovery_code)?;

    let recovery_dir = directory.path().join(".locket/recovery");
    assert!(!recovery_dir.join("kdf.toml").exists());
    assert!(recovery_dir.join("envelope.bin").exists());

    let recovered_key_store = Arc::new(MemoryMasterKeyStore::default());
    let recovered_context = test_context_with_key_store(&directory, recovered_key_store.clone());
    let resolved = crate::require_project(&recovered_context)?;
    let kdf = locket_platform::load_recovery_kdf_toml(&crate::recovery_dir(&resolved))?;
    let envelope = locket_platform::load_recovery_envelope(&crate::recovery_dir(&resolved))?;
    let mut recover_output = Vec::new();
    crate::restore_from_recovery_code(
        &recovered_context,
        &mut recover_output,
        &resolved,
        &kdf,
        &envelope,
        &recovery_code_bytes,
        false,
    )?;
    let recover_output = String::from_utf8(recover_output)?;
    assert!(recover_output.contains("recovered: master_key"));
    assert!(recover_output.contains("metadata_only: yes"));
    assert!(!recover_output.contains("postgres://localhost/app"));
    assert!(recovered_key_store.load_master_key(resolved.config.project_id.as_str()).is_ok());

    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &recovered_context,
        &mut get_output,
    )?;
    assert_eq!(String::from_utf8(get_output)?, "postgres://localhost/app\n");
    Ok(())
}

#[test]
fn install_hooks_requires_confirmation_for_unmanaged_hook() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "wrong\n");
    let hooks_dir = directory.path().join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    std::fs::write(hooks_dir.join("pre-commit"), "echo existing\n")?;

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--recovery-code",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut init_output,
    )?;

    let mut install_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut install_output,
    );
    assert_error_contains(result, "confirmation did not match");
    let install_output = String::from_utf8(install_output)?;
    assert!(install_output.contains("pre_commit_hook: unmanaged"));
    assert!(install_output.contains("metadata_only: yes"));
    assert!(install_output.contains("type project name 'app'"));
    assert!(!install_output.contains("echo existing"));
    assert_eq!(std::fs::read_to_string(hooks_dir.join("pre-commit"))?, "echo existing\n");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let hook_installs: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'HOOK_INSTALL'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(hook_installs, 0);
    Ok(())
}

#[test]
fn install_hooks_confirms_unmanaged_hook_and_preserves_existing_hook()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "app\n");
    let hooks_dir = directory.path().join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    std::fs::write(hooks_dir.join("pre-commit"), "#!/bin/sh\necho existing\n")?;

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--recovery-code",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut init_output,
    )?;

    let mut install_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut install_output,
    )?;
    let install_output = String::from_utf8(install_output)?;
    assert!(install_output.contains("pre_commit_hook: unmanaged"));
    assert!(install_output.contains("hook_change: prepended-after-confirmation"));
    assert!(install_output.contains("hook: locket scan --staged"));
    assert!(install_output.contains("secrets: not written"));
    assert!(!install_output.contains("echo existing"));

    let hook = std::fs::read_to_string(hooks_dir.join("pre-commit"))?;
    assert!(hook.starts_with("#!/bin/sh\n\n"));
    assert!(hook.contains("locket scan --staged"));
    assert!(hook.contains(crate::HOOK_END));
    assert!(hook.contains("echo existing"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(hooks_dir.join("pre-commit"))?.permissions().mode();
        assert_eq!(mode & 0o700, 0o700);
    }

    let mut reinstall_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut reinstall_output,
    )?;
    assert!(String::from_utf8(reinstall_output)?.contains("hook_change: unchanged"));
    let reinstalled_hook = std::fs::read_to_string(hooks_dir.join("pre-commit"))?;
    assert_eq!(reinstalled_hook, hook);
    assert_eq!(reinstalled_hook.matches(crate::HOOK_BEGIN).count(), 1);
    assert_eq!(reinstalled_hook.matches(crate::HOOK_END).count(), 1);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let hook_installs: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'HOOK_INSTALL'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(hook_installs, 2);
    let (command, metadata_json): (String, String) = store.connection().query_row(
        "SELECT command, metadata_json FROM audit_log WHERE action = 'HOOK_INSTALL' ORDER BY sequence LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata_json)?;
    assert_eq!(command, "install-hooks");
    assert_eq!(metadata["schema_version"], 1);
    assert_eq!(metadata["action"], "HOOK_INSTALL");
    assert_eq!(metadata["status"], "SUCCESS");
    assert_eq!(metadata["command"], "install-hooks");
    assert_eq!(metadata["hook"], "pre-commit");
    assert_eq!(metadata["hook_change"], "prepended-after-confirmation");
    assert_eq!(metadata["hook_command"], "locket scan --staged");
    assert_eq!(metadata["hook_path_kind"], "git-hooks/pre-commit");
    assert_eq!(metadata["hook_path_hash"].as_str().map(str::len), Some(64));
    assert!(metadata.get("secret_name").is_none());
    Ok(())
}

#[test]
fn install_hooks_creates_missing_hook_without_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "wrong\n");
    let hooks_dir = directory.path().join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir)?;

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--recovery-code",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut init_output,
    )?;

    let mut install_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut install_output,
    )?;
    let install_output = String::from_utf8(install_output)?;
    assert!(install_output.contains("hook_change: created"));
    assert!(!install_output.contains("pre_commit_hook: unmanaged"));

    let hook = std::fs::read_to_string(hooks_dir.join("pre-commit"))?;
    assert!(hook.starts_with("#!/bin/sh"));
    assert!(hook.contains(crate::HOOK_BEGIN));
    assert!(hook.contains("locket scan --staged"));
    assert!(hook.contains(crate::HOOK_END));

    let stale_managed = hook.replace("locket scan --staged", "locket scan --staged --old");
    std::fs::write(hooks_dir.join("pre-commit"), stale_managed)?;
    let mut reinstall_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut reinstall_output,
    )?;
    assert!(String::from_utf8(reinstall_output)?.contains("hook_change: rewrote-managed-block"));
    let rewritten_hook = std::fs::read_to_string(hooks_dir.join("pre-commit"))?;
    assert!(rewritten_hook.contains("locket scan --staged"));
    assert!(!rewritten_hook.contains("--old"));
    Ok(())
}
