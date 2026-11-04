#[allow(unused_imports)]
use super::*;

#[test]
fn audit_checkpoint_detects_rollback_without_overwriting_the_external_anchor()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let external = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut local_only_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "audit", "verify"])?,
        &context,
        &mut local_only_output,
    )?;
    assert!(
        String::from_utf8(local_only_output)?.contains("rollback detection requires --checkpoint")
    );
    let path = external.path().join("checkpoint.json");
    let path_arg = path.to_str().ok_or("checkpoint path is not UTF-8")?;
    let checkpoint_command =
        Cli::try_parse_from(["locket", "audit", "checkpoint", "--output", path_arg]);
    assert!(checkpoint_command.is_ok(), "audit checkpoint must be available");
    run_with_context(checkpoint_command?, &context, &mut Vec::new())?;
    let original = std::fs::read(&path)?;
    let overwrite = run_with_context(
        Cli::try_parse_from(["locket", "audit", "checkpoint", "--output", path_arg])?,
        &context,
        &mut Vec::new(),
    );
    assert!(overwrite.is_err(), "trusted checkpoint must never be overwritten");
    assert_eq!(std::fs::read(&path)?, original);
    run_with_context(
        Cli::try_parse_from(["locket", "audit", "verify", "--checkpoint", path_arg])?,
        &context,
        &mut Vec::new(),
    )?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    store.connection().execute("DELETE FROM audit_log", [])?;
    let result = run_with_context(
        Cli::try_parse_from(["locket", "audit", "verify", "--checkpoint", path_arg])?,
        &context,
        &mut Vec::new(),
    );
    assert!(
        matches!(result, Err(ref error) if error.exit_code() == locket_core::LocketError::AuditIntegrityFailed.exit_code())
    );
    let remaining: i64 =
        store.connection().query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
    assert_eq!(remaining, 0, "failed anchored verification must not append an audit row");
    Ok(())
}

#[test]
fn audit_checkpoint_rejects_malformed_oversized_and_nonregular_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let external = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    let path = external.path().join("checkpoint.json");
    let path_arg = path.to_str().ok_or("checkpoint path is not UTF-8")?;
    run_with_context(
        Cli::try_parse_from(["locket", "audit", "checkpoint", "--output", path_arg])?,
        &context,
        &mut Vec::new(),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    }
    let original = std::fs::read(&path)?;
    let mut unknown_field: serde_json::Value = serde_json::from_slice(&original)?;
    unknown_field["unexpected"] = serde_json::json!("CHECKPOINT_INPUT_MUST_NOT_LEAK");
    let duplicate_field =
        String::from_utf8(original.clone())?.replacen('{', "{\"schema_version\":1,", 1);
    for invalid in [
        b"CHECKPOINT_INPUT_MUST_NOT_LEAK".to_vec(),
        Vec::new(),
        vec![b'x'; locket_core::AUDIT_CHECKPOINT_MAX_BYTES + 1],
        serde_json::to_vec(&unknown_field)?,
        duplicate_field.into_bytes(),
    ] {
        std::fs::write(&path, invalid)?;
        let mut output = Vec::new();
        let error = run_with_context(
            Cli::try_parse_from(["locket", "audit", "verify", "--checkpoint", path_arg])?,
            &context,
            &mut output,
        )
        .err()
        .ok_or("invalid checkpoint must fail")?;
        assert_eq!(error.exit_code(), locket_core::LocketError::AuditIntegrityFailed.exit_code());
        assert_eq!(output, [] as [u8; 0]);
        assert!(!error.to_string().contains("CHECKPOINT_INPUT_MUST_NOT_LEAK"));
    }
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;
    assert!(
        run_with_context(
            Cli::try_parse_from(["locket", "audit", "verify", "--checkpoint", path_arg])?,
            &context,
            &mut Vec::new(),
        )
        .is_err()
    );
    #[cfg(unix)]
    {
        std::fs::remove_dir(&path)?;
        let target = external.path().join("anchor.json");
        std::fs::write(&target, original)?;
        std::os::unix::fs::symlink(&target, &path)?;
        assert!(
            run_with_context(
                Cli::try_parse_from(["locket", "audit", "verify", "--checkpoint", path_arg])?,
                &context,
                &mut Vec::new(),
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn completion_command_generates_scripts_without_project() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "completion", "bash"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("_locket()"));
    assert!(output.contains("complete -F _locket"));
    assert!(output.contains("completion"));
    assert!(!directory.path().join("locket.toml").exists());
    Ok(())
}

#[test]
fn client_add_list_and_revoke_are_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "ci", "--", "cargo", "test"])?,
        &context,
        &mut Vec::new(),
    )?;
    let public_key = "11".repeat(32);
    let mut add_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "client",
            "add",
            "ci_bot",
            "--pubkey",
            &public_key,
            "--action",
            "run-policy",
            "--action",
            "redact",
            "--policy",
            "ci",
        ])?,
        &context,
        &mut add_output,
    )?;

    let add_output = String::from_utf8(add_output)?;
    assert!(add_output.contains("client: ci_bot"));
    assert!(add_output.contains("private_key_material: never displayed"));
    assert!(!add_output.contains(&public_key));

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "client", "list"])?,
        &context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("ci_bot"));
    assert!(list_output.contains("actions=redact,run-policy"));
    assert!(list_output.contains("policies=ci"));
    assert!(list_output.contains("private_key_material: never displayed"));
    assert!(!list_output.contains(&public_key));

    let mut revoke_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "client", "revoke", "ci_bot"])?,
        &context,
        &mut revoke_output,
    )?;
    let revoke_output = String::from_utf8(revoke_output)?;
    assert!(revoke_output.contains("revoked_at:"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    assert_eq!(store.list_automation_clients(resolved.config.project_id.as_str(), false)?.len(), 0);
    assert!(
        store.list_automation_clients(resolved.config.project_id.as_str(), true)?[0]
            .revoked_at
            .is_some()
    );
    let mut statement = store
        .connection()
        .prepare("SELECT action, metadata_json FROM audit_log ORDER BY sequence")?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert!(rows.iter().any(|(action, _)| action == "CLIENT_ADD"));
    assert!(rows.iter().any(|(action, _)| action == "CLIENT_REVOKE"));
    for (_, metadata) in rows {
        assert!(!metadata.contains(&public_key));
    }
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn client_create_stores_locket_managed_private_key_refs() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--recovery-code",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut init_output,
    )?;
    let init_output = String::from_utf8(init_output)?;
    let recovery_code = recovery_code_from_output(&init_output)?.to_owned();
    let create_context = context_with_recovery_code(&context, &format!("{recovery_code}\n"));
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "ci", "--", "cargo", "test"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut keychain_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "client",
            "create",
            "managed_keychain",
            "--action",
            "run-policy",
            "--policy",
            "ci",
        ])?,
        &create_context,
        &mut keychain_output,
    )?;
    let keychain_output = String::from_utf8(keychain_output)?;
    assert!(keychain_output.contains("private_key_storage: os-keychain"));
    assert!(keychain_output.contains("private_key_material: never displayed"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let keychain_client = store
        .get_automation_client(resolved.config.project_id.as_str(), "managed_keychain")?
        .ok_or("keychain client should exist")?;
    let keychain_ref = store
        .get_automation_client_private_key_ref(&keychain_client.id)?
        .ok_or("keychain private key ref should exist")?;
    assert_eq!(keychain_ref.storage, "os-keychain");
    assert!(keychain_ref.keychain_account.as_deref().unwrap_or("").contains(&keychain_client.id));
    assert!(keychain_ref.local_path_hash.is_none());

    let mut file_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "client",
            "create",
            "managed_file",
            "--storage",
            "wrapped-local-file",
            "--action",
            "run-policy",
            "--policy",
            "ci",
        ])?,
        &create_context,
        &mut file_output,
    )?;
    let file_output = String::from_utf8(file_output)?;
    assert!(file_output.contains("private_key_storage: wrapped-local-file"));
    assert!(file_output.contains("private_key_material: never displayed"));

    let file_client = store
        .get_automation_client(resolved.config.project_id.as_str(), "managed_file")?
        .ok_or("file client should exist")?;
    let file_ref = store
        .get_automation_client_private_key_ref(&file_client.id)?
        .ok_or("file private key ref should exist")?;
    assert_eq!(file_ref.storage, "wrapped-local-file");
    assert!(file_ref.local_path_hash.is_some());
    assert!(file_ref.keychain_account.is_none());
    let envelope = crate::load_recovery_envelope(&directory.path().join(".locket/recovery"))?;
    assert!(envelope.entries.iter().any(|entry| {
        entry.entry_kind == format!("automation_client_private_key:{}", keychain_client.id)
            && entry.entry_id == keychain_client.id
    }));
    assert!(envelope.entries.iter().any(|entry| {
        entry.entry_kind == format!("automation_client_private_key:{}", file_client.id)
            && entry.entry_id == file_client.id
    }));
    let key_file =
        directory.path().join("automation-clients").join(format!("{}.key", file_client.id));
    let key_file_text = fs::read_to_string(&key_file)?;
    assert!(key_file_text.contains("wrapped_private_key"));
    assert!(!key_file_text.contains("private_key_material"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(fs::metadata(&key_file)?.permissions().mode() & 0o777, 0o600);
    }

    context.key_store.delete_master_key(resolved.config.project_id.as_str())?;
    context.automation_client_key_store.delete_client_key(&keychain_client.id)?;
    fs::remove_file(&key_file)?;
    let mut recover_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "recover"])?,
        &create_context,
        &mut recover_output,
    )?;
    let recover_output = String::from_utf8(recover_output)?;
    assert!(recover_output.contains("recovered: automation_client_private_keys=2 skipped=0"));
    assert!(key_file.exists());

    run_with_context(
        Cli::try_parse_from(["locket", "client", "revoke", "managed_file"])?,
        &context,
        &mut Vec::new(),
    )?;
    assert!(!key_file.exists());
    assert!(store.get_automation_client_private_key_ref(&file_client.id)?.is_none());
    Ok(())
}

#[test]
fn client_rejects_unsupported_actions_and_missing_policies()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let public_key = "22".repeat(32);
    assert_error_contains(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "client",
                "add",
                "ci_bot",
                "--pubkey",
                &public_key,
                "--action",
                "reveal",
                "--policy",
                "ci",
            ])?,
            &context,
            &mut Vec::new(),
        ),
        "InvalidPolicy",
    );
    assert_error_contains(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "client",
                "add",
                "ci_bot",
                "--pubkey",
                &public_key,
                "--action",
                "run-policy",
            ])?,
            &context,
            &mut Vec::new(),
        ),
        "at least one --policy",
    );

    let missing_policy_result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "client",
            "add",
            "ci_bot",
            "--pubkey",
            &public_key,
            "--action",
            "run-policy",
            "--policy",
            "missing",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = missing_policy_result else {
        return Err("client add with missing policy should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::PolicyNotFound.exit_code());
    assert!(error.to_string().contains("command policy not found: missing"));

    let missing_client_result = run_with_context(
        Cli::try_parse_from(["locket", "client", "revoke", "missing-client"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = missing_client_result else {
        return Err("client revoke with missing client should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::PolicyNotFound.exit_code());
    assert!(error.to_string().contains("automation client not found: missing-client"));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn sealed_bundle_export_verify_and_import_are_metadata_only()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://bundle-secret", "manual", 1_000)?;

    let mut device_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut device_output,
    )?;
    let descriptor = String::from_utf8(device_output)?
        .lines()
        .find_map(|line| line.strip_prefix("descriptor: "))
        .ok_or("missing descriptor")?
        .to_owned();
    let bundle_path = directory.path().join("dev.locket-bundle");

    let mut export_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--include-personal",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--include-audit",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut export_output,
    )?;
    let export_output = String::from_utf8(export_output)?;
    assert!(export_output.contains("bundle: exported"));
    assert!(export_output.contains("secret_count: 1"));
    assert!(export_output.contains("secret_version_count: 1"));
    assert!(export_output.contains("blob_count: 1"));
    assert!(export_output.contains("profile_key_count: 2"));
    assert!(export_output.contains("active_secret_count: 1"));
    assert!(export_output.contains("metadata_only: yes"));
    let bundle_bytes = fs::read(&bundle_path)?;
    assert!(bundle_bytes.starts_with(locket_core::BUNDLE_MAGIC));
    assert!(
        !bundle_bytes
            .windows("postgres://bundle-secret".len())
            .any(|window| window == b"postgres://bundle-secret")
    );
    assert!(!bundle_bytes.windows("DATABASE_URL".len()).any(|window| window == b"DATABASE_URL"));

    let mut verify_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "bundle",
            "verify",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut verify_output,
    )?;
    let verify_output = String::from_utf8(verify_output)?;
    assert!(verify_output.contains("bundle: valid"));
    // Per docs/specs/team-sync-recovery.md:213, when the verifying device
    // is also a recipient (this same context exported the bundle to its
    // own descriptor), `bundle verify` must attempt decryption and report
    // the truthful flag plus inner counts. Bundle verify remains
    // metadata-only — no rows are applied.
    assert!(verify_output.contains("decryptable_by_this_device: yes"));
    assert!(verify_output.contains("decrypted_secret_count: 1"));
    assert!(verify_output.contains("decrypted_blob_count: 1"));
    assert!(verify_output.contains("metadata_only: yes"));

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-local",
            "--include-audit",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("bundle: verified"));
    assert!(import_output.contains("import: decrypted"));
    assert!(import_output.contains("profiles: 1"));
    assert!(import_output.contains("secrets: 1"));
    assert!(import_output.contains("blobs: 1"));
    assert!(import_output.contains("command_policies: 0"));
    assert!(import_output.contains("metadata_only: yes"));

    assert_error_contains(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "export",
                "--sealed",
                "--include-personal",
                "--recipient",
                &descriptor,
                "--profile",
                "dev",
                "--output",
                bundle_path.to_str().ok_or("utf8 path")?,
            ])?,
            &context,
            &mut Vec::new(),
        ),
        "bundle output already exists",
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let mut statement = store
        .connection()
        .prepare("SELECT action, metadata_json FROM audit_log ORDER BY sequence")?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert!(rows.iter().any(|(action, _)| action == "BACKUP_EXPORT"));
    let verify_metadata = rows
        .iter()
        .find_map(|(action, metadata)| (action == "BUNDLE_VERIFY").then_some(metadata))
        .ok_or("missing BUNDLE_VERIFY audit row")?;
    let verify_metadata: serde_json::Value = serde_json::from_str(verify_metadata)?;
    assert_eq!(verify_metadata["bundle_schema_version"], serde_json::json!(1));
    assert_eq!(verify_metadata["profile_count"], serde_json::json!(1));
    assert_eq!(verify_metadata["recipient_count"], serde_json::json!(1));
    assert_eq!(verify_metadata["decryptable_by_this_device"], serde_json::json!(true));
    assert_eq!(verify_metadata["decrypted_profile_count"], serde_json::json!(1));
    assert_eq!(verify_metadata["decrypted_secret_count"], serde_json::json!(1));
    assert_eq!(verify_metadata["decrypted_blob_count"], serde_json::json!(1));
    assert_eq!(verify_metadata["decrypted_command_policy_count"], serde_json::json!(0));
    assert_eq!(verify_metadata["metadata_only"], serde_json::json!(true));
    assert!(verify_metadata.get("recipient_fingerprints").is_none());
    let import_metadata = rows
        .iter()
        .find_map(|(action, metadata)| (action == "BACKUP_IMPORT").then_some(metadata))
        .ok_or("missing BACKUP_IMPORT audit row")?;
    let import_metadata: serde_json::Value = serde_json::from_str(import_metadata)?;
    assert_eq!(import_metadata["profile_count"], serde_json::json!(1));
    assert_eq!(import_metadata["secret_count"], serde_json::json!(1));
    assert_eq!(import_metadata["blob_count"], serde_json::json!(1));
    assert_eq!(import_metadata["command_policy_count"], serde_json::json!(0));
    for (_, metadata) in rows {
        assert!(!metadata.contains("postgres://bundle-secret"));
    }
    Ok(())
}

#[test]
fn bundle_verify_rejects_unsupported_schema_as_config_error()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut device_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut device_output,
    )?;
    let descriptor = String::from_utf8(device_output)?
        .lines()
        .find_map(|line| line.strip_prefix("descriptor: "))
        .ok_or("missing descriptor")?
        .to_owned();
    let bundle_path = directory.path().join("unsupported.locket-bundle");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut bundle_bytes = fs::read(&bundle_path)?;
    bundle_bytes[locket_core::BUNDLE_MAGIC.len()] = 99;
    bundle_bytes[locket_core::BUNDLE_MAGIC.len() + 1] = 0;
    fs::write(&bundle_path, bundle_bytes)?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "bundle",
            "verify",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("expected unsupported schema error".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::MetadataInvalid.exit_code());
    assert!(error.to_string().contains("unsupported bundle schema version 99"));
    match error {
        crate::CliError::Typed { kind, .. } => {
            assert_eq!(kind, locket_core::LocketError::MetadataInvalid);
        }
        other => return Err(format!("expected typed MetadataInvalid error, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn import_bundle_without_device_private_key_fails_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://x", "manual", 1_000)?;

    let mut device_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut device_output,
    )?;
    let descriptor = String::from_utf8(device_output)?
        .lines()
        .find_map(|line| line.strip_prefix("descriptor: "))
        .ok_or("missing descriptor")?
        .to_owned();
    let bundle_path = directory.path().join("dev.locket-bundle");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    // Remove the device's wrapped private-key file so the import path
    // observes DevicePrivateKeyNotFound and returns BundleVerificationFailed.
    let devices_dir = directory.path().join("devices");
    if devices_dir.exists() {
        fs::remove_dir_all(&devices_dir)?;
    }

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-local",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("expected bundle verification error".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::BundleVerificationFailed.exit_code(),);
    assert!(
        error.to_string().contains("device private-key storage not initialized"),
        "unexpected error message: {error}"
    );
    Ok(())
}

#[test]
fn import_bundle_with_corrupt_age_payload_fails_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut device_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut device_output,
    )?;
    let descriptor = String::from_utf8(device_output)?
        .lines()
        .find_map(|line| line.strip_prefix("descriptor: "))
        .ok_or("missing descriptor")?
        .to_owned();
    let bundle_path = directory.path().join("dev.locket-bundle");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    // Flip a byte inside the encrypted payload (after the manifest header)
    // so age authenticated decryption fails. The container-level digest is
    // recomputed to bypass the manifest digest check and exercise the age
    // decrypt path.
    let bundle_bytes = fs::read(&bundle_path)?;
    let mut container = locket_core::BundleContainer::deserialize(&bundle_bytes)?;
    let payload_len = container.encrypted_payload.len();
    assert!(payload_len > 32, "encrypted payload unexpectedly short");
    // Flip a byte well inside the ciphertext to corrupt the auth tag.
    container.encrypted_payload[payload_len - 8] ^= 0xff;
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    <sha2::Sha256 as sha2::Digest>::update(&mut hasher, &container.encrypted_payload);
    container.manifest.payload_digest =
        crate::format_hex(<sha2::Sha256 as sha2::Digest>::finalize(hasher).as_slice());
    let rebuilt =
        locket_core::BundleContainer::new(container.manifest, container.encrypted_payload)?;
    fs::write(&bundle_path, rebuilt.serialize()?)?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-local",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("expected bundle decryption to fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::BundleVerificationFailed.exit_code(),);
    assert!(
        error.to_string().contains("bundle verification failed"),
        "unexpected error message: {error}"
    );
    Ok(())
}

#[test]
fn dangerous_profile_bundle_export_honors_configured_user_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &context_with_confirmation(&context, "dev\n"),
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "user_verification_required_for.dangerous_profile_switch",
            "true",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = crate::open_store(&context)?;
    let descriptor = store
        .get_active_local_device(
            crate::read_project_config(&directory.path().join("locket.toml"))?.project_id.as_str(),
        )?
        .map(|device| crate::encode_device_descriptor(&device))
        .transpose()?
        .ok_or("missing local device")?;
    let bundle_path = directory.path().join("dangerous.locket-bundle");
    let denied_context = context_with_user_verifier(
        &context_with_confirmation(&context, "export --sealed dev\n"),
        Arc::new(MemoryLocalUserVerifier::denying()),
    );
    let denied = run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &denied_context,
        &mut Vec::new(),
    );
    assert_error_contains(denied, "local user verification failed");
    assert!(!bundle_path.exists());

    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context_with_confirmation(&context, "export --sealed dev\n"),
        &mut Vec::new(),
    )?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'BACKUP_EXPORT'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["user_verification"]["required"], json!(true));
    assert_eq!(metadata["user_verification"]["satisfied"], json!(true));
    assert_eq!(metadata["user_verification"]["method"], json!("test"));
    Ok(())
}

#[test]
fn bundle_verify_rejects_tampered_digest() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut device_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut device_output,
    )?;
    let descriptor = String::from_utf8(device_output)?
        .lines()
        .find_map(|line| line.strip_prefix("descriptor: "))
        .ok_or("missing descriptor")?
        .to_owned();
    let bundle_path = directory.path().join("tampered.locket-bundle");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let bundle_bytes = fs::read(&bundle_path)?;
    let mut container = locket_core::BundleContainer::deserialize(&bundle_bytes)?;
    container.manifest.payload_digest = "0".repeat(64);
    fs::write(&bundle_path, container.serialize()?)?;
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "bundle",
            "verify",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "manifest digest mismatch");
    assert_eq!(crate::bundle_verification_error("failed").exit_code(), 110);
    Ok(())
}

#[test]
fn status_reports_not_initialized_without_project() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(Cli::try_parse_from(["locket"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("not initialized"));
    assert!(output.contains("next_action: run locket init"));
    Ok(())
}

#[test]
fn setup_guides_new_projects_without_writing_files() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(Cli::try_parse_from(["locket", "setup"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("setup: new_project"));
    assert!(output.contains("metadata_only: yes"));
    assert!(output.contains("locket init --name <name> --profile dev"));
    assert!(output.contains("locket import .env"));
    assert!(!directory.path().join("locket.toml").exists());
    Ok(())
}

#[test]
fn setup_guides_initialized_projects() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "setup", "status"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("setup: local_development"));
    assert!(output.contains("project: app"));
    assert!(output.contains("profile: dev"));
    assert!(output.contains("metadata_only: yes"));
    assert!(output.contains("locket policy add dev --"));
    assert!(output.contains("next_action: locket policy add dev -- <command>"));
    assert_eq!(output.lines().filter(|line| line.starts_with("- ")).count(), 1);
    Ok(())
}

#[test]
fn setup_agent_prints_paste_friendly_handoff_steps() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(Cli::try_parse_from(["locket", "setup", "agent"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("setup: agent_invite"));
    assert!(output.contains("metadata_only: yes"));
    assert!(output.contains("receiver: locket agent invite request"));
    assert!(
        output.contains(
            "maintainer: locket agent invite create <label> --device <descriptor> --profile dev --role developer --expires-in 7d"
        ),
        "{output}"
    );
    assert!(output.contains("receiver_accept: locket agent invite accept -"));
    Ok(())
}

#[test]
fn setup_share_points_to_agent_and_team_paths() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(Cli::try_parse_from(["locket", "setup", "share"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("setup: share_access"));
    assert!(output.contains("metadata_only: yes"));
    assert!(output.contains("agent_path: locket setup agent"));
    assert!(
        output.contains(
            "team_path: locket team invite <name> --device <descriptor> --profile dev --role developer"
        ),
        "{output}"
    );
    Ok(())
}

#[test]
fn status_reports_metadata_summary_and_next_action() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut init_output,
    )?;

    std::fs::write(directory.path().join("leak.txt"), "token=sk_test_sampleTokenValue123\n")?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let profile = store
        .get_profile_by_name(resolved.config.project_id.as_str(), "dev")?
        .ok_or("default profile should exist")?;
    store.insert_runtime_session(&locket_store::RuntimeSessionRecord {
        id: "lk_sess_status".to_owned(),
        project_id: resolved.config.project_id.to_string(),
        profile_id: profile.id,
        policy_name: Some("dev".to_owned()),
        process_id: 42,
        process_start_time: 900,
        started_at: 1_000,
        ended_at: None,
        exit_status: None,
        secret_names: vec!["API_KEY".to_owned()],
        spawn_audit_sequence: None,
        completion_audit_sequence: None,
    })?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "status"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("project: app"));
    assert!(output.contains("default_profile: dev"));
    assert!(output.contains("active_profile: unknown"));
    assert!(output.contains("lock_state: unknown"));
    assert!(output.contains("agent_state: unavailable"));
    assert!(output.contains("running_sessions: 1"));
    assert!(output.contains("scan_warnings: unknown"), "{output}");
    assert!(output.contains("trusted_root: yes"));
    assert!(output.contains("metadata_only: yes"));
    assert!(output.contains("next_action: run locket setup"));
    assert!(!output.contains("sk_test_sampleTokenValue123"));
    Ok(())
}

#[test]
fn status_redacts_project_and_profile_names_from_privacy_config()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut init_output,
    )?;
    let mut config_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut config_output,
    )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "status"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("project: project-"));
    assert!(output.contains("project_id: project-"));
    assert!(output.contains("default_profile: profile-"));
    assert!(output.contains("active_profile: unknown"));
    assert!(!output.contains("project: app"));
    assert!(!output.contains("default_profile: dev"));
    assert!(!output.contains("active_profile: dev"));
    Ok(())
}

#[test]
fn status_reports_cwd_matches_root_when_run_from_project_root()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "status"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("cwd: "), "{output}");
    assert!(output.contains("cwd_matches_root: yes"), "{output}");
    assert!(!output.contains("cwd_hint:"), "{output}");
    Ok(())
}

#[test]
fn status_shows_cwd_mismatch_when_run_from_subdirectory() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    let subdir = directory.path().join("sub");
    std::fs::create_dir_all(&subdir)?;
    let sub_context = RuntimeContext { cwd: subdir, ..context };

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "status"])?, &sub_context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("cwd_matches_root: no"), "{output}");
    assert!(
        output.contains(
            "cwd_hint: locket.toml resolved from a parent directory; commands act on the project at root:"
        ),
        "{output}"
    );
    Ok(())
}

#[test]
fn completion_generates_shell_script() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "completion", "bash"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("_locket"));
    assert!(output.contains("bootstrap"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn status_uses_live_profile_and_lock_snapshot_and_scans_only_when_requested()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::write(directory.path().join("leak.txt"), "token=sk_test_statusFixtureValue123\n")?;
    let project = crate::require_project(&context)?;
    let expected_project_id = project.config.project_id.to_string();
    for (snapshot, active, lock) in [
        (
            serde_json::json!({"project_id":project.config.project_id.as_str(),"profile_name":"staging","lock_state":"unlocked"}),
            "staging",
            "unlocked",
        ),
        (
            serde_json::json!({"project_id":null,"profile_name":null,"lock_state":"locked"}),
            "unknown",
            "unknown",
        ),
    ] {
        let socket = crate::agent_socket_path(&context);
        let listener = UnixListener::bind(&socket)?;
        let expected_project_id = expected_project_id.clone();
        let thread = std::thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|e| e.to_string())?;
            let mut buffer = Vec::new();
            let request = loop {
                if let Ok((request, _)) = locket_agent::decode_request_frame(
                    &buffer,
                    locket_agent::DEFAULT_MAX_MESSAGE_SIZE,
                ) {
                    break request;
                }
                let mut bytes = [0u8; 1024];
                let count = stream.read(&mut bytes).map_err(|e| e.to_string())?;
                if count == 0 {
                    return Err("status client closed early".to_owned());
                }
                buffer.extend_from_slice(&bytes[..count]);
            };
            if request.method().map_err(|e| e.to_string())? != locket_agent::AgentMethod::Status {
                return Err("expected read-only status request".to_owned());
            }
            if request.payload.get("project_id").and_then(serde_json::Value::as_str)
                != Some(expected_project_id.as_str())
            {
                return Err("status request must be project-scoped".into());
            }
            let frame = locket_agent::encode_frame(
                &locket_agent::SuccessEnvelope::new(request.id, snapshot),
                locket_agent::DEFAULT_MAX_MESSAGE_SIZE,
            )
            .map_err(|e| e.to_string())?;
            stream.write_all(&frame).map_err(|e| e.to_string())?;
            Ok(())
        });
        let mut output = Vec::new();
        run_with_context(Cli::try_parse_from(["locket", "status"])?, &context, &mut output)?;
        thread
            .join()
            .map_err(|_| "status fixture thread panicked")?
            .map_err(std::io::Error::other)?;
        std::fs::remove_file(socket)?;
        let output = String::from_utf8(output)?;
        assert!(output.contains(&format!("active_profile: {active}")), "{output}");
        assert!(output.contains(&format!("lock_state: {lock}")), "{output}");
        assert!(output.contains("scan_warnings: unknown"));
        assert!(!crate::agent_pid_path(&context).exists());
    }
    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "status", "--scan"])?, &context, &mut output)?;
    assert!(String::from_utf8(output)?.contains("scan_warnings: 1"));
    Ok(())
}

#[test]
fn context_json_returns_real_metadata_and_never_creates_missing_stores()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    assert!(
        run_with_context(
            Cli::try_parse_from(["locket", "context", "--json"])?,
            &context,
            &mut Vec::new()
        )
        .is_err()
    );
    assert!(!context.store_path.exists());
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "identity-fixture",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(
        &context,
        &test_secret_write_args("API_KEY"),
        "private-identity-fixture",
        "manual",
        1000,
    )?;
    let resolved = crate::require_project(&context)?;
    let store = crate::open_store(&context)?;
    let profile = crate::default_profile(&store, &resolved.config)?;
    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "context", "--json"])?, &context, &mut output)?;
    let identity: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(
        identity,
        serde_json::json!({"root":resolved.root,"project_id":resolved.config.project_id.as_str(),"project_name":"identity-fixture","profile_id":profile.id,"profile_name":"dev","store_path":context.store_path.canonicalize()?})
    );
    assert!(!String::from_utf8(output)?.contains("private-identity-fixture"));
    assert!(!crate::agent_socket_path(&context).exists());
    store
        .connection()
        .execute("UPDATE profiles SET name='missing-default' WHERE id=?1", [profile.id.as_str()])?;
    assert!(
        run_with_context(
            Cli::try_parse_from(["locket", "context", "--json"])?,
            &context,
            &mut Vec::new()
        )
        .is_err()
    );
    Ok(())
}
