#[allow(unused_imports)]
use super::*;
use locket_platform::LocalDevicePrivateKeyStorage;
use sha2::Digest;

#[test]
fn recovery_restore_rejects_mismatched_kdf_profile() -> Result<(), Box<dyn std::error::Error>> {
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
    let resolved = crate::require_project(&context)?;
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;
    let (kdf, mut envelope, code_bytes) =
        setup_recovery_envelope(&context, &project_id, &master_key)?;
    envelope.kdf_profile_id = "lk_kdf_other".to_owned();

    let result = crate::restore_from_recovery_code(
        &context,
        &mut Vec::new(),
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        true,
    );

    assert_error_contains(result, "kdf profile mismatch");
    Ok(())
}

#[test]
fn recovery_restore_recovers_master_key_from_envelope() -> Result<(), Box<dyn std::error::Error>> {
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
    let resolved = crate::require_project(&context)?;
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;
    let (kdf, envelope, code_bytes) = setup_recovery_envelope(&context, &project_id, &master_key)?;
    context.key_store.delete_master_key(&project_id)?;

    let mut recover_output = Vec::new();
    crate::restore_from_recovery_code(
        &context,
        &mut recover_output,
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        false,
    )?;

    assert_eq!(*context.key_store.load_master_key(&project_id)?, master_key);
    let recover_output = String::from_utf8(recover_output)?;
    assert!(recover_output.contains("recovered: master_key"));
    assert!(recover_output.contains("metadata_only: yes"));
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let (schema_version, command, metadata, previous_hmac, hmac): (
        u16,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
    ) = store.connection().query_row(
        "SELECT schema_version, command, metadata_json, previous_hmac, hmac
         FROM audit_log WHERE action = 'RECOVER'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    assert_eq!(schema_version, 1);
    assert_eq!(command, "recover");
    assert_eq!(previous_hmac.len(), locket_core::AUDIT_HMAC_LEN);
    assert_eq!(hmac.len(), locket_core::AUDIT_HMAC_LEN);
    let expected_checksum = crate::format_hex(&sha2::Sha256::digest(envelope.serialize()?));
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["schema_version"], 1);
    assert_eq!(metadata["action"], "RECOVER");
    assert_eq!(metadata["status"], "SUCCESS");
    assert_eq!(metadata["command"], "recover");
    assert_eq!(metadata["project_id"], project_id);
    assert_eq!(metadata["kdf_profile_id"], kdf.kdf_profile_id);
    assert_eq!(metadata["force"], false);
    assert_eq!(metadata["restored_entry_kinds"], serde_json::json!(["master_key"]));
    assert_eq!(metadata["restored_entry_counts"]["master_key"], 1);
    assert_eq!(metadata["envelope_checksum_sha256"], expected_checksum);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn recovery_restore_recovers_managed_automation_client_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let automation_keys = Arc::new(MemoryAutomationClientKeyStore::default());
    let mut context = test_context(&directory);
    context.automation_client_key_store = automation_keys.clone();
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
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "ci", "--", "cargo", "test"])?,
        &context,
        &mut Vec::new(),
    )?;

    let resolved = crate::require_project(&context)?;
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;
    let (kdf, mut envelope, code_bytes) =
        setup_recovery_envelope(&context, &project_id, &master_key)?;
    let salt = kdf.decode_salt()?;
    let unwrap_root =
        locket_crypto::derive_recovery_key_v1(&code_bytes, &salt, kdf.to_crypto_params())?;
    let os_client_id = "lk_client_recover_os";
    let file_client_id = "lk_client_recover_file";
    let revoked_client_id = "lk_client_recover_revoked";
    let os_client_key = [41_u8; locket_crypto::KEY_LEN];
    let file_client_key = [42_u8; locket_crypto::KEY_LEN];
    let revoked_client_key = [43_u8; locket_crypto::KEY_LEN];
    envelope.entries.push(crate::seal_recovery_envelope_entry(
        &unwrap_root,
        &kdf.kdf_profile_id,
        "automation_client_private_key",
        os_client_id,
        &os_client_key,
    )?);
    envelope.entries.push(crate::seal_recovery_envelope_entry(
        &unwrap_root,
        &kdf.kdf_profile_id,
        "automation_client_private_key",
        file_client_id,
        &file_client_key,
    )?);
    envelope.entries.push(crate::seal_recovery_envelope_entry(
        &unwrap_root,
        &kdf.kdf_profile_id,
        "automation_client_private_key",
        revoked_client_id,
        &revoked_client_key,
    )?);

    let mut store = locket_store::Store::open(directory.path().join("store.db"))?;
    insert_recovery_automation_client(
        &mut store,
        &project_id,
        os_client_id,
        "managed_os",
        "os-keychain",
        None,
    )?;
    insert_recovery_automation_client(
        &mut store,
        &project_id,
        file_client_id,
        "managed_file",
        "wrapped-local-file",
        None,
    )?;
    insert_recovery_automation_client(
        &mut store,
        &project_id,
        revoked_client_id,
        "managed_revoked",
        "os-keychain",
        Some(10_000),
    )?;
    drop(store);

    context.key_store.delete_master_key(&project_id)?;
    let mut recover_output = Vec::new();
    crate::restore_from_recovery_code(
        &context,
        &mut recover_output,
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        false,
    )?;

    assert_eq!(*context.key_store.load_master_key(&project_id)?, master_key);
    assert_eq!(automation_keys.load_client_key(os_client_id)?.as_deref(), Some(&os_client_key));
    assert_eq!(automation_keys.load_client_key(revoked_client_id)?.as_deref(), None);
    let key_file =
        directory.path().join("automation-clients").join(format!("{file_client_id}.key"));
    let key_file_text = fs::read_to_string(&key_file)?;
    assert!(key_file_text.contains("wrapped_private_key"));
    assert!(!key_file_text.contains("private_key_material"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(fs::metadata(&key_file)?.permissions().mode() & 0o777, 0o600);
    }
    let recover_output = String::from_utf8(recover_output)?;
    assert!(recover_output.contains("recovered: master_key"));
    assert!(recover_output.contains("recovered: automation_client_private_keys=2 skipped=1"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RECOVER' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(
        metadata["restored_entry_kinds"],
        serde_json::json!(["master_key", "automation_client_private_key"])
    );
    assert_eq!(metadata["restored_entry_counts"]["master_key"], 1);
    assert_eq!(metadata["restored_entry_counts"]["automation_client_private_key"], 2);
    assert_eq!(metadata["restored_entry_counts"]["automation_client_private_key_skipped"], 1);
    Ok(())
}

#[test]
fn recovery_restore_requires_device_entries_when_local_device_exists()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
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
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut Vec::new(),
    )?;
    let resolved = crate::require_project(&context)?;
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;
    let (kdf, envelope, code_bytes) = setup_recovery_envelope(&context, &project_id, &master_key)?;
    context.key_store.delete_master_key(&project_id)?;

    let result = crate::restore_from_recovery_code(
        &context,
        &mut Vec::new(),
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        false,
    );

    let Err(error) = result else {
        return Err("recovery without device entries must fail when a local device exists".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UnrecoverableVault.exit_code());
    assert!(error.to_string().contains("device_signing_private_key"));
    Ok(())
}

fn insert_recovery_automation_client(
    store: &mut locket_store::Store,
    project_id: &str,
    client_id: &str,
    name: &str,
    storage: &str,
    revoked_at: Option<i64>,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = locket_store::AutomationClientRecord {
        id: client_id.to_owned(),
        project_id: project_id.to_owned(),
        name: name.to_owned(),
        public_key: vec![7; 32],
        fingerprint: format!("fingerprint-{client_id}"),
        storage: storage.to_owned(),
        allowed_actions: vec!["run-policy".to_owned()],
        allowed_policies: vec!["ci".to_owned()],
        created_at: 1_000,
        last_used_at: None,
        revoked_at,
    };
    let keychain_service =
        (storage == "os-keychain").then(|| "dev.0xdoublesharp.locket".to_owned());
    let keychain_account =
        (storage == "os-keychain").then(|| format!("automation-client:{client_id}"));
    let local_path_hash = (storage == "wrapped-local-file").then(|| "path-hash".to_owned());
    let metadata_json = local_path_hash.as_deref().map_or_else(
        || {
            serde_json::json!({
                "schema_version": 1,
                "storage": storage,
            })
        },
        |path_hash| {
            serde_json::json!({
                "schema_version": 1,
                "storage": storage,
                "local_path_hash": path_hash,
            })
        },
    );
    let reference = locket_store::AutomationClientPrivateKeyRefRecord {
        client_id: client_id.to_owned(),
        storage: storage.to_owned(),
        keychain_service,
        keychain_account,
        local_path_hash,
        metadata_json: metadata_json.to_string(),
        created_at: 1_000,
        updated_at: 1_000,
    };
    store.insert_automation_client_with_private_key_ref(&client, Some(&reference))?;
    Ok(())
}

#[test]
fn recovery_restore_validation_failure_writes_no_recover_audit()
-> Result<(), Box<dyn std::error::Error>> {
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
    let resolved = crate::require_project(&context)?;
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;
    let (kdf, mut envelope, code_bytes) =
        setup_recovery_envelope(&context, &project_id, &master_key)?;
    envelope.kdf_profile_id = "lk_kdf_other".to_owned();

    let result = crate::restore_from_recovery_code(
        &context,
        &mut Vec::new(),
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        true,
    );

    assert_error_contains(result, "kdf profile mismatch");
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let recover_rows: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'RECOVER'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(recover_rows, 0);
    Ok(())
}

#[test]
fn recovery_rotate_creates_envelope_and_prints_full_code() -> Result<(), Box<dyn std::error::Error>>
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
    let initial_recovery_code = recovery_code_from_output(&init_output)?.to_owned();
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;

    let rotate_context = context_with_recovery_code(&context, &initial_recovery_code);
    let mut rotate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "recovery", "rotate"])?,
        &rotate_context,
        &mut rotate_output,
    )?;

    let rotate_output = String::from_utf8(rotate_output)?;
    assert!(rotate_output.contains("recovery_code_rotate: success"));
    assert!(rotate_output.contains("warning: terminal scrollback may retain this code"));
    assert!(rotate_output.contains("metadata_only: yes"));
    let code_line = recovery_code_from_output(&rotate_output)?;
    let code_bytes = locket_crypto::recovery_code_decode(code_line)?;
    let recovery_dir = directory.path().join(".locket").join("recovery");
    let kdf = crate::load_recovery_kdf_toml(&recovery_dir)?;
    let envelope = crate::load_recovery_envelope(&recovery_dir)?;
    assert_eq!(envelope.kdf_profile_id, kdf.kdf_profile_id);

    context.key_store.delete_master_key(&project_id)?;
    let resolved = crate::require_project(&context)?;
    crate::restore_from_recovery_code(
        &context,
        &mut Vec::new(),
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        false,
    )?;
    assert_eq!(*context.key_store.load_master_key(&project_id)?, master_key);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RECOVERY_ROTATE'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"kdf_profile_id\""));
    assert!(metadata.contains("\"command\":\"recovery rotate\""));
    assert!(metadata.contains("\"user_verification\""));
    assert!(metadata.contains("\"method\":\"test\""));
    assert!(!metadata.contains(code_line));
    Ok(())
}

#[test]
fn recovery_rotate_requires_fresh_user_verification_before_writing()
-> Result<(), Box<dyn std::error::Error>> {
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
    let initial_recovery_code =
        recovery_code_from_output(&String::from_utf8(init_output)?)?.to_owned();
    let recovery_dir = directory.path().join(".locket").join("recovery");
    let envelope_before = fs::read(recovery_dir.join("envelope.bin"))?;
    let kdf_before = fs::read_to_string(recovery_dir.join("kdf.toml"))?;
    let rejecting_context = context_with_user_verifier(
        &context_with_recovery_code(&context, &format!("{initial_recovery_code}\n")),
        Arc::new(MemoryLocalUserVerifier::denying()),
    );

    let mut rotate_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "recovery", "rotate"])?,
        &rejecting_context,
        &mut rotate_output,
    );

    let Err(error) = result else {
        return Err("recovery rotate must fail when user verification is denied".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UserVerificationFailed.exit_code());
    assert_eq!(rotate_output.len(), 0);
    assert_eq!(fs::read(recovery_dir.join("envelope.bin"))?, envelope_before);
    assert_eq!(fs::read_to_string(recovery_dir.join("kdf.toml"))?, kdf_before);
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let rotate_rows: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'RECOVERY_ROTATE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(rotate_rows, 0);
    Ok(())
}

#[test]
fn recovery_rotate_carries_device_keys_and_recover_restores_device_envelope()
-> Result<(), Box<dyn std::error::Error>> {
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
    let initial_recovery_code =
        recovery_code_from_output(&String::from_utf8(init_output)?)?.to_owned();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = crate::open_store(&context)?;
    let project_id = crate::require_project(&context)?.config.project_id;
    let device =
        store.get_active_local_device(project_id.as_str())?.ok_or("missing active local device")?;
    let storage = crate::commands::team::device::build_device_private_key_storage(
        &context,
        project_id.as_str(),
    )?;
    let original_device_key = storage.load(&device.id)?;

    let rotate_context =
        context_with_recovery_code(&context, &format!("{initial_recovery_code}\n"));
    let mut rotate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "recovery", "rotate"])?,
        &rotate_context,
        &mut rotate_output,
    )?;
    let rotate_output = String::from_utf8(rotate_output)?;
    let new_code = recovery_code_from_output(&rotate_output)?;
    let new_code_bytes = locket_crypto::recovery_code_decode(new_code)?;

    let recovery_dir = directory.path().join(".locket").join("recovery");
    let kdf = crate::load_recovery_kdf_toml(&recovery_dir)?;
    let envelope = crate::load_recovery_envelope(&recovery_dir)?;
    assert!(envelope.entries.iter().any(|entry| entry.entry_kind == "device_signing_private_key"));
    assert!(envelope.entries.iter().any(|entry| entry.entry_kind == "device_sealing_private_key"));

    context.key_store.delete_master_key(project_id.as_str())?;
    storage.delete(&device.id)?;
    storage.clone().for_signing().delete(&device.fingerprint)?;
    let resolved = crate::require_project(&context)?;
    let mut recover_output = Vec::new();
    crate::restore_from_recovery_code(
        &context,
        &mut recover_output,
        &resolved,
        &kdf,
        &envelope,
        &new_code_bytes,
        false,
    )?;

    assert_eq!(storage.load(&device.id)?.as_slice(), original_device_key.as_slice());
    let signer = crate::commands::team::device::load_device_signing_key(&context, &store, &device)?;
    assert_eq!(signer.verifying_key().as_bytes().as_slice(), device.signing_public_key);
    let recover_output = String::from_utf8(recover_output)?;
    assert!(recover_output.contains("recovered: device_private_keys=1"));
    Ok(())
}

#[test]
fn recover_with_corrupted_kdf_file_exits_with_metadata_invalid()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
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
        &mut Vec::new(),
    )?;
    let recovery_dir = directory.path().join(".locket/recovery");
    // A legacy two-file backup must still reject a damaged KDF.
    let legacy = crate::load_recovery_envelope(&recovery_dir)?;
    fs::write(recovery_dir.join("envelope.bin"), legacy.serialize()?)?;
    let kdf_path = recovery_dir.join("kdf.toml");
    std::fs::write(&kdf_path, "this-is-not-valid-toml = = = corrupted\n")?;

    let recover_context = context_with_recovery_code(&context, "ignored-code\n");
    let result = run_with_context(
        Cli::try_parse_from(["locket", "recover"])?,
        &recover_context,
        &mut Vec::new(),
    );

    let Err(error) = result else {
        return Err("recover with corrupted kdf.toml must fail".into());
    };
    assert_eq!(error.exit_code(), 64, "MetadataInvalid is in the input/config band");
    assert!(error.to_string().contains("recovery/kdf.toml"));
    Ok(())
}

#[test]
fn e2e_recovery_roundtrip_init_recover_and_rotate() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    // Step 1: init — captures the initial recovery code from output.
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
    let initial_code = recovery_code_from_output(&init_output)?.to_owned();
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;

    // Step 2: delete the keychain entry to simulate loss, then recover.
    context.key_store.delete_master_key(&project_id)?;
    assert!(context.key_store.load_master_key(&project_id).is_err());

    let recover_context = context_with_recovery_code(&context, &format!("{initial_code}\n"));
    let mut recover_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "recover"])?,
        &recover_context,
        &mut recover_output,
    )?;
    let recover_output = String::from_utf8(recover_output)?;
    assert!(recover_output.contains("recovered: master_key"));
    assert!(recover_output.contains("metadata_only: yes"));
    assert_eq!(*context.key_store.load_master_key(&project_id)?, master_key);

    // Step 3: rotate — produces a new code and new envelope.
    let rotate_context = context_with_recovery_code(&context, &format!("{initial_code}\n"));
    let mut rotate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "recovery", "rotate"])?,
        &rotate_context,
        &mut rotate_output,
    )?;
    let rotate_output = String::from_utf8(rotate_output)?;
    assert!(rotate_output.contains("recovery_code_rotate: success"));
    assert!(rotate_output.contains("warning: terminal scrollback may retain this code"));
    assert!(rotate_output.contains("metadata_only: yes"));

    // Step 4: verify the new code actually unlocks the envelope.
    let new_code = recovery_code_from_output(&rotate_output)?.to_owned();
    assert_ne!(new_code, initial_code, "rotate must produce a fresh code");

    context.key_store.delete_master_key(&project_id)?;
    let new_code_context = context_with_recovery_code(&context, &format!("{new_code}\n"));
    let mut new_code_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "recover"])?,
        &new_code_context,
        &mut new_code_output,
    )?;
    assert!(String::from_utf8(new_code_output)?.contains("recovered: master_key"));
    assert_eq!(*context.key_store.load_master_key(&project_id)?, master_key);
    Ok(())
}

#[test]
fn e2e_recover_refuses_when_keychain_valid_without_force() -> Result<(), Box<dyn std::error::Error>>
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
    let code = recovery_code_from_output(&init_output)?;

    let recover_context = context_with_recovery_code(&context, &format!("{code}\n"));
    let result = run_with_context(
        Cli::try_parse_from(["locket", "recover"])?,
        &recover_context,
        &mut Vec::new(),
    );

    let Err(error) = result else {
        return Err("recover without --force when keychain valid must fail".into());
    };
    assert_eq!(error.exit_code(), 67, "SecretAlreadyExists is exit 67");
    assert!(error.to_string().contains("master key already exists"));
    Ok(())
}

#[test]
fn e2e_recover_force_overwrites_existing_keychain_entry_and_records_audit()
-> Result<(), Box<dyn std::error::Error>> {
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
    let code = recovery_code_from_output(&init_output)?.to_owned();
    let (project_id, original_master_key) = test_project_id_and_master_key(&context)?;

    let recover_context = context_with_recovery_code(&context, &format!("{code}\n"));
    let mut recover_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "recover", "--force"])?,
        &recover_context,
        &mut recover_output,
    )?;
    let recover_output = String::from_utf8(recover_output)?;
    assert!(recover_output.contains("recovered: master_key"));
    assert!(recover_output.contains("metadata_only: yes"));
    // Key is the same since the envelope holds the same key.
    assert_eq!(*context.key_store.load_master_key(&project_id)?, original_master_key);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RECOVER' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"force\":true"));
    assert!(metadata.contains("\"action\":\"RECOVER\""));
    assert!(metadata.contains("\"status\":\"SUCCESS\""));
    assert!(metadata.contains("\"intact_keychain_override\":true"));
    assert!(metadata.contains("\"user_verification\""));
    assert!(metadata.contains("\"method\":\"test\""));
    Ok(())
}

#[test]
fn e2e_recover_force_requires_user_verification_before_overwrite()
-> Result<(), Box<dyn std::error::Error>> {
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
    let code = recovery_code_from_output(&init_output)?.to_owned();
    let (project_id, original_master_key) = test_project_id_and_master_key(&context)?;

    let recover_context = context_with_recovery_code(&context, &format!("{code}\n"));
    let rejecting_context =
        context_with_user_verifier(&recover_context, Arc::new(MemoryLocalUserVerifier::denying()));
    let mut recover_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "recover", "--force"])?,
        &rejecting_context,
        &mut recover_output,
    );
    let Err(error) = result else {
        return Err("recover --force must fail when user verification is denied".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UserVerificationFailed.exit_code());
    assert_eq!(recover_output.len(), 0);
    assert_eq!(*context.key_store.load_master_key(&project_id)?, original_master_key);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let recover_rows: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'RECOVER'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(recover_rows, 0);
    Ok(())
}

#[test]
fn init_and_rotate_do_not_emit_ansi_clear_when_stdout_is_not_a_terminal()
-> Result<(), Box<dyn std::error::Error>> {
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
    assert!(
        !init_output.contains(&0x1b),
        "init output must not contain ANSI escape when stdout is not a terminal"
    );

    let init_output = String::from_utf8(init_output)?;
    let initial_code = recovery_code_from_output(&init_output)?.to_owned();
    let rotate_context = context_with_recovery_code(&context, &initial_code);

    let mut rotate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "recovery", "rotate"])?,
        &rotate_context,
        &mut rotate_output,
    )?;
    assert!(
        !rotate_output.contains(&0x1b),
        "rotate output must not contain ANSI escape when stdout is not a terminal"
    );
    Ok(())
}

#[test]
fn legacy_recovery_rotates_disclosed_signing_seed_and_preserves_sealing_key()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app"])?,
        &context,
        &mut Vec::new(),
    )?;
    let resolved = crate::require_project(&context)?;
    let (project_id, master) = test_project_id_and_master_key(&context)?;
    let (kdf, mut envelope, code) = setup_recovery_envelope(&context, &project_id, &master)?;
    let root =
        locket_crypto::derive_recovery_key_v1(&code, &kdf.decode_salt()?, kdf.to_crypto_params())?;
    let store = crate::open_store(&context)?;
    let device =
        store.get_active_local_device(&project_id)?.ok_or("active local device missing")?;
    let storage =
        crate::commands::team::device::build_device_private_key_storage(&context, &project_id)?;
    let sealing = storage.load(&device.id)?;
    let leaked = [29_u8; 32];
    let sealing_public: [u8; 32] = device.sealing_public_key.as_slice().try_into()?;
    let fingerprint = crate::device_fingerprint_hex(&leaked, &sealing_public);
    store
        .connection()
        .execute("DELETE FROM device_signing_versions WHERE device_id = ?1", [&device.id])?;
    store.connection().execute(
        "UPDATE devices SET signing_public_key = ?1, fingerprint = ?2 WHERE id = ?3",
        rusqlite::params![leaked.as_slice(), fingerprint, device.id],
    )?;
    for (kind, bytes) in [
        ("device_signing_private_key", leaked.as_slice()),
        ("device_sealing_private_key", sealing.as_slice()),
    ] {
        envelope.entries.push(crate::seal_recovery_envelope_entry(
            &root,
            &kdf.kdf_profile_id,
            kind,
            &device.id,
            bytes,
        )?);
    }
    context.key_store.delete_master_key(&project_id)?;
    storage.delete(&device.id)?;
    crate::restore_from_recovery_code(
        &context,
        &mut Vec::new(),
        &resolved,
        &kdf,
        &envelope,
        &code,
        false,
    )?;
    let recovered =
        store.get_active_local_device(&project_id)?.ok_or("active local device missing")?;
    assert!(store.device_signing_is_v2(&device.id)?);
    assert_ne!(
        recovered.signing_public_key,
        ed25519_dalek::SigningKey::from_bytes(&leaked).verifying_key().as_bytes()
    );
    assert_eq!(*storage.load(&device.id)?, *sealing);
    assert!(store.device_matches_bundle_recipient(&recovered, &fingerprint)?);
    crate::commands::team::device::load_device_signing_key(&context, &store, &recovered)?;
    Ok(())
}

#[test]
fn initial_recovery_with_default_device_restores_identity() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--recovery-code",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    let code = locket_crypto::recovery_code_decode(recovery_code_from_output(&output)?)?;
    let resolved = crate::require_project(&context)?;
    let project = resolved.config.project_id.as_str();
    let device = crate::open_store(&context)?.get_active_local_device(project)?.ok_or("device")?;
    let storage =
        crate::commands::team::device::build_device_private_key_storage(&context, project)?;
    let sealing = storage.load(&device.id)?;
    let signing = storage.clone().for_signing().load(&device.fingerprint)?;
    let recovery_dir = directory.path().join(".locket/recovery");
    let kdf = crate::load_recovery_kdf_toml(&recovery_dir)?;
    let envelope = crate::load_recovery_envelope(&recovery_dir)?;
    storage.delete(&device.id)?;
    storage.clone().for_signing().delete(&device.fingerprint)?;
    context.key_store.delete_master_key(project)?;
    crate::restore_from_recovery_code(
        &context,
        &mut Vec::new(),
        &resolved,
        &kdf,
        &envelope,
        &code,
        false,
    )?;
    assert_eq!(*storage.load(&device.id)?, *sealing);
    assert_eq!(*storage.for_signing().load(&device.fingerprint)?, *signing);
    Ok(())
}

#[test]
fn recovery_rotation_rejection_or_audit_failure_preserves_previous_backup()
-> Result<(), Box<dyn std::error::Error>> {
    for fail_audit in [false, true] {
        let directory = tempdir()?;
        let context = test_context(&directory);
        let mut output = Vec::new();
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "init",
                "--recovery-code",
                "--no-device",
                "--no-passkey",
                "--name",
                "app",
            ])?,
            &context,
            &mut output,
        )?;
        let output = String::from_utf8(output)?;
        let old_code = recovery_code_from_output(&output)?;
        let dir = directory.path().join(".locket/recovery");
        let previous = fs::read(dir.join("envelope.bin"))?;
        let old_kdf = crate::load_recovery_kdf_toml(&dir)?;
        if fail_audit {
            crate::open_store(&context)?.connection().execute_batch(
                "CREATE TRIGGER deny_rotation BEFORE INSERT ON audit_log WHEN NEW.action='RECOVERY_ROTATE' BEGIN SELECT RAISE(ABORT, 'injected audit failure'); END;",
            )?;
        }
        let rotate = context_with_confirmation(
            &context_with_recovery_code(&context, old_code),
            if fail_audit { "app" } else { "not acknowledged" },
        );
        let result = crate::recovery_rotate_command(&rotate, &mut Vec::new());
        assert!(result.is_err(), "rotation must fail when confirmation or audit fails");
        assert_eq!(fs::read(dir.join("envelope.bin"))?, previous);
        assert_eq!(crate::load_recovery_kdf_toml(&dir)?.kdf_profile_id, old_kdf.kdf_profile_id);
    }
    Ok(())
}
