use locket_crypto::{KEY_LEN, NONCE_LEN};

use super::{
    KeyringMasterKeyStore, LocalDevicePrivateKeyStorage, LocalUserVerificationMethod,
    LocalUserVerificationRequest, LocalUserVerifier, MasterKeyStore, MemoryDevicePrivateKeyStorage,
    MemoryLocalUserVerifier, MemoryMasterKeyStore, MemoryPlatformPasskeyRegistrar,
    MockMasterKeyStore, MockMasterKeyStoreFailure, PasskeyAssertionContext, PasskeyRegistration,
    PassphraseFallbackMasterKeyStore, PlatformError, PlatformPasskeyRegistrar, ProcessBinding,
    RecoveryEnvelope, RecoveryEnvelopeEntry, RecoveryKdfToml, UnavailableLocalUserVerifier,
    UnavailablePlatformPasskeyRegistrar, WrappedLocalFileDevicePrivateKeyStorage,
    current_process_binding, decode_key, encode_key, load_recovery_envelope,
    load_recovery_kdf_toml, master_key_account, platform_name,
    process_binding_matches_live_process, save_recovery_envelope, save_recovery_state,
};

const PROJECT_ID: &str = "lk_proj_test";
const MASTER_KEY: [u8; KEY_LEN] = [42; KEY_LEN];

#[test]
fn platform_name_matches_rust_target_os() {
    assert_eq!(platform_name(), std::env::consts::OS);
}

#[test]
fn encodes_master_key_without_padding() -> Result<(), PlatformError> {
    let encoded = encode_key(&MASTER_KEY);

    assert!(!encoded.contains('='));
    assert_eq!(&*decode_key(encoded.as_bytes())?, &MASTER_KEY);
    Ok(())
}

#[test]
fn rejects_invalid_encoded_key_length() {
    assert!(matches!(decode_key(b"AA"), Err(PlatformError::InvalidMasterKey)));
}

#[test]
fn rejects_invalid_encoded_key_alphabet() {
    assert!(matches!(decode_key(b"not valid base64"), Err(PlatformError::InvalidMasterKey)));
    let mut malformed = encode_key(&MASTER_KEY);
    let last = malformed.len() - 1;
    malformed.replace_range(last.., "!");
    assert!(matches!(decode_key(malformed.as_bytes()), Err(PlatformError::InvalidMasterKey)));
}

#[cfg(unix)]
#[test]
fn write_user_only_file_refuses_existing_symlink() -> Result<(), PlatformError> {
    use std::fs;
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let referent = directory.path().join("referent");
    let path = directory.path().join("envelope");
    fs::write(&referent, b"original")?;
    symlink(&referent, &path)?;

    assert!(matches!(
        super::write_user_only_file(&path, b"replacement"),
        Err(PlatformError::Io(_))
    ));
    assert_eq!(fs::read(&referent)?, b"original");
    assert_eq!(fs::read_link(&path)?, referent);
    assert_eq!(fs::read_dir(directory.path())?.count(), 2);
    Ok(())
}

#[cfg(unix)]
#[test]
fn write_user_only_file_restricts_existing_permissions() -> Result<(), PlatformError> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("envelope");
    fs::write(&path, b"previous")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;

    super::fs_helpers::write_user_only_file(&path, b"replacement")?;

    assert_eq!(fs::read(&path)?, b"replacement");
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read_dir(directory.path())?.count(), 1);
    Ok(())
}

#[test]
fn memory_store_round_trips_and_deletes_master_key() -> Result<(), PlatformError> {
    let store = MemoryMasterKeyStore::default();

    store.store_master_key(PROJECT_ID, &MASTER_KEY)?;
    assert_eq!(&*store.load_master_key(PROJECT_ID)?, &MASTER_KEY);

    store.delete_master_key(PROJECT_ID)?;
    assert!(matches!(store.load_master_key(PROJECT_ID), Err(PlatformError::MasterKeyNotFound)));
    Ok(())
}

#[test]
fn memory_store_is_project_scoped() -> Result<(), PlatformError> {
    let store = MemoryMasterKeyStore::default();

    store.store_master_key(PROJECT_ID, &MASTER_KEY)?;

    assert!(matches!(
        store.load_master_key("lk_proj_other"),
        Err(PlatformError::MasterKeyNotFound)
    ));
    Ok(())
}

#[test]
fn memory_store_replaces_existing_project_key() -> Result<(), PlatformError> {
    let store = MemoryMasterKeyStore::default();
    let replacement = [7; KEY_LEN];

    store.store_master_key(PROJECT_ID, &MASTER_KEY)?;
    store.store_master_key(PROJECT_ID, &replacement)?;
    assert_eq!(*store.load_master_key(PROJECT_ID)?, replacement);
    store.store_master_key("lk_proj_other", &replacement)?;

    assert!(matches!(store.load_master_key(PROJECT_ID), Err(PlatformError::MasterKeyNotFound)));
    assert_eq!(&*store.load_master_key("lk_proj_other")?, &replacement);
    Ok(())
}

#[test]
fn mock_keychain_covers_success_and_error_paths() -> Result<(), PlatformError> {
    let store = MockMasterKeyStore::default();
    let replacement = [7; KEY_LEN];

    store.store_master_key(PROJECT_ID, &MASTER_KEY)?;
    assert_eq!(&*store.load_master_key(PROJECT_ID)?, &MASTER_KEY);
    store.store_master_key(PROJECT_ID, &replacement)?;
    assert_eq!(&*store.load_master_key(PROJECT_ID)?, &replacement);

    store.set_store_failure(Some(MockMasterKeyStoreFailure::MemoryPoisoned))?;
    assert!(matches!(
        store.store_master_key(PROJECT_ID, &MASTER_KEY),
        Err(PlatformError::MemoryPoisoned)
    ));
    store.set_store_failure(None)?;

    store.set_load_failure(Some(MockMasterKeyStoreFailure::InvalidMasterKey))?;
    assert!(matches!(store.load_master_key(PROJECT_ID), Err(PlatformError::InvalidMasterKey)));
    store.set_load_failure(None)?;

    store.set_delete_failure(Some(MockMasterKeyStoreFailure::MemoryPoisoned))?;
    assert!(matches!(store.delete_master_key(PROJECT_ID), Err(PlatformError::MemoryPoisoned)));
    assert_eq!(&*store.load_master_key(PROJECT_ID)?, &replacement);
    store.set_delete_failure(None)?;

    store.delete_master_key(PROJECT_ID)?;
    assert!(matches!(store.load_master_key(PROJECT_ID), Err(PlatformError::MasterKeyNotFound)));
    Ok(())
}

#[test]
fn keyring_account_is_project_scoped() {
    assert_eq!(master_key_account(PROJECT_ID), "master:lk_proj_test");
}

// Regression: keyring v3 ships with all OS backends behind cargo features.
// If `locket-platform` forgets to enable the per-OS feature, the crate
// silently falls back to a stub that returns Ok from `set_password` but
// `NoEntry` from `get_password`, which surfaced as `locket init` printing
// "master key not found" right after writing the master key. This test
// rejects that regression by performing a real store→load→delete round
// trip against the host keyring. Opt-in because it mutates the user's
// real keychain/secret-service and needs an unlocked session; CI that
// wants coverage sets `LOCKET_KEYRING_HOST_TEST=1`.
#[test]
fn keyring_store_round_trips_against_host_keychain() -> Result<(), PlatformError> {
    if std::env::var_os("LOCKET_KEYRING_HOST_TEST").is_none() {
        return Ok(());
    }
    crate::init_platform_keyring()?;

    let project_id = format!(
        "lk_proj_test_keyring_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let store = KeyringMasterKeyStore;

    assert!(matches!(store.load_master_key(&project_id), Err(PlatformError::MasterKeyNotFound)));

    store.store_master_key(&project_id, &MASTER_KEY)?;
    let loaded = match store.load_master_key(&project_id) {
        Ok(loaded) => loaded,
        Err(error) => {
            let _ignored = store.delete_master_key(&project_id);
            return Err(error);
        }
    };
    assert_eq!(&*loaded, &MASTER_KEY);

    store.delete_master_key(&project_id)?;
    assert!(matches!(store.load_master_key(&project_id), Err(PlatformError::MasterKeyNotFound)));
    Ok(())
}

#[test]
fn unavailable_user_verifier_fails_closed() {
    let verifier = UnavailableLocalUserVerifier;
    let request = LocalUserVerificationRequest::new("reveal", "Reveal DATABASE_URL");

    let result = verifier.verify_user(&request);

    assert!(matches!(result, Err(PlatformError::LocalUserVerificationUnavailable)));
}

#[test]
fn memory_user_verifier_supports_success_and_failure() -> Result<(), PlatformError> {
    let request = LocalUserVerificationRequest::new("unlock", "Unlock local vault");
    let success = MemoryLocalUserVerifier::allowing().verify_user(&request)?;

    assert_eq!(success.method, LocalUserVerificationMethod::Test);
    assert_eq!(success.platform, super::platform_name());
    assert!(matches!(
        MemoryLocalUserVerifier::denying().verify_user(&request),
        Err(PlatformError::LocalUserVerificationFailed)
    ));
    Ok(())
}

#[test]
fn memory_user_verifier_covers_unavailable_and_cancelled_paths() {
    let request = LocalUserVerificationRequest::new("reveal", "Reveal secret");

    assert!(matches!(
        MemoryLocalUserVerifier::unavailable().verify_user(&request),
        Err(PlatformError::LocalUserVerificationUnavailable)
    ));
    assert!(matches!(
        MemoryLocalUserVerifier::cancelled().verify_user(&request),
        Err(PlatformError::LocalUserVerificationFailed)
    ));
}

#[test]
fn current_process_binding_matches_current_process() -> Result<(), PlatformError> {
    let binding = current_process_binding()?;

    assert_eq!(binding.pid, std::process::id());
    assert_ne!(binding.process_start_time, "");
    assert!(process_binding_matches_live_process(&binding)?);
    Ok(())
}

#[test]
fn process_binding_rejects_start_time_mismatch() -> Result<(), PlatformError> {
    let current = current_process_binding()?;
    let stale = ProcessBinding::new(current.pid, format!("{}-stale", current.process_start_time));

    assert!(!process_binding_matches_live_process(&stale)?);
    Ok(())
}

#[test]
fn process_binding_rejects_missing_pid_without_trusting_pid() -> Result<(), PlatformError> {
    let missing = ProcessBinding::new(u32::MAX, "not-a-real-start-time");

    assert!(!process_binding_matches_live_process(&missing)?);
    Ok(())
}

#[test]
fn passphrase_fallback_round_trips_master_key() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store = PassphraseFallbackMasterKeyStore::new(directory.path());

    store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;

    assert!(store.contains_project(PROJECT_ID)?);
    let loaded = store.load_master_key(PROJECT_ID, b"fallback passphrase")?;
    assert_eq!(&*loaded, &MASTER_KEY);

    let envelope = std::fs::read_to_string(directory.path().join(format!("{PROJECT_ID}.toml")))?;
    assert!(!envelope.contains("fallback passphrase"));
    assert!(!envelope.contains(encode_key(&MASTER_KEY).as_str()));
    assert!(envelope.contains("algorithm = \"argon2id\""));
    assert!(envelope.contains("m_cost = 32768"));
    Ok(())
}

#[test]
fn passphrase_fallback_rejects_wrong_passphrase() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store = PassphraseFallbackMasterKeyStore::new(directory.path());

    store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;
    let result = store.load_master_key(PROJECT_ID, b"wrong passphrase");

    assert!(matches!(result, Err(PlatformError::InvalidPassphrase)));
    Ok(())
}

#[test]
fn passphrase_fallback_rejects_tampered_kdf_params() -> Result<(), PlatformError> {
    let cases = [
        ("m_cost", "m_cost = 32768", "m_cost = 1048576"),
        ("t_cost", "t_cost = 2", "t_cost = 100"),
        ("p_cost", "p_cost = 4", "p_cost = 128"),
        ("output_len", "output_len = 32", "output_len = 64"),
        ("salt", "salt = ", "salt = \"AA\""),
        ("wrapped_master_key", "wrapped_master_key = ", "wrapped_master_key = \"AA\""),
    ];

    for (case, from, to) in cases {
        let directory = tempfile::tempdir()?;
        let store = PassphraseFallbackMasterKeyStore::new(directory.path());

        store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;
        let envelope_path = directory.path().join(format!("{PROJECT_ID}.toml"));
        let envelope = std::fs::read_to_string(&envelope_path)?;
        let tampered = if from.ends_with("= ") {
            replace_toml_assignment(&envelope, from, to)
        } else {
            envelope.replace(from, to)
        };
        assert_ne!(tampered, envelope, "case {case} did not tamper the envelope");
        std::fs::write(&envelope_path, tampered)?;

        let result = store.load_master_key(PROJECT_ID, b"fallback passphrase");

        assert!(
            matches!(result, Err(PlatformError::InvalidPassphraseFallback)),
            "case {case} should reject before derivation/decrypt"
        );
    }
    Ok(())
}

fn replace_toml_assignment(text: &str, prefix: &str, replacement: &str) -> String {
    text.lines()
        .map(|line| if line.starts_with(prefix) { replacement } else { line })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn passphrase_fallback_delete_is_idempotent() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store = PassphraseFallbackMasterKeyStore::new(directory.path());

    store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;
    store.delete_master_key(PROJECT_ID)?;
    store.delete_master_key(PROJECT_ID)?;

    assert!(!store.contains_project(PROJECT_ID)?);
    assert!(matches!(
        store.load_master_key(PROJECT_ID, b"fallback passphrase"),
        Err(PlatformError::MasterKeyNotFound)
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn passphrase_fallback_uses_user_only_permissions() -> Result<(), PlatformError> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir()?;
    let store = PassphraseFallbackMasterKeyStore::new(directory.path());

    store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;

    let dir_mode = std::fs::metadata(directory.path())?.permissions().mode() & 0o777;
    let file_mode = std::fs::metadata(directory.path().join(format!("{PROJECT_ID}.toml")))?
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(file_mode, 0o600);
    Ok(())
}

#[test]
fn recovery_kdf_round_trips_and_rejects_tampering() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let salt = [3_u8; locket_crypto::RECOVERY_SALT_LEN];
    let kdf = RecoveryKdfToml::new_v1("lk_kdf_test".to_owned(), &salt, 456);
    let envelope = RecoveryEnvelope {
        kdf_profile_id: kdf.kdf_profile_id.clone(),
        created_at_unix_nanos: 456,
        entries: Vec::new(),
    };

    save_recovery_state(directory.path(), &kdf, &envelope)?;
    let loaded = load_recovery_kdf_toml(directory.path())?;

    assert_eq!(loaded.kdf_profile_id, "lk_kdf_test");
    assert_eq!(loaded.decode_salt()?, salt);

    let mut tampered = loaded;
    tampered.m_cost = locket_crypto::RECOVERY_M_COST + 1;
    assert!(matches!(
        save_recovery_state(directory.path(), &tampered, &envelope),
        Err(PlatformError::InvalidRecoveryEnvelope(_))
    ));
    Ok(())
}

#[test]
fn recovery_envelope_round_trips_and_rejects_tampering() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let envelope = RecoveryEnvelope {
        kdf_profile_id: "lk_kdf_test".to_owned(),
        created_at_unix_nanos: 123,
        entries: vec![RecoveryEnvelopeEntry {
            entry_kind: "master_key".to_owned(),
            entry_id: PROJECT_ID.to_owned(),
            nonce: [1_u8; NONCE_LEN],
            ciphertext: vec![2_u8; KEY_LEN + locket_crypto::TAG_LEN],
        }],
    };

    let salt = [3_u8; locket_crypto::RECOVERY_SALT_LEN];
    let kdf = RecoveryKdfToml::new_v1("lk_kdf_test".to_owned(), &salt, 123);
    save_recovery_state(directory.path(), &kdf, &envelope)?;
    let loaded = load_recovery_envelope(directory.path())?;

    assert_eq!(loaded.kdf_profile_id, envelope.kdf_profile_id);
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries[0].ciphertext, envelope.entries[0].ciphertext);

    let mut bytes = envelope.serialize()?;
    bytes[0] ^= 0xFF;
    assert!(matches!(
        RecoveryEnvelope::deserialize(&bytes),
        Err(PlatformError::InvalidRecoveryEnvelope(_))
    ));
    Ok(())
}

#[test]
fn recovery_envelope_rejects_impossible_entry_count_without_allocation() -> Result<(), PlatformError>
{
    let envelope = RecoveryEnvelope {
        kdf_profile_id: "lk_kdf_test".to_owned(),
        created_at_unix_nanos: 123,
        entries: Vec::new(),
    };
    let mut bytes = envelope.serialize()?;
    let count_offset = bytes.len() - 4;
    bytes[count_offset..].copy_from_slice(&u32::MAX.to_le_bytes());

    assert!(matches!(
        RecoveryEnvelope::deserialize(&bytes),
        Err(PlatformError::InvalidRecoveryEnvelope(_))
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn recovery_files_use_user_only_permissions() -> Result<(), PlatformError> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir()?;
    let recovery_dir = directory.path().join("recovery");
    let salt = [4_u8; locket_crypto::RECOVERY_SALT_LEN];
    let kdf = RecoveryKdfToml::new_v1("lk_kdf_test".to_owned(), &salt, 456);
    let envelope = RecoveryEnvelope {
        kdf_profile_id: "lk_kdf_test".to_owned(),
        created_at_unix_nanos: 123,
        entries: vec![RecoveryEnvelopeEntry {
            entry_kind: "master_key".to_owned(),
            entry_id: PROJECT_ID.to_owned(),
            nonce: [1_u8; NONCE_LEN],
            ciphertext: vec![2_u8; KEY_LEN + locket_crypto::TAG_LEN],
        }],
    };

    save_recovery_state(&recovery_dir, &kdf, &envelope)?;

    let dir_mode = std::fs::metadata(&recovery_dir)?.permissions().mode() & 0o777;
    let envelope_mode =
        std::fs::metadata(recovery_dir.join("envelope.bin"))?.permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(envelope_mode, 0o600);
    Ok(())
}

const DEVICE_ID_A: &str = "lk_dev_aaa";
const DEVICE_ID_B: &str = "lk_dev_bbb";
const PRIVATE_KEY_A: [u8; KEY_LEN] = [7; KEY_LEN];
const PRIVATE_KEY_B: [u8; KEY_LEN] = [8; KEY_LEN];

fn populated_master_key_store(
    master_key: [u8; KEY_LEN],
) -> Result<std::sync::Arc<MemoryMasterKeyStore>, PlatformError> {
    let store = std::sync::Arc::new(MemoryMasterKeyStore::default());
    store.store_master_key(PROJECT_ID, &master_key)?;
    Ok(store)
}

#[test]
fn wrapped_device_private_key_round_trips_and_writes_user_only_files() -> Result<(), PlatformError>
{
    let directory = tempfile::tempdir()?;
    let store = populated_master_key_store(MASTER_KEY)?;
    let storage = WrappedLocalFileDevicePrivateKeyStorage::new(
        directory.path(),
        PROJECT_ID,
        store as std::sync::Arc<dyn MasterKeyStore + Send + Sync>,
    );
    storage.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;
    let loaded = storage.load(DEVICE_ID_A)?;
    assert_eq!(&*loaded, &PRIVATE_KEY_A);

    let envelope_path = storage.envelope_path(DEVICE_ID_A)?;
    assert!(envelope_path.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&envelope_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let parent = envelope_path.parent().ok_or_else(|| PlatformError::InvalidProjectId)?;
        let dir_mode = std::fs::metadata(parent)?.permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
    }
    let serialized = std::fs::read_to_string(&envelope_path)?;
    assert!(!serialized.contains(&data_encoding::BASE64URL_NOPAD.encode(&PRIVATE_KEY_A)));
    Ok(())
}

#[test]
fn wrapped_device_private_key_load_returns_not_found_when_missing() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store = populated_master_key_store(MASTER_KEY)?;
    let storage = WrappedLocalFileDevicePrivateKeyStorage::new(
        directory.path(),
        PROJECT_ID,
        store as std::sync::Arc<dyn MasterKeyStore + Send + Sync>,
    );
    assert!(matches!(storage.load(DEVICE_ID_A), Err(PlatformError::DevicePrivateKeyNotFound)));
    Ok(())
}

#[test]
fn wrapped_device_private_key_rejects_load_with_wrong_master_key() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store_a = populated_master_key_store(MASTER_KEY)?;
    let storage_a = WrappedLocalFileDevicePrivateKeyStorage::new(
        directory.path(),
        PROJECT_ID,
        store_a as std::sync::Arc<dyn MasterKeyStore + Send + Sync>,
    );
    storage_a.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;

    let store_b = populated_master_key_store([99; KEY_LEN])?;
    let storage_b = WrappedLocalFileDevicePrivateKeyStorage::new(
        directory.path(),
        PROJECT_ID,
        store_b as std::sync::Arc<dyn MasterKeyStore + Send + Sync>,
    );
    let Err(err) = storage_b.load(DEVICE_ID_A) else {
        return Err(PlatformError::InvalidMasterKey);
    };
    assert!(
        matches!(err, PlatformError::DevicePrivateKeyIntegrityFailure(_)),
        "expected integrity failure, got {err:?}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn wrapped_device_private_key_rejects_world_readable_envelope() -> Result<(), PlatformError> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    let store = populated_master_key_store(MASTER_KEY)?;
    let storage = WrappedLocalFileDevicePrivateKeyStorage::new(
        directory.path(),
        PROJECT_ID,
        store as std::sync::Arc<dyn MasterKeyStore + Send + Sync>,
    );
    storage.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;
    let envelope_path = storage.envelope_path(DEVICE_ID_A)?;
    std::fs::set_permissions(&envelope_path, std::fs::Permissions::from_mode(0o644))?;
    let Err(err) = storage.load(DEVICE_ID_A) else {
        return Err(PlatformError::InvalidMasterKey);
    };
    assert!(
        matches!(err, PlatformError::DevicePrivateKeyPermissionsTooWide(0o644)),
        "expected permissions-too-wide error, got {err:?}"
    );
    Ok(())
}

#[test]
fn wrapped_device_private_key_list_returns_sorted_device_ids() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store = populated_master_key_store(MASTER_KEY)?;
    let storage = WrappedLocalFileDevicePrivateKeyStorage::new(
        directory.path(),
        PROJECT_ID,
        store as std::sync::Arc<dyn MasterKeyStore + Send + Sync>,
    );
    storage.store(DEVICE_ID_B, &PRIVATE_KEY_B)?;
    storage.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;
    let listed = storage.list()?;
    assert_eq!(listed, vec![DEVICE_ID_A.to_owned(), DEVICE_ID_B.to_owned()]);
    Ok(())
}

#[test]
fn wrapped_device_private_key_list_is_empty_when_directory_missing() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store = populated_master_key_store(MASTER_KEY)?;
    let storage = WrappedLocalFileDevicePrivateKeyStorage::new(
        directory.path(),
        PROJECT_ID,
        store as std::sync::Arc<dyn MasterKeyStore + Send + Sync>,
    );
    let listed = storage.list()?;
    assert_eq!(listed.len(), 0);
    Ok(())
}

#[test]
fn wrapped_device_private_key_delete_is_idempotent() -> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store = populated_master_key_store(MASTER_KEY)?;
    let storage = WrappedLocalFileDevicePrivateKeyStorage::new(
        directory.path(),
        PROJECT_ID,
        store as std::sync::Arc<dyn MasterKeyStore + Send + Sync>,
    );
    storage.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;
    storage.delete(DEVICE_ID_A)?;
    assert!(matches!(storage.load(DEVICE_ID_A), Err(PlatformError::DevicePrivateKeyNotFound)));
    storage.delete(DEVICE_ID_A)?;
    Ok(())
}

#[test]
fn memory_device_private_key_round_trips() -> Result<(), PlatformError> {
    let storage = MemoryDevicePrivateKeyStorage::default();
    storage.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;
    storage.store(DEVICE_ID_B, &PRIVATE_KEY_B)?;
    let loaded = storage.load(DEVICE_ID_A)?;
    assert_eq!(&*loaded, &PRIVATE_KEY_A);
    let listed = storage.list()?;
    assert_eq!(listed, vec![DEVICE_ID_A.to_owned(), DEVICE_ID_B.to_owned()]);
    storage.delete(DEVICE_ID_A)?;
    assert!(matches!(storage.load(DEVICE_ID_A), Err(PlatformError::DevicePrivateKeyNotFound)));
    Ok(())
}

#[test]
fn unavailable_passkey_registrar_reports_unsupported() {
    let registrar = UnavailablePlatformPasskeyRegistrar;
    assert!(matches!(
        registrar.register_passkey("label", "rp"),
        Err(PlatformError::PasskeyUnsupported)
    ));
    assert!(matches!(
        registrar.evaluate_prf(
            PasskeyAssertionContext {
                credential_id: &[1_u8; 4],
                relying_party_id: "rp",
                public_key: &[],
            },
            &[2_u8; 32]
        ),
        Err(PlatformError::PasskeyUnsupported)
    ));
}

#[test]
fn memory_passkey_registrar_round_trips_register_then_prf() -> Result<(), PlatformError> {
    let registration = PasskeyRegistration {
        credential_id: vec![0x01, 0x02, 0x03, 0x04],
        public_key: vec![0xaa, 0xbb],
        user_handle: vec![0xcc; 32],
        transports: vec!["internal".to_owned()],
        prf_capable: true,
        backup_eligible: Some(true),
        backup_state: Some(false),
    };
    let registrar = MemoryPlatformPasskeyRegistrar::allowing(registration.clone(), [5_u8; 32]);
    let result = registrar.register_passkey("label", "rp")?;
    assert_eq!(result.credential_id, registration.credential_id);
    let context = PasskeyAssertionContext {
        credential_id: &registration.credential_id,
        relying_party_id: "rp",
        public_key: &registration.public_key,
    };
    let prf = registrar.evaluate_prf(context, &[0xcc; 16])?;
    assert_eq!(*prf, [5_u8; 32]);
    assert!(matches!(
        registrar.evaluate_prf(
            PasskeyAssertionContext { credential_id: &[0x99; 4], ..context },
            &[0xcc; 16]
        ),
        Err(PlatformError::PasskeyNotFound)
    ));
    Ok(())
}

#[test]
fn memory_passkey_registrar_unsupported_outcome_blocks_register() {
    let registrar = MemoryPlatformPasskeyRegistrar::unsupported();
    assert!(matches!(
        registrar.register_passkey("label", "rp"),
        Err(PlatformError::PasskeyUnsupported)
    ));
}

#[test]
fn signing_storage_is_separate_and_rejects_sealing_envelope_substitution()
-> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let store = populated_master_key_store(MASTER_KEY)?;
    let sealing = WrappedLocalFileDevicePrivateKeyStorage::new(directory.path(), PROJECT_ID, store);
    let signing = sealing.clone().for_signing();
    sealing.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;
    signing.store(DEVICE_ID_A, &PRIVATE_KEY_B)?;
    assert_eq!(*sealing.load(DEVICE_ID_A)?, PRIVATE_KEY_A);
    assert_eq!(*signing.load(DEVICE_ID_A)?, PRIVATE_KEY_B);
    std::fs::copy(sealing.envelope_path(DEVICE_ID_A)?, signing.envelope_path(DEVICE_ID_A)?)?;
    assert!(signing.load(DEVICE_ID_A).is_err());
    Ok(())
}

#[test]
fn recovery_entry_updates_keep_the_stored_kdf_until_atomic_replacement() -> Result<(), PlatformError>
{
    let directory = tempfile::tempdir()?;
    let original_kdf =
        RecoveryKdfToml::new_v1("lk_kdf_old".into(), &[3; locket_crypto::RECOVERY_SALT_LEN], 1);
    let original = RecoveryEnvelope {
        kdf_profile_id: original_kdf.kdf_profile_id.clone(),
        created_at_unix_nanos: 1,
        entries: vec![],
    };
    // Entry updates need an existing container to take the KDF from.
    assert!(save_recovery_envelope(directory.path(), &original).is_err());
    save_recovery_state(directory.path(), &original_kdf, &original)?;
    save_recovery_envelope(directory.path(), &original)?;
    assert_eq!(
        load_recovery_kdf_toml(directory.path())?.decode_salt()?,
        original_kdf.decode_salt()?
    );
    let next_kdf =
        RecoveryKdfToml::new_v1("lk_kdf_next".into(), &[4; locket_crypto::RECOVERY_SALT_LEN], 2);
    assert!(save_recovery_state(directory.path(), &next_kdf, &original).is_err());
    assert_eq!(load_recovery_kdf_toml(directory.path())?.kdf_profile_id, "lk_kdf_old");
    let next = RecoveryEnvelope { kdf_profile_id: next_kdf.kdf_profile_id.clone(), ..original };
    save_recovery_state(directory.path(), &next_kdf, &next)?;
    assert_eq!(load_recovery_kdf_toml(directory.path())?.kdf_profile_id, "lk_kdf_next");
    assert_eq!(load_recovery_envelope(directory.path())?.kdf_profile_id, "lk_kdf_next");
    // Neither a header alone nor an envelope without the header is a recovery file.
    std::fs::write(directory.path().join("envelope.bin"), b"LOCKET-RECOVERY-STATE-V1\0")?;
    assert!(load_recovery_kdf_toml(directory.path()).is_err());
    std::fs::write(directory.path().join("envelope.bin"), next.serialize()?)?;
    assert!(load_recovery_envelope(directory.path()).is_err());
    Ok(())
}

#[test]
fn recovery_atomic_container_rejects_truncation_lengths_and_mismatched_metadata()
-> Result<(), PlatformError> {
    let directory = tempfile::tempdir()?;
    let kdf =
        RecoveryKdfToml::new_v1("lk_kdf_test".into(), &[3; locket_crypto::RECOVERY_SALT_LEN], 1);
    let envelope = RecoveryEnvelope {
        kdf_profile_id: kdf.kdf_profile_id.clone(),
        created_at_unix_nanos: 1,
        entries: vec![],
    };
    crate::save_recovery_state(directory.path(), &kdf, &envelope)?;
    let encoded = std::fs::read(directory.path().join("envelope.bin"))?;
    let magic = b"LOCKET-RECOVERY-STATE-V1\0";
    for end in magic.len()..encoded.len() {
        assert!(crate::decode_recovery_state(&encoded[..end]).is_err(), "truncation at {end}");
    }
    for size in [0, 16 * 1024 + 1, u32::MAX] {
        let mut bad = encoded.clone();
        bad[magic.len()..magic.len() + 4].copy_from_slice(&size.to_le_bytes());
        assert!(crate::decode_recovery_state(&bad).is_err());
    }
    let mut mismatched = encoded.clone();
    let at = mismatched
        .windows(b"lk_kdf_test".len())
        .position(|window| window == b"lk_kdf_test")
        .ok_or_else(|| PlatformError::InvalidRecoveryEnvelope("missing test id".into()))?;
    mismatched[at + b"lk_kdf_".len()] = b'X';
    assert!(crate::decode_recovery_state(&mismatched).is_err());
    assert!(crate::decode_recovery_state(&encoded).is_ok());
    assert!(crate::decode_recovery_state(&envelope.serialize()?).is_err());
    Ok(())
}

#[test]
fn wrapped_device_key_rejects_envelope_field_corruption() -> Result<(), PlatformError> {
    use std::fs;
    let directory = tempfile::tempdir()?;
    let store = populated_master_key_store(MASTER_KEY)?;
    let storage = WrappedLocalFileDevicePrivateKeyStorage::new(directory.path(), PROJECT_ID, store);
    storage.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;
    let path = storage.envelope_path(DEVICE_ID_A)?;
    let canonical = fs::read_to_string(&path)?;
    let assert_rejected = |text: &str, expected: &str| -> Result<(), PlatformError> {
        fs::write(&path, text)?;
        assert!(matches!(
            storage.load(DEVICE_ID_A),
            Err(PlatformError::DevicePrivateKeyIntegrityFailure(message))
                if message.contains(expected)
        ));
        Ok(())
    };
    assert_rejected("not valid TOML [", "malformed")?;

    for (field, value, expected) in [
        ("version", toml::Value::Integer(2), "unsupported device private-key envelope version"),
        (
            "algorithm",
            toml::Value::String("unknown".into()),
            "unsupported device private-key envelope algorithm",
        ),
        ("project_id", toml::Value::String("another_project".into()), "project_id mismatch"),
        ("device_id", toml::Value::String("another_device".into()), "device_id mismatch"),
        ("nonce", toml::Value::String("!".repeat(32)), "nonce is invalid"),
        ("wrapped_private_key", toml::Value::String("!".into()), "ciphertext is invalid"),
        (
            "wrapped_private_key",
            toml::Value::String("AA".into()),
            "ciphertext has unexpected length",
        ),
    ] {
        let mut envelope: toml::Table = toml::from_str(&canonical)?;
        assert!(envelope.insert(field.into(), value).is_some());
        assert_rejected(&toml::to_string(&envelope)?, expected)?;
    }
    Ok(())
}

#[test]
fn signing_key_storage_is_separate_and_signing_domain_is_authenticated() -> Result<(), PlatformError>
{
    use std::fs;
    let directory = tempfile::tempdir()?;
    let store = populated_master_key_store(MASTER_KEY)?;
    let sealing = WrappedLocalFileDevicePrivateKeyStorage::new(directory.path(), PROJECT_ID, store);
    let signing = sealing.clone().for_signing();
    sealing.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;
    signing.store(DEVICE_ID_A, &PRIVATE_KEY_B)?;
    assert_eq!(*sealing.load(DEVICE_ID_A)?, PRIVATE_KEY_A);
    assert_eq!(*signing.load(DEVICE_ID_A)?, PRIVATE_KEY_B);
    let sealing_path = sealing.envelope_path(DEVICE_ID_A)?;
    let signing_path = signing.envelope_path(DEVICE_ID_A)?;

    fs::copy(signing_path, sealing_path)?;
    assert!(matches!(
        sealing.load(DEVICE_ID_A),
        Err(PlatformError::DevicePrivateKeyIntegrityFailure(message)) if message.contains("authentication")
    ));
    assert!(matches!(signing.envelope_path("../outside"), Err(PlatformError::InvalidProjectId)));
    assert!(matches!(signing.envelope_path(""), Err(PlatformError::InvalidProjectId)));
    let debug = format!("{signing:?}");
    assert!(debug.contains(PROJECT_ID));
    assert!(!debug.contains("master_key_store"));
    Ok(())
}

#[test]
fn device_key_storage_filters_unrelated_files_and_propagates_io_errors() -> Result<(), PlatformError>
{
    use std::fs;
    let directory = tempfile::tempdir()?;
    let store = populated_master_key_store(MASTER_KEY)?;
    let storage = WrappedLocalFileDevicePrivateKeyStorage::new(directory.path(), PROJECT_ID, store);
    storage.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;
    let envelope = storage.envelope_path(DEVICE_ID_A)?;
    let devices = envelope.parent().ok_or(PlatformError::InvalidProjectId)?;
    fs::write(devices.join("notes"), b"unrelated")?;
    fs::write(devices.join("invalid device.priv"), b"unrelated")?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        fs::write(devices.join(std::ffi::OsStr::from_bytes(b"bad-\xff.priv")), b"unrelated")?;
    }
    assert_eq!(storage.list()?, [DEVICE_ID_A]);

    fs::remove_file(&envelope)?;
    crate::secure_directory(&envelope)?;
    assert!(matches!(storage.load(DEVICE_ID_A), Err(PlatformError::Io(_))));
    assert!(matches!(storage.delete(DEVICE_ID_A), Err(PlatformError::Io(_))));
    fs::remove_dir_all(devices)?;
    fs::write(devices, b"not a device directory")?;
    assert!(matches!(storage.list(), Err(PlatformError::Io(_))));
    #[cfg(unix)]
    assert!(matches!(storage.load(DEVICE_ID_A), Err(PlatformError::Io(_))));
    Ok(())
}

#[test]
fn default_verifier_rejects_a_blank_prompt_before_platform_authentication() {
    let request = LocalUserVerificationRequest::new("unlock", " \t");
    assert!(matches!(
        crate::default_local_user_verifier().verify_user(&request),
        Err(PlatformError::LocalUserVerificationFailed
            | PlatformError::LocalUserVerificationUnavailable)
    ));
}

#[test]
fn mock_passkey_registrars_expose_capability_and_missing_enrollment() -> Result<(), PlatformError> {
    assert!(!UnavailablePlatformPasskeyRegistrar.supports_registration());
    let unsupported = MemoryPlatformPasskeyRegistrar::unsupported();
    let failed = MemoryPlatformPasskeyRegistrar::auth_failed();
    assert!(!unsupported.supports_registration());
    assert!(failed.supports_registration());

    let id = [1, 2, 3];
    let context = PasskeyAssertionContext {
        credential_id: &id,
        relying_party_id: "locket.localhost",
        public_key: &[],
    };
    assert!(matches!(
        unsupported.evaluate_prf(context, &[0; 32]),
        Err(PlatformError::PasskeyUnsupported)
    ));
    assert!(matches!(
        failed.evaluate_prf(context, &[0; 32]),
        Err(PlatformError::PasskeyAuthFailed)
    ));
    let known = MemoryPlatformPasskeyRegistrar::with_known_credential([9; 32], id.to_vec());
    assert_eq!(*known.evaluate_prf(context, &[0; 32])?, [9; 32]);
    let other = MemoryPlatformPasskeyRegistrar::with_known_credential([41; 32], vec![4, 5]);
    assert_eq!(format!("{known:?}"), format!("{other:?}"));
    assert_eq!(format!("{known:?}"), "MemoryPlatformPasskeyRegistrar { .. }");
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn opens_only_regular_files_without_following_symlinks_or_waiting_on_fifos()
-> Result<(), PlatformError> {
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let file = directory.path().join("regular");
    let link = directory.path().join("link");
    let fifo = directory.path().join("fifo");
    fs::write(&file, b"regular contents")?;
    symlink(&file, &link)?;
    assert!(std::process::Command::new("/usr/bin/mkfifo").arg(&fifo).status()?.success());

    let mut contents = Vec::new();
    crate::fs_helpers::open_regular_file(&file)?.read_to_end(&mut contents)?;
    assert_eq!(contents, b"regular contents");
    assert!(crate::fs_helpers::open_regular_file(&link).is_err());
    let (opened, result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _sent = opened.send(crate::fs_helpers::open_regular_file(&fifo));
    });
    let result =
        result.recv_timeout(std::time::Duration::from_secs(2)).map_err(std::io::Error::other)?;
    assert_eq!(result.err().map(|error| error.kind()), Some(std::io::ErrorKind::InvalidInput));
    assert!(crate::fs_helpers::open_regular_file(directory.path()).is_err());
    Ok(())
}

#[test]
fn memory_store_debug_reveals_neither_keys_nor_identifiers() -> Result<(), PlatformError> {
    let master = MemoryMasterKeyStore::default();
    let device = MemoryDevicePrivateKeyStorage::default();
    let automation = crate::MemoryAutomationClientKeyStore::default();
    master.store_master_key(PROJECT_ID, &MASTER_KEY)?;
    device.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;
    crate::AutomationClientKeyStore::store_client_key(
        &automation,
        "lk_private_client",
        &MASTER_KEY,
    )?;

    assert_eq!(format!("{master:?}"), "MemoryMasterKeyStore { .. }");
    assert_eq!(format!("{device:?}"), "MemoryDevicePrivateKeyStorage { .. }");
    assert_eq!(format!("{automation:?}"), "MemoryAutomationClientKeyStore { .. }");
    Ok(())
}

#[cfg(unix)]
#[test]
fn passphrase_fallback_reports_storage_errors_for_a_directory_at_the_envelope_path()
-> Result<(), PlatformError> {
    let temp = tempfile::tempdir()?;
    let store = PassphraseFallbackMasterKeyStore::new(temp.path());
    std::fs::create_dir(temp.path().join(format!("{PROJECT_ID}.toml")))?;
    assert!(matches!(store.load_master_key(PROJECT_ID, b"fixture"), Err(PlatformError::Io(_))));
    assert!(matches!(store.delete_master_key(PROJECT_ID), Err(PlatformError::Io(_))));
    Ok(())
}

#[cfg(unix)]
#[test]
fn device_key_load_rejects_a_symlink_even_to_a_valid_envelope() -> Result<(), PlatformError> {
    use std::fs;
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir()?;
    let store = populated_master_key_store(MASTER_KEY)?;
    let storage = WrappedLocalFileDevicePrivateKeyStorage::new(directory.path(), PROJECT_ID, store);
    storage.store(DEVICE_ID_A, &PRIVATE_KEY_A)?;
    assert_eq!(*storage.load(DEVICE_ID_A)?, PRIVATE_KEY_A);
    let path = storage.envelope_path(DEVICE_ID_A)?;
    let referent = directory.path().join("original-envelope");
    fs::rename(&path, &referent)?;
    symlink(&referent, &path)?;

    assert!(matches!(
        storage.load(DEVICE_ID_A),
        Err(PlatformError::Io(error))
            if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
    ));
    Ok(())
}

#[test]
fn without_keyring_user_interaction_is_reentrant() {
    let nested = crate::without_keyring_user_interaction(|| {
        crate::without_keyring_user_interaction(|| 42_u8)
    });
    assert_eq!(nested, 42);
}
