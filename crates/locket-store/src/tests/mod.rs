#![allow(clippy::redundant_pub_crate)]

use std::error::Error;

use tempfile::{TempDir, tempdir};

use crate::{
    DeviceRecord, PasskeyCredentialRecord, RuntimeSessionRecord, SecretBlobRecord,
    SecretFingerprintRecord, SecretRecord, SecretVersionRecord, Store,
};

mod audit;
mod automation;
mod command_policies;
mod devices;
mod discovery;
mod grants;
mod keys;
mod passkeys;
mod profiles;
mod projects;
mod roots;
mod runtime_sessions;
mod schema;
mod secrets;
mod team;

pub(super) struct TestStore {
    pub(super) directory: TempDir,
    pub(super) store: Store,
}

pub(super) fn open_initialized_store() -> Result<TestStore, Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("store.db");

    let mut store = Store::open(path)?;
    store.initialize_schema()?;

    Ok(TestStore { directory, store })
}

pub(super) fn insert_project_profile(store: &Store) -> Result<(), Box<dyn Error>> {
    let connection = store.connection();
    connection.execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
        [],
    )?;

    connection.execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_test', 'lk_proj_test', 'default', 0, 1)",
        [],
    )?;

    Ok(())
}

pub(super) fn insert_project_profile_secret(store: &Store) -> Result<(), Box<dyn Error>> {
    insert_project_profile(store)?;

    let connection = store.connection();
    connection.execute(
        "INSERT INTO secrets(
           id, project_id, profile_id, name, source, origin, required,
           current_version, state, created_at, updated_at
         )
         VALUES (
           'lk_sec_test', 'lk_proj_test', 'lk_prof_test', 'DATABASE_URL',
           'user-local', 'manual', 1, 1, 'active', 1, 1
         )",
        [],
    )?;

    Ok(())
}

pub(super) fn test_secret() -> SecretRecord {
    SecretRecord {
        id: "lk_sec_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: "lk_prof_test".to_owned(),
        name: "DATABASE_URL".to_owned(),
        source: "user-local".to_owned(),
        origin: "manual".to_owned(),
        current_version: 1,
        state: "active".to_owned(),
        created_at: 100,
        updated_at: 100,
        last_rotated_at: None,
        deleted_at: None,
    }
}

pub(super) fn test_secret_version() -> SecretVersionRecord {
    SecretVersionRecord {
        secret_id: "lk_sec_test".to_owned(),
        version: 1,
        source: "user-local".to_owned(),
        origin: "manual".to_owned(),
        state: "current".to_owned(),
        created_at: 100,
        deprecated_at: None,
        grace_until: None,
        purged_at: None,
    }
}

pub(super) fn test_secret_blob() -> SecretBlobRecord {
    SecretBlobRecord {
        secret_id: "lk_sec_test".to_owned(),
        version: 1,
        encrypted_dek: vec![1, 2, 3, 4],
        ciphertext: vec![5, 6, 7, 8],
        value_nonce: [9; 24],
        aad_schema_version: 1,
        created_at: 100,
    }
}

pub(super) fn test_secret_fingerprint() -> SecretFingerprintRecord {
    SecretFingerprintRecord {
        secret_id: "lk_sec_test".to_owned(),
        version: 1,
        fingerprint: vec![10, 11, 12, 13],
        created_at: 100,
    }
}

pub(super) fn test_runtime_session(id: &str, started_at: i64) -> RuntimeSessionRecord {
    RuntimeSessionRecord {
        id: id.to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: "lk_prof_test".to_owned(),
        policy_name: Some("dev".to_owned()),
        process_id: 42,
        process_start_time: started_at - 10,
        started_at,
        ended_at: None,
        exit_status: None,
        secret_names: vec!["DATABASE_URL".to_owned(), "API_TOKEN".to_owned()],
        spawn_audit_sequence: Some(1),
        completion_audit_sequence: None,
    }
}

pub(super) fn test_device() -> DeviceRecord {
    DeviceRecord {
        id: "lk_dev_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        member_id: None,
        name: "work-laptop".to_owned(),
        label: "Work Laptop".to_owned(),
        signing_public_key: vec![1; 32],
        sealing_public_key: vec![2; 32],
        fingerprint: "ab".repeat(32),
        safety_words: vec!["amber".to_owned(), "river".to_owned(), "north".to_owned()],
        local: true,
        created_at: 100,
        last_seen_at: Some(100),
        revoked_at: None,
    }
}

pub(super) fn test_passkey_credential() -> PasskeyCredentialRecord {
    PasskeyCredentialRecord {
        id: "lk_passkey_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        device_id: "lk_dev_test".to_owned(),
        member_id: Some("lk_member_test".to_owned()),
        label: "work-laptop".to_owned(),
        credential_id: vec![0xab, 0xcd, 0xef, 0x12, 0x34, 0x56],
        public_key: vec![0x42; 65],
        user_handle: vec![0x77; 32],
        transports: vec!["internal".to_owned(), "usb".to_owned()],
        prf_capable: true,
        webauthn_relying_party_id: crate::DEFAULT_WEBAUTHN_RELYING_PARTY_ID.to_owned(),
        backup_eligible: Some(true),
        backup_state: Some(false),
        created_at: 100,
        last_used_at: Some(150),
        revoked_at: None,
    }
}
