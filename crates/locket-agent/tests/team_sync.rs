//! Independent-store authenticated onboarding and update regressions.
#![allow(unused_crate_dependencies)]
use ed25519_dalek::SigningKey;
use locket_agent::team_sync;
use locket_core::team_package::{
    DeviceIdentity, SignedStatement, TeamBlob, TeamMember, TeamProfile, TeamSecret, TeamStatement,
};
use locket_crypto::{
    KeyPurpose, KeyWrapAad, KeyWrapPurpose, SecretBlobAad, encrypt_secret_value_v1,
    key_wrap_aad_v1, secret_blob_aad_v1,
};
use locket_store::Store;

fn receiver(path: &std::path::Path) -> Result<Store, Box<dyn std::error::Error>> {
    let mut store = Store::open(path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("project", "project", 1)?;
    team_sync::store_key(&store, "project", None, KeyPurpose::Audit, &[22; 32], &[23; 32], 100)?;
    Ok(store)
}
fn fixture() -> Result<(TeamStatement, SigningKey, [u8; 32]), Box<dyn std::error::Error>> {
    let key = SigningKey::from_bytes(&[7; 32]);
    let owner = DeviceIdentity::new("owner-device".into(), key.verifying_key().to_bytes(), [8; 32]);
    let secret = [9; 32];
    let sealing =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret)).to_bytes();
    let recipient = DeviceIdentity::new(
        "receiver-device".into(),
        SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
        sealing,
    );
    let value_aad =
        secret_blob_aad_v1(&SecretBlobAad::new("project", "profile", "secret", "TOKEN", 1))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "project",
        "secret",
        Some("profile"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;
    let blob = encrypt_secret_value_v1(&[11; 32], "current-value", &value_aad, &wrap_aad)?;
    let statement = TeamStatement {
        v: 1,
        team_id: "team".into(),
        project_id: "project".into(),
        epoch: 1,
        previous_digest: String::new(),
        issued_at: 100,
        expires_at: 500,
        nonce: [4; 24],
        publisher: owner.clone(),
        recipient: recipient.clone(),
        members: vec![
            TeamMember {
                id: "owner-member".into(),
                name: "owner".into(),
                role: "owner".into(),
                profiles: vec!["profile".into()],
                device: owner,
                removed: false,
            },
            TeamMember {
                id: "receiver-member".into(),
                name: "receiver".into(),
                role: "developer".into(),
                profiles: vec!["profile".into()],
                device: recipient,
                removed: false,
            },
        ],
        profiles: vec![TeamProfile {
            id: "profile".into(),
            name: "dev".into(),
            dangerous: true,
            created_at: 1,
            key_epoch: 1,
            secret_key: [11; 32],
            fingerprint_key: [12; 32],
            secrets: vec![TeamSecret {
                id: "secret".into(),
                name: "TOKEN".into(),
                version: 1,
                deleted: false,
                created_at: 1,
                blob: Some(TeamBlob {
                    encrypted_dek: blob.encrypted_dek,
                    ciphertext: blob.ciphertext,
                    value_nonce: blob.value_nonce,
                    aad_schema_version: 1,
                }),
            }],
        }],
    };
    Ok((statement, key, secret))
}
#[test]
fn fresh_join_decrypts_current_values_without_team_or_pending_invite()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (statement, key, sealing) = fixture()?;
    insert_local(&store, &statement.recipient)?;
    let bytes = SignedStatement::sign(&statement, &key)?.seal(&statement.recipient.sealing_key)?;
    assert!(!bytes.windows(7).any(|w| w == b"project"));
    assert!(store.get_team_by_project("project")?.is_none());
    let result = team_sync::apply_package(
        &mut store,
        &bytes,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        150,
    )?;
    assert_eq!(result.applied, 1);
    let profile_key = team_sync::load_key(
        &store,
        "project",
        Some("profile"),
        KeyPurpose::ProfileSecret,
        &[22; 32],
    )?;
    assert_eq!(*profile_key, [11; 32]);
    let blob = store.get_blob("secret", 1)?.ok_or("missing imported current value")?;
    let aad = secret_blob_aad_v1(&SecretBlobAad::new("project", "profile", "secret", "TOKEN", 1))?;
    let wrap = key_wrap_aad_v1(&KeyWrapAad::new(
        "project",
        "secret",
        Some("profile"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;
    let value = locket_crypto::decrypt_secret_value_v1(
        &profile_key,
        &locket_crypto::EncryptedSecretValue {
            encrypted_dek: blob.encrypted_dek,
            ciphertext: blob.ciphertext,
            value_nonce: blob.value_nonce,
            aad_schema_version: 1,
        },
        &aad,
        &wrap,
    )?;
    assert_eq!(value.as_str(), "current-value");
    assert!(store.verify_audit_chain_read_only("project", &[23; 32])?.hmac_ok);
    let replay = team_sync::apply_package(
        &mut store,
        &bytes,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        None,
        150,
    )?;
    assert!(replay.duplicate);
    assert_eq!(team_sync::status(&store, "project")?.epoch, 1);
    Ok(())
}
#[test]
fn fork_rejection_and_invalid_blob_leave_prior_head_and_values()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (mut statement, key, sealing) = fixture()?;
    insert_local(&store, &statement.recipient)?;
    let signed = SignedStatement::sign(&statement, &key)?;
    let bytes = signed.seal(&statement.recipient.sealing_key)?;
    team_sync::apply_package(
        &mut store,
        &bytes,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        150,
    )?;
    statement.nonce = [5; 24];
    let fork = SignedStatement::sign(&statement, &key)?.seal(&statement.recipient.sealing_key)?;
    assert!(
        team_sync::apply_package(
            &mut store,
            &fork,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            None,
            150
        )
        .is_err()
    );
    assert_eq!(team_sync::status(&store, "project")?.epoch, 1);
    Ok(())
}

fn insert_local(store: &Store, d: &DeviceIdentity) -> Result<(), Box<dyn std::error::Error>> {
    store.insert_device(&locket_store::DeviceRecord {
        id: d.id.clone(),
        project_id: "project".into(),
        member_id: None,
        name: "local".into(),
        label: "local".into(),
        signing_public_key: d.signing_key.to_vec(),
        sealing_public_key: d.sealing_key.to_vec(),
        fingerprint: d.fingerprint.clone(),
        safety_words: vec![],
        local: true,
        created_at: 1,
        last_seen_at: None,
        revoked_at: None,
    })?;
    Ok(())
}

#[test]
fn value_conflict_advances_membership_then_keep_local_creates_override()
-> Result<(), Box<dyn std::error::Error>> {
    value_conflict_flow(true, false, false)
}

#[test]
fn value_conflict_take_team_restores_shared_value_without_local_override()
-> Result<(), Box<dyn std::error::Error>> {
    value_conflict_flow(false, false, false)
}

#[test]
fn stale_conflict_cannot_restore_a_profile_after_scope_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    value_conflict_flow(false, true, false)
}

#[test]
fn pending_profile_blocks_resolution_of_older_value_conflicts()
-> Result<(), Box<dyn std::error::Error>> {
    value_conflict_flow(false, false, true)
}

#[allow(clippy::too_many_lines)]
fn value_conflict_flow(
    keep_local: bool,
    revoke_scope: bool,
    hold_profile: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (mut statement, key, sealing) = fixture()?;
    insert_local(&store, &statement.recipient)?;
    let first = SignedStatement::sign(&statement, &key)?;
    team_sync::apply_package(
        &mut store,
        &first.seal(&statement.recipient.sealing_key)?,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        150,
    )?;
    store.connection().execute("UPDATE secrets SET current_version=2 WHERE id='secret'", [])?;
    store.connection().execute("INSERT INTO secret_versions(secret_id,version,source,origin,state,created_at) VALUES ('secret',2,'team-managed','manual','current',1)",[])?;
    let value_aad =
        secret_blob_aad_v1(&SecretBlobAad::new("project", "profile", "secret", "TOKEN", 2))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "project",
        "secret",
        Some("profile"),
        2,
        KeyWrapPurpose::SecretDek,
    ))?;
    let local = encrypt_secret_value_v1(&[11; 32], "my-local-edit", &value_aad, &wrap_aad)?;
    store.connection().execute(
        "INSERT INTO blobs VALUES ('secret',2,?1,?2,?3,1,1)",
        rusqlite::params![local.encrypted_dek, local.ciphertext, local.value_nonce.as_slice()],
    )?;
    statement.epoch = 2;
    statement.previous_digest = locket_core::team_package::digest(&first.statement);
    statement.nonce = [6; 24];
    let next = SignedStatement::sign(&statement, &key)?.seal(&statement.recipient.sealing_key)?;
    let result = team_sync::apply_package(
        &mut store,
        &next,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        None,
        150,
    )?;
    assert_eq!(result.conflicts, 1);
    assert_eq!(team_sync::status(&store, "project")?.epoch, 2);
    if hold_profile {
        let second = SignedStatement::open(&next, &sealing)?;
        statement.epoch = 3;
        statement.previous_digest = locket_core::team_package::digest(&second.statement);
        let pending =
            SignedStatement::sign(&statement, &key)?.seal(&statement.recipient.sealing_key)?;
        team_sync::apply_package_with_consent_guarded(
            &mut store,
            &pending,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            None,
            150,
            false,
            None,
        )?;
        assert!(
            team_sync::resolve_conflict(
                &mut store,
                "project",
                "TOKEN",
                false,
                &[22; 32],
                &sealing,
                &statement.recipient,
                150
            )
            .is_err()
        );
        assert_eq!(
            store
                .get_secret_by_source("project", "profile", "TOKEN", "team-managed")?
                .ok_or("local missing")?
                .current_version,
            2
        );
        assert!(store.verify_audit_chain_read_only("project", &[23; 32])?.hmac_ok);
        return Ok(());
    }
    if revoke_scope {
        let second = SignedStatement::open(&next, &sealing)?;
        statement.epoch = 3;
        statement.previous_digest = locket_core::team_package::digest(&second.statement);
        statement.members[1].profiles.clear();
        statement.profiles.clear();
        let revoked =
            SignedStatement::sign(&statement, &key)?.seal(&statement.recipient.sealing_key)?;
        team_sync::apply_package(
            &mut store,
            &revoked,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            None,
            150,
        )?;
        assert!(
            team_sync::resolve_conflict(
                &mut store,
                "project",
                "TOKEN",
                false,
                &[22; 32],
                &sealing,
                &statement.recipient,
                150
            )
            .is_err()
        );
        assert_eq!(team_sync::status(&store, "project")?.epoch, 3);
        assert_eq!(
            store
                .get_secret_by_source("project", "profile", "TOKEN", "team-managed")?
                .ok_or("missing local value")?
                .current_version,
            2
        );
        return Ok(());
    }
    team_sync::resolve_conflict(
        &mut store,
        "project",
        "TOKEN",
        keep_local,
        &[22; 32],
        &sealing,
        &statement.recipient,
        150,
    )?;
    assert_eq!(
        store.get_secret_by_source("project", "profile", "TOKEN", "user-local")?.is_some(),
        keep_local
    );
    assert_eq!(
        store
            .get_secret_by_source("project", "profile", "TOKEN", "team-managed")?
            .ok_or("team value missing")?
            .current_version,
        1
    );
    assert_eq!(team_sync::status(&store, "project")?.conflicts, 0);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn owner_poll_publishes_only_changes_and_offboarding_rotates_keys()
-> Result<(), Box<dyn std::error::Error>> {
    use locket_platform::{LocalDevicePrivateKeyStorage, MasterKeyStore};
    let dir = tempfile::tempdir()?;
    let mut owner_store = receiver(&dir.path().join("owner.db"))?;
    let (statement, signer, _) = fixture()?;
    insert_local(&owner_store, &statement.publisher)?;
    owner_store.insert_team(&locket_store::TeamRecord {
        id: "team".into(),
        project_id: "project".into(),
        name: "team".into(),
        created_at: 1,
        updated_at: 1,
    })?;
    owner_store.insert_team_member(
        "owner-member",
        "team",
        Some(&statement.publisher.id),
        "owner",
        "owner",
        1,
    )?;
    owner_store.insert_profile_if_absent("profile", "project", "dev", true, 1)?;
    team_sync::store_key(
        &owner_store,
        "project",
        Some("profile"),
        KeyPurpose::ProfileSecret,
        &[22; 32],
        &[11; 32],
        100,
    )?;
    team_sync::store_key(
        &owner_store,
        "project",
        Some("profile"),
        KeyPurpose::ProfileFingerprint,
        &[22; 32],
        &[12; 32],
        100,
    )?;
    let blob = statement.profiles[0].secrets[0].blob.as_ref().ok_or("fixture blob missing")?;
    owner_store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at) VALUES ('secret','project','profile','TOKEN','team-managed','manual',0,1,'active',1,1)",[])?;
    owner_store.connection().execute("INSERT INTO secret_versions(secret_id,version,source,origin,state,created_at) VALUES ('secret',1,'team-managed','manual','current',1)",[])?;
    owner_store.connection().execute(
        "INSERT INTO blobs VALUES ('secret',1,?1,?2,?3,1,1)",
        rusqlite::params![blob.encrypted_dek, blob.ciphertext, blob.value_nonce.as_slice()],
    )?;
    let value_aad =
        secret_blob_aad_v1(&SecretBlobAad::new("project", "profile", "secret", "TOKEN", 2))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "project",
        "secret",
        Some("profile"),
        2,
        KeyWrapPurpose::SecretDek,
    ))?;
    let next_blob = encrypt_secret_value_v1(&[11; 32], "second-value", &value_aad, &wrap_aad)?;
    owner_store
        .connection()
        .execute("UPDATE secrets SET current_version=2 WHERE id='secret'", [])?;
    owner_store
        .connection()
        .execute("UPDATE secret_versions SET state='deprecated' WHERE secret_id='secret'", [])?;
    owner_store.connection().execute("INSERT INTO secret_versions(secret_id,version,source,origin,state,created_at) VALUES ('secret',2,'team-managed','manual','current',2)", [])?;
    owner_store.connection().execute(
        "INSERT INTO blobs VALUES ('secret',2,?1,?2,?3,1,2)",
        rusqlite::params![
            next_blob.encrypted_dek,
            next_blob.ciphertext,
            next_blob.value_nonce.as_slice()
        ],
    )?;
    for (version, value) in [(1, "current-value"), (2, "second-value")] {
        let fp = locket_crypto::secret_fingerprint_v1(&[12; 32], value)?;
        owner_store.connection().execute(
            "INSERT INTO fingerprints VALUES ('secret',?1,?2,1)",
            rusqlite::params![version, fp.as_slice()],
        )?;
    }
    team_sync::initialize_owner(&mut owner_store, "project", &statement.publisher, 100)?;
    for (role, profiles, reason) in [
        ("owner", vec!["profile".into()], "invalid recipient or role"),
        ("developer", vec!["foreign-profile".into()], "profile outside project"),
        (
            "developer",
            vec!["profile".into(), "profile".into()],
            "recipient revoked or duplicate scope",
        ),
    ] {
        assert!(matches!(team_sync::add_recipient(
            &mut owner_store, "project", &statement.recipient, "receiver", role, &profiles, 100,
        ), Err(team_sync::SyncError::Rejected(message)) if message == reason));
        assert!(owner_store.find_device("project", &statement.recipient.id)?.is_none());
    }
    team_sync::add_recipient(
        &mut owner_store,
        "project",
        &statement.recipient,
        "receiver",
        "developer",
        &["profile".into()],
        100,
    )?;
    let third_secret = x25519_dalek::StaticSecret::from([30; 32]);
    let third = DeviceIdentity::new(
        "third-device".into(),
        SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        x25519_dalek::PublicKey::from(&third_secret).to_bytes(),
    );
    team_sync::add_recipient(
        &mut owner_store,
        "project",
        &third,
        "remaining",
        "developer",
        &["profile".into()],
        100,
    )?;
    let key_root = dir.path().join("keys");
    let folder = dir.path().join("exchange");
    std::fs::create_dir(&key_root)?;
    std::fs::create_dir(&folder)?;
    let memory = std::sync::Arc::new(locket_platform::MemoryMasterKeyStore::default());
    memory.store_master_key("project", &[22; 32])?;
    let storage =
        locket_platform::WrappedLocalFileDevicePrivateKeyStorage::new(&key_root, "project", memory);
    storage.for_signing().store(&statement.publisher.fingerprint, &signer.to_bytes())?;
    let inside_key_root = key_root.join("nested-share");
    std::fs::create_dir(&inside_key_root)?;
    assert!(
        matches!(team_sync::configure_folder(&owner_store, "project", &inside_key_root, &key_root, true),
        Err(team_sync::SyncError::Rejected(message)) if message.contains("must be separate"))
    );
    #[cfg(unix)]
    {
        let link = dir.path().join("shared-link");
        std::os::unix::fs::symlink(&folder, &link)?;
        assert!(
            matches!(team_sync::configure_folder(&owner_store, "project", &link, &key_root, true),
            Err(team_sync::SyncError::Rejected(message)) if message.contains("existing regular shared folder"))
        );
    }
    team_sync::configure_folder(&owner_store, "project", &folder, &key_root, false)?;
    assert!(matches!(team_sync::sync_folder(&mut owner_store, "project", &[22; 32], 150),
        Err(team_sync::SyncError::Rejected(message)) if message.contains("explicit folder consent")));
    assert_eq!(std::fs::read_dir(&folder)?.count(), 0);
    team_sync::configure_folder(&owner_store, "project", &folder, &key_root, true)?;
    assert_eq!(team_sync::sync_folder(&mut owner_store, "project", &[22; 32], 150)?.published, 2);
    assert_eq!(team_sync::sync_folder(&mut owner_store, "project", &[22; 32], 151)?.published, 0);
    let original_files = std::fs::read_dir(&folder)?
        .map(|entry| {
            let path = entry?.path();
            let bytes = std::fs::read(&path)?;
            Ok((path, bytes))
        })
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    for (path, _) in &original_files {
        std::fs::remove_file(path)?;
    }
    assert_eq!(team_sync::flush_outbox(&owner_store, "project")?, 2);
    for (path, bytes) in original_files {
        assert_eq!(std::fs::read(path)?, bytes);
    }
    // A corrupted old transport file cannot block the next delivery.
    let damaged: String = owner_store.connection().query_row(
        "SELECT filename FROM team_sync_outbox WHERE project_id='project' AND recipient=?1 LIMIT 1",
        [&third.fingerprint],
        |row| row.get(0),
    )?;
    std::fs::write(folder.join(&damaged), b"modified by folder writer")?;
    assert_eq!(team_sync::flush_outbox(&owner_store, "project")?, 1);
    // Repair the legacy device-removal path: revocation happened without rotating keys.
    owner_store.connection().execute(
        "UPDATE devices SET revoked_at=151000000000 WHERE id=?1",
        [&statement.recipient.id],
    )?;
    owner_store.connection().execute(
        "UPDATE team_members SET removed_at=151000000000 WHERE device_id=?1",
        [&statement.recipient.id],
    )?;
    assert!(team_sync::publish(&mut owner_store, "project", &[22; 32], &signer, 152).is_err());
    assert_eq!(
        team_sync::remove_member(&mut owner_store, "project", "receiver", &[22; 32], 152)?,
        vec!["TOKEN"]
    );
    assert!(matches!(team_sync::add_recipient(
        &mut owner_store, "project", &statement.recipient, "receiver", "developer",
        &["profile".into()], 153,
    ), Err(team_sync::SyncError::Rejected(message)) if message.contains("recipient revoked")));
    let new_key = team_sync::load_key(
        &owner_store,
        "project",
        Some("profile"),
        KeyPurpose::ProfileSecret,
        &[22; 32],
    )?;
    assert_ne!(*new_key, [11; 32]);
    let changed = owner_store.get_blob("secret", 1)?.ok_or("rotated blob missing")?;
    let wrap = key_wrap_aad_v1(&KeyWrapAad::new(
        "project",
        "secret",
        Some("profile"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;
    assert!(locket_crypto::unwrap_dek_v1(&[11; 32], &changed.encrypted_dek, &wrap).is_err());
    assert!(locket_crypto::unwrap_dek_v1(&new_key, &changed.encrypted_dek, &wrap).is_ok());
    let fingerprint_key = team_sync::load_key(
        &owner_store,
        "project",
        Some("profile"),
        KeyPurpose::ProfileFingerprint,
        &[22; 32],
    )?;
    assert_ne!(*fingerprint_key, [12; 32]);
    for (version, value) in [(1, "current-value"), (2, "second-value")] {
        let blob = owner_store.get_blob("secret", version)?.ok_or("retained blob missing")?;
        let wrap = key_wrap_aad_v1(&KeyWrapAad::new(
            "project",
            "secret",
            Some("profile"),
            version,
            KeyWrapPurpose::SecretDek,
        ))?;
        assert!(locket_crypto::unwrap_dek_v1(&[11; 32], &blob.encrypted_dek, &wrap).is_err());
        let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
            "project", "profile", "secret", "TOKEN", version,
        ))?;
        let actual = locket_crypto::decrypt_secret_value_v1(
            &new_key,
            &locket_crypto::EncryptedSecretValue {
                encrypted_dek: blob.encrypted_dek,
                ciphertext: blob.ciphertext,
                value_nonce: blob.value_nonce,
                aad_schema_version: blob.aad_schema_version,
            },
            &value_aad,
            &wrap,
        )?;
        assert_eq!(actual.as_str(), value);
        let actual_fp: Vec<u8> = owner_store.connection().query_row(
            "SELECT fingerprint FROM fingerprints WHERE secret_id='secret' AND version=?1",
            [version],
            |r| r.get(0),
        )?;
        assert_eq!(
            actual_fp,
            locket_crypto::secret_fingerprint_v1(&fingerprint_key, value)?.to_vec()
        );
    }
    assert_eq!(team_sync::sync_folder(&mut owner_store, "project", &[22; 32], 153)?.published, 1);
    assert_eq!(
        team_sync::sync_folder(&mut owner_store, "project", &[22; 32], 153 + 6 * 86400)?.published,
        1
    );
    let epoch: i64 = owner_store.connection().query_row(
        "SELECT epoch FROM team_sync_outbound WHERE project_id='project' AND recipient=?1",
        [&third.fingerprint],
        |r| r.get(0),
    )?;
    assert_eq!(epoch, 3);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let barrier = barrier.clone();
        let path = dir.path().join("owner.db");
        workers.push(std::thread::spawn(move || -> Result<usize, String> {
            let mut store = Store::open(path).map_err(|e| e.to_string())?;
            let signing = SigningKey::from_bytes(&[7; 32]);
            barrier.wait();
            team_sync::publish(&mut store, "project", &[22; 32], &signing, 153 + 12 * 86400)
                .map_err(|e| e.to_string())
        }));
    }
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().map_err(|_| "publisher panicked"))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(outcomes.iter().filter(|result| matches!(result, Ok(1))).count(), 1);
    let epoch: i64 = owner_store.connection().query_row(
        "SELECT epoch FROM team_sync_outbound WHERE project_id='project' AND recipient=?1",
        [&third.fingerprint],
        |row| row.get(0),
    )?;
    assert_eq!(epoch, 4);
    let packages: i64 = owner_store.connection().query_row(
        "SELECT COUNT(*) FROM team_sync_outbox WHERE project_id='project' AND recipient=?1",
        [&third.fingerprint],
        |row| row.get(0),
    )?;
    assert_eq!(packages, 4);
    let path = dir.path().join("owner.db");
    let changed: team_sync::CommitAuthorization = std::sync::Arc::new(move || {
        let other = Store::open(&path)?;
        other.connection().execute(
            "UPDATE secrets SET state='deleted',deleted_at=200000000000 WHERE id='secret'",
            [],
        )?;
        Ok(Box::new(()))
    });
    assert!(
        team_sync::publish_guarded(
            &mut owner_store,
            "project",
            &[22; 32],
            &signer,
            153 + 18 * 86400,
            Some(&changed)
        )
        .is_err()
    );
    let epoch: i64 = owner_store.connection().query_row(
        "SELECT epoch FROM team_sync_outbound WHERE project_id='project' AND recipient=?1",
        [&third.fingerprint],
        |row| row.get(0),
    )?;
    assert_eq!(epoch, 4, "stale profile snapshot must not publish after concurrent mutation");
    assert!(owner_store.verify_audit_chain_read_only("project", &[23; 32])?.hmac_ok);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn offline_receiver_recovers_expired_predecessor_and_fresh_join_accepts_current_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut established = receiver(&dir.path().join("established.db"))?;
    let mut fresh = receiver(&dir.path().join("fresh.db"))?;
    let (mut statement, signer, sealing) = fixture()?;
    insert_local(&established, &statement.recipient)?;
    insert_local(&fresh, &statement.recipient)?;
    let first = SignedStatement::sign(&statement, &signer)?;
    let bytes = first.seal(&statement.recipient.sealing_key)?;
    team_sync::apply_package(
        &mut established,
        &bytes,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        150,
    )?;
    statement.epoch = 2;
    statement.previous_digest = locket_core::team_package::digest(&first.statement);
    let second = SignedStatement::sign(&statement, &signer)?;
    let bytes = second.seal(&statement.recipient.sealing_key)?;
    assert!(
        team_sync::apply_package(
            &mut fresh,
            &bytes,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            Some(&statement.publisher.fingerprint),
            1_000_000
        )
        .is_err()
    );
    team_sync::apply_package(
        &mut established,
        &bytes,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        None,
        1_000_000,
    )?;
    statement.epoch = 3;
    statement.previous_digest = locket_core::team_package::digest(&second.statement);
    statement.issued_at = 1_000_000;
    statement.expires_at = 1_000_500;
    let bytes =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    team_sync::apply_package(
        &mut established,
        &bytes,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        None,
        1_000_000,
    )?;
    team_sync::apply_package(
        &mut fresh,
        &bytes,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        1_000_000,
    )?;
    assert_eq!(team_sync::status(&established, "project")?.epoch, 3);
    assert_eq!(team_sync::status(&fresh, "project")?.epoch, 3);
    let historical = first.seal(&statement.recipient.sealing_key)?;
    let ignored = team_sync::apply_package(
        &mut fresh,
        &historical,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        None,
        1_000_000,
    )?;
    assert!(ignored.duplicate);
    assert_eq!(team_sync::status(&fresh, "project")?.state, "verified");
    assert_eq!(team_sync::status(&fresh, "project")?.epoch, 3);
    statement.nonce = [99; 24];
    let equivocation =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    assert!(
        team_sync::apply_package(
            &mut fresh,
            &equivocation,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            None,
            1_000_000
        )
        .is_err()
    );
    assert_eq!(team_sync::status(&fresh, "project")?.state, "fork");
    assert!(established.verify_audit_chain_read_only("project", &[23; 32])?.hmac_ok);
    assert!(fresh.verify_audit_chain_read_only("project", &[23; 32])?.hmac_ok);
    Ok(())
}

#[test]
fn corrupt_authenticated_blob_rolls_back_bootstrap_without_partial_security_state()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (mut statement, signer, sealing) = fixture()?;
    insert_local(&store, &statement.recipient)?;
    statement.profiles[0].secrets[0].blob.as_mut().ok_or("missing fixture blob")?.ciphertext[0] ^=
        1;
    let bytes =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    assert!(
        team_sync::apply_package(
            &mut store,
            &bytes,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            Some(&statement.publisher.fingerprint),
            150
        )
        .is_err()
    );
    assert!(store.get_team_by_project("project")?.is_none());
    assert!(!store.list_profiles("project")?.iter().any(|profile| profile.id == "profile"));
    assert_eq!(team_sync::status(&store, "project")?.epoch, 0);
    assert_eq!(team_sync::status(&store, "project")?.owner_fingerprint, None);
    Ok(())
}

#[test]
fn initial_pin_scope_and_key_collision_rejections_leave_store_unchanged()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (mut statement, signer, sealing) = fixture()?;
    insert_local(&store, &statement.recipient)?;
    let bytes =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    for pin in [None, Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")] {
        assert!(
            team_sync::apply_package(
                &mut store,
                &bytes,
                &[22; 32],
                &sealing,
                &statement.recipient,
                "project",
                pin,
                150
            )
            .is_err()
        );
        assert!(store.get_team_by_project("project")?.is_none());
    }
    statement.members[1].profiles.clear();
    let outside_scope =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    assert!(
        team_sync::apply_package(
            &mut store,
            &outside_scope,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            Some(&statement.publisher.fingerprint),
            150
        )
        .is_err()
    );
    assert!(store.get_team_by_project("project")?.is_none());
    statement.members[1].profiles.push("profile".into());
    store.insert_profile_if_absent("profile", "project", "dev", false, 1)?;
    team_sync::store_key(
        &store,
        "project",
        Some("profile"),
        KeyPurpose::ProfileSecret,
        &[22; 32],
        &[99; 32],
        100,
    )?;
    store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at) VALUES ('personal','project','profile','PERSONAL','user-local','manual',0,1,'active',1,1)", [])?;
    assert!(
        team_sync::apply_package(
            &mut store,
            &bytes,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            Some(&statement.publisher.fingerprint),
            150
        )
        .is_err()
    );
    assert!(store.get_team_by_project("project")?.is_none());
    assert_eq!(
        *team_sync::load_key(
            &store,
            "project",
            Some("profile"),
            KeyPurpose::ProfileSecret,
            &[22; 32]
        )?,
        [99; 32]
    );
    assert!(store.get_secret_by_source("project", "profile", "PERSONAL", "user-local")?.is_some());
    assert_eq!(team_sync::status(&store, "project")?.epoch, 0);
    Ok(())
}

#[test]
fn missing_predecessor_waits_and_wrong_parent_stops_without_value_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (mut statement, signer, sealing) = fixture()?;
    insert_local(&store, &statement.recipient)?;
    let first = SignedStatement::sign(&statement, &signer)?;
    team_sync::apply_package(
        &mut store,
        &first.seal(&statement.recipient.sealing_key)?,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        150,
    )?;
    statement.epoch = 3;
    let gap = SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    assert!(
        team_sync::apply_package(
            &mut store,
            &gap,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            None,
            150
        )
        .is_err()
    );
    assert_eq!(team_sync::status(&store, "project")?.state, "verified");
    assert_eq!(team_sync::status(&store, "project")?.epoch, 1);
    statement.epoch = 2;
    statement.previous_digest = "wrong-parent".into();
    let wrong =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    assert!(
        team_sync::apply_package(
            &mut store,
            &wrong,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            None,
            150
        )
        .is_err()
    );
    assert_eq!(team_sync::status(&store, "project")?.state, "fork");
    assert_eq!(team_sync::status(&store, "project")?.epoch, 1);
    assert_eq!(
        store
            .get_secret_by_source("project", "profile", "TOKEN", "team-managed")?
            .ok_or("missing value")?
            .current_version,
        1
    );
    Ok(())
}

#[test]
fn folder_retries_clock_skew_and_pages_past_unrelated_files()
-> Result<(), Box<dyn std::error::Error>> {
    use locket_platform::{LocalDevicePrivateKeyStorage, MasterKeyStore};
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (mut statement, signer, sealing) = fixture()?;
    insert_local(&store, &statement.recipient)?;
    let first = SignedStatement::sign(&statement, &signer)?;
    team_sync::apply_package(
        &mut store,
        &first.seal(&statement.recipient.sealing_key)?,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        150,
    )?;
    let keys = dir.path().join("keys");
    let folder = dir.path().join("exchange");
    std::fs::create_dir(&keys)?;
    std::fs::create_dir(&folder)?;
    let memory = std::sync::Arc::new(locket_platform::MemoryMasterKeyStore::default());
    memory.store_master_key("project", &[22; 32])?;
    locket_platform::WrappedLocalFileDevicePrivateKeyStorage::new(&keys, "project", memory)
        .store(&statement.recipient.id, &sealing)?;
    team_sync::configure_folder(&store, "project", &folder, &keys, true)?;
    statement.epoch = 2;
    statement.previous_digest = locket_core::team_package::digest(&first.statement);
    statement.issued_at = 1000;
    statement.expires_at = 1400;
    let next =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    for index in 0..5000 {
        std::fs::write(folder.join(format!("junk-{index}.txt")), b"unrelated")?;
    }
    for index in 0..140 {
        std::fs::write(folder.join(format!("bad-{index:04}.lkpkg")), b"incomplete")?;
    }
    std::fs::write(folder.join("zzz-next.lkpkg"), next)?;
    for _ in 0..5 {
        let _ = team_sync::sync_folder(&mut store, "project", &[22; 32], 400)?;
    }
    assert_eq!(team_sync::status(&store, "project")?.epoch, 1);
    for _ in 0..5 {
        let _ = team_sync::sync_folder(&mut store, "project", &[22; 32], 1000)?;
    }
    assert_eq!(team_sync::status(&store, "project")?.epoch, 2);
    Ok(())
}

#[test]
fn commit_authorization_rejection_does_not_establish_trust_or_mark_a_fork()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut store = receiver(&directory.path().join("receiver.db"))?;
    let (mut statement, signer, sealing) = fixture()?;
    insert_local(&store, &statement.recipient)?;
    let rejected: team_sync::CommitAuthorization =
        std::sync::Arc::new(|| Err(team_sync::SyncError::Rejected("unlock expired".into())));
    let bytes =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    assert!(
        team_sync::apply_package_guarded(
            &mut store,
            &bytes,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            Some(&statement.publisher.fingerprint),
            150,
            Some(&rejected)
        )
        .is_err()
    );
    assert!(store.get_team_by_project("project")?.is_none());
    assert_eq!(team_sync::status(&store, "project")?.epoch, 0);
    team_sync::apply_package(
        &mut store,
        &bytes,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        150,
    )?;
    statement.nonce = [66; 24];
    let fork =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    assert!(
        team_sync::apply_package_guarded(
            &mut store,
            &fork,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            None,
            150,
            Some(&rejected)
        )
        .is_err()
    );
    assert_eq!(team_sync::status(&store, "project")?.state, "verified");
    assert_eq!(team_sync::status(&store, "project")?.epoch, 1);
    Ok(())
}

#[test]
fn local_profile_name_collision_does_not_block_authenticated_head()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (mut statement, signer, sealing) = fixture()?;
    insert_local(&store, &statement.recipient)?;
    let first = SignedStatement::sign(&statement, &signer)?;
    team_sync::apply_package(
        &mut store,
        &first.seal(&statement.recipient.sealing_key)?,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        150,
    )?;
    store.insert_profile_if_absent("local-prod", "project", "prod", false, 1)?;
    store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at) VALUES ('local-value','project','local-prod','LOCAL','user-local','manual',0,1,'deleted',1,1)",[])?;
    statement.epoch = 2;
    statement.previous_digest = locket_core::team_package::digest(&first.statement);
    let mut incoming = statement.profiles[0].clone();
    incoming.id = "incoming-prod".into();
    incoming.name = "prod".into();
    incoming.secrets.clear();
    statement.profiles.push(incoming);
    statement.members[1].profiles.push("incoming-prod".into());
    let bytes =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    team_sync::apply_package(
        &mut store,
        &bytes,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        None,
        150,
    )?;
    assert_eq!(team_sync::status(&store, "project")?.epoch, 2);
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Full independent-store collision/retention regression fixture.
async fn pending_profiles_preserve_security_keys_and_local_values_until_explicit_retry()
-> Result<(), Box<dyn std::error::Error>> {
    for reason in ["consent-required", "secret-name-collision", "profile-name-collision"] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("receiver.db");
        let mut store = receiver(&path)?;
        let (mut statement, signer, sealing) = fixture()?;
        insert_local(&store, &statement.recipient)?;
        let now = i64::try_from(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        )?;
        statement.issued_at = now - 1;
        statement.expires_at = now + 300;
        let first = SignedStatement::sign(&statement, &signer)?;
        team_sync::apply_package(
            &mut store,
            &first.seal(&statement.recipient.sealing_key)?,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            Some(&statement.publisher.fingerprint),
            now,
        )?;
        store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at) VALUES ('existing-local','project','profile','TOKEN','user-local','manual',0,1,'active',1,1)",[])?;
        store.connection().execute("INSERT INTO secret_versions(secret_id,version,source,origin,state,created_at) VALUES ('existing-local',1,'user-local','manual','current',1)",[])?;
        let local_aad = secret_blob_aad_v1(&SecretBlobAad::new(
            "project",
            "profile",
            "existing-local",
            "TOKEN",
            1,
        ))?;
        let local_wrap = key_wrap_aad_v1(&KeyWrapAad::new(
            "project",
            "existing-local",
            Some("profile"),
            1,
            KeyWrapPurpose::SecretDek,
        ))?;
        let local_blob =
            encrypt_secret_value_v1(&[11; 32], "personal-override", &local_aad, &local_wrap)?;
        store.connection().execute(
            "INSERT INTO blobs VALUES ('existing-local',1,?1,?2,?3,1,1)",
            rusqlite::params![
                local_blob.encrypted_dek,
                local_blob.ciphertext,
                local_blob.value_nonce.as_slice()
            ],
        )?;
        let local_fp = locket_crypto::secret_fingerprint_v1(&[12; 32], "personal-override")?;
        store.connection().execute(
            "INSERT INTO fingerprints VALUES ('existing-local',1,?1,1)",
            [local_fp.as_slice()],
        )?;
        statement.epoch = 2;
        statement.previous_digest = locket_core::team_package::digest(&first.statement);
        let profile = &mut statement.profiles[0];
        let secret = &profile.secrets[0];
        let wrap = key_wrap_aad_v1(&KeyWrapAad::new(
            "project",
            &secret.id,
            Some(&profile.id),
            secret.version,
            KeyWrapPurpose::SecretDek,
        ))?;
        let blob = profile.secrets[0].blob.as_mut().ok_or("missing blob")?;
        let dek = locket_crypto::unwrap_dek_v1(&[11; 32], &blob.encrypted_dek, &wrap)?;
        blob.encrypted_dek = locket_crypto::wrap_dek_v1(&[44; 32], &dek, &wrap)?;
        profile.secret_key = [44; 32];
        profile.fingerprint_key = [45; 32];
        profile.key_epoch = 2;
        let pending_id =
            if reason == "profile-name-collision" { "incoming-profile" } else { "profile" };
        if reason == "consent-required" {
            profile.dangerous = false; // Local dangerous marker remains true.
            let secret = &mut profile.secrets[0];
            secret.version = 2;
            let aad = secret_blob_aad_v1(&SecretBlobAad::new(
                "project", "profile", "secret", "TOKEN", 2,
            ))?;
            let wrap = key_wrap_aad_v1(&KeyWrapAad::new(
                "project",
                "secret",
                Some("profile"),
                2,
                KeyWrapPurpose::SecretDek,
            ))?;
            let next = encrypt_secret_value_v1(&[44; 32], "owner-next", &aad, &wrap)?;
            secret.blob = Some(TeamBlob {
                encrypted_dek: next.encrypted_dek,
                ciphertext: next.ciphertext,
                value_nonce: next.value_nonce,
                aad_schema_version: 1,
            });
        }

        if reason == "secret-name-collision" {
            store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at) VALUES ('local-collision','project','profile','NEW_TOKEN','team-managed','manual',0,2,'active',1,1)",[])?;
            for (version, value) in [(1, "local-old"), (2, "local-current")] {
                let aad = secret_blob_aad_v1(&SecretBlobAad::new(
                    "project",
                    "profile",
                    "local-collision",
                    "NEW_TOKEN",
                    version,
                ))?;
                let wrap = key_wrap_aad_v1(&KeyWrapAad::new(
                    "project",
                    "local-collision",
                    Some("profile"),
                    version,
                    KeyWrapPurpose::SecretDek,
                ))?;
                let blob = encrypt_secret_value_v1(&[11; 32], value, &aad, &wrap)?;
                store.connection().execute("INSERT INTO secret_versions(secret_id,version,source,origin,state,created_at) VALUES ('local-collision',?1,'team-managed','manual',?2,1)",rusqlite::params![version,if version==2 {"current"}else{"deprecated"}])?;
                store.connection().execute(
                    "INSERT INTO blobs VALUES ('local-collision',?1,?2,?3,?4,1,1)",
                    rusqlite::params![
                        version,
                        blob.encrypted_dek,
                        blob.ciphertext,
                        blob.value_nonce.as_slice()
                    ],
                )?;
                let fp = locket_crypto::secret_fingerprint_v1(&[12; 32], value)?;
                store.connection().execute(
                    "INSERT INTO fingerprints VALUES ('local-collision',?1,?2,1)",
                    rusqlite::params![version, fp.as_slice()],
                )?;
            }
            let mut incoming = profile.secrets[0].clone();
            incoming.id = "incoming-collision".into();
            incoming.name = "NEW_TOKEN".into();
            incoming.deleted = true;
            incoming.blob = None;
            profile.secrets.push(incoming);
        }
        if reason == "profile-name-collision" {
            store.insert_profile_if_absent("personal-profile", "project", "prod", false, 1)?;
            store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at) VALUES ('personal','project','personal-profile','PERSONAL','user-local','manual',0,1,'deleted',1,1)",[])?;
            let mut incoming = profile.clone();
            incoming.id = "incoming-profile".into();
            incoming.name = "prod".into();
            incoming.secrets.clear();
            statement.profiles.push(incoming);
            statement.members[1].profiles.push("incoming-profile".into());
        }
        let bytes =
            SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
        let result = team_sync::apply_package_with_consent_guarded(
            &mut store,
            &bytes,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            None,
            now,
            reason != "consent-required",
            None,
        )?;
        assert_eq!(result.pending_profiles, 1);
        assert_eq!(team_sync::status(&store, "project")?.epoch, 2);
        assert_eq!(
            team_sync::status(&store, "project")?
                .pending_profiles
                .get(pending_id)
                .map(String::as_str),
            Some(reason)
        );
        assert_eq!(
            *team_sync::load_key(
                &store,
                "project",
                Some("profile"),
                KeyPurpose::ProfileSecret,
                &[22; 32]
            )?,
            [44; 32]
        );
        let retained = store.get_blob("secret", 1)?.ok_or("retained blob missing")?;
        assert!(locket_crypto::unwrap_dek_v1(&[11; 32], &retained.encrypted_dek, &wrap).is_err());
        assert!(locket_crypto::unwrap_dek_v1(&[44; 32], &retained.encrypted_dek, &wrap).is_ok());
        let local_blob = store.get_blob("existing-local", 1)?.ok_or("local override lost")?;
        let local_value = locket_crypto::decrypt_secret_value_v1(
            &[44; 32],
            &locket_crypto::EncryptedSecretValue {
                encrypted_dek: local_blob.encrypted_dek,
                ciphertext: local_blob.ciphertext,
                value_nonce: local_blob.value_nonce,
                aad_schema_version: 1,
            },
            &local_aad,
            &local_wrap,
        )?;
        assert_eq!(
            local_value.as_str(),
            "personal-override",
            "held key rotation must preserve an existing local override"
        );
        let local_fp: Vec<u8> = store.connection().query_row(
            "SELECT fingerprint FROM fingerprints WHERE secret_id='existing-local' AND version=1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            local_fp,
            locket_crypto::secret_fingerprint_v1(&[45; 32], "personal-override")?.to_vec()
        );
        let pending: Vec<u8> = store.connection().query_row(
            "SELECT encrypted_package FROM team_sync_pending_packages WHERE project_id='project'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(pending, bytes);
        assert!(!pending.windows(13).any(|window| window == b"current-value"));
        let denied: team_sync::CommitAuthorization =
            std::sync::Arc::new(|| Err(team_sync::SyncError::Rejected("locked".into())));
        let audit_before: i64 = store.connection().query_row(
            "SELECT COUNT(*) FROM audit_log WHERE project_id='project'",
            [],
            |row| row.get(0),
        )?;
        let wrapped_before = store
            .get_key_by_scope("project", Some("profile"), KeyPurpose::ProfileSecret.as_str())?
            .ok_or("key missing")?;
        for _ in 0..2 {
            let held = team_sync::resume_pending_profiles_guarded(
                &mut store,
                "project",
                &[22; 32],
                &sealing,
                &statement.recipient,
                false,
                now,
                Some(&denied),
            )?;
            assert_eq!(held.pending_profiles, 1);
        }
        assert_eq!(
            store
                .get_key_by_scope("project", Some("profile"), KeyPurpose::ProfileSecret.as_str())?
                .ok_or("key missing")?,
            wrapped_before
        );
        assert_eq!(
            store.connection().query_row(
                "SELECT COUNT(*) FROM audit_log WHERE project_id='project'",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            audit_before
        );
        let duplicate = team_sync::apply_package(
            &mut store,
            &bytes,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            None,
            now,
        )?;
        assert!(duplicate.duplicate);
        assert_eq!(team_sync::status(&store, "project")?.pending_profiles.len(), 1);
        let agent = ReconciliationAgent::new(&path, &statement.recipient.id, &sealing).await?;
        let details = agent.status().await?.pending_details;
        assert_eq!(details.len(), 1);
        let dto = serde_json::to_string(&details)?;
        assert!(
            !dto.contains("current-value")
                && !dto.contains("secret_key")
                && !dto.contains("ciphertext")
        );
        if reason == "consent-required" {
            assert!(
                team_sync::resume_pending_profiles_guarded(
                    &mut store,
                    "project",
                    &[22; 32],
                    &sealing,
                    &statement.recipient,
                    true,
                    now,
                    Some(&denied)
                )
                .is_err()
            );
        }
        if reason == "secret-name-collision" {
            assert_eq!(details[0].colliding_secrets[0].id, "local-collision");
            assert!(
                team_sync::preserve_collision_as_override(
                    &mut store,
                    "project",
                    "profile",
                    "secret",
                    &[22; 32],
                    &sealing,
                    &statement.recipient,
                    now,
                    None
                )
                .is_err()
            );
            assert!(
                team_sync::preserve_collision_as_override(
                    &mut store,
                    "project",
                    "profile",
                    "local-collision",
                    &[22; 32],
                    &sealing,
                    &statement.recipient,
                    now,
                    Some(&denied)
                )
                .is_err()
            );
            store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at) VALUES ('existing-override','project','profile','NEW_TOKEN','user-local','manual',0,1,'deleted',1,1)",[])?;
            assert!(
                team_sync::preserve_collision_as_override(
                    &mut store,
                    "project",
                    "profile",
                    "local-collision",
                    &[22; 32],
                    &sealing,
                    &statement.recipient,
                    now,
                    None
                )
                .is_err()
            );
            assert!(
                store
                    .get_secret_by_source("project", "profile", "NEW_TOKEN", "user-local")?
                    .is_some()
            );
            store.connection().execute("DELETE FROM secrets WHERE id='existing-override'", [])?;
            let versions = store.list_secret_versions("local-collision")?;
            let blobs =
                [store.get_blob("local-collision", 1)?, store.get_blob("local-collision", 2)?];
            agent
                .reconcile(
                    pending_id,
                    locket_agent::TeamSyncAction::PreserveOverride {
                        local_secret_id: "local-collision".into(),
                    },
                )
                .await?;
            assert_eq!(
                store.list_secret_versions("local-collision")?,
                versions,
                "historical provenance is preserved"
            );
            assert_eq!(
                [store.get_blob("local-collision", 1)?, store.get_blob("local-collision", 2)?],
                blobs,
                "preserving an override does not re-encrypt or drop history"
            );
            for (index, value) in [(0, "local-old"), (1, "local-current")] {
                let version = u32::try_from(index + 1)?;
                let blob = blobs[index].as_ref().ok_or("history missing")?;
                let aad = secret_blob_aad_v1(&SecretBlobAad::new(
                    "project",
                    "profile",
                    "local-collision",
                    "NEW_TOKEN",
                    version,
                ))?;
                let wrap = key_wrap_aad_v1(&KeyWrapAad::new(
                    "project",
                    "local-collision",
                    Some("profile"),
                    version,
                    KeyWrapPurpose::SecretDek,
                ))?;
                let plain = locket_crypto::decrypt_secret_value_v1(
                    &[44; 32],
                    &locket_crypto::EncryptedSecretValue {
                        encrypted_dek: blob.encrypted_dek.clone(),
                        ciphertext: blob.ciphertext.clone(),
                        value_nonce: blob.value_nonce,
                        aad_schema_version: 1,
                    },
                    &aad,
                    &wrap,
                )?;
                assert_eq!(plain.as_str(), value);
            }
            let current = store
                .get_secret_by_source("project", "profile", "NEW_TOKEN", "user-local")?
                .ok_or("override missing")?;
            let mut next = store
                .list_secret_versions("local-collision")?
                .into_iter()
                .find(|version| version.version == 2)
                .ok_or("version missing")?;
            next.version = 3;
            next.source = "user-local".into();
            next.created_at = 151_000_000_000;
            let aad = secret_blob_aad_v1(&SecretBlobAad::new(
                "project",
                "profile",
                "local-collision",
                "NEW_TOKEN",
                3,
            ))?;
            let wrap = key_wrap_aad_v1(&KeyWrapAad::new(
                "project",
                "local-collision",
                Some("profile"),
                3,
                KeyWrapPurpose::SecretDek,
            ))?;
            let encrypted = encrypt_secret_value_v1(&[44; 32], "local-next", &aad, &wrap)?;
            let fp = locket_crypto::secret_fingerprint_v1(&[45; 32], "local-next")?;
            store.rotate_secret(
                &current,
                &next,
                &locket_store::SecretBlobRecord {
                    secret_id: current.id.clone(),
                    version: 3,
                    encrypted_dek: encrypted.encrypted_dek,
                    ciphertext: encrypted.ciphertext,
                    value_nonce: encrypted.value_nonce,
                    aad_schema_version: 1,
                    created_at: 151_000_000_000,
                },
                &locket_store::SecretFingerprintRecord {
                    secret_id: current.id.clone(),
                    version: 3,
                    fingerprint: fp.to_vec(),
                    created_at: 151_000_000_000,
                },
                151_000_000_000,
                None,
            )?;
            assert_eq!(
                store
                    .get_secret_by_source("project", "profile", "NEW_TOKEN", "user-local")?
                    .ok_or("override missing")?
                    .current_version,
                3
            );
        }
        let delivery = if reason == "profile-name-collision" {
            assert_eq!(
                details[0].colliding_profile.as_ref().ok_or("collision missing")?.id,
                "personal-profile"
            );
            for name in ["BAD NAME", "dev", "prod"] {
                assert!(
                    team_sync::rename_local_profile_for_pending(
                        &mut store,
                        "project",
                        "incoming-profile",
                        "personal-profile",
                        name,
                        &[22; 32],
                        &sealing,
                        &statement.recipient,
                        now,
                        None
                    )
                    .is_err()
                );
            }
            assert!(
                team_sync::rename_local_profile_for_pending(
                    &mut store,
                    "project",
                    "incoming-profile",
                    "profile",
                    "prod-local",
                    &[22; 32],
                    &sealing,
                    &statement.recipient,
                    now,
                    None
                )
                .is_err()
            );
            let exchange = tempfile::tempdir()?;
            let folder = exchange.path().join("share");
            std::fs::create_dir(&folder)?;
            let config = locket_agent::TeamSyncConfigureRequest {
                scope: agent.scope.clone(),
                folder: folder.clone(),
                allow_dangerous: false,
            };
            let configured =
                agent.sync_rpc(locket_agent::AgentMethod::TeamSyncConfigure, &config).await;
            std::fs::remove_dir(&folder)?;
            assert_eq!(configured?.epoch, 2);
            // Saving the local resolution succeeds even when delivery later fails.
            agent
                .reconcile(
                    pending_id,
                    locket_agent::TeamSyncAction::RenameProfile {
                        local_profile_id: "personal-profile".into(),
                        new_name: "prod-local".into(),
                    },
                )
                .await?;
            assert!(agent.status().await?.last_error.is_some_and(|error| {
                error.contains("Local resolution saved; delivery retry failed")
            }));
            std::fs::create_dir(&folder)?;
            Some(exchange)
        } else {
            None
        };
        let resumed = team_sync::resume_pending_profiles_guarded(
            &mut store,
            "project",
            &[22; 32],
            &sealing,
            &statement.recipient,
            true,
            now,
            None,
        )?;
        assert_eq!(resumed.pending_profiles, 0);
        assert_eq!(resumed.conflicts, 0, "rewrap must not invent local drift");
        if let Some(_exchange) = delivery {
            let status =
                agent.sync_rpc(locket_agent::AgentMethod::TeamSyncNow, &agent.scope).await?;
            assert!(status.last_error.is_none());
        }
        assert_eq!(team_sync::status(&store, "project")?.state, "verified");
        assert!(team_sync::status(&store, "project")?.pending_profiles.is_empty());
        assert!(store.verify_audit_chain_read_only("project", &[23; 32])?.hmac_ok);
        if reason == "secret-name-collision" {
            assert_eq!(
                store
                    .get_secret_by_source("project", "profile", "NEW_TOKEN", "user-local")?
                    .ok_or("local row lost")?
                    .id,
                "local-collision"
            );
        }
        if reason == "profile-name-collision" {
            assert_eq!(
                store.get_profile_by_name("project", "prod-local")?.ok_or("local profile lost")?.id,
                "personal-profile"
            );
        }
    }
    Ok(())
}

#[test]
fn pending_values_cannot_be_replayed_after_recipient_removal()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (mut statement, signer, sealing) = fixture()?;
    insert_local(&store, &statement.recipient)?;
    let first = SignedStatement::sign(&statement, &signer)?;
    team_sync::apply_package(
        &mut store,
        &first.seal(&statement.recipient.sealing_key)?,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        150,
    )?;
    statement.epoch = 2;
    statement.previous_digest = locket_core::team_package::digest(&first.statement);
    let second = SignedStatement::sign(&statement, &signer)?;
    team_sync::apply_package_with_consent_guarded(
        &mut store,
        &second.seal(&statement.recipient.sealing_key)?,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        None,
        150,
        false,
        None,
    )?;
    assert_eq!(team_sync::status(&store, "project")?.pending_profiles.len(), 1);
    statement.epoch = 3;
    statement.previous_digest = locket_core::team_package::digest(&second.statement);
    statement.members[1].removed = true;
    statement.profiles.clear();
    team_sync::apply_package(
        &mut store,
        &SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        None,
        150,
    )?;
    assert_eq!(team_sync::status(&store, "project")?.state, "removed");
    assert!(team_sync::status(&store, "project")?.pending_profiles.is_empty());
    assert!(
        team_sync::resume_pending_profiles_guarded(
            &mut store,
            "project",
            &[22; 32],
            &sealing,
            &statement.recipient,
            true,
            150,
            None
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn empty_profile_collision_and_remote_rename_do_not_hold_values()
-> Result<(), Box<dyn std::error::Error>> {
    for remote_rename in [false, true] {
        let dir = tempfile::tempdir()?;
        let mut store = receiver(&dir.path().join("receiver.db"))?;
        let (mut statement, signer, sealing) = fixture()?;
        insert_local(&store, &statement.recipient)?;
        let first = SignedStatement::sign(&statement, &signer)?;
        team_sync::apply_package(
            &mut store,
            &first.seal(&statement.recipient.sealing_key)?,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            Some(&statement.publisher.fingerprint),
            150,
        )?;
        store.insert_profile_if_absent("local-prod", "project", "prod", false, 1)?;
        statement.epoch = 2;
        statement.previous_digest = locket_core::team_package::digest(&first.statement);
        if remote_rename {
            store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at) VALUES ('local-value','project','local-prod','LOCAL','user-local','manual',0,1,'deleted',1,1)",[])?;
            statement.profiles[0].name = "prod".into();
            let secret = &mut statement.profiles[0].secrets[0];
            secret.version = 2;
            let aad = secret_blob_aad_v1(&SecretBlobAad::new(
                "project", "profile", "secret", "TOKEN", 2,
            ))?;
            let wrap = key_wrap_aad_v1(&KeyWrapAad::new(
                "project",
                "secret",
                Some("profile"),
                2,
                KeyWrapPurpose::SecretDek,
            ))?;
            let blob = encrypt_secret_value_v1(&[11; 32], "renamed-new-value", &aad, &wrap)?;
            secret.blob = Some(TeamBlob {
                encrypted_dek: blob.encrypted_dek,
                ciphertext: blob.ciphertext,
                value_nonce: blob.value_nonce,
                aad_schema_version: 1,
            });
        } else {
            let mut incoming = statement.profiles[0].clone();
            incoming.id = "incoming-prod".into();
            incoming.name = "prod".into();
            incoming.secrets.clear();
            statement.profiles.push(incoming);
            statement.members[1].profiles.push("incoming-prod".into());
        }
        let bytes =
            SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
        let result = team_sync::apply_package(
            &mut store,
            &bytes,
            &[22; 32],
            &sealing,
            &statement.recipient,
            "project",
            None,
            150,
        )?;
        assert_eq!(result.pending_profiles, 0);
        if remote_rename {
            assert_eq!(
                store.get_profile_by_name("project", "dev")?.ok_or("local name lost")?.id,
                "profile"
            );
            assert_eq!(
                store
                    .get_secret_by_source("project", "profile", "TOKEN", "team-managed")?
                    .ok_or("value missing")?
                    .current_version,
                2
            );
        } else {
            assert_eq!(
                store.get_profile_by_name("project", "prod")?.ok_or("incoming missing")?.id,
                "incoming-prod"
            );
        }
    }
    Ok(())
}

#[test]
fn folder_prioritizes_new_security_checkpoint_and_held_polls_do_not_rewrap_or_audit()
-> Result<(), Box<dyn std::error::Error>> {
    use locket_platform::{LocalDevicePrivateKeyStorage, MasterKeyStore};
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (mut statement, signer, sealing) = fixture()?;
    let other = DeviceIdentity::new(
        "other-device".into(),
        SigningKey::from_bytes(&[70; 32]).verifying_key().to_bytes(),
        [71; 32],
    );
    statement.members.push(TeamMember {
        id: "other-member".into(),
        name: "other".into(),
        role: "developer".into(),
        profiles: vec!["profile".into()],
        device: other.clone(),
        removed: false,
    });
    insert_local(&store, &statement.recipient)?;
    let first = SignedStatement::sign(&statement, &signer)?;
    team_sync::apply_package(
        &mut store,
        &first.seal(&statement.recipient.sealing_key)?,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        150,
    )?;
    let keys = dir.path().join("keys");
    let folder = dir.path().join("exchange");
    std::fs::create_dir(&keys)?;
    std::fs::create_dir(&folder)?;
    let memory = std::sync::Arc::new(locket_platform::MemoryMasterKeyStore::default());
    memory.store_master_key("project", &[22; 32])?;
    locket_platform::WrappedLocalFileDevicePrivateKeyStorage::new(&keys, "project", memory)
        .store(&statement.recipient.id, &sealing)?;
    team_sync::configure_folder(&store, "project", &folder, &keys, false)?;
    statement.epoch = 2;
    statement.previous_digest = locket_core::team_package::digest(&first.statement);
    let second = SignedStatement::sign(&statement, &signer)?;
    std::fs::write(folder.join("second.lkpkg"), second.seal(&statement.recipient.sealing_key)?)?;
    let status = team_sync::sync_folder(&mut store, "project", &[22; 32], 150)?;
    assert_eq!(status.epoch, 2);
    assert_eq!(status.pending_profiles.len(), 1);
    assert_eq!(status.applied, 0);
    let key = store
        .get_key_by_scope("project", Some("profile"), KeyPurpose::ProfileSecret.as_str())?
        .ok_or("key missing")?;
    let audit: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE project_id='project'",
        [],
        |row| row.get(0),
    )?;
    for _ in 0..2 {
        team_sync::sync_folder(&mut store, "project", &[22; 32], 150)?;
    }
    assert_eq!(
        store
            .get_key_by_scope("project", Some("profile"), KeyPurpose::ProfileSecret.as_str())?
            .ok_or("key missing")?,
        key
    );
    assert_eq!(
        store.connection().query_row(
            "SELECT COUNT(*) FROM audit_log WHERE project_id='project'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        audit
    );
    // An unusable retained package must not block a valid newer security update.
    store.connection().execute(
        "UPDATE team_sync_pending_packages SET encrypted_package=X'00' WHERE project_id='project'",
        [],
    )?;
    statement.epoch = 3;
    statement.previous_digest = locket_core::team_package::digest(&second.statement);
    statement.members[2].removed = true;
    let third = SignedStatement::sign(&statement, &signer)?;
    std::fs::write(folder.join("third.lkpkg"), third.seal(&statement.recipient.sealing_key)?)?;
    let status = team_sync::sync_folder(&mut store, "project", &[22; 32], 150)?;
    assert_eq!(status.epoch, 3);
    assert_eq!(status.pending_profiles.len(), 1);
    assert!(store.find_device("project", &other.id)?.ok_or("other missing")?.revoked_at.is_some());
    assert!(store.verify_audit_chain_read_only("project", &[23; 32])?.hmac_ok);
    Ok(())
}

#[test]
fn folder_gap_in_earlier_window_is_retryable_and_does_not_block_pending_consent()
-> Result<(), Box<dyn std::error::Error>> {
    use locket_platform::{LocalDevicePrivateKeyStorage, MasterKeyStore};
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (mut statement, signer, sealing) = fixture()?;
    insert_local(&store, &statement.recipient)?;
    let first = SignedStatement::sign(&statement, &signer)?;
    team_sync::apply_package(
        &mut store,
        &first.seal(&statement.recipient.sealing_key)?,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        Some(&statement.publisher.fingerprint),
        150,
    )?;
    statement.epoch = 2;
    statement.previous_digest = locket_core::team_package::digest(&first.statement);
    let second = SignedStatement::sign(&statement, &signer)?;
    team_sync::apply_package_with_consent_guarded(
        &mut store,
        &second.seal(&statement.recipient.sealing_key)?,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        None,
        150,
        false,
        None,
    )?;
    assert_eq!(team_sync::status(&store, "project")?.pending_profiles.len(), 1);
    let keys = dir.path().join("keys");
    let folder = dir.path().join("exchange");
    std::fs::create_dir(&keys)?;
    std::fs::create_dir(&folder)?;
    let memory = std::sync::Arc::new(locket_platform::MemoryMasterKeyStore::default());
    memory.store_master_key("project", &[22; 32])?;
    locket_platform::WrappedLocalFileDevicePrivateKeyStorage::new(&keys, "project", memory)
        .store(&statement.recipient.id, &sealing)?;
    // Explicitly saved consent should allow retry even when a gapped candidate
    // arrives in an earlier directory window than its valid predecessor.
    team_sync::configure_folder(&store, "project", &folder, &keys, false)?;
    statement.epoch = 3;
    statement.previous_digest = locket_core::team_package::digest(&second.statement);
    let third = SignedStatement::sign(&statement, &signer)?;
    let predecessor = third.seal(&statement.recipient.sealing_key)?;
    statement.epoch = 4;
    statement.previous_digest = locket_core::team_package::digest(&third.statement);
    let fourth = SignedStatement::sign(&statement, &signer)?;
    let future = fourth.seal(&statement.recipient.sealing_key)?;
    let future_file = format!("file:{}", locket_core::team_package::digest(&future));
    std::fs::write(folder.join("a-gap.lkpkg"), future)?;
    for index in 0..63 {
        std::fs::write(folder.join(format!("m-{index:03}.lkpkg")), b"incomplete")?;
    }
    std::fs::write(folder.join("z-predecessor.lkpkg"), &predecessor)?;
    let early = team_sync::sync_folder(&mut store, "project", &[22; 32], 150)?;
    assert_eq!(early.epoch, 2);
    assert_eq!(early.state, "pending-values", "delivery diagnostics must not hide pending consent");
    assert!(early.last_error.is_some());
    assert_eq!(early.pending_profiles.len(), 1);
    assert_eq!(early.applied, 0);
    // Withdraw the later-window predecessor, then explicitly grant local consent.
    // The same still-gapped scan must reach the pending retry without a fatal error.
    std::fs::remove_file(folder.join("z-predecessor.lkpkg"))?;
    team_sync::configure_folder(&store, "project", &folder, &keys, true)?;
    let resumed = team_sync::sync_folder(&mut store, "project", &[22; 32], 150)?;
    assert_eq!(resumed.epoch, 2);
    assert_eq!(resumed.applied, 1, "missing predecessor must not abort the pending-value retry");
    assert!(resumed.pending_profiles.is_empty());
    let seen:bool=store.connection().query_row("SELECT EXISTS(SELECT 1 FROM team_sync_seen WHERE project_id='project' AND (digest=?1 OR digest=?2))",(&future_file,locket_core::team_package::digest(&fourth.statement)),|row|row.get(0))?;
    assert!(!seen, "a gapped package must remain retryable");
    std::fs::write(folder.join("z-predecessor.lkpkg"), predecessor)?;
    let caught_up = team_sync::sync_folder(&mut store, "project", &[22; 32], 150)?;
    assert_eq!(caught_up.epoch, 4);
    assert_eq!(caught_up.state, "verified");
    assert_eq!(caught_up.applied, 2, "both predecessor and retained successor apply in order");
    assert!(store.verify_audit_chain_read_only("project", &[23; 32])?.hmac_ok);
    Ok(())
}

struct ReconciliationAgent {
    state: locket_agent::AgentSocketState,
    scope: locket_agent::TeamSyncRequest,
}

impl ReconciliationAgent {
    async fn new(
        path: &std::path::Path,
        device_id: &str,
        sealing: &[u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use locket_agent::{AgentMethod, GrantBinding};
        use locket_platform::{LocalDevicePrivateKeyStorage, MasterKeyStore};
        use serde_json::json;
        use std::sync::Arc;

        let root = path.parent().ok_or("vault storage missing")?;
        let master = Arc::new(locket_platform::MemoryMasterKeyStore::default());
        master.store_master_key("project", &[22; 32])?;
        locket_platform::WrappedLocalFileDevicePrivateKeyStorage::new(
            root,
            "project",
            master.clone(),
        )
        .store(device_id, sealing)?;
        let state = locket_agent::AgentSocketState::with_stores(
            "test",
            0,
            master,
            Arc::new(locket_platform::PassphraseFallbackMasterKeyStore::new(root.join("fallback"))),
        );
        let unlock = locket_agent::RequestEnvelope::new(
            "unlock",
            AgentMethod::Unlock,
            json!({"project_id":"project", "store_path": path, "ttl_seconds": 60}),
        );
        assert!(matches!(
            locket_agent::dispatch(&unlock, &state).await,
            locket_agent::ResponseEnvelope::Success(_)
        ));
        let binding = GrantBinding::new(std::process::id(), "test client");
        let grant = locket_agent::RequestEnvelope::new(
            "grant",
            AgentMethod::RequestGrant,
            json!({"project_id": "project", "profile_id": "profile", "action": "TeamSync",
                "binding": binding, "ttl_seconds": 60, "confirm_dangerous": true}),
        );
        let locket_agent::ResponseEnvelope::Success(grant) =
            locket_agent::dispatch(&grant, &state).await
        else {
            return Err("team sync grant rejected".into());
        };
        let grant_id = grant.payload["grant_id"].as_str().ok_or("missing grant id")?.to_owned();
        Ok(Self {
            state,
            scope: locket_agent::TeamSyncRequest {
                project_id: "project".into(),
                store_path: Some(path.to_owned()),
                profile_id: Some("profile".into()),
                grant_id: Some(grant_id),
                binding: Some(binding),
            },
        })
    }

    async fn status(&self) -> Result<team_sync::SyncStatus, Box<dyn std::error::Error>> {
        self.sync_rpc(locket_agent::AgentMethod::TeamSyncStatus, &self.scope).await
    }

    async fn reconcile(
        &self,
        incoming: &str,
        action: locket_agent::TeamSyncAction,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let status = self
            .sync_rpc(
                locket_agent::AgentMethod::TeamSyncReconcile,
                &locket_agent::TeamSyncReconcileRequest {
                    scope: self.scope.clone(),
                    incoming_profile_id: incoming.to_owned(),
                    action,
                },
            )
            .await?;
        assert_eq!(status.epoch, 2);
        assert_eq!(status.pending_profiles.len(), 1);
        Ok(())
    }

    async fn sync_rpc(
        &self,
        method: locket_agent::AgentMethod,
        payload: &(impl serde::Serialize + Sync),
    ) -> Result<team_sync::SyncStatus, Box<dyn std::error::Error>> {
        let request =
            locket_agent::RequestEnvelope::new("sync", method, serde_json::to_value(payload)?);
        match locket_agent::dispatch(&request, &self.state).await {
            locket_agent::ResponseEnvelope::Success(success) => {
                Ok(serde_json::from_value(success.payload)?)
            }
            locket_agent::ResponseEnvelope::Error(error) => {
                Err(format!("{}: {}", error.error, error.message).into())
            }
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // The three signed snapshots share the same verified history.
fn signed_update_cannot_erase_personal_values_or_reinstate_removed_members()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut store = receiver(&dir.path().join("receiver.db"))?;
    let (mut statement, signer, sealing) = fixture()?;
    let observer = TeamMember {
        id: "observer-member".into(),
        name: "observer".into(),
        role: "read-only".into(),
        profiles: Vec::new(),
        device: DeviceIdentity::new(
            "observer-device".into(),
            SigningKey::from_bytes(&[30; 32]).verifying_key().to_bytes(),
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([31; 32])).to_bytes(),
        ),
        removed: false,
    };
    statement.members.push(observer.clone());
    let first = SignedStatement::sign(&statement, &signer)?;
    let bytes = first.seal(&statement.recipient.sealing_key)?;
    let local = &statement.recipient;
    let owner_pin = &statement.publisher.fingerprint;
    assert_eq!(
        team_sync::join_package_checkpoint(&bytes, &sealing, local, "project", owner_pin, 150)?.0,
        1
    );
    assert!(
        team_sync::join_package_checkpoint(&bytes, &sealing, local, "project", owner_pin, 801)
            .is_err()
    );
    assert!(matches!(team_sync::apply_package(
        &mut store, &bytes, &[22; 32], &sealing, local, "project", Some(owner_pin), 150,
    ), Err(team_sync::SyncError::Rejected(message)) if message == "prepare a local device before joining"));
    insert_local(&store, local)?;
    assert!(matches!(team_sync::apply_package(
        &mut store, &bytes, &[22; 32], &sealing, &statement.publisher, "project", Some(owner_pin), 150,
    ), Err(team_sync::SyncError::Rejected(message)) if message == "recipient differs from local device"));
    assert_eq!(team_sync::status(&store, "project")?.epoch, 0);
    team_sync::apply_package(
        &mut store,
        &bytes,
        &[22; 32],
        &sealing,
        local,
        "project",
        Some(owner_pin),
        150,
    )?;
    store.connection().execute(
        "INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at)
         VALUES ('local-token','project','profile','TOKEN','user-local','manual',0,1,'active',1,1)",
        [],
    )?;
    statement.epoch = 2;
    statement.previous_digest = locket_core::team_package::digest(&first.statement);
    statement.profiles[0].secrets.clear();
    statement.members.retain(|member| member.id != observer.id);

    let next =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    let apply = team_sync::apply_package(
        &mut store,
        &next,
        &[22; 32],
        &sealing,
        &statement.recipient,
        "project",
        None,
        151,
    )?;
    assert_eq!(apply.conflicts, 0);
    assert_eq!(team_sync::status(&store, "project")?.epoch, 2);
    let shared = store
        .get_secret_by_source("project", "profile", "TOKEN", "team-managed")?
        .ok_or("shared tombstone missing")?;
    assert_eq!(shared.state, "deleted");
    assert!(shared.deleted_at.is_some());
    assert_eq!(
        store
            .get_active_secret("project", "profile", "TOKEN", "user-local")?
            .ok_or("local value missing")?
            .id,
        "local-token"
    );
    let revoked =
        store.get_team_member("team", "observer-member")?.ok_or("observer membership missing")?;
    assert!(revoked.removed_at.is_some());
    let removed = SignedStatement::sign(&statement, &signer)?;
    statement.epoch = 3;
    statement.previous_digest = locket_core::team_package::digest(&removed.statement);
    statement.members.push(observer);
    let reinstated =
        SignedStatement::sign(&statement, &signer)?.seal(&statement.recipient.sealing_key)?;
    assert!(matches!(team_sync::apply_package(
        &mut store, &reinstated, &[22; 32], &sealing, &statement.recipient, "project", None, 152,
    ), Err(team_sync::SyncError::Rejected(message)) if message == "removed membership cannot be reinstated"));
    assert_eq!(team_sync::status(&store, "project")?.epoch, 2);
    assert!(
        store
            .get_team_member("team", "observer-member")?
            .ok_or("observer membership missing")?
            .removed_at
            .is_some()
    );
    assert!(store.verify_audit_chain_read_only("project", &[23; 32])?.hmac_ok);
    Ok(())
}
