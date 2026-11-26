use std::collections::BTreeMap;
use std::error::Error;

use crate::{
    AuditContext, AuditWrite, SecretBlobRecord, SecretCopyTarget, SecretFingerprintRecord,
    SecretInitialMetadata, SecretMutableMetadata, SecretRecord, SecretVersionRecord, Store,
    StoreError, VersionDeprecation,
};

use super::{
    insert_project_profile, insert_project_profile_secret, open_initialized_store, test_secret,
    test_secret_blob, test_secret_fingerprint, test_secret_version,
};

#[test]
fn create_secret_lists_blob_and_fingerprint() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let secret = test_secret();
    let version = test_secret_version();
    let blob = test_secret_blob();
    let fingerprint = test_secret_fingerprint();
    test_store.store.create_active_secret(&secret, &version, &blob, &fingerprint)?;

    assert_eq!(
        test_store.store.get_active_secret(
            "lk_proj_test",
            "lk_prof_test",
            "DATABASE_URL",
            "user-local"
        )?,
        Some(secret.clone())
    );
    assert_eq!(
        test_store.store.list_active_secrets_by_profile("lk_proj_test", "lk_prof_test")?,
        vec![secret]
    );
    assert_eq!(test_store.store.get_blob("lk_sec_test", 1)?, Some(blob));

    let stored_fingerprint = test_store.store.connection().query_row(
        "SELECT fingerprint FROM fingerprints WHERE secret_id = 'lk_sec_test' AND version = 1",
        [],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    assert_eq!(stored_fingerprint, fingerprint.fingerprint);

    Ok(())
}

#[test]
fn active_secret_metadata_uses_source_precedence_ordering() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    for (id, name, source, required, current_version) in [
        ("lk_sec_team", "DATABASE_URL", "team-managed", true, 1),
        ("lk_sec_machine", "DATABASE_URL", "machine-local", false, 3),
        ("lk_sec_user", "DATABASE_URL", "user-local", false, 2),
        ("lk_sec_api", "API_TOKEN", "user-local", true, 1),
        ("lk_sec_deleted", "Z_DELETED", "machine-local", false, 4),
    ] {
        let state = if id == "lk_sec_deleted" { "deleted" } else { "active" };
        test_store.store.connection().execute(
            "INSERT INTO secrets(
               id, project_id, profile_id, name, source, origin, required,
               current_version, state, created_at, updated_at, last_rotated_at, deleted_at
             )
             VALUES (?1, 'lk_proj_test', 'lk_prof_test', ?2, ?3, 'manual', ?4, ?5, ?6, 100, 200, 300, NULL)",
            rusqlite::params![id, name, source, required, current_version, state],
        )?;
    }

    let rows =
        test_store.store.list_active_secret_metadata_by_profile("lk_proj_test", "lk_prof_test")?;

    let ordered = rows
        .iter()
        .map(|row| (row.name.as_str(), row.source.as_str(), row.source_precedence))
        .collect::<Vec<_>>();
    assert_eq!(
        ordered,
        vec![
            ("API_TOKEN", "user-local", 3),
            ("DATABASE_URL", "machine-local", 4),
            ("DATABASE_URL", "user-local", 3),
            ("DATABASE_URL", "team-managed", 1),
        ]
    );
    assert!(rows[0].required);
    assert_eq!(rows[1].current_version, 3);
    assert_eq!(rows[1].last_rotated_at, Some(300));
    Ok(())
}

#[test]
fn create_secret_rolls_back_when_version_source_mismatches() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let version =
        SecretVersionRecord { source: "team-managed".to_owned(), ..test_secret_version() };

    let result = test_store.store.create_active_secret(
        &test_secret(),
        &version,
        &test_secret_blob(),
        &test_secret_fingerprint(),
    );

    assert!(result.is_err());
    assert_eq!(
        test_store.store.get_secret_by_source(
            "lk_proj_test",
            "lk_prof_test",
            "DATABASE_URL",
            "user-local",
        )?,
        None
    );
    let version_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM secret_versions WHERE secret_id = 'lk_sec_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let blob_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM blobs WHERE secret_id = 'lk_sec_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let fingerprint_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM fingerprints WHERE secret_id = 'lk_sec_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(version_rows, 0);
    assert_eq!(blob_rows, 0);
    assert_eq!(fingerprint_rows, 0);

    Ok(())
}

#[test]
fn secret_metadata_update_changes_metadata_columns() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    test_store.store.create_active_secret(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
    )?;

    assert!(test_store.store.update_secret_metadata(
        "lk_sec_test",
        Some("database connection"),
        Some("platform"),
        Some(&["database".to_owned(), "prod".to_owned()]),
        Some(true),
    )?);

    let row = test_store.store.connection().query_row(
        "SELECT description, owner, tags_json, required, updated_at
         FROM secrets
         WHERE id = 'lk_sec_test'",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, i64>(4)?,
            ))
        },
    )?;
    assert_eq!(
        row,
        (
            "database connection".to_owned(),
            "platform".to_owned(),
            "[\"database\",\"prod\"]".to_owned(),
            true,
            100,
        )
    );
    assert!(!test_store.store.update_secret_metadata(
        "lk_sec_missing",
        Some("missing"),
        None,
        None,
        None,
    )?);

    Ok(())
}

#[test]
fn tombstone_secret_hides_it_from_active_queries() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    test_store.store.create_active_secret(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
    )?;
    test_store.store.tombstone_secret("lk_sec_test", 300)?;

    assert_eq!(
        test_store.store.get_active_secret(
            "lk_proj_test",
            "lk_prof_test",
            "DATABASE_URL",
            "user-local"
        )?,
        None
    );
    assert_eq!(
        test_store.store.list_active_secrets_by_profile("lk_proj_test", "lk_prof_test")?.len(),
        0
    );

    let deleted_at = test_store.store.connection().query_row(
        "SELECT deleted_at FROM secrets WHERE id = 'lk_sec_test' AND state = 'deleted'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(deleted_at, 300);

    Ok(())
}

#[test]
fn rotate_secret_advances_current_and_deprecates_prior() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    test_store.store.create_active_secret(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
    )?;

    test_store.store.rotate_secret(
        &test_secret(),
        &SecretVersionRecord { version: 2, created_at: 400, ..test_secret_version() },
        &SecretBlobRecord { version: 2, created_at: 400, ..test_secret_blob() },
        &SecretFingerprintRecord { version: 2, created_at: 400, ..test_secret_fingerprint() },
        300,
        Some(500),
    )?;

    let secret = test_store
        .store
        .get_active_secret("lk_proj_test", "lk_prof_test", "DATABASE_URL", "user-local")?
        .ok_or("active secret should exist")?;
    assert_eq!(secret.current_version, 2);
    assert_eq!(secret.last_rotated_at, Some(400));

    let versions = test_store.store.list_secret_versions("lk_sec_test")?;
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].state, "deprecated");
    assert_eq!(versions[0].deprecated_at, Some(300));
    assert_eq!(versions[0].grace_until, Some(500));
    assert_eq!(versions[1].state, "current");
    assert_eq!(versions[1].version, 2);

    Ok(())
}

#[derive(Clone, Copy)]
enum ConcurrentSecretChange {
    Tombstone,
    Rotate,
    Purge,
}

impl ConcurrentSecretChange {
    fn apply(self, store: &mut Store, secret: &SecretRecord) -> Result<u32, StoreError> {
        match self {
            Self::Tombstone => {
                store.tombstone_secret(&secret.id, 200)?;
                Ok(2)
            }
            Self::Rotate => {
                store.rotate_secret(
                    secret,
                    &SecretVersionRecord { version: 2, created_at: 200, ..test_secret_version() },
                    &SecretBlobRecord { version: 2, created_at: 200, ..test_secret_blob() },
                    &SecretFingerprintRecord {
                        version: 2,
                        created_at: 200,
                        ..test_secret_fingerprint()
                    },
                    200,
                    None,
                )?;
                // Use an unused version so a uniqueness error cannot mask stale-state handling.
                Ok(3)
            }
            Self::Purge => {
                // Simulate a store written before the active-current purge guard.
                store.connection().execute_batch(
                    "UPDATE secret_versions SET state = 'purged', purged_at = 200
                     WHERE secret_id = 'lk_sec_test' AND version = 1;
                     DELETE FROM blobs WHERE secret_id = 'lk_sec_test' AND version = 1;
                     DELETE FROM fingerprints WHERE secret_id = 'lk_sec_test' AND version = 1;",
                )?;
                Ok(2)
            }
        }
    }
}

fn stored_fingerprints(store: &Store) -> rusqlite::Result<Vec<(u32, Vec<u8>)>> {
    store
        .connection()
        .prepare(
            "SELECT version, fingerprint FROM fingerprints
             WHERE secret_id = 'lk_sec_test' ORDER BY version",
        )?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect()
}

fn assert_stale_rotation_rolls_back(
    copy: bool,
    change: ConcurrentSecretChange,
) -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    test_store.store.create_active_secret(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
    )?;
    let stale_secret = test_store
        .store
        .get_active_secret("lk_proj_test", "lk_prof_test", "DATABASE_URL", "user-local")?
        .ok_or("missing active secret")?;

    let mut other = Store::open(test_store.store.connection().path().ok_or("missing store path")?)?;
    let next_version = change.apply(&mut other, &stale_secret)?;
    let before_secret =
        other.get_secret_by_source("lk_proj_test", "lk_prof_test", "DATABASE_URL", "user-local")?;
    let before_versions = other.list_secret_versions(&stale_secret.id)?;
    let before_blob = other.get_blob(&stale_secret.id, 1)?;
    let before_fingerprints = stored_fingerprints(&other)?;
    let action = if copy { "SECRET_COPY" } else { "ROTATE" };
    let mut metadata = serde_json::json!({
        "schema_version": 1,
        "action": action,
        "status": "SUCCESS",
        "secret_name": "DATABASE_URL",
        "profile_id": "lk_prof_test",
        "source": "user-local",
    });
    if copy {
        metadata["from_profile_id"] = serde_json::json!("lk_prof_test");
        metadata["to_profile_id"] = serde_json::json!("lk_prof_test");
    }
    let audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action,
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: &metadata,
        timestamp: 300,
    };
    let version =
        SecretVersionRecord { version: next_version, created_at: 300, ..test_secret_version() };
    let blob = SecretBlobRecord { version: next_version, created_at: 300, ..test_secret_blob() };
    let fingerprint = SecretFingerprintRecord {
        version: next_version,
        created_at: 300,
        ..test_secret_fingerprint()
    };
    let deprecation = VersionDeprecation { deprecated_at: 300, grace_until: None };
    let audit = Some(AuditContext { key: &[42; 32], write: &audit });
    let result = if copy {
        test_store.store.copy_secret_with_audit(
            SecretCopyTarget::Rotate { secret: &stale_secret, deprecation },
            &version,
            &blob,
            &fingerprint,
            audit,
        )
    } else {
        test_store.store.rotate_secret_with_audit(
            &stale_secret,
            &version,
            &blob,
            &fingerprint,
            deprecation,
            audit,
        )
    };

    assert!(
        matches!(result, Err(StoreError::SecretStateConflict { ref secret_id, expected_version: 1 })
            if secret_id == &stale_secret.id),
        "{action} must reject the stale secret snapshot, got {result:?}"
    );
    assert_eq!(
        result.as_ref().err().map(StoreError::locket_error),
        Some(locket_core::LocketError::StorageBusy)
    );
    assert_eq!(
        other.get_secret_by_source("lk_proj_test", "lk_prof_test", "DATABASE_URL", "user-local")?,
        before_secret
    );
    assert_eq!(other.list_secret_versions(&stale_secret.id)?, before_versions);
    assert_eq!(other.get_blob(&stale_secret.id, 1)?, before_blob);
    assert_eq!(other.get_blob(&stale_secret.id, next_version)?, None);
    assert_eq!(stored_fingerprints(&other)?, before_fingerprints);
    assert_eq!(other.list_recent_audit_actions("lk_proj_test", 10)?, Vec::<String>::new());
    Ok(())
}

#[test]
fn stale_rotate_after_tombstone_rolls_back() -> Result<(), Box<dyn Error>> {
    assert_stale_rotation_rolls_back(false, ConcurrentSecretChange::Tombstone)
}

#[test]
fn stale_copy_rotation_after_tombstone_rolls_back() -> Result<(), Box<dyn Error>> {
    assert_stale_rotation_rolls_back(true, ConcurrentSecretChange::Tombstone)
}

#[test]
fn stale_rotate_after_concurrent_rotation_rolls_back() -> Result<(), Box<dyn Error>> {
    assert_stale_rotation_rolls_back(false, ConcurrentSecretChange::Rotate)
}

#[test]
fn stale_copy_rotation_after_concurrent_rotation_rolls_back() -> Result<(), Box<dyn Error>> {
    assert_stale_rotation_rolls_back(true, ConcurrentSecretChange::Rotate)
}

#[test]
fn stale_rotate_after_current_version_purge_rolls_back() -> Result<(), Box<dyn Error>> {
    assert_stale_rotation_rolls_back(false, ConcurrentSecretChange::Purge)
}

#[test]
fn stale_copy_rotation_after_current_version_purge_rolls_back() -> Result<(), Box<dyn Error>> {
    assert_stale_rotation_rolls_back(true, ConcurrentSecretChange::Purge)
}

#[test]
fn version_metadata_lists_profile_rows_by_source_precedence_and_version()
-> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    for (id, source, current_version, last_rotated_at) in [
        ("lk_sec_team", "team-managed", 1, None),
        ("lk_sec_machine", "machine-local", 3, Some(400)),
        ("lk_sec_user", "user-local", 2, Some(300)),
    ] {
        test_store.store.connection().execute(
            "INSERT INTO secrets(
               id, project_id, profile_id, name, source, origin, required,
               current_version, state, created_at, updated_at, last_rotated_at, deleted_at
             )
             VALUES (?1, 'lk_proj_test', 'lk_prof_test', 'DATABASE_URL', ?2, 'manual', 1,
                     ?3, 'active', 100, 200, ?4, NULL)",
            rusqlite::params![id, source, current_version, last_rotated_at],
        )?;
    }
    for (secret_id, version, state, created_at, deprecated_at, grace_until, purged_at) in [
        ("lk_sec_team", 1, "current", 100, None, None, None),
        ("lk_sec_user", 1, "deprecated", 100, Some(300), Some(900), None),
        ("lk_sec_user", 2, "current", 300, None, None, None),
        ("lk_sec_machine", 1, "purged", 100, Some(200), None, Some(500)),
        ("lk_sec_machine", 2, "deprecated", 200, Some(400), Some(800), None),
        ("lk_sec_machine", 3, "current", 400, None, None, None),
    ] {
        test_store.store.connection().execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, (SELECT source FROM secrets WHERE id = ?1), 'manual', ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![secret_id, version, state, created_at, deprecated_at, grace_until, purged_at],
        )?;
    }

    let rows =
        test_store.store.list_secret_version_metadata_by_profile("lk_proj_test", "lk_prof_test")?;
    let ordered = rows
        .iter()
        .map(|row| (row.source.as_str(), row.version, row.version_state.as_str()))
        .collect::<Vec<_>>();

    assert_eq!(
        ordered,
        vec![
            ("machine-local", 3, "current"),
            ("machine-local", 2, "deprecated"),
            ("machine-local", 1, "purged"),
            ("user-local", 2, "current"),
            ("user-local", 1, "deprecated"),
            ("team-managed", 1, "current"),
        ]
    );
    assert_eq!(rows[0].source_precedence, 4);
    assert_eq!(rows[0].current_version, 3);
    assert_eq!(rows[0].last_rotated_at, Some(400));
    assert_eq!(rows[1].grace_until, Some(800));
    assert_eq!(rows[2].purged_at, Some(500));
    Ok(())
}

#[test]
fn purge_secret_versions_removes_material_but_keeps_version_rows() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    test_store.store.create_active_secret(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
    )?;
    test_store.store.rotate_secret(
        &test_secret(),
        &SecretVersionRecord { version: 2, created_at: 400, ..test_secret_version() },
        &SecretBlobRecord { version: 2, created_at: 400, ..test_secret_blob() },
        &SecretFingerprintRecord { version: 2, created_at: 400, ..test_secret_fingerprint() },
        300,
        Some(500),
    )?;

    let result =
        test_store.store.purge_secret_versions_with_audit("lk_sec_test", &[1, 2], 550, None);
    assert!(matches!(
        result,
        Err(StoreError::ActiveSecretVersionPurge { ref secret_id, version: 2 })
            if secret_id == "lk_sec_test"
    ));
    assert!(test_store.store.get_blob("lk_sec_test", 1)?.is_some());
    assert!(test_store.store.get_blob("lk_sec_test", 2)?.is_some());
    assert!(test_store.store.purge_secret_version("lk_sec_test", 1, 600)?);
    assert!(!test_store.store.purge_secret_version("lk_sec_test", 1, 700)?);

    let versions = test_store.store.list_secret_versions("lk_sec_test")?;
    assert_eq!(versions[0].state, "purged");
    assert_eq!(versions[0].grace_until, None);
    assert_eq!(versions[0].purged_at, Some(600));
    assert_eq!(versions[1].state, "current");
    assert_eq!(test_store.store.get_blob("lk_sec_test", 1)?, None);
    assert!(test_store.store.get_blob("lk_sec_test", 2)?.is_some());

    let fingerprint_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM fingerprints WHERE secret_id = 'lk_sec_test' AND version = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(fingerprint_rows, 0);

    test_store.store.tombstone_secret("lk_sec_test", 800)?;
    assert!(test_store.store.purge_secret_versions_with_audit("lk_sec_test", &[2], 900, None)?);
    assert_eq!(test_store.store.get_blob("lk_sec_test", 2)?, None);

    Ok(())
}

#[test]
fn secret_version_range_constraints_are_enforced() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile_secret(&test_store.store)?;

    for version in [0_i64, 4_294_967_296_i64] {
        let result = test_store.store.connection().execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at
             )
             VALUES ('lk_sec_test', ?1, 'user-local', 'manual', 'current', 1)",
            [version],
        );
        assert!(result.is_err(), "version {version} should be rejected");
    }

    let rows = test_store.store.connection().execute(
        "INSERT INTO secret_versions(secret_id, version, source, origin, state, created_at)
         VALUES ('lk_sec_test', 1, 'user-local', 'manual', 'current', 1)",
        [],
    )?;
    assert_eq!(rows, 1);

    Ok(())
}

fn secret_audit_metadata(action: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "action": action,
        "status": "SUCCESS",
        "secret_name": "DATABASE_URL",
        "profile_id": "lk_prof_test",
        "source": "user-local",
    })
}

fn secret_audit<'a>(action: &'a str, metadata: &'a serde_json::Value) -> AuditWrite<'a> {
    AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action,
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: metadata,
        timestamp: 200,
    }
}

#[test]
fn create_secret_metadata_commits_with_audit_and_rolls_back_on_error() -> Result<(), Box<dyn Error>>
{
    let mut fixture = open_initialized_store()?;
    let store = &mut fixture.store;
    insert_project_profile(store)?;
    let (secret, version, blob, fingerprint) =
        (test_secret(), test_secret_version(), test_secret_blob(), test_secret_fingerprint());
    let tags = ["on-call".to_owned(), "données".to_owned()];
    let metadata = SecretInitialMetadata {
        description: Some("Production"),
        owner: Some("Infra"),
        tags: &tags,
        required: true,
    };
    let bad_json = serde_json::json!({});
    let rejected_audit = secret_audit("SET", &bad_json);
    let key = [42; 32];
    assert!(matches!(
        store.create_active_secret_with_metadata_and_audit(
            &secret,
            &version,
            &blob,
            &fingerprint,
            metadata,
            Some(AuditContext { key: &key, write: &rejected_audit }),
        ),
        Err(StoreError::AuditMetadataInvalid { .. })
    ));
    assert!(store.get_secret_mutable_metadata(&secret.id)?.is_none());
    assert!(store.get_secret_version(&secret.id, 1)?.is_none());
    assert!(store.get_blob(&secret.id, 1)?.is_none());

    let audit_json = secret_audit_metadata("SET");
    let audit = secret_audit("SET", &audit_json);
    store.create_active_secret_with_metadata_and_audit(
        &secret,
        &version,
        &blob,
        &fingerprint,
        metadata,
        Some(AuditContext { key: &key, write: &audit }),
    )?;
    assert_eq!(
        store.get_secret_mutable_metadata(&secret.id)?,
        Some(SecretMutableMetadata {
            description: Some("Production".into()),
            owner: Some("Infra".into()),
            tags: tags.to_vec(),
            required: true,
        })
    );
    let rows = store.list_audit_rows_since(&secret.project_id, &secret.profile_id, 0)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "SET");
    Ok(())
}

#[test]
fn rotate_secret_metadata_is_preserved_or_replaced_atomically() -> Result<(), Box<dyn Error>> {
    let mut fixture = open_initialized_store()?;
    let store = &mut fixture.store;
    insert_project_profile(store)?;
    let mut secret = test_secret();
    store.create_active_secret(
        &secret,
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
    )?;
    assert_eq!(
        store.get_secret_mutable_metadata(&secret.id)?,
        Some(SecretMutableMetadata {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false
        })
    );
    let tags = ["tag".to_owned()];
    store.update_secret_metadata(
        &secret.id,
        Some("initial"),
        Some("old"),
        Some(&tags),
        Some(true),
    )?;
    let previous = store.get_secret_mutable_metadata(&secret.id)?;

    let version = SecretVersionRecord { version: 2, created_at: 200, ..test_secret_version() };
    let blob = SecretBlobRecord { version: 2, created_at: 200, ..test_secret_blob() };
    let fingerprint =
        SecretFingerprintRecord { version: 2, created_at: 200, ..test_secret_fingerprint() };
    let deprecation = VersionDeprecation { deprecated_at: 200, grace_until: None };
    store.rotate_secret_with_audit(&secret, &version, &blob, &fingerprint, deprecation, None)?;
    assert_eq!(store.get_secret_mutable_metadata(&secret.id)?, previous);

    secret.current_version = 2;
    let version = SecretVersionRecord { version: 3, created_at: 300, ..version };
    let blob = SecretBlobRecord { version: 3, created_at: 300, ..blob };
    let fingerprint = SecretFingerprintRecord { version: 3, created_at: 300, ..fingerprint };
    let deprecation = VersionDeprecation { deprecated_at: 300, grace_until: Some(400) };
    let bad_json = serde_json::json!({});
    let rejected_audit = secret_audit("ROTATE", &bad_json);
    let key = [42; 32];
    let replacement = Some(SecretInitialMetadata { owner: Some("new"), ..Default::default() });
    assert!(matches!(
        store.rotate_secret_with_metadata_and_audit(
            &secret,
            &version,
            &blob,
            &fingerprint,
            deprecation,
            replacement,
            Some(AuditContext { key: &key, write: &rejected_audit }),
        ),
        Err(StoreError::AuditMetadataInvalid { .. })
    ));
    assert_eq!(store.get_secret_mutable_metadata(&secret.id)?, previous);
    assert_eq!(
        store.get_secret_version(&secret.id, 2)?.ok_or("old version absent")?.state,
        "current"
    );
    assert!(store.get_secret_version(&secret.id, 3)?.is_none());
    assert!(store.get_blob(&secret.id, 3)?.is_none());

    let audit_json = secret_audit_metadata("ROTATE");
    let audit = secret_audit("ROTATE", &audit_json);
    store.rotate_secret_with_metadata_and_audit(
        &secret,
        &version,
        &blob,
        &fingerprint,
        deprecation,
        replacement,
        Some(AuditContext { key: &key, write: &audit }),
    )?;
    assert_eq!(
        store.get_secret_mutable_metadata(&secret.id)?,
        Some(SecretMutableMetadata {
            description: None,
            owner: Some("new".into()),
            tags: Vec::new(),
            required: false,
        })
    );
    let stored = store
        .get_active_secret(&secret.project_id, &secret.profile_id, &secret.name, &secret.source)?
        .ok_or("active secret absent")?;
    assert_eq!(
        (stored.current_version, stored.updated_at, stored.last_rotated_at),
        (3, 300, Some(300))
    );
    let rows = store.list_audit_rows_since(&secret.project_id, &secret.profile_id, 0)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "ROTATE");
    Ok(())
}

#[test]
fn secret_expiry_policy_round_trips_and_can_be_cleared() -> Result<(), Box<dyn Error>> {
    use crate::SecretExpiryPolicy;

    let test_store = open_initialized_store()?;
    let store = &test_store.store;
    insert_project_profile_secret(store)?;
    let secret = "lk_sec_test";
    assert_eq!(store.get_secret_expiry_policy(secret)?, Some(SecretExpiryPolicy::default()));
    assert_eq!(store.get_secret_expiry_policy("missing")?, None);

    let policy = SecretExpiryPolicy { expires_at: Some(200), rotate_after_days: Some(3) };
    assert!(!store.set_secret_expiry_policy("missing", policy, 100)?);
    assert!(store.set_secret_expiry_policy(secret, policy, 100)?);
    assert_eq!(store.get_secret_expiry_policy(secret)?, Some(policy));
    let stored_updated_at: i64 = store.connection().query_row(
        "SELECT updated_at FROM secrets WHERE id = ?1",
        [secret],
        |row| row.get(0),
    )?;
    assert_eq!(stored_updated_at, 100);

    assert!(store.set_secret_expiry_policy(secret, SecretExpiryPolicy::default(), 150)?);
    assert_eq!(store.get_secret_expiry_policy(secret)?, Some(SecretExpiryPolicy::default()));
    assert_eq!(store.list_expiring_or_stale_secrets(None, 300, 0)?, []);
    Ok(())
}

#[test]
fn secret_expiry_notices_respect_boundaries_rotation_and_project_scope()
-> Result<(), Box<dyn Error>> {
    use crate::{SecretExpiryPolicy, SecretExpiryStatus};

    const DAY: i64 = 86_400_000_000_000;
    let test_store = open_initialized_store()?;
    let store = &test_store.store;
    insert_project_profile(store)?;
    let connection = store.connection();
    connection.execute_batch(
        "INSERT INTO projects(id, name, created_at) VALUES ('other', 'other', 0);
         INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('other-profile', 'other', 'default', 0, 0);",
    )?;
    let now = 2 * DAY;

    for (id, project, profile, state, expiry, rotate_days, rotated_at) in [
        ("a-expired", "lk_proj_test", "lk_prof_test", "active", Some(now), Some(2_u32), None),
        ("b-soon", "lk_proj_test", "lk_prof_test", "active", Some(now + 5), Some(2), Some(DAY)),
        ("c-stale", "lk_proj_test", "lk_prof_test", "active", None, Some(1), Some(DAY)),
        ("d-later", "lk_proj_test", "lk_prof_test", "active", Some(now + 6), Some(u32::MAX), None),
        ("e-deleted", "lk_proj_test", "lk_prof_test", "deleted", Some(1), Some(1), None),
        ("f-other", "other", "other-profile", "active", Some(now - 1), None, None),
    ] {
        connection.execute(
            "INSERT INTO secrets(
               id, project_id, profile_id, name, source, origin, required,
               current_version, state, created_at, updated_at, last_rotated_at
             ) VALUES (?1, ?2, ?3, ?1, 'user-local', 'manual', 0, 1, ?4, 0, 0, ?5)",
            rusqlite::params![id, project, profile, state, rotated_at],
        )?;
        assert!(store.set_secret_expiry_policy(
            id,
            SecretExpiryPolicy { expires_at: expiry, rotate_after_days: rotate_days },
            DAY,
        )?);
    }

    let notices = store.list_expiring_or_stale_secrets(Some("lk_proj_test"), now, 5)?;
    let summarized = notices
        .iter()
        .map(|row| (row.secret_id.as_str(), row.expiry_status, row.stale))
        .collect::<Vec<_>>();
    assert_eq!(
        summarized,
        [
            ("a-expired", Some(SecretExpiryStatus::Expired), true),
            ("b-soon", Some(SecretExpiryStatus::ExpiringSoon), false),
            ("c-stale", None, true),
        ]
    );
    assert_eq!(store.list_expiring_or_stale_secrets(None, now, -1)?.len(), 3);
    let other = store.list_expiring_or_stale_secrets(Some("other"), now, 0)?;
    assert_eq!(other.len(), 1);
    assert_eq!(other[0].secret_id, "f-other");
    assert_eq!(store.list_expiring_or_stale_secrets(Some("missing"), now, 0)?, []);
    Ok(())
}

#[test]
fn copied_secret_is_listed_and_stale_tombstones_leave_the_target_intact()
-> Result<(), Box<dyn Error>> {
    let mut fixture = open_initialized_store()?;
    let store = &mut fixture.store;
    insert_project_profile(store)?;
    let mut secret = test_secret();
    secret.origin = "profile-copy".into();
    let mut version = test_secret_version();
    version.origin.clone_from(&secret.origin);
    let blob = test_secret_blob();
    store.copy_secret_with_audit(
        SecretCopyTarget::Create(&secret),
        &version,
        &blob,
        &test_secret_fingerprint(),
        None,
    )?;
    assert_eq!(
        store.list_secrets_by_name(&secret.project_id, &secret.profile_id, &secret.name)?,
        [secret.clone()]
    );
    assert!(!store.purge_secret_versions(&secret.id, &[], 150)?);
    assert_eq!(store.get_blob(&secret.id, version.version)?, Some(blob));

    let metadata = secret_audit_metadata("DELETE");
    let write = secret_audit("DELETE", &metadata);
    let audit = AuditContext { key: &[42; 32], write: &write };
    let stale = SecretRecord { current_version: 2, ..secret.clone() };
    assert!(matches!(
        store.tombstone_current_secret_with_audit(&stale, 200, audit),
        Err(StoreError::SecretStateConflict { secret_id, expected_version: 2 }) if secret_id == secret.id
    ));
    assert_eq!(store.list_recent_audit_actions(&secret.project_id, 10)?, Vec::<String>::new());
    store.tombstone_current_secret_with_audit(&secret, 200, audit)?;
    assert_eq!(store.list_active_secrets_by_profile(&secret.project_id, &secret.profile_id)?, []);
    assert_eq!(store.list_recent_audit_actions(&secret.project_id, 10)?, ["DELETE"]);
    Ok(())
}

#[test]
fn secret_queries_propagate_missing_schema_instead_of_reporting_absent_records()
-> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    store.connection().execute_batch(
        "ALTER TABLE blobs RENAME TO unavailable_blobs;
         ALTER TABLE secret_versions RENAME TO unavailable_versions;
         ALTER TABLE secrets RENAME TO unavailable_secrets;",
    )?;
    let secret = test_secret();
    let (project, profile, name, source) = (
        secret.project_id.as_str(),
        secret.profile_id.as_str(),
        secret.name.as_str(),
        secret.source.as_str(),
    );
    for result in [
        store.get_secret_mutable_metadata(&secret.id).map(|_| ()),
        store.get_active_secret(project, profile, name, source).map(|_| ()),
        store.get_secret_by_source(project, profile, name, source).map(|_| ()),
        store.list_secrets_by_name(project, profile, name).map(|_| ()),
        store.list_active_secrets_by_profile(project, profile).map(|_| ()),
        store.list_active_secret_metadata_by_profile(project, profile).map(|_| ()),
        store.list_secrets_by_profile(project, profile).map(|_| ()),
        store.list_secret_versions(&secret.id).map(|_| ()),
        store.list_secret_version_metadata_by_profile(project, profile).map(|_| ()),
        store.get_secret_version(&secret.id, 1).map(|_| ()),
        store.get_blob(&secret.id, 1).map(|_| ()),
    ] {
        assert!(matches!(result, Err(StoreError::Sqlite(_))));
    }
    Ok(())
}

#[test]
fn secret_links_resolve_list_count_and_unlink_on_shared_delete() -> Result<(), Box<dyn Error>> {
    let mut fixture = open_initialized_store()?;
    let store = &mut fixture.store;
    insert_project_profile(store)?;
    store.insert_project_if_absent("lk_proj_shared_test", "@shared", 1)?;
    store.insert_profile_if_absent("lk_prof_shared", "lk_proj_shared_test", "default", false, 1)?;
    let shared_secret = SecretRecord {
        id: "lk_sec_shared_rpc".into(),
        project_id: "lk_proj_shared_test".into(),
        profile_id: "lk_prof_shared".into(),
        name: "ALCHEMY_MAINNET_RPC".into(),
        source: "user-local".into(),
        origin: "manual".into(),
        current_version: 1,
        state: "active".into(),
        created_at: 10,
        updated_at: 20,
        last_rotated_at: None,
        deleted_at: None,
    };
    let shared_version = SecretVersionRecord {
        secret_id: shared_secret.id.clone(),
        version: 1,
        source: "user-local".into(),
        origin: "manual".into(),
        state: "current".into(),
        created_at: 10,
        deprecated_at: None,
        grace_until: None,
        purged_at: None,
    };
    let shared_blob = SecretBlobRecord {
        secret_id: shared_secret.id.clone(),
        version: 1,
        encrypted_dek: vec![1; 40],
        ciphertext: vec![2; 40],
        value_nonce: [3; 24],
        aad_schema_version: 1,
        created_at: 10,
    };
    let shared_fp = SecretFingerprintRecord {
        secret_id: shared_secret.id.clone(),
        version: 1,
        fingerprint: vec![4; 32],
        created_at: 10,
    };
    store.create_active_secret(&shared_secret, &shared_version, &shared_blob, &shared_fp)?;

    let link = crate::SecretLinkRecord {
        id: "lk_link_rpc".into(),
        project_id: "lk_proj_test".into(),
        profile_id: "lk_prof_test".into(),
        local_name: "RPC_URL".into(),
        target_project_id: "lk_proj_shared_test".into(),
        target_profile_id: "lk_prof_shared".into(),
        target_secret_id: shared_secret.id.clone(),
        created_at: 30,
        updated_at: 30,
    };
    store.upsert_secret_link_with_audit(&link, None)?;

    let resolved = store
        .resolve_active_secret_link("lk_proj_test", "lk_prof_test", "RPC_URL")?
        .ok_or("link missing")?;
    assert_eq!(resolved.target_secret.name, "ALCHEMY_MAINNET_RPC");

    let proj_rows = store.list_active_secret_metadata_by_profile("lk_proj_test", "lk_prof_test")?;
    assert_eq!(proj_rows.len(), 1);
    assert_eq!(proj_rows[0].name, "RPC_URL");
    assert_eq!(proj_rows[0].source, "shared-link");
    assert_eq!(proj_rows[0].source_precedence, 2);
    assert_eq!(proj_rows[0].linked_target_name.as_deref(), Some("ALCHEMY_MAINNET_RPC"));

    let shared_rows =
        store.list_active_secret_metadata_by_profile("lk_proj_shared_test", "lk_prof_shared")?;
    assert_eq!(shared_rows[0].link_count, 1);

    let usages = store.list_shared_secret_usages(&shared_secret.id)?;
    assert_eq!(usages.len(), 1);
    assert_eq!(usages[0].local_name, "RPC_URL");

    assert_audited_shared_cascade(store, &shared_secret, link)
}

fn assert_audited_shared_cascade(
    store: &mut Store,
    shared_secret: &SecretRecord,
    link: crate::SecretLinkRecord,
) -> Result<(), Box<dyn Error>> {
    store.insert_project_if_absent("lk_proj_other", "Other", 1)?;
    store.insert_profile_if_absent("lk_prof_other", "lk_proj_other", "dev", false, 1)?;
    store.upsert_secret_link_with_audit(
        &crate::SecretLinkRecord {
            id: "lk_link_other".into(),
            project_id: "lk_proj_other".into(),
            profile_id: "lk_prof_other".into(),
            local_name: "OTHER_RPC".into(),
            ..link
        },
        None,
    )?;
    let usages = store.list_shared_secret_usages(&shared_secret.id)?;
    let metadata: Vec<_> =
        usages.iter().map(|usage| usage.unlink_audit_metadata(shared_secret)).collect();
    let writes: Vec<_> = usages
        .iter()
        .zip(&metadata)
        .map(|(usage, metadata)| usage.unlink_audit(metadata, 50))
        .collect();
    let keys = [[11; 32], [12; 32]];
    let audits: BTreeMap<_, _> = usages
        .iter()
        .zip(&writes)
        .zip(&keys)
        .map(|((usage, write), key)| (usage.link_id.as_str(), AuditContext { key, write }))
        .collect();
    assert!(matches!(
        store.tombstone_secret_and_unlink_with_audit(
            shared_secret,
            50,
            None,
            &audits,
            Some(&["lk_link_rpc".into()]),
        ),
        Err(StoreError::LinkSetChanged),
    ));
    assert_eq!(store.list_shared_secret_usages(&shared_secret.id)?, usages);
    let mut bad_audits = audits.clone();
    // Reject an invalid context after the first consumer's audit insert, rolling it back too.
    bad_audits.insert(&usages[1].link_id, AuditContext { key: &[], write: &writes[1] });
    assert!(matches!(
        store.tombstone_secret_and_unlink_with_audit(shared_secret, 50, None, &bad_audits, None),
        Err(StoreError::InvalidAuditKeyLength { .. }),
    ));
    for usage in &usages {
        assert_eq!(store.list_exportable_audit_rows(&usage.project_id)?, []);
    }
    assert_eq!(store.get_secret_by_id(&shared_secret.id)?.as_ref(), Some(shared_secret));
    assert_eq!(store.list_shared_secret_usages(&shared_secret.id)?, usages);

    let reviewed = ["lk_link_rpc".into(), "lk_link_other".into()];
    let unlinked = store.tombstone_secret_and_unlink_with_audit(
        shared_secret,
        50,
        None,
        &audits,
        Some(&reviewed),
    )?;
    assert_eq!(unlinked, usages);
    for (usage, key) in usages.iter().zip(keys) {
        let chain = store.verify_audit_chain_read_only(&usage.project_id, &key)?;
        assert!(chain.hmac_ok);
        assert_eq!(chain.rows_verified, 1);
        let rows = store.list_exportable_audit_rows(&usage.project_id)?;
        assert_eq!(rows[0].action, "SECRET_UNLINK");
        assert_eq!(rows[0].secret_name.as_deref(), Some(usage.local_name.as_str()));
    }
    assert!(store.get_secret_link("lk_proj_test", "lk_prof_test", "RPC_URL")?.is_none());
    assert_eq!(
        store.list_active_secret_metadata_by_profile("lk_proj_test", "lk_prof_test")?.len(),
        0
    );
    Ok(())
}

#[test]
fn local_value_fingerprints_group_cross_project_duplicates_and_clear_on_purge()
-> Result<(), Box<dyn Error>> {
    let mut fixture = open_initialized_store()?;
    let store = &mut fixture.store;
    insert_project_profile(store)?;
    store.insert_project_if_absent("lk_proj_shared_test", "@shared", 1)?;
    store.insert_profile_if_absent("lk_prof_shared", "lk_proj_shared_test", "default", false, 1)?;
    store.create_active_secret(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
    )?;
    let shared_secret = SecretRecord {
        id: "lk_sec_shared_dup".into(),
        project_id: "lk_proj_shared_test".into(),
        profile_id: "lk_prof_shared".into(),
        name: "GLOBAL_RPC".into(),
        source: "user-local".into(),
        origin: "manual".into(),
        current_version: 1,
        state: "active".into(),
        created_at: 10,
        updated_at: 10,
        last_rotated_at: None,
        deleted_at: None,
    };
    let shared_version = SecretVersionRecord {
        secret_id: shared_secret.id.clone(),
        version: 1,
        source: "user-local".into(),
        origin: "manual".into(),
        state: "current".into(),
        created_at: 10,
        deprecated_at: None,
        grace_until: None,
        purged_at: None,
    };
    let shared_blob = SecretBlobRecord {
        secret_id: shared_secret.id.clone(),
        version: 1,
        encrypted_dek: vec![1; 40],
        ciphertext: vec![2; 40],
        value_nonce: [3; 24],
        aad_schema_version: 1,
        created_at: 10,
    };
    let shared_fp = SecretFingerprintRecord {
        secret_id: shared_secret.id.clone(),
        version: 1,
        fingerprint: vec![4; 32],
        created_at: 10,
    };
    store.create_active_secret(&shared_secret, &shared_version, &shared_blob, &shared_fp)?;

    let tag = [0xAB_u8; 32];
    store.upsert_local_value_fingerprint(&test_secret().id, 1, &tag, 20)?;
    store.upsert_local_value_fingerprint(&shared_secret.id, 1, &tag, 20)?;

    let matches = store.find_active_secrets_by_dedup_tag(&tag)?;
    assert_eq!(matches.len(), 2);
    assert!(matches[0].is_shared);
    assert_eq!(matches[0].name, "GLOBAL_RPC");
    assert_eq!(matches[1].name, test_secret().name);

    let groups = store.list_duplicate_value_groups()?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].members.len(), 2);

    store.tombstone_secret(&test_secret().id, 30)?;
    store.purge_secret_version(&test_secret().id, 1, 40)?;
    assert_eq!(store.find_active_secrets_by_dedup_tag(&tag)?.len(), 1);
    assert_eq!(store.list_duplicate_value_groups()?.len(), 0);
    Ok(())
}
