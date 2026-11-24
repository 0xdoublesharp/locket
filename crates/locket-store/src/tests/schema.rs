use std::error::Error;

use tempfile::tempdir;

use crate::{AUDIT_ACTION_SCHEMA_MIGRATE, SCHEMA_VERSION, Store, StoreError};

use super::{insert_project_profile, insert_project_profile_secret, open_initialized_store};

#[test]
fn creates_schema_and_records_migration() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    let connection = test_store.store.connection();

    for table in [
        "projects",
        "profiles",
        "secrets",
        "secret_versions",
        "blobs",
        "keys",
        "devices",
        "passkey_credentials",
        "automation_clients",
        "automation_client_private_key_refs",
        "automation_client_nonces",
        "teams",
        "team_members",
        "team_invites",
        "command_policies",
        "project_roots",
        "directory_grants",
        "audit_log",
        "audit_witness_receipts",
        "imported_audit_chains",
        "fingerprints",
        "runtime_sessions",
        "schema_migrations",
    ] {
        let exists = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(exists, 1, "{table} should exist");
    }

    let schema_version =
        connection.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get::<_, u32>(0)
        })?;
    assert_eq!(schema_version, SCHEMA_VERSION);

    let rp_id_column = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('passkey_credentials')
         WHERE name = 'webauthn_relying_party_id'
           AND type = 'TEXT'
           AND \"notnull\" = 1
           AND dflt_value = '''locket.localhost'''",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(rp_id_column, 1, "passkey credentials must persist the WebAuthn RP ID");

    for (name, type_name, notnull) in [
        ("device_id", "TEXT", 1),
        ("member_id", "TEXT", 0),
        ("public_key", "BLOB", 1),
        ("user_handle", "BLOB", 1),
    ] {
        let column = connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('passkey_credentials')
             WHERE name = ?1 AND type = ?2 AND \"notnull\" = ?3",
            (name, type_name, notnull),
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(column, 1, "passkey_credentials.{name} must match the data model");
    }

    let foreign_keys =
        connection.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))?;
    assert_eq!(foreign_keys, 1);

    Ok(())
}

#[test]
fn automation_private_key_refs_enforce_metadata_only_storage() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    let connection = test_store.store.connection();

    insert_schema_project(connection)?;
    insert_schema_automation_client(connection)?;
    connection.execute(
        "INSERT INTO automation_client_private_key_refs(
           client_id, storage, keychain_service, keychain_account, metadata_json, created_at,
           updated_at
         )
         VALUES (
           'lk_client_schema', 'os-keychain', 'locket', 'lk_client_schema', '{}', 1, 1
         )",
        [],
    )?;

    let bad_key_ref = connection.execute(
        "INSERT INTO automation_client_private_key_refs(
           client_id, storage, keychain_service, keychain_account, local_path_hash, created_at,
           updated_at
         )
         VALUES (
           'lk_client_missing', 'os-keychain', 'locket', 'missing', 'path-hash', 1, 1
         )",
        [],
    );
    assert!(bad_key_ref.is_err());

    Ok(())
}

#[test]
fn team_required_tables_enforce_metadata_constraints() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    let connection = test_store.store.connection();

    insert_schema_project(connection)?;
    connection.execute(
        "INSERT INTO teams(id, project_id, name, created_at, updated_at)
         VALUES ('lk_team_schema', 'lk_proj_schema', 'app-team', 1, 1)",
        [],
    )?;
    connection.execute(
        "INSERT INTO team_members(id, team_id, display_name, role, joined_at)
         VALUES ('lk_member_schema', 'lk_team_schema', 'Alice', 'owner', 1)",
        [],
    )?;
    connection.execute(
        "UPDATE team_members
            SET profiles_json = '[\"dev\"]'
          WHERE id = 'lk_member_schema'",
        [],
    )?;
    let bad_member_profiles = connection.execute(
        "INSERT INTO team_members(id, team_id, display_name, role, profiles_json, joined_at)
         VALUES (
           'lk_member_bad_profiles', 'lk_team_schema', 'Bad Profiles', 'developer',
           'not-json', 1
         )",
        [],
    );
    assert!(bad_member_profiles.is_err());
    let bad_member_profile_shape = connection.execute(
        "INSERT INTO team_members(id, team_id, display_name, role, profiles_json, joined_at)
         VALUES (
           'lk_member_bad_profile_shape', 'lk_team_schema', 'Bad Profile Shape', 'developer',
           '{}', 1
         )",
        [],
    );
    assert!(bad_member_profile_shape.is_err());
    connection.execute(
        "INSERT INTO devices(
           id, project_id, name, signing_public_key, sealing_public_key, fingerprint,
           safety_words_json, local, created_at
         )
         VALUES (
           'lk_dev_schema', 'lk_proj_schema', 'workstation', zeroblob(32), zeroblob(32),
           'fp-schema', '[]', 0, 1
         )",
        [],
    )?;
    connection.execute(
        "INSERT INTO team_members(id, team_id, device_id, display_name, role, joined_at)
         VALUES ('lk_member_device_schema', 'lk_team_schema', 'lk_dev_schema', 'Alice laptop',
                 'developer', 1)",
        [],
    )?;
    connection.execute("DELETE FROM devices WHERE id = 'lk_dev_schema'", [])?;
    let cleared_device_id: Option<String> = connection.query_row(
        "SELECT device_id FROM team_members WHERE id = 'lk_member_device_schema'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(cleared_device_id, None, "device retirement must retain member history");

    connection.execute(
        "INSERT INTO team_invites(
           id, team_id, issuer_member_id, recipient_device_fingerprint, role, profiles_json,
           nonce, created_at, expires_at
         )
         VALUES (
           'lk_invite_schema', 'lk_team_schema', 'lk_member_schema', 'recipient-fp',
           'developer', '[\"dev\"]', zeroblob(24), 1, 2
         )",
        [],
    )?;

    let bad_invite_json = connection.execute(
        "INSERT INTO team_invites(
           id, team_id, recipient_device_fingerprint, role, profiles_json, nonce, created_at,
           expires_at
         )
         VALUES (
           'lk_invite_bad_json', 'lk_team_schema', 'recipient-fp', 'developer',
           'not-json', zeroblob(24), 1, 2
         )",
        [],
    );
    assert!(bad_invite_json.is_err());

    Ok(())
}

#[test]
fn policy_and_imported_audit_tables_enforce_metadata_constraints() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    let connection = test_store.store.connection();

    insert_schema_project(connection)?;
    connection.execute(
        "INSERT INTO command_policies(
           project_id, name, policy_json, normalized_json, created_at, updated_at
         )
         VALUES ('lk_proj_schema', 'dev', '{\"argv\":[\"true\"]}', '{\"argv\":[\"true\"]}', 1, 1)",
        [],
    )?;

    let bad_policy_json = connection.execute(
        "INSERT INTO command_policies(
           project_id, name, policy_json, normalized_json, created_at, updated_at
         )
         VALUES ('lk_proj_schema', 'bad', 'not-json', '{}', 1, 1)",
        [],
    );
    assert!(bad_policy_json.is_err());

    connection.execute(
        "INSERT INTO imported_audit_chains(
           id, project_id, source_device_fingerprint, bundle_digest, checkpoint_sequence,
           checkpoint_hmac, encrypted_rows, nonce, aad_schema_version, imported_at
         )
         VALUES (
           'lk_chain_schema', 'lk_proj_schema', 'device-fp', zeroblob(32), 1, zeroblob(32),
           zeroblob(16), zeroblob(24), 1, 1
         )",
        [],
    )?;

    let bad_imported_chain = connection.execute(
        "INSERT INTO imported_audit_chains(
           id, project_id, source_device_fingerprint, bundle_digest, checkpoint_sequence,
           checkpoint_hmac, encrypted_rows, nonce, aad_schema_version, imported_at
         )
         VALUES (
           'lk_chain_bad', 'lk_proj_schema', 'device-fp', zeroblob(16), 1, zeroblob(32),
           zeroblob(16), zeroblob(24), 1, 1
         )",
        [],
    );
    assert!(bad_imported_chain.is_err());

    Ok(())
}

fn insert_schema_project(connection: &rusqlite::Connection) -> Result<(), Box<dyn Error>> {
    connection.execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_schema', 'app', 1)",
        [],
    )?;
    Ok(())
}

fn insert_schema_automation_client(
    connection: &rusqlite::Connection,
) -> Result<(), Box<dyn Error>> {
    connection.execute(
        "INSERT INTO automation_clients(
           id, project_id, name, public_key, fingerprint, storage, allowed_actions_json,
           allowed_policies_json, created_at
         )
         VALUES (
           'lk_client_schema', 'lk_proj_schema', 'ci', zeroblob(32), 'fp',
           'external', '[]', '[]', 1
         )",
        [],
    )?;
    Ok(())
}

#[test]
fn schema_initialization_is_idempotent() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;

    assert_eq!(test_store.store.current_schema_version()?, Some(i64::from(SCHEMA_VERSION)));
    let outcome = test_store.store.initialize_schema()?;
    assert!(!outcome.advanced(), "no-op initialize must not advance the ledger");
    assert_eq!(outcome.applied_steps.len(), 0);
    assert_eq!(outcome.before, Some(SCHEMA_VERSION));
    assert_eq!(outcome.after, SCHEMA_VERSION);

    let migration_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
        [i64::from(SCHEMA_VERSION)],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(migration_rows, 1);

    Ok(())
}

#[test]
fn fresh_initialize_reports_pending_schema_migration() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("store.db");
    let mut store = Store::open(path)?;

    let outcome = store.initialize_schema()?;
    assert!(outcome.advanced(), "fresh store must advance the ledger");
    assert_eq!(outcome.before, None);
    assert_eq!(outcome.after, SCHEMA_VERSION);
    assert_eq!(outcome.applied_steps.as_slice(), &["schema.bootstrap_v7"]);

    Ok(())
}

#[test]
fn v1_store_migrates_recent_schema_alignment_columns_and_indexes() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("store.db");
    let mut store = Store::open(path)?;
    create_legacy_v1_schema(store.connection())?;

    let outcome = store.initialize_schema()?;

    assert!(outcome.advanced(), "v1 store must advance to current schema");
    assert_eq!(outcome.before, Some(1));
    assert_eq!(outcome.after, SCHEMA_VERSION);
    assert_eq!(
        outcome.applied_steps.as_slice(),
        &[
            "schema.migrate_v2_recent_schema_alignment",
            "schema.migrate_v3_team_member_profiles",
            "schema.migrate_v4_device_signing",
            "schema.migrate_v5_authenticated_team_sync",
            "schema.migrate_v6_pending_team_profiles",
            "schema.migrate_v7_expiry_and_witnesses",
        ]
    );
    assert_eq!(store.current_schema_version()?, Some(i64::from(SCHEMA_VERSION)));

    for (table, column) in [
        ("directory_grants", "granted_by"),
        ("directory_grants", "revoked_at"),
        ("devices", "member_id"),
        ("devices", "label"),
        ("team_members", "profiles_json"),
        ("passkey_credentials", "device_id"),
        ("passkey_credentials", "member_id"),
        ("passkey_credentials", "public_key"),
        ("passkey_credentials", "user_handle"),
    ] {
        assert!(column_exists(store.connection(), table, column)?, "{table}.{column} missing");
    }

    for index in [
        "secrets_bundle_conflict_idx",
        "devices_member_idx",
        "directory_grants_active_idx",
        "passkey_credentials_device_idx",
        "passkey_credentials_member_idx",
    ] {
        assert!(index_exists(store.connection(), index)?, "{index} missing");
    }

    let migrated_label: String = store.connection().query_row(
        "SELECT label FROM devices WHERE id = 'lk_dev_legacy'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(migrated_label, "", "legacy devices must receive the label default");

    Ok(())
}

#[test]
fn record_schema_migrate_audit_skips_when_no_steps_applied() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let outcome = test_store.store.initialize_schema()?;
    assert!(!outcome.advanced());

    let wrote = test_store.store.record_schema_migrate_audit(
        "lk_proj_test",
        &[42; 32],
        &outcome,
        1_700_000_000_000_000_000,
    )?;
    assert!(!wrote, "no row must be written when no steps were applied");

    let actions = test_store.store.list_recent_audit_actions("lk_proj_test", 8)?;
    assert!(actions.is_empty(), "no audit rows must be written");

    Ok(())
}

#[test]
fn record_schema_migrate_audit_writes_row_for_advancement() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    // Simulate the fresh-initialize outcome (`before = None`, `after = 3`)
    // produced when the schema bootstrap actually advanced the ledger. The
    // outcome is constructed directly because v1 is the only schema family
    // and the ledger created during fresh initialization has no project
    // context yet to consume the row.
    let outcome = crate::SchemaMigrationOutcome {
        before: None,
        after: SCHEMA_VERSION,
        applied_steps: vec!["schema.bootstrap_v6"],
    };

    let wrote = test_store.store.record_schema_migrate_audit(
        "lk_proj_test",
        &[42; 32],
        &outcome,
        1_700_000_000_000_000_000,
    )?;
    assert!(wrote, "advancement must produce one audit row");

    let actions = test_store.store.list_recent_audit_actions("lk_proj_test", 8)?;
    assert_eq!(actions.as_slice(), &[AUDIT_ACTION_SCHEMA_MIGRATE.to_owned()]);

    let metadata_json: String = test_store.store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE project_id = ?1 AND action = ?2
         ORDER BY sequence DESC
         LIMIT 1",
        ["lk_proj_test", AUDIT_ACTION_SCHEMA_MIGRATE],
        |row| row.get::<_, String>(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata_json)?;
    assert_eq!(metadata["schema_versions"]["before"], serde_json::Value::Null);
    assert_eq!(metadata["schema_versions"]["after"], SCHEMA_VERSION);
    assert_eq!(metadata["migration_count"], 1);
    assert_eq!(metadata["check_names"][0], "schema.bootstrap_v6");
    assert_eq!(metadata["status"], "SUCCESS");

    Ok(())
}

#[test]
fn record_schema_migrate_audit_writes_row_for_stale_schema() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let outcome = crate::SchemaMigrationOutcome {
        before: Some(0),
        after: SCHEMA_VERSION,
        applied_steps: vec![
            "schema.migrate_v2_recent_schema_alignment",
            "schema.migrate_v3_team_member_profiles",
        ],
    };

    let wrote = test_store.store.record_schema_migrate_audit(
        "lk_proj_test",
        &[42; 32],
        &outcome,
        1_700_000_000_000_000_001,
    )?;
    assert!(wrote);

    let metadata_json: String = test_store.store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE project_id = ?1 AND action = ?2
         ORDER BY sequence DESC
         LIMIT 1",
        ["lk_proj_test", AUDIT_ACTION_SCHEMA_MIGRATE],
        |row| row.get::<_, String>(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata_json)?;
    assert_eq!(metadata["schema_versions"]["before"], 0);
    assert_eq!(metadata["schema_versions"]["after"], SCHEMA_VERSION);
    assert_eq!(metadata["migration_count"], 2);

    Ok(())
}

#[test]
fn current_schema_version_reports_absent_migration_ledger() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("store.db");
    let store = Store::open(path)?;

    assert_eq!(store.current_schema_version()?, None);
    Ok(())
}

#[test]
fn schema_initialization_rejects_newer_existing_version() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("store.db");
    let mut store = Store::open(path)?;
    store.connection().execute(
        "CREATE TABLE schema_migrations (
           version INTEGER PRIMARY KEY,
           applied_at INTEGER NOT NULL
         )",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, 1)",
        [i64::from(SCHEMA_VERSION) + 1],
    )?;

    let result = store.initialize_schema();

    match result {
        Err(StoreError::UnsupportedSchema { found, supported }) => {
            assert_eq!(found, i64::from(SCHEMA_VERSION) + 1);
            assert_eq!(supported, SCHEMA_VERSION);
        }
        other => return Err(format!("unexpected schema result: {other:?}").into()),
    }
    Ok(())
}

#[test]
fn store_errors_map_to_stable_locket_failures() {
    let unsupported = StoreError::UnsupportedSchema { found: 2, supported: SCHEMA_VERSION };
    assert_eq!(unsupported.locket_error(), locket_core::LocketError::SchemaNewerThanBinary);

    let audit = StoreError::AuditIntegrity { sequence: 1, reason: "row hmac mismatch".to_owned() };
    assert_eq!(audit.locket_error(), locket_core::LocketError::AuditIntegrityFailed);

    let busy = StoreError::Sqlite(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
        None,
    ));
    assert_eq!(busy.locket_error(), locket_core::LocketError::StorageBusy);

    let corrupt = StoreError::Sqlite(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
        None,
    ));
    assert_eq!(corrupt.locket_error(), locket_core::LocketError::CorruptDb);
}

#[test]
fn foreign_keys_are_enforced() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;

    let result = test_store.store.connection().execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_orphan', 'lk_proj_missing', 'orphan', 0, 1)",
        [],
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn schema_migrate_audit_action_constant_matches_spec() {
    assert_eq!(AUDIT_ACTION_SCHEMA_MIGRATE, "SCHEMA_MIGRATE");
}

#[test]
fn wal_journal_mode_is_enabled() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;

    let journal_mode =
        test_store
            .store
            .connection()
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?;

    // WAL mode reports "wal" after enabling.
    assert_eq!(journal_mode, "wal");
    Ok(())
}

#[test]
fn schema_migrations_applied_at_is_positive_integer() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;

    let applied_at = test_store.store.connection().query_row(
        "SELECT applied_at FROM schema_migrations WHERE version = ?1",
        [i64::from(SCHEMA_VERSION)],
        |row| row.get::<_, i64>(0),
    )?;

    assert!(applied_at > 0, "applied_at should be a positive Unix nanoseconds timestamp");
    Ok(())
}

#[test]
fn schema_version_constant_is_current() {
    assert_eq!(SCHEMA_VERSION, 7);
}

#[test]
fn schema_six_upgrades_with_existing_secrets_and_nullable_expiry() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile_secret(&test_store.store)?;
    test_store.store.connection().execute_batch(
        "DROP TABLE audit_witness_receipts;
         ALTER TABLE secrets DROP COLUMN expires_at;
         ALTER TABLE secrets DROP COLUMN rotate_after_days;
         DELETE FROM schema_migrations WHERE version = 7;",
    )?;

    let migration = test_store.store.initialize_schema()?;
    assert_eq!(migration.before, Some(6));
    assert_eq!(migration.after, 7);
    assert_eq!(migration.applied_steps, ["schema.migrate_v7_expiry_and_witnesses"]);
    assert_eq!(
        test_store.store.get_secret_expiry_policy("lk_sec_test")?,
        Some(crate::SecretExpiryPolicy::default())
    );
    assert_eq!(test_store.store.list_audit_witness_receipts("lk_proj_test")?, []);
    assert!(!test_store.store.initialize_schema()?.advanced());

    // A repeated migration must tolerate columns and the witness table already existing.
    let policy = crate::SecretExpiryPolicy { expires_at: Some(20), rotate_after_days: Some(2) };
    assert!(test_store.store.set_secret_expiry_policy("lk_sec_test", policy, 10)?);
    test_store.store.connection().execute("DELETE FROM schema_migrations WHERE version = 7", [])?;
    assert!(test_store.store.initialize_schema()?.advanced());
    assert_eq!(test_store.store.get_secret_expiry_policy("lk_sec_test")?, Some(policy));
    Ok(())
}

#[test]
fn devices_table_persists_member_id_and_label_columns() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    let connection = test_store.store.connection();

    // `Device.member_id: Option<MemberId>` and `Device.label: String` from
    // docs/specs/data-model.md lines 254-265 must be present.
    let member_id_column: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('devices')
         WHERE name = 'member_id' AND type = 'TEXT'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(member_id_column, 1, "devices.member_id must exist");

    let label_column: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('devices')
         WHERE name = 'label' AND type = 'TEXT' AND \"notnull\" = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(label_column, 1, "devices.label must exist as NOT NULL TEXT");

    Ok(())
}

#[test]
fn secrets_bundle_conflict_index_exists_and_supports_apply_path() -> Result<(), Box<dyn Error>> {
    // docs/specs/storage.md line 149 requires "bundle/import conflict
    // lookup by profile/name/version" indexes. The composite index on
    // secrets supports get_active_secret / get_secret_by_source filters
    // used by team-bundle apply for name/source-keyed conflict matching;
    // the secret_versions PRIMARY KEY (secret_id, version) covers the
    // version side of the same workflow.
    let test_store = open_initialized_store()?;
    let connection = test_store.store.connection();

    let bundle_index_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE type = 'index' AND name = 'secrets_bundle_conflict_idx'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(bundle_index_count, 1, "secrets_bundle_conflict_idx must exist");

    // Confirm the SQLite planner actually picks this index for the
    // bundle-conflict predicate. We seed at least one matching row so
    // the planner has up-to-date stats and intentionally do not run
    // ANALYZE — the partial-on-equality predicate plan is index-driven
    // regardless.
    insert_project_profile(&test_store.store)?;
    connection.execute(
        "INSERT INTO secrets(
           id, project_id, profile_id, name, source, origin, required, current_version, state,
           created_at, updated_at
         ) VALUES (
           'lk_secret_idx', 'lk_proj_test', 'lk_prof_test', 'DATABASE_URL', 'team-managed',
           'manual', 0, 1, 'active', 1, 1
         )",
        [],
    )?;

    let plan_rows = collect_query_plan(
        connection,
        "SELECT id FROM secrets
         WHERE project_id = ? AND profile_id = ? AND name = ? AND source = ? AND state = 'active'",
    )?;
    let plan_uses_index = plan_rows.iter().any(|line| line.contains("secrets_bundle_conflict_idx"));
    assert!(
        plan_uses_index,
        "EXPLAIN QUERY PLAN must reference secrets_bundle_conflict_idx; got {plan_rows:?}"
    );

    Ok(())
}

fn collect_query_plan(
    connection: &rusqlite::Connection,
    sql: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let plan_sql = format!("EXPLAIN QUERY PLAN {sql}");
    let mut statement = connection.prepare(&plan_sql)?;
    let rows = statement
        .query_map(["lk_proj_test", "lk_prof_test", "DATABASE_URL", "team-managed"], |row| {
            row.get::<_, String>(3)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[allow(clippy::too_many_lines)]
fn create_legacy_v1_schema(connection: &rusqlite::Connection) -> Result<(), Box<dyn Error>> {
    connection.execute_batch(
        r"
        CREATE TABLE schema_migrations (
          version INTEGER PRIMARY KEY,
          applied_at INTEGER NOT NULL
        );
        INSERT INTO schema_migrations(version, applied_at) VALUES (1, 1);

        CREATE TABLE projects (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          user_verification_policy_json TEXT NOT NULL DEFAULT '{}',
          created_at INTEGER NOT NULL
        );
        CREATE TABLE profiles (
          id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          dangerous INTEGER NOT NULL CHECK (dangerous IN (0, 1)),
          created_at INTEGER NOT NULL,
          UNIQUE (project_id, name)
        );
        CREATE TABLE teams (
          id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          UNIQUE (project_id, name)
        );
        CREATE TABLE team_members (
          id TEXT PRIMARY KEY,
          team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
          device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
          display_name TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('owner', 'maintainer', 'developer', 'read-only')),
          joined_at INTEGER NOT NULL,
          removed_at INTEGER,
          UNIQUE (team_id, display_name)
        );
        CREATE TABLE directory_grants (
          grant_id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
          root_hash BLOB NOT NULL CHECK (length(root_hash) = 32),
          directory_hash BLOB NOT NULL CHECK (length(directory_hash) = 32),
          grant_scope TEXT NOT NULL CHECK (grant_scope IN ('project-root')),
          display_path TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          UNIQUE (project_id, profile_id, root_hash, directory_hash, grant_scope)
        );
        CREATE TABLE secrets (
          id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          description TEXT,
          owner TEXT,
          source TEXT NOT NULL CHECK (source IN ('team-managed', 'user-local', 'machine-local')),
          origin TEXT NOT NULL CHECK (origin IN ('manual', 'imported', 'team-accept', 'profile-copy')),
          tags_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags_json)),
          required INTEGER NOT NULL CHECK (required IN (0, 1)),
          current_version INTEGER NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('active', 'deleted')),
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL,
          last_rotated_at INTEGER,
          deleted_at INTEGER,
          UNIQUE (project_id, profile_id, name, source)
        );
        CREATE TABLE devices (
          id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          signing_public_key BLOB NOT NULL CHECK (length(signing_public_key) = 32),
          sealing_public_key BLOB NOT NULL CHECK (length(sealing_public_key) = 32),
          fingerprint TEXT NOT NULL,
          safety_words_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(safety_words_json)),
          local INTEGER NOT NULL CHECK (local IN (0, 1)),
          created_at INTEGER NOT NULL,
          last_seen_at INTEGER,
          revoked_at INTEGER
        );
        CREATE TABLE passkey_credentials (
          id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
          label TEXT NOT NULL,
          credential_id BLOB NOT NULL CHECK (length(credential_id) > 0),
          transports_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(transports_json)),
          prf_capable INTEGER NOT NULL CHECK (prf_capable IN (0, 1)),
          webauthn_relying_party_id TEXT NOT NULL DEFAULT 'locket.localhost',
          backup_eligible INTEGER CHECK (backup_eligible IN (0, 1)),
          backup_state INTEGER CHECK (backup_state IN (0, 1)),
          created_at INTEGER NOT NULL,
          last_used_at INTEGER,
          revoked_at INTEGER,
          UNIQUE (project_id, label),
          UNIQUE (project_id, credential_id)
        );
        INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_legacy', 'legacy', 1);
        INSERT INTO devices(
          id, project_id, name, signing_public_key, sealing_public_key, fingerprint,
          safety_words_json, local, created_at
        )
        VALUES (
          'lk_dev_legacy', 'lk_proj_legacy', 'legacy-device', zeroblob(32), zeroblob(32),
          'legacy-fp', '[]', 1, 1
        );
        ",
    )?;
    Ok(())
}

fn column_exists(
    connection: &rusqlite::Connection,
    table: &str,
    column: &str,
) -> Result<bool, Box<dyn Error>> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn index_exists(connection: &rusqlite::Connection, index: &str) -> Result<bool, Box<dyn Error>> {
    let exists = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
        [index],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(exists == 1)
}

#[test]
fn directory_grants_table_persists_granted_by_and_revoked_at_columns() -> Result<(), Box<dyn Error>>
{
    let test_store = open_initialized_store()?;
    let connection = test_store.store.connection();

    // `DirectoryGrant.granted_by: Option<MemberId>` and
    // `DirectoryGrant.revoked_at: Option<Timestamp>` from data-model.md
    // lines 221-228.
    let granted_by_column: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('directory_grants')
         WHERE name = 'granted_by' AND type = 'TEXT' AND \"notnull\" = 0",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(granted_by_column, 1, "directory_grants.granted_by must exist as nullable TEXT");

    let revoked_at_column: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('directory_grants')
         WHERE name = 'revoked_at' AND type = 'INTEGER' AND \"notnull\" = 0",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(revoked_at_column, 1, "directory_grants.revoked_at must exist as nullable INTEGER");

    Ok(())
}

#[test]
fn newer_schema_version_blocks_initialization_before_any_tables_are_created()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("store.db");
    let mut store = Store::open(path)?;

    store.connection().execute(
        "CREATE TABLE schema_migrations (
           version INTEGER PRIMARY KEY,
           applied_at INTEGER NOT NULL
         )",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, 1)",
        [i64::from(SCHEMA_VERSION) + 1],
    )?;

    // The rest of the v1 tables are absent — verify the check fires before DDL.
    let result = store.initialize_schema();

    assert!(matches!(
        result,
        Err(StoreError::UnsupportedSchema { found, .. }) if found == i64::from(SCHEMA_VERSION) + 1
    ));

    let projects_absent = store.connection().query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'projects'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(projects_absent, 0, "rollback must leave other tables absent");

    Ok(())
}

#[test]
fn schema_five_adds_pending_tables_with_an_explicit_six_migration() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let mut store = Store::open(directory.path().join("store.db"))?;
    store.initialize_schema()?;
    store.connection().execute("DELETE FROM schema_migrations WHERE version >= 6", [])?;
    store.connection().execute_batch(
        "DROP TABLE team_sync_pending_profiles; DROP TABLE team_sync_pending_packages;",
    )?;
    store.connection().execute_batch("ALTER TABLE team_sync_folders DROP COLUMN scan_after; ALTER TABLE team_sync_folders DROP COLUMN last_error;")?;
    store.insert_project_if_absent("old-team-project", "fixture", 1)?;
    store.connection().execute(
        "INSERT INTO team_sync_heads VALUES ('old-team-project',5,'head-five','[]','verified',1)",
        [],
    )?;
    store.connection().execute("INSERT INTO team_sync_seen VALUES ('old-team-project','first-three',3,'applied'),('old-team-project','head-five',5,'applied')",[])?;
    let migration = store.initialize_schema()?;
    assert_eq!(migration.before, Some(5));
    assert_eq!(migration.after, 7);
    assert_eq!(
        migration.applied_steps,
        ["schema.migrate_v6_pending_team_profiles", "schema.migrate_v7_expiry_and_witnesses"]
    );
    let tables:i64=store.connection().query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('team_sync_pending_profiles','team_sync_pending_packages')",[],|row|row.get(0))?;
    assert_eq!(tables, 2);
    let join: i64 = store.connection().query_row(
        "SELECT epoch FROM team_sync_join_checkpoints WHERE project_id='old-team-project'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(join, 3, "upgrade preserves the earliest authenticated join boundary");
    assert!(column_exists(store.connection(), "team_sync_folders", "scan_after")?);
    assert!(column_exists(store.connection(), "team_sync_folders", "last_error")?);
    assert!(!store.initialize_schema()?.advanced());
    Ok(())
}

#[test]
fn read_only_store_preserves_legacy_schema_and_journal_and_rejects_writes()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("read-only.db");
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied_at INTEGER NOT NULL); INSERT INTO schema_migrations VALUES (5,1); CREATE TABLE report(label TEXT); INSERT INTO report VALUES ('metadata');")?;
    drop(connection);
    let before = std::fs::read(&path)?;
    let store = Store::open_read_only(&path)?;
    assert_eq!(
        store.connection().query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?,
        "delete"
    );
    assert_eq!(store.current_schema_version()?, Some(5));
    assert_eq!(
        store
            .connection()
            .query_row("SELECT label FROM report", [], |row| row.get::<_, String>(0))?,
        "metadata"
    );
    assert!(store.connection().execute("INSERT INTO report VALUES ('forbidden')", []).is_err());
    assert!(store.connection().execute_batch("CREATE TABLE forbidden(value TEXT)").is_err());
    drop(store);
    assert_eq!(std::fs::read(&path)?, before);
    let after = rusqlite::Connection::open(&path)?;
    assert_eq!(
        after.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?,
        "delete"
    );
    assert_eq!(
        after.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| row
            .get::<_, i64>(0))?,
        5
    );
    Ok(())
}

#[test]
fn read_only_store_does_not_create_a_missing_database() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("missing.db");
    assert!(Store::open_read_only(&path).is_err());
    assert!(!path.exists());
    Ok(())
}
