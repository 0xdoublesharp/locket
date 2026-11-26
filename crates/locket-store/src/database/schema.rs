//! `SQLite` schema bootstrap and connection configuration.

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};

use crate::error::StoreError;

/// Current storage schema version.
pub const SCHEMA_VERSION: u32 = 1;

const BUSY_TIMEOUT_MS: u64 = 5_000;

pub fn configure_connection(
    connection: &Connection,
    writable: bool,
) -> Result<(), rusqlite::Error> {
    connection.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    connection.pragma_update(None, "secure_delete", "ON")?;
    if writable {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
    }
    Ok(())
}

/// Creates a fresh store at [`SCHEMA_VERSION`] or opens one already at it.
///
/// Older stores, newer stores, and stores without a schema ledger are rejected.
pub fn initialize_schema(connection: &mut Connection) -> Result<(), StoreError> {
    // Inspect the ledger and catalog under the same write reservation used
    // for bootstrap. Another initializer can otherwise commit between reads.
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    match current_schema_version(&transaction)? {
        Some(version) => require_supported_schema(version)?,
        None if store_has_tables(&transaction)? => {
            return Err(StoreError::OutdatedSchema { found: 0, supported: SCHEMA_VERSION });
        }
        None => {}
    }
    transaction.execute_batch(SCHEMA_SQL)?;
    // Existing vaults on this schema version retain their shared-folder rows.
    for (column, sql) in [
        (
            "transport_kind",
            "ALTER TABLE team_sync_folders ADD COLUMN transport_kind TEXT NOT NULL DEFAULT 'folder'",
        ),
        (
            "transport_config_json",
            "ALTER TABLE team_sync_folders ADD COLUMN transport_config_json TEXT",
        ),
    ] {
        let exists = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('team_sync_folders') WHERE name = ?1)",
            [column],
            |row| row.get::<_, bool>(0),
        )?;
        if !exists {
            transaction.execute_batch(sql)?;
        }
    }
    transaction.execute(
        "INSERT OR IGNORE INTO schema_migrations(version, applied_at)
         VALUES (?1, CAST(strftime('%s', 'now') AS INTEGER) * 1000000000)",
        [i64::from(SCHEMA_VERSION)],
    )?;
    transaction.commit()?;
    Ok(())
}

pub fn current_schema_version(connection: &Connection) -> Result<Option<i64>, StoreError> {
    let migrations_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();

    if !migrations_exists {
        return Ok(None);
    }

    let version =
        connection.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get::<_, Option<i64>>(0)
        })?;

    Ok(version)
}

const fn require_supported_schema(version: i64) -> Result<(), StoreError> {
    if version > SCHEMA_VERSION as i64 {
        return Err(StoreError::UnsupportedSchema { found: version, supported: SCHEMA_VERSION });
    }
    if version < SCHEMA_VERSION as i64 {
        return Err(StoreError::OutdatedSchema { found: version, supported: SCHEMA_VERSION });
    }
    Ok(())
}

fn store_has_tables(connection: &Connection) -> Result<bool, StoreError> {
    let table_count = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE type = 'table'
           AND name NOT LIKE 'sqlite_%'
           AND name != 'schema_migrations'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(table_count > 0)
}

const SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  user_verification_policy_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  dangerous INTEGER NOT NULL CHECK (dangerous IN (0, 1)),
  created_at INTEGER NOT NULL,
  UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS project_roots (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  root_hash BLOB NOT NULL CHECK (length(root_hash) = 32),
  display_path TEXT,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  PRIMARY KEY (project_id, root_hash)
);

CREATE INDEX IF NOT EXISTS project_roots_root_hash_idx
  ON project_roots(root_hash);

-- `directory_grants.granted_by` and `directory_grants.revoked_at`:
--   `docs/specs/data-model.md` (lines 221-228) declares
--   `DirectoryGrant.granted_by: Option<MemberId>` and
--   `DirectoryGrant.revoked_at: Option<Timestamp>`. Deny is a soft-revoke:
--   the row survives with `revoked_at` set so the audit chain references the
--   surviving grant id and downstream re-allow can revive it by clearing
--   `revoked_at` (deny → allow on the same scope reuses the prior row).
--   `granted_by` is nullable because v1 install paths predate the team
--   member binding; see `crates/locket-cli/src/commands/shell.rs` allow path.
CREATE TABLE IF NOT EXISTS directory_grants (
  grant_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  root_hash BLOB NOT NULL CHECK (length(root_hash) = 32),
  directory_hash BLOB NOT NULL CHECK (length(directory_hash) = 32),
  grant_scope TEXT NOT NULL CHECK (grant_scope IN ('project-root')),
  display_path TEXT,
  granted_by TEXT REFERENCES team_members(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  revoked_at INTEGER,
  UNIQUE (project_id, profile_id, root_hash, directory_hash, grant_scope)
);

CREATE INDEX IF NOT EXISTS directory_grants_project_root_idx
  ON directory_grants(project_id, root_hash);

CREATE INDEX IF NOT EXISTS directory_grants_active_idx
  ON directory_grants(project_id, profile_id, root_hash, directory_hash, grant_scope)
  WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  owner TEXT,
  source TEXT NOT NULL CHECK (source IN ('team-managed', 'user-local', 'machine-local')),
  origin TEXT NOT NULL CHECK (origin IN ('manual', 'imported', 'team-accept', 'profile-copy')),
  tags_json TEXT NOT NULL DEFAULT '[]',
  required INTEGER NOT NULL CHECK (required IN (0, 1)),
  current_version INTEGER NOT NULL CHECK (current_version >= 1 AND current_version <= 4294967295),
  state TEXT NOT NULL CHECK (state IN ('active', 'deleted')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_rotated_at INTEGER,
  deleted_at INTEGER,
  expires_at INTEGER,
  rotate_after_days INTEGER,
  UNIQUE (project_id, profile_id, name, source)
);

CREATE INDEX IF NOT EXISTS secrets_project_profile_name_idx
  ON secrets(project_id, profile_id, name);

-- Bundle/import conflict lookup support per docs/specs/storage.md line 149.
--
-- `apply_bundle_payload` (crates/locket-cli/src/commands/team/bundle.rs)
-- detects secret conflicts via `read_local_secret(secret_id)` (covered
-- by the `secrets` PRIMARY KEY) and, when an incoming row references a
-- name/profile pair instead of an existing local id, callers fall back
-- to `get_active_secret(project_id, profile_id, name, source)` and
-- `get_secret_by_source(project_id, profile_id, name, source)`. This
-- index covers the (project_id, profile_id, name, source, state)
-- predicate used by those callers and keeps `current_version` available
-- as an index column so conflict resolution can compare incoming
-- bundle-version against the local current_version without an extra
-- table fetch.
CREATE INDEX IF NOT EXISTS secrets_bundle_conflict_idx
  ON secrets(project_id, profile_id, name, source, state, current_version);

-- `secret_versions` already has a `PRIMARY KEY (secret_id, version)` that
-- supports `read_local_secret_version(secret_id, version)` lookups; no
-- additional index is required for the version side of bundle conflict
-- detection. Documented here so future readers don't add a redundant
-- composite index.

CREATE TABLE IF NOT EXISTS secret_versions (
  secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version >= 1 AND version <= 4294967295),
  source TEXT NOT NULL CHECK (source IN ('team-managed', 'user-local', 'machine-local')),
  origin TEXT NOT NULL CHECK (origin IN ('manual', 'imported', 'team-accept', 'profile-copy')),
  state TEXT NOT NULL CHECK (state IN ('current', 'deprecated', 'purged')),
  created_at INTEGER NOT NULL,
  deprecated_at INTEGER,
  grace_until INTEGER,
  purged_at INTEGER,
  PRIMARY KEY (secret_id, version)
);

CREATE TRIGGER IF NOT EXISTS secret_versions_source_matches_secret_insert
BEFORE INSERT ON secret_versions
FOR EACH ROW
WHEN NEW.source != (SELECT source FROM secrets WHERE id = NEW.secret_id)
BEGIN
  SELECT RAISE(ABORT, 'secret_versions.source must match secrets.source');
END;

CREATE TRIGGER IF NOT EXISTS secret_versions_source_matches_secret_update
BEFORE UPDATE OF secret_id, source ON secret_versions
FOR EACH ROW
WHEN NEW.source != (SELECT source FROM secrets WHERE id = NEW.secret_id)
BEGIN
  SELECT RAISE(ABORT, 'secret_versions.source must match secrets.source');
END;

CREATE TABLE IF NOT EXISTS blobs (
  secret_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  encrypted_dek BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  value_nonce BLOB NOT NULL CHECK (length(value_nonce) = 24),
  aad_schema_version INTEGER NOT NULL CHECK (aad_schema_version >= 1),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (secret_id, version),
  FOREIGN KEY (secret_id, version)
    REFERENCES secret_versions(secret_id, version)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS fingerprints (
  secret_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1 AND version <= 4294967295),
  fingerprint BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (secret_id, version),
  FOREIGN KEY (secret_id, version)
    REFERENCES secret_versions(secret_id, version)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS secret_links (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  local_name TEXT NOT NULL,
  target_project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  target_profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  target_secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK (project_id != target_project_id),
  UNIQUE (project_id, profile_id, local_name)
);

CREATE INDEX IF NOT EXISTS secret_links_target_idx
  ON secret_links(target_secret_id);

CREATE INDEX IF NOT EXISTS secret_links_project_profile_idx
  ON secret_links(project_id, profile_id, local_name);

CREATE TABLE IF NOT EXISTS local_value_fingerprints (
  secret_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1 AND version <= 4294967295),
  dedup_tag BLOB NOT NULL CHECK (length(dedup_tag) = 32),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (secret_id, version),
  FOREIGN KEY (secret_id, version)
    REFERENCES secret_versions(secret_id, version)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS local_value_fingerprints_tag_idx
  ON local_value_fingerprints(dedup_tag);

CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK (purpose IN ('project-metadata', 'project-audit', 'profile-secret', 'profile-fingerprint')),
  wrapped_material BLOB NOT NULL,
  nonce BLOB NOT NULL CHECK (length(nonce) = 24),
  created_at INTEGER NOT NULL,
  CHECK (
    (profile_id IS NULL AND purpose IN ('project-metadata', 'project-audit'))
    OR
    (profile_id IS NOT NULL AND purpose IN ('profile-secret', 'profile-fingerprint'))
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS keys_project_scope_unique
  ON keys(project_id, purpose)
  WHERE profile_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS keys_profile_scope_unique
  ON keys(project_id, profile_id, purpose)
  WHERE profile_id IS NOT NULL;

-- `devices.member_id` and `devices.label`:
--   `docs/specs/data-model.md` (lines 254-265) declares
--   `Device.member_id: Option<MemberId>` and `Device.label: String`
--   alongside `Device.name`. v1 stores both: `name` keeps acting as the
--   stable, unique identifier across active rows (used by the
--   `devices_active_name_unique_idx` partial index and CLI selectors that
--   match by id/name/fingerprint), and `label` is a separate display
--   string. Existing rows migrate cleanly because `label` defaults to ''
--   and `member_id` defaults to NULL. The forward `devices.member_id ->
--   team_members(id)` link complements the inverse `team_members.device_id`
--   so device cards can render the bound member without join gymnastics.
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  member_id TEXT REFERENCES team_members(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  signing_public_key BLOB NOT NULL CHECK (length(signing_public_key) = 32),
  sealing_public_key BLOB NOT NULL CHECK (length(sealing_public_key) = 32),
  fingerprint TEXT NOT NULL,
  safety_words_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(safety_words_json)),
  local INTEGER NOT NULL CHECK (local IN (0, 1)),
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS devices_member_idx
  ON devices(project_id, member_id)
  WHERE member_id IS NOT NULL AND revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS devices_active_name_unique_idx
  ON devices(project_id, name)
  WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS devices_active_fingerprint_unique_idx
  ON devices(project_id, fingerprint)
  WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS devices_one_active_local_idx
  ON devices(project_id)
  WHERE local = 1 AND revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS passkey_credentials (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  member_id TEXT REFERENCES team_members(id) ON DELETE SET NULL,
  label TEXT NOT NULL,
  credential_id BLOB NOT NULL CHECK (length(credential_id) > 0),
  public_key BLOB NOT NULL CHECK (length(public_key) > 0),
  transports_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(transports_json)),
  prf_capable INTEGER NOT NULL CHECK (prf_capable IN (0, 1)),
  webauthn_relying_party_id TEXT NOT NULL DEFAULT 'locket.localhost',
  user_handle BLOB NOT NULL CHECK (length(user_handle) = 32),
  backup_eligible INTEGER CHECK (backup_eligible IN (0, 1)),
  backup_state INTEGER CHECK (backup_state IN (0, 1)),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER,
  UNIQUE (project_id, label),
  UNIQUE (project_id, credential_id)
);

CREATE INDEX IF NOT EXISTS passkey_credentials_project_revoked_idx
  ON passkey_credentials(project_id, revoked_at);

CREATE INDEX IF NOT EXISTS passkey_credentials_device_idx
  ON passkey_credentials(project_id, device_id)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS passkey_credentials_member_idx
  ON passkey_credentials(project_id, member_id)
  WHERE member_id IS NOT NULL AND revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS passkey_prf_wraps (
  passkey_id TEXT PRIMARY KEY REFERENCES passkey_credentials(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  prf_salt BLOB NOT NULL CHECK (length(prf_salt) >= 16),
  wrapped_master_key BLOB NOT NULL CHECK (length(wrapped_master_key) > 0),
  wrap_nonce BLOB NOT NULL CHECK (length(wrap_nonce) = 24),
  created_at INTEGER NOT NULL,
  UNIQUE (project_id, passkey_id)
);

CREATE INDEX IF NOT EXISTS passkey_prf_wraps_project_idx
  ON passkey_prf_wraps(project_id);

CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (project_id, name)
);

CREATE UNIQUE INDEX IF NOT EXISTS teams_one_per_project_idx
  ON teams(project_id);

-- `team_members.device_id`:
--   `docs/specs/storage.md` (lines 26-51) lists `team_members` as a
--   required table without dictating an FK rule. The `TeamMember` model
--   in `docs/specs/data-model.md` describes a member with
--   `trusted_devices: Vec<DeviceId>`; v1 SQLite stores the active
--   trusted device per row and uses the partial unique index
--   `team_members_active_device_idx` plus extra rows to express the
--   1-to-many relationship without a join table. Deleting a `device`
--   row clears `device_id` to NULL (`ON DELETE SET NULL`) so the
--   audit-relevant member row survives device retirement and the unique
--   active-device index does not block re-binding the member to a new
--   device. This matches the spec intent.
CREATE TABLE IF NOT EXISTS team_members (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'maintainer', 'developer', 'read-only')),
  profiles_json TEXT CHECK (profiles_json IS NULL OR (json_valid(profiles_json) AND json_type(profiles_json) = 'array')),
  joined_at INTEGER NOT NULL,
  removed_at INTEGER,
  CHECK (removed_at IS NULL OR removed_at >= joined_at),
  UNIQUE (team_id, display_name)
);

CREATE UNIQUE INDEX IF NOT EXISTS team_members_active_device_idx
  ON team_members(team_id, device_id)
  WHERE device_id IS NOT NULL AND removed_at IS NULL;

CREATE INDEX IF NOT EXISTS team_members_team_role_idx
  ON team_members(team_id, role)
  WHERE removed_at IS NULL;

CREATE TABLE IF NOT EXISTS team_invites (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  issuer_member_id TEXT REFERENCES team_members(id) ON DELETE SET NULL,
  recipient_device_fingerprint TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'maintainer', 'developer', 'read-only')),
  profiles_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(profiles_json)),
  nonce BLOB NOT NULL CHECK (length(nonce) = 24),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  accepted_at INTEGER,
  revoked_at INTEGER,
  CHECK (expires_at > created_at),
  CHECK (accepted_at IS NULL OR accepted_at >= created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX IF NOT EXISTS team_invites_team_status_idx
  ON team_invites(team_id, expires_at, accepted_at, revoked_at);

CREATE TABLE IF NOT EXISTS command_policies (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  policy_json TEXT NOT NULL CHECK (json_valid(policy_json)),
  normalized_json TEXT NOT NULL CHECK (json_valid(normalized_json)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (project_id, name)
);

CREATE INDEX IF NOT EXISTS command_policies_project_updated_idx
  ON command_policies(project_id, updated_at);

CREATE TABLE IF NOT EXISTS audit_log (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL CHECK (sequence >= 1),
  schema_version INTEGER NOT NULL CHECK (schema_version >= 1 AND schema_version <= 4294967295),
  timestamp INTEGER NOT NULL,
  profile_id TEXT REFERENCES profiles(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  secret_name TEXT,
  command TEXT,
  previous_hmac BLOB CHECK (previous_hmac IS NULL OR length(previous_hmac) = 32),
  hmac BLOB NOT NULL CHECK (length(hmac) = 32),
  PRIMARY KEY (project_id, sequence)
);

CREATE TABLE IF NOT EXISTS audit_witness_receipts (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  seq_no INTEGER NOT NULL CHECK (seq_no >= 1),
  checkpoint_hmac_hex TEXT NOT NULL,
  prev_receipt_sha256_hex TEXT,
  receipt_sha256_hex TEXT NOT NULL UNIQUE,
  witness_id TEXT NOT NULL,
  signer_id TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  recorded_at INTEGER NOT NULL,
  UNIQUE (project_id, seq_no)
);

CREATE UNIQUE INDEX IF NOT EXISTS audit_witness_receipts_project_nonce_idx
  ON audit_witness_receipts(project_id, json_extract(receipt_json, '$.statement.nonce_hex'));

CREATE TABLE IF NOT EXISTS imported_audit_chains (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source_device_fingerprint TEXT NOT NULL,
  bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
  checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence >= 1),
  checkpoint_hmac BLOB NOT NULL CHECK (length(checkpoint_hmac) = 32),
  encrypted_rows BLOB NOT NULL,
  nonce BLOB NOT NULL CHECK (length(nonce) = 24),
  aad_schema_version INTEGER NOT NULL CHECK (aad_schema_version >= 1),
  imported_at INTEGER NOT NULL,
  UNIQUE (project_id, source_device_fingerprint, bundle_digest)
);

CREATE INDEX IF NOT EXISTS imported_audit_chains_conflict_idx
  ON imported_audit_chains(project_id, bundle_digest, checkpoint_sequence);

CREATE TABLE IF NOT EXISTS runtime_sessions (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  policy_name TEXT,
  process_id INTEGER NOT NULL CHECK (process_id >= 0 AND process_id <= 4294967295),
  process_start_time INTEGER NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  exit_status INTEGER,
  secret_names_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(secret_names_json)),
  spawn_audit_sequence INTEGER CHECK (spawn_audit_sequence IS NULL OR spawn_audit_sequence >= 1),
  completion_audit_sequence INTEGER CHECK (
    completion_audit_sequence IS NULL OR completion_audit_sequence >= 1
  ),
  CHECK (ended_at IS NULL OR ended_at >= started_at),
  CHECK ((ended_at IS NULL AND exit_status IS NULL) OR ended_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS runtime_sessions_project_incomplete_idx
  ON runtime_sessions(project_id, started_at)
  WHERE ended_at IS NULL;

CREATE INDEX IF NOT EXISTS runtime_sessions_project_secret_names_retention_idx
  ON runtime_sessions(project_id, started_at)
  WHERE secret_names_json != '[]';

CREATE INDEX IF NOT EXISTS runtime_sessions_process_identity_idx
  ON runtime_sessions(process_id, process_start_time);

CREATE TABLE IF NOT EXISTS automation_clients (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  public_key BLOB NOT NULL CHECK (length(public_key) = 32),
  fingerprint TEXT NOT NULL,
  storage TEXT NOT NULL CHECK (storage IN ('external', 'os-keychain', 'wrapped-local-file')),
  allowed_actions_json TEXT NOT NULL CHECK (json_valid(allowed_actions_json)),
  allowed_policies_json TEXT NOT NULL CHECK (json_valid(allowed_policies_json)),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER,
  UNIQUE (project_id, name),
  UNIQUE (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS automation_clients_project_active_idx
  ON automation_clients(project_id, name)
  WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS automation_client_private_key_refs (
  client_id TEXT PRIMARY KEY REFERENCES automation_clients(id) ON DELETE CASCADE,
  storage TEXT NOT NULL CHECK (storage IN ('os-keychain', 'wrapped-local-file')),
  keychain_service TEXT,
  keychain_account TEXT,
  local_path_hash TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK (
    (
      storage = 'os-keychain'
      AND keychain_service IS NOT NULL
      AND keychain_account IS NOT NULL
      AND local_path_hash IS NULL
    )
    OR
    (
      storage = 'wrapped-local-file'
      AND keychain_service IS NULL
      AND keychain_account IS NULL
      AND local_path_hash IS NOT NULL
    )
  )
);

CREATE TABLE IF NOT EXISTS automation_client_nonces (
  client_id TEXT NOT NULL REFERENCES automation_clients(id) ON DELETE CASCADE,
  nonce BLOB NOT NULL CHECK (length(nonce) = 24),
  request_timestamp INTEGER NOT NULL,
  seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (client_id, nonce)
);

CREATE TABLE IF NOT EXISTS team_sync_anchors (
 project_id TEXT PRIMARY KEY REFERENCES projects(id), team_id TEXT NOT NULL,
 owner_json TEXT NOT NULL, pinned_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS team_sync_join_checkpoints (
 project_id TEXT PRIMARY KEY REFERENCES projects(id), epoch INTEGER NOT NULL CHECK(epoch > 0)
);
CREATE TABLE IF NOT EXISTS team_sync_heads (
 project_id TEXT PRIMARY KEY REFERENCES projects(id), epoch INTEGER NOT NULL,
 digest TEXT NOT NULL, members_json TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'verified',
 verified_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS team_sync_seen (
 project_id TEXT NOT NULL, digest TEXT NOT NULL, epoch INTEGER NOT NULL,
 outcome TEXT NOT NULL, PRIMARY KEY(project_id,digest)
);
CREATE TABLE IF NOT EXISTS team_sync_values (
 project_id TEXT NOT NULL, secret_id TEXT NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(project_id,secret_id)
);
CREATE TABLE IF NOT EXISTS team_sync_profile_epochs (
 project_id TEXT NOT NULL, profile_id TEXT NOT NULL, epoch INTEGER NOT NULL,
 PRIMARY KEY(project_id,profile_id)
);
CREATE TABLE IF NOT EXISTS team_sync_conflicts (
 project_id TEXT NOT NULL, secret_id TEXT NOT NULL, epoch INTEGER NOT NULL,
 encrypted_package BLOB NOT NULL, PRIMARY KEY(project_id,secret_id)
);
CREATE TABLE IF NOT EXISTS team_sync_pending_packages (
 project_id TEXT PRIMARY KEY REFERENCES projects(id), epoch INTEGER NOT NULL,
 digest TEXT NOT NULL, encrypted_package BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS team_sync_pending_profiles (
 project_id TEXT NOT NULL REFERENCES team_sync_pending_packages(project_id) ON DELETE CASCADE,
 profile_id TEXT NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(project_id,profile_id)
);
CREATE TABLE IF NOT EXISTS team_sync_folders (
 project_id TEXT PRIMARY KEY REFERENCES projects(id), path TEXT NOT NULL,
 device_key_root TEXT NOT NULL, allow_dangerous INTEGER NOT NULL DEFAULT 0,
 enabled INTEGER NOT NULL DEFAULT 1, last_error TEXT, scan_after TEXT,
 transport_kind TEXT NOT NULL DEFAULT 'folder', transport_config_json TEXT
);
CREATE TABLE IF NOT EXISTS team_sync_credentials (
 project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
 ciphertext BLOB NOT NULL,
 nonce BLOB NOT NULL CHECK (length(nonce) = 24),
 aad_schema_version INTEGER NOT NULL DEFAULT 1,
 updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS team_sync_outbound (
 project_id TEXT NOT NULL, recipient TEXT NOT NULL, epoch INTEGER NOT NULL,
 digest TEXT NOT NULL, content_digest TEXT NOT NULL, expires_at INTEGER NOT NULL,
 PRIMARY KEY(project_id,recipient)
);
CREATE TABLE IF NOT EXISTS team_sync_outbox (
 project_id TEXT NOT NULL, filename TEXT NOT NULL, recipient TEXT NOT NULL,
 ciphertext BLOB NOT NULL, delivered INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(project_id,filename)
);
CREATE TABLE IF NOT EXISTS team_sync_publications (
 project_id TEXT PRIMARY KEY, members_json TEXT NOT NULL, keys_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY CHECK (version >= 1 AND version <= 4294967295),
  applied_at INTEGER NOT NULL
);
";
