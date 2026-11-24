//! Runtime-session and automation-client records, plus `Store` operations.

use std::str::FromStr;

use locket_core::Duration as LocketDuration;
use rusqlite::types::Type;
use rusqlite::{OptionalExtension, params};
use serde_json::json;
use thiserror::Error;

use crate::Store;
use crate::audit::{AuditWrite, append_audit};
use crate::error::StoreError;

/// Metadata-only runtime process/session row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSessionRecord {
    /// Runtime session identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Parent profile identifier.
    pub profile_id: String,
    /// Optional policy name used to authorize the session.
    pub policy_name: Option<String>,
    /// Runtime process id.
    pub process_id: u32,
    /// Process start timestamp in nanoseconds since the Unix epoch.
    pub process_start_time: i64,
    /// Session start timestamp in nanoseconds since the Unix epoch.
    pub started_at: i64,
    /// Session end timestamp in nanoseconds since the Unix epoch.
    pub ended_at: Option<i64>,
    /// Process exit status when known.
    pub exit_status: Option<i32>,
    /// Sensitive metadata names only; never secret values.
    pub secret_names: Vec<String>,
    /// Optional project-scoped audit sequence for the spawn event.
    pub spawn_audit_sequence: Option<u64>,
    /// Optional project-scoped audit sequence for the completion event.
    pub completion_audit_sequence: Option<u64>,
}

/// Public metadata for a registered automation client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationClientRecord {
    /// Automation-client identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Human-readable client name.
    pub name: String,
    /// Ed25519 public key bytes.
    pub public_key: Vec<u8>,
    /// Stable public-key fingerprint.
    pub fingerprint: String,
    /// Persisted private-key storage mode metadata.
    pub storage: String,
    /// Allowed agent action strings.
    pub allowed_actions: Vec<String>,
    /// Allowed command-policy names.
    pub allowed_policies: Vec<String>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last successful use timestamp in nanoseconds since the Unix epoch.
    pub last_used_at: Option<i64>,
    /// Revocation timestamp in nanoseconds since the Unix epoch.
    pub revoked_at: Option<i64>,
}

/// Metadata-only reference for Locket-managed automation-client private keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationClientPrivateKeyRefRecord {
    /// Parent automation-client identifier.
    pub client_id: String,
    /// Storage backend, currently `os-keychain` or `wrapped-local-file`.
    pub storage: String,
    /// OS keychain service when `storage = os-keychain`.
    pub keychain_service: Option<String>,
    /// OS keychain account when `storage = os-keychain`.
    pub keychain_account: Option<String>,
    /// Hash of the local wrapped-key path when `storage = wrapped-local-file`.
    pub local_path_hash: Option<String>,
    /// Metadata-only JSON object.
    pub metadata_json: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
}

/// Recently seen automation-client challenge nonce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationClientNonceRecord {
    /// Parent automation-client identifier.
    pub client_id: String,
    /// Agent-issued challenge nonce.
    pub nonce: [u8; 24],
    /// Request timestamp in nanoseconds since the Unix epoch.
    pub request_timestamp: i64,
    /// Timestamp when the nonce was observed.
    pub seen_at: i64,
    /// Timestamp after which the nonce can be pruned.
    pub expires_at: i64,
}

/// Retention behavior for `runtime_sessions.secret_names`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeSessionSecretNameRetention {
    /// Store secret names on new runtime-session rows and prune them after this duration.
    RetainFor(LocketDuration),
    /// Do not store secret names on new runtime-session rows.
    Off,
}

impl RuntimeSessionSecretNameRetention {
    /// Default `runtime.session_secret_name_retention` value in seconds.
    pub const DEFAULT_SECONDS: u64 = 90 * 24 * 60 * 60;

    /// Returns the default 90-day retention behavior.
    #[must_use]
    pub const fn default_retention() -> Self {
        Self::RetainFor(LocketDuration::from_secs(Self::DEFAULT_SECONDS))
    }

    /// Filters the candidate names according to this retention mode.
    #[must_use]
    pub fn secret_names_for_storage(&self, secret_names: &[String]) -> Vec<String> {
        match self {
            Self::RetainFor(_) => secret_names.to_vec(),
            Self::Off => Vec::new(),
        }
    }
}

impl Default for RuntimeSessionSecretNameRetention {
    fn default() -> Self {
        Self::default_retention()
    }
}

impl FromStr for RuntimeSessionSecretNameRetention {
    type Err = InvalidRuntimeSessionSecretNameRetention;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "off" {
            return Ok(Self::Off);
        }

        Ok(Self::RetainFor(
            LocketDuration::from_str(value)
                .map_err(|_| InvalidRuntimeSessionSecretNameRetention)?,
        ))
    }
}

/// Invalid `runtime.session_secret_name_retention` value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("runtime.session_secret_name_retention must be a duration or off")]
pub struct InvalidRuntimeSessionSecretNameRetention;

fn runtime_session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RuntimeSessionRecord> {
    let secret_names_json = row.get::<_, String>(9)?;
    let secret_names =
        serde_json::from_str::<Vec<String>>(&secret_names_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(9, Type::Text, Box::new(error))
        })?;
    Ok(RuntimeSessionRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        policy_name: row.get(3)?,
        process_id: row.get(4)?,
        process_start_time: row.get(5)?,
        started_at: row.get(6)?,
        ended_at: row.get(7)?,
        exit_status: row.get(8)?,
        secret_names,
        spawn_audit_sequence: row.get::<_, Option<i64>>(10)?.map(i64::cast_unsigned),
        completion_audit_sequence: row.get::<_, Option<i64>>(11)?.map(i64::cast_unsigned),
    })
}

fn automation_client_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AutomationClientRecord> {
    let allowed_actions_json = row.get::<_, String>(6)?;
    let allowed_actions =
        serde_json::from_str::<Vec<String>>(&allowed_actions_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(6, Type::Text, Box::new(error))
        })?;
    let allowed_policies_json = row.get::<_, String>(7)?;
    let allowed_policies =
        serde_json::from_str::<Vec<String>>(&allowed_policies_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(7, Type::Text, Box::new(error))
        })?;
    Ok(AutomationClientRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        name: row.get(2)?,
        public_key: row.get(3)?,
        fingerprint: row.get(4)?,
        storage: row.get(5)?,
        allowed_actions,
        allowed_policies,
        created_at: row.get(8)?,
        last_used_at: row.get(9)?,
        revoked_at: row.get(10)?,
    })
}

fn automation_client_private_key_ref_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<AutomationClientPrivateKeyRefRecord> {
    Ok(AutomationClientPrivateKeyRefRecord {
        client_id: row.get(0)?,
        storage: row.get(1)?,
        keychain_service: row.get(2)?,
        keychain_account: row.get(3)?,
        local_path_hash: row.get(4)?,
        metadata_json: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

impl Store {
    /// Inserts a runtime-session row at process spawn time.
    ///
    /// `secret_names` are stored as names only for troubleshooting correlation. Callers
    /// should pass names filtered through [`RuntimeSessionSecretNameRetention`] when the
    /// configured retention mode is `off`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert.
    pub fn insert_runtime_session(&self, session: &RuntimeSessionRecord) -> Result<(), StoreError> {
        let secret_names_json = json!(&session.secret_names).to_string();
        self.connection.execute(
            "INSERT INTO runtime_sessions(
               id, project_id, profile_id, policy_name, process_id, process_start_time,
               started_at, ended_at, exit_status, secret_names_json,
               spawn_audit_sequence, completion_audit_sequence
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                session.id.as_str(),
                session.project_id.as_str(),
                session.profile_id.as_str(),
                session.policy_name.as_deref(),
                session.process_id,
                session.process_start_time,
                session.started_at,
                session.ended_at,
                session.exit_status,
                secret_names_json,
                session.spawn_audit_sequence.map(u64::cast_signed),
                session.completion_audit_sequence.map(u64::cast_signed),
            ],
        )?;
        Ok(())
    }

    /// Marks a runtime session completed when the process exits.
    ///
    /// Returns `true` when an incomplete session was updated and `false` when the row
    /// was missing or already completed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn mark_runtime_session_completed(
        &self,
        id: &str,
        ended_at: i64,
        exit_status: Option<i32>,
        completion_audit_sequence: Option<u64>,
    ) -> Result<bool, StoreError> {
        let updated = self.connection.execute(
            "UPDATE runtime_sessions
             SET ended_at = ?2,
                 exit_status = ?3,
                 completion_audit_sequence = ?4
             WHERE id = ?1 AND ended_at IS NULL",
            params![id, ended_at, exit_status, completion_audit_sequence.map(u64::cast_signed)],
        )?;
        Ok(updated > 0)
    }

    /// Lists runtime sessions that do not have completion metadata.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the rows.
    pub fn list_incomplete_runtime_sessions(
        &self,
        project_id: &str,
    ) -> Result<Vec<RuntimeSessionRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, profile_id, policy_name, process_id, process_start_time,
                    started_at, ended_at, exit_status, secret_names_json,
                    spawn_audit_sequence, completion_audit_sequence
             FROM runtime_sessions
             WHERE project_id = ?1 AND ended_at IS NULL
             ORDER BY started_at, id",
        )?;
        statement
            .query_map([project_id], runtime_session_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Lists runtime sessions whose retained `secret_names` have passed the cutoff.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the rows.
    pub fn list_runtime_sessions_with_expired_secret_names(
        &self,
        project_id: &str,
        started_before_or_at: i64,
    ) -> Result<Vec<RuntimeSessionRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, profile_id, policy_name, process_id, process_start_time,
                    started_at, ended_at, exit_status, secret_names_json,
                    spawn_audit_sequence, completion_audit_sequence
             FROM runtime_sessions
             WHERE project_id = ?1
               AND started_at <= ?2
               AND secret_names_json != '[]'
             ORDER BY started_at, id",
        )?;
        statement
            .query_map(params![project_id, started_before_or_at], runtime_session_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Prunes only the sensitive `secret_names` metadata for sessions at or before a cutoff.
    ///
    /// Session timing, process identity, policy name, exit status, and audit sequence
    /// linkage are preserved.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn prune_runtime_session_secret_names(
        &self,
        project_id: &str,
        started_before_or_at: i64,
    ) -> Result<usize, StoreError> {
        self.connection
            .execute(
                "UPDATE runtime_sessions
                 SET secret_names_json = '[]'
                 WHERE project_id = ?1
                   AND started_at <= ?2
                   AND secret_names_json != '[]'",
                params![project_id, started_before_or_at],
            )
            .map_err(StoreError::from)
    }

    /// Registers or refreshes public automation-client metadata.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the row.
    pub fn insert_automation_client(
        &self,
        client: &AutomationClientRecord,
    ) -> Result<(), StoreError> {
        let allowed_actions_json = json!(&client.allowed_actions).to_string();
        let allowed_policies_json = json!(&client.allowed_policies).to_string();
        self.connection.execute(
            "INSERT INTO automation_clients(
               id, project_id, name, public_key, fingerprint, storage,
               allowed_actions_json, allowed_policies_json, created_at, last_used_at, revoked_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                client.id.as_str(),
                client.project_id.as_str(),
                client.name.as_str(),
                client.public_key.as_slice(),
                client.fingerprint.as_str(),
                client.storage.as_str(),
                allowed_actions_json,
                allowed_policies_json,
                client.created_at,
                client.last_used_at,
                client.revoked_at,
            ],
        )?;
        Ok(())
    }

    /// Registers public automation-client metadata and its private-key reference atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects either row.
    pub fn insert_automation_client_with_private_key_ref(
        &mut self,
        client: &AutomationClientRecord,
        private_key_ref: Option<&AutomationClientPrivateKeyRefRecord>,
    ) -> Result<(), StoreError> {
        let allowed_actions_json = json!(&client.allowed_actions).to_string();
        let allowed_policies_json = json!(&client.allowed_policies).to_string();
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO automation_clients(
               id, project_id, name, public_key, fingerprint, storage,
               allowed_actions_json, allowed_policies_json, created_at, last_used_at, revoked_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                client.id.as_str(),
                client.project_id.as_str(),
                client.name.as_str(),
                client.public_key.as_slice(),
                client.fingerprint.as_str(),
                client.storage.as_str(),
                allowed_actions_json,
                allowed_policies_json,
                client.created_at,
                client.last_used_at,
                client.revoked_at,
            ],
        )?;
        if let Some(reference) = private_key_ref {
            transaction.execute(
                "INSERT INTO automation_client_private_key_refs(
                   client_id, storage, keychain_service, keychain_account, local_path_hash,
                   metadata_json, created_at, updated_at
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    reference.client_id.as_str(),
                    reference.storage.as_str(),
                    reference.keychain_service.as_deref(),
                    reference.keychain_account.as_deref(),
                    reference.local_path_hash.as_deref(),
                    reference.metadata_json.as_str(),
                    reference.created_at,
                    reference.updated_at,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Lists automation-client metadata for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when rows cannot be queried or parsed.
    pub fn list_automation_clients(
        &self,
        project_id: &str,
        include_revoked: bool,
    ) -> Result<Vec<AutomationClientRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, name, public_key, fingerprint, storage,
                    allowed_actions_json, allowed_policies_json, created_at, last_used_at, revoked_at
             FROM automation_clients
             WHERE project_id = ?1 AND (?2 OR revoked_at IS NULL)
             ORDER BY name, created_at, id",
        )?;
        statement
            .query_map(params![project_id, include_revoked], automation_client_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Returns one automation client by id or project-scoped name.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when the row cannot be queried or parsed.
    pub fn get_automation_client(
        &self,
        project_id: &str,
        client: &str,
    ) -> Result<Option<AutomationClientRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, name, public_key, fingerprint, storage,
                        allowed_actions_json, allowed_policies_json, created_at, last_used_at, revoked_at
                 FROM automation_clients
                 WHERE project_id = ?1 AND (id = ?2 OR name = ?2)
                 ORDER BY CASE WHEN id = ?2 THEN 0 ELSE 1 END, created_at
                 LIMIT 1",
                params![project_id, client],
                automation_client_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Revokes an automation client by id.
    ///
    /// Returns `true` when an active client was revoked.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn revoke_automation_client(
        &self,
        project_id: &str,
        client_id: &str,
        revoked_at: i64,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "UPDATE automation_clients
             SET revoked_at = ?3
             WHERE project_id = ?1 AND id = ?2 AND revoked_at IS NULL",
            params![project_id, client_id, revoked_at],
        )?;
        Ok(self.connection.changes() == 1)
    }

    /// Inserts or replaces the metadata-only private-key storage reference.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the row.
    pub fn upsert_automation_client_private_key_ref(
        &self,
        reference: &AutomationClientPrivateKeyRefRecord,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO automation_client_private_key_refs(
               client_id, storage, keychain_service, keychain_account, local_path_hash,
               metadata_json, created_at, updated_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(client_id) DO UPDATE SET
               storage = excluded.storage,
               keychain_service = excluded.keychain_service,
               keychain_account = excluded.keychain_account,
               local_path_hash = excluded.local_path_hash,
               metadata_json = excluded.metadata_json,
               updated_at = excluded.updated_at",
            params![
                reference.client_id.as_str(),
                reference.storage.as_str(),
                reference.keychain_service.as_deref(),
                reference.keychain_account.as_deref(),
                reference.local_path_hash.as_deref(),
                reference.metadata_json.as_str(),
                reference.created_at,
                reference.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Returns a metadata-only private-key storage reference.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when the row cannot be queried.
    pub fn get_automation_client_private_key_ref(
        &self,
        client_id: &str,
    ) -> Result<Option<AutomationClientPrivateKeyRefRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT client_id, storage, keychain_service, keychain_account, local_path_hash,
                        metadata_json, created_at, updated_at
                 FROM automation_client_private_key_refs
                 WHERE client_id = ?1",
                [client_id],
                automation_client_private_key_ref_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Deletes a metadata-only private-key storage reference.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the delete.
    pub fn delete_automation_client_private_key_ref(
        &self,
        client_id: &str,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "DELETE FROM automation_client_private_key_refs WHERE client_id = ?1",
            [client_id],
        )?;
        Ok(self.connection.changes() == 1)
    }

    /// Records an automation-client challenge nonce.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the nonce.
    pub fn insert_automation_client_nonce(
        &self,
        nonce: &AutomationClientNonceRecord,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO automation_client_nonces(
               client_id, nonce, request_timestamp, seen_at, expires_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                nonce.client_id.as_str(),
                nonce.nonce.as_slice(),
                nonce.request_timestamp,
                nonce.seen_at,
                nonce.expires_at,
            ],
        )?;
        Ok(())
    }

    /// Prunes expired automation-client nonces, then records one accepted auth nonce.
    ///
    /// This is the write path intended for challenge-response authentication:
    /// it keeps replay rows bounded while preserving the `(client_id, nonce)`
    /// uniqueness check that detects accepted nonce reuse across agent restarts.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the prune or insert.
    pub fn record_automation_client_auth_nonce(
        &mut self,
        nonce: &AutomationClientNonceRecord,
        now: i64,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        transaction
            .execute("DELETE FROM automation_client_nonces WHERE expires_at <= ?1", [now])?;
        transaction.execute(
            "INSERT INTO automation_client_nonces(
               client_id, nonce, request_timestamp, seen_at, expires_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                nonce.client_id.as_str(),
                nonce.nonce.as_slice(),
                nonce.request_timestamp,
                nonce.seen_at,
                nonce.expires_at,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Records an accepted automation-client nonce, updates client usage, and appends audit.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the nonce, usage update, or audit row cannot be written.
    pub fn record_automation_client_auth_with_audit(
        &mut self,
        nonce: &AutomationClientNonceRecord,
        now: i64,
        audit_key: &[u8],
        audit: &AuditWrite<'_>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        transaction
            .execute("DELETE FROM automation_client_nonces WHERE expires_at <= ?1", [now])?;
        transaction.execute(
            "INSERT INTO automation_client_nonces(
               client_id, nonce, request_timestamp, seen_at, expires_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                nonce.client_id.as_str(),
                nonce.nonce.as_slice(),
                nonce.request_timestamp,
                nonce.seen_at,
                nonce.expires_at,
            ],
        )?;
        let updated = transaction.execute(
            "UPDATE automation_clients
             SET last_used_at = ?2
             WHERE id = ?1 AND revoked_at IS NULL",
            params![nonce.client_id.as_str(), now],
        )?;
        if updated == 0 {
            return Err(StoreError::AutomationClientRevoked { client_id: nonce.client_id.clone() });
        }
        append_audit(&transaction, audit_key, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Prunes expired automation-client nonces.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the delete.
    pub fn prune_automation_client_nonces(&self, now: i64) -> Result<usize, StoreError> {
        self.connection
            .execute("DELETE FROM automation_client_nonces WHERE expires_at <= ?1", [now])
            .map_err(StoreError::from)
    }
}
