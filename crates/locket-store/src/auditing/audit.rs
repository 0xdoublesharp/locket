//! Audit-log row types, append/verify helpers, and `Store` audit methods.

use hmac::{Hmac, KeyInit, Mac};
use locket_core::{
    AUDIT_HMAC_LEN, AuditCheckpoint, AuditHmacInput, ProjectId, Timestamp,
    audit_checkpoint_v1_bytes, audit_hmac_v1_bytes, canonical_json_string,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::Store;
use crate::error::StoreError;
use crate::schema::{AUDIT_ACTION_SCHEMA_MIGRATE, SchemaMigrationOutcome};

/// Maximum serialized `metadata_json` byte length per audit row.
///
/// `docs/specs/audit.md` and `docs/specs/data-model.md` cap each
/// row's metadata at 64 KiB. The append path enforces this before
/// writing so the chain never contains an unbounded row.
pub const AUDIT_METADATA_JSON_LIMIT: usize = 64 * 1024;

/// HMAC-covered audit row to append.
#[derive(Debug)]
pub struct AuditWrite<'a> {
    /// Parent project identifier.
    pub project_id: &'a str,
    /// Optional profile identifier.
    pub profile_id: Option<&'a str>,
    /// Audit action string.
    pub action: &'a str,
    /// Audit status string.
    pub status: &'a str,
    /// Optional query convenience secret name.
    pub secret_name: Option<&'a str>,
    /// Optional query convenience command string.
    pub command: Option<&'a str>,
    /// HMAC-covered metadata object.
    pub metadata_json: &'a Value,
    /// Event timestamp in nanoseconds since the Unix epoch.
    pub timestamp: i64,
}

/// Metadata-only audit row returned for reporting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLogRecord {
    /// Project-scoped audit sequence.
    pub sequence: u64,
    /// Event timestamp in nanoseconds since the Unix epoch.
    pub timestamp: i64,
    /// Optional profile identifier.
    pub profile_id: Option<String>,
    /// Audit action string.
    pub action: String,
    /// Audit status string.
    pub status: String,
    /// Optional secret name from HMAC-covered metadata.
    pub secret_name: Option<String>,
    /// Optional command string from HMAC-covered metadata.
    pub command: Option<String>,
}

/// Filters for metadata-only audit log reads.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditListFilter {
    /// Optional project profile filter.
    pub profile_id: Option<String>,
    /// Optional audit action filter.
    pub action: Option<String>,
    /// Optional audit status filter.
    pub status: Option<String>,
    /// Optional inclusive lower timestamp bound.
    pub since_unix_nanos: Option<i64>,
    /// Optional inclusive upper timestamp bound.
    pub until_unix_nanos: Option<i64>,
    /// Maximum number of rows to return from the end of the matching range.
    pub limit: u32,
}

/// Stored row material for structural verification of an imported audit chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportedAuditChainRow {
    /// Sequence number from the source project's audit chain.
    pub sequence: u64,
    /// Stored previous-row HMAC from the imported row.
    pub previous_hmac: [u8; AUDIT_HMAC_LEN],
    /// Stored row HMAC from the imported row.
    pub hmac: [u8; AUDIT_HMAC_LEN],
}

/// Full audit-log row for sealed-bundle export with `--include-audit`.
///
/// Carries every field needed by the receiver to structurally verify
/// the imported chain and write it into `imported_audit_chains` with no
/// further DB-side translation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportableAuditRow {
    /// Project-scoped audit sequence.
    pub sequence: u64,
    /// HMAC-covered metadata schema version stored alongside the row.
    pub schema_version: u16,
    /// Event timestamp in nanoseconds since the Unix epoch.
    pub timestamp: i64,
    /// Optional profile identifier covered by the HMAC.
    pub profile_id: Option<String>,
    /// HMAC-covered action label.
    pub action: String,
    /// HMAC-covered status label.
    pub status: String,
    /// HMAC-covered metadata object as canonical JSON text.
    pub metadata_json: String,
    /// Optional query-convenience secret name.
    pub secret_name: Option<String>,
    /// Optional query-convenience command string.
    pub command: Option<String>,
    /// Previous row HMAC (32 bytes, all zeroes for sequence 1).
    pub previous_hmac: [u8; AUDIT_HMAC_LEN],
    /// Stored row HMAC (32 bytes).
    pub hmac: [u8; AUDIT_HMAC_LEN],
}

/// Summary returned after imported audit-chain structural verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportedAuditChainVerification {
    /// Number of imported rows verified.
    pub rows_verified: u64,
    /// Checkpoint sequence the imported chain was verified against.
    pub checkpoint_sequence: u64,
}

/// Read-only audit HMAC chain verification result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditChainVerification {
    /// Whether the full chain verified.
    pub hmac_ok: bool,
    /// First broken sequence when verification failed.
    pub first_break_sequence: Option<u64>,
    /// Metadata-only failure reason when verification failed.
    pub first_break_reason: Option<String>,
    /// Rows verified before the first break, or all rows on success.
    pub rows_verified: u64,
}

/// Audit key plus row payload for transaction-scoped appends.
#[derive(Clone, Copy, Debug)]
pub struct AuditContext<'a> {
    /// Unwrapped project audit key.
    pub key: &'a [u8],
    /// Audit row payload.
    pub write: &'a AuditWrite<'a>,
}

#[derive(Debug)]
struct StoredAuditRow {
    sequence: u64,
    schema_version: u16,
    timestamp: i64,
    project_id: String,
    profile_id: Option<String>,
    action: String,
    status: String,
    metadata_json: String,
    secret_name: Option<String>,
    command: Option<String>,
    previous_hmac: [u8; AUDIT_HMAC_LEN],
    hmac: [u8; AUDIT_HMAC_LEN],
}

pub fn audit_log_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditLogRecord> {
    Ok(AuditLogRecord {
        sequence: row.get::<_, i64>(0)?.cast_unsigned(),
        timestamp: row.get(1)?,
        profile_id: row.get(2)?,
        action: row.get(3)?,
        status: row.get(4)?,
        secret_name: row.get(5)?,
        command: row.get(6)?,
    })
}

pub fn append_optional_audit(
    transaction: &Connection,
    audit: Option<AuditContext<'_>>,
) -> Result<(), StoreError> {
    if let Some(audit) = audit {
        append_audit(transaction, audit.key, audit.write)?;
    }
    Ok(())
}

fn read_audit_rows(
    transaction: &Connection,
    project_id: &str,
) -> Result<Vec<StoredAuditRow>, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT sequence, schema_version, timestamp, project_id, profile_id,
                action, status, metadata_json, previous_hmac, hmac, secret_name, command
         FROM audit_log
         WHERE project_id = ?1
         ORDER BY sequence",
    )?;
    let rows = statement
        .query_map([project_id], |row| {
            let previous_hmac = row.get::<_, Vec<u8>>(8)?;
            let hmac = row.get::<_, Vec<u8>>(9)?;
            Ok((
                row.get::<_, i64>(0)?.cast_unsigned(),
                row.get::<_, u16>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                previous_hmac,
                hmac,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
            ))
        })?
        .map(|row| {
            let (
                sequence,
                schema_version,
                timestamp,
                project_id,
                profile_id,
                action,
                status,
                metadata_json,
                previous_hmac,
                hmac,
                secret_name,
                command,
            ) = row?;
            Ok(StoredAuditRow {
                sequence,
                schema_version,
                timestamp,
                project_id,
                profile_id,
                action,
                status,
                metadata_json,
                secret_name,
                command,
                previous_hmac: hmac_vec_to_array(sequence, previous_hmac)?,
                hmac: hmac_vec_to_array(sequence, hmac)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;

    Ok(rows)
}

fn hmac_vec_to_array(sequence: u64, value: Vec<u8>) -> Result<[u8; AUDIT_HMAC_LEN], StoreError> {
    value.try_into().map_err(|bytes: Vec<u8>| StoreError::AuditIntegrity {
        sequence,
        reason: format!("invalid hmac length {}", bytes.len()),
    })
}

fn checkpoint_mac(
    checkpoint: &AuditCheckpoint,
    audit_key: &[u8; AUDIT_HMAC_LEN],
) -> Result<Hmac<Sha256>, StoreError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(audit_key)
        .map_err(|_| StoreError::InvalidAuditKeyLength { actual: audit_key.len() })?;
    mac.update(&audit_checkpoint_v1_bytes(checkpoint)?);
    Ok(mac)
}

fn verify_checkpoint(
    project_id: &str,
    audit_key: &[u8; AUDIT_HMAC_LEN],
    checkpoint: &AuditCheckpoint,
    rows: &[StoredAuditRow],
) -> Result<(), StoreError> {
    let invalid = |reason: &str| StoreError::AuditIntegrity {
        sequence: checkpoint.sequence,
        reason: reason.to_owned(),
    };
    if checkpoint.schema_version != 1
        || checkpoint.sequence == 0
        || i64::try_from(checkpoint.sequence).is_err()
    {
        return Err(invalid("invalid audit checkpoint schema or sequence"));
    }
    if checkpoint.project_id.as_str() != project_id {
        return Err(invalid("audit checkpoint belongs to a different project"));
    }
    checkpoint_mac(checkpoint, audit_key)?
        .verify_slice(&checkpoint.authentication_tag)
        .map_err(|_| invalid("audit checkpoint authentication failed"))?;
    let Some(anchored) = rows.iter().find(|row| row.sequence == checkpoint.sequence) else {
        return Err(invalid("audit history is older than the retained checkpoint"));
    };
    if anchored.hmac != checkpoint.row_hmac {
        return Err(invalid("audit history does not match the retained checkpoint"));
    }
    Ok(())
}

fn require_verified_chain(verification: &AuditChainVerification) -> Result<(), StoreError> {
    if verification.hmac_ok {
        Ok(())
    } else {
        Err(StoreError::AuditIntegrity {
            sequence: verification.first_break_sequence.unwrap_or(1),
            reason: verification
                .first_break_reason
                .clone()
                .unwrap_or_else(|| "audit verification failed".to_owned()),
        })
    }
}

/// Verifies imported remote audit rows against their plaintext bundle checkpoint.
///
/// The source project's audit key is never exported in sealed bundles, so this
/// check verifies only structural continuity and the final checkpoint match.
///
/// # Errors
///
/// Returns [`StoreError::AuditIntegrity`] when the imported rows are reordered,
/// have gaps, break previous-HMAC linkage, or do not match the checkpoint.
pub fn verify_imported_audit_chain_structure(
    rows: &[ImportedAuditChainRow],
    checkpoint_sequence: u64,
    checkpoint_hmac: &[u8; AUDIT_HMAC_LEN],
) -> Result<ImportedAuditChainVerification, StoreError> {
    let mut previous_hmac = [0; AUDIT_HMAC_LEN];

    for (expected_sequence, row) in (1_u64..).zip(rows) {
        if row.sequence != expected_sequence {
            return Err(StoreError::AuditIntegrity {
                sequence: expected_sequence,
                reason: "sequence gap or reordering".to_owned(),
            });
        }
        if row.previous_hmac != previous_hmac {
            return Err(StoreError::AuditIntegrity {
                sequence: row.sequence,
                reason: "previous_hmac mismatch".to_owned(),
            });
        }

        previous_hmac = row.hmac;
    }

    let Some(final_row) = rows.last() else {
        return Err(StoreError::AuditIntegrity {
            sequence: 1,
            reason: "imported audit chain is empty".to_owned(),
        });
    };
    if final_row.sequence != checkpoint_sequence {
        return Err(StoreError::AuditIntegrity {
            sequence: final_row.sequence,
            reason: "checkpoint_sequence mismatch".to_owned(),
        });
    }
    if final_row.hmac != *checkpoint_hmac {
        return Err(StoreError::AuditIntegrity {
            sequence: final_row.sequence,
            reason: "checkpoint_hmac mismatch".to_owned(),
        });
    }

    Ok(ImportedAuditChainVerification { rows_verified: rows.len() as u64, checkpoint_sequence })
}

fn verify_audit_rows(
    rows: &[StoredAuditRow],
    audit_key: &[u8],
) -> Result<AuditChainVerification, StoreError> {
    let mut previous_hmac = [0; AUDIT_HMAC_LEN];
    let mut rows_verified = 0_u64;

    for (expected_sequence, row) in (1_u64..).zip(rows) {
        if row.sequence != expected_sequence {
            return Ok(AuditChainVerification {
                hmac_ok: false,
                first_break_sequence: Some(expected_sequence),
                first_break_reason: Some("sequence gap or reordering".to_owned()),
                rows_verified,
            });
        }
        if row.previous_hmac != previous_hmac {
            return Ok(AuditChainVerification {
                hmac_ok: false,
                first_break_sequence: Some(row.sequence),
                first_break_reason: Some("previous_hmac mismatch".to_owned()),
                rows_verified,
            });
        }
        let metadata = match serde_json::from_str::<Value>(&row.metadata_json) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Ok(AuditChainVerification {
                    hmac_ok: false,
                    first_break_sequence: Some(row.sequence),
                    first_break_reason: Some(format!("metadata_json is not valid JSON: {error}")),
                    rows_verified,
                });
            }
        };
        let input = AuditHmacInput {
            schema_version: row.schema_version,
            sequence: row.sequence,
            timestamp: Timestamp::from_unix_nanos(row.timestamp),
            project_id: Some(&row.project_id),
            profile_id: row.profile_id.as_deref(),
            action: &row.action,
            status: &row.status,
            metadata_json: Some(&metadata),
            previous_hmac: Some(&row.previous_hmac),
        };
        let canonical = audit_hmac_v1_bytes(&input)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(audit_key)
            .map_err(|_| StoreError::InvalidAuditKeyLength { actual: audit_key.len() })?;
        mac.update(&canonical);
        if mac.verify_slice(&row.hmac).is_err() {
            return Ok(AuditChainVerification {
                hmac_ok: false,
                first_break_sequence: Some(row.sequence),
                first_break_reason: Some("row hmac mismatch".to_owned()),
                rows_verified,
            });
        }

        for (field, displayed) in
            [("secret_name", row.secret_name.as_deref()), ("command", row.command.as_deref())]
        {
            let matches = match (displayed, metadata.get(field)) {
                (None, None) => true,
                (Some(displayed), Some(Value::String(authenticated))) => displayed == authenticated,
                _ => false,
            };
            if !matches {
                return Ok(AuditChainVerification {
                    hmac_ok: false,
                    first_break_sequence: Some(row.sequence),
                    first_break_reason: Some(format!(
                        "{field} convenience column does not match metadata_json"
                    )),
                    rows_verified,
                });
            }
        }

        previous_hmac = row.hmac;
        rows_verified += 1;
    }

    Ok(AuditChainVerification {
        hmac_ok: true,
        first_break_sequence: None,
        first_break_reason: None,
        rows_verified,
    })
}

pub fn append_audit(
    transaction: &Connection,
    audit_key: &[u8],
    audit: &AuditWrite<'_>,
) -> Result<(), StoreError> {
    validate_audit_metadata(audit)?;
    let metadata_json = canonical_json_string(Some(audit.metadata_json));
    if metadata_json.len() > AUDIT_METADATA_JSON_LIMIT {
        return Err(StoreError::AuditMetadataTooLarge {
            action: audit.action.to_owned(),
            actual: metadata_json.len(),
            limit: AUDIT_METADATA_JSON_LIMIT,
        });
    }
    let previous = transaction
        .query_row(
            "SELECT sequence, hmac
             FROM audit_log
             WHERE project_id = ?1
             ORDER BY sequence DESC
             LIMIT 1",
            [audit.project_id],
            |row| Ok((row.get::<_, i64>(0)?.cast_unsigned(), row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let (sequence, previous_hmac) = match previous {
        Some((sequence, hmac)) => {
            let previous_hmac = hmac.try_into().map_err(|bytes: Vec<u8>| {
                StoreError::InvalidAuditHmacLength { actual: bytes.len() }
            })?;
            (sequence + 1, previous_hmac)
        }
        None => (1, [0; AUDIT_HMAC_LEN]),
    };

    let input = AuditHmacInput {
        schema_version: 1,
        sequence,
        timestamp: Timestamp::from_unix_nanos(audit.timestamp),
        project_id: Some(audit.project_id),
        profile_id: audit.profile_id,
        action: audit.action,
        status: audit.status,
        metadata_json: Some(audit.metadata_json),
        previous_hmac: Some(&previous_hmac),
    };
    let canonical = audit_hmac_v1_bytes(&input)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(audit_key)
        .map_err(|_| StoreError::InvalidAuditKeyLength { actual: audit_key.len() })?;
    mac.update(&canonical);
    let hmac = mac.finalize().into_bytes();

    transaction.execute(
        "INSERT INTO audit_log(
           project_id, sequence, schema_version, timestamp, profile_id, action,
           status, metadata_json, secret_name, command, previous_hmac, hmac
         )
         VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            audit.project_id,
            sequence.cast_signed(),
            audit.timestamp,
            audit.profile_id,
            audit.action,
            audit.status,
            metadata_json,
            audit.secret_name,
            audit.command,
            previous_hmac.as_slice(),
            hmac.as_slice(),
        ],
    )?;

    Ok(())
}

fn validate_audit_metadata(audit: &AuditWrite<'_>) -> Result<(), StoreError> {
    let Some(metadata) = audit.metadata_json.as_object() else {
        return audit_metadata_invalid(audit.action, "metadata_json must be an object");
    };
    validate_metadata_string(audit.action, metadata, "action", audit.action)?;
    validate_metadata_string(audit.action, metadata, "status", audit.status)?;
    let schema_version = validate_schema_version(audit.action, metadata)?;
    validate_convenience_field(audit.action, metadata, "secret_name", audit.secret_name)?;
    validate_convenience_field(audit.action, metadata, "command", audit.command)?;
    validate_required_fields(audit.action, metadata)?;
    if schema_version == 1 {
        validate_known_fields(audit.action, metadata)?;
    }
    Ok(())
}

fn validate_schema_version(action: &str, metadata: &Map<String, Value>) -> Result<u64, StoreError> {
    let Some(schema_version) = metadata.get("schema_version").and_then(Value::as_u64) else {
        return audit_metadata_invalid(action, "schema_version must be an integer");
    };
    if schema_version == 0 {
        return audit_metadata_invalid(action, "schema_version must be at least 1");
    }
    Ok(schema_version)
}

fn validate_metadata_string(
    action: &str,
    metadata: &Map<String, Value>,
    field: &'static str,
    expected: &str,
) -> Result<(), StoreError> {
    match metadata.get(field).and_then(Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => audit_metadata_invalid(action, format!("{field} must match audit row")),
        None => audit_metadata_invalid(action, format!("{field} must be a string")),
    }
}

fn validate_convenience_field(
    action: &str,
    metadata: &Map<String, Value>,
    field: &'static str,
    expected: Option<&str>,
) -> Result<(), StoreError> {
    match (expected, metadata.get(field)) {
        (Some(expected), Some(Value::String(actual))) if actual == expected => Ok(()),
        (Some(_), Some(Value::String(_))) => {
            audit_metadata_invalid(action, format!("{field} must match audit row"))
        }
        (Some(_), Some(Value::Null)) => {
            audit_metadata_invalid(action, format!("{field} must not be null"))
        }
        (Some(_), Some(_)) => audit_metadata_invalid(action, format!("{field} must be a string")),
        (Some(_), None) => audit_metadata_invalid(
            action,
            format!("{field} convenience column must be mirrored in metadata_json"),
        ),
        (None, Some(Value::Null)) => {
            audit_metadata_invalid(action, format!("{field} must be omitted, not null"))
        }
        (None, Some(_)) => {
            audit_metadata_invalid(action, format!("{field} must be omitted when absent"))
        }
        (None, None) => Ok(()),
    }
}

fn validate_required_fields(action: &str, metadata: &Map<String, Value>) -> Result<(), StoreError> {
    for field in required_fields_for_action(action) {
        if !metadata.contains_key(*field) {
            return audit_metadata_invalid(action, format!("missing required field {field}"));
        }
    }
    Ok(())
}

fn validate_known_fields(action: &str, metadata: &Map<String, Value>) -> Result<(), StoreError> {
    for field in metadata.keys() {
        if !KNOWN_AUDIT_METADATA_FIELDS.contains(&field.as_str()) {
            return audit_metadata_invalid(action, format!("unknown field {field}"));
        }
    }
    Ok(())
}

fn audit_metadata_invalid<T>(action: &str, reason: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError::AuditMetadataInvalid { action: action.to_owned(), reason: reason.into() })
}

fn required_fields_for_action(action: &str) -> &'static [&'static str] {
    match action {
        "SET" | "ROTATE" | "PURGE" | "SECRET_META_UPDATE" | "DELETE" | "IMPORT" => {
            &["secret_name", "profile_id", "source"]
        }
        "REVEAL" | "COPY" | "GET" => &["secret_name", "profile_id", "source", "access_mode"],
        "RESOLVE_REFERENCE" => &["secret_name", "profile_id", "source"],
        "SECRET_COPY" => &["secret_name", "from_profile_id", "to_profile_id"],
        "RUN" | "RUN_POLICY" | "EXEC" => &["command"],
        "SCAN" | "REDACT" => &["scope", "known_value_coverage", "finding_counts", "pattern_only"],
        "TRUST_ROOT" => &["root_hash", "trust_operation"],
        "POLICY_UPDATE" => &["policy_name", "change_kind"],
        "CONFIG_UPDATE" => &["config_path_hash", "config_keys"],
        "EXAMPLE_EMIT" => &["example_path_kind", "example_path_hash", "secret_name_count"],
        "BOOTSTRAP" => &["project_id", "default_profile_id", "recovery_code_displayed"],
        "PROFILE_CREATE" => &["project_id", "profile_id", "profile_name"],
        "PROFILE_CHANGE" => &["operation"],
        "ALLOW_DIRECTORY" | "DENY_DIRECTORY" => {
            &["project_id", "profile_id", "root_hash", "directory_hash", "grant_scope"]
        }
        "UNLOCK" | "LOCK" | "AGENT_GRANT" | "AGENT_REVOKE" | "GRANT_EXPIRED" => {
            &["client_kind", "grant_actions", "ttl_seconds"]
        }
        "PASSKEY_REGISTER" | "PASSKEY_REMOVE" | "PASSKEY_AUTH" => {
            &["passkey_id", "credential_id_prefix", "auth_result"]
        }
        "CLIENT_AUTH" => &["client_id", "request_id", "auth_result"],
        "DEVICE_ADD" | "DEVICE_REVOKE" => &["device_id", "fingerprint"],
        "CLIENT_ADD" | "CLIENT_REVOKE" => &["client_id", "public_key_fingerprint"],
        "TEAM_INIT" => &["project_id", "team_id", "team_name"],
        "TEAM_INVITE" | "TEAM_ACCEPT" | "TEAM_REMOVE" => &["team_id", "member_id"],
        "RECOVER" | "RECOVERY_ROTATE" => &["device_id"],
        "BACKUP_EXPORT" | "BACKUP_IMPORT" | "BUNDLE_VERIFY" => &["bundle_digest"],
        "SCHEMA_MIGRATE" => &["check_names", "schema_versions", "migration_count"],
        "DOCTOR" => &["check_names"],
        "AUDIT_VERIFY" => &["check_names", "pass_count", "warn_count", "fail_count", "skip_count"],
        "HOOK_INSTALL" => &["hook_path_kind", "hook_path_hash"],
        _ => &[],
    }
}

const KNOWN_AUDIT_METADATA_FIELDS: &[&str] = &[
    "credential_kind",
    "access_mode",
    "accepted_at",
    "action",
    "active_secret_count",
    "agent_available",
    "all_mode",
    "allowed_actions",
    "allowed_policies",
    "allowed_secret_names",
    "applied",
    "applied_blob_count",
    "applied_command_policy_count",
    "applied_profile_count",
    "archived_local_profile_count",
    "applied_profile_key_count",
    "applied_secret_count",
    "applied_secret_version_count",
    "arg_count",
    "auth_result",
    "argv0",
    "argv_program",
    "backup_eligible",
    "backup_state",
    "blob_count",
    "buffer_limit_flushes",
    "bundle_digest",
    "bundle_schema_version",
    "cached_keys",
    "cached_keys_cleared",
    "check_names",
    "checks",
    "child_exit",
    "child_exit_code",
    "client_id",
    "client_kind",
    "client_name",
    "challenge_id",
    "change_kind",
    "clipboard_clear_supported",
    "clipboard_supported",
    "command",
    "command_count",
    "command_policy_count",
    "command_type",
    "config_path_hash",
    "config_keys",
    "confirmation_source",
    "conflict_counts",
    "counts",
    "created_at",
    "created_by_locket",
    "credential_id_prefix",
    "critical_fail_count",
    "cwd_kind",
    "dangerous",
    "default_profile_id",
    "default_profile",
    "delivery_mode",
    "denial_reason",
    "deprecated_at",
    "deprecated_version",
    "decryptable_by_this_device",
    "decrypted_blob_count",
    "decrypted_command_policy_count",
    "decrypted_profile_count",
    "decrypted_secret_count",
    "decrypted_secret_version_count",
    "description_updated",
    "device_id",
    "device_name",
    "diagnostics",
    "directory_grants_revoked",
    "directory_hash",
    "docker_context_class",
    "env_mode",
    "envelope_checksum_sha256",
    "example_path_hash",
    "example_path_kind",
    "expires_at",
    "exit_code",
    "expected_secret_count",
    "external_env_names",
    "external_env_sources",
    "external_sources",
    "fail_count",
    "failure_reason",
    "finding_counts",
    "fingerprint",
    "force",
    "from_profile",
    "from_profile_id",
    "from_source",
    "from_version",
    "generated_files",
    "grace_until",
    "grant_scope",
    "grant_actions",
    "grant_id",
    "helper",
    "hook_change",
    "hook",
    "hook_command",
    "hook_path_hash",
    "hook_path_kind",
    "imported_audit_chain_count",
    "include_audit",
    "include_audit_requested",
    "input_kind",
    "intact_keychain_override",
    "invalid_utf8_passthrough",
    "invite_id",
    "issuer_device_fingerprint",
    "issuer_device_id",
    "issuer_member_id",
    "key_purposes_initialized",
    "kdf_profile_id",
    "kept_blocking_count",
    "kept_warning_count",
    "key",
    "known_coverage_active",
    "known_secret_names_redacted",
    "known_value_coverage",
    "live_grants_revoked",
    "local",
    "label",
    "log_path_hash",
    "metadata_only",
    "marker_only",
    "member_id",
    "member_role",
    "method",
    "migration_count",
    "new_dangerous",
    "new_profile_dangerous",
    "new_profile_id",
    "new_profile_name",
    "nonce_freshness",
    "operation",
    "output_destinations",
    "output_path_kind",
    "override",
    "override_explicit",
    "owner_updated",
    "partial_line_flushes",
    "pass_count",
    "passkey_id",
    "path_hash",
    "path_kind",
    "path_label",
    "pattern_only",
    "policy",
    "policy_count",
    "policy_id",
    "policy_name",
    "prf_capable",
    "pid_path_hash",
    "prior_dangerous",
    "prior_grant",
    "prior_profile_id",
    "prior_profile_name",
    "prior_target_version",
    "prior_version",
    "process_id",
    "process_start_time",
    "profile",
    "profile_count",
    "profile_id",
    "profile_key_count",
    "profile_name",
    "profiles",
    "project_config_schema",
    "project_id",
    "public_key_fingerprint",
    "recipient_device_fingerprint",
    "recipient_device_id",
    "recipient_fingerprints",
    "recipient_count",
    "recovery_code_displayed",
    "redact_names",
    "redact_names_enabled",
    "redacted_secret_names",
    "redaction_counts_by_rule",
    "replaced_unmanaged",
    "request_id",
    "requested_action",
    "requested_policy",
    "require_known",
    "required",
    "required_update",
    "required_secret_names",
    "restored_entry_counts",
    "restored_entry_kinds",
    "revoked_at",
    "revoked_count",
    "revoker_member_id",
    "result_state",
    "role",
    "root_hash",
    "root_kind",
    "rows_verified",
    "schema_version",
    "schema_versions",
    "scope",
    "secret_name",
    "secret_name_count",
    "secret_names",
    "secret_count",
    "secret_sources",
    "secret_version_count",
    "secrets",
    "sealed_payload_applied",
    "selected_source",
    "selected_version",
    "severity",
    "socket_path_hash",
    "skip_count",
    "smoke_policy_configured",
    "source",
    "sources",
    "status",
    "storage",
    "store_path_hash",
    "stderr_chunks",
    "stdout_chunks",
    "suppressed_count",
    "suppressions",
    "tag_update_count",
    "target_version",
    "team_id",
    "team_name",
    "team_status",
    "template_name",
    "template_source_kind",
    "timestamp",
    "to_profile",
    "to_profile_id",
    "to_source",
    "transports",
    "trust_operation",
    "trust_root_recorded",
    "ttl_seconds",
    "unsupported_reason",
    "updated_field_count",
    "updated_fields",
    "user_verification",
    "value",
    "version",
    "versions",
    "warn_count",
    "webauthn_relying_party_id",
];

impl Store {
    /// Appends one metadata-only audit row to the project audit chain.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the audit row cannot be canonicalized, signed,
    /// or inserted.
    pub fn append_audit(
        &mut self,
        audit_key: &[u8],
        audit: &AuditWrite<'_>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.savepoint()?;
        append_audit(&transaction, audit_key, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Appends a `SCHEMA_MIGRATE` audit row describing a schema bootstrap that
    /// actually advanced the migration ledger.
    ///
    /// Returns `Ok(false)` and writes nothing when `outcome` reports no applied
    /// steps (idempotent re-init). On any real version change the helper writes
    /// one row to the project's audit chain and returns `Ok(true)`.
    ///
    /// `initialize_schema` runs before any project exists, so the migration row
    /// itself is deferred to the first call site that holds a project audit
    /// key. This sidesteps the chicken-and-egg between the schema bootstrap
    /// (which creates the `audit_log` table) and the audit chain (which needs
    /// the bootstrapped table plus a project key).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the audit row cannot be canonicalized,
    /// signed, or inserted.
    pub fn record_schema_migrate_audit(
        &mut self,
        project_id: &str,
        audit_key: &[u8],
        outcome: &SchemaMigrationOutcome,
        timestamp: i64,
    ) -> Result<bool, StoreError> {
        if !outcome.advanced() {
            return Ok(false);
        }
        let before = outcome.before.map_or(Value::Null, Value::from);
        let metadata = json!({
            "schema_version": 1,
            "action": AUDIT_ACTION_SCHEMA_MIGRATE,
            "status": "SUCCESS",
            "check_names": outcome
                .applied_steps
                .iter()
                .map(|step| (*step).to_owned())
                .collect::<Vec<_>>(),
            "schema_versions": json!({
                "before": before,
                "after": outcome.after,
            }),
            "migration_count": outcome.applied_steps.len() as u64,
        });
        let audit = AuditWrite {
            project_id,
            profile_id: None,
            action: AUDIT_ACTION_SCHEMA_MIGRATE,
            status: "SUCCESS",
            secret_name: None,
            command: None,
            metadata_json: &metadata,
            timestamp,
        };
        self.append_audit(audit_key, &audit)?;
        Ok(true)
    }

    /// Lists recent metadata-only audit action names for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query audit rows.
    pub fn list_recent_audit_actions(
        &self,
        project_id: &str,
        limit: u32,
    ) -> Result<Vec<String>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT action
             FROM audit_log
             WHERE project_id = ?1
             ORDER BY sequence DESC
             LIMIT ?2",
        )?;
        let mut actions = statement
            .query_map((project_id, limit), |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        actions.reverse();
        Ok(actions)
    }

    /// Lists metadata-only audit rows for a profile since the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query audit rows.
    pub fn list_audit_rows_since(
        &self,
        project_id: &str,
        profile_id: &str,
        since: i64,
    ) -> Result<Vec<AuditLogRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, timestamp, profile_id, action, status,
                    json_extract(metadata_json, '$.secret_name'),
                    json_extract(metadata_json, '$.command')
             FROM audit_log
             WHERE project_id = ?1 AND profile_id = ?2 AND timestamp >= ?3
             ORDER BY timestamp, sequence",
        )?;
        let rows = statement
            .query_map((project_id, profile_id, since), audit_log_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists metadata-only audit rows for a project using optional filters.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query audit rows.
    pub fn list_audit_rows_filtered(
        &self,
        project_id: &str,
        filter: &AuditListFilter,
    ) -> Result<Vec<AuditLogRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, timestamp, profile_id, action, status,
                    json_extract(metadata_json, '$.secret_name'),
                    json_extract(metadata_json, '$.command')
             FROM (
               SELECT sequence, timestamp, profile_id, action, status, metadata_json
               FROM audit_log
               WHERE project_id = ?1
                 AND (?2 IS NULL OR profile_id = ?2)
                 AND (?3 IS NULL OR action = ?3)
                 AND (?4 IS NULL OR status = ?4)
                 AND (?5 IS NULL OR timestamp >= ?5)
                 AND (?6 IS NULL OR timestamp <= ?6)
               ORDER BY sequence DESC
               LIMIT ?7
             )
             ORDER BY sequence",
        )?;
        let rows = statement
            .query_map(
                params![
                    project_id,
                    filter.profile_id.as_deref(),
                    filter.action.as_deref(),
                    filter.status.as_deref(),
                    filter.since_unix_nanos,
                    filter.until_unix_nanos,
                    filter.limit,
                ],
                audit_log_record_from_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Returns every audit row for a project, in ascending sequence
    /// order, with all HMAC-covered and convenience fields preserved.
    ///
    /// Used by sealed-bundle export when `--include-audit` is set so
    /// the bundle payload carries the structurally verifiable chain.
    /// The returned rows form a contiguous prefix of the project audit
    /// log up to the latest sequence; callers serializing them into a
    /// bundle should treat the final row's `sequence` and `hmac` as the
    /// `(checkpoint_sequence, checkpoint_hmac)` for that bundle.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the
    /// audit log or any row carries a malformed HMAC blob.
    pub fn list_exportable_audit_rows(
        &self,
        project_id: &str,
    ) -> Result<Vec<ExportableAuditRow>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, schema_version, timestamp, profile_id, action, status,
                    metadata_json, secret_name, command, previous_hmac, hmac
             FROM audit_log
             WHERE project_id = ?1
             ORDER BY sequence",
        )?;
        let rows = statement
            .query_map([project_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?.cast_unsigned(),
                    row.get::<_, u16>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            })?
            .map(|row| {
                let (
                    sequence,
                    schema_version,
                    timestamp,
                    profile_id,
                    action,
                    status,
                    metadata_json,
                    secret_name,
                    command,
                    previous_hmac,
                    hmac,
                ) = row?;
                Ok(ExportableAuditRow {
                    sequence,
                    schema_version,
                    timestamp,
                    profile_id,
                    action,
                    status,
                    metadata_json,
                    secret_name,
                    command,
                    previous_hmac: hmac_vec_to_array(sequence, previous_hmac)?,
                    hmac: hmac_vec_to_array(sequence, hmac)?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(rows)
    }

    /// Verifies the local audit HMAC chain without appending an audit row.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] for database, HMAC-key, or canonicalization failures.
    pub fn verify_audit_chain_read_only(
        &self,
        project_id: &str,
        audit_key: &[u8],
    ) -> Result<AuditChainVerification, StoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        let rows = read_audit_rows(&transaction, project_id)?;
        let verification = verify_audit_rows(&rows, audit_key)?;
        transaction.commit()?;
        Ok(verification)
    }

    /// Creates an authenticated checkpoint from a verified, nonempty audit chain.
    ///
    /// Retain the result outside the vault's rollback domain. This does not
    /// append a row or establish whether the chain was rolled back before the
    /// checkpoint was created. The chain and its last row share one snapshot.
    ///
    /// # Errors
    /// Returns [`StoreError::AuditIntegrity`] for an empty or invalid chain,
    /// or a storage/cryptographic error when the checkpoint cannot be created.
    pub fn audit_checkpoint(
        &self,
        project_id: &ProjectId,
        audit_key: &[u8; AUDIT_HMAC_LEN],
    ) -> Result<AuditCheckpoint, StoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        let rows = read_audit_rows(&transaction, project_id.as_str())?;
        require_verified_chain(&verify_audit_rows(&rows, audit_key)?)?;
        let Some(last) = rows.last() else {
            return Err(StoreError::AuditIntegrity {
                sequence: 0,
                reason: "cannot checkpoint an empty audit history".to_owned(),
            });
        };
        let mut checkpoint = AuditCheckpoint {
            schema_version: 1,
            project_id: project_id.clone(),
            sequence: last.sequence,
            row_hmac: last.hmac,
            authentication_tag: [0; AUDIT_HMAC_LEN],
        };
        checkpoint.authentication_tag =
            checkpoint_mac(&checkpoint, audit_key)?.finalize().into_bytes().into();
        transaction.commit()?;
        Ok(checkpoint)
    }

    /// Verifies that the current chain extends an independently retained checkpoint.
    ///
    /// The full chain and checkpoint are checked in the same transaction as the
    /// success audit append. Checkpoint, chain, or storage errors append nothing.
    ///
    /// # Errors
    /// Returns [`StoreError::AuditIntegrity`] when the checkpoint is invalid,
    /// belongs to another project, or is not part of the verified local history.
    pub fn verify_audit_checkpoint_and_append(
        &mut self,
        project_id: &ProjectId,
        audit_key: &[u8; AUDIT_HMAC_LEN],
        checkpoint: &AuditCheckpoint,
        timestamp: i64,
    ) -> Result<u64, StoreError> {
        self.verify_and_append(project_id.as_str(), audit_key, Some(checkpoint), timestamp)
    }

    /// Verifies the local audit HMAC chain and appends an `AUDIT_VERIFY` row on success.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AuditIntegrity`] for the first detected chain break.
    /// Returns other [`StoreError`] values for database, parsing, or HMAC construction failures.
    pub fn verify_audit_chain_and_append(
        &mut self,
        project_id: &str,
        audit_key: &[u8],
        timestamp: i64,
    ) -> Result<u64, StoreError> {
        self.verify_and_append(project_id, audit_key, None, timestamp)
    }

    fn verify_and_append(
        &mut self,
        project_id: &str,
        audit_key: &[u8],
        checkpoint: Option<&AuditCheckpoint>,
        timestamp: i64,
    ) -> Result<u64, StoreError> {
        let transaction = self.connection.transaction()?;
        let rows = read_audit_rows(&transaction, project_id)?;
        let verification = verify_audit_rows(&rows, audit_key)?;
        require_verified_chain(&verification)?;
        if let Some(checkpoint) = checkpoint {
            let key = audit_key
                .try_into()
                .map_err(|_| StoreError::InvalidAuditKeyLength { actual: audit_key.len() })?;
            verify_checkpoint(project_id, key, checkpoint, &rows)?;
        }

        let rows_verified = verification.rows_verified;
        let check_names = if checkpoint.is_some() {
            vec!["audit_hmac_chain", "external_audit_checkpoint"]
        } else {
            vec!["audit_hmac_chain"]
        };
        let metadata = json!({
            "schema_version": 1,
            "action": "AUDIT_VERIFY",
            "status": "SUCCESS",
            "check_names": check_names,
            "pass_count": check_names.len(),
            "warn_count": 0,
            "fail_count": 0,
            "skip_count": 0,
            "rows_verified": rows_verified,
        });
        let audit = AuditWrite {
            project_id,
            profile_id: None,
            action: "AUDIT_VERIFY",
            status: "SUCCESS",
            secret_name: None,
            command: None,
            metadata_json: &metadata,
            timestamp,
        };
        append_audit(&transaction, audit_key, &audit)?;
        transaction.commit()?;

        Ok(rows_verified)
    }
}
