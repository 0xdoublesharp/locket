//! Metadata-only audit-log RPC payloads and read helpers.

use std::path::PathBuf;

use locket_core::privacy_alias;
use locket_store::{AuditListFilter, Store, StoreError};
use serde::{Deserialize, Serialize};

/// Maximum number of audit rows returned by one `ListAudit` call.
const MAX_LIST_AUDIT_ROWS: u32 = 500;
/// Default number of recent audit rows when the client does not supply a limit.
const DEFAULT_LIST_AUDIT_ROWS: u32 = 100;

/// Wire payload for the `ListAudit` RPC.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListAuditRequest {
    /// `SQLite` store path to read.
    pub store_path: PathBuf,
    /// Project id whose audit chain is listed.
    pub project_id: String,
    /// Optional profile id filter.
    pub profile_id: Option<String>,
    /// Optional audit action filter.
    pub action: Option<String>,
    /// Optional audit status filter.
    pub status: Option<String>,
    /// Optional inclusive lower timestamp bound.
    pub since_unix_nanos: Option<i64>,
    /// Optional inclusive upper timestamp bound.
    pub until_unix_nanos: Option<i64>,
    /// Maximum number of recent matching rows.
    pub limit: Option<u32>,
    /// Whether project/profile/secret/command labels should be aliased.
    #[serde(default)]
    pub redact_names: bool,
}

/// Metadata-only `ListAudit` response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListAuditResponse {
    /// Matching audit rows, ordered by sequence ascending.
    pub rows: Vec<ListAuditRow>,
    /// Whole-project chain status, independent of filters.
    pub chain_status: AuditChainStatus,
}

/// Metadata-only audit row for agent clients.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListAuditRow {
    /// Project-local audit sequence.
    pub sequence: u64,
    /// Event timestamp in nanoseconds since the Unix epoch.
    pub timestamp: i64,
    /// Optional profile id or privacy alias.
    pub profile_id: Option<String>,
    /// Audit action.
    pub action: String,
    /// Audit status.
    pub status: String,
    /// Optional secret-name label; never a value.
    pub secret_name: Option<String>,
    /// Optional command label.
    pub command: Option<String>,
}

/// Read-only chain status returned with audit rows.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditChainStatus {
    /// `Some(true)` when the unlocked audit key verifies the full chain,
    /// `Some(false)` on first break, and `None` when the vault is locked.
    pub hmac_ok: Option<bool>,
    /// First broken sequence if `hmac_ok` is `Some(false)`.
    pub first_break_sequence: Option<u64>,
    /// Rows verified before the first break, or all rows on success.
    pub rows_verified: u64,
    /// Whether HMAC verification was skipped because no live key was available.
    pub locked: bool,
}

/// Lists filtered audit rows and returns read-only chain status.
///
/// # Errors
///
/// Returns [`StoreError`] when the chain cannot be queried or verified.
pub fn list_audit(
    store: &Store,
    request: &ListAuditRequest,
    audit_key: Option<&[u8]>,
) -> Result<ListAuditResponse, StoreError> {
    let limit = request.limit.unwrap_or(DEFAULT_LIST_AUDIT_ROWS).clamp(1, MAX_LIST_AUDIT_ROWS);
    let filter = AuditListFilter {
        profile_id: request.profile_id.clone(),
        action: request.action.clone(),
        status: request.status.clone(),
        since_unix_nanos: request.since_unix_nanos,
        until_unix_nanos: request.until_unix_nanos,
        limit,
    };
    let rows = store
        .list_audit_rows_filtered(&request.project_id, &filter)?
        .into_iter()
        .map(|row| ListAuditRow {
            sequence: row.sequence,
            timestamp: row.timestamp,
            profile_id: row.profile_id.map(|value| profile_label(&value, request.redact_names)),
            action: row.action,
            status: row.status,
            secret_name: row.secret_name.map(|value| secret_label(&value, request.redact_names)),
            command: row.command.map(|value| command_label(&value, request.redact_names)),
        })
        .collect();

    let chain_status = match audit_key {
        Some(key) => {
            let verification = store.verify_audit_chain_read_only(&request.project_id, key)?;
            AuditChainStatus {
                hmac_ok: Some(verification.hmac_ok),
                first_break_sequence: verification.first_break_sequence,
                rows_verified: verification.rows_verified,
                locked: false,
            }
        }
        None => AuditChainStatus {
            hmac_ok: None,
            first_break_sequence: None,
            rows_verified: 0,
            locked: true,
        },
    };

    Ok(ListAuditResponse { rows, chain_status })
}

fn profile_label(value: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("profile", value) } else { value.to_owned() }
}

fn secret_label(value: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("secret", value) } else { value.to_owned() }
}

fn command_label(value: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("command", value) } else { value.to_owned() }
}
