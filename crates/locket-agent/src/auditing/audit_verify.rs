//! Audit verification RPC payloads and read-only HMAC check helper.

use std::path::PathBuf;

use locket_store::{Store, StoreError};
use serde::{Deserialize, Serialize};

/// Wire payload for the `VerifyAudit` RPC.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifyAuditRequest {
    /// `SQLite` store path to read.
    pub store_path: PathBuf,
    /// Project id whose audit chain is verified.
    pub project_id: String,
}

/// Wire response for the `VerifyAudit` RPC.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifyAuditResponse {
    /// `Some(true)` when the unlocked audit key verifies the chain,
    /// `Some(false)` on first break, and `None` when the vault is locked.
    pub hmac_ok: Option<bool>,
    /// First broken sequence if `hmac_ok` is `Some(false)`.
    pub first_break_sequence: Option<u64>,
    /// Metadata-only break reason if `hmac_ok` is `Some(false)`.
    pub first_break_reason: Option<String>,
    /// Rows verified before the first break, or all rows on success.
    pub rows_verified: u64,
    /// Whether verification was skipped because no live key was available.
    pub locked: bool,
}

impl VerifyAuditResponse {
    /// Returns a locked/metadata-only skipped response.
    #[must_use]
    pub const fn locked() -> Self {
        Self {
            hmac_ok: None,
            first_break_sequence: None,
            first_break_reason: None,
            rows_verified: 0,
            locked: true,
        }
    }
}

/// Verifies the audit chain without appending an `AUDIT_VERIFY` row.
///
/// # Errors
///
/// Returns [`StoreError`] when the chain cannot be queried or verified.
pub fn verify_audit(
    store: &Store,
    request: &VerifyAuditRequest,
    audit_key: &[u8],
) -> Result<VerifyAuditResponse, StoreError> {
    let verification = store.verify_audit_chain_read_only(&request.project_id, audit_key)?;
    Ok(VerifyAuditResponse {
        hmac_ok: Some(verification.hmac_ok),
        first_break_sequence: verification.first_break_sequence,
        first_break_reason: verification.first_break_reason,
        rows_verified: verification.rows_verified,
        locked: false,
    })
}
