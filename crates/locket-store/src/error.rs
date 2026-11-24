//! Storage-layer error types.

use locket_core::{AuditCanonicalizationError, AuditWitnessError, LocketError};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("{field} must be {expected} bytes, got {actual}")]
pub struct InvalidFixedBytesLength {
    pub field: &'static str,
    pub expected: usize,
    pub actual: usize,
}

#[derive(Debug, Error)]
#[error("{field} must be 24 bytes, got {actual}")]
pub struct InvalidNonceLength {
    pub field: &'static str,
    pub actual: usize,
}

/// Error returned by the storage layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// `SQLite` returned an error.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// A secret changed after the caller fetched its current version.
    #[error(
        "secret {secret_id} is no longer active at version {expected_version}; reload and retry"
    )]
    SecretStateConflict {
        /// Secret whose stored state no longer matches the caller's snapshot.
        secret_id: String,
        /// Current version expected by the caller.
        expected_version: u32,
    },

    /// The selected versions include the current version of an active secret.
    #[error("cannot purge current version {version} of active secret {secret_id}")]
    ActiveSecretVersionPurge {
        /// Identifier of the active secret.
        secret_id: String,
        /// Current version that cannot be purged.
        version: u32,
    },

    /// JSON metadata encoding failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Audit HMAC canonicalization failed.
    #[error(transparent)]
    AuditCanonicalization(#[from] AuditCanonicalizationError),

    /// External witness signature or chain verification failed.
    #[error(transparent)]
    AuditWitness(#[from] AuditWitnessError),

    /// Audit HMAC key length was invalid.
    #[error("audit HMAC key must be non-empty, got {actual}")]
    InvalidAuditKeyLength {
        /// Actual key length in bytes.
        actual: usize,
    },

    /// Stored audit HMAC length was invalid.
    #[error("audit HMAC must be 32 bytes, got {actual}")]
    InvalidAuditHmacLength {
        /// Actual HMAC length in bytes.
        actual: usize,
    },

    /// Audit chain verification failed.
    #[error("audit integrity failed at sequence {sequence}: {reason}")]
    AuditIntegrity {
        /// Sequence number where verification failed.
        sequence: u64,
        /// Metadata-only failure reason.
        reason: String,
    },

    /// Serialized `metadata_json` exceeded the per-row spec cap.
    #[error(
        "audit metadata_json is {actual} bytes; the per-row cap is {limit} bytes (action {action})"
    )]
    AuditMetadataTooLarge {
        /// Action name from the rejected `AuditWrite`.
        action: String,
        /// Serialized JSON byte length the writer attempted to insert.
        actual: usize,
        /// Spec-defined per-row cap (64 KiB).
        limit: usize,
    },

    /// HMAC-covered audit metadata did not match the v1 typed shape rules.
    #[error("audit metadata_json for action {action} is invalid: {reason}")]
    AuditMetadataInvalid {
        /// Action name from the rejected `AuditWrite`.
        action: String,
        /// Metadata-only validation reason.
        reason: String,
    },

    /// The database schema is newer than this binary can read.
    #[error(
        "database schema version {found} is newer than supported schema version {supported}; upgrade Locket"
    )]
    UnsupportedSchema {
        /// Newer schema version found in the database.
        found: i64,
        /// Maximum schema version this binary supports.
        supported: u32,
    },

    /// A team-invite acceptance was attempted for an invite that has
    /// already been accepted or revoked. Maps to
    /// [`LocketError::ReplayDetected`] (exit 113) at the CLI boundary.
    #[error("invite {invite_id} already accepted or revoked; refusing replay")]
    InviteReplayDetected {
        /// Invite identifier the caller tried to mark accepted.
        invite_id: String,
    },

    /// A team-invite acceptance was attempted for an invite that does
    /// not exist in the local store.
    #[error("invite {invite_id} not found in local team_invites store")]
    InviteNotFound {
        /// Invite identifier the caller tried to mark accepted.
        invite_id: String,
    },
}

impl StoreError {
    /// Returns the stable high-level Locket failure represented by this store error.
    #[must_use]
    pub fn locket_error(&self) -> LocketError {
        match self {
            Self::Sqlite(error) => sqlite_locket_error(error),
            Self::SecretStateConflict { .. } => LocketError::StorageBusy,
            Self::UnsupportedSchema { .. } => LocketError::SchemaNewerThanBinary,
            Self::AuditIntegrity { .. }
            | Self::InvalidAuditHmacLength { .. }
            | Self::InvalidAuditKeyLength { .. }
            | Self::AuditCanonicalization(_)
            | Self::AuditWitness(_) => LocketError::AuditIntegrityFailed,
            Self::AuditMetadataTooLarge { .. }
            | Self::AuditMetadataInvalid { .. }
            | Self::ActiveSecretVersionPurge { .. }
            | Self::InviteNotFound { .. } => LocketError::MetadataInvalid,
            Self::Json(_) => LocketError::CorruptDb,
            Self::InviteReplayDetected { .. } => LocketError::ReplayDetected,
        }
    }
}

fn sqlite_locket_error(error: &rusqlite::Error) -> LocketError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            LocketError::StorageBusy
        }
        Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase) => {
            LocketError::CorruptDb
        }
        _ => LocketError::CorruptDb,
    }
}
