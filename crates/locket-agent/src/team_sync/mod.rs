//! Shared authenticated team package service for CLI and agent.
#![allow(missing_docs, clippy::too_many_arguments, clippy::too_many_lines)]
mod folder;
mod keys;
mod pending;
mod prune;
mod snapshot;
pub mod transport;
pub use folder::{
    SyncStatus, configure_folder, configure_folder_guarded, flush_outbox, flush_outbox_with_master,
    status, sync_folder, sync_folder_guarded,
};
pub use keys::{load_key, store_key};
use locket_core::team_package::DeviceIdentity;
use locket_store::DeviceRecord;
pub use pending::{
    PendingCollision, PendingProfileDetails, pending_profile_details,
    preserve_collision_as_override, rename_local_profile_for_pending,
};
pub use prune::{PruneResult, prune_remote_packages};
pub use snapshot::{
    add_recipient, apply_package, apply_package_guarded, apply_package_with_consent_guarded,
    initialize_owner, join_package_checkpoint, publish, publish_guarded, remove_member,
    resolve_conflict, resume_pending_profiles_guarded, shared_profile_ids,
};
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("{0}")]
    Rejected(String),
    #[error("waiting for missing predecessor; restore encrypted earlier packages")]
    MissingPredecessor,
    #[error("team transport response exceeds size limit")]
    RemoteBodyTooLarge,
    #[error("team store operation failed: {0}")]
    Store(#[from] locket_store::StoreError),
    #[error("team database operation failed: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("team cryptographic operation failed: {0}")]
    Crypto(#[from] locket_crypto::CryptoError),
    #[error("team data schema is invalid")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Package(#[from] locket_core::team_package::PackageError),
    #[error("team folder operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("protected device key unavailable: {0}")]
    Platform(#[from] locket_platform::PlatformError),
}
pub type Result<T> = std::result::Result<T, SyncError>;
/// Revalidates the unlock context immediately before committing and holds its guard.
pub type CommitAuthorization = std::sync::Arc<dyn Fn() -> Result<Box<dyn Send>> + Send + Sync>;
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn identity(device: &DeviceRecord) -> Result<DeviceIdentity> {
    Ok(DeviceIdentity::new(
        device.id.clone(),
        device
            .signing_public_key
            .as_slice()
            .try_into()
            .map_err(|_| reject("invalid signing key"))?,
        device
            .sealing_public_key
            .as_slice()
            .try_into()
            .map_err(|_| reject("invalid sealing key"))?,
    ))
}
fn reject(message: &str) -> SyncError {
    SyncError::Rejected(message.into())
}
fn nanos(now: i64) -> Result<i64> {
    now.checked_mul(1_000_000_000).ok_or_else(|| reject("invalid timestamp"))
}
#[derive(Default, Debug, serde::Serialize)]
pub struct ApplyResult {
    pub applied: usize,
    pub conflicts: usize,
    pub duplicate: bool,
    pub removed: bool,
    pub pending_profiles: usize,
}

pub use crate::handlers::team_sync::spawn_team_sync_poll;
pub use transport::{
    CredentialMode, JoinPackages, PutOutcome, RemoteTestResult, TeamTransport, TransportConfig,
    TransportSecretInput, TransportSummary, WebDavAuthKind, clear_transport, configure_transport,
    configure_transport_guarded, list_and_read_configured_join_packages,
    list_and_read_configured_join_packages_for_recipient, list_and_read_join_packages,
    list_and_read_join_packages_for_recipient, read_package_file, test_configured_transport,
    test_transport,
};
