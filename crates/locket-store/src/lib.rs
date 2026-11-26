//! `SQLite` storage layer for Locket.

// age 0.11 enters through locket-core and carries older transitive crates
// alongside workspace versions. The sealed-bundle dependency owns that skew.
#![allow(clippy::multiple_crate_versions)]

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

mod access;
mod atomic;
mod auditing;
mod database;
mod error;
mod records;
mod secret;

pub(crate) use access::{grants, runtime_session};
pub(crate) use auditing::audit;
pub(crate) use database::{row, schema};
pub(crate) use records::{command_policy, device, keys, passkey, profile, project, roots, team};

pub use audit::{
    AUDIT_METADATA_JSON_LIMIT, AuditChainVerification, AuditContext, AuditListFilter,
    AuditLogRecord, AuditWrite, ExportableAuditRow, ImportedAuditChainRow,
    ImportedAuditChainVerification, verify_imported_audit_chain_structure,
};
pub use auditing::witness::AuditWitnessReceiptRecord;
pub use command_policy::CommandPolicyIndexRecord;
pub use device::DeviceRecord;
pub use error::StoreError;
pub use grants::DirectoryGrantRecord;
pub use keys::KeyRecord;
pub use passkey::{
    DEFAULT_WEBAUTHN_RELYING_PARTY_ID, PasskeyCredentialRecord, PasskeyPrfWrapRecord,
};
pub use profile::{
    ProfileDangerousAudit, ProfileDangerousChange, ProfileRecord, archive_empty_profile_for_import,
};
pub use project::{ProjectRecord, ProjectSelectorResolution, ProjectSummaryRecord};
pub use roots::ProjectRootRecord;
pub use runtime_session::{
    AutomationClientNonceRecord, AutomationClientPrivateKeyRefRecord, AutomationClientRecord,
    InvalidRuntimeSessionSecretNameRetention, RuntimeSessionRecord,
    RuntimeSessionSecretNameRetention,
};
pub use schema::SCHEMA_VERSION;
pub use secret::{
    DiscoveredSecretRecord, DuplicateSecretMemberRecord, DuplicateValueGroupRecord,
    ResolvedSecretLink, SecretBlobRecord, SecretCopyTarget, SecretDiscoveryFilter,
    SecretExpirationNotice, SecretExpiryPolicy, SecretExpiryStatus, SecretFingerprintRecord,
    SecretInitialMetadata, SecretLinkRecord, SecretMetadataRecord, SecretMetadataUpdate,
    SecretMutableMetadata, SecretRecord, SecretTransferAudit, SecretVersionRecord,
    SharedSecretUsageRecord, VersionDeprecation,
};
pub use team::{
    PendingTeamInviteRecord, StoredTeamInviteRecord, TeamInviteRecord, TeamMemberListRecord,
    TeamRecord,
};

/// SQLite-backed Locket store.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
}

impl Store {
    /// Opens a `SQLite` store at `path` and configures connection-level safety pragmas.
    ///
    /// The connection enables foreign key enforcement and secure deletion, requests
    /// WAL journaling where `SQLite` supports it, and sets a 5000 ms busy timeout.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot open or configure the store.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        schema::configure_connection(&connection, true)?;
        Ok(Self { connection })
    }

    /// Opens an existing `SQLite` database without schema or journal-mode writes.
    ///
    /// Sets the busy timeout and secure deletion connection settings. This never
    /// creates a missing database or runs migrations, and the open flags deny writes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when the existing database cannot be opened.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        schema::configure_connection(&connection, false)?;
        Ok(Self { connection })
    }

    /// Creates a fresh store at [`SCHEMA_VERSION`] or opens one already at it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnsupportedSchema`] for a store from a newer Locket
    /// binary and [`StoreError::OutdatedSchema`] for an older store, which
    /// Locket does not migrate. Returns [`StoreError::Sqlite`] for `SQLite`
    /// failures while creating or recording the schema.
    pub fn initialize_schema(&mut self) -> Result<(), StoreError> {
        schema::initialize_schema(&mut self.connection)
    }

    /// Returns the highest recorded schema version, or `None` for a store
    /// without the migration ledger.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot inspect the
    /// migration ledger.
    pub fn current_schema_version(&self) -> Result<Option<i64>, StoreError> {
        schema::current_schema_version(&self.connection)
    }

    /// Returns the underlying `SQLite` connection.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Returns the underlying `SQLite` connection mutably.
    #[must_use]
    pub const fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    /// Runs `SQLite`'s metadata-only integrity check.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot execute the check.
    pub fn integrity_check(&self) -> Result<Vec<String>, StoreError> {
        let mut statement = self.connection.prepare("PRAGMA integrity_check")?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests;
