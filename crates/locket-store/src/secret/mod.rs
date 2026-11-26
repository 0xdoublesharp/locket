//! Secret records, versions, blobs, fingerprints, and `Store` lifecycle methods.

use crate::audit::AuditContext;

mod discovery;
mod expiry;
mod lifecycle;
mod links;
mod queries;

pub use discovery::{DiscoveredSecretRecord, SecretDiscoveryFilter};
pub use expiry::{SecretExpirationNotice, SecretExpiryPolicy, SecretExpiryStatus};
pub use links::{
    DuplicateSecretMemberRecord, DuplicateValueGroupRecord, ResolvedSecretLink, SecretLinkRecord,
    SecretTransferAudit, SharedSecretUsageRecord,
};

/// Secret metadata row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretRecord {
    /// Secret identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Parent profile identifier.
    pub profile_id: String,
    /// Secret name.
    pub name: String,
    /// Persisted secret source string.
    pub source: String,
    /// Persisted secret origin string.
    pub origin: String,
    /// Current secret version.
    pub current_version: u32,
    /// Persisted secret state string.
    pub state: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last metadata update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
    /// Last rotation timestamp in nanoseconds since the Unix epoch.
    pub last_rotated_at: Option<i64>,
    /// Tombstone timestamp in nanoseconds since the Unix epoch.
    pub deleted_at: Option<i64>,
}

/// Secret metadata row ordered for active-profile UI listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretMetadataRecord {
    /// Secret identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Parent profile identifier.
    pub profile_id: String,
    /// Secret name.
    pub name: String,
    /// Persisted secret source string.
    pub source: String,
    /// Numeric source precedence, with larger values winning runtime resolution.
    pub source_precedence: u8,
    /// Persisted secret origin string.
    pub origin: String,
    /// Current secret version.
    pub current_version: u32,
    /// Persisted secret state string.
    pub state: String,
    /// Whether command policies should treat the secret as required.
    pub required: bool,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last metadata update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
    /// Last rotation timestamp in nanoseconds since the Unix epoch.
    pub last_rotated_at: Option<i64>,
    /// Target Global Vault secret identifier when `source == "shared-link"`.
    pub linked_target_secret_id: Option<String>,
    /// Target Global Vault secret name when `source == "shared-link"`.
    pub linked_target_name: Option<String>,
    /// Number of project links pointing to this Global Vault secret.
    pub link_count: u32,
}

/// Secret version metadata row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretVersionRecord {
    /// Parent secret identifier.
    pub secret_id: String,
    /// Version number.
    pub version: u32,
    /// Persisted secret source string.
    pub source: String,
    /// Persisted secret origin string.
    pub origin: String,
    /// Persisted version state string.
    pub state: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Deprecation timestamp in nanoseconds since the Unix epoch.
    pub deprecated_at: Option<i64>,
    /// Grace-window expiration timestamp in nanoseconds since the Unix epoch.
    pub grace_until: Option<i64>,
    /// Purge timestamp in nanoseconds since the Unix epoch.
    pub purged_at: Option<i64>,
}

/// Secret version metadata joined with its parent secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretVersionMetadataRecord {
    /// Parent secret identifier.
    pub secret_id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Parent profile identifier.
    pub profile_id: String,
    /// Secret name.
    pub name: String,
    /// Persisted secret source string.
    pub source: String,
    /// Numeric source precedence, with larger values winning runtime resolution.
    pub source_precedence: u8,
    /// Persisted secret origin string.
    pub origin: String,
    /// Whole-secret state.
    pub secret_state: String,
    /// Current version pointer on the parent secret.
    pub current_version: u32,
    /// Last rotation timestamp on the parent secret.
    pub last_rotated_at: Option<i64>,
    /// Version number.
    pub version: u32,
    /// Persisted version state string.
    pub version_state: String,
    /// Version creation timestamp.
    pub created_at: i64,
    /// Deprecation timestamp.
    pub deprecated_at: Option<i64>,
    /// Grace-window expiration timestamp.
    pub grace_until: Option<i64>,
    /// Purge timestamp.
    pub purged_at: Option<i64>,
}

/// Encrypted secret value row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretBlobRecord {
    /// Parent secret identifier.
    pub secret_id: String,
    /// Version number.
    pub version: u32,
    /// Encrypted data-encryption key bytes.
    pub encrypted_dek: Vec<u8>,
    /// Encrypted secret value bytes.
    pub ciphertext: Vec<u8>,
    /// Nonce used for the value ciphertext.
    pub value_nonce: [u8; 24],
    /// AAD schema version.
    pub aad_schema_version: u16,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

/// Keyed secret fingerprint row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretFingerprintRecord {
    /// Parent secret identifier.
    pub secret_id: String,
    /// Version number.
    pub version: u32,
    /// Keyed fingerprint bytes.
    pub fingerprint: Vec<u8>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

/// Metadata applied to the version being superseded by rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionDeprecation {
    /// Deprecation timestamp in nanoseconds since the Unix epoch.
    pub deprecated_at: i64,
    /// Optional grace-window expiration timestamp.
    pub grace_until: Option<i64>,
}

/// Target lifecycle operation for a profile copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretCopyTarget<'a> {
    /// Create a new target secret row at version 1.
    Create(&'a SecretRecord),
    /// Rotate an existing active target secret.
    Rotate {
        /// Existing active target secret.
        secret: &'a SecretRecord,
        /// Metadata to apply to the superseded target version.
        deprecation: VersionDeprecation,
    },
}

/// Complete mutable metadata written when creating or rotating a secret.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecretInitialMetadata<'a> {
    /// Optional description.
    pub description: Option<&'a str>,
    /// Optional owner.
    pub owner: Option<&'a str>,
    /// Full tag list.
    pub tags: &'a [String],
    /// Whether command policies should treat the secret as required.
    pub required: bool,
}

/// Stored mutable metadata for a secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretMutableMetadata {
    /// Optional description.
    pub description: Option<String>,
    /// Optional owner.
    pub owner: Option<String>,
    /// Full tag list.
    pub tags: Vec<String>,
    /// Whether command policies should treat the secret as required.
    pub required: bool,
}

fn mutable_metadata_from_row(
    row: &rusqlite::Row<'_>,
    start: usize,
) -> Result<SecretMutableMetadata, crate::StoreError> {
    let tags_json: String = row.get(start + 2)?;
    Ok(SecretMutableMetadata {
        description: row.get(start)?,
        owner: row.get(start + 1)?,
        tags: serde_json::from_str(&tags_json)?,
        required: row.get(start + 3)?,
    })
}

/// Mutable secret metadata update plus optional timestamp/audit context.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretMetadataUpdate<'a> {
    /// Optional description replacement.
    pub description: Option<&'a str>,
    /// Optional owner replacement.
    pub owner: Option<&'a str>,
    /// Optional full tag-list replacement.
    pub tags: Option<&'a [String]>,
    /// Optional required flag replacement.
    pub required: Option<bool>,
    /// Optional `updated_at` replacement.
    pub updated_at: Option<i64>,
    /// Optional audit row appended in the same transaction when the update matches.
    pub audit: Option<AuditContext<'a>>,
}

pub fn secret_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRecord> {
    Ok(SecretRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        name: row.get(3)?,
        source: row.get(4)?,
        origin: row.get(5)?,
        current_version: row.get(6)?,
        state: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        last_rotated_at: row.get(10)?,
        deleted_at: row.get(11)?,
    })
}

pub fn secret_metadata_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<SecretMetadataRecord> {
    Ok(SecretMetadataRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        name: row.get(3)?,
        source: row.get(4)?,
        source_precedence: row.get(5)?,
        origin: row.get(6)?,
        current_version: row.get(7)?,
        state: row.get(8)?,
        required: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        last_rotated_at: row.get(12)?,
        linked_target_secret_id: row.get(13)?,
        linked_target_name: row.get(14)?,
        link_count: row.get(15)?,
    })
}

pub fn secret_version_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<SecretVersionRecord> {
    Ok(SecretVersionRecord {
        secret_id: row.get(0)?,
        version: row.get(1)?,
        source: row.get(2)?,
        origin: row.get(3)?,
        state: row.get(4)?,
        created_at: row.get(5)?,
        deprecated_at: row.get(6)?,
        grace_until: row.get(7)?,
        purged_at: row.get(8)?,
    })
}

pub fn secret_version_metadata_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<SecretVersionMetadataRecord> {
    Ok(SecretVersionMetadataRecord {
        secret_id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        name: row.get(3)?,
        source: row.get(4)?,
        source_precedence: row.get(5)?,
        origin: row.get(6)?,
        secret_state: row.get(7)?,
        current_version: row.get(8)?,
        last_rotated_at: row.get(9)?,
        version: row.get(10)?,
        version_state: row.get(11)?,
        created_at: row.get(12)?,
        deprecated_at: row.get(13)?,
        grace_until: row.get(14)?,
        purged_at: row.get(15)?,
    })
}

pub fn secret_blob_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretBlobRecord> {
    Ok(SecretBlobRecord {
        secret_id: row.get(0)?,
        version: row.get(1)?,
        encrypted_dek: row.get(2)?,
        ciphertext: row.get(3)?,
        value_nonce: crate::row::nonce_from_row(row, 4, "blobs.value_nonce")?,
        aad_schema_version: row.get(5)?,
        created_at: row.get(6)?,
    })
}
