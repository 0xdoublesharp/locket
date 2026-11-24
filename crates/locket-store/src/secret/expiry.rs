//! Metadata-only secret expiry and rotation policy.

use rusqlite::{OptionalExtension, params};

use crate::{Store, StoreError};

const NANOS_PER_DAY: i128 = 86_400_000_000_000;

/// Expiry and advisory rotation settings for a secret.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecretExpiryPolicy {
    /// Hard expiry timestamp in Unix nanoseconds, if configured.
    pub expires_at: Option<i64>,
    /// Advisory rotation interval in days, if configured.
    pub rotate_after_days: Option<u32>,
}

/// Hard-expiry status within the requested notice window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretExpiryStatus {
    /// The expiry timestamp has been reached.
    Expired,
    /// The expiry timestamp is within the requested warning window.
    ExpiringSoon,
}

/// A metadata-only notice for an active secret that is expiring or due for rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretExpirationNotice {
    /// Identifier of the secret.
    pub secret_id: String,
    /// Identifier of the project that owns the secret.
    pub project_id: String,
    /// Identifier of the profile containing the secret.
    pub profile_id: String,
    /// Name of the secret.
    pub name: String,
    /// Persisted source name.
    pub source: String,
    /// Stored expiry and rotation settings.
    pub policy: SecretExpiryPolicy,
    /// Hard-expiry status, when due within the requested window.
    pub expiry_status: Option<SecretExpiryStatus>,
    /// Whether the advisory rotation deadline has been reached.
    pub stale: bool,
}

impl Store {
    /// Reads the expiry policy of a secret, including a tombstoned secret.
    ///
    /// Returns `None` when the secret does not exist. A secret with no settings
    /// returns the default policy.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when policy metadata cannot be read or decoded.
    pub fn get_secret_expiry_policy(
        &self,
        secret_id: &str,
    ) -> Result<Option<SecretExpiryPolicy>, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT expires_at, rotate_after_days FROM secrets WHERE id = ?1",
                [secret_id],
                |row| {
                    Ok(SecretExpiryPolicy {
                        expires_at: row.get(0)?,
                        rotate_after_days: row.get(1)?,
                    })
                },
            )
            .optional()?)
    }

    /// Replaces the expiry policy and update timestamp of an existing secret.
    ///
    /// Returns whether the secret exists. A field set to `None` clears that setting.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when policy metadata cannot be written.
    pub fn set_secret_expiry_policy(
        &self,
        secret_id: &str,
        policy: SecretExpiryPolicy,
        updated_at: i64,
    ) -> Result<bool, StoreError> {
        let updated = self.connection.execute(
            "UPDATE secrets SET expires_at = ?2, rotate_after_days = ?3, updated_at = ?4
             WHERE id = ?1",
            params![secret_id, policy.expires_at, policy.rotate_after_days, updated_at],
        )?;
        Ok(updated != 0)
    }

    /// Lists active secrets that have expired, will expire within the warning
    /// window, or are due for rotation. Reads metadata only.
    ///
    /// The window includes its end, and negative windows count as zero.
    /// Rotation intervals are measured from the last rotation or, if the secret
    /// has never been rotated, its creation.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when policy metadata cannot be read or decoded.
    pub fn list_expiring_or_stale_secrets(
        &self,
        project_id: Option<&str>,
        now_unix_nanos: i64,
        warn_within_nanos: i64,
    ) -> Result<Vec<SecretExpirationNotice>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT id, project_id, profile_id, name, source, expires_at, rotate_after_days,
                    COALESCE(last_rotated_at, created_at)
             FROM secrets
             WHERE state = 'active' AND (?1 IS NULL OR project_id = ?1)
               AND (expires_at IS NOT NULL OR rotate_after_days IS NOT NULL)
             ORDER BY project_id, profile_id, name, source",
        )?;
        let warn_until = now_unix_nanos.saturating_add(warn_within_nanos.max(0));
        let mut rows = statement.query([project_id])?;
        let mut notices = Vec::new();
        while let Some(row) = rows.next()? {
            let policy =
                SecretExpiryPolicy { expires_at: row.get(5)?, rotate_after_days: row.get(6)? };
            let rotation_base: i64 = row.get(7)?;
            let expiry_status = match policy.expires_at {
                Some(expires_at) if expires_at <= now_unix_nanos => {
                    Some(SecretExpiryStatus::Expired)
                }
                Some(expires_at) if expires_at <= warn_until => {
                    Some(SecretExpiryStatus::ExpiringSoon)
                }
                _ => None,
            };
            let stale = policy.rotate_after_days.is_some_and(|days| {
                i128::from(now_unix_nanos) - i128::from(rotation_base)
                    >= i128::from(days) * NANOS_PER_DAY
            });
            if expiry_status.is_some() || stale {
                notices.push(SecretExpirationNotice {
                    secret_id: row.get(0)?,
                    project_id: row.get(1)?,
                    profile_id: row.get(2)?,
                    name: row.get(3)?,
                    source: row.get(4)?,
                    policy,
                    expiry_status,
                    stale,
                });
            }
        }
        Ok(notices)
    }
}
