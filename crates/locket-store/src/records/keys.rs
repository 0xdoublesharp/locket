//! Wrapped key material records and `Store` operations.

use rusqlite::{OptionalExtension, params};

use crate::Store;
use crate::error::StoreError;
use crate::row::nonce_from_row;

/// Wrapped project/profile key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRecord {
    /// Key identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Optional parent profile identifier for profile-scoped keys.
    pub profile_id: Option<String>,
    /// Persisted key purpose string.
    pub purpose: String,
    /// Encrypted key material.
    pub wrapped_material: Vec<u8>,
    /// Nonce used to wrap the key material.
    pub nonce: [u8; 24],
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

fn key_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KeyRecord> {
    Ok(KeyRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        purpose: row.get(3)?,
        wrapped_material: row.get(4)?,
        nonce: nonce_from_row(row, 5, "keys.nonce")?,
        created_at: row.get(6)?,
    })
}

impl Store {
    /// Inserts wrapped key material.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert, including
    /// uniqueness, foreign-key, and key-scope constraint failures.
    pub fn insert_key(&self, key: &KeyRecord) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO keys(id, project_id, profile_id, purpose, wrapped_material, nonce, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                key.id.as_str(),
                key.project_id.as_str(),
                key.profile_id.as_deref(),
                key.purpose.as_str(),
                key.wrapped_material.as_slice(),
                key.nonce.as_slice(),
                key.created_at,
            ],
        )?;

        Ok(())
    }

    /// Returns wrapped key material by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the key row.
    pub fn get_key(&self, id: &str) -> Result<Option<KeyRecord>, StoreError> {
        self.connection
            .prepare_cached(
                "SELECT id, project_id, profile_id, purpose, wrapped_material, nonce, created_at
                 FROM keys
                 WHERE id = ?1",
            )?
            .query_row([id], key_record_from_row)
            .optional()
            .map_err(StoreError::from)
    }

    /// Returns wrapped key material by project/profile scope and purpose.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the key row.
    pub fn get_key_by_scope(
        &self,
        project_id: &str,
        profile_id: Option<&str>,
        purpose: &str,
    ) -> Result<Option<KeyRecord>, StoreError> {
        self.connection
            .prepare_cached(
                "SELECT id, project_id, profile_id, purpose, wrapped_material, nonce, created_at
                 FROM keys
                 WHERE project_id = ?1 AND profile_id IS ?2 AND purpose = ?3",
            )?
            .query_row(params![project_id, profile_id, purpose], key_record_from_row)
            .optional()
            .map_err(StoreError::from)
    }
}
