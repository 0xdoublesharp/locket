//! Trusted project root records and `Store` operations.

use rusqlite::params;

use crate::Store;
use crate::error::StoreError;
use crate::row::root_hash_from_row;

/// Metadata for a trusted project root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectRootRecord {
    /// Parent project identifier.
    pub project_id: String,
    /// SHA-256 hash of the canonical root path.
    pub root_hash: [u8; 32],
    /// Last known display path for the root.
    pub display_path: Option<String>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last-seen timestamp in nanoseconds since the Unix epoch.
    pub last_seen_at: Option<i64>,
}

pub fn project_root_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ProjectRootRecord> {
    Ok(ProjectRootRecord {
        project_id: row.get(0)?,
        root_hash: root_hash_from_row(row, 1, "project_roots.root_hash")?,
        display_path: row.get(2)?,
        created_at: row.get(3)?,
        last_seen_at: row.get(4)?,
    })
}

impl Store {
    /// Records or refreshes trust for a project root hash.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the write.
    pub fn trust_project_root(
        &self,
        project_id: &str,
        root_hash: &[u8; 32],
        display_path: Option<&str>,
        timestamp: i64,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO project_roots(project_id, root_hash, display_path, created_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(project_id, root_hash) DO UPDATE SET
               display_path = excluded.display_path,
               last_seen_at = excluded.last_seen_at",
            params![project_id, root_hash.as_slice(), display_path, timestamp],
        )?;

        Ok(())
    }

    /// Returns whether a root hash is trusted for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the root row.
    pub fn project_root_is_trusted(
        &self,
        project_id: &str,
        root_hash: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let row_count = self.connection.query_row(
            "SELECT COUNT(*) FROM project_roots WHERE project_id = ?1 AND root_hash = ?2",
            params![project_id, root_hash.as_slice()],
            |row| row.get::<_, i64>(0),
        )?;

        Ok(row_count > 0)
    }

    /// Lists trusted roots for a project ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query trusted root rows.
    pub fn list_project_roots(
        &self,
        project_id: &str,
    ) -> Result<Vec<ProjectRootRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT project_id, root_hash, display_path, created_at, last_seen_at
             FROM project_roots
             WHERE project_id = ?1
             ORDER BY created_at, root_hash",
        )?;
        let roots = statement
            .query_map([project_id], project_root_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(roots)
    }

    /// Removes a trusted root from a project.
    ///
    /// Returns `true` when a root was removed and `false` when no matching root existed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the delete.
    pub fn untrust_project_root(
        &self,
        project_id: &str,
        root_hash: &[u8; 32],
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "DELETE FROM project_roots WHERE project_id = ?1 AND root_hash = ?2",
            params![project_id, root_hash.as_slice()],
        )?;

        Ok(self.connection.changes() == 1)
    }
}
