//! Project metadata records and `Store` project operations.

use std::path::Path;

use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

use crate::error::StoreError;
use crate::{ProfileRecord, ProjectRootRecord, Store};

/// Metadata for a stored project.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectRecord {
    /// Project identifier.
    pub id: String,
    /// Human-readable project name.
    pub name: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

/// Project metadata with its profiles, trusted roots, and active secret count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectSummaryRecord {
    /// Project metadata.
    pub project: ProjectRecord,
    /// Profiles ordered by name.
    pub profiles: Vec<ProfileRecord>,
    /// Trusted roots ordered by creation time and root hash.
    pub trusted_roots: Vec<ProjectRootRecord>,
    /// Number of active secret records across all profiles and sources.
    pub active_secret_count: u64,
}

/// Result of resolving a project by id, name, or trusted root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectSelectorResolution {
    /// Exactly one project matched.
    Found(ProjectRecord),
    /// No project matched.
    NotFound,
    /// Multiple distinct projects matched, ordered by name and id.
    Ambiguous(Vec<ProjectRecord>),
}

fn resolve_matches(mut projects: Vec<ProjectRecord>) -> ProjectSelectorResolution {
    match projects.len() {
        0 => ProjectSelectorResolution::NotFound,
        1 => ProjectSelectorResolution::Found(projects.remove(0)),
        _ => ProjectSelectorResolution::Ambiguous(projects),
    }
}

pub fn project_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectRecord> {
    Ok(ProjectRecord { id: row.get(0)?, name: row.get(1)?, created_at: row.get(2)? })
}

impl Store {
    /// Inserts a project metadata row when `id` does not already exist.
    ///
    /// Returns `true` when the project was inserted and `false` when a project
    /// with the same `id` already existed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert.
    pub fn insert_project_if_absent(
        &self,
        id: &str,
        name: &str,
        created_at: i64,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO projects(id, name, created_at) VALUES (?1, ?2, ?3)",
            (id, name, created_at),
        )?;

        Ok(self.connection.changes() == 1)
    }

    /// Returns project metadata by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the project row.
    pub fn get_project(&self, id: &str) -> Result<Option<ProjectRecord>, StoreError> {
        self.connection
            .prepare_cached("SELECT id, name, created_at FROM projects WHERE id = ?1")?
            .query_row([id], project_record_from_row)
            .optional()
            .map_err(StoreError::from)
    }

    /// Lists project metadata ordered by name and id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot read project metadata.
    pub fn list_projects(&self) -> Result<Vec<ProjectRecord>, StoreError> {
        let mut statement = self
            .connection
            .prepare_cached("SELECT id, name, created_at FROM projects ORDER BY name, id")?;
        let projects = statement.query_map([], project_record_from_row)?;
        Ok(projects.collect::<Result<Vec<_>, _>>()?)
    }

    /// Lists metadata-only project summaries ordered by project name and id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot read the metadata.
    pub fn list_project_summaries(&self) -> Result<Vec<ProjectSummaryRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT p.id, p.name, p.created_at,
                    (SELECT count(*) FROM secrets s WHERE s.project_id = p.id AND s.state = 'active')
             FROM projects p ORDER BY p.name, p.id",
        )?;
        let mut rows = statement.query([])?;
        let mut summaries = Vec::new();
        while let Some(row) = rows.next()? {
            let project = project_record_from_row(row)?;
            summaries.push(ProjectSummaryRecord {
                profiles: self.list_profiles(&project.id)?,
                trusted_roots: self.list_project_roots(&project.id)?,
                active_secret_count: row.get::<_, i64>(3)?.cast_unsigned(),
                project,
            });
        }
        Ok(summaries)
    }

    /// Resolves an exact project id, name, or trusted root, in that order.
    ///
    /// Root matching uses the display path and, when the selector can be
    /// canonicalized, the canonical path and its stored trust hash.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot read the metadata.
    pub fn resolve_project_selector(
        &self,
        selector: &str,
    ) -> Result<ProjectSelectorResolution, StoreError> {
        if let Some(project) = self.get_project(selector)? {
            return Ok(ProjectSelectorResolution::Found(project));
        }

        let mut by_name = self.connection.prepare_cached(
            "SELECT id, name, created_at FROM projects WHERE name = ?1 ORDER BY id",
        )?;
        let projects = by_name
            .query_map([selector], project_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        if !projects.is_empty() {
            return Ok(resolve_matches(projects));
        }

        let canonical = Path::new(selector).canonicalize().ok();
        let canonical = canonical.as_deref().map(Path::to_string_lossy);
        // This is the same canonical-path digest used when recording root trust.
        let hash = canonical.as_ref().map(|path| Sha256::digest(path.as_bytes()));
        let mut by_root = self.connection.prepare_cached(
            "SELECT p.id, p.name, p.created_at FROM projects p
             WHERE EXISTS (
                 SELECT 1 FROM project_roots r WHERE r.project_id = p.id
                 AND (r.display_path IN (?1, ?2) OR r.root_hash = ?3)
             )
             ORDER BY p.name, p.id",
        )?;
        let projects = by_root
            .query_map((selector, canonical.as_deref(), hash.as_deref()), project_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(resolve_matches(projects))
    }

    /// Deletes a project and its cascading local metadata.
    ///
    /// Returns `true` when a project row was removed and `false` when it was
    /// already absent.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the delete.
    pub fn delete_project(&self, id: &str) -> Result<bool, StoreError> {
        // An explicit savepoint preserves the shared-reference API and permits nesting.
        self.connection.execute_batch("SAVEPOINT locket_delete_project")?;
        let result = (|| {
            // Pending profile rows cascade from their package. Other sync rows
            // are project-owned, including those without a foreign key.
            for sql in [
                "DELETE FROM team_sync_pending_packages WHERE project_id = ?1",
                "DELETE FROM team_sync_anchors WHERE project_id = ?1",
                "DELETE FROM team_sync_join_checkpoints WHERE project_id = ?1",
                "DELETE FROM team_sync_heads WHERE project_id = ?1",
                "DELETE FROM team_sync_seen WHERE project_id = ?1",
                "DELETE FROM team_sync_values WHERE project_id = ?1",
                "DELETE FROM team_sync_profile_epochs WHERE project_id = ?1",
                "DELETE FROM team_sync_conflicts WHERE project_id = ?1",
                "DELETE FROM team_sync_folders WHERE project_id = ?1",
                "DELETE FROM team_sync_outbound WHERE project_id = ?1",
                "DELETE FROM team_sync_outbox WHERE project_id = ?1",
                "DELETE FROM team_sync_publications WHERE project_id = ?1",
            ] {
                self.connection.execute(sql, [id])?;
            }
            let deleted = self.connection.execute("DELETE FROM projects WHERE id = ?1", [id])?;
            self.connection.execute_batch("RELEASE locket_delete_project")?;
            Ok(deleted != 0)
        })();
        if result.is_err() {
            self.connection.execute_batch(
                "ROLLBACK TO locket_delete_project; RELEASE locket_delete_project",
            )?;
        }
        result
    }
}
