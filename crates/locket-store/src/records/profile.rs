//! Profile metadata records and `Store` profile operations.

use rusqlite::OptionalExtension;
use serde_json::json;

use crate::Store;
use crate::audit::{AuditWrite, append_audit};
use crate::error::StoreError;

/// Metadata for a stored profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRecord {
    /// Profile identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Human-readable profile name.
    pub name: String,
    /// Whether the profile is marked dangerous.
    pub dangerous: bool,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

/// Audit context for an atomic dangerous-profile marker change.
#[derive(Clone, Copy, Debug)]
pub struct ProfileDangerousAudit<'a> {
    /// Unwrapped project audit key.
    pub audit_key: &'a [u8],
    /// Event timestamp in nanoseconds since the Unix epoch.
    pub timestamp: i64,
    /// Command or surface that initiated the change.
    pub command: &'a str,
}

/// Result of an atomic dangerous-profile marker change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileDangerousChange {
    /// Profile metadata before the update.
    pub profile: ProfileRecord,
    /// Previous dangerous marker.
    pub prior_dangerous: bool,
    /// New dangerous marker.
    pub new_dangerous: bool,
}

pub fn profile_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProfileRecord> {
    Ok(ProfileRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        name: row.get(2)?,
        dangerous: row.get(3)?,
        created_at: row.get(4)?,
    })
}

impl Store {
    /// Inserts a profile metadata row when `id` and `(project_id, name)` are absent.
    ///
    /// Returns `true` when the profile was inserted and `false` when either the
    /// profile id or the project-scoped profile name already existed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert, including
    /// when `project_id` does not reference an existing project.
    pub fn insert_profile_if_absent(
        &self,
        id: &str,
        project_id: &str,
        name: &str,
        dangerous: bool,
        created_at: i64,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO profiles(id, project_id, name, dangerous, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (id, project_id, name, dangerous, created_at),
        )?;

        Ok(self.connection.changes() == 1)
    }

    /// Lists project profile metadata ordered by profile name.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query profile rows.
    pub fn list_profiles(&self, project_id: &str) -> Result<Vec<ProfileRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT id, project_id, name, dangerous, created_at
             FROM profiles
             WHERE project_id = ?1
             ORDER BY name",
        )?;
        let profiles = statement
            .query_map([project_id], profile_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(profiles)
    }

    /// Returns profile metadata by project id and profile name.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the profile row.
    pub fn get_profile_by_name(
        &self,
        project_id: &str,
        name: &str,
    ) -> Result<Option<ProfileRecord>, StoreError> {
        self.connection
            .prepare_cached(
                "SELECT id, project_id, name, dangerous, created_at
                 FROM profiles
                 WHERE project_id = ?1 AND name = ?2",
            )?
            .query_row((project_id, name), profile_record_from_row)
            .optional()
            .map_err(StoreError::from)
    }

    /// Updates the dangerous marker for a profile by project id and profile name.
    ///
    /// Returns `true` when a profile row was updated and `false` when no matching
    /// profile exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn set_profile_dangerous(
        &self,
        project_id: &str,
        name: &str,
        dangerous: bool,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "UPDATE profiles
             SET dangerous = ?3
             WHERE project_id = ?1 AND name = ?2",
            (project_id, name, dangerous),
        )?;

        Ok(self.connection.changes() == 1)
    }

    /// Updates a profile dangerous marker and appends the corresponding audit row in one tx.
    ///
    /// Returns `None` when the profile is absent.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the profile cannot be read, updated, or audited.
    pub fn set_profile_dangerous_with_audit(
        &mut self,
        project_id: &str,
        name: &str,
        dangerous: bool,
        audit: ProfileDangerousAudit<'_>,
    ) -> Result<Option<ProfileDangerousChange>, StoreError> {
        let transaction = self.connection.transaction()?;
        let Some(profile) = transaction
            .prepare_cached(
                "SELECT id, project_id, name, dangerous, created_at
                 FROM profiles
                 WHERE project_id = ?1 AND name = ?2",
            )?
            .query_row((project_id, name), profile_record_from_row)
            .optional()?
        else {
            transaction.commit()?;
            return Ok(None);
        };
        transaction.execute(
            "UPDATE profiles
             SET dangerous = ?3
             WHERE project_id = ?1 AND name = ?2",
            (project_id, name, dangerous),
        )?;
        let metadata = json!({
            "schema_version": 1,
            "action": "PROFILE_CHANGE",
            "status": "SUCCESS",
            "command": audit.command,
            "operation": "set_dangerous",
            "profile_id": profile.id,
            "profile_name": profile.name,
            "prior_dangerous": profile.dangerous,
            "new_dangerous": dangerous,
        });
        let write = AuditWrite {
            project_id,
            profile_id: Some(profile.id.as_str()),
            action: "PROFILE_CHANGE",
            status: "SUCCESS",
            secret_name: None,
            command: Some(audit.command),
            metadata_json: &metadata,
            timestamp: audit.timestamp,
        };
        append_audit(&transaction, audit.audit_key, &write)?;
        transaction.commit()?;
        Ok(Some(ProfileDangerousChange {
            prior_dangerous: profile.dangerous,
            new_dangerous: dangerous,
            profile,
        }))
    }
}

/// Renames an empty local profile inside the caller's import transaction.
///
/// Keeps its identity, wrapped keys, audit references, grants and sessions intact.
/// Returns `None` when the profile is absent or contains any secret rows.
///
/// # Errors
/// Returns a storage error if names or profile metadata cannot be read or updated.
pub fn archive_empty_profile_for_import(
    connection: &rusqlite::Connection,
    project_id: &str,
    profile_id: &str,
) -> Result<Option<String>, StoreError> {
    use sha2::{Digest, Sha256};
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let original: Option<String> = connection
        .prepare_cached(
            "SELECT name FROM profiles WHERE project_id=?1 AND id=?2
             AND NOT EXISTS (SELECT 1 FROM secrets WHERE profile_id=?2)",
        )?
        .query_row((project_id, profile_id), |row| row.get(0))
        .optional()?;
    let Some(original) = original else {
        return Ok(None);
    };
    let prefix: String = original
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'))
        .collect();
    let prefix = if prefix.as_bytes().first().is_some_and(u8::is_ascii_lowercase) {
        prefix
    } else {
        "profile".into()
    };
    let digest = Sha256::digest(profile_id.as_bytes());
    let short_id: String = digest[..6]
        .iter()
        .flat_map(|byte| {
            [char::from(HEX[usize::from(byte >> 4)]), char::from(HEX[usize::from(byte & 15)])]
        })
        .collect();
    let mut name_exists = connection
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM profiles WHERE project_id=?1 AND name=?2)")?;
    for attempt in 0_u64.. {
        let suffix = if attempt == 0 {
            format!("-local-{short_id}")
        } else {
            format!("-local-{short_id}-{attempt}")
        };
        let prefix_len = prefix.len().min(64 - suffix.len());
        let archived = format!("{}{suffix}", &prefix[..prefix_len]);
        let exists: bool = name_exists.query_row((project_id, &archived), |row| row.get(0))?;
        if !exists {
            connection.execute(
                "UPDATE profiles SET name=?3 WHERE project_id=?1 AND id=?2",
                (project_id, profile_id, &archived),
            )?;
            return Ok(Some(archived));
        }
    }
    unreachable!("finite database cannot exhaust archival names")
}

#[cfg(test)]
mod import_archive_tests {
    use super::*;
    #[test]
    fn archival_names_are_valid_unique_and_roll_back_with_import()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut store = Store::open(directory.path().join("store.db"))?;
        store.initialize_schema()?;
        store.insert_project_if_absent("project", "project", 1)?;
        let long_name = "a".repeat(64);
        store.insert_profile_if_absent("local", "project", &long_name, true, 1)?;
        let first = {
            let transaction = store.connection_mut().transaction()?;
            archive_empty_profile_for_import(&transaction, "project", "local")?
                .ok_or("archival rename")?
        };
        assert_eq!(
            store.get_profile_by_name("project", &long_name)?.ok_or("rolled back")?.id,
            "local"
        );
        locket_core::ProfileName::new(first.clone())?;
        store.insert_profile_if_absent("occupied", "project", &first, false, 1)?;
        let next = archive_empty_profile_for_import(store.connection(), "project", "local")?
            .ok_or("archival rename")?;
        assert_ne!(first, next);
        locket_core::ProfileName::new(next.clone())?;
        let profile = store.get_profile_by_name("project", &next)?.ok_or("archived")?;
        assert_eq!(profile.id, "local");
        assert!(profile.dangerous);
        Ok(())
    }
    #[test]
    fn populated_profiles_are_never_archived_even_when_deleted()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut store = Store::open(directory.path().join("store.db"))?;
        store.initialize_schema()?;
        store.insert_project_if_absent("project", "project", 1)?;
        store.insert_profile_if_absent("local", "project", "dev", false, 1)?;
        store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at,deleted_at) VALUES ('secret','project','local','TOKEN','machine-local','manual',0,1,'deleted',1,1,1)", [])?;
        assert!(
            archive_empty_profile_for_import(store.connection(), "project", "local")?.is_none()
        );
        assert_eq!(
            store.get_profile_by_name("project", "dev")?.ok_or("profile retained")?.id,
            "local"
        );
        Ok(())
    }
}
