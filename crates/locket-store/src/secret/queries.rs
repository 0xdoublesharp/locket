//! Read-only secret queries.

use rusqlite::{OptionalExtension, params};

use crate::Store;
use crate::error::StoreError;
use crate::secret::{
    SecretBlobRecord, SecretMetadataRecord, SecretMutableMetadata, SecretRecord,
    SecretVersionMetadataRecord, SecretVersionRecord, mutable_metadata_from_row,
    secret_blob_record_from_row, secret_metadata_record_from_row, secret_record_from_row,
    secret_version_metadata_record_from_row, secret_version_record_from_row,
};

impl Store {
    /// Returns mutable metadata by secret id, including for deleted secrets.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the row cannot be queried or its tags cannot be decoded.
    pub fn get_secret_mutable_metadata(
        &self,
        secret_id: &str,
    ) -> Result<Option<SecretMutableMetadata>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT description, owner, tags_json, required FROM secrets WHERE id = ?1",
        )?;
        let mut rows = statement.query([secret_id])?;
        rows.next()?.map(|row| mutable_metadata_from_row(row, 0)).transpose()
    }

    /// Returns an active secret by project/profile/name/source.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the secret row.
    pub fn get_active_secret(
        &self,
        project_id: &str,
        profile_id: &str,
        name: &str,
        source: &str,
    ) -> Result<Option<SecretRecord>, StoreError> {
        self.connection
            .prepare_cached(
                "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                        created_at, updated_at, last_rotated_at, deleted_at
                 FROM secrets
                 WHERE project_id = ?1
                   AND profile_id = ?2
                   AND name = ?3
                   AND source = ?4
                   AND state = 'active'",
            )?
            .query_row((project_id, profile_id, name, source), secret_record_from_row)
            .optional()
            .map_err(StoreError::from)
    }

    /// Returns a secret by project/profile/name/source regardless of active or deleted state.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the secret row.
    pub fn get_secret_by_source(
        &self,
        project_id: &str,
        profile_id: &str,
        name: &str,
        source: &str,
    ) -> Result<Option<SecretRecord>, StoreError> {
        self.connection
            .prepare_cached(
                "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                        created_at, updated_at, last_rotated_at, deleted_at
                 FROM secrets
                 WHERE project_id = ?1
                   AND profile_id = ?2
                   AND name = ?3
                   AND source = ?4",
            )?
            .query_row((project_id, profile_id, name, source), secret_record_from_row)
            .optional()
            .map_err(StoreError::from)
    }

    /// Lists secrets for a project/profile/name across all sources and states.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query secret rows.
    pub fn list_secrets_by_name(
        &self,
        project_id: &str,
        profile_id: &str,
        name: &str,
    ) -> Result<Vec<SecretRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                    created_at, updated_at, last_rotated_at, deleted_at
             FROM secrets
             WHERE project_id = ?1 AND profile_id = ?2 AND name = ?3
             ORDER BY name, source",
        )?;
        let secrets = statement
            .query_map((project_id, profile_id, name), secret_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(secrets)
    }

    /// Lists active secrets for a profile ordered by name and source.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query secret rows.
    pub fn list_active_secrets_by_profile(
        &self,
        project_id: &str,
        profile_id: &str,
    ) -> Result<Vec<SecretRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                    created_at, updated_at, last_rotated_at, deleted_at
             FROM secrets
             WHERE project_id = ?1 AND profile_id = ?2 AND state = 'active'
             ORDER BY name, source",
        )?;
        let secrets = statement
            .query_map((project_id, profile_id), secret_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(secrets)
    }

    /// Lists active secret metadata for a profile ordered by logical name and source precedence.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query secret rows.
    pub fn list_active_secret_metadata_by_profile(
        &self,
        project_id: &str,
        profile_id: &str,
    ) -> Result<Vec<SecretMetadataRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT id, project_id, profile_id, name, source,
                    CASE source
                      WHEN 'machine-local' THEN 3
                      WHEN 'user-local' THEN 2
                      WHEN 'team-managed' THEN 1
                      ELSE 0
                    END AS source_precedence,
                    origin, current_version, state, required, created_at, updated_at,
                    last_rotated_at
             FROM secrets
             WHERE project_id = ?1 AND profile_id = ?2 AND state = 'active'
             ORDER BY name,
                      source_precedence DESC,
                      source",
        )?;
        let secrets = statement
            .query_map((project_id, profile_id), secret_metadata_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(secrets)
    }

    /// Lists all secrets for a profile ordered by name and source.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query secret rows.
    pub fn list_secrets_by_profile(
        &self,
        project_id: &str,
        profile_id: &str,
    ) -> Result<Vec<SecretRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                    created_at, updated_at, last_rotated_at, deleted_at
             FROM secrets
             WHERE project_id = ?1 AND profile_id = ?2
             ORDER BY name, source",
        )?;
        let secrets = statement
            .query_map((project_id, profile_id), secret_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(secrets)
    }

    /// Lists version metadata for a secret ordered by version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query version rows.
    pub fn list_secret_versions(
        &self,
        secret_id: &str,
    ) -> Result<Vec<SecretVersionRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT secret_id, version, source, origin, state, created_at,
                    deprecated_at, grace_until, purged_at
             FROM secret_versions
             WHERE secret_id = ?1
             ORDER BY version",
        )?;
        let versions = statement
            .query_map([secret_id], secret_version_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(versions)
    }

    /// Lists all version metadata for a profile joined to parent secret metadata.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query version rows.
    pub fn list_secret_version_metadata_by_profile(
        &self,
        project_id: &str,
        profile_id: &str,
    ) -> Result<Vec<SecretVersionMetadataRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT s.id, s.project_id, s.profile_id, s.name, s.source,
                    CASE s.source
                      WHEN 'machine-local' THEN 3
                      WHEN 'user-local' THEN 2
                      WHEN 'team-managed' THEN 1
                      ELSE 0
                    END AS source_precedence,
                    s.origin, s.state, s.current_version, s.last_rotated_at,
                    v.version, v.state, v.created_at, v.deprecated_at, v.grace_until, v.purged_at
             FROM secrets s
             JOIN secret_versions v ON v.secret_id = s.id
             WHERE s.project_id = ?1 AND s.profile_id = ?2
             ORDER BY s.name,
                      source_precedence DESC,
                      s.source,
                      v.version DESC",
        )?;
        let versions = statement
            .query_map((project_id, profile_id), secret_version_metadata_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(versions)
    }

    /// Returns version metadata for a secret version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the version row.
    pub fn get_secret_version(
        &self,
        secret_id: &str,
        version: u32,
    ) -> Result<Option<SecretVersionRecord>, StoreError> {
        self.connection
            .prepare_cached(
                "SELECT secret_id, version, source, origin, state, created_at,
                        deprecated_at, grace_until, purged_at
                 FROM secret_versions
                 WHERE secret_id = ?1 AND version = ?2",
            )?
            .query_row(params![secret_id, version], secret_version_record_from_row)
            .optional()
            .map_err(StoreError::from)
    }

    /// Returns an encrypted blob by secret id and version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the blob row.
    pub fn get_blob(
        &self,
        secret_id: &str,
        version: u32,
    ) -> Result<Option<SecretBlobRecord>, StoreError> {
        self.connection
            .prepare_cached(
                "SELECT secret_id, version, encrypted_dek, ciphertext, value_nonce,
                        aad_schema_version, created_at
                 FROM blobs
                 WHERE secret_id = ?1 AND version = ?2",
            )?
            .query_row(params![secret_id, version], secret_blob_record_from_row)
            .optional()
            .map_err(StoreError::from)
    }
}
