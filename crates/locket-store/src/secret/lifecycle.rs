//! Secret create / rotate / copy / purge / tombstone lifecycle methods.

use locket_core::canonical_json_string;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

use crate::Store;
use crate::audit::{AuditContext, append_optional_audit};
use crate::error::StoreError;
use crate::secret::{
    SecretBlobRecord, SecretCopyTarget, SecretFingerprintRecord, SecretInitialMetadata,
    SecretMetadataUpdate, SecretRecord, SecretVersionRecord, VersionDeprecation,
};

fn advance_secret_current_version(
    transaction: &Connection,
    secret: &SecretRecord,
    new_version: &SecretVersionRecord,
) -> Result<(), StoreError> {
    let updated = transaction.execute(
        "UPDATE secrets
         SET current_version = ?2, updated_at = ?3, last_rotated_at = ?3
         WHERE id = ?1 AND state = 'active' AND current_version = ?4",
        params![
            secret.id.as_str(),
            new_version.version,
            new_version.created_at,
            secret.current_version,
        ],
    )?;
    if updated != 1 {
        return Err(StoreError::SecretStateConflict {
            secret_id: secret.id.clone(),
            expected_version: secret.current_version,
        });
    }
    Ok(())
}

impl Store {
    /// Creates a secret, its initial version, encrypted blob, and keyed fingerprint atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects any insert. The
    /// transaction is rolled back when any row fails to insert.
    pub fn create_active_secret(
        &mut self,
        secret: &SecretRecord,
        version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
    ) -> Result<(), StoreError> {
        self.create_active_secret_with_audit(secret, version, blob, fingerprint, None)
    }

    /// Creates a secret and optionally appends the matching audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn create_active_secret_with_audit(
        &mut self,
        secret: &SecretRecord,
        version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        self.create_active_secret_with_metadata_and_audit(
            secret,
            version,
            blob,
            fingerprint,
            SecretInitialMetadata::default(),
            audit,
        )
    }

    /// Creates a secret, its initial metadata and version, and any audit row atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when metadata encoding, a database write, or the audit append fails.
    pub fn create_active_secret_with_metadata_and_audit(
        &mut self,
        secret: &SecretRecord,
        version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        metadata: SecretInitialMetadata<'_>,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let tags_json = serde_json::to_string(metadata.tags)?;
        let transaction = self.connection.savepoint()?;
        transaction.execute(
            "INSERT INTO secrets(
               id, project_id, profile_id, name, source, origin, current_version, state,
               created_at, updated_at, last_rotated_at, deleted_at,
               description, owner, tags_json, required
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                secret.id.as_str(),
                secret.project_id.as_str(),
                secret.profile_id.as_str(),
                secret.name.as_str(),
                secret.source.as_str(),
                secret.origin.as_str(),
                secret.current_version,
                secret.state.as_str(),
                secret.created_at,
                secret.updated_at,
                secret.last_rotated_at,
                secret.deleted_at,
                metadata.description,
                metadata.owner,
                tags_json,
                metadata.required,
            ],
        )?;
        transaction.execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                version.secret_id.as_str(),
                version.version,
                version.source.as_str(),
                version.origin.as_str(),
                version.state.as_str(),
                version.created_at,
                version.deprecated_at,
                version.grace_until,
                version.purged_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO blobs(
               secret_id, version, encrypted_dek, ciphertext, value_nonce,
               aad_schema_version, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                blob.secret_id.as_str(),
                blob.version,
                blob.encrypted_dek.as_slice(),
                blob.ciphertext.as_slice(),
                blob.value_nonce.as_slice(),
                blob.aad_schema_version,
                blob.created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO fingerprints(secret_id, version, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                fingerprint.secret_id.as_str(),
                fingerprint.version,
                fingerprint.fingerprint.as_slice(),
                fingerprint.created_at,
            ],
        )?;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Updates mutable metadata fields on an active secret without changing secret material.
    ///
    /// `None` keeps the existing field. `tags` replaces the whole tag list when
    /// present.
    ///
    /// Returns `true` when an active secret row was updated and `false` when no
    /// matching active secret exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn update_secret_metadata(
        &self,
        secret_id: &str,
        description: Option<&str>,
        owner: Option<&str>,
        tags: Option<&[String]>,
        required: Option<bool>,
    ) -> Result<bool, StoreError> {
        self.update_secret_metadata_with_options(
            secret_id,
            SecretMetadataUpdate {
                description,
                owner,
                tags,
                required,
                updated_at: None,
                audit: None,
            },
        )
    }

    /// Updates mutable secret metadata and optionally records a metadata-only audit row atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects the update or audit canonicalization fails.
    pub fn update_secret_metadata_with_options(
        &self,
        secret_id: &str,
        update: SecretMetadataUpdate<'_>,
    ) -> Result<bool, StoreError> {
        let tags_json = update.tags.map(|tags| {
            let tags = tags.iter().map(|tag| Value::String(tag.clone())).collect::<Vec<_>>();
            canonical_json_string(Some(&Value::Array(tags)))
        });
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE secrets
             SET description = COALESCE(?2, description),
                 owner = COALESCE(?3, owner),
                 tags_json = COALESCE(?4, tags_json),
                 required = COALESCE(?5, required),
                 updated_at = COALESCE(?6, updated_at)
             WHERE id = ?1 AND state = 'active'",
            params![
                secret_id,
                update.description,
                update.owner,
                tags_json.as_deref(),
                update.required,
                update.updated_at,
            ],
        )?;
        let changed = transaction.changes() == 1;
        if changed {
            append_optional_audit(&transaction, update.audit)?;
        }
        transaction.commit()?;

        Ok(changed)
    }

    /// Rotates a secret by deprecating the current version and inserting the new current version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SecretStateConflict`] when the secret changed since it was read,
    /// or [`StoreError::Sqlite`] when an update or insert fails. Errors roll back the transaction.
    pub fn rotate_secret(
        &mut self,
        secret: &SecretRecord,
        new_version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        deprecated_at: i64,
        grace_until: Option<i64>,
    ) -> Result<(), StoreError> {
        self.rotate_secret_with_audit(
            secret,
            new_version,
            blob,
            fingerprint,
            VersionDeprecation { deprecated_at, grace_until },
            None,
        )
    }

    /// Rotates a secret and optionally appends the matching audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SecretStateConflict`] when the stored active/current state
    /// no longer matches `secret`, or another [`StoreError`] when a row or audit append fails.
    pub fn rotate_secret_with_audit(
        &mut self,
        secret: &SecretRecord,
        new_version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        deprecation: VersionDeprecation,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        self.rotate_secret_with_metadata_and_audit(
            secret,
            new_version,
            blob,
            fingerprint,
            deprecation,
            None,
            audit,
        )
    }

    /// Rotates a secret, optionally replacing its mutable metadata and appending an audit row.
    ///
    /// When supplied, `metadata` replaces the full set of mutable fields. Passing
    /// `None` preserves them. All writes share the rotation savepoint.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SecretStateConflict`] when the stored active/current state
    /// has changed, or another [`StoreError`] when metadata encoding, a write, or the audit fails.
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_secret_with_metadata_and_audit(
        &mut self,
        secret: &SecretRecord,
        new_version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        deprecation: VersionDeprecation,
        metadata: Option<SecretInitialMetadata<'_>>,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.savepoint()?;
        let deprecated = transaction.execute(
            "UPDATE secret_versions
             SET state = 'deprecated', deprecated_at = ?3, grace_until = ?4
             WHERE secret_id = ?1 AND version = ?2 AND state = 'current'",
            params![
                secret.id.as_str(),
                secret.current_version,
                deprecation.deprecated_at,
                deprecation.grace_until,
            ],
        )?;
        if deprecated != 1 {
            return Err(StoreError::SecretStateConflict {
                secret_id: secret.id.clone(),
                expected_version: secret.current_version,
            });
        }
        transaction.execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                new_version.secret_id.as_str(),
                new_version.version,
                new_version.source.as_str(),
                new_version.origin.as_str(),
                new_version.state.as_str(),
                new_version.created_at,
                new_version.deprecated_at,
                new_version.grace_until,
                new_version.purged_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO blobs(
               secret_id, version, encrypted_dek, ciphertext, value_nonce,
               aad_schema_version, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                blob.secret_id.as_str(),
                blob.version,
                blob.encrypted_dek.as_slice(),
                blob.ciphertext.as_slice(),
                blob.value_nonce.as_slice(),
                blob.aad_schema_version,
                blob.created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO fingerprints(secret_id, version, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                fingerprint.secret_id.as_str(),
                fingerprint.version,
                fingerprint.fingerprint.as_slice(),
                fingerprint.created_at,
            ],
        )?;
        advance_secret_current_version(&transaction, secret, new_version)?;
        if let Some(metadata) = metadata {
            let tags_json = serde_json::to_string(metadata.tags)?;
            transaction.execute(
                "UPDATE secrets SET description = ?2, owner = ?3, tags_json = ?4, required = ?5
                 WHERE id = ?1",
                params![
                    secret.id,
                    metadata.description,
                    metadata.owner,
                    tags_json,
                    metadata.required
                ],
            )?;
        }
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Copies secret material into a target source by creating or rotating it.
    ///
    /// The copied plaintext is supplied only as already-encrypted target material. The secret
    /// lifecycle update and optional `SECRET_COPY` audit append happen in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SecretStateConflict`] when a rotation target's stored active/current
    /// state changed, or another [`StoreError`] when a row or audit append fails.
    pub fn copy_secret_with_audit(
        &mut self,
        target: SecretCopyTarget<'_>,
        new_version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.savepoint()?;
        match target {
            SecretCopyTarget::Create(secret) => {
                transaction.execute(
                    "INSERT INTO secrets(
                       id, project_id, profile_id, name, source, origin, required,
                       current_version, state, created_at, updated_at, last_rotated_at, deleted_at
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        secret.id.as_str(),
                        secret.project_id.as_str(),
                        secret.profile_id.as_str(),
                        secret.name.as_str(),
                        secret.source.as_str(),
                        secret.origin.as_str(),
                        secret.current_version,
                        secret.state.as_str(),
                        secret.created_at,
                        secret.updated_at,
                        secret.last_rotated_at,
                        secret.deleted_at,
                    ],
                )?;
            }
            SecretCopyTarget::Rotate { secret, deprecation } => {
                let deprecated = transaction.execute(
                    "UPDATE secret_versions
                     SET state = 'deprecated', deprecated_at = ?3, grace_until = ?4
                     WHERE secret_id = ?1 AND version = ?2 AND state = 'current'",
                    params![
                        secret.id.as_str(),
                        secret.current_version,
                        deprecation.deprecated_at,
                        deprecation.grace_until,
                    ],
                )?;
                if deprecated != 1 {
                    return Err(StoreError::SecretStateConflict {
                        secret_id: secret.id.clone(),
                        expected_version: secret.current_version,
                    });
                }
            }
        }
        transaction.execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                new_version.secret_id.as_str(),
                new_version.version,
                new_version.source.as_str(),
                new_version.origin.as_str(),
                new_version.state.as_str(),
                new_version.created_at,
                new_version.deprecated_at,
                new_version.grace_until,
                new_version.purged_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO blobs(
               secret_id, version, encrypted_dek, ciphertext, value_nonce,
               aad_schema_version, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                blob.secret_id.as_str(),
                blob.version,
                blob.encrypted_dek.as_slice(),
                blob.ciphertext.as_slice(),
                blob.value_nonce.as_slice(),
                blob.aad_schema_version,
                blob.created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO fingerprints(secret_id, version, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                fingerprint.secret_id.as_str(),
                fingerprint.version,
                fingerprint.fingerprint.as_slice(),
                fingerprint.created_at,
            ],
        )?;
        if let SecretCopyTarget::Rotate { secret, .. } = target {
            advance_secret_current_version(&transaction, secret, new_version)?;
        }
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Purges encrypted material and fingerprints for one version.
    ///
    /// Returns `true` when material was newly purged and `false` when the
    /// version was already purged.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ActiveSecretVersionPurge`] for an active current
    /// version, or [`StoreError::Sqlite`] when `SQLite` rejects the updates.
    pub fn purge_secret_version(
        &mut self,
        secret_id: &str,
        version: u32,
        purged_at: i64,
    ) -> Result<bool, StoreError> {
        self.purge_secret_versions(secret_id, &[version], purged_at)
    }

    /// Purges encrypted material and fingerprints for multiple versions atomically.
    ///
    /// Returns `true` when at least one version was newly purged and `false`
    /// when all selected versions were already purged.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ActiveSecretVersionPurge`] for an active current
    /// version, or [`StoreError::Sqlite`] when `SQLite` rejects the updates.
    pub fn purge_secret_versions(
        &mut self,
        secret_id: &str,
        versions: &[u32],
        purged_at: i64,
    ) -> Result<bool, StoreError> {
        self.purge_secret_versions_with_audit(secret_id, versions, purged_at, None)
    }

    /// Purges versions and optionally appends a `PURGE` audit row when material changed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::ActiveSecretVersionPurge`] if the selection
    /// includes the current version of an active secret.
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn purge_secret_versions_with_audit(
        &mut self,
        secret_id: &str,
        versions: &[u32],
        purged_at: i64,
        audit: Option<AuditContext<'_>>,
    ) -> Result<bool, StoreError> {
        if versions.is_empty() {
            return Ok(false);
        }
        let transaction = self.connection.savepoint()?;
        let active_current = transaction
            .query_row(
                "SELECT current_version FROM secrets WHERE id = ?1 AND state = 'active'",
                [secret_id],
                |row| row.get::<_, u32>(0),
            )
            .optional()?;
        if let Some(version) = active_current
            && versions.contains(&version)
        {
            return Err(StoreError::ActiveSecretVersionPurge {
                secret_id: secret_id.to_owned(),
                version,
            });
        }
        let mut changed_any = false;
        for version in versions {
            let changed = transaction.execute(
                "UPDATE secret_versions
                 SET state = 'purged', grace_until = NULL, purged_at = ?3
                 WHERE secret_id = ?1 AND version = ?2 AND state != 'purged'",
                params![secret_id, version, purged_at],
            )?;
            if changed == 0 {
                continue;
            }
            changed_any = true;
            transaction.execute(
                "DELETE FROM blobs WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
            )?;
            transaction.execute(
                "DELETE FROM fingerprints WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
            )?;
            transaction.execute(
                "DELETE FROM local_value_fingerprints WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
            )?;
        }
        if !changed_any {
            transaction.commit()?;
            return Ok(false);
        }
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(true)
    }

    /// Tombstones a secret by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn tombstone_secret(&self, id: &str, deleted_at: i64) -> Result<(), StoreError> {
        self.tombstone_secret_with_audit(id, deleted_at, None)
    }

    /// Tombstones a secret and optionally appends the matching audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn tombstone_secret_with_audit(
        &self,
        id: &str,
        deleted_at: i64,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        tombstone(&transaction, id, deleted_at, None, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Tombstones the selected active version and appends its audit row atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SecretStateConflict`] if the secret is no longer active
    /// at the selected version, or another [`StoreError`] on write failure.
    pub fn tombstone_current_secret_with_audit(
        &mut self,
        secret: &SecretRecord,
        deleted_at: i64,
        audit: AuditContext<'_>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.savepoint()?;
        tombstone(&transaction, &secret.id, deleted_at, Some(secret.current_version), Some(audit))?;
        transaction.commit()?;
        Ok(())
    }
}

fn tombstone(
    transaction: &Connection,
    id: &str,
    deleted_at: i64,
    expected_version: Option<u32>,
    audit: Option<AuditContext<'_>>,
) -> Result<(), StoreError> {
    let updated = transaction.execute(
        "UPDATE secrets
         SET state = 'deleted', deleted_at = ?2, updated_at = ?2
         WHERE id = ?1 AND (?3 IS NULL OR (state = 'active' AND current_version = ?3))",
        (id, deleted_at, expected_version),
    )?;
    if let Some(expected_version) = expected_version
        && updated != 1
    {
        return Err(StoreError::SecretStateConflict { secret_id: id.to_owned(), expected_version });
    }
    append_optional_audit(transaction, audit)
}
