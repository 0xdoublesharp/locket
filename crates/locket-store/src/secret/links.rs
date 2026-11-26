//! Shared secret links and local-only keyed value deduplication records.

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::audit::{AuditContext, AuditWrite, append_optional_audit};
use crate::error::StoreError;
use crate::secret::{SecretRecord, secret_record_from_row};
use crate::{ProfileRecord, Store};

/// Local pointer binding a project variable name to a Global Vault (`@shared`) secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretLinkRecord {
    /// Opaque link identifier (`lk_link_*`).
    pub id: String,
    /// Consuming project identifier.
    pub project_id: String,
    /// Consuming profile identifier.
    pub profile_id: String,
    /// Environment variable name exposed in the consuming project.
    pub local_name: String,
    /// Target Global Vault project identifier.
    pub target_project_id: String,
    /// Target Global Vault profile identifier.
    pub target_profile_id: String,
    /// Target Global Vault secret identifier.
    pub target_secret_id: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
}

/// Active link paired with its active Global Vault target secret row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSecretLink {
    /// Stored link row.
    pub link: SecretLinkRecord,
    /// Active target secret in `@shared`.
    pub target_secret: SecretRecord,
}

/// Reverse-lookup consumer row describing a project using a `@shared` secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedSecretUsageRecord {
    /// Opaque link identifier.
    pub link_id: String,
    /// Consuming project identifier.
    pub project_id: String,
    /// Consuming project display name.
    pub project_name: String,
    /// Consuming profile identifier.
    pub profile_id: String,
    /// Consuming profile name.
    pub profile_name: String,
    /// Whether the consuming profile is marked dangerous.
    pub profile_dangerous: bool,
    /// Environment variable name bound in the consuming project.
    pub local_name: String,
    /// Target Global Vault secret identifier.
    pub target_secret_id: String,
    /// Target Global Vault secret name.
    pub target_secret_name: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
}

impl SharedSecretUsageRecord {
    /// Canonical metadata for a consumer's authenticated cascade unlink entry.
    #[must_use]
    pub fn unlink_audit_metadata(&self, target: &SecretRecord) -> Value {
        json!({
            "schema_version": 1,
            "action": "SECRET_UNLINK",
            "status": "SUCCESS",
            "secret_name": self.local_name,
            "profile_id": self.profile_id,
            "target_project_id": target.project_id,
            "target_profile_id": target.profile_id,
            "target_secret_id": self.target_secret_id,
            "target_secret_name": self.target_secret_name,
        })
    }

    /// Audit row for the consumer's project and profile.
    #[must_use]
    pub fn unlink_audit<'a>(&'a self, metadata: &'a Value, timestamp: i64) -> AuditWrite<'a> {
        AuditWrite {
            project_id: &self.project_id,
            profile_id: Some(&self.profile_id),
            action: "SECRET_UNLINK",
            status: "SUCCESS",
            secret_name: Some(&self.local_name),
            command: None,
            metadata_json: metadata,
            timestamp,
        }
    }
}

/// Metadata for an audited cross-profile copy or promotion.
pub struct SecretTransferAudit<'a> {
    /// `SECRET_COPY` or `SECRET_PROMOTE`.
    pub action: &'static str,
    /// Whether the target was created, rotated, or reused.
    pub operation: &'static str,
    /// Source project ID.
    pub from_project_id: &'a str,
    /// Source profile ID.
    pub from_profile_id: &'a str,
    /// Source secret, when the value came from the store.
    pub from_secret: Option<&'a SecretRecord>,
    /// Destination profile.
    pub target_profile: &'a ProfileRecord,
    /// Destination name, which can differ from the source name.
    pub target_name: &'a str,
    /// Previous destination version, if any.
    pub prior_target_version: Option<u32>,
    /// Current destination version after the transfer.
    pub target_version: u32,
    /// Timestamp in nanoseconds since the Unix epoch.
    pub timestamp: i64,
}

impl SecretTransferAudit<'_> {
    /// Append the same transfer metadata to the source and destination project chains.
    ///
    /// # Errors
    ///
    /// Returns a storage or audit error if either append fails. Neither row is committed on failure.
    pub fn append(
        &self,
        store: &mut Store,
        source_key: &[u8],
        target_key: &[u8],
    ) -> Result<(), StoreError> {
        let metadata = json!({
            "schema_version": 1, "action": self.action, "status": "SUCCESS",
            "operation": self.operation, "secret_name": self.target_name,
            "from_project_id": self.from_project_id, "from_profile_id": self.from_profile_id,
            "from_source": self.from_secret.map(|secret| &secret.source),
            "from_version": self.from_secret.map(|secret| secret.current_version),
            "to_project_id": self.target_profile.project_id, "to_profile_id": self.target_profile.id,
            "to_source": "user-local", "prior_target_version": self.prior_target_version,
            "target_version": self.target_version,
        });
        let target_write = AuditWrite {
            project_id: &self.target_profile.project_id,
            profile_id: Some(&self.target_profile.id),
            action: self.action,
            status: "SUCCESS",
            secret_name: Some(self.target_name),
            command: None,
            metadata_json: &metadata,
            timestamp: self.timestamp,
        };
        store.with_atomic_write(|store| {
            store.append_audit(target_key, &target_write)?;
            if self.from_project_id != self.target_profile.project_id {
                store.append_audit(
                    source_key,
                    &AuditWrite {
                        project_id: self.from_project_id,
                        profile_id: Some(self.from_profile_id),
                        ..target_write
                    },
                )?;
            }
            Ok(())
        })
    }
}

/// One active secret participating in a cross-project duplicate value group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicateSecretMemberRecord {
    /// Secret identifier.
    pub secret_id: String,
    /// Project identifier.
    pub project_id: String,
    /// Project display name.
    pub project_name: String,
    /// Whether the project is a Global Vault (`@shared`).
    pub is_shared: bool,
    /// Profile identifier.
    pub profile_id: String,
    /// Profile name.
    pub profile_name: String,
    /// Whether the profile is marked dangerous.
    pub profile_dangerous: bool,
    /// Secret name in its project.
    pub name: String,
    /// Persisted secret source (`user-local`, `machine-local`, `team-managed`).
    pub source: String,
    /// Active current version number.
    pub current_version: u32,
    /// Last update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
}

/// Group of two or more active secrets sharing the same local-only keyed dedup tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicateValueGroupRecord {
    /// Local-only HMAC-SHA256 dedup tag bytes.
    pub dedup_tag: [u8; 32],
    /// Active secret rows that hold the exact same value.
    pub members: Vec<DuplicateSecretMemberRecord>,
}

fn secret_link_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretLinkRecord> {
    Ok(SecretLinkRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        local_name: row.get(3)?,
        target_project_id: row.get(4)?,
        target_profile_id: row.get(5)?,
        target_secret_id: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn duplicate_member_from_row(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<DuplicateSecretMemberRecord> {
    let project_id: String = row.get(offset + 1)?;
    let is_shared = project_id.starts_with("lk_proj_shared_");
    Ok(DuplicateSecretMemberRecord {
        secret_id: row.get(offset)?,
        project_id,
        project_name: row.get(offset + 2)?,
        is_shared,
        profile_id: row.get(offset + 3)?,
        profile_name: row.get(offset + 4)?,
        profile_dangerous: row.get(offset + 5)?,
        name: row.get(offset + 6)?,
        source: row.get(offset + 7)?,
        current_version: row.get(offset + 8)?,
        updated_at: row.get(offset + 9)?,
    })
}

impl Store {
    /// Inserts or replaces a project secret link to an active Global Vault secret atomically.
    ///
    /// Returns the persisted link ID (preserving the existing row ID when retargeting).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the link violates depth-1 Global Vault constraints,
    /// the target secret is missing or deleted, or `SQLite` rejects the write.
    pub fn upsert_secret_link_with_audit(
        &mut self,
        link: &SecretLinkRecord,
        audit: Option<AuditContext<'_>>,
    ) -> Result<String, StoreError> {
        let transaction = self.connection.savepoint()?;
        let target_active = transaction.query_row(
            "SELECT EXISTS(
                   SELECT 1 FROM secrets
                   WHERE id = ?1
                     AND project_id = ?2
                     AND profile_id = ?3
                     AND state = 'active'
                 )",
            params![link.target_secret_id, link.target_project_id, link.target_profile_id],
            |row| row.get::<_, bool>(0),
        )?;
        if !target_active {
            return Err(StoreError::SecretStateConflict {
                secret_id: link.target_secret_id.clone(),
                expected_version: 1,
            });
        }
        let persisted_id: String = transaction.query_row(
            "INSERT INTO secret_links(
               id, project_id, profile_id, local_name,
               target_project_id, target_profile_id, target_secret_id,
               created_at, updated_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(project_id, profile_id, local_name) DO UPDATE SET
               target_project_id = excluded.target_project_id,
               target_profile_id = excluded.target_profile_id,
               target_secret_id = excluded.target_secret_id,
               updated_at = excluded.updated_at
             RETURNING id",
            params![
                link.id,
                link.project_id,
                link.profile_id,
                link.local_name,
                link.target_project_id,
                link.target_profile_id,
                link.target_secret_id,
                link.created_at,
                link.updated_at,
            ],
            |row| row.get(0),
        )?;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(persisted_id)
    }

    /// Removes one secret link for a project/profile/name and optionally appends an audit row.
    ///
    /// Returns the removed link row when one existed, or `None` if no link was present.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects the delete or audit write.
    pub fn delete_secret_link_with_audit(
        &mut self,
        project_id: &str,
        profile_id: &str,
        local_name: &str,
        audit: Option<AuditContext<'_>>,
    ) -> Result<Option<SecretLinkRecord>, StoreError> {
        let transaction = self.connection.savepoint()?;
        let existing = transaction
            .query_row(
                "SELECT id, project_id, profile_id, local_name,
                        target_project_id, target_profile_id, target_secret_id,
                        created_at, updated_at
                 FROM secret_links
                 WHERE project_id = ?1 AND profile_id = ?2 AND local_name = ?3",
                params![project_id, profile_id, local_name],
                secret_link_from_row,
            )
            .optional()?;
        let Some(link) = existing else {
            return Ok(None);
        };
        transaction.execute("DELETE FROM secret_links WHERE id = ?1", [&link.id])?;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(Some(link))
    }

    /// Returns the stored link for `(project_id, profile_id, local_name)`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the link row.
    pub fn get_secret_link(
        &self,
        project_id: &str,
        profile_id: &str,
        local_name: &str,
    ) -> Result<Option<SecretLinkRecord>, StoreError> {
        self.connection
            .prepare_cached(
                "SELECT id, project_id, profile_id, local_name,
                        target_project_id, target_profile_id, target_secret_id,
                        created_at, updated_at
                 FROM secret_links
                 WHERE project_id = ?1 AND profile_id = ?2 AND local_name = ?3",
            )?
            .query_row(params![project_id, profile_id, local_name], secret_link_from_row)
            .optional()
            .map_err(StoreError::from)
    }

    /// Resolves an active link to its active `@shared` target secret row.
    ///
    /// Returns `None` if no link exists or if the target secret is not active.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the joined row.
    pub fn resolve_active_secret_link(
        &self,
        project_id: &str,
        profile_id: &str,
        local_name: &str,
    ) -> Result<Option<ResolvedSecretLink>, StoreError> {
        self.connection
            .prepare_cached(
                "SELECT l.id, l.project_id, l.profile_id, l.local_name,
                        l.target_project_id, l.target_profile_id, l.target_secret_id,
                        l.created_at, l.updated_at,
                        s.id, s.project_id, s.profile_id, s.name, s.source, s.origin,
                        s.current_version, s.state, s.created_at, s.updated_at,
                        s.last_rotated_at, s.deleted_at
                 FROM secret_links l
                 JOIN secrets s ON s.id = l.target_secret_id
                 WHERE l.project_id = ?1
                   AND l.profile_id = ?2
                   AND l.local_name = ?3
                   AND s.state = 'active'",
            )?
            .query_row(params![project_id, profile_id, local_name], |row| {
                let link = secret_link_from_row(row)?;
                let target_secret = SecretRecord {
                    id: row.get(9)?,
                    project_id: row.get(10)?,
                    profile_id: row.get(11)?,
                    name: row.get(12)?,
                    source: row.get(13)?,
                    origin: row.get(14)?,
                    current_version: row.get(15)?,
                    state: row.get(16)?,
                    created_at: row.get(17)?,
                    updated_at: row.get(18)?,
                    last_rotated_at: row.get(19)?,
                    deleted_at: row.get(20)?,
                };
                Ok(ResolvedSecretLink { link, target_secret })
            })
            .optional()
            .map_err(StoreError::from)
    }

    /// Lists all active links in a consuming profile paired with their active target secrets.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the link rows.
    pub fn list_active_secret_links_by_profile(
        &self,
        project_id: &str,
        profile_id: &str,
    ) -> Result<Vec<ResolvedSecretLink>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT l.id, l.project_id, l.profile_id, l.local_name,
                    l.target_project_id, l.target_profile_id, l.target_secret_id,
                    l.created_at, l.updated_at,
                    s.id, s.project_id, s.profile_id, s.name, s.source, s.origin,
                    s.current_version, s.state, s.created_at, s.updated_at,
                    s.last_rotated_at, s.deleted_at
             FROM secret_links l
             JOIN secrets s ON s.id = l.target_secret_id
             WHERE l.project_id = ?1
               AND l.profile_id = ?2
               AND s.state = 'active'
             ORDER BY l.local_name",
        )?;
        let rows = statement
            .query_map(params![project_id, profile_id], |row| {
                let link = secret_link_from_row(row)?;
                let target_secret = SecretRecord {
                    id: row.get(9)?,
                    project_id: row.get(10)?,
                    profile_id: row.get(11)?,
                    name: row.get(12)?,
                    source: row.get(13)?,
                    origin: row.get(14)?,
                    current_version: row.get(15)?,
                    state: row.get(16)?,
                    created_at: row.get(17)?,
                    updated_at: row.get(18)?,
                    last_rotated_at: row.get(19)?,
                    deleted_at: row.get(20)?,
                };
                Ok(ResolvedSecretLink { link, target_secret })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists every project/profile/name currently linked to `target_secret_id`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query usage rows.
    pub fn list_shared_secret_usages(
        &self,
        target_secret_id: &str,
    ) -> Result<Vec<SharedSecretUsageRecord>, StoreError> {
        shared_secret_usages(&self.connection, target_secret_id)
    }

    /// Atomically tombstones a secret, deletes its links, and appends the deletion and
    /// consumer unlink audits. Each active link must have an audit context keyed by link ID.
    ///
    /// Returns the usages that were unlinked.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::LinkSetChanged`] if the reviewed IDs or unlink audit scopes
    /// differ from the current links. Returns [`StoreError::SecretStateConflict`] if the
    /// secret no longer matches its expected version, or another error on write failure.
    pub fn tombstone_secret_and_unlink_with_audit(
        &mut self,
        secret: &SecretRecord,
        deleted_at: i64,
        audit: Option<AuditContext<'_>>,
        unlink_audits: &BTreeMap<&str, AuditContext<'_>>,
        expected_link_ids: Option<&[String]>,
    ) -> Result<Vec<SharedSecretUsageRecord>, StoreError> {
        let transaction = self.connection.savepoint()?;
        let usages = shared_secret_usages(&transaction, &secret.id)?;
        let mut current_ids: Vec<_> = usages.iter().map(|usage| usage.link_id.as_str()).collect();
        current_ids.sort_unstable();
        if let Some(expected) = expected_link_ids {
            let mut expected_ids: Vec<_> = expected.iter().map(String::as_str).collect();
            expected_ids.sort_unstable();
            if expected_ids != current_ids {
                return Err(StoreError::LinkSetChanged);
            }
        }
        if !unlink_audits.keys().copied().eq(current_ids) {
            return Err(StoreError::LinkSetChanged);
        }
        for usage in &usages {
            let audit = unlink_audits[usage.link_id.as_str()];
            if audit.write.project_id != usage.project_id
                || audit.write.profile_id != Some(usage.profile_id.as_str())
                || audit.write.action != "SECRET_UNLINK"
                || audit.write.status != "SUCCESS"
                || audit.write.secret_name != Some(usage.local_name.as_str())
                || audit.write.metadata_json != &usage.unlink_audit_metadata(secret)
            {
                return Err(StoreError::LinkSetChanged);
            }
            append_optional_audit(&transaction, Some(audit))?;
        }
        let updated = transaction.execute(
            "UPDATE secrets
             SET state = 'deleted', deleted_at = ?2, updated_at = ?2
             WHERE id = ?1 AND state = 'active' AND current_version = ?3",
            params![secret.id, deleted_at, secret.current_version],
        )?;
        if updated != 1 {
            return Err(StoreError::SecretStateConflict {
                secret_id: secret.id.clone(),
                expected_version: secret.current_version,
            });
        }
        transaction
            .execute("DELETE FROM secret_links WHERE target_secret_id = ?1", [&secret.id])?;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(usages)
    }

    /// Stores or updates a local-only keyed deduplication tag for a secret version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the upsert.
    pub fn upsert_local_value_fingerprint(
        &self,
        secret_id: &str,
        version: u32,
        dedup_tag: &[u8; 32],
        created_at: i64,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO local_value_fingerprints(secret_id, version, dedup_tag, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(secret_id, version) DO UPDATE SET
               dedup_tag = excluded.dedup_tag,
               created_at = excluded.created_at",
            params![secret_id, version, dedup_tag.as_slice(), created_at],
        )?;
        Ok(())
    }

    /// Lists all active current secrets matching a local-only keyed deduplication tag.
    ///
    /// Global Vault (`@shared`) matches are ordered first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query matching rows.
    pub fn find_active_secrets_by_dedup_tag(
        &self,
        dedup_tag: &[u8; 32],
    ) -> Result<Vec<DuplicateSecretMemberRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT s.id, s.project_id, p.name, s.profile_id, pr.name, pr.dangerous,
                    s.name, s.source, s.current_version, s.updated_at
             FROM local_value_fingerprints lvf
             JOIN secrets s
               ON s.id = lvf.secret_id
              AND s.current_version = lvf.version
              AND s.state = 'active'
             JOIN projects p ON p.id = s.project_id
             JOIN profiles pr ON pr.id = s.profile_id
             WHERE lvf.dedup_tag = ?1
             ORDER BY CASE WHEN s.project_id GLOB 'lk_proj_shared_*' THEN 0 ELSE 1 END,
                      p.name, pr.name, s.name, s.source",
        )?;
        let rows = statement
            .query_map([dedup_tag.as_slice()], |row| duplicate_member_from_row(row, 0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists all active value groups where two or more secrets share the same local dedup tag.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query duplicate groups.
    pub fn list_duplicate_value_groups(
        &self,
    ) -> Result<Vec<DuplicateValueGroupRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT lvf.dedup_tag,
                    s.id, s.project_id, p.name, s.profile_id, pr.name, pr.dangerous,
                    s.name, s.source, s.current_version, s.updated_at
             FROM local_value_fingerprints lvf
             JOIN secrets s
               ON s.id = lvf.secret_id
              AND s.current_version = lvf.version
              AND s.state = 'active'
             JOIN projects p ON p.id = s.project_id
             JOIN profiles pr ON pr.id = s.profile_id
             WHERE lvf.dedup_tag IN (
               SELECT l2.dedup_tag
               FROM local_value_fingerprints l2
               JOIN secrets s2
                 ON s2.id = l2.secret_id
                AND s2.current_version = l2.version
                AND s2.state = 'active'
               GROUP BY l2.dedup_tag
               HAVING COUNT(*) >= 2
             )
             ORDER BY lvf.dedup_tag,
                      CASE WHEN s.project_id GLOB 'lk_proj_shared_*' THEN 0 ELSE 1 END,
                      p.name, pr.name, s.name, s.source",
        )?;
        let mut groups: BTreeMap<[u8; 32], Vec<DuplicateSecretMemberRecord>> = BTreeMap::new();
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let tag_bytes: Vec<u8> = row.get(0)?;
            let Ok(tag): Result<[u8; 32], _> = tag_bytes.try_into() else {
                continue;
            };
            let member = duplicate_member_from_row(row, 1)?;
            groups.entry(tag).or_default().push(member);
        }
        Ok(groups
            .into_iter()
            .filter(|(_, members)| members.len() >= 2)
            .map(|(dedup_tag, members)| DuplicateValueGroupRecord { dedup_tag, members })
            .collect())
    }

    /// Returns one secret row by id regardless of state.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the secret row.
    pub fn get_secret_by_id(&self, id: &str) -> Result<Option<SecretRecord>, StoreError> {
        self.connection
            .prepare_cached(
                "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                        created_at, updated_at, last_rotated_at, deleted_at
                 FROM secrets
                 WHERE id = ?1",
            )?
            .query_row([id], secret_record_from_row)
            .optional()
            .map_err(StoreError::from)
    }
}

fn shared_secret_usages(
    connection: &Connection,
    target_secret_id: &str,
) -> Result<Vec<SharedSecretUsageRecord>, StoreError> {
    let mut statement = connection.prepare_cached(
        "SELECT l.id, l.project_id, p.name, l.profile_id, pr.name, pr.dangerous,
                l.local_name, l.target_secret_id, s.name, l.created_at, l.updated_at
         FROM secret_links l
         JOIN projects p ON p.id = l.project_id
         JOIN profiles pr ON pr.id = l.profile_id
         JOIN secrets s ON s.id = l.target_secret_id
         WHERE l.target_secret_id = ?1
         ORDER BY p.name, pr.name, l.local_name",
    )?;
    let rows = statement
        .query_map([target_secret_id], |row| {
            Ok(SharedSecretUsageRecord {
                link_id: row.get(0)?,
                project_id: row.get(1)?,
                project_name: row.get(2)?,
                profile_id: row.get(3)?,
                profile_name: row.get(4)?,
                profile_dangerous: row.get(5)?,
                local_name: row.get(6)?,
                target_secret_id: row.get(7)?,
                target_secret_name: row.get(8)?,
                created_at: row.get(9)?,
                updated_at: row.get(10)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
