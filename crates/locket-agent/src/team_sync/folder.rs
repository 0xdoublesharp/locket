use super::transport::{self, PutOutcome, TeamTransport, TransportConfig, TransportSummary};
use super::{Result, identity, reject};
use locket_core::team_package::{SignedStatement, digest};
use locket_crypto::KeyBytes;
use locket_platform::{
    LocalDevicePrivateKeyStorage, MasterKeyStore, MemoryMasterKeyStore,
    WrappedLocalFileDevicePrivateKeyStorage,
};
use locket_store::Store;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SyncStatus {
    pub epoch: u64,
    pub state: String,
    pub conflicts: usize,
    pub conflict_ids: Vec<String>,
    #[serde(default)]
    pub pending_profiles: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub pending_details: Vec<super::PendingProfileDetails>,
    pub waiting: usize,
    pub waiting_known: bool,
    pub last_error: Option<String>,
    pub last_verified_at: Option<i64>,
    pub folder: Option<String>,
    #[serde(default)]
    pub transport_kind: Option<String>,
    #[serde(default)]
    pub remote_target: Option<String>,
    #[serde(default)]
    pub remote_endpoint: Option<String>,
    #[serde(default)]
    pub remote_region: Option<String>,
    #[serde(default)]
    pub credential_mode: Option<String>,
    pub owner_fingerprint: Option<String>,
    pub published: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub applied: usize,
}
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn status(store: &Store, project: &str) -> Result<SyncStatus> {
    let head: Option<(i64, String, i64)> = store
        .connection()
        .query_row(
            "SELECT epoch,state,verified_at FROM team_sync_heads WHERE project_id=?1",
            [project],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let summary = transport::configured(store, project)?
        .map(|configured| configured.config.summary())
        .transpose()?;
    let folder = summary
        .as_ref()
        .filter(|summary| summary.transport_kind == "folder")
        .map(|summary| summary.target.clone());
    let (transport_kind, remote_target, remote_endpoint, remote_region, credential_mode) = summary
        .map_or(
            (None, None, None, None, None),
            |TransportSummary { transport_kind, target, endpoint, region, credential_mode }| {
                (Some(transport_kind), Some(target), endpoint, region, Some(credential_mode))
            },
        );
    let conflicts: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM team_sync_conflicts WHERE project_id=?1",
        [project],
        |r| r.get(0),
    )?;
    let conflict_ids = store
        .connection()
        .prepare(
            "SELECT secret_id FROM team_sync_conflicts WHERE project_id=?1 ORDER BY secret_id",
        )?
        .query_map([project], |r| r.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let pending_profiles = store.connection().prepare(
        "SELECT profile_id,reason FROM team_sync_pending_profiles WHERE project_id=?1 ORDER BY profile_id",
    )?.query_map([project], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<std::result::Result<std::collections::BTreeMap<String,String>, _>>()?;
    let last_error: Option<String> = store
        .connection()
        .query_row("SELECT last_error FROM team_sync_folders WHERE project_id=?1", [project], |r| {
            r.get(0)
        })
        .optional()?
        .flatten();
    let owner = super::snapshot::anchor(store, project)?.map(|(_, o)| o.fingerprint);
    Ok(SyncStatus {
        epoch: head.as_ref().map_or(0, |h| u64::try_from(h.0).unwrap_or(0)),
        state: if last_error.is_some()
            && !head.as_ref().is_some_and(|h| {
                ["fork", "removed", "locked", "pending-values"].contains(&h.1.as_str())
            }) {
            "delivery-error".into()
        } else {
            head.as_ref().map_or_else(
                || if owner.is_some() { "owner".into() } else { "unanchored".into() },
                |h| h.1.clone(),
            )
        },
        last_error,
        last_verified_at: head.map(|h| h.2),
        folder,
        transport_kind,
        remote_target,
        remote_endpoint,
        remote_region,
        credential_mode,
        conflict_ids,
        pending_profiles,
        owner_fingerprint: owner,
        conflicts: usize::try_from(conflicts).unwrap_or(0),
        ..SyncStatus::default()
    })
}
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn configure_folder(
    store: &Store,
    project: &str,
    path: &Path,
    device_key_root: &Path,
    allow_dangerous: bool,
) -> Result<()> {
    configure_folder_guarded(store, project, path, device_key_root, allow_dangerous, None)
}
/// Validates the delivery paths outside the live unlock guard, then authorizes the insert.
/// # Errors
/// Rejects invalid paths, trust, storage or expired local authorization.
pub fn configure_folder_guarded(
    store: &Store,
    project: &str,
    path: &Path,
    device_key_root: &Path,
    allow_dangerous: bool,
    authorization: Option<&super::CommitAuthorization>,
) -> Result<()> {
    let path = path.to_str().ok_or_else(|| reject("shared folder path must be UTF-8"))?;
    transport::configure_transport_guarded(
        store,
        project,
        TransportConfig::Folder { path: path.into() },
        None,
        device_key_root,
        None,
        allow_dangerous,
        authorization,
    )
}

/// Upload queued packages to the configured folder or with environment credentials.
/// # Errors
/// Returns an error if delivery fails or vault credentials are required.
pub fn flush_outbox(store: &Store, project: &str) -> Result<usize> {
    flush_outbox_with_master(store, project, None)
}

/// Upload queued packages, using the master key if the backend needs vault credentials.
/// # Errors
/// Returns an error if the transport, credentials, or storage fail.
pub fn flush_outbox_with_master(
    store: &Store,
    project: &str,
    master: Option<&KeyBytes>,
) -> Result<usize> {
    let (transport, _) = transport::open_configured(store, project, master)?;
    flush_to(store, project, transport.as_ref())
}

fn flush_to(store: &Store, project: &str, transport: &dyn TeamTransport) -> Result<usize> {
    let mut stmt = store.connection().prepare(
        "SELECT filename,ciphertext,recipient FROM team_sync_outbox WHERE project_id=?1 ORDER BY rowid",
    )?;
    let rows = stmt
        .query_map([project], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, String>(2)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut count = 0;
    for (mut name, bytes, recipient) in rows {
        transport::validate_filename(&name)?;
        // Bound upload attempts when the backend keeps reporting name conflicts.
        let mut delivered = false;
        for _ in 0..8 {
            // Hold the write transaction through the upload so pruning cannot
            // delete a row between the eligibility check and upload.
            let tx =
                Transaction::new_unchecked(store.connection(), TransactionBehavior::Immediate)?;
            let allowed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM devices d JOIN team_members m ON m.device_id=d.id
                 JOIN teams t ON t.id=m.team_id WHERE t.project_id=?1 AND d.fingerprint=?2
                 AND d.revoked_at IS NULL AND m.removed_at IS NULL)
                 AND EXISTS(SELECT 1 FROM team_sync_outbox WHERE project_id=?1 AND filename=?3)",
                (project, &recipient, &name),
                |r| r.get(0),
            )?;
            if !allowed {
                // Skip rows renamed or pruned since the scan and recipients who lost access.
                delivered = true;
                break;
            }
            match transport.put_package(&name, &bytes)? {
                PutOutcome::Conflict => {
                    let suffix = digest(&locket_crypto::random_bytes::<32>()?);
                    let next = if let Some((prefix, _)) =
                        name.rsplit_once('-').filter(|_| name.starts_with("r-"))
                    {
                        format!("{prefix}-{}.lkpkg", &suffix[..16])
                    } else {
                        format!("{suffix}.lkpkg")
                    };
                    let updated = tx.execute(
                        "UPDATE OR IGNORE team_sync_outbox SET filename=?3,delivered=0
                         WHERE project_id=?1 AND filename=?2",
                        (project, &name, &next),
                    )?;
                    if updated != 0 {
                        name = next;
                    }
                }
                outcome => {
                    tx.execute(
                        "UPDATE team_sync_outbox SET delivered=1 WHERE project_id=?1 AND filename=?2",
                        (project, &name),
                    )?;
                    count += usize::from(outcome == PutOutcome::Written);
                    delivered = true;
                }
            }
            tx.commit()?;
            if delivered {
                break;
            }
        }
        if !delivered {
            return Err(reject("team package delivery encountered too many filename conflicts"));
        }
    }
    Ok(count)
}
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn sync_folder(
    store: &mut Store,
    project: &str,
    master: &KeyBytes,
    now: i64,
) -> Result<SyncStatus> {
    sync_folder_guarded(store, project, master, now, None)
}
/// Runs configured delivery with a live authorization check immediately before vault commits.
/// # Errors
/// Returns scope, trust, delivery or expired-authorization errors without exposing values.
pub fn sync_folder_guarded(
    store: &mut Store,
    project: &str,
    master: &KeyBytes,
    now: i64,
    authorization: Option<&super::CommitAuthorization>,
) -> Result<SyncStatus> {
    let (transport, configured) = transport::open_configured(store, project, Some(master))?;
    let transport = transport.as_ref();
    let allow_dangerous = configured.allow_dangerous;
    let local_record = store
        .get_active_local_device(project)?
        .ok_or_else(|| reject("active local device missing"))?;
    let local = identity(&local_record)?;
    let (_, owner) =
        super::snapshot::anchor(store, project)?.ok_or_else(|| reject("owner pin missing"))?;
    let memory = Arc::new(MemoryMasterKeyStore::default());
    memory.store_master_key(project, master)?;
    let storage =
        WrappedLocalFileDevicePrivateKeyStorage::new(configured.key_root, project, memory);
    if owner == local {
        let shared_profiles = super::shared_profile_ids(store, project)?;
        if !allow_dangerous
            && store
                .list_profiles(project)?
                .iter()
                .any(|p| p.dangerous && shared_profiles.contains(&p.id))
        {
            let message = if matches!(configured.config, TransportConfig::Folder { .. }) {
                "automatic dangerous-profile publication needs explicit folder consent"
            } else {
                "automatic dangerous-profile publication needs explicit transport consent"
            };
            return Err(reject(message));
        }
        let signing = storage.for_signing().load(&local.fingerprint)?;
        // Retry already queued ciphertext even when a newer publication cannot be prepared.
        let initial_delivery = flush_to(store, project, transport)?;
        let publication = super::publish_with_warnings(
            store,
            project,
            master,
            &ed25519_dalek::SigningKey::from_bytes(&signing),
            now,
            authorization,
        )?;
        let published = initial_delivery + flush_to(store, project, transport)?;
        store.connection().execute(
            "UPDATE team_sync_folders SET last_error=NULL WHERE project_id=?1",
            [project],
        )?;
        let mut result = status(store, project)?;
        result.published = published;
        result.warnings = publication.warnings;
        return Ok(result);
    }
    let sealing = storage.load(&local.id)?;
    let starting_head = receiver_head(store, project)?;
    let mut candidates = Vec::new();
    let mut files = transport.list_packages()?;
    let is_remote = !matches!(configured.config, TransportConfig::Folder { .. });
    if is_remote {
        let prefix = transport::recipient_prefix(&local.fingerprint)?;
        files.retain(|name| transport::is_recipient_candidate(name, &prefix));
    }
    let cursor: Option<String> = store.connection().query_row(
        "SELECT scan_after FROM team_sync_folders WHERE project_id=?1",
        [project],
        |row| row.get(0),
    )?;
    let start = cursor
        .as_ref()
        .and_then(|cursor| files.iter().position(|entry| entry > cursor))
        .unwrap_or(0);
    let mut scanned_bytes = 0_usize;
    let mut next_cursor = None;
    let mut delivery_error = None;
    for entry in files.iter().cycle().skip(start).take(files.len().min(64)) {
        if scanned_bytes >= 32 * 1024 * 1024 {
            break;
        }
        next_cursor = Some(entry);
        let bytes = match transport.get_package(entry) {
            Ok(bytes) => bytes,
            Err(error) => {
                if is_remote {
                    delivery_error.get_or_insert_with(|| error.to_string());
                }
                continue;
            }
        };
        scanned_bytes += bytes.len();
        let file_digest = format!("file:{}", digest(&bytes));
        let seen: bool = store.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM team_sync_seen WHERE project_id=?1 AND digest=?2)",
            (project, &file_digest),
            |r| r.get(0),
        )?;
        if seen {
            continue;
        }
        let signed = match SignedStatement::open(&bytes, &sealing) {
            Ok(s) => s,
            Err(error) => {
                if error.0 == "not decryptable" {
                    store.connection().execute(
                        "INSERT OR IGNORE INTO team_sync_seen VALUES (?1,?2,0,'not_for_me')",
                        (project, &file_digest),
                    )?;
                }
                continue;
            }
        };
        // Time-window failures are retryable after clocks correct.
        let Ok(verified) = signed.verify_update(&owner.fingerprint, project, &local, now) else {
            continue;
        };
        candidates.push((verified.statement.epoch, file_digest, bytes));
    }
    store.connection().execute(
        "UPDATE team_sync_folders SET scan_after=?2 WHERE project_id=?1",
        (project, &next_cursor),
    )?;
    candidates.sort_by_key(|c| c.0);
    let mut applied = 0;
    for (_, file_digest, bytes) in candidates {
        let attempt = super::apply_package_with_consent_guarded(
            store,
            &bytes,
            master,
            &sealing,
            &local,
            project,
            None,
            now,
            allow_dangerous,
            authorization,
        );
        let result = match attempt {
            Ok(result) => result,
            Err(super::SyncError::MissingPredecessor) => {
                delivery_error = Some(super::SyncError::MissingPredecessor.to_string());
                continue;
            }
            Err(error) => return Err(error),
        };
        applied += result.applied;
        store.connection().execute(
            "INSERT OR IGNORE INTO team_sync_seen VALUES (?1,?2,0,'processed')",
            (project, &file_digest),
        )?;
    }
    // New authenticated checkpoints take priority over retrying older held values.
    let retry_error = if receiver_head(store, project)? == starting_head {
        match super::resume_pending_profiles_guarded(
            store,
            project,
            master,
            &sealing,
            &local,
            allow_dangerous,
            now,
            authorization,
        ) {
            Ok(resumed) => {
                applied += resumed.applied;
                None
            }
            Err(error) => Some(error.to_string()),
        }
    } else {
        None
    };
    let last_error = retry_error.or(delivery_error);
    store.connection().execute(
        "UPDATE team_sync_folders SET last_error=?2 WHERE project_id=?1",
        (project, &last_error),
    )?;
    let mut result = status(store, project)?;
    match super::pending_profile_details(store, project, &sealing, &local, now) {
        Ok(details) => result.pending_details = details,
        Err(error) => {
            let message = error.to_string();
            store.connection().execute(
                "UPDATE team_sync_folders SET last_error=?2 WHERE project_id=?1",
                (project, &message),
            )?;
            result.last_error = Some(message);
        }
    }
    result.applied = applied;
    Ok(result)
}

fn receiver_head(store: &Store, project: &str) -> Result<Option<(i64, String)>> {
    Ok(store
        .connection()
        .query_row(
            "SELECT epoch,digest FROM team_sync_heads WHERE project_id=?1",
            [project],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?)
}
