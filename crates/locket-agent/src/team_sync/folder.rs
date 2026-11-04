use super::{Result, identity, reject};
use locket_core::team_package::{MAX_PACKAGE_BYTES, SignedStatement, digest};
use locket_crypto::KeyBytes;
use locket_platform::{
    LocalDevicePrivateKeyStorage, MasterKeyStore, MemoryMasterKeyStore,
    WrappedLocalFileDevicePrivateKeyStorage,
};
use locket_store::Store;
use rusqlite::{OptionalExtension, params};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
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
    pub owner_fingerprint: Option<String>,
    pub published: usize,
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
    let folder: Option<String> = store
        .connection()
        .query_row(
            "SELECT path FROM team_sync_folders WHERE project_id=?1 AND enabled=1",
            [project],
            |r| r.get(0),
        )
        .optional()?;
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
    if fs::symlink_metadata(path)?.file_type().is_symlink() || !path.is_dir() {
        return Err(reject("choose an existing regular shared folder"));
    }
    let path = path.canonicalize()?;
    let key_root = device_key_root.canonicalize()?;
    if key_root.starts_with(&path) || path.starts_with(&key_root) {
        return Err(reject("shared folder must be separate from local vault/private-key storage"));
    }
    if super::snapshot::anchor(store, project)?.is_none() {
        return Err(reject("join with independent owner pin before enabling automatic sync"));
    }
    // Acquire SQLite's write slot before taking the short live-unlock guard.
    let transaction = rusqlite::Transaction::new_unchecked(
        store.connection(),
        rusqlite::TransactionBehavior::Immediate,
    )?;
    let _authorization = authorization.map(|authorize| authorize()).transpose()?;
    store.connection().execute("INSERT INTO team_sync_folders(project_id,path,device_key_root,allow_dangerous,enabled) VALUES (?1,?2,?3,?4,1) ON CONFLICT(project_id) DO UPDATE SET path=excluded.path,device_key_root=excluded.device_key_root,allow_dangerous=excluded.allow_dangerous,enabled=1",params![project,path.to_string_lossy(),key_root.to_string_lossy(),allow_dangerous])?;
    transaction.commit()?;
    Ok(())
}
fn folder(store: &Store, project: &str) -> Result<(PathBuf, PathBuf, bool)> {
    let row:Option<(String,String,bool)>=store.connection().query_row("SELECT path,device_key_root,allow_dangerous FROM team_sync_folders WHERE project_id=?1 AND enabled=1",[project],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let (path, keys, dangerous) = row.ok_or_else(|| reject("shared folder not configured"))?;
    let path = PathBuf::from(path);
    if fs::symlink_metadata(&path)?.file_type().is_symlink() || !path.is_dir() {
        return Err(reject("shared folder unavailable"));
    }
    Ok((path, PathBuf::from(keys), dangerous))
}
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn read_package_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.len() > u64::try_from(MAX_PACKAGE_BYTES + 18).unwrap_or(u64::MAX)
    {
        return Err(reject("ignore nonregular or oversized package"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(reject("package is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take((MAX_PACKAGE_BYTES + 19) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PACKAGE_BYTES + 18 {
        return Err(reject("oversized package"));
    }
    Ok(bytes)
}
/// # Errors
/// Returns an error when trust, scope, cryptography, storage or folder validation fails.
pub fn flush_outbox(store: &Store, project: &str) -> Result<usize> {
    let (directory, _, _) = folder(store, project)?;
    let mut stmt=store.connection().prepare("SELECT filename,ciphertext,recipient FROM team_sync_outbox WHERE project_id=?1 ORDER BY rowid")?;
    let rows = stmt
        .query_map([project], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, String>(2)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut count = 0;
    for (name, bytes, recipient) in rows {
        let allowed:bool=store.connection().query_row("SELECT EXISTS(SELECT 1 FROM devices d JOIN team_members m ON m.device_id=d.id JOIN teams t ON t.id=m.team_id WHERE t.project_id=?1 AND d.fingerprint=?2 AND d.revoked_at IS NULL AND m.removed_at IS NULL)",(project,&recipient),|r|r.get(0))?;
        if !allowed {
            continue;
        }
        if Path::new(&name).file_name().and_then(|n| n.to_str()) != Some(name.as_str()) {
            return Err(reject("invalid outbox filename"));
        }
        let original_target = directory.join(&name);
        let mut target = original_target.clone();
        let mut delivery_name = name.clone();
        let matches = read_package_file(&target).is_ok_and(|existing| existing == bytes);
        if !matches {
            // Preserve an untrusted conflicting transport entry. Deliver the exact
            // durable ciphertext under a new random name instead of stalling later rows.
            if fs::symlink_metadata(&target).is_ok() {
                delivery_name = format!("{}.lkpkg", digest(&locket_crypto::random_bytes::<32>()?));
                target = directory.join(&delivery_name);
                store.connection().execute(
                    "UPDATE team_sync_outbox SET filename=?3,delivered=0 WHERE project_id=?1 AND filename=?2",
                    (project, &name, &delivery_name),
                )?;
            }
            let temporary =
                directory.join(format!(".{}.tmp", digest(&locket_crypto::random_bytes::<32>()?)));
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            let written = (|| -> std::io::Result<()> {
                file.write_all(&bytes)?;
                file.sync_all()?;
                fs::rename(&temporary, &target)?;
                #[cfg(unix)]
                fs::File::open(&directory)?.sync_all()?;
                Ok(())
            })();
            if written.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            written?;
            count += 1;
        }
        store.connection().execute(
            "UPDATE team_sync_outbox SET delivered=1 WHERE project_id=?1 AND filename=?2",
            (project, &delivery_name),
        )?;
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
/// Runs folder delivery with a live authorization check immediately before vault commits.
/// # Errors
/// Returns scope, trust, delivery or expired-authorization errors without exposing values.
pub fn sync_folder_guarded(
    store: &mut Store,
    project: &str,
    master: &KeyBytes,
    now: i64,
    authorization: Option<&super::CommitAuthorization>,
) -> Result<SyncStatus> {
    let (directory, key_root, allow_dangerous) = folder(store, project)?;
    let local_record = store
        .get_active_local_device(project)?
        .ok_or_else(|| reject("active local device missing"))?;
    let local = identity(&local_record)?;
    let (_, owner) =
        super::snapshot::anchor(store, project)?.ok_or_else(|| reject("owner pin missing"))?;
    let memory = Arc::new(MemoryMasterKeyStore::default());
    memory.store_master_key(project, master)?;
    let storage = WrappedLocalFileDevicePrivateKeyStorage::new(key_root, project, memory);
    if owner == local {
        let shared_profiles = super::shared_profile_ids(store, project)?;
        if !allow_dangerous
            && store
                .list_profiles(project)?
                .iter()
                .any(|p| p.dangerous && shared_profiles.contains(&p.id))
        {
            return Err(reject(
                "automatic dangerous-profile publication needs explicit folder consent",
            ));
        }
        let signing = storage.for_signing().load(&local.fingerprint)?;
        // Retry already queued ciphertext even when a newer publication cannot be prepared.
        let initial_delivery = flush_outbox(store, project)?;
        super::publish_guarded(
            store,
            project,
            master,
            &ed25519_dalek::SigningKey::from_bytes(&signing),
            now,
            authorization,
        )?;
        let published = initial_delivery + flush_outbox(store, project)?;
        let mut result = status(store, project)?;
        result.published = published;
        return Ok(result);
    }
    let sealing = storage.load(&local.id)?;
    let starting_head = receiver_head(store, project)?;
    let mut candidates = Vec::new();
    let mut files = Vec::new();
    let mut entries = 0_u32;
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        entries += 1;
        if entries > 100_000 {
            return Err(reject(
                "shared folder has too many entries; choose a dedicated team folder",
            ));
        }
        if entry.path().extension().and_then(|e| e.to_str()) == Some("lkpkg")
            && entry.file_type()?.is_file()
            && !entry.file_type()?.is_symlink()
        {
            files.push(entry);
        }
    }
    files.sort_by_key(std::fs::DirEntry::file_name);
    let cursor: Option<String> = store.connection().query_row(
        "SELECT scan_after FROM team_sync_folders WHERE project_id=?1",
        [project],
        |row| row.get(0),
    )?;
    let start = cursor
        .as_ref()
        .and_then(|cursor| {
            files
                .iter()
                .position(|entry| entry.file_name().to_string_lossy().as_ref() > cursor.as_str())
        })
        .unwrap_or(0);
    let mut scanned_bytes = 0_usize;
    let mut next_cursor = None;
    for entry in files.iter().cycle().skip(start).take(files.len().min(64)) {
        if scanned_bytes >= 32 * 1024 * 1024 {
            break;
        }
        next_cursor = Some(entry.file_name().to_string_lossy().into_owned());
        let path = entry.path();
        let Ok(bytes) = read_package_file(&path) else {
            continue;
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
    let mut delivery_error = None;
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
