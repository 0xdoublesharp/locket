//! Team sync RPCs use the current agent unlock and explicit local grants.
#![allow(missing_docs)]
use crate::team_sync::{self, SyncStatus};
use crate::{
    AgentSocketState, ErrorEnvelope, GrantAction, GrantBinding, GrantValidation, RequestEnvelope,
    ResponseEnvelope, SuccessEnvelope,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TeamSyncRequest {
    pub project_id: String,
    #[serde(default)]
    pub store_path: Option<PathBuf>,
    #[serde(default)]
    pub profile_id: Option<String>,
    #[serde(default)]
    pub grant_id: Option<String>,
    #[serde(default)]
    pub binding: Option<GrantBinding>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TeamSyncConfigureRequest {
    #[serde(flatten)]
    pub scope: TeamSyncRequest,
    pub folder: PathBuf,
    #[serde(default)]
    pub allow_dangerous: bool,
}
fn open_sync_store(path: impl AsRef<std::path::Path>) -> team_sync::Result<locket_store::Store> {
    let mut store = locket_store::Store::open(path)?;
    store.initialize_schema()?;
    Ok(store)
}
fn response<T: Serialize>(request: &RequestEnvelope, value: T) -> ResponseEnvelope {
    ResponseEnvelope::Success(SuccessEnvelope::new(
        request.id.clone(),
        serde_json::to_value(value).unwrap_or(serde_json::Value::Null),
    ))
}
fn error(request: &RequestEnvelope, code: &str, message: &str) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), code, message, false))
}
async fn granted(request: &TeamSyncRequest, state: &AgentSocketState) -> bool {
    let (Some(grant), Some(profile)) = (&request.grant_id, &request.profile_id) else {
        return false;
    };
    state.grants.lock().await.validate(
        grant,
        &request.project_id,
        profile,
        GrantAction::TeamSync,
        crate::server::current_unix_nanos(),
        request.binding.as_ref(),
    ) == GrantValidation::Valid
}
pub async fn handle_team_sync_status(
    request: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<TeamSyncRequest>(request.payload.clone()) else {
        return error(request, "ProtocolError", "invalid sync status request");
    };
    let cache = state.unlock_cache.lock().await;
    let entry = cache.lookup(&typed.project_id, crate::server::current_unix_nanos());
    let path =
        entry.and_then(|e| e.audit_context()).map(|c| c.store_path.clone()).or(typed.store_path);
    let unlocked = entry.is_some();
    drop(cache);
    let project = typed.project_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let Some(path) = path.filter(|path| path.is_file()) else {
            return Ok(SyncStatus::default());
        };
        if unlocked {
            open_sync_store(path).and_then(|store| team_sync::status(&store, &project))
        } else {
            // Locked metadata reads never migrate or create a caller-selected store.
            let result = locket_store::Store::open_read_only(path)
                .map_err(team_sync::SyncError::from)
                .and_then(|store| team_sync::status(&store, &project));
            Ok(result.unwrap_or_default())
        }
    })
    .await;
    let Ok(Ok(mut result)) = result else {
        return error(request, "MetadataInvalid", "team status unavailable");
    };
    if !unlocked {
        result.state = "locked".into();
    } else if ["removed", "fork"].contains(&result.state.as_str()) {
        if state
            .lock_for_team_sync_event(&typed.project_id, crate::server::current_unix_nanos())
            .await
            .is_err()
        {
            return error(request, "MetadataInvalid", "team lock audit unavailable");
        }
    } else if !result.pending_profiles.is_empty() {
        match unlocked_pending_details(state, typed.project_id).await {
            Ok(details) => result.pending_details = details,
            Err(failure) => result.last_error = Some(failure.to_string()),
        }
    }
    response(request, result)
}
pub async fn handle_team_sync_configure(
    request: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<TeamSyncConfigureRequest>(request.payload.clone())
    else {
        return error(request, "ProtocolError", "invalid sync configuration");
    };
    if !granted(&typed.scope, state).await {
        return error(request, "GrantRequired", "explicit local grant required for team sync");
    }
    match configure_cached(state, typed).await {
        Ok(status) => response(request, status),
        Err(failure) => error(request, "TeamSyncRejected", &failure.to_string()),
    }
}

async fn configure_cached(
    state: &AgentSocketState,
    request: TeamSyncConfigureRequest,
) -> team_sync::Result<SyncStatus> {
    let project = request.scope.project_id.clone();
    let (key, context, expiry) = cached_sync_context(state, &project).await?;
    let authorization = granted_commit_authorization(
        state,
        &request.scope,
        commit_authorization(state, &project, &context.store_path, expiry, &key),
    );
    run_sync_worker(state, project, context.store_path.clone(), move |store| {
        configure_store(store, &request, &context.store_path, &authorization)
    })
    .await
}
fn configure_store(
    store: &locket_store::Store,
    request: &TeamSyncConfigureRequest,
    store_path: &std::path::Path,
    authorization: &team_sync::CommitAuthorization,
) -> team_sync::Result<SyncStatus> {
    check_selected_store(request.scope.store_path.as_deref(), store_path)?;
    let root = store_path
        .parent()
        .ok_or_else(|| team_sync::SyncError::Rejected("local key directory unavailable".into()))?;
    team_sync::configure_folder_guarded(
        store,
        &request.scope.project_id,
        &request.folder,
        root,
        request.allow_dangerous,
        Some(authorization),
    )?;
    team_sync::status(store, &request.scope.project_id)
}

fn check_selected_store(
    selected: Option<&std::path::Path>,
    actual: &std::path::Path,
) -> team_sync::Result<()> {
    if let Some(selected) = selected {
        let same = match (selected.canonicalize(), actual.canonicalize()) {
            (Ok(selected), Ok(actual)) => selected == actual,
            _ => false,
        };
        if !same {
            return Err(team_sync::SyncError::Rejected(
                "selected store differs from unlock context".into(),
            ));
        }
    }
    Ok(())
}

pub async fn handle_team_sync_now(
    request: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<TeamSyncRequest>(request.payload.clone()) else {
        return error(request, "ProtocolError", "invalid sync request");
    };
    if !granted(&typed, state).await {
        return error(request, "GrantRequired", "explicit local grant required for team sync");
    }
    match run_cached_sync(state, typed.project_id, typed.store_path).await {
        Ok(status) => response(request, status),
        Err(failure) => error(request, "TeamSyncRejected", &failure.to_string()),
    }
}

async fn run_cached_sync(
    state: &AgentSocketState,
    project: String,
    selected_store: Option<PathBuf>,
) -> team_sync::Result<SyncStatus> {
    let (key, context, expiry) = cached_sync_context(state, &project).await?;
    let authorization = commit_authorization(state, &project, &context.store_path, expiry, &key);
    run_sync_worker(state, project.clone(), context.store_path.clone(), move |store| {
        check_selected_store(selected_store.as_deref(), &context.store_path)?;
        let configured = store.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM team_sync_folders WHERE project_id=?1 AND enabled=1)",
            [&project],
            |row| row.get::<_, bool>(0),
        )?;
        if !configured {
            return team_sync::status(store, &project);
        }
        let now = i64::try_from(crate::server::current_unix_nanos() / 1_000_000_000)
            .map_err(|_| team_sync::SyncError::Rejected("clock unavailable".into()))?;
        let result =
            team_sync::sync_folder_guarded(store, &project, &key, now, Some(&authorization));
        let message = result.as_ref().err().map(ToString::to_string);
        if let Some(message) = message {
            store.connection().execute(
                "UPDATE team_sync_folders SET last_error=?2 WHERE project_id=?1",
                rusqlite::params![project, message],
            )?;
        }
        result
    })
    .await
}

/// Observe persisted security state even if the worker returned an error after
/// committing a fork marker. Never retain authorization when that check fails.
async fn run_sync_worker(
    state: &AgentSocketState,
    project: String,
    store_path: PathBuf,
    operation: impl FnOnce(&mut locket_store::Store) -> team_sync::Result<SyncStatus> + Send + 'static,
) -> team_sync::Result<SyncStatus> {
    let worker_project = project.clone();
    let worker = tokio::task::spawn_blocking(move || -> team_sync::Result<_> {
        let mut store = open_sync_store(store_path)?;
        let result = operation(&mut store);
        let invalidated = store.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM team_sync_heads WHERE project_id=?1 AND state IN ('removed','fork'))",
            [&worker_project],
            |row| row.get::<_, bool>(0),
        );
        Ok((result, invalidated))
    })
    .await;
    let (result, invalidated) = if let Ok(result) = worker {
        result?
    } else {
        // A worker may have persisted a security transition before panicking.
        let _ = state.lock_for_team_sync_event(&project, crate::server::current_unix_nanos()).await;
        return Err(team_sync::SyncError::Rejected("team update worker stopped".into()));
    };
    let lock = if matches!(invalidated, Ok(false)) {
        Ok(())
    } else {
        state
            .lock_for_team_sync_event(&project, crate::server::current_unix_nanos())
            .await
            .map(|_| ())
    };
    // Preserve the original sync rejection after cleanup has completed.
    let status = result?;
    invalidated?;
    lock?;
    Ok(status)
}

async fn cached_sync_context(
    state: &AgentSocketState,
    project: &str,
) -> team_sync::Result<(
    zeroize::Zeroizing<locket_crypto::KeyBytes>,
    crate::unlock_cache::UnlockAuditContext,
    i128,
)> {
    {
        let cache = state.unlock_cache.lock().await;
        let entry = cache
            .lookup(project, crate::server::current_unix_nanos())
            .ok_or_else(|| team_sync::SyncError::Rejected("unlock the selected project".into()))?;
        let context = entry.audit_context().cloned().ok_or_else(|| {
            team_sync::SyncError::Rejected("unlock context lacks store path".into())
        })?;
        let key: locket_crypto::KeyBytes = entry
            .key_bytes()
            .try_into()
            .map_err(|_| team_sync::SyncError::Rejected("invalid cached key".into()))?;
        let result = (zeroize::Zeroizing::new(key), context, entry.expires_at_unix_nanos());
        drop(cache);
        Ok(result)
    }
}

async fn unlocked_pending_details(
    state: &AgentSocketState,
    project: String,
) -> team_sync::Result<Vec<team_sync::PendingProfileDetails>> {
    let (key, context, _) = cached_sync_context(state, &project).await?;
    tokio::task::spawn_blocking(move || {
        let store = open_sync_store(&context.store_path)?;
        pending_details(&store, &project, &key, &context.store_path, sync_now()?)
    })
    .await
    .map_err(|_| team_sync::SyncError::Rejected("team metadata worker stopped".into()))?
}
fn sync_now() -> team_sync::Result<i64> {
    i64::try_from(crate::server::current_unix_nanos() / 1_000_000_000)
        .map_err(|_| team_sync::SyncError::Rejected("clock unavailable".into()))
}

pub async fn handle_team_sync_reconcile(
    request: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let Ok(typed) =
        serde_json::from_value::<crate::TeamSyncReconcileRequest>(request.payload.clone())
    else {
        return error(request, "ProtocolError", "invalid team reconciliation request");
    };
    if !granted(&typed.scope, state).await {
        return error(request, "GrantRequired", "explicit local grant required for team sync");
    }
    match reconcile_cached(state, typed).await {
        Ok(status) => response(request, status),
        Err(failure) => error(request, "TeamSyncRejected", &failure.to_string()),
    }
}
async fn reconcile_cached(
    state: &AgentSocketState,
    request: crate::TeamSyncReconcileRequest,
) -> team_sync::Result<SyncStatus> {
    use locket_platform::{LocalDevicePrivateKeyStorage, MasterKeyStore};
    let project = request.scope.project_id.clone();
    let (key, context, expiry) = cached_sync_context(state, &project).await?;
    let authorization = granted_commit_authorization(
        state,
        &request.scope,
        commit_authorization(state, &project, &context.store_path, expiry, &key),
    );
    run_sync_worker(state, project.clone(), context.store_path.clone(), move |store| {
        check_selected_store(request.scope.store_path.as_deref(), &context.store_path)?;
        let local = store
            .get_active_local_device(&project)?
            .ok_or_else(|| team_sync::SyncError::Rejected("active local device missing".into()))?;
        let root = context.store_path.parent().ok_or_else(|| {
            team_sync::SyncError::Rejected("local key directory unavailable".into())
        })?;
        let memory = std::sync::Arc::new(locket_platform::MemoryMasterKeyStore::default());
        memory.store_master_key(&project, &key)?;
        let storage =
            locket_platform::WrappedLocalFileDevicePrivateKeyStorage::new(root, &project, memory);
        let sealing = storage.load(&local.id)?;
        let identity = team_sync::identity(&local)?;
        let now = sync_now()?;
        match request.action {
            crate::TeamSyncAction::RenameProfile { local_profile_id, new_name } => {
                team_sync::rename_local_profile_for_pending(
                    store,
                    &project,
                    &request.incoming_profile_id,
                    &local_profile_id,
                    &new_name,
                    &key,
                    &sealing,
                    &identity,
                    now,
                    Some(&authorization),
                )?;
            }
            crate::TeamSyncAction::PreserveOverride { local_secret_id } => {
                team_sync::preserve_collision_as_override(
                    store,
                    &project,
                    &request.incoming_profile_id,
                    &local_secret_id,
                    &key,
                    &sealing,
                    &identity,
                    now,
                    Some(&authorization),
                )?;
            }
        }
        let configured: bool = store.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM team_sync_folders WHERE project_id=?1 AND enabled=1)",
            [&project],
            |row| row.get(0),
        )?;
        let mut status = if configured {
            match team_sync::sync_folder_guarded(store, &project, &key, now, Some(&authorization)) {
                Ok(status) => status,
                Err(failure) => {
                    let message =
                        format!("Local resolution saved; delivery retry failed: {failure}");
                    store.connection().execute(
                        "UPDATE team_sync_folders SET last_error=?2 WHERE project_id=?1",
                        rusqlite::params![project, message],
                    )?;
                    team_sync::status(store, &project)?
                }
            }
        } else {
            team_sync::status(store, &project)?
        };
        status.pending_details =
            team_sync::pending_profile_details(store, &project, &sealing, &identity, now)?;
        Ok(status)
    })
    .await
}

fn pending_details(
    store: &locket_store::Store,
    project: &str,
    master: &locket_crypto::KeyBytes,
    store_path: &std::path::Path,
    now: i64,
) -> team_sync::Result<Vec<team_sync::PendingProfileDetails>> {
    use locket_platform::{LocalDevicePrivateKeyStorage, MasterKeyStore};
    let local = store
        .get_active_local_device(project)?
        .ok_or_else(|| team_sync::SyncError::Rejected("active local device missing".into()))?;
    let root = store_path
        .parent()
        .ok_or_else(|| team_sync::SyncError::Rejected("local key directory unavailable".into()))?;
    let memory = std::sync::Arc::new(locket_platform::MemoryMasterKeyStore::default());
    memory.store_master_key(project, master)?;
    let storage =
        locket_platform::WrappedLocalFileDevicePrivateKeyStorage::new(root, project, memory);
    let sealing = storage.load(&local.id)?;
    team_sync::pending_profile_details(store, project, &sealing, &team_sync::identity(&local)?, now)
}

fn granted_commit_authorization(
    state: &AgentSocketState,
    scope: &TeamSyncRequest,
    unlock: team_sync::CommitAuthorization,
) -> team_sync::CommitAuthorization {
    let grants = std::sync::Arc::clone(&state.grants);
    let scope = scope.clone();
    std::sync::Arc::new(move || {
        let unlock_guard = unlock()?;
        let guard = std::sync::Arc::clone(&grants).blocking_lock_owned();
        let allowed = match (&scope.grant_id, &scope.profile_id) {
            (Some(grant), Some(profile)) => {
                guard.validate(
                    grant,
                    &scope.project_id,
                    profile,
                    GrantAction::TeamSync,
                    crate::server::current_unix_nanos(),
                    scope.binding.as_ref(),
                ) == GrantValidation::Valid
            }
            _ => false,
        };
        if !allowed {
            return Err(team_sync::SyncError::Rejected(
                "team sync grant expired or changed before commit".into(),
            ));
        }
        Ok(Box::new((unlock_guard, guard)) as Box<dyn Send>)
    })
}

fn commit_authorization(
    state: &AgentSocketState,
    project: &str,
    store_path: &std::path::Path,
    expiry: i128,
    key: &locket_crypto::KeyBytes,
) -> team_sync::CommitAuthorization {
    let cache = std::sync::Arc::clone(&state.unlock_cache);
    let project = project.to_owned();
    let store_path = store_path.to_owned();
    let key = zeroize::Zeroizing::new(*key);
    std::sync::Arc::new(move || {
        // Runs only on the blocking worker. Lock stays responsive during folder
        // I/O; the short commit guard prevents a successful Lock racing a write.
        let guard = std::sync::Arc::clone(&cache).blocking_lock_owned();
        let allowed =
            guard.lookup(&project, crate::server::current_unix_nanos()).is_some_and(|entry| {
                entry.expires_at_unix_nanos() == expiry
                    && entry.key_bytes() == key.as_slice()
                    && entry.audit_context().is_some_and(|context| context.store_path == store_path)
            });
        if !allowed {
            drop(guard);
            return Err(team_sync::SyncError::Rejected(
                "unlock expired or changed before team update commit".into(),
            ));
        }
        Ok(Box::new(guard) as Box<dyn Send>)
    })
}

/// Starts one bounded poll worker. The daemon owns and cancels its task.
#[must_use]
pub fn spawn_team_sync_poll(state: AgentSocketState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {()=state.shutdown.notified()=>break,_=timer.tick()=>{}}
            let projects = {
                let cache = state.unlock_cache.lock().await;
                cache.entries_for_sync().map(|(id, _)| id.to_owned()).collect::<Vec<_>>()
            };
            for project in projects {
                let _ = run_cached_sync(&state, project, None).await;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GrantRecord, GrantRecordFields, UnlockEntry, UnlockMethod};

    async fn cached_projects(path: &std::path::Path) -> AgentSocketState {
        let state = AgentSocketState::locked("test");
        let now = crate::server::current_unix_nanos();
        for project in ["project", "other"] {
            let mut entry = UnlockEntry::new(
                vec![22; 32],
                now,
                std::time::Duration::from_secs(60),
                UnlockMethod::Passphrase,
            );
            if project == "project" {
                entry = entry.with_audit_context(crate::unlock_cache::UnlockAuditContext {
                    store_path: path.to_owned(),
                    profile_id: None,
                });
            }
            state.unlock_cache.lock().await.insert(project.into(), entry);
            state.grants.lock().await.insert(GrantRecord::new(GrantRecordFields {
                grant_id: project.into(),
                project_id: project.into(),
                profile_id: "profile".into(),
                action: GrantAction::TeamSync,
                binding: GrantBinding::new(42, "start"),
                issued_at_unix_nanos: now,
                ttl_seconds: 60,
                expires_at_unix_nanos: now + 60_000_000_000,
            }));
        }
        state
    }

    async fn assert_project_invalidated(state: &AgentSocketState) {
        let now = crate::server::current_unix_nanos();
        let cache = state.unlock_cache.lock().await;
        assert!(cache.lookup("project", now).is_none(), "unsafe project key stayed cached");
        assert!(cache.lookup("other", now).is_some(), "unrelated project was locked");
        drop(cache);
        let grants = state.grants.lock().await;
        assert!(grants.get("project").is_none(), "unsafe project grant stayed live");
        assert!(grants.get("other").is_some(), "unrelated grant was revoked");
        drop(grants);
    }

    fn receiver_store(path: &std::path::Path) -> team_sync::Result<locket_store::Store> {
        let store = open_sync_store(path)?;
        store.insert_project_if_absent("project", "project", 1)?;
        team_sync::store_key(
            &store,
            "project",
            None,
            locket_crypto::KeyPurpose::Audit,
            &[22; 32],
            &[23; 32],
            100,
        )?;
        Ok(store)
    }

    #[tokio::test]
    async fn observed_team_security_state_evicts_only_affected_project()
    -> Result<(), Box<dyn std::error::Error>> {
        for terminal_state in ["removed", "fork"] {
            for via_status in [false, true] {
                let directory = tempfile::tempdir()?;
                let path = directory.path().join("store.db");
                let store = receiver_store(&path)?;
                store.connection().execute(
                    "INSERT INTO team_sync_heads VALUES ('project',1,'digest','[]',?1,1)",
                    [terminal_state],
                )?;
                let state = cached_projects(&path).await;
                if via_status {
                    let request = RequestEnvelope::new(
                        "status",
                        crate::AgentMethod::TeamSyncStatus,
                        serde_json::json!({"project_id":"project"}),
                    );
                    assert!(matches!(
                        handle_team_sync_status(&request, &state).await,
                        ResponseEnvelope::Success(_)
                    ));
                } else {
                    assert_eq!(
                        run_cached_sync(&state, "project".into(), None).await?.state,
                        terminal_state
                    );
                }
                assert_project_invalidated(&state).await;
                let metadata: String = store.connection().query_row(
                    "SELECT metadata_json FROM audit_log WHERE action='LOCK'",
                    [],
                    |row| row.get(0),
                )?;
                let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
                assert_eq!(metadata["source"], "team_sync_invalidated");
                assert_eq!(metadata["cached_keys_cleared"], 1);
                assert_eq!(metadata["live_grants_revoked"], 1);
                assert!(store.verify_audit_chain_read_only("project", &[23; 32])?.hmac_ok);
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // Real signed fork traverses the folder worker's error path.
    async fn observed_team_fork_error_revokes_cached_authorization()
    -> Result<(), Box<dyn std::error::Error>> {
        use locket_core::team_package::{
            DeviceIdentity, SignedStatement, TeamMember, TeamStatement,
        };
        use locket_platform::{LocalDevicePrivateKeyStorage, MasterKeyStore};
        let directory = tempfile::tempdir()?;
        let private = directory.path().join("private");
        let folder = directory.path().join("exchange");
        std::fs::create_dir(&private)?;
        std::fs::create_dir(&folder)?;
        let path = private.join("store.db");
        let mut store = receiver_store(&path)?;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let owner =
            DeviceIdentity::new("owner".into(), signing.verifying_key().to_bytes(), [8; 32]);
        let sealing = [9; 32];
        let local = DeviceIdentity::new(
            "receiver".into(),
            ed25519_dalek::SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(sealing)).to_bytes(),
        );
        store.insert_device(&locket_store::DeviceRecord {
            id: local.id.clone(),
            project_id: "project".into(),
            member_id: None,
            name: "receiver".into(),
            label: "receiver".into(),
            signing_public_key: local.signing_key.to_vec(),
            sealing_public_key: local.sealing_key.to_vec(),
            fingerprint: local.fingerprint.clone(),
            safety_words: vec![],
            local: true,
            created_at: 1,
            last_seen_at: None,
            revoked_at: None,
        })?;
        let now = sync_now()?;
        let mut statement = TeamStatement {
            v: 1,
            team_id: "team".into(),
            project_id: "project".into(),
            epoch: 1,
            previous_digest: String::new(),
            issued_at: now - 1,
            expires_at: now + 300,
            nonce: [4; 24],
            publisher: owner.clone(),
            recipient: local.clone(),
            members: vec![
                TeamMember {
                    id: "owner-member".into(),
                    name: "owner".into(),
                    role: "owner".into(),
                    profiles: vec![],
                    device: owner.clone(),
                    removed: false,
                },
                TeamMember {
                    id: "receiver-member".into(),
                    name: "receiver".into(),
                    role: "developer".into(),
                    profiles: vec![],
                    device: local.clone(),
                    removed: false,
                },
            ],
            profiles: vec![],
        };
        let first = SignedStatement::sign(&statement, &signing)?.seal(&local.sealing_key)?;
        team_sync::apply_package(
            &mut store,
            &first,
            &[22; 32],
            &sealing,
            &local,
            "project",
            Some(&owner.fingerprint),
            now,
        )?;
        let memory = std::sync::Arc::new(locket_platform::MemoryMasterKeyStore::default());
        memory.store_master_key("project", &[22; 32])?;
        locket_platform::WrappedLocalFileDevicePrivateKeyStorage::new(&private, "project", memory)
            .store(&local.id, &sealing)?;
        team_sync::configure_folder(&store, "project", &folder, &private, false)?;
        statement.nonce = [5; 24];
        std::fs::write(
            folder.join("fork.lkpkg"),
            SignedStatement::sign(&statement, &signing)?.seal(&local.sealing_key)?,
        )?;
        let state = cached_projects(&path).await;
        let failure =
            run_cached_sync(&state, "project".into(), None).await.err().ok_or("fork accepted")?;
        assert!(failure.to_string().contains("fork or rollback detected"));
        assert_eq!(team_sync::status(&store, "project")?.state, "fork");
        assert_project_invalidated(&state).await;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn configure_worker_keeps_cache_responsive_and_cannot_insert_after_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("private");
        let folder = directory.path().join("exchange");
        std::fs::create_dir(&root)?;
        std::fs::create_dir(&folder)?;
        let path = root.join("store.db");
        let store = open_sync_store(&path)?;
        store.insert_project_if_absent("project", "fixture", 1)?;
        let owner =
            locket_core::team_package::DeviceIdentity::new("owner".into(), [3; 32], [4; 32]);
        store.connection().execute(
            "INSERT INTO team_sync_anchors VALUES ('project','team',?1,1)",
            [serde_json::to_string(&owner)?],
        )?;
        let state = AgentSocketState::locked("test");
        let entry = UnlockEntry::new(
            vec![42; 32],
            crate::server::current_unix_nanos(),
            std::time::Duration::from_secs(60),
            UnlockMethod::Passphrase,
        )
        .with_audit_context(crate::unlock_cache::UnlockAuditContext {
            store_path: path.clone(),
            profile_id: None,
        });
        let expiry = entry.expires_at_unix_nanos();
        state.unlock_cache.lock().await.insert("project".into(), entry);
        let authorize = commit_authorization(&state, "project", &path, expiry, &[42; 32]);
        let request = TeamSyncConfigureRequest {
            scope: TeamSyncRequest {
                project_id: "project".into(),
                store_path: Some(path.clone()),
                profile_id: None,
                grant_id: None,
                binding: None,
            },
            folder,
            allow_dangerous: false,
        };
        let (started, ready) = tokio::sync::oneshot::channel();
        let (resume, parked) = tokio::sync::oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = parked.blocking_recv();
            configure_store(&open_sync_store(&path)?, &request, &path, &authorize)
        });
        ready.await?;
        let mut cache =
            tokio::time::timeout(std::time::Duration::from_millis(100), state.unlock_cache.lock())
                .await?;
        cache.evict("project");
        drop(cache);
        let _ = resume.send(());
        assert!(worker.await?.is_err());
        assert_eq!(
            store
                .connection()
                .query_row("SELECT COUNT(*) FROM team_sync_folders", [], |row| row
                    .get::<_, i64>(0))?,
            0
        );
        Ok(())
    }

    #[tokio::test]
    async fn locked_status_does_not_migrate_or_change_a_supplied_sqlite_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("foreign.db");
        {
            let connection = rusqlite::Connection::open(&path)?;
            connection.execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES ('keep');")?;
        }
        let before = std::fs::read(&path)?;
        let state = AgentSocketState::locked("test");
        let request = RequestEnvelope::new(
            "status",
            crate::AgentMethod::TeamSyncStatus,
            serde_json::json!({"project_id":"project", "store_path":path}),
        );
        let result = serde_json::to_value(handle_team_sync_status(&request, &state).await)?;
        assert_eq!(result["payload"]["state"], "locked");
        assert_eq!(std::fs::read(&path)?, before);
        assert!(!path.with_extension("db-wal").exists());
        assert!(!path.with_extension("db-shm").exists());
        Ok(())
    }

    #[test]
    fn agent_sync_open_migrates_existing_v5_before_pending_queries()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("store.db");
        {
            let store = open_sync_store(&path)?;
            store.connection().execute_batch("DROP TABLE team_sync_pending_profiles; DROP TABLE team_sync_pending_packages; DELETE FROM schema_migrations WHERE version=6;")?;
        }
        let store = open_sync_store(&path)?;
        assert!(team_sync::status(&store, "project")?.pending_profiles.is_empty());
        assert_eq!(
            store.connection().query_row(
                "SELECT MAX(version) FROM schema_migrations",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            6
        );
        Ok(())
    }

    #[test]
    fn reconciliation_commit_rechecks_revoked_or_expired_process_grant()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentSocketState::locked("test");
        let binding = GrantBinding::new(42, "start");
        let request = TeamSyncRequest {
            project_id: "project".into(),
            store_path: None,
            profile_id: Some("profile".into()),
            grant_id: Some("grant".into()),
            binding: Some(binding.clone()),
        };
        let mut grant = GrantRecord::new(GrantRecordFields {
            grant_id: "grant".into(),
            project_id: "project".into(),
            profile_id: "profile".into(),
            action: GrantAction::TeamSync,
            binding,
            issued_at_unix_nanos: 0,
            ttl_seconds: 60,
            expires_at_unix_nanos: i128::MAX,
        });
        state.grants.blocking_lock().insert(grant.clone());
        let unlocked: team_sync::CommitAuthorization =
            std::sync::Arc::new(|| Ok(Box::new(()) as Box<dyn Send>));
        let authorize = granted_commit_authorization(&state, &request, unlocked);
        drop(authorize()?);
        let _ = state.grants.blocking_lock().revoke("grant");
        assert!(authorize().is_err());
        grant.expires_at_unix_nanos = 0;
        state.grants.blocking_lock().insert(grant);
        assert!(authorize().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn reconciliation_refuses_missing_grant_before_opening_any_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentSocketState::locked("test");
        let request = RequestEnvelope::new(
            "request",
            crate::AgentMethod::TeamSyncReconcile,
            serde_json::json!({"project_id":"project","profile_id":"profile","incoming_profile_id":"incoming", "action":{"kind":"preserve_override","local_secret_id":"local"}}),
        );
        let result = handle_team_sync_reconcile(&request, &state).await;
        let value = serde_json::to_value(result)?;
        assert!(value.to_string().contains("GrantRequired"));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_folder_work_keeps_cache_responsive_and_rejects_post_lock_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentSocketState::locked("test");
        let path = std::path::PathBuf::from("synthetic-store.db");
        let entry = UnlockEntry::new(
            vec![42; 32],
            crate::server::current_unix_nanos(),
            std::time::Duration::from_secs(60),
            UnlockMethod::Passphrase,
        )
        .with_audit_context(crate::unlock_cache::UnlockAuditContext {
            store_path: path.clone(),
            profile_id: None,
        });
        let expiry = entry.expires_at_unix_nanos();
        state.unlock_cache.lock().await.insert("project".into(), entry);
        let authorize = commit_authorization(&state, "project", &path, expiry, &[42; 32]);
        let (started, ready) = tokio::sync::oneshot::channel();
        let (resume, blocked) = tokio::sync::oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = blocked.blocking_recv();
            authorize().is_ok()
        });
        ready.await?;
        let mut cache =
            tokio::time::timeout(std::time::Duration::from_millis(100), state.unlock_cache.lock())
                .await?;
        cache.evict("project");
        drop(cache);
        let _ = resume.send(());
        assert!(!worker.await?);
        Ok(())
    }

    #[tokio::test]
    async fn team_sync_grant_requires_exact_action_scope_and_process()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentSocketState::locked("test");
        let binding = GrantBinding::new(42, "process-start");
        let mut request = TeamSyncRequest {
            project_id: "project".into(),
            store_path: None,
            profile_id: Some("profile".into()),
            grant_id: Some("grant".into()),
            binding: Some(binding.clone()),
        };
        let mut record = GrantRecord::new(GrantRecordFields {
            grant_id: "grant".into(),
            project_id: "project".into(),
            profile_id: "profile".into(),
            action: GrantAction::SetSecret,
            binding,
            issued_at_unix_nanos: 0,
            ttl_seconds: 30,
            expires_at_unix_nanos: i128::MAX,
        });
        state.grants.lock().await.insert(record.clone());
        assert!(!granted(&request, &state).await);
        record.action = GrantAction::TeamSync;
        state.grants.lock().await.insert(record);
        assert!(granted(&request, &state).await);
        request.profile_id = Some("other-profile".into());
        assert!(!granted(&request, &state).await);
        request.profile_id = Some("profile".into());
        request.binding = Some(GrantBinding::new(42, "reused-pid"));
        assert!(!granted(&request, &state).await);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_cached_unlock_does_not_apply_or_poll_configured_folder()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("store.db");
        let mut store = locket_store::Store::open(&path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent("project", "fixture", 1)?;
        store.connection().execute("INSERT INTO team_sync_folders(project_id,path,device_key_root) VALUES ('project',?1,?1)",[directory.path().to_string_lossy()])?;
        let state = AgentSocketState::locked("test");
        state.unlock_cache.lock().await.insert(
            "project".into(),
            UnlockEntry::new(vec![7; 32], 0, std::time::Duration::ZERO, UnlockMethod::Passphrase)
                .with_audit_context(crate::unlock_cache::UnlockAuditContext {
                    store_path: path,
                    profile_id: None,
                }),
        );
        let worker = spawn_team_sync_poll(state);
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        worker.abort();
        let _ = worker.await;
        let last_error: Option<String> = store.connection().query_row(
            "SELECT last_error FROM team_sync_folders WHERE project_id='project'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(last_error, None);
        assert_eq!(team_sync::status(&store, "project")?.epoch, 0);
        Ok(())
    }
}
