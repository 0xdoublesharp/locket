//! Team sync RPCs use the current agent unlock and explicit local grants.
#![allow(missing_docs)]
use crate::team_sync::{self, SyncStatus};
use crate::{
    AgentSocketState, ErrorEnvelope, GrantAction, GrantBinding, GrantValidation, RequestEnvelope,
    ResponseEnvelope, SuccessEnvelope, TeamSyncTransportConfigureInput,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TeamSyncTransportConfigureInput>,
    #[serde(default)]
    pub allow_dangerous: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TeamSyncTestRemoteRequest {
    #[serde(flatten)]
    pub scope: TeamSyncRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TeamSyncTransportConfigureInput>,
}
#[cfg(test)]
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
async fn granted(
    request: &TeamSyncRequest,
    state: &AgentSocketState,
    require_dangerous: bool,
) -> bool {
    let (Some(grant), Some(profile)) = (&request.grant_id, &request.profile_id) else {
        return false;
    };
    let table = state.grants.lock().await;
    table.validate(
        grant,
        &request.project_id,
        profile,
        GrantAction::TeamSync,
        crate::server::current_unix_nanos(),
        request.binding.as_ref(),
    ) == GrantValidation::Valid
        && (!require_dangerous || table.get(grant).is_some_and(|record| record.confirm_dangerous))
}
pub async fn handle_team_sync_status(
    request: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<TeamSyncRequest>(request.payload.clone()) else {
        return error(request, "ProtocolError", "invalid sync status request");
    };
    let (path, pin, unlocked) = {
        let cache = state.unlock_cache.lock().await;
        let entry = cache.lookup(&typed.project_id, crate::server::current_unix_nanos());
        let context = entry.and_then(crate::UnlockEntry::audit_context);
        if let Some(context) = context
            && check_selected_store(typed.store_path.as_deref(), &context.store_path).is_err()
        {
            return error(request, "AccessDenied", "selected store differs from unlock context");
        }
        let path = context.map(|context| context.store_path.clone()).or(typed.store_path);
        let pin = entry.and_then(|entry| entry.store_identity.clone());
        let unlocked = entry.is_some();
        drop(cache);
        (path, pin, unlocked)
    };
    let project = typed.project_id.clone();
    let worker_state = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        let Some(path) = path.filter(|path| path.is_file()) else {
            return Ok(SyncStatus::default());
        };
        let (mut store, _) = worker_state
            .open_store(&path, pin.as_ref(), !unlocked)
            .map_err(locket_store::StoreError::from)?;
        if unlocked {
            store.initialize_schema()?;
        }
        let result = team_sync::status(&store, &project);
        if unlocked { result } else { Ok(result.unwrap_or_default()) }
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
    let Ok(typed) = TeamSyncConfigureRequest::deserialize(&request.payload) else {
        return error(request, "ProtocolError", "invalid sync configuration");
    };
    if !granted(&typed.scope, state, typed.allow_dangerous).await {
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
    let (key, context, expiry, pin) = cached_sync_context(state, &project).await?;
    let authorization = granted_commit_authorization(
        state,
        &request.scope,
        request.allow_dangerous,
        commit_authorization(state, &project, &context.store_path, expiry, &key),
    );
    run_sync_worker(state, project, context.store_path.clone(), pin, move |store| {
        configure_store(store, request, &context.store_path, Some(&key), &authorization)
    })
    .await
}
fn configure_store(
    store: &locket_store::Store,
    request: TeamSyncConfigureRequest,
    store_path: &std::path::Path,
    master: Option<&locket_crypto::KeyBytes>,
    authorization: &team_sync::CommitAuthorization,
) -> team_sync::Result<SyncStatus> {
    check_selected_store(request.scope.store_path.as_deref(), store_path)?;
    let root = store_path
        .parent()
        .ok_or_else(|| team_sync::SyncError::Rejected("local key directory unavailable".into()))?;
    match (request.folder, request.transport) {
        (Some(folder), None) => team_sync::configure_folder_guarded(
            store,
            &request.scope.project_id,
            &folder,
            root,
            request.allow_dangerous,
            Some(authorization),
        )?,
        (None, Some(transport)) => {
            let (config, credentials) = transport.into_parts()?;
            team_sync::configure_transport_guarded(
                store,
                &request.scope.project_id,
                config,
                credentials,
                root,
                master,
                request.allow_dangerous,
                Some(authorization),
            )?;
        }
        _ => return Err(team_sync::SyncError::Rejected("select one team sync transport".into())),
    }
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

pub async fn handle_team_sync_clear(
    request: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<TeamSyncRequest>(request.payload.clone()) else {
        return error(request, "ProtocolError", "invalid sync clear request");
    };
    if !granted(&typed, state, false).await {
        return error(request, "GrantRequired", "explicit local grant required for team sync");
    }
    match clear_cached_transport(state, typed).await {
        Ok(status) => response(request, status),
        Err(failure) => error(request, "TeamSyncRejected", &failure.to_string()),
    }
}

async fn clear_cached_transport(
    state: &AgentSocketState,
    request: TeamSyncRequest,
) -> team_sync::Result<SyncStatus> {
    let project = request.project_id.clone();
    let (key, context, expiry, pin) = cached_sync_context(state, &project).await?;
    let authorization = granted_commit_authorization(
        state,
        &request,
        false,
        commit_authorization(state, &project, &context.store_path, expiry, &key),
    );
    run_sync_worker(state, project.clone(), context.store_path.clone(), pin, move |store| {
        check_selected_store(request.store_path.as_deref(), &context.store_path)?;
        let commit_guard = authorization()?;
        team_sync::clear_transport(store, &project)?;
        drop(commit_guard);
        team_sync::status(store, &project)
    })
    .await
}

pub async fn handle_team_sync_now(
    request: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<TeamSyncRequest>(request.payload.clone()) else {
        return error(request, "ProtocolError", "invalid sync request");
    };
    if !granted(&typed, state, false).await {
        return error(request, "GrantRequired", "explicit local grant required for team sync");
    }
    match run_cached_sync(state, typed.project_id.clone(), Some(typed)).await {
        Ok(status) => response(request, status),
        Err(failure) => error(request, "TeamSyncRejected", &failure.to_string()),
    }
}

pub async fn handle_team_sync_test_remote(
    request: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let Ok(typed) = TeamSyncTestRemoteRequest::deserialize(&request.payload) else {
        return error(request, "ProtocolError", "invalid remote test request");
    };
    if !granted(&typed.scope, state, false).await {
        return error(request, "GrantRequired", "explicit local grant required for team sync");
    }
    match test_cached_remote(state, typed).await {
        Ok(result) => response(request, result),
        Err(failure) => error(request, "TeamSyncRejected", &failure.to_string()),
    }
}

async fn test_cached_remote(
    state: &AgentSocketState,
    request: TeamSyncTestRemoteRequest,
) -> team_sync::Result<team_sync::RemoteTestResult> {
    let project = request.scope.project_id.clone();
    let (key, context, expiry, pin) = cached_sync_context(state, &project).await?;
    let authorization = granted_commit_authorization(
        state,
        &request.scope,
        false,
        commit_authorization(state, &project, &context.store_path, expiry, &key),
    );
    tokio::task::spawn_blocking({
        let state = state.clone();
        move || {
            check_selected_store(request.scope.store_path.as_deref(), &context.store_path)?;
            let (store, _) = state
                .open_store(&context.store_path, pin.as_ref(), true)
                .map_err(locket_store::StoreError::from)?;
            // Recheck authorization after opening the store, without holding a
            // live unlock guard during network I/O.
            drop(authorization()?);
            if let Some(transport) = request.transport {
                let (config, credentials) = transport.into_parts()?;
                if config.credential_mode() == team_sync::CredentialMode::Env {
                    return Err(team_sync::SyncError::Rejected(
                        "save the transport before testing environment credentials".into(),
                    ));
                }
                team_sync::test_transport(&config, credentials)
            } else {
                team_sync::test_configured_transport(&store, &project, Some(&key))
            }
        }
    })
    .await
    .map_err(|_| team_sync::SyncError::Rejected("team sync worker failed".into()))?
}

async fn run_cached_sync(
    state: &AgentSocketState,
    project: String,
    request: Option<TeamSyncRequest>,
) -> team_sync::Result<SyncStatus> {
    let (key, context, expiry, pin) = cached_sync_context(state, &project).await?;
    let unlock = commit_authorization(state, &project, &context.store_path, expiry, &key);
    let authorization = match &request {
        Some(request) => granted_commit_authorization(state, request, false, unlock),
        None => unlock,
    };
    run_sync_worker(state, project.clone(), context.store_path.clone(), pin, move |store| {
        let selected_store = request.as_ref().and_then(|request| request.store_path.as_deref());
        check_selected_store(selected_store, &context.store_path)?;
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
    pin: Option<crate::keys::StoreFileIdentity>,
    operation: impl FnOnce(&mut locket_store::Store) -> team_sync::Result<SyncStatus> + Send + 'static,
) -> team_sync::Result<SyncStatus> {
    let worker_project = project.clone();
    let worker_state = state.clone();
    let worker = tokio::task::spawn_blocking(move || -> team_sync::Result<_> {
        let (mut store, _) = worker_state.open_store(&store_path, pin.as_ref(), false)
            .map_err(locket_store::StoreError::from)?;
        store.initialize_schema()?;
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
    Option<crate::keys::StoreFileIdentity>,
)> {
    {
        let cache = state.unlock_cache.lock().await;
        let entry = cache
            .lookup(project, crate::server::current_unix_nanos())
            .ok_or_else(|| team_sync::SyncError::Rejected("unlock the selected project".into()))?;
        let context = entry.audit_context().cloned().ok_or_else(|| {
            team_sync::SyncError::Rejected("unlock context lacks store path".into())
        })?;
        let key = crate::keys::master_key_array(entry.key_bytes())
            .map_err(|_| team_sync::SyncError::Rejected("invalid cached key".into()))?;
        let result = (key, context, entry.expires_at_unix_nanos(), entry.store_identity.clone());
        drop(cache);
        Ok(result)
    }
}

async fn unlocked_pending_details(
    state: &AgentSocketState,
    project: String,
) -> team_sync::Result<Vec<team_sync::PendingProfileDetails>> {
    let (key, context, _, pin) = cached_sync_context(state, &project).await?;
    let worker_state = state.clone();
    tokio::task::spawn_blocking(move || {
        let (store, _) = worker_state
            .open_store(&context.store_path, pin.as_ref(), true)
            .map_err(locket_store::StoreError::from)?;
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
    if !granted(&typed.scope, state, false).await {
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
    let (key, context, expiry, pin) = cached_sync_context(state, &project).await?;
    let authorization = granted_commit_authorization(
        state,
        &request.scope,
        false,
        commit_authorization(state, &project, &context.store_path, expiry, &key),
    );
    run_sync_worker(state, project.clone(), context.store_path.clone(), pin, move |store| {
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
    require_dangerous: bool,
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
                    && (!require_dangerous
                        || guard.get(grant).is_some_and(|record| record.confirm_dangerous))
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
                    && entry.store_identity.as_ref().is_none_or(|pin| pin.matches(&store_path))
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
            let mut record = GrantRecord::new(GrantRecordFields {
                grant_id: project.into(),
                project_id: project.into(),
                profile_id: "profile".into(),
                action: GrantAction::TeamSync,
                binding: crate::tests::test_process_binding(),
                issued_at_unix_nanos: now,
                ttl_seconds: 60,
                expires_at_unix_nanos: now + 60_000_000_000,
            });
            record.observed_peer_pid = Some(record.binding.pid);
            state.grants.lock().await.insert(record);
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
    async fn clear_transport_requires_live_grant_and_preserves_trust()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{AgentMethod, tests::dispatch_as_current_process};
        use serde_json::json;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("store.db");
        let store = receiver_store(&path)?;
        let owner =
            locket_core::team_package::DeviceIdentity::new("owner".into(), [3; 32], [4; 32]);
        let owner_json = serde_json::to_string(&owner)?;
        store.connection().execute(
            "INSERT INTO team_sync_anchors VALUES ('project','team',?1,1)",
            [&owner_json],
        )?;
        store.connection().execute_batch(
            "INSERT INTO team_sync_heads VALUES ('project',3,'head','[]','verified',4);
             INSERT INTO team_sync_seen VALUES ('project','predecessor',2,'verified');
             INSERT INTO team_sync_join_checkpoints VALUES ('project',2);",
        )?;
        let state = cached_projects(&path).await;
        let scope = json!({
            "project_id": "project", "store_path": path, "profile_id": "profile",
            "grant_id": "project", "binding": crate::tests::test_process_binding(),
        });
        let mut configuration = scope.clone();
        configuration["transport"] = json!({
            "kind": "webdav", "url": "https://fixture.example/team/", "auth_kind": "bearer",
            "credential_mode": "vault", "secret": "fixture-token",
        });
        let configure =
            RequestEnvelope::new("configure", AgentMethod::TeamSyncConfigure, configuration);
        assert!(matches!(
            dispatch_as_current_process(&configure, &state).await,
            ResponseEnvelope::Success(_)
        ));

        let clear = RequestEnvelope::new("clear", AgentMethod::TeamSyncClear, scope);
        assert_eq!(clear.kind, "team_sync.clear");
        let grant = state.grants.lock().await.revoke("project").ok_or("missing grant")?;
        assert!(matches!(dispatch_as_current_process(&clear, &state).await,
            ResponseEnvelope::Error(error) if error.error == "GrantRequired"));
        let credential_exists = || {
            store.connection().query_row(
                "SELECT EXISTS(SELECT 1 FROM team_sync_credentials WHERE project_id='project')",
                [],
                |row| row.get::<_, bool>(0),
            )
        };
        assert!(credential_exists()?);
        assert_eq!(team_sync::status(&store, "project")?.transport_kind.as_deref(), Some("webdav"));

        state.grants.lock().await.insert(grant);
        let ResponseEnvelope::Success(result) = dispatch_as_current_process(&clear, &state).await
        else {
            return Err("clear rejected a live grant".into());
        };
        let status: SyncStatus = serde_json::from_value(result.payload)?;
        assert!(status.folder.is_none() && status.remote_target.is_none());
        assert!(status.transport_kind.is_none() && status.credential_mode.is_none());
        assert!(!credential_exists()?);
        assert_eq!(status.owner_fingerprint.as_deref(), Some(owner.fingerprint.as_str()));
        assert_eq!(
            (status.epoch, status.state.as_str(), status.last_verified_at),
            (3, "verified", Some(4))
        );
        let history = store.connection().query_row(
            "SELECT owner_json, head.digest, seen.epoch, seen.outcome, checkpoint.epoch
             FROM team_sync_anchors AS anchor
             JOIN team_sync_heads AS head USING (project_id)
             JOIN team_sync_seen AS seen USING (project_id)
             JOIN team_sync_join_checkpoints AS checkpoint USING (project_id)
             WHERE anchor.project_id='project' AND seen.digest='predecessor'",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )?;
        assert_eq!(history, (owner_json, "head".into(), 2, "verified".into(), 2));
        Ok(())
    }

    #[tokio::test]
    async fn sync_rpcs_reject_invalid_scope_and_keep_configured_vault_unchanged()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{AgentMethod, dispatch};
        use serde_json::{Value, json};
        use std::fs;

        let dir = tempfile::tempdir()?;
        let private = dir.path().join("private");
        let share = dir.path().join("share");
        fs::create_dir(&private)?;
        fs::create_dir(&share)?;
        let path = private.join("store.db");
        let store = receiver_store(&path)?;
        let owner =
            locket_core::team_package::DeviceIdentity::new("owner".into(), [3; 32], [4; 32]);
        store.connection().execute(
            "INSERT INTO team_sync_anchors VALUES ('project','team',?1,1)",
            [serde_json::to_string(&owner)?],
        )?;
        let state = cached_projects(&path).await;
        let rpc = |method, payload| {
            let request = RequestEnvelope::new("sync", method, payload);
            let state = &state;
            async move {
                if method == AgentMethod::TeamSyncStatus {
                    dispatch(&request, state).await
                } else {
                    crate::tests::dispatch_as_current_process(&request, state).await
                }
            }
        };
        let mut request = json!({
            "project_id": "project", "store_path": path, "profile_id":"profile",
            "binding": crate::tests::test_process_binding(), "folder": share,
            "incoming_profile_id":"incoming",
            "action":{"kind":"preserve_override","local_secret_id":"local"}
        });
        for method in [
            AgentMethod::TeamSyncStatus,
            AgentMethod::TeamSyncConfigure,
            AgentMethod::TeamSyncClear,
            AgentMethod::TeamSyncNow,
            AgentMethod::TeamSyncTestRemote,
            AgentMethod::TeamSyncReconcile,
        ] {
            assert!(matches!(rpc(method, Value::Null).await,
                ResponseEnvelope::Error(error) if error.error == "ProtocolError"));
            if method != AgentMethod::TeamSyncStatus {
                assert!(matches!(rpc(method, request.clone()).await,
                    ResponseEnvelope::Error(error) if error.error == "GrantRequired"));
            }
        }
        request["grant_id"] = json!("project");
        let mut foreign = request.clone();
        foreign["store_path"] = json!(dir.path().join("different.db"));
        assert!(matches!(rpc(AgentMethod::TeamSyncStatus, foreign.clone()).await,
            ResponseEnvelope::Error(error) if error.error == "AccessDenied"));
        for method in [
            AgentMethod::TeamSyncConfigure,
            AgentMethod::TeamSyncClear,
            AgentMethod::TeamSyncNow,
            AgentMethod::TeamSyncTestRemote,
            AgentMethod::TeamSyncReconcile,
        ] {
            assert!(matches!(rpc(method, foreign.clone()).await,
                ResponseEnvelope::Error(error) if error.error == "TeamSyncRejected"));
        }
        assert!(team_sync::status(&store, "project")?.folder.is_none());
        assert!(matches!(rpc(AgentMethod::TeamSyncNow, request.clone()).await,
            ResponseEnvelope::Success(result) if result.payload["epoch"] == 0));
        assert!(matches!(
            rpc(AgentMethod::TeamSyncConfigure, request.clone()).await,
            ResponseEnvelope::Success(_)
        ));
        assert!(matches!(rpc(AgentMethod::TeamSyncTestRemote, request.clone()).await,
            ResponseEnvelope::Success(result) if result.payload["ok"] == true
                && result.payload["writable_checked"] == false));
        assert!(matches!(rpc(AgentMethod::TeamSyncReconcile, request.clone()).await,
            ResponseEnvelope::Error(error)
                if error.error == "TeamSyncRejected" && error.message.contains("active local device missing")));
        assert!(matches!(rpc(AgentMethod::TeamSyncNow, request.clone()).await,
            ResponseEnvelope::Error(error)
                if error.error == "TeamSyncRejected" && error.message.contains("active local device missing")));
        let status = team_sync::status(&store, "project")?;
        assert!(status.folder.is_some());
        assert_eq!(status.epoch, 0);
        assert!(
            status.last_error.is_some_and(|error| error.contains("active local device missing"))
        );

        request["project_id"] = json!("other");
        request["grant_id"] = json!("other");
        assert!(matches!(rpc(AgentMethod::TeamSyncNow, request).await,
            ResponseEnvelope::Error(error)
                if error.error == "TeamSyncRejected" && error.message.contains("unlock context")));
        assert!(!dir.path().join("different.db").exists());
        Ok(())
    }

    #[test]
    fn shared_vault_team_sync_has_status_and_requires_owner_pin()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let local = directory.path().join("local");
        let folder = directory.path().join("delivery");
        std::fs::create_dir(&local)?;
        std::fs::create_dir(&folder)?;
        let path = local.join("store.db");
        let store = open_sync_store(&path)?;
        let project_id = "lk_proj_shared_team";
        store.insert_project_if_absent(project_id, "@shared", 1)?;
        let request = TeamSyncConfigureRequest {
            scope: TeamSyncRequest {
                project_id: project_id.into(),
                store_path: Some(path.clone()),
                profile_id: None,
                grant_id: None,
                binding: None,
            },
            folder: Some(folder),
            transport: None,
            allow_dangerous: false,
        };
        let authorize: team_sync::CommitAuthorization = std::sync::Arc::new(|| Ok(Box::new(())));
        let result = configure_store(&store, request, &path, None, &authorize);
        assert!(
            matches!(result, Err(team_sync::SyncError::Rejected(reason)) if reason.contains("independent owner pin"))
        );
        let status = team_sync::status(&store, project_id)?;
        assert_eq!(status.state, "unanchored");
        assert!(status.folder.is_none());
        Ok(())
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
    async fn terminal_sync_with_audit_failure_still_erases_cached_authorization()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("store.db");
        let store = receiver_store(&path)?;
        store.connection().execute_batch(
            "INSERT INTO team_sync_heads VALUES ('project',1,'digest','[]','removed',1);
             CREATE TRIGGER deny_lock_audit BEFORE INSERT ON audit_log
             WHEN NEW.action = 'LOCK' BEGIN SELECT RAISE(ABORT, 'fixture denied'); END",
        )?;
        let state = cached_projects(&path).await;
        let request = RequestEnvelope::new(
            "status",
            crate::AgentMethod::TeamSyncStatus,
            serde_json::json!({"project_id":"project"}),
        );
        assert!(matches!(handle_team_sync_status(&request, &state).await,
            ResponseEnvelope::Error(error) if error.error == "MetadataInvalid"
                && error.message == "team lock audit unavailable"));
        assert_project_invalidated(&state).await;
        assert_eq!(team_sync::status(&store, "project")?.state, "removed");
        assert_eq!(store.list_recent_audit_actions("project", 5)?, Vec::<String>::new());
        Ok(())
    }

    #[tokio::test]
    async fn status_never_turns_unreadable_pending_package_into_verified_details()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("store.db");
        let store = receiver_store(&path)?;
        store.connection().execute_batch(
            "INSERT INTO team_sync_heads VALUES ('project',1,'digest','[]','pending-values',1);
             INSERT INTO team_sync_pending_packages VALUES ('project',1,'digest',X'00');
             INSERT INTO team_sync_pending_profiles VALUES ('project','profile','consent-required');",
        )?;
        let state = cached_projects(&path).await;
        let request = RequestEnvelope::new(
            "status",
            crate::AgentMethod::TeamSyncStatus,
            serde_json::json!({"project_id":"project"}),
        );
        assert!(matches!(handle_team_sync_status(&request, &state).await,
            ResponseEnvelope::Success(success)
                if success.payload["state"] == "pending-values"
                    && success.payload["pending_profiles"]["profile"] == "consent-required"
                    && success.payload["pending_details"] == serde_json::json!([])
                    && success.payload["last_error"].as_str().is_some_and(|text| text.contains("active local device missing"))));
        assert_eq!(store.list_profiles("project")?, Vec::<locket_store::ProfileRecord>::new());
        assert!(state.grants.lock().await.get("project").is_some());
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
        let signed = SignedStatement::sign(&statement, &signing)?;
        let first = signed.seal(&local.sealing_key)?;
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
        let state = cached_projects(&path).await;
        let mut valid_update = statement.clone();
        valid_update.nonce = [6; 24];
        valid_update.epoch = 2;
        valid_update.previous_digest = locket_core::team_package::digest(&signed.statement);
        let update_path = folder.join("valid.lkpkg");
        std::fs::write(
            &update_path,
            SignedStatement::sign(&valid_update, &signing)?.seal(&local.sealing_key)?,
        )?;
        let request = TeamSyncRequest {
            project_id: "project".into(),
            store_path: Some(path.clone()),
            profile_id: Some("profile".into()),
            grant_id: Some("withdrawn-grant".into()),
            binding: None,
        };
        let denied = run_cached_sync(&state, "project".into(), Some(request))
            .await
            .err()
            .ok_or("withdrawn team sync grant was accepted")?;
        assert!(denied.to_string().contains("team sync grant expired or changed before commit"));
        assert_eq!(team_sync::status(&store, "project")?.epoch, 1);
        std::fs::remove_file(update_path)?;
        statement.nonce = [5; 24];
        std::fs::write(
            folder.join("fork.lkpkg"),
            SignedStatement::sign(&statement, &signing)?.seal(&local.sealing_key)?,
        )?;
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
            folder: Some(folder),
            transport: None,
            allow_dangerous: false,
        };
        let (started, ready) = tokio::sync::oneshot::channel();
        let (resume, parked) = tokio::sync::oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            let _ = parked.blocking_recv();
            configure_store(&open_sync_store(&path)?, request, &path, None, &authorize)
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
        let authorize = granted_commit_authorization(&state, &request, false, unlocked);
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
        assert!(!granted(&request, &state, false).await);
        record.action = GrantAction::TeamSync;
        state.grants.lock().await.insert(record.clone());
        assert!(granted(&request, &state, false).await);
        assert!(!granted(&request, &state, true).await);
        record.confirm_dangerous = true;
        state.grants.lock().await.insert(record);
        assert!(granted(&request, &state, true).await);
        request.profile_id = Some("other-profile".into());
        assert!(!granted(&request, &state, false).await);
        request.profile_id = Some("profile".into());
        request.binding = Some(GrantBinding::new(42, "reused-pid"));
        assert!(!granted(&request, &state, false).await);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn team_sync_configure_dangerous_and_adhoc_env_test_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("store.db");
        let mut store = locket_store::Store::open(&path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent("project", "fixture", 1)?;
        let state = AgentSocketState::locked("test");
        let binding = GrantBinding::new(42, "start");
        let record = GrantRecord::new(GrantRecordFields {
            grant_id: "grant".into(),
            project_id: "project".into(),
            profile_id: "profile".into(),
            action: GrantAction::TeamSync,
            binding: binding.clone(),
            issued_at_unix_nanos: 0,
            ttl_seconds: 60,
            expires_at_unix_nanos: i128::MAX,
        });
        state.grants.lock().await.insert(record);
        state.unlock_cache.lock().await.insert(
            "project".into(),
            UnlockEntry::new(
                vec![7; 32],
                crate::server::current_unix_nanos(),
                std::time::Duration::from_secs(60),
                UnlockMethod::Passphrase,
            )
            .with_audit_context(crate::unlock_cache::UnlockAuditContext {
                store_path: path.clone(),
                profile_id: Some("profile".into()),
            }),
        );

        let dangerous_configure = RequestEnvelope::new(
            "configure-dangerous",
            crate::AgentMethod::TeamSyncConfigure,
            serde_json::json!({
                "project_id": "project",
                "profile_id": "profile",
                "store_path": path,
                "grant_id": "grant",
                "binding": binding,
                "folder": directory.path(),
                "allow_dangerous": true,
            }),
        );
        let configure_resp =
            serde_json::to_value(handle_team_sync_configure(&dangerous_configure, &state).await)?;
        assert_eq!(configure_resp["error"], "GrantRequired");

        let adhoc_env_test = RequestEnvelope::new(
            "test-env-adhoc",
            crate::AgentMethod::TeamSyncTestRemote,
            serde_json::json!({
                "project_id": "project",
                "profile_id": "profile",
                "store_path": path,
                "grant_id": "grant",
                "binding": binding,
                "transport": {
                    "kind": "webdav",
                    "url": "https://attacker.example/dav",
                    "credential_mode": "env",
                    "auth_kind": "bearer",
                },
            }),
        );
        let test_resp =
            serde_json::to_value(handle_team_sync_test_remote(&adhoc_env_test, &state).await)?;
        assert_eq!(test_resp["error"], "TeamSyncRejected");
        assert!(
            test_resp["message"]
                .as_str()
                .is_some_and(|message| message.contains("environment credentials"))
        );
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
