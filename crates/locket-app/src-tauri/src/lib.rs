//! Tauri 2 desktop shell entry point for Locket.
//!
//! Registers a minimal scoped IPC surface. Each command opts in to the
//! smallest capability set needed for metadata-only desktop views and
//! agent-backed actions.

use std::path::PathBuf;
use std::sync::Mutex;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use tauri::Manager as _;
use tauri::{Emitter as _, RunEvent, Runtime};
use zeroize::Zeroizing;

// Test-only dev-deps; suppress `unused_crate_dependencies` for the lib-test target.
#[cfg(test)]
use locket_store as _;
#[cfg(test)]
use tempfile as _;

mod agent_client;
mod clipboard;
mod desktop_actions;
#[cfg(any(target_os = "macos", test))]
mod launch_agent;
#[cfg(unix)]
mod macos_lifecycle;
mod tray;

#[cfg(all(test, unix))]
mod command_tests;

pub use agent_client::{
    AgentClientError, CancelToken, RECONNECT_INITIAL_BACKOFF, RECONNECT_MAX_BACKOFF, fetch_status,
    invoke_method, next_reconnect_delay, resolve_socket_path, stream_status_events,
    stream_status_events_with_cancel,
};
pub use clipboard::{
    ClipboardCopyDecision, ClipboardCopyOutcome, ClipboardError, ClipboardPlatform,
    ClipboardSession, clipboard_platform, decide_clear,
};
pub use tray::{
    LOCKET_TRAY_ID, TRAY_MENU_ACTION_EVENT, TrayMenuAction, TrayMenuItemEnablement,
    TrayMenuSideEffect, TrayPrivacyContext, TraySelectionState, TrayState, icon_bytes_for,
    refresh_tray_menu, refresh_tray_tooltip, setup_tray, store_privacy_context,
    store_selection_state, tooltip_for, tooltip_for_context, tray_menu_action_enablement,
    tray_menu_action_for_id, tray_menu_action_side_effect, tray_menu_action_view,
    tray_menu_actions, tray_state_for_status, tray_state_for_status_event, update_tray_state,
};

const CONFIG_TOML: &str = "config.toml";

#[derive(Deserialize)]
struct DesktopListSecretsRequest {
    store_path: Option<PathBuf>,
    project_id: String,
    profile_id: String,
    #[serde(default)]
    redact_names: bool,
}

impl DesktopListSecretsRequest {
    fn into_agent_request(self) -> Result<locket_agent::ListSecretsRequest, AgentClientError> {
        Ok(locket_agent::ListSecretsRequest {
            store_path: resolve_path(self.store_path, default_store_path)?,
            project_id: self.project_id,
            profile_id: self.profile_id,
            redact_names: self.redact_names,
        })
    }
}

#[derive(Deserialize)]
struct DesktopDiscoverSecretsRequest {
    store_path: Option<PathBuf>,
    #[serde(flatten)]
    filters: locket_agent::DiscoveryFilters,
}

impl DesktopDiscoverSecretsRequest {
    fn into_agent_request(self) -> Result<locket_agent::DiscoverSecretsRequest, AgentClientError> {
        Ok(locket_agent::DiscoverSecretsRequest {
            store_path: resolve_discovery_store_path(self.store_path)?,
            filters: self.filters,
        })
    }
}

#[derive(Deserialize)]
struct DesktopListProjectsRequest {
    store_path: Option<PathBuf>,
    #[serde(default)]
    redact_names: bool,
}

impl DesktopListProjectsRequest {
    fn into_agent_request(self) -> Result<locket_agent::ListProjectsRequest, AgentClientError> {
        Ok(locket_agent::ListProjectsRequest {
            store_path: resolve_discovery_store_path(self.store_path)?,
            redact_names: self.redact_names,
        })
    }
}

fn resolve_discovery_store_path(path: Option<PathBuf>) -> Result<String, AgentClientError> {
    resolve_path(path, default_store_path)?.into_os_string().into_string().map_err(|_| {
        AgentClientError::Protocol { reason: "Locket store path must be valid Unicode".into() }
    })
}

#[derive(Deserialize)]
struct DesktopListDeviceMembersRequest {
    store_path: Option<PathBuf>,
    project_id: String,
    #[serde(default)]
    redact_names: bool,
    #[serde(default = "default_true")]
    include_revoked_devices: bool,
}

impl DesktopListDeviceMembersRequest {
    fn into_agent_request(
        self,
    ) -> Result<locket_agent::ListDeviceMembersRequest, AgentClientError> {
        Ok(locket_agent::ListDeviceMembersRequest {
            store_path: resolve_path(self.store_path, default_store_path)?,
            project_id: self.project_id,
            redact_names: self.redact_names,
            include_revoked_devices: self.include_revoked_devices,
        })
    }
}

#[derive(Debug, Deserialize)]
struct DesktopReadConfigRequest {
    config_path: Option<PathBuf>,
    store_path: Option<PathBuf>,
    project_id: Option<String>,
    profile_name: Option<String>,
}

impl DesktopReadConfigRequest {
    fn into_agent_request(self) -> Result<locket_agent::ReadConfigRequest, AgentClientError> {
        Ok(locket_agent::ReadConfigRequest {
            config_path: resolve_path(self.config_path, default_config_path)?,
            store_path: self.store_path,
            project_id: self.project_id,
            profile_name: self.profile_name,
        })
    }
}

#[derive(Debug, Deserialize)]
struct DesktopWriteConfigRequest {
    config_path: Option<PathBuf>,
    store_path: Option<PathBuf>,
    project_id: String,
    profile_name: Option<String>,
    #[serde(default)]
    changes: locket_agent::WriteConfigChanges,
}

impl DesktopWriteConfigRequest {
    fn into_agent_request(self) -> Result<locket_agent::WriteConfigRequest, AgentClientError> {
        Ok(locket_agent::WriteConfigRequest {
            config_path: resolve_path(self.config_path, default_config_path)?,
            store_path: resolve_path(self.store_path, default_store_path)?,
            project_id: self.project_id,
            profile_name: self.profile_name,
            changes: self.changes,
        })
    }
}

/// Desktop-side audit-list request.
///
/// Mirrors `locket_agent::ListAuditRequest`, but lets the webview omit
/// `store_path` so the shell can use the same default store location as
/// the CLI without exposing local filesystem details to the frontend.
#[derive(Debug, Deserialize)]
struct DesktopListAuditRequest {
    /// Optional explicit SQLite store path for tests or advanced shells.
    store_path: Option<PathBuf>,
    /// Project id whose audit chain is listed.
    project_id: String,
    /// Optional profile id filter.
    profile_id: Option<String>,
    /// Optional audit action filter.
    action: Option<String>,
    /// Optional audit status filter.
    status: Option<String>,
    /// Optional inclusive lower timestamp bound.
    since_unix_nanos: Option<i64>,
    /// Optional inclusive upper timestamp bound.
    until_unix_nanos: Option<i64>,
    /// Maximum number of recent matching rows.
    limit: Option<u32>,
    /// Whether project/profile/secret/command labels should be aliased.
    #[serde(default)]
    redact_names: bool,
}

#[derive(Debug, Deserialize)]
struct DesktopListVersionsRequest {
    store_path: Option<PathBuf>,
    project_id: String,
    profile_id: String,
    secret_name: Option<String>,
    source: Option<String>,
    now_unix_nanos: i64,
    #[serde(default)]
    redact_names: bool,
}

impl DesktopListVersionsRequest {
    fn into_agent_request(self) -> Result<locket_agent::ListVersionsRequest, AgentClientError> {
        Ok(locket_agent::ListVersionsRequest {
            store_path: resolve_path(self.store_path, default_store_path)?,
            project_id: self.project_id,
            profile_id: self.profile_id,
            secret_name: self.secret_name,
            source: self.source,
            now_unix_nanos: self.now_unix_nanos,
            redact_names: self.redact_names,
        })
    }
}

impl DesktopListAuditRequest {
    fn into_agent_request(self) -> Result<locket_agent::ListAuditRequest, AgentClientError> {
        let store_path = match self.store_path {
            Some(path) => path,
            None => default_store_path()?,
        };
        Ok(locket_agent::ListAuditRequest {
            store_path,
            project_id: self.project_id,
            profile_id: self.profile_id,
            action: self.action,
            status: self.status,
            since_unix_nanos: self.since_unix_nanos,
            until_unix_nanos: self.until_unix_nanos,
            limit: self.limit,
            redact_names: self.redact_names,
        })
    }
}

fn resolve_path(
    explicit: Option<PathBuf>,
    fallback: impl FnOnce() -> Result<PathBuf, AgentClientError>,
) -> Result<PathBuf, AgentClientError> {
    explicit.map_or_else(fallback, Ok)
}

fn project_dirs() -> Result<ProjectDirs, AgentClientError> {
    locket_platform::LocketInstance::current().project_dirs().ok_or_else(|| {
        AgentClientError::Protocol {
            reason: "could not resolve the default Locket data directory".to_owned(),
        }
    })
}

fn default_config_path() -> Result<PathBuf, AgentClientError> {
    Ok(project_dirs()?.config_dir().join(CONFIG_TOML))
}

fn default_store_path() -> Result<PathBuf, AgentClientError> {
    Ok(project_dirs()?.data_dir().join("store.db"))
}

const fn default_true() -> bool {
    true
}

const AGENT_STATUS_EVENT: &str = "agent-status";
const AGENT_STATUS_ERROR_EVENT: &str = "agent-status-error";
const AGENT_STATUS_DISCONNECTED_EVENT: &str = "agent-status-disconnected";

/// Process-wide cancel token shared by every long-lived
/// `SubscribeStatus` task. The Tauri shell flips it on exit so the
/// reconnect loop and the tray subscription join cleanly without
/// leaving the agent's subscriber slot open.
struct StatusSubscription {
    cancel: agent_client::CancelToken,
    started: bool,
}

static STATUS_SUBSCRIPTION: Mutex<Option<StatusSubscription>> = Mutex::new(None);

fn status_subscription_cancel_token() -> agent_client::CancelToken {
    let mut guard = STATUS_SUBSCRIPTION.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(state) = guard.as_ref() {
        return state.cancel.clone();
    }
    let cancel = agent_client::CancelToken::new();
    *guard = Some(StatusSubscription { cancel: cancel.clone(), started: false });
    cancel
}

fn mark_status_subscription_started() -> bool {
    let mut guard = STATUS_SUBSCRIPTION.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let state = guard.get_or_insert_with(|| StatusSubscription {
        cancel: agent_client::CancelToken::new(),
        started: false,
    });
    if state.started {
        return false;
    }
    state.started = true;
    true
}

fn cancel_status_subscription() {
    let guard = STATUS_SUBSCRIPTION.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(state) = guard.as_ref() {
        state.cancel.cancel();
    }
}

/// Tauri command exposing the agent client to the webview.
///
/// Honors `LOCKET_AGENT_SOCKET`, otherwise resolves the platform's user socket
/// or SID-scoped named pipe, and returns metadata-only status or a typed
/// [`AgentClientError`].
#[tauri::command]
async fn agent_status() -> Result<locket_agent::StatusPayload, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    desktop_actions::selected_agent_status(&path).await
}

/// Tauri command bridging `SubscribeStatus` stream frames to webview events.
///
/// Idempotent: the first call wires up the long-lived reconnect loop,
/// subsequent calls are no-ops so the webview can call this on every
/// mount without spawning multiple sockets.
#[tauri::command]
async fn agent_subscribe_status<R: Runtime>(
    app: tauri::AppHandle<R>,
) -> Result<(), AgentClientError> {
    if !mark_status_subscription_started() {
        return Ok(());
    }
    let cancel = status_subscription_cancel_token();
    spawn_status_subscription(app, cancel);
    Ok(())
}

fn spawn_status_subscription<R: Runtime>(
    app: tauri::AppHandle<R>,
    cancel: agent_client::CancelToken,
) {
    tauri::async_runtime::spawn(async move {
        run_status_subscription_loop(app, cancel).await;
    });
}

async fn run_status_subscription_loop<R: Runtime>(
    app: tauri::AppHandle<R>,
    cancel: agent_client::CancelToken,
) {
    let event_app = app.clone();
    agent_client::maintain_status_stream(
        &agent_client::resolve_socket_path(),
        &cancel,
        move |event| {
            let _ = event_app.emit(AGENT_STATUS_EVENT, &event);
        },
        |error| {
            if let Some(error) = error {
                let _ = app.emit(AGENT_STATUS_ERROR_EVENT, &error);
            }
            let _ = app.emit(AGENT_STATUS_DISCONNECTED_EVENT, ());
        },
    )
    .await;
}

/// Tauri command exposing the agent's `Lock` RPC to the webview and tray.
#[tauri::command]
async fn agent_lock() -> Result<(), AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::Lock, &()).await
}

/// Source describing how the agent should derive the unwrapped key.
///
/// Stays distinct from the agent's wire format so we can grow the set
/// of unlock paths without leaking unwrapped keys to the webview.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum UnlockSource {
    Passphrase {
        #[serde(deserialize_with = "deserialize_secret")]
        passphrase: Zeroizing<String>,
    },
    OsKeychain,
}

fn deserialize_secret<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

#[derive(Deserialize, Serialize)]
struct DesktopUnlockAudit {
    #[serde(skip_serializing_if = "Option::is_none")]
    store_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_id: Option<String>,
}

#[derive(Deserialize)]
struct DesktopUnlockRequest {
    project_id: String,
    ttl_seconds: u64,
    source: UnlockSource,
    #[serde(default)]
    audit: Option<DesktopUnlockAudit>,
}

#[derive(Serialize)]
struct AgentUnlockPayload<'a> {
    project_id: &'a str,
    ttl_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    passphrase: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<locket_agent::UnlockMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audit: Option<&'a DesktopUnlockAudit>,
}

impl DesktopUnlockRequest {
    fn agent_payload(&self) -> AgentUnlockPayload<'_> {
        let passphrase = match &self.source {
            UnlockSource::Passphrase { passphrase } => Some(passphrase.as_str()),
            UnlockSource::OsKeychain => None,
        };
        AgentUnlockPayload {
            project_id: &self.project_id,
            ttl_seconds: self.ttl_seconds,
            passphrase,
            method: passphrase.map(|_| locket_agent::UnlockMethod::Passphrase),
            audit: self.audit.as_ref(),
        }
    }
}

/// Tauri command exposing the agent's `Unlock` RPC behind a passphrase
/// fallback. The agent owns the unwrap path: it pulls the master key
/// from the OS keychain when no passphrase is supplied, and from the
/// passphrase-fallback envelope otherwise. The webview never holds the
/// unwrapped key.
#[tauri::command]
async fn agent_unlock(request: DesktopUnlockRequest) -> Result<(), AgentClientError> {
    let payload = request.agent_payload();
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::Unlock, &payload).await
}

#[derive(Debug, Deserialize)]
struct DesktopSetActiveProfileRequest {
    config_path: Option<PathBuf>,
    store_path: Option<PathBuf>,
    project_id: String,
    profile_name: String,
    confirmation: Option<String>,
    #[serde(default)]
    privacy_redact_names: bool,
    root_hash: Option<String>,
}

impl DesktopSetActiveProfileRequest {
    fn into_agent_request(self) -> Result<locket_agent::SetActiveProfileRequest, AgentClientError> {
        if desktop_actions::is_shared_project_id(&self.project_id) {
            return Err(AgentClientError::Protocol {
                reason: "Environments require a connected project folder with locket.toml.".into(),
            });
        }
        let store_path = resolve_path(self.store_path, default_store_path)?;
        let config_path = match self.config_path {
            Some(path) => path,
            None => desktop_actions::project_config_path(&store_path, &self.project_id)
                .map_err(|reason| AgentClientError::Protocol { reason })?,
        };
        Ok(locket_agent::SetActiveProfileRequest {
            config_path,
            store_path,
            project_id: self.project_id,
            profile_name: self.profile_name,
            confirmation: self.confirmation,
            privacy_redact_names: self.privacy_redact_names,
            root_hash: self.root_hash,
        })
    }
}

/// Tauri command exposing the agent's `SetActiveProfile` RPC.
#[tauri::command]
async fn agent_set_active_profile(
    request: DesktopSetActiveProfileRequest,
) -> Result<locket_agent::SetActiveProfileResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let agent_request = request.into_agent_request()?;
    agent_client::invoke_method(&path, locket_agent::AgentMethod::SetActiveProfile, &agent_request)
        .await
}

#[derive(Deserialize)]
struct DesktopValueAccess<T> {
    #[serde(flatten)]
    request: T,
    confirm_dangerous_profile: Option<String>,
}

fn value_access_payload(
    request: impl Serialize,
    confirm_dangerous_profile: Option<String>,
) -> Result<serde_json::Value, AgentClientError> {
    let mut payload = serde_json::to_value(request).map_err(|_| AgentClientError::Protocol {
        reason: "Invalid secret access request.".into(),
    })?;
    payload["confirm_dangerous_profile"] = serde_json::json!(confirm_dangerous_profile);
    Ok(payload)
}

/// Tauri command exposing the agent's `Reveal` RPC to the webview.
///
/// Resolves native project context and obtains a grant before requesting
/// plaintext. The webview owns the reveal's focus, context, and TTL lifetime.
#[tauri::command]
async fn agent_reveal(
    request: DesktopValueAccess<locket_agent::RevealRequest>,
) -> Result<locket_agent::RevealResponse, AgentClientError> {
    let DesktopValueAccess { request, confirm_dangerous_profile } = request;
    let store = resolve_path(request.store_path.clone(), default_store_path)?;
    let project =
        request.project_id.clone().map(Ok).unwrap_or_else(desktop_actions::selected_project_id)?;
    let mut request = request;
    request.store_path = Some(store.clone());
    request.project_id = Some(project.clone());
    desktop_actions::invoke_granted(
        locket_agent::AgentMethod::Reveal,
        locket_agent::GrantAction::Reveal,
        value_access_payload(&request, confirm_dangerous_profile)?,
        &store,
        &project,
        &request.profile_id,
    )
    .await
}

/// Tauri command exposing the agent's `ScanKnownValues` RPC.
#[tauri::command]
async fn agent_scan(
    request: locket_agent::ScanRequest,
) -> Result<locket_agent::ScanResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ScanKnownValues, &request).await
}

/// Tauri command exposing the agent's `ResolveReference` RPC.
#[tauri::command]
async fn agent_resolve(
    request: locket_agent::ResolveRequest,
) -> Result<locket_agent::ResolveResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ResolveReference, &request).await
}

#[derive(Deserialize)]
struct DesktopPrepareExecRequest {
    policy_name: String,
    profile_id: String,
    project_id: String,
    confirm_dangerous_profile: Option<String>,
    binding: Option<locket_agent::GrantBinding>,
}

/// Tauri command exposing the agent's `PrepareExec` RPC.
#[tauri::command]
async fn agent_prepare_exec(
    request: DesktopPrepareExecRequest,
) -> Result<locket_agent::PrepareExecResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let confirmed = desktop_actions::confirm_prepare_exec(
        &default_store_path()?,
        &request.project_id,
        &request.profile_id,
        request.confirm_dangerous_profile.as_deref(),
    )?;
    let payload = locket_agent::PrepareExecRequest {
        policy_name: request.policy_name,
        profile_id: request.profile_id,
        project_id: request.project_id,
        confirm_dangerous: confirmed,
        binding: request.binding,
    };
    agent_client::invoke_method(&path, locket_agent::AgentMethod::PrepareExec, &payload).await
}

#[derive(Debug, Deserialize)]
struct DesktopPolicyDoctorRequest {
    project_id: String,
    profile_id: String,
    policy: locket_agent::CommandPolicySnapshot,
    #[serde(default)]
    references: Vec<String>,
    store_path: Option<PathBuf>,
    #[serde(default)]
    binding: Option<locket_agent::GrantBinding>,
}

impl DesktopPolicyDoctorRequest {
    fn into_agent_request(self) -> Result<locket_agent::PolicyDoctorRequest, AgentClientError> {
        Ok(locket_agent::PolicyDoctorRequest {
            project_id: self.project_id,
            profile_id: self.profile_id,
            policy: self.policy,
            references: self.references,
            store_path: resolve_path(self.store_path, default_store_path)?,
            binding: self.binding,
        })
    }
}

/// Tauri command exposing the agent's command-policy dry-run validator.
#[tauri::command]
async fn agent_policy_doctor(
    request: DesktopPolicyDoctorRequest,
) -> Result<locket_agent::PolicyDoctorResponse, AgentClientError> {
    let agent_request = request.into_agent_request()?;
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::PolicyDoctor, &agent_request)
        .await
}

#[derive(Deserialize)]
struct DesktopExportBundleRequest {
    project_id: String,
    profile_id: Option<String>,
    recipient_descriptor: String,
    scope: locket_agent::BundleExportScope,
    include_audit: bool,
    #[serde(default)]
    include_personal: bool,
    #[serde(default)]
    include_history: bool,
    #[serde(default)]
    preview_only: bool,
    output_path: Option<PathBuf>,
    confirm_dangerous_profile: Option<String>,
}

#[derive(Deserialize)]
struct DesktopImportBundleRequest {
    project_id: String,
    bundle_path: PathBuf,
    include_audit: bool,
    conflict_mode: locket_agent::BundleConflictMode,
    confirm_dangerous_profile: Option<String>,
}

/// Tauri command exposing the agent's typed sealed-bundle export path.
#[tauri::command]
async fn agent_export_bundle(
    request: DesktopExportBundleRequest,
) -> Result<locket_agent::BackupActionResponse, AgentClientError> {
    let payload = locket_agent::ExportBundleRequest {
        project_id: request.project_id,
        profile_id: request.profile_id,
        recipient_descriptor: request.recipient_descriptor,
        scope: request.scope,
        include_audit: request.include_audit,
        include_personal: request.include_personal,
        include_history: request.include_history,
        preview_only: request.preview_only,
        output_path: request.output_path,
        grant_id: None,
        binding: None,
        confirm_dangerous: false,
    };
    desktop_actions::export_bundle(
        &default_store_path()?,
        payload,
        request.confirm_dangerous_profile.as_deref(),
    )
    .await
}

/// Tauri command exposing the agent's typed sealed-bundle import path.
#[tauri::command]
async fn agent_import_bundle(
    request: DesktopImportBundleRequest,
) -> Result<locket_agent::BackupActionResponse, AgentClientError> {
    let payload = locket_agent::ImportBundleRequest {
        project_id: request.project_id,
        bundle_path: request.bundle_path,
        include_audit: request.include_audit,
        conflict_mode: request.conflict_mode,
        grant_id: None,
        binding: None,
        confirm_dangerous: false,
    };
    desktop_actions::import_bundle(
        &default_store_path()?,
        payload,
        request.confirm_dangerous_profile.as_deref(),
    )
    .await
}

/// Tauri command exposing non-destructive sealed-bundle verification.
#[tauri::command]
async fn agent_verify_bundle(
    request: locket_agent::VerifyBundleRequest,
) -> Result<locket_agent::VerifyBundleResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::VerifyBundle, &request).await
}

/// Tauri command exposing the agent's typed recovery-code rotation path.
#[tauri::command]
async fn agent_recovery_rotate(
    request: locket_agent::RecoveryRotateRequest,
) -> Result<locket_agent::BackupActionResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::RecoveryRotate, &request).await
}

/// Tauri command exposing the agent's metadata-only runtime session list.
#[tauri::command]
async fn agent_list_runtime_sessions(
    request: locket_agent::ListRuntimeSessionsRequest,
) -> Result<locket_agent::ListRuntimeSessionsResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListRuntimeSessions, &request)
        .await
}

/// Tauri command exposing the agent's metadata-only saved policy list.
#[tauri::command]
async fn agent_list_policies(
    request: locket_agent::ListPoliciesRequest,
) -> Result<locket_agent::ListPoliciesResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListPolicies, &request).await
}

/// Desktop wrapper for `agent_register_command_policies`. Lets the
/// webview replace the in-agent snapshot for the active project after
/// a create / edit / delete in the UI policy editor.
///
/// `store_path` defaults to the user-default `store.db` so the
/// metadata-only `POLICY_UPDATE` audit row is appended to the same
/// chain the CLI writes.
#[derive(Debug, Deserialize)]
struct DesktopRegisterCommandPoliciesRequest {
    project_id: String,
    policies: Vec<locket_agent::CommandPolicySnapshot>,
    store_path: Option<PathBuf>,
    #[serde(default)]
    audit_profile_id: Option<String>,
}

impl DesktopRegisterCommandPoliciesRequest {
    fn into_agent_request(
        self,
    ) -> Result<locket_agent::RegisterCommandPoliciesRequest, AgentClientError> {
        Ok(locket_agent::RegisterCommandPoliciesRequest {
            project_id: self.project_id,
            policies: self.policies,
            store_path: resolve_path(self.store_path, default_store_path)?,
            audit_profile_id: self.audit_profile_id,
        })
    }
}

/// Tauri command bridging the desktop policy editor to the agent's
/// `RegisterCommandPolicies` RPC.
///
/// The desktop never writes audit rows directly: the agent appends the
/// `POLICY_UPDATE` row server-side. Returning `()` mirrors the CLI
/// pump path so the UI can refresh the metadata list independently
/// once the call lands.
#[tauri::command]
async fn agent_register_command_policies(
    request: DesktopRegisterCommandPoliciesRequest,
) -> Result<(), AgentClientError> {
    let agent_request = request.into_agent_request()?;
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(
        &path,
        locket_agent::AgentMethod::RegisterCommandPolicies,
        &agent_request,
    )
    .await
}

/// Tauri command exposing the agent's metadata-only device/member directory.
#[tauri::command]
async fn agent_list_device_members(
    request: DesktopListDeviceMembersRequest,
) -> Result<locket_agent::ListDeviceMembersResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let request = request.into_agent_request()?;
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListDeviceMembers, &request).await
}

/// Tauri command exposing the agent's metadata-only active-profile secret list.
#[tauri::command]
async fn agent_list_secrets(
    request: DesktopListSecretsRequest,
) -> Result<locket_agent::ListSecretsResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let request = request.into_agent_request()?;
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListSecrets, &request).await
}

#[tauri::command]
async fn agent_discover_secrets(
    request: DesktopDiscoverSecretsRequest,
) -> Result<serde_json::Value, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let request = request.into_agent_request()?;
    agent_client::invoke_method(&path, locket_agent::AgentMethod::DiscoverSecrets, &request).await
}

#[tauri::command]
async fn agent_list_projects(
    request: DesktopListProjectsRequest,
) -> Result<serde_json::Value, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let request = request.into_agent_request()?;
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListProjects, &request).await
}

/// Webview input for the agent's `SetSecret` RPC.
#[derive(Deserialize)]
struct DesktopSetSecretRequest {
    store_path: Option<PathBuf>,
    project_id: String,
    profile_id: String,
    secret_name: String,
    confirm_dangerous_profile: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(deserialize_with = "deserialize_secret")]
    value: Zeroizing<String>,
    #[serde(default)]
    grace_until: Option<i64>,
}

#[derive(Serialize)]
struct AgentSetSecretPayload<'a> {
    store_path: String,
    project_id: &'a str,
    profile_id: &'a str,
    secret_name: &'a str,
    #[serde(skip)]
    confirm_dangerous_profile: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'a str>,
    value: &'a str,
    rotate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    grace_until: Option<i64>,
    grant_id: Option<String>,
    binding: Option<locket_agent::GrantBinding>,
}

impl desktop_actions::GrantPayload for AgentSetSecretPayload<'_> {
    fn confirms_dangerous(&self, profile_name: &str) -> bool {
        desktop_actions::matches_profile_confirmation(self.confirm_dangerous_profile, profile_name)
    }

    fn authorize(
        &mut self,
        grant: &locket_agent::GrantIdPayload,
        binding: locket_agent::GrantBinding,
    ) {
        self.grant_id = Some(grant.grant_id.clone());
        self.binding = Some(binding);
    }
}

impl DesktopSetSecretRequest {
    fn agent_payload(&self, store: &std::path::Path, rotate: bool) -> AgentSetSecretPayload<'_> {
        AgentSetSecretPayload {
            store_path: store.display().to_string(),
            project_id: &self.project_id,
            profile_id: &self.profile_id,
            secret_name: &self.secret_name,
            confirm_dangerous_profile: self.confirm_dangerous_profile.as_deref(),
            source: self.source.as_deref(),
            value: self.value.as_str(),
            rotate,
            grace_until: self.grace_until,
            grant_id: None,
            binding: None,
        }
    }

    async fn submit(
        mut self,
        rotate: bool,
    ) -> Result<locket_agent::SetSecretResponse, AgentClientError> {
        let store = resolve_path(self.store_path.take(), default_store_path)?;
        desktop_actions::invoke_granted(
            locket_agent::AgentMethod::SetSecret,
            locket_agent::GrantAction::SetSecret,
            self.agent_payload(&store, rotate),
            &store,
            &self.project_id,
            &self.profile_id,
        )
        .await
    }
}

/// Tauri command bridging the desktop secret editor to the agent's
/// `SetSecret` RPC for the create-new path. The webview accepts a
/// plaintext value through a password-masked input and forwards it
/// inside a single Tauri invoke; the agent's
/// `set_secret::handle_set_secret` validates the live grant, encrypts
/// the value, and appends a metadata-only audit row server-side.
#[tauri::command]
async fn agent_set_secret(
    request: DesktopSetSecretRequest,
) -> Result<locket_agent::SetSecretResponse, AgentClientError> {
    request.submit(false).await
}

/// Tauri command bridging the desktop secret editor to the agent's
/// `SetSecret` RPC for the rotation path. Identical to `agent_set_secret`
/// but pins `rotate=true` server-side so the agent creates a new
/// version + deprecates the prior one with the supplied grace window.
#[tauri::command]
async fn agent_rotate_secret(
    request: DesktopSetSecretRequest,
) -> Result<locket_agent::SetSecretResponse, AgentClientError> {
    request.submit(true).await
}

/// Tauri command exposing metadata-only desktop settings.
#[tauri::command]
async fn agent_read_config(
    request: DesktopReadConfigRequest,
) -> Result<locket_agent::AgentConfigSettings, AgentClientError> {
    let request = request.into_agent_request()?;
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ReadConfig, &request).await
}

/// Tauri command writing desktop settings through the agent.
#[tauri::command]
async fn agent_write_config(
    request: DesktopWriteConfigRequest,
) -> Result<locket_agent::WriteConfigResponse, AgentClientError> {
    let request = request.into_agent_request()?;
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::WriteConfig, &request).await
}

#[derive(Deserialize)]
struct DesktopVerifyAuditRequest {
    project_id: String,
}

impl DesktopVerifyAuditRequest {
    fn into_agent_request(self) -> Result<locket_agent::VerifyAuditRequest, AgentClientError> {
        Ok(locket_agent::VerifyAuditRequest {
            store_path: default_store_path()?,
            project_id: self.project_id,
        })
    }
}

/// Tauri command exposing the agent's metadata-only audit list.
#[tauri::command]
async fn agent_list_audit(
    request: DesktopListAuditRequest,
) -> Result<locket_agent::ListAuditResponse, AgentClientError> {
    let request = request.into_agent_request()?;
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListAudit, &request).await
}

/// Tauri command exposing read-only audit chain verification.
#[tauri::command]
async fn agent_verify_audit(
    request: DesktopVerifyAuditRequest,
) -> Result<locket_agent::VerifyAuditResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let request = request.into_agent_request()?;
    agent_client::invoke_method(&path, locket_agent::AgentMethod::VerifyAudit, &request).await
}

/// Tauri command exposing the agent's metadata-only secret version history.
#[tauri::command]
async fn agent_list_versions(
    request: DesktopListVersionsRequest,
) -> Result<locket_agent::ListVersionsResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let request = request.into_agent_request()?;
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListVersions, &request).await
}

#[derive(Debug, Deserialize)]
struct DesktopClipboardCopyRequest {
    secret_name: String,
    profile_id: String,
    project_id: Option<String>,
    store_path: Option<PathBuf>,
    confirm_dangerous_profile: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum DesktopClipboardCopyResponse {
    Copied { ttl_seconds: u32 },
    Unsupported { unsupported_reason: String },
}

/// Tauri `agent_copy_secret` command. Calls the agent `Copy` RPC,
/// writes the returned value to the OS clipboard, and schedules a
/// TTL-bound clear that re-reads the clipboard before wiping anything.
/// Returns an `unsupported` shape on Wayland sessions and skips the
/// timer.
#[tauri::command]
async fn agent_copy_secret(
    handoff: tauri::State<'_, desktop_actions::DesktopHandoff>,
    request: DesktopClipboardCopyRequest,
) -> Result<DesktopClipboardCopyResponse, AgentClientError> {
    if matches!(clipboard::clipboard_platform(), clipboard::ClipboardPlatform::Wayland) {
        return Ok(DesktopClipboardCopyResponse::Unsupported {
            unsupported_reason: "wayland-session".to_owned(),
        });
    }
    let store = resolve_path(request.store_path.clone(), default_store_path)?;
    let project =
        request.project_id.clone().map(Ok).unwrap_or_else(desktop_actions::selected_project_id)?;
    let agent_request = locket_agent::CopyRequest {
        secret_name: request.secret_name,
        profile_id: request.profile_id,
        project_id: Some(project.clone()),
        store_path: Some(store.clone()),
        grant_id: None,
        binding: None,
    };
    let response: locket_agent::CopyResponse = desktop_actions::invoke_granted(
        locket_agent::AgentMethod::Copy,
        locket_agent::GrantAction::Copy,
        value_access_payload(&agent_request, request.confirm_dangerous_profile)?,
        &store,
        &project,
        &agent_request.profile_id,
    )
    .await?;
    const MAX_NATIVE_CLIPBOARD_TTL_SECONDS: u32 = 300;
    let ttl_seconds = response.ttl_seconds.min(MAX_NATIVE_CLIPBOARD_TTL_SECONDS);
    (handoff.copy_secret)(response.value, std::time::Duration::from_secs(u64::from(ttl_seconds)))
        .await
        .map_err(|error| AgentClientError::Protocol {
            reason: format!("clipboard write failed: {error}"),
        })?;
    Ok(DesktopClipboardCopyResponse::Copied { ttl_seconds })
}

/// Tauri command pushing a new tray icon state from the webview.
///
/// The frontend's `useTray` composable derives the desired
/// [`TrayState`] from `AgentStatus` and `AgentClientError` and invokes
/// this command on every change. Returns a string error rather than a
/// typed [`AgentClientError`] because tray failures are local rendering
/// faults, not agent protocol faults.
#[tauri::command]
async fn tray_set_state<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: TrayState,
) -> Result<(), String> {
    tray::update_tray_state(&app, state.into()).map_err(|error| error.to_string())
}

/// Tauri command pushing the current vault + secret-selection state
/// into the tray module. The webview invokes this every time the
/// agent's lock state changes or the user picks a different row in the
/// metadata list, so the tray's reveal/copy items stay in sync with
/// [`tray_menu_action_enablement`].
///
/// Carries booleans only — never a secret name, value, or id — so the
/// tray surface remains metadata-only per the desktop spec.
#[tauri::command]
async fn tray_set_selection<R: Runtime>(
    app: tauri::AppHandle<R>,
    selection: TraySelectionState,
) -> Result<(), String> {
    let previous = tray::store_selection_state(selection);
    if previous == selection {
        return Ok(());
    }
    tray::refresh_tray_menu(&app).map_err(|error| error.to_string())
}

/// Tauri command pushing redaction-aware tray tooltip context from the webview.
#[tauri::command]
async fn tray_set_privacy_context<R: Runtime>(
    app: tauri::AppHandle<R>,
    context: TrayPrivacyContext,
) -> Result<(), String> {
    let previous = tray::store_privacy_context(context.clone());
    if previous == context {
        return Ok(());
    }
    tray::refresh_tray_tooltip(&app).map_err(|error| error.to_string())
}

fn register_commands<R: Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    builder.invoke_handler(tauri::generate_handler![
        desktop_actions::desktop_list_projects,
        desktop_actions::desktop_open_project,
        desktop_actions::desktop_open_shared_vault,
        desktop_actions::desktop_inspect_project_folder,
        desktop_actions::desktop_initialize_project,
        desktop_actions::desktop_import_env,
        desktop_actions::desktop_create_profile,
        desktop_actions::desktop_delete_secret,
        desktop_actions::desktop_copy_secret_to_shared,
        desktop_actions::desktop_link_secret,
        desktop_actions::desktop_unlink_secret,
        desktop_actions::desktop_list_shared_usages,
        desktop_actions::desktop_list_duplicates,
        desktop_actions::desktop_detect_commands,
        desktop_actions::desktop_start_agent,
        desktop_actions::desktop_run_policy,
        desktop_actions::desktop_scan_project,
        desktop_actions::desktop_save_policy,
        desktop_actions::desktop_variable_readiness,
        desktop_actions::desktop_team_sync_status,
        desktop_actions::desktop_team_sync_configure,
        desktop_actions::desktop_team_sync_test_remote,
        desktop_actions::desktop_team_sync_clear,
        desktop_actions::desktop_team_sync_now,
        desktop_actions::desktop_team_sync_rename_profile,
        desktop_actions::desktop_team_sync_preserve_override,
        desktop_actions::desktop_get_launch_at_login,
        desktop_actions::desktop_set_launch_at_login,
        desktop_actions::desktop_pick_directory,
        desktop_actions::desktop_pick_file,
        desktop_actions::desktop_copy_text_plain,
        desktop_actions::desktop_mcp_config_snippet,
        agent_status,
        agent_subscribe_status,
        agent_lock,
        agent_unlock,
        agent_set_active_profile,
        agent_reveal,
        agent_scan,
        agent_resolve,
        agent_prepare_exec,
        agent_policy_doctor,
        agent_export_bundle,
        agent_import_bundle,
        agent_verify_bundle,
        agent_recovery_rotate,
        agent_list_runtime_sessions,
        agent_list_policies,
        agent_register_command_policies,
        agent_list_device_members,
        agent_list_secrets,
        agent_discover_secrets,
        agent_list_projects,
        agent_set_secret,
        agent_rotate_secret,
        agent_read_config,
        agent_write_config,
        agent_list_audit,
        agent_verify_audit,
        agent_list_versions,
        agent_copy_secret,
        tray_set_state,
        tray_set_selection,
        tray_set_privacy_context,
    ])
}

fn desktop_builder<R: Runtime>(
    builder: tauri::Builder<R>,
    install_tray: impl FnOnce(&tauri::AppHandle<R>) -> tauri::Result<()> + Send + 'static,
) -> tauri::Builder<R> {
    register_commands(builder.manage(desktop_actions::DesktopHandoff::default()))
        .on_window_event(|window, event| {
            #[cfg(target_os = "macos")]
            if window.label() == "main"
                && let tauri::WindowEvent::CloseRequested { api, .. } = event
            {
                api.prevent_close();
                let _ = window.hide();
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (window, event);
        })
        .setup(move |app| {
            if let Ok(path) = app.path().resource_dir() {
                desktop_actions::set_resource_root(path);
            }
            #[cfg(debug_assertions)]
            {
                if let Some(window) = app.get_webview_window("main") {
                    window.open_devtools();
                }
            }
            install_tray(app.handle())?;
            Ok(())
        })
}

fn run_app<R: Runtime>(
    app: tauri::App<R>,
    #[cfg(unix)] mut owner: macos_lifecycle::DesktopInstance,
) -> tauri::Result<()> {
    #[cfg(unix)]
    {
        let handle = app.handle().clone();
        owner.start(move || {
            let handle_for_show = handle.clone();
            handle.run_on_main_thread(move || tray::show_main_window(&handle_for_show)).is_ok()
        })?;
    }
    #[cfg(unix)]
    let mut instance = Some(owner);

    app.run(move |_app, event| {
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            cancel_status_subscription();
        }
        #[cfg(target_os = "macos")]
        if matches!(event, RunEvent::Reopen { has_visible_windows: false, .. }) {
            tray::show_main_window(_app);
        }
        #[cfg(unix)]
        if matches!(event, RunEvent::Exit) {
            drop(instance.take());
        }
    });
    Ok(())
}

/// Run the Locket desktop application.
///
/// Builds the Tauri 2 app, registers the scoped IPC handlers, sets up
/// the system tray, and — in debug builds only — opens devtools on the
/// main window. Returns the Tauri result so the binary entry point can
/// surface a non-zero exit on startup failure.
///
/// # Errors
///
/// Returns any error produced by Tauri while building or running the
/// application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> tauri::Result<()> {
    #[cfg(unix)]
    let owner = {
        let directories = project_dirs().map_err(std::io::Error::other)?;
        let Some(owner) = macos_lifecycle::DesktopInstance::acquire(directories.data_dir())? else {
            return Ok(());
        };
        owner
    };

    // keyring-core 1.0 requires registering a credential store before any
    // Entry can resolve. A failure here surfaces later as the same error
    // from whichever agent command first touches the keychain.
    let _ = locket_platform::init_platform_keyring();
    let app = desktop_builder(tauri::Builder::default(), tray::setup_tray)
        .build(tauri::generate_context!())?;
    run_app(
        app,
        #[cfg(unix)]
        owner,
    )
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::PathBuf;

    use serde_json::json;

    use super::{
        DesktopListAuditRequest, DesktopListDeviceMembersRequest, DesktopListSecretsRequest,
        DesktopListVersionsRequest, DesktopPolicyDoctorRequest,
        DesktopRegisterCommandPoliciesRequest, DesktopSetActiveProfileRequest,
        DesktopSetSecretRequest, DesktopUnlockRequest, DesktopVerifyAuditRequest,
        DesktopWriteConfigRequest, UnlockSource, default_true,
    };
    use crate::AgentClientError;
    use crate::desktop_actions::GrantPayload as _;

    #[test]
    fn explicit_path_does_not_require_default_directory() -> Result<(), AgentClientError> {
        let path = PathBuf::from("custom/store.db");
        let resolved = super::resolve_path(Some(path.clone()), || {
            Err(AgentClientError::Protocol { reason: "default directory unavailable".to_owned() })
        })?;
        assert_eq!(resolved, path);
        Ok(())
    }

    #[test]
    fn shared_vault_cannot_switch_environments_even_with_an_explicit_config_path() {
        let request = DesktopSetActiveProfileRequest {
            config_path: Some(PathBuf::from("locket.toml")),
            store_path: Some(PathBuf::from("store.db")),
            project_id: "lk_proj_shared_test".into(),
            profile_name: "other".into(),
            confirmation: None,
            privacy_redact_names: false,
            root_hash: None,
        };
        assert!(
            matches!(request.into_agent_request(), Err(AgentClientError::Protocol { reason }) if reason.contains("connected project folder"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn discovery_does_not_lossily_encode_an_explicit_nonunicode_store_path() {
        use std::os::unix::ffi::OsStringExt as _;
        let path = PathBuf::from(std::ffi::OsString::from_vec(b"vault-\xff.db".to_vec()));
        assert!(matches!(super::resolve_discovery_store_path(Some(path)),
            Err(AgentClientError::Protocol { reason }) if reason == "Locket store path must be valid Unicode"));
    }

    #[test]
    fn missing_path_uses_default_or_propagates_lookup_error() -> Result<(), AgentClientError> {
        let path = PathBuf::from("default/store.db");
        assert_eq!(super::resolve_path(None, || Ok(path.clone()))?, path);
        let result = super::resolve_path(None, || {
            Err(AgentClientError::Protocol { reason: "default directory unavailable".to_owned() })
        });
        assert!(
            matches!(result, Err(AgentClientError::Protocol { reason }) if reason == "default directory unavailable")
        );
        Ok(())
    }

    pub(super) fn sample_policy() -> locket_agent::CommandPolicySnapshot {
        locket_agent::CommandPolicySnapshot {
            project_id: "lk_proj_test".to_owned(),
            name: "serve".to_owned(),
            command_kind: "argv".to_owned(),
            command_preview: "npm run dev".to_owned(),
            required_secrets: vec!["DATABASE_URL".to_owned()],
            optional_secrets: vec!["API_KEY".to_owned()],
            allowed_secrets: vec!["API_KEY".to_owned(), "DATABASE_URL".to_owned()],
            confirm: true,
            require_user_verification: true,
            require_agent: true,
            allow_remote_docker: false,
            ttl_seconds: 60,
            env_mode: "strict".to_owned(),
            override_mode: "error".to_owned(),
            updated_at_unix_nanos: 123,
        }
    }

    #[test]
    fn desktop_request_defaults_deserialize_as_expected() -> Result<(), Box<dyn Error>> {
        let members: DesktopListDeviceMembersRequest = serde_json::from_value(json!({
            "project_id": "lk_proj_test"
        }))?;
        assert!(members.include_revoked_devices);
        assert!(!members.redact_names);
        assert!(default_true());

        let versions: DesktopListVersionsRequest = serde_json::from_value(json!({
            "project_id": "lk_proj_test",
            "profile_id": "lk_prof_test",
            "secret_name": null,
            "source": null,
            "now_unix_nanos": 100
        }))?;
        assert!(!versions.redact_names);
        assert!(versions.secret_name.is_none());

        Ok(())
    }

    #[test]
    fn unlock_request_builds_passphrase_and_keychain_payloads() -> Result<(), Box<dyn Error>> {
        let request: DesktopUnlockRequest = serde_json::from_value(serde_json::json!({
            "project_id": "lk_proj_test",
            "ttl_seconds": 900,
            "source": {"kind": "passphrase", "passphrase": "secret"},
            "audit": {"store_path": "/vault/store.db", "profile_id": "lk_prof_test"}
        }))?;
        let payload = serde_json::to_value(request.agent_payload())?;
        assert_eq!(payload["project_id"], "lk_proj_test");
        assert_eq!(payload["ttl_seconds"], 900);
        assert_eq!(payload["method"], "Passphrase");
        assert_eq!(payload["passphrase"], "secret");
        assert_eq!(payload["audit"]["store_path"], "/vault/store.db");
        assert_eq!(payload["audit"]["profile_id"], "lk_prof_test");

        let request = DesktopUnlockRequest {
            project_id: "lk_proj_test".to_owned(),
            ttl_seconds: 60,
            source: UnlockSource::OsKeychain,
            audit: None,
        };
        let payload = serde_json::to_value(request.agent_payload())?;
        assert!(payload.get("passphrase").is_none());
        assert!(payload.get("method").is_none());
        assert!(payload.get("audit").is_none());

        Ok(())
    }

    #[test]
    fn unlock_request_rejects_unknown_sources_during_deserialization() {
        for kind in ["recovery", "future-source"] {
            let request = serde_json::from_value::<DesktopUnlockRequest>(serde_json::json!({
                "project_id": "lk_proj_test",
                "ttl_seconds": 60,
                "source": {"kind": kind},
            }));
            assert!(matches!(request, Err(error) if error.to_string().contains("unknown variant")));
        }
    }

    #[test]
    fn discovery_preserves_filters_and_uses_the_default_store_when_omitted()
    -> Result<(), Box<dyn Error>> {
        let discover: super::DesktopDiscoverSecretsRequest =
            serde_json::from_value(serde_json::json!({
                "store_path": "/vault/store.db",
                "project": "locket",
                "query": "token",
                "limit": 3,
                "redact_names": true,
            }))?;
        let payload = serde_json::to_value(discover.into_agent_request()?)?;
        assert_eq!(payload["store_path"], "/vault/store.db");
        assert_eq!(payload["project"], "locket");
        assert_eq!(payload["query"], "token");
        assert_eq!(payload["limit"], 3);
        assert_eq!(payload["redact_names"], true);

        let list: super::DesktopListProjectsRequest =
            serde_json::from_value(serde_json::json!({}))?;
        let list = list.into_agent_request()?;
        assert_eq!(PathBuf::from(list.store_path), super::default_store_path()?);
        assert!(!list.redact_names);
        Ok(())
    }

    #[test]
    fn desktop_agent_request_conversions_preserve_metadata() -> Result<(), Box<dyn Error>> {
        let store_path = PathBuf::from("/tmp/store.db");
        let config_path = PathBuf::from("/tmp/config.toml");

        let read_config = super::DesktopReadConfigRequest {
            config_path: Some(config_path.clone()),
            store_path: Some(store_path.clone()),
            project_id: Some("lk_proj_test".to_owned()),
            profile_name: Some("dev".to_owned()),
        }
        .into_agent_request()?;
        assert_eq!(read_config.config_path, config_path);
        assert_eq!(read_config.store_path, Some(store_path.clone()));
        assert_eq!(read_config.project_id.as_deref(), Some("lk_proj_test"));

        let write_config = DesktopWriteConfigRequest {
            config_path: Some(PathBuf::from("/tmp/write.toml")),
            store_path: Some(store_path.clone()),
            project_id: "lk_proj_test".to_owned(),
            profile_name: Some("dev".to_owned()),
            changes: locket_agent::WriteConfigChanges::default(),
        }
        .into_agent_request()?;
        assert_eq!(write_config.store_path, store_path);
        assert_eq!(write_config.profile_name.as_deref(), Some("dev"));

        let active_profile = DesktopSetActiveProfileRequest {
            config_path: Some(PathBuf::from("/tmp/active.toml")),
            store_path: Some(PathBuf::from("/tmp/active.db")),
            project_id: "lk_proj_test".to_owned(),
            profile_name: "prod".to_owned(),
            confirmation: Some("prod".to_owned()),
            privacy_redact_names: true,
            root_hash: Some("abc123".to_owned()),
        }
        .into_agent_request()?;
        assert_eq!(active_profile.profile_name, "prod");
        assert_eq!(active_profile.confirmation.as_deref(), Some("prod"));
        assert!(active_profile.privacy_redact_names);
        assert_eq!(active_profile.root_hash.as_deref(), Some("abc123"));

        Ok(())
    }

    #[test]
    fn desktop_list_and_policy_requests_convert_to_agent_shapes() -> Result<(), Box<dyn Error>> {
        let store_path = PathBuf::from("/tmp/store.db");
        let list_audit = DesktopListAuditRequest {
            store_path: Some(store_path.clone()),
            project_id: "lk_proj_test".to_owned(),
            profile_id: Some("lk_prof_test".to_owned()),
            action: Some("UNLOCK".to_owned()),
            status: Some("SUCCESS".to_owned()),
            since_unix_nanos: Some(10),
            until_unix_nanos: Some(20),
            limit: Some(5),
            redact_names: true,
        }
        .into_agent_request()?;
        assert_eq!(list_audit.store_path, store_path);
        assert_eq!(list_audit.action.as_deref(), Some("UNLOCK"));
        assert_eq!(list_audit.limit, Some(5));
        assert!(list_audit.redact_names);

        let list_members = DesktopListDeviceMembersRequest {
            store_path: Some(PathBuf::from("/tmp/members.db")),
            project_id: "lk_proj_test".to_owned(),
            redact_names: true,
            include_revoked_devices: false,
        }
        .into_agent_request()?;
        assert_eq!(list_members.project_id, "lk_proj_test");
        assert!(list_members.redact_names);
        assert!(!list_members.include_revoked_devices);

        let list_secrets = DesktopListSecretsRequest {
            store_path: Some(PathBuf::from("/tmp/secrets.db")),
            project_id: "lk_proj_test".to_owned(),
            profile_id: "lk_prof_test".to_owned(),
            redact_names: true,
        }
        .into_agent_request()?;
        assert_eq!(list_secrets.profile_id, "lk_prof_test");
        assert!(list_secrets.redact_names);

        let list_versions = DesktopListVersionsRequest {
            store_path: Some(PathBuf::from("/tmp/versions.db")),
            project_id: "lk_proj_test".to_owned(),
            profile_id: "lk_prof_test".to_owned(),
            secret_name: Some("DATABASE_URL".to_owned()),
            source: Some("machine-local".to_owned()),
            now_unix_nanos: 42,
            redact_names: true,
        }
        .into_agent_request()?;
        assert_eq!(list_versions.secret_name.as_deref(), Some("DATABASE_URL"));
        assert_eq!(list_versions.source.as_deref(), Some("machine-local"));
        assert_eq!(list_versions.now_unix_nanos, 42);

        let policy = sample_policy();
        let doctor = DesktopPolicyDoctorRequest {
            project_id: "lk_proj_test".to_owned(),
            profile_id: "lk_prof_test".to_owned(),
            policy: policy.clone(),
            references: vec!["lk://dev/DATABASE_URL".to_owned()],
            store_path: Some(PathBuf::from("/tmp/policy.db")),
            binding: None,
        }
        .into_agent_request()?;
        assert_eq!(doctor.policy, policy.clone());
        assert_eq!(doctor.references, ["lk://dev/DATABASE_URL"]);

        let register = DesktopRegisterCommandPoliciesRequest {
            project_id: "lk_proj_test".to_owned(),
            policies: vec![policy],
            store_path: Some(PathBuf::from("/tmp/register.db")),
            audit_profile_id: Some("lk_prof_test".to_owned()),
        }
        .into_agent_request()?;
        assert_eq!(register.policies.len(), 1);
        assert_eq!(register.audit_profile_id.as_deref(), Some("lk_prof_test"));

        Ok(())
    }

    #[test]
    fn desktop_set_secret_and_verify_audit_requests_convert() -> Result<(), Box<dyn Error>> {
        for rotate in [false, true] {
            let request: DesktopSetSecretRequest = serde_json::from_value(json!({
                "project_id": "lk_proj_test",
                "profile_id": "lk_prof_test",
                "secret_name": "DATABASE_URL",
                "source": "machine-local",
                "value": "postgres://localhost/dev",
                "grace_until": 123,
                "grant_id": "ignored",
            }))?;
            let mut payload =
                request.agent_payload(std::path::Path::new("/vault/store.db"), rotate);
            payload.authorize(
                &locket_agent::GrantIdPayload { grant_id: "grant-1".into() },
                locket_agent::GrantBinding::new(std::process::id(), "42"),
            );
            let set_secret: locket_agent::SetSecretRequest =
                serde_json::from_value(serde_json::to_value(payload)?)?;
            assert_eq!(set_secret.store_path, "/vault/store.db");
            assert_eq!(set_secret.source.as_deref(), Some("machine-local"));
            assert_eq!(set_secret.rotate, rotate);
            assert_eq!(set_secret.grace_until, Some(123));
            assert_eq!(set_secret.grant_id.as_deref(), Some("grant-1"));
            assert_eq!(
                set_secret.binding.as_ref().map(|binding| binding.pid),
                Some(std::process::id())
            );
            assert_eq!(set_secret.project_id, "lk_proj_test");
            assert_eq!(set_secret.profile_id, "lk_prof_test");
            assert_eq!(set_secret.secret_name, "DATABASE_URL");
            assert_eq!(set_secret.value, "postgres://localhost/dev");
        }

        let verify = DesktopVerifyAuditRequest { project_id: "lk_proj_test".to_owned() }
            .into_agent_request()?;
        assert_eq!(verify.project_id, "lk_proj_test");
        assert!(verify.store_path.ends_with("store.db"));

        Ok(())
    }
}
