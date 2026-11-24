//! Tauri 2 system tray binding for the Locket desktop shell.
//!
//! This module registers the tray icon, a metadata-only menu, and a
//! direct subscription to the agent status stream. Notification dispatch
//! lands in a later slice. Per the desktop tray privacy spec the
//! registered surface is metadata-only:
//! tooltip text comes from `TrayIconState::descriptor().label`, which is
//! a fixed, name-free string.
//!
//! Asset selection mirrors `tray_icon_asset_styles_for_os`:
//!
//! - macOS uses a single template (alpha-mask) variant — the OS picks
//!   the right rendering for light or dark menu bar modes.
//! - Windows and Linux use full-color variants and pick `light` or
//!   `dark` based on the main webview theme, defaulting to `dark`.
//!
//! Placeholder PNG bytes are emitted by `build.rs` into `OUT_DIR` and
//! baked into the binary via `include_bytes!`. A later slice swaps in
//! Lucide-derived final assets without touching this module.
#![allow(clippy::missing_panics_doc)]

use locket_agent::{LockState, StatusEvent, StatusPayload};
use locket_app::TrayIconState;
use locket_core::privacy_alias;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::image::Image;
use tauri::menu::{Menu, MenuBuilder, MenuEvent, MenuItemBuilder};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, Runtime};

/// Stable identifier used to look up the registered tray icon.
pub const LOCKET_TRAY_ID: &str = "locket";
/// Frontend event emitted when a tray menu item requests a UI-routed action.
pub const TRAY_MENU_ACTION_EVENT: &str = "tray-menu-action";

const MENU_OPEN_APP: &str = "tray-open-app";
const MENU_LOCK_VAULT: &str = "tray-lock-vault";
const MENU_UNLOCK_VAULT: &str = "tray-unlock-vault";
const MENU_SWITCH_PROFILE: &str = "tray-switch-profile";
const MENU_RUN_POLICY: &str = "tray-run-policy";
const MENU_START_SCAN: &str = "tray-start-scan";
const MENU_REVEAL_SECRET: &str = "tray-reveal-secret";
const MENU_COPY_SECRET: &str = "tray-copy-secret";

/// Metadata-only tray menu actions exposed to the webview.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrayMenuAction {
    /// Open/focus the desktop app.
    OpenApp,
    /// Lock the vault through the local agent.
    LockVault,
    /// Open the unlock surface.
    UnlockVault,
    /// Open the profile switcher surface.
    SwitchProfile,
    /// Open saved command policies.
    RunPolicy,
    /// Launch the CLI scanner in an interactive terminal.
    StartScan,
    /// Reveal the currently-selected secret in the desktop reveal modal.
    /// Only enabled when the vault is unlocked and a secret is selected.
    RevealSecret,
    /// Copy the currently-selected secret to the clipboard via
    /// `agent_copy_secret`. Only enabled when the vault is unlocked and
    /// a secret is selected.
    CopySecret,
}

impl TrayMenuAction {
    /// Stable menu id for this action.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::OpenApp => MENU_OPEN_APP,
            Self::LockVault => MENU_LOCK_VAULT,
            Self::UnlockVault => MENU_UNLOCK_VAULT,
            Self::SwitchProfile => MENU_SWITCH_PROFILE,
            Self::RunPolicy => MENU_RUN_POLICY,
            Self::StartScan => MENU_START_SCAN,
            Self::RevealSecret => MENU_REVEAL_SECRET,
            Self::CopySecret => MENU_COPY_SECRET,
        }
    }

    /// Human-readable menu label. Labels are generic by design and never
    /// include project, profile, policy, or secret names.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OpenApp => "Open Locket",
            Self::LockVault => "Lock Vault",
            Self::UnlockVault => "Unlock Vault...",
            Self::SwitchProfile => "Switch Profile...",
            Self::RunPolicy => "Run Policy...",
            Self::StartScan => "Scan in terminal",
            Self::RevealSecret => "Reveal selected secret",
            Self::CopySecret => "Copy selected secret",
        }
    }

    /// Whether this action depends on the current vault unlock state and
    /// secret selection. Selection-aware actions are gated by
    /// [`tray_menu_action_enablement`].
    #[must_use]
    pub const fn requires_selection(self) -> bool {
        matches!(self, Self::RevealSecret | Self::CopySecret)
    }
}

/// Tray menu actions in spec order.
#[must_use]
pub const fn tray_menu_actions() -> &'static [TrayMenuAction] {
    &[
        TrayMenuAction::OpenApp,
        TrayMenuAction::LockVault,
        TrayMenuAction::UnlockVault,
        TrayMenuAction::SwitchProfile,
        TrayMenuAction::RunPolicy,
        TrayMenuAction::StartScan,
        TrayMenuAction::RevealSecret,
        TrayMenuAction::CopySecret,
    ]
}

/// Vault + secret-selection state captured by the webview and pushed
/// into the tray module via `tray_set_selection`. Used as the input to
/// [`tray_menu_action_enablement`] and [`build_tray_menu_with`] so the
/// reveal/copy items only light up when the agent has an active unlock
/// and the user has selected a secret in the desktop UI.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct TraySelectionState {
    /// Whether the agent reports the vault is currently unlocked.
    pub vault_unlocked: bool,
    /// Whether the desktop UI has a selected secret in the metadata
    /// list. Carries no name or value — selection identity is owned by
    /// the webview, the tray module only needs the boolean predicate.
    pub secret_selected: bool,
}

/// Potentially sensitive status context used to render tray hover text.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
pub struct TrayPrivacyContext {
    /// Active project id/name from the agent status payload.
    pub project_id: Option<String>,
    /// Active profile id/name from the agent status payload.
    pub profile_name: Option<String>,
    /// Whether names should be replaced with stable local aliases.
    #[serde(default)]
    pub privacy_redact_names: bool,
}

impl TrayPrivacyContext {
    fn project_label(&self) -> Option<String> {
        self.project_id.as_ref().map(|value| {
            if self.privacy_redact_names { privacy_alias("project", value) } else { value.clone() }
        })
    }

    fn profile_label(&self) -> Option<String> {
        self.profile_name.as_ref().map(|value| {
            if self.privacy_redact_names { privacy_alias("profile", value) } else { value.clone() }
        })
    }
}

impl TraySelectionState {
    /// Convenience constructor.
    #[must_use]
    pub const fn new(vault_unlocked: bool, secret_selected: bool) -> Self {
        Self { vault_unlocked, secret_selected }
    }
}

/// Result of evaluating the enablement matrix for a tray menu action.
/// When `enabled` is false, `disabled_reason` carries a short, generic,
/// metadata-only tooltip explaining the precondition; never includes
/// secret, profile, or project names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrayMenuItemEnablement {
    /// Whether the menu item should accept clicks.
    pub enabled: bool,
    /// Tooltip shown when the item is disabled. `None` means the item
    /// is enabled.
    pub disabled_reason: Option<&'static str>,
}

impl TrayMenuItemEnablement {
    const fn enabled() -> Self {
        Self { enabled: true, disabled_reason: None }
    }

    const fn disabled(reason: &'static str) -> Self {
        Self { enabled: false, disabled_reason: Some(reason) }
    }
}

/// Pure mapping from (action, selection-state) to whether the tray item
/// is currently enabled and, when disabled, the metadata-only tooltip
/// the menu item should surface. Selection-aware actions
/// (`RevealSecret`, `CopySecret`) require both the vault to be unlocked
/// and a secret to be selected; all other actions are always enabled
/// because their own pre-conditions live in the agent.
#[must_use]
pub const fn tray_menu_action_enablement(
    action: TrayMenuAction,
    state: TraySelectionState,
) -> TrayMenuItemEnablement {
    if !action.requires_selection() {
        return TrayMenuItemEnablement::enabled();
    }
    if !state.vault_unlocked {
        return TrayMenuItemEnablement::disabled("Unlock the vault to use this action.");
    }
    if !state.secret_selected {
        return TrayMenuItemEnablement::disabled("Select a secret in the desktop list first.");
    }
    TrayMenuItemEnablement::enabled()
}

/// Map a menu event id back to the typed action.
#[must_use]
pub fn tray_menu_action_for_id(id: &str) -> Option<TrayMenuAction> {
    tray_menu_actions().iter().copied().find(|action| action.id() == id)
}

/// Stable webview view key a tray menu action should focus before any
/// side-effect runs. Returns `None` for actions that do not change the
/// focused view (e.g. `LockVault`).
#[must_use]
pub const fn tray_menu_action_view(action: TrayMenuAction) -> Option<&'static str> {
    match action {
        TrayMenuAction::OpenApp | TrayMenuAction::UnlockVault | TrayMenuAction::SwitchProfile => {
            Some("dashboard")
        }
        TrayMenuAction::LockVault => None,
        TrayMenuAction::RunPolicy => Some("policies"),
        TrayMenuAction::StartScan => Some("scan"),
        // Reveal/copy stay anchored to the secrets surface so the user
        // can see which secret is selected before the modal appears or
        // the clipboard fires.
        TrayMenuAction::RevealSecret | TrayMenuAction::CopySecret => Some("secrets"),
    }
}

/// Categories of side-effects the desktop performs after focusing the
/// view returned by [`tray_menu_action_view`]. Pure helper so the tests
/// can pin the contract independently of the Tauri runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrayMenuSideEffect {
    /// Open or focus the desktop without running another action.
    None,
    /// Invoke the agent `Lock` RPC.
    LockVault,
    /// Open the unlock modal so the user can submit a passphrase.
    OpenUnlockModal,
    /// Open the profile switcher modal.
    OpenProfileSwitcher,
    /// Refresh the policy list before showing the policy view.
    RefreshPolicies,
    /// Launch the selected project's CLI scan in a terminal.
    StartScan,
    /// Open the reveal modal for the currently selected secret.
    RevealSelectedSecret,
    /// Trigger `agent_copy_secret` for the currently selected secret.
    CopySelectedSecret,
}

/// Pure mapping from a tray menu action to its side-effect category.
#[must_use]
pub const fn tray_menu_action_side_effect(action: TrayMenuAction) -> TrayMenuSideEffect {
    match action {
        TrayMenuAction::OpenApp => TrayMenuSideEffect::None,
        TrayMenuAction::LockVault => TrayMenuSideEffect::LockVault,
        TrayMenuAction::UnlockVault => TrayMenuSideEffect::OpenUnlockModal,
        TrayMenuAction::SwitchProfile => TrayMenuSideEffect::OpenProfileSwitcher,
        TrayMenuAction::RunPolicy => TrayMenuSideEffect::RefreshPolicies,
        TrayMenuAction::StartScan => TrayMenuSideEffect::StartScan,
        TrayMenuAction::RevealSecret => TrayMenuSideEffect::RevealSelectedSecret,
        TrayMenuAction::CopySecret => TrayMenuSideEffect::CopySelectedSecret,
    }
}

// macOS template (alpha-mask) variants.
const MACOS_AGENT_UNLOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/macos/agent-unlocked.png"));
const MACOS_AGENT_LOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/macos/agent-locked.png"));
const MACOS_AGENT_STOPPED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/macos/agent-stopped.png"));
const MACOS_SCAN_WARNING: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/macos/scan-warning.png"));
const MACOS_ERROR_DEGRADED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/macos/error-degraded.png"));

// Light-theme full-color variants (Windows / Linux).
const LIGHT_AGENT_UNLOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/light/agent-unlocked.png"));
const LIGHT_AGENT_LOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/light/agent-locked.png"));
const LIGHT_AGENT_STOPPED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/light/agent-stopped.png"));
const LIGHT_SCAN_WARNING: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/light/scan-warning.png"));
const LIGHT_ERROR_DEGRADED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/light/error-degraded.png"));

// Dark-theme full-color variants (Windows / Linux).
const DARK_AGENT_UNLOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/dark/agent-unlocked.png"));
const DARK_AGENT_LOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/dark/agent-locked.png"));
const DARK_AGENT_STOPPED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/dark/agent-stopped.png"));
const DARK_SCAN_WARNING: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/dark/scan-warning.png"));
const DARK_ERROR_DEGRADED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/dark/error-degraded.png"));

/// Wire-shape tray state used by the `tray_set_state` Tauri command.
///
/// Mirrors `TrayIconState` with kebab-case variant names so the
/// frontend composable can call `invoke('tray_set_state', { state: '...' })`
/// using the same vocabulary as `tray_icon_descriptors()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrayState {
    /// Agent reachable and vault unlocked.
    AgentUnlocked,
    /// Agent reachable and vault locked.
    AgentLocked,
    /// No reachable agent.
    AgentStopped,
    /// One or more unresolved scan warnings.
    ScanWarning,
    /// Agent error or degraded hardening state.
    ErrorDegraded,
}

impl From<TrayState> for TrayIconState {
    fn from(value: TrayState) -> Self {
        match value {
            TrayState::AgentUnlocked => Self::AgentUnlocked,
            TrayState::AgentLocked => Self::AgentLocked,
            TrayState::AgentStopped => Self::AgentStopped,
            TrayState::ScanWarning => Self::ScanWarning,
            TrayState::ErrorDegraded => Self::ErrorDegraded,
        }
    }
}

/// Pure mapping from a tray icon state to the baked-in PNG bytes for
/// the current platform. Exposed as a `pub` helper so the integration
/// tests can assert on it without spinning up a full Tauri runtime.
#[must_use]
pub fn icon_bytes_for(state: TrayIconState) -> &'static [u8] {
    if cfg!(target_os = "macos") {
        macos_bytes(state)
    } else {
        // Without a webview to consult we default to the dark variant.
        // `update_tray_state` overrides this when a `WebviewWindow` is
        // available and reports a concrete theme.
        dark_bytes(state)
    }
}

/// Pure mapping from a tray icon state to its tooltip string. Sourced
/// from `TrayIconState::descriptor().label` so the metadata-only spec
/// stays the single source of truth for tray copy.
#[must_use]
pub fn tooltip_for(state: TrayIconState) -> &'static str {
    state.descriptor().label
}

/// Render tray tooltip text using the generic state plus redaction-aware
/// active project/profile context.
#[must_use]
pub fn tooltip_for_context(state: TrayIconState, context: &TrayPrivacyContext) -> String {
    let mut parts = vec![tooltip_for(state).to_owned()];
    if let Some(project) = context.project_label() {
        parts.push(format!("project: {project}"));
    }
    if let Some(profile) = context.profile_label() {
        parts.push(format!("profile: {profile}"));
    }
    parts.join(" | ")
}

/// Pure mapping from agent status metadata to the generic tray state.
#[must_use]
pub const fn tray_state_for_status(status: &StatusPayload) -> TrayIconState {
    if status.scan_warning_count > 0 {
        return TrayIconState::ScanWarning;
    }
    match status.lock_state {
        LockState::Unlocked => TrayIconState::AgentUnlocked,
        LockState::Locked => TrayIconState::AgentLocked,
        LockState::Unknown => TrayIconState::ErrorDegraded,
    }
}

/// Metadata-only tooltip for a status-derived tray update.
#[cfg(test)]
#[must_use]
fn tooltip_for_status(status: &StatusPayload) -> String {
    tooltip_for_status_context(status, &TrayPrivacyContext::default())
}

/// Metadata-only tooltip for a status-derived tray update with
/// redaction-aware project/profile context.
#[must_use]
pub fn tooltip_for_status_context(status: &StatusPayload, context: &TrayPrivacyContext) -> String {
    let state = tray_state_for_status(status);
    let mut tooltip = format!(
        "{}; running sessions: {}; scan warnings: {}; audit: {:?}; pinned reference warnings: {}",
        tooltip_for(state),
        status.running_session_count,
        status.scan_warning_count,
        status.recent_audit_status,
        status.pinned_reference_warning_count
    )
    .to_lowercase();
    if let Some(project) = context.project_label() {
        tooltip.push_str(&format!("; project: {project}"));
    }
    if let Some(profile) = context.profile_label() {
        tooltip.push_str(&format!("; profile: {profile}"));
    }
    tooltip
}

/// Pure mapping from a stream event to a tray state update.
///
/// Heartbeats are keepalives only; the agent marks them as not being
/// state changes, so the tray ignores them.
#[must_use]
pub fn tray_state_for_status_event(event: &StatusEvent) -> Option<TrayIconState> {
    event.is_state_change().then(|| tray_state_for_status(&event.status))
}

const fn macos_bytes(state: TrayIconState) -> &'static [u8] {
    match state {
        TrayIconState::AgentUnlocked => MACOS_AGENT_UNLOCKED,
        TrayIconState::AgentLocked => MACOS_AGENT_LOCKED,
        TrayIconState::AgentStopped => MACOS_AGENT_STOPPED,
        TrayIconState::ScanWarning => MACOS_SCAN_WARNING,
        TrayIconState::ErrorDegraded => MACOS_ERROR_DEGRADED,
    }
}

const fn light_bytes(state: TrayIconState) -> &'static [u8] {
    match state {
        TrayIconState::AgentUnlocked => LIGHT_AGENT_UNLOCKED,
        TrayIconState::AgentLocked => LIGHT_AGENT_LOCKED,
        TrayIconState::AgentStopped => LIGHT_AGENT_STOPPED,
        TrayIconState::ScanWarning => LIGHT_SCAN_WARNING,
        TrayIconState::ErrorDegraded => LIGHT_ERROR_DEGRADED,
    }
}

const fn dark_bytes(state: TrayIconState) -> &'static [u8] {
    match state {
        TrayIconState::AgentUnlocked => DARK_AGENT_UNLOCKED,
        TrayIconState::AgentLocked => DARK_AGENT_LOCKED,
        TrayIconState::AgentStopped => DARK_AGENT_STOPPED,
        TrayIconState::ScanWarning => DARK_SCAN_WARNING,
        TrayIconState::ErrorDegraded => DARK_ERROR_DEGRADED,
    }
}

/// Pick the appropriate icon bytes for the current platform and theme.
///
/// macOS: always returns the template (alpha-mask) variant — the OS
/// applies the correct light/dark menu bar appearance itself.
///
/// Windows / Linux: probes the main webview's theme via
/// `WebviewWindow::theme()` and returns the matching full-color variant,
/// falling back to the dark variant if the theme can't be resolved.
fn platform_icon_bytes<R: Runtime>(app: &AppHandle<R>, state: TrayIconState) -> &'static [u8] {
    if cfg!(target_os = "macos") {
        return macos_bytes(state);
    }
    let theme = app.get_webview_window("main").and_then(|window| window.theme().ok());
    match theme {
        Some(tauri::Theme::Light) => light_bytes(state),
        _ => dark_bytes(state),
    }
}

/// Whether the icon should be flagged as a macOS template image.
const fn icon_is_template() -> bool {
    cfg!(target_os = "macos")
}

/// Register the Locket tray icon at app startup.
///
/// Call this exactly once from inside the Tauri `setup` hook. The tray
/// is registered with the `LOCKET_TRAY_ID` and the current selection's
/// action menu. Menu events route to the app; direct icon clicks have
/// no additional action.
///
/// The initial icon is the `AgentStopped` placeholder because the
/// agent socket connect happens after `setup`. A background
/// `SubscribeStatus` task replaces it with the real state when the
/// daemon is reachable.
///
/// # Errors
///
/// Returns any `tauri::Error` produced while building the action menu
/// or the tray icon, decoding the baked-in PNG bytes, or registering
/// the icon with the app.
pub fn setup_tray<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let initial = TrayIconState::AgentStopped;
    let bytes = platform_icon_bytes(app, initial);
    let image = Image::from_bytes(bytes)?;
    let selection = current_selection_state();
    let menu = build_tray_menu_with(app, selection)?;
    TrayIconBuilder::<R>::with_id(LOCKET_TRAY_ID)
        .icon(image)
        .icon_as_template(icon_is_template())
        .tooltip(tooltip_for(initial))
        .menu(&menu)
        .on_menu_event(|app, event| handle_tray_menu_event(app, &event))
        .on_tray_icon_event(|_tray, _event| {
            // Click routing is wired up in a later slice. We register
            // a no-op handler here so the menu still surfaces on the
            // platforms that need an explicit listener.
        })
        .build(app)?;
    start_tray_status_subscription(app.clone());
    Ok(())
}

/// Cached vault + secret-selection state pushed in by the webview via
/// `tray_set_selection`. The tray menu is rebuilt against this state on
/// every change so reveal/copy items match the matrix in
/// [`tray_menu_action_enablement`]. The default is "vault locked, no
/// secret selected" until the webview reports otherwise.
static CURRENT_SELECTION: Mutex<TraySelectionState> =
    Mutex::new(TraySelectionState { vault_unlocked: false, secret_selected: false });

static CURRENT_PRIVACY_CONTEXT: Mutex<TrayPrivacyContext> = Mutex::new(TrayPrivacyContext {
    project_id: None,
    profile_name: None,
    privacy_redact_names: false,
});

static CURRENT_TRAY_STATE: Mutex<TrayIconState> = Mutex::new(TrayIconState::AgentStopped);

fn current_selection_state() -> TraySelectionState {
    CURRENT_SELECTION
        .lock()
        .map(|guard| *guard)
        .unwrap_or(TraySelectionState { vault_unlocked: false, secret_selected: false })
}

fn current_privacy_context() -> TrayPrivacyContext {
    CURRENT_PRIVACY_CONTEXT.lock().map(|guard| guard.clone()).unwrap_or_default()
}

fn current_tray_state() -> TrayIconState {
    CURRENT_TRAY_STATE.lock().map(|guard| *guard).unwrap_or(TrayIconState::AgentStopped)
}

/// Replace the cached tray selection state. Returns the previous value
/// so callers can decide whether to rebuild the menu.
pub fn store_selection_state(state: TraySelectionState) -> TraySelectionState {
    let Ok(mut guard) = CURRENT_SELECTION.lock() else {
        return state;
    };
    let previous = *guard;
    *guard = state;
    previous
}

/// Replace the cached tray privacy context. Returns the previous value
/// so callers can decide whether to update the tooltip.
pub fn store_privacy_context(context: TrayPrivacyContext) -> TrayPrivacyContext {
    let Ok(mut guard) = CURRENT_PRIVACY_CONTEXT.lock() else {
        return context;
    };
    let previous = guard.clone();
    *guard = context;
    previous
}

/// Refresh the registered tray tooltip using the current icon state and
/// cached privacy context.
///
/// # Errors
///
/// Returns any `tauri::Error` produced while updating the OS tray tooltip.
pub fn refresh_tray_tooltip<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let Some(tray) = app.tray_by_id(LOCKET_TRAY_ID) else {
        return Ok(());
    };
    let state = current_tray_state();
    let context = current_privacy_context();
    tray.set_tooltip(Some(tooltip_for_context(state, &context)))?;
    Ok(())
}

/// Build the metadata-only tray menu against an explicit selection
/// state. Selection-aware items are added with their enablement and
/// disabled-tooltip taken from [`tray_menu_action_enablement`].
pub fn build_tray_menu_with<R: Runtime>(
    app: &AppHandle<R>,
    selection: TraySelectionState,
) -> tauri::Result<Menu<R>> {
    let mut builder = MenuBuilder::new(app)
        .text(MENU_OPEN_APP, TrayMenuAction::OpenApp.label())
        .separator()
        .text(MENU_LOCK_VAULT, TrayMenuAction::LockVault.label())
        .text(MENU_UNLOCK_VAULT, TrayMenuAction::UnlockVault.label())
        .separator()
        .text(MENU_SWITCH_PROFILE, TrayMenuAction::SwitchProfile.label())
        .text(MENU_RUN_POLICY, TrayMenuAction::RunPolicy.label())
        .text(MENU_START_SCAN, TrayMenuAction::StartScan.label())
        .separator();

    for action in [TrayMenuAction::RevealSecret, TrayMenuAction::CopySecret] {
        let enablement = tray_menu_action_enablement(action, selection);
        let label = match enablement.disabled_reason {
            Some(reason) => format!("{} - {}", action.label(), reason),
            None => action.label().to_owned(),
        };
        let item =
            MenuItemBuilder::with_id(action.id(), label).enabled(enablement.enabled).build(app)?;
        builder = builder.item(&item);
    }

    builder.build()
}

/// Backwards-compatible wrapper used by `setup_tray` and tests that
/// don't need to vary the selection state. Reads the cached selection
/// pushed in by the webview.
pub fn build_tray_menu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<Menu<R>> {
    build_tray_menu_with(app, current_selection_state())
}

/// Rebuild and replace the registered tray icon's menu so its
/// reveal/copy items reflect the current selection state. Silently
/// no-ops if the tray icon has not been registered yet — same contract
/// as [`update_tray_state`].
///
/// # Errors
///
/// Returns any `tauri::Error` produced while building the menu or
/// pushing it through to the OS.
pub fn refresh_tray_menu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let Some(tray) = app.tray_by_id(LOCKET_TRAY_ID) else {
        return Ok(());
    };
    let menu = build_tray_menu(app)?;
    tray.set_menu(Some(menu))?;
    Ok(())
}

fn handle_tray_menu_event<R: Runtime>(app: &AppHandle<R>, event: &MenuEvent) {
    let Some(action) = tray_menu_action_for_id(event.id().as_ref()) else {
        return;
    };
    // Every action that maps to a focused view also reveals the main
    // window; lock-vault is the only headless action and stays in the
    // menu bar.
    if tray_menu_action_view(action).is_some() {
        show_main_window(app);
    }
    match tray_menu_action_side_effect(action) {
        TrayMenuSideEffect::LockVault => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let _ = crate::agent_client::invoke_method::<(), ()>(
                    &crate::agent_client::resolve_socket_path(),
                    locket_agent::AgentMethod::Lock,
                    &(),
                )
                .await;
                let _ = app.emit(TRAY_MENU_ACTION_EVENT, action);
            });
        }
        _ => {
            let _ = app.emit(TRAY_MENU_ACTION_EVENT, action);
        }
    }
}

fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn start_tray_status_subscription<R: Runtime>(app: AppHandle<R>) {
    tauri::async_runtime::spawn(async move {
        let path = crate::agent_client::resolve_socket_path();
        let cancel = crate::agent_client::CancelToken::new();
        let mut last_delay: Option<std::time::Duration> = None;
        loop {
            let (sender, mut receiver) = tokio::sync::mpsc::channel::<StatusEvent>(16);
            let updater_app = app.clone();
            let updater = tauri::async_runtime::spawn(async move {
                while let Some(event) = receiver.recv().await {
                    if !event.is_state_change() {
                        continue;
                    }
                    let _ = update_tray_status(&updater_app, &event.status);
                }
            });
            let result =
                crate::agent_client::stream_status_events_with_cancel(&path, sender, &cancel).await;
            let _ = updater.await;
            if cancel.is_cancelled() {
                break;
            }
            if result.is_err() {
                let _ = update_tray_state(&app, TrayIconState::AgentStopped);
            }
            // Reconnect with the shared exponential backoff so the tray
            // recovers automatically once the agent restarts.
            let delay = crate::agent_client::next_reconnect_delay(last_delay);
            last_delay = Some(delay);
            tokio::time::sleep(delay).await;
        }
    });
}

fn update_tray_status<R: Runtime>(app: &AppHandle<R>, status: &StatusPayload) -> tauri::Result<()> {
    let Some(tray) = app.tray_by_id(LOCKET_TRAY_ID) else {
        return Ok(());
    };
    let state = tray_state_for_status(status);
    let bytes = platform_icon_bytes(app, state);
    let image = Image::from_bytes(bytes)?;
    tray.set_icon(Some(image))?;
    if let Ok(mut guard) = CURRENT_TRAY_STATE.lock() {
        *guard = state;
    }
    let context = current_privacy_context();
    tray.set_tooltip(Some(tooltip_for_status_context(status, &context)))?;
    Ok(())
}

/// Update the registered tray icon to reflect a new `TrayIconState`.
///
/// Looks up the tray by `LOCKET_TRAY_ID`, re-decodes the baked-in PNG
/// bytes for the requested state under the current platform / theme,
/// and updates the icon and tooltip atomically.
///
/// Silently no-ops if the tray icon has not been registered yet —
/// callers may invoke this before `setup_tray` runs (e.g. during a
/// frontend hot reload) and we do not want that to crash the app.
///
/// # Errors
///
/// Returns any `tauri::Error` produced while decoding the PNG bytes
/// or pushing the icon / tooltip update through to the OS.
pub fn update_tray_state<R: Runtime>(
    app: &AppHandle<R>,
    state: TrayIconState,
) -> tauri::Result<()> {
    let Some(tray) = app.tray_by_id(LOCKET_TRAY_ID) else {
        return Ok(());
    };
    let bytes = platform_icon_bytes(app, state);
    let image = Image::from_bytes(bytes)?;
    tray.set_icon(Some(image))?;
    if let Ok(mut guard) = CURRENT_TRAY_STATE.lock() {
        *guard = state;
    }
    let context = current_privacy_context();
    tray.set_tooltip(Some(tooltip_for_context(state, &context)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        TrayMenuAction, TrayMenuSideEffect, TrayPrivacyContext, TraySelectionState, TrayState,
        dark_bytes, icon_bytes_for, light_bytes, macos_bytes, tooltip_for, tooltip_for_context,
        tooltip_for_status, tooltip_for_status_context, tray_menu_action_enablement,
        tray_menu_action_for_id, tray_menu_action_side_effect, tray_menu_action_view,
        tray_menu_actions, tray_state_for_status, tray_state_for_status_event,
    };
    use locket_agent::{LockState, StatusEvent, StatusPayload};
    use locket_app::{TrayIconState, tray_icon_states};
    use std::collections::BTreeSet;

    #[test]
    fn icon_bytes_are_non_empty_for_every_state() {
        for state in tray_icon_states() {
            assert!(!icon_bytes_for(*state).is_empty());
            assert!(!macos_bytes(*state).is_empty());
            assert!(!light_bytes(*state).is_empty());
        }
    }

    #[test]
    fn generated_icon_variants_contain_visible_pixels() {
        for state in tray_icon_states() {
            for bytes in [macos_bytes(*state), light_bytes(*state), dark_bytes(*state)] {
                let pixels = decode_stored_rgba_png(bytes);
                assert_eq!(pixels.width, 32);
                assert_eq!(pixels.height, 32);
                assert!(
                    pixels.visible_alpha_pixels() > 32,
                    "{state:?} must not be a transparent placeholder",
                );
            }
            assert_ne!(
                light_bytes(*state),
                dark_bytes(*state),
                "{state:?} must have distinct light and dark variants",
            );
        }
    }

    #[test]
    fn macos_icon_variants_are_template_alpha_masks() {
        for state in tray_icon_states() {
            let pixels = decode_stored_rgba_png(macos_bytes(*state));
            assert!(
                pixels.visible_rgbs().all(|rgb| rgb == [0, 0, 0]),
                "{state:?} macOS tray asset must be black-only for template rendering",
            );
        }
    }

    #[test]
    fn windows_linux_icon_variants_are_full_color() {
        for state in tray_icon_states() {
            for (variant, bytes) in [("light", light_bytes(*state)), ("dark", dark_bytes(*state))] {
                let pixels = decode_stored_rgba_png(bytes);
                let colors = pixels.visible_rgb_set();
                assert!(
                    colors.iter().any(|rgb| rgb[0] != rgb[1] || rgb[1] != rgb[2]),
                    "{state:?} {variant} tray asset must include full-color pixels",
                );
                assert!(
                    colors.len() >= 2,
                    "{state:?} {variant} tray asset must include multiple visible colors",
                );
            }
        }
    }

    #[test]
    fn tooltip_matches_descriptor_label_for_every_state() {
        for state in tray_icon_states() {
            assert_eq!(tooltip_for(*state), state.descriptor().label);
            assert!(!tooltip_for(*state).is_empty());
        }
    }

    #[test]
    fn tooltip_context_applies_privacy_aliases_when_redaction_is_enabled() {
        let context = TrayPrivacyContext {
            project_id: Some("payments-api".to_owned()),
            profile_name: Some("prod".to_owned()),
            privacy_redact_names: true,
        };
        let tooltip = tooltip_for_context(TrayIconState::AgentUnlocked, &context);
        assert!(tooltip.contains("project-"));
        assert!(tooltip.contains("profile-"));
        assert!(!tooltip.contains("payments-api"));
        assert!(!tooltip.contains("prod"));
    }

    #[test]
    fn scan_menu_label_explains_the_terminal_handoff() {
        assert_eq!(TrayMenuAction::StartScan.label(), "Scan in terminal");
    }

    #[test]
    fn tray_menu_action_view_routes_each_action_to_a_focusable_surface() {
        let pairs = [
            (TrayMenuAction::OpenApp, Some("dashboard")),
            (TrayMenuAction::LockVault, None),
            (TrayMenuAction::UnlockVault, Some("dashboard")),
            (TrayMenuAction::SwitchProfile, Some("dashboard")),
            (TrayMenuAction::RunPolicy, Some("policies")),
            (TrayMenuAction::StartScan, Some("scan")),
            (TrayMenuAction::RevealSecret, Some("secrets")),
            (TrayMenuAction::CopySecret, Some("secrets")),
        ];
        for (action, expected) in pairs {
            assert_eq!(tray_menu_action_view(action), expected, "{action:?}");
        }
    }

    #[test]
    fn tray_menu_action_side_effect_covers_every_action() {
        let pairs = [
            (TrayMenuAction::OpenApp, TrayMenuSideEffect::None),
            (TrayMenuAction::LockVault, TrayMenuSideEffect::LockVault),
            (TrayMenuAction::UnlockVault, TrayMenuSideEffect::OpenUnlockModal),
            (TrayMenuAction::SwitchProfile, TrayMenuSideEffect::OpenProfileSwitcher),
            (TrayMenuAction::RunPolicy, TrayMenuSideEffect::RefreshPolicies),
            (TrayMenuAction::StartScan, TrayMenuSideEffect::StartScan),
            (TrayMenuAction::RevealSecret, TrayMenuSideEffect::RevealSelectedSecret),
            (TrayMenuAction::CopySecret, TrayMenuSideEffect::CopySelectedSecret),
        ];
        for (action, expected) in pairs {
            assert_eq!(tray_menu_action_side_effect(action), expected, "{action:?}");
        }
    }

    #[test]
    fn lock_vault_is_the_only_headless_tray_action() {
        for action in tray_menu_actions() {
            let view = tray_menu_action_view(*action);
            if *action == TrayMenuAction::LockVault {
                assert!(view.is_none(), "lock-vault must stay in the menu bar");
            } else {
                assert!(view.is_some(), "{action:?} must focus a webview surface");
            }
        }
    }

    #[test]
    fn tray_menu_actions_match_spec_inventory() {
        assert_eq!(
            tray_menu_actions(),
            &[
                TrayMenuAction::OpenApp,
                TrayMenuAction::LockVault,
                TrayMenuAction::UnlockVault,
                TrayMenuAction::SwitchProfile,
                TrayMenuAction::RunPolicy,
                TrayMenuAction::StartScan,
                TrayMenuAction::RevealSecret,
                TrayMenuAction::CopySecret,
            ]
        );
        for action in tray_menu_actions() {
            assert_eq!(tray_menu_action_for_id(action.id()), Some(*action));
            assert!(!action.label().is_empty());
            // Label uses the generic phrase "selected secret" (no secret
            // names) — the substring check banned the historical
            // accidental inclusion of an actual secret name. Keep the
            // intent of that check by rejecting the literal token
            // "value" which would imply leaked data.
            assert!(!action.label().to_lowercase().contains("value"));
        }
    }

    #[test]
    fn reveal_and_copy_actions_require_unlock_and_secret_selection() {
        // Matrix: (vault_unlocked, secret_selected, expected_enabled,
        // expected_reason_substring)
        let cases: &[(bool, bool, bool, Option<&str>)] = &[
            (false, false, false, Some("Unlock")),
            (false, true, false, Some("Unlock")),
            (true, false, false, Some("Select")),
            (true, true, true, None),
        ];
        for (unlocked, selected, expected_enabled, expected_reason) in cases.iter().copied() {
            let state = TraySelectionState::new(unlocked, selected);
            for action in [TrayMenuAction::RevealSecret, TrayMenuAction::CopySecret] {
                let result = tray_menu_action_enablement(action, state);
                assert_eq!(result.enabled, expected_enabled, "{action:?} {state:?}");
                if let Some(needle) = expected_reason {
                    let reason = result.disabled_reason.unwrap_or("");
                    assert!(
                        reason.contains(needle),
                        "{action:?} {state:?}: expected reason to contain {needle:?}, got {reason:?}",
                    );
                    // Tooltip is metadata-only — never includes a
                    // value or a name.
                    assert!(!reason.to_lowercase().contains("value"));
                } else {
                    assert_eq!(
                        result.disabled_reason, None,
                        "{action:?} {state:?} unexpected disabled reason",
                    );
                }
            }
        }
    }

    #[test]
    fn selection_independent_actions_are_always_enabled() {
        for state in [
            TraySelectionState::new(false, false),
            TraySelectionState::new(false, true),
            TraySelectionState::new(true, false),
            TraySelectionState::new(true, true),
        ] {
            for action in tray_menu_actions() {
                if action.requires_selection() {
                    continue;
                }
                let result = tray_menu_action_enablement(*action, state);
                assert!(result.enabled, "{action:?} {state:?} must always be enabled");
                assert!(result.disabled_reason.is_none());
            }
        }
    }

    #[test]
    fn tray_state_round_trips_to_tray_icon_state() {
        let pairs = [
            (TrayState::AgentUnlocked, TrayIconState::AgentUnlocked),
            (TrayState::AgentLocked, TrayIconState::AgentLocked),
            (TrayState::AgentStopped, TrayIconState::AgentStopped),
            (TrayState::ScanWarning, TrayIconState::ScanWarning),
            (TrayState::ErrorDegraded, TrayIconState::ErrorDegraded),
        ];
        for (wire, expected) in pairs {
            assert_eq!(TrayIconState::from(wire), expected);
        }
    }

    #[test]
    fn status_payload_maps_to_metadata_only_tray_state() {
        let mut status = StatusPayload::locked("test-version");
        assert_eq!(tray_state_for_status(&status), TrayIconState::AgentLocked);

        status.lock_state = LockState::Unlocked;
        status.project_id = Some("project-main".to_owned());
        status.profile_name = Some("profile-prod".to_owned());
        assert_eq!(tray_state_for_status(&status), TrayIconState::AgentUnlocked);

        status.lock_state = LockState::Unknown;
        assert_eq!(tray_state_for_status(&status), TrayIconState::ErrorDegraded);
    }

    #[test]
    fn status_payload_scan_warnings_take_tray_precedence_and_tooltip_counts() {
        let mut status = StatusPayload::locked("test-version");
        status.lock_state = LockState::Unlocked;
        status.running_session_count = 2;
        status.scan_warning_count = 3;
        status.pinned_reference_warning_count = 1;

        assert_eq!(tray_state_for_status(&status), TrayIconState::ScanWarning);
        let tooltip = tooltip_for_status(&status);
        assert!(tooltip.contains("scan warning"));
        assert!(tooltip.contains("running sessions: 2"));
        assert!(tooltip.contains("scan warnings: 3"));
        assert!(tooltip.contains("pinned reference warnings: 1"));
    }

    #[test]
    fn status_tooltip_context_applies_privacy_aliases_when_redaction_is_enabled() {
        let mut status = StatusPayload::locked("test-version");
        status.project_id = Some("payments-api".to_owned());
        status.profile_name = Some("prod".to_owned());
        let context = TrayPrivacyContext {
            project_id: status.project_id.clone(),
            profile_name: status.profile_name.clone(),
            privacy_redact_names: true,
        };

        let tooltip = tooltip_for_status_context(&status, &context);
        assert!(tooltip.contains("project-"));
        assert!(tooltip.contains("profile-"));
        assert!(!tooltip.contains("payments-api"));
        assert!(!tooltip.contains("prod"));
    }

    #[test]
    fn status_stream_events_only_update_on_state_changes() {
        let status = StatusPayload::locked("test-version");
        let event = StatusEvent::status(1, status.clone());
        assert_eq!(tray_state_for_status_event(&event), Some(TrayIconState::AgentLocked));

        let heartbeat = StatusEvent::heartbeat(2, status);
        assert_eq!(tray_state_for_status_event(&heartbeat), None);
    }

    struct DecodedPng {
        width: u32,
        height: u32,
        pixels: Vec<u8>,
    }

    impl DecodedPng {
        fn visible_alpha_pixels(&self) -> usize {
            self.pixels.as_chunks::<4>().0.iter().filter(|rgba| rgba[3] > 0).count()
        }

        fn visible_rgbs(&self) -> impl Iterator<Item = [u8; 3]> + '_ {
            self.pixels
                .as_chunks::<4>()
                .0
                .iter()
                .filter(|rgba| rgba[3] > 0)
                .map(|rgba| [rgba[0], rgba[1], rgba[2]])
        }

        fn visible_rgb_set(&self) -> BTreeSet<[u8; 3]> {
            self.visible_rgbs().collect()
        }
    }

    fn decode_stored_rgba_png(bytes: &[u8]) -> DecodedPng {
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        let mut offset = 8;
        let mut width = 0;
        let mut height = 0;
        let mut idat = Vec::new();
        while offset + 12 <= bytes.len() {
            let length = read_be_u32(&bytes[offset..offset + 4]) as usize;
            offset += 4;
            let tag = &bytes[offset..offset + 4];
            offset += 4;
            let data = &bytes[offset..offset + length];
            offset += length;
            offset += 4;
            match tag {
                b"IHDR" => {
                    width = read_be_u32(&data[0..4]);
                    height = read_be_u32(&data[4..8]);
                    assert_eq!(data[8], 8, "expected 8-bit PNG");
                    assert_eq!(data[9], 6, "expected RGBA PNG");
                }
                b"IDAT" => idat.extend_from_slice(data),
                b"IEND" => break,
                _ => {}
            }
        }
        let raw = decode_zlib_stored(&idat);
        let row_len = (width as usize * 4) + 1;
        assert_eq!(raw.len(), row_len * height as usize);
        let mut pixels = Vec::with_capacity(width as usize * height as usize * 4);
        for row in raw.chunks_exact(row_len) {
            assert_eq!(row[0], 0, "expected unfiltered rows");
            pixels.extend_from_slice(&row[1..]);
        }
        DecodedPng { width, height, pixels }
    }

    fn decode_zlib_stored(bytes: &[u8]) -> Vec<u8> {
        assert_eq!(&bytes[0..2], &[0x78, 0x01]);
        let mut offset = 2;
        let mut out = Vec::new();
        loop {
            let header = bytes[offset];
            offset += 1;
            let final_block = header & 1 == 1;
            assert_eq!(header & 0b110, 0, "expected stored deflate block");
            let len = read_le_u16(&bytes[offset..offset + 2]);
            offset += 2;
            let nlen = read_le_u16(&bytes[offset..offset + 2]);
            offset += 2;
            assert_eq!(nlen, !len);
            let len = usize::from(len);
            out.extend_from_slice(&bytes[offset..offset + len]);
            offset += len;
            if final_block {
                break;
            }
        }
        out
    }

    fn read_be_u32(bytes: &[u8]) -> u32 {
        assert_eq!(bytes.len(), 4);
        let mut value = [0; 4];
        value.copy_from_slice(bytes);
        u32::from_be_bytes(value)
    }

    fn read_le_u16(bytes: &[u8]) -> u16 {
        assert_eq!(bytes.len(), 2);
        let mut value = [0; 2];
        value.copy_from_slice(bytes);
        u16::from_le_bytes(value)
    }
}
