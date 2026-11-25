//! Desktop app and tray shell primitives for Locket.
//!
//! This crate intentionally starts as a thin, non-Tauri skeleton. It gives the
//! workspace a stable `locket-app` crate boundary while the real Tauri v2 app,
//! commands, and frontend are delivered in later slices.

/// Top-level app surfaces described by the desktop spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppSurface {
    /// Full desktop control surface.
    Desktop,
    /// Compact tray or app-bar status surface.
    Tray,
}

/// Primary desktop views required by the v1 desktop spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimaryView {
    /// Project-level dashboard.
    ProjectDashboard,
    /// Profile switcher.
    ProfileSwitcher,
    /// Secret metadata list.
    SecretMetadataList,
    /// Gated secret editor.
    SecretEditor,
    /// Secret version history.
    SecretVersionHistory,
    /// Command policy editor.
    CommandPolicyEditor,
    /// Execution and runtime session monitor.
    ExecutionMonitor,
    /// Scan results.
    ScanResults,
    /// Audit log and verification view.
    AuditLog,
    /// Backup, recovery, and device import/export.
    BackupRecovery,
    /// Settings.
    Settings,
}

/// Tray icon state from the desktop spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrayIconState {
    /// Agent running and vault unlocked.
    AgentUnlocked,
    /// Agent running and vault locked.
    AgentLocked,
    /// No reachable agent.
    AgentStopped,
    /// One or more unresolved scan warnings.
    ScanWarning,
    /// Agent error or degraded hardening state.
    ErrorDegraded,
}

/// Tray icon asset style required for a platform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrayIconAssetStyle {
    /// macOS template image: black-only alpha mask.
    TemplateMask,
    /// Full-color icon for light system themes.
    FullColorLight,
    /// Full-color icon for dark system themes.
    FullColorDark,
}

/// Metadata-only tray icon descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrayIconDescriptor {
    /// State represented by this icon.
    pub state: TrayIconState,
    /// Lucide icon name backing the state.
    pub lucide_icon: &'static str,
    /// Short safe label for accessibility and diagnostics.
    pub label: &'static str,
}

/// Passive tray notification event classes covered by the desktop privacy spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrayNotificationKind {
    /// A reveal or copy flow completed or needs user attention.
    RevealOrCopy,
    /// A reveal, copy, run, or grant request was denied.
    DeniedAccess,
    /// Scan findings are present.
    ScanFinding,
    /// A saved command policy failed during execution.
    ExecutionFailure,
}

/// Potentially sensitive event metadata from core or agent surfaces.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrayNotificationContext<'a> {
    /// Exact secret name, if known. Passive notifications ignore it.
    pub secret_name: Option<&'a str>,
    /// Exact policy name, if known. Passive notifications ignore it.
    pub policy_name: Option<&'a str>,
    /// Exact project name, if known. Passive notifications ignore it.
    pub project_name: Option<&'a str>,
    /// Secret value, if a caller accidentally provides one. Passive notifications ignore it.
    pub secret_value: Option<&'a str>,
    /// Metadata-only scan finding count.
    pub finding_count: Option<u32>,
}

/// Metadata-only passive tray notification copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrayNotification {
    /// Generic notification title.
    pub title: String,
    /// Generic notification body.
    pub body: String,
}

/// User-controlled notification preferences for passive tray routing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrayNotificationPreferences {
    /// Suppress passive tray notifications while enabled.
    pub do_not_disturb: bool,
}

/// Distinct denial reasons surfaced by desktop error views.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialReason {
    /// Vault must be unlocked before the requested action can proceed.
    LockedVault,
    /// No live grant covers the requested action.
    MissingGrant,
    /// A saved policy or role rule denied the action.
    PolicyDenied,
    /// Dangerous-profile safeguards require explicit confirmation.
    DangerousProfile,
    /// The selected device is no longer trusted.
    RevokedDevice,
    /// The invite can no longer be accepted.
    ExpiredInvite,
}

/// Metadata-only copy and recovery affordance for a denial view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenialUxDescriptor {
    /// Denial reason represented by this descriptor.
    pub reason: DenialReason,
    /// Stable UI copy heading.
    pub title: &'static str,
    /// Metadata-only next-action text.
    pub next_action: &'static str,
    /// Primary recovery affordance.
    pub affordance: &'static str,
}

/// Empty setup states called out by the desktop UX spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmptyState {
    /// No local project is available yet.
    NoProject,
    /// No profile exists in the current project.
    NoProfile,
    /// No secret has been created or imported yet.
    NoSecret,
    /// No saved command policy exists yet.
    NoPolicy,
    /// No trusted local agent is running.
    NoAgent,
    /// No local team device key exists yet.
    NoTeamDevice,
}

/// Metadata-only desktop guidance for an empty setup state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptyStateDescriptor {
    /// Empty state represented by this descriptor.
    pub state: EmptyState,
    /// Stable UI copy heading.
    pub title: &'static str,
    /// Short safe explanation.
    pub guidance: &'static str,
    /// Primary setup command to offer.
    pub primary_command: &'static str,
    /// Optional alternate setup command.
    pub secondary_command: Option<&'static str>,
}

/// Desktop accessibility baseline requirements from the UX spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessibilityRequirement {
    /// Every workflow is reachable without a pointer device.
    KeyboardNavigation,
    /// Focus is visible and high-contrast on interactive controls.
    VisibleFocus,
    /// Icon-only and dynamic controls expose non-secret assistive labels.
    ScreenReaderLabels,
    /// Text, controls, warnings, and focus treatments meet contrast budgets.
    SufficientContrast,
    /// Motion and transitions respect reduced-motion preferences.
    ReducedMotion,
    /// Reveal/copy flows never leave secret values in accessibility metadata after TTL expiry.
    PostTtlMetadataScrub,
}

/// Metadata-only checklist entry for desktop accessibility implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessibilityDescriptor {
    /// Requirement represented by this descriptor.
    pub requirement: AccessibilityRequirement,
    /// Stable implementation key for UI tests and component mapping.
    pub key: &'static str,
    /// Safe assistive copy or validation guidance.
    pub guidance: &'static str,
    /// Whether the requirement applies to short-lived plaintext flows.
    pub plaintext_ttl_sensitive: bool,
}

/// Secret version states rendered by the desktop version history view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionHistoryState {
    /// Current active version for a source.
    Current,
    /// Deprecated version retained for grace-window references.
    Deprecated,
    /// Purged version whose value material has been removed.
    Purged,
}

/// Metadata fields rendered by the desktop version history view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionHistoryField {
    /// Version state label.
    State,
    /// Timestamp at which the version became deprecated.
    DeprecatedAt,
    /// Grace-window expiry timestamp.
    GraceUntil,
    /// Whether pinned `lk://...@vN` references remain eligible.
    PinnedReferenceEligibility,
    /// Whether the version still participates in scans.
    ScanInclusion,
    /// Metadata-only rotation audit summary for the deprecation.
    RotationAuditMetadata,
}

/// Metadata-only state descriptor for version history rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionHistoryStateDescriptor {
    /// Version state represented by this descriptor.
    pub state: VersionHistoryState,
    /// Stable display label.
    pub label: &'static str,
    /// Whether the encrypted value material is still retained.
    pub retains_value_material: bool,
    /// Whether deprecated-version grace metadata can make pinned references eligible.
    pub supports_pinned_reference: bool,
}

/// Metadata-only field descriptor for version history columns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionHistoryFieldDescriptor {
    /// Field represented by this descriptor.
    pub field: VersionHistoryField,
    /// Stable implementation key for the UI column.
    pub key: &'static str,
    /// Safe column label.
    pub label: &'static str,
    /// Whether the field is a timestamp.
    pub timestamp: bool,
}

/// Runtime-session states rendered by the desktop execution monitor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMonitorState {
    /// Session has no completion metadata yet.
    Running,
    /// Session completed with exit status zero.
    Completed,
    /// Session completed with a non-zero or signal-derived exit status.
    Failed,
    /// Session is incomplete but its process binding no longer resolves.
    Stale,
}

/// Metadata fields rendered by the desktop execution monitor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMonitorField {
    /// Runtime session identifier.
    SessionId,
    /// Profile identifier or alias.
    Profile,
    /// Command policy name or alias.
    Policy,
    /// Runtime process id and process-start binding.
    ProcessBinding,
    /// Session start timestamp.
    StartedAt,
    /// Session end timestamp.
    EndedAt,
    /// Child process exit status.
    ExitStatus,
    /// Count of retained secret names, never values.
    SecretNameCount,
    /// Spawn and completion audit sequence links.
    AuditSequences,
}

/// Metadata-only state descriptor for execution monitor rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionMonitorStateDescriptor {
    /// State represented by this descriptor.
    pub state: ExecutionMonitorState,
    /// Stable display label.
    pub label: &'static str,
    /// Whether the row represents an active runtime session.
    pub active: bool,
    /// Whether the state should render as a warning.
    pub warning: bool,
}

/// Metadata-only field descriptor for execution monitor columns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionMonitorFieldDescriptor {
    /// Field represented by this descriptor.
    pub field: ExecutionMonitorField,
    /// Stable implementation key for the UI column.
    pub key: &'static str,
    /// Safe column label.
    pub label: &'static str,
    /// Backing `runtime_sessions` column or derived expression.
    pub source: &'static str,
    /// Privacy alias kind to apply when `privacy.redact_names` is enabled.
    pub privacy_alias_kind: Option<&'static str>,
    /// Whether the field is a timestamp.
    pub timestamp: bool,
    /// Whether this field is guaranteed to be names/counts only.
    pub metadata_only: bool,
}

impl DenialReason {
    /// Return the desktop denial view descriptor for this reason.
    #[must_use]
    pub const fn descriptor(self) -> DenialUxDescriptor {
        let (title, next_action, affordance) = match self {
            Self::LockedVault => ("Vault locked", "Unlock the vault to continue.", "unlock-vault"),
            Self::MissingGrant => {
                ("Grant required", "Approve a short-lived grant before retrying.", "request-grant")
            }
            Self::PolicyDenied => {
                ("Policy denied", "Review the saved policy or ask for access.", "open-policy")
            }
            Self::DangerousProfile => (
                "Dangerous profile",
                "Confirm the profile scope before continuing.",
                "confirm-profile",
            ),
            Self::RevokedDevice => {
                ("Device revoked", "Use a trusted device or add a new one.", "manage-devices")
            }
            Self::ExpiredInvite => {
                ("Invite expired", "Request a fresh invite from a maintainer.", "request-invite")
            }
        };
        DenialUxDescriptor { reason: self, title, next_action, affordance }
    }
}

impl VersionHistoryState {
    /// Return the desktop descriptor for this version state.
    #[must_use]
    pub const fn descriptor(self) -> VersionHistoryStateDescriptor {
        let (label, retains_value_material, supports_pinned_reference) = match self {
            Self::Current => ("current", true, true),
            Self::Deprecated => ("deprecated", true, true),
            Self::Purged => ("purged", false, false),
        };
        VersionHistoryStateDescriptor {
            state: self,
            label,
            retains_value_material,
            supports_pinned_reference,
        }
    }
}

impl VersionHistoryField {
    /// Return the desktop descriptor for this version history field.
    #[must_use]
    pub const fn descriptor(self) -> VersionHistoryFieldDescriptor {
        let (key, label, timestamp) = match self {
            Self::State => ("state", "State", false),
            Self::DeprecatedAt => ("deprecated-at", "Deprecated at", true),
            Self::GraceUntil => ("grace-until", "Grace until", true),
            Self::PinnedReferenceEligibility => {
                ("pinned-reference-eligibility", "Pinned reference eligibility", false)
            }
            Self::ScanInclusion => ("scan-inclusion", "Scan inclusion", false),
            Self::RotationAuditMetadata => {
                ("rotation-audit-metadata", "Rotation audit metadata", false)
            }
        };
        VersionHistoryFieldDescriptor { field: self, key, label, timestamp }
    }
}

impl ExecutionMonitorState {
    /// Return the desktop descriptor for this execution monitor state.
    #[must_use]
    pub const fn descriptor(self) -> ExecutionMonitorStateDescriptor {
        let (label, active, warning) = match self {
            Self::Running => ("running", true, false),
            Self::Completed => ("completed", false, false),
            Self::Failed => ("failed", false, true),
            Self::Stale => ("stale", false, true),
        };
        ExecutionMonitorStateDescriptor { state: self, label, active, warning }
    }
}

impl ExecutionMonitorField {
    /// Return the desktop descriptor for this execution monitor field.
    #[must_use]
    pub const fn descriptor(self) -> ExecutionMonitorFieldDescriptor {
        let (key, label, source, privacy_alias_kind, timestamp) = match self {
            Self::SessionId => ("session-id", "Session", "runtime_sessions.id", None, false),
            Self::Profile => {
                ("profile", "Profile", "runtime_sessions.profile_id", Some("profile"), false)
            }
            Self::Policy => {
                ("policy", "Policy", "runtime_sessions.policy_name", Some("policy"), false)
            }
            Self::ProcessBinding => (
                "process-binding",
                "Process",
                "runtime_sessions.process_id + runtime_sessions.process_start_time",
                None,
                false,
            ),
            Self::StartedAt => ("started-at", "Started", "runtime_sessions.started_at", None, true),
            Self::EndedAt => ("ended-at", "Ended", "runtime_sessions.ended_at", None, true),
            Self::ExitStatus => {
                ("exit-status", "Exit", "runtime_sessions.exit_status", None, false)
            }
            Self::SecretNameCount => (
                "secret-name-count",
                "Secrets",
                "runtime_sessions.secret_names_json count",
                None,
                false,
            ),
            Self::AuditSequences => (
                "audit-sequences",
                "Audit",
                "runtime_sessions.spawn_audit_sequence + runtime_sessions.completion_audit_sequence",
                None,
                false,
            ),
        };
        ExecutionMonitorFieldDescriptor {
            field: self,
            key,
            label,
            source,
            privacy_alias_kind,
            timestamp,
            metadata_only: true,
        }
    }
}

impl AccessibilityRequirement {
    /// Return the metadata-only descriptor for this accessibility requirement.
    #[must_use]
    pub const fn descriptor(self) -> AccessibilityDescriptor {
        let (key, guidance, plaintext_ttl_sensitive) = match self {
            Self::KeyboardNavigation => (
                "keyboard-navigation",
                "Expose every primary action through tab order and shortcuts.",
                false,
            ),
            Self::VisibleFocus => (
                "visible-focus",
                "Render a persistent focus treatment for every interactive control.",
                false,
            ),
            Self::ScreenReaderLabels => (
                "screen-reader-labels",
                "Use labels that describe metadata-only actions and state.",
                false,
            ),
            Self::SufficientContrast => (
                "sufficient-contrast",
                "Keep text, status, warning, and focus colors above contrast thresholds.",
                false,
            ),
            Self::ReducedMotion => (
                "reduced-motion",
                "Disable nonessential animation when reduced motion is requested.",
                false,
            ),
            Self::PostTtlMetadataScrub => (
                "post-ttl-metadata-scrub",
                "Clear reveal and copy accessibility metadata when plaintext TTL expires.",
                true,
            ),
        };
        AccessibilityDescriptor { requirement: self, key, guidance, plaintext_ttl_sensitive }
    }
}

impl EmptyState {
    /// Return the desktop empty-state guidance descriptor for this state.
    #[must_use]
    pub const fn descriptor(self) -> EmptyStateDescriptor {
        let (title, guidance, primary_command, secondary_command) = match self {
            Self::NoProject => (
                "No project",
                "Initialize a project or accept a team invite.",
                "locket init",
                Some("locket team accept <invite.locket>"),
            ),
            Self::NoProfile => (
                "No profile",
                "Create a development profile before adding secrets.",
                "locket profile create dev",
                None,
            ),
            Self::NoSecret => (
                "No secrets",
                "Add or import a secret to populate this view.",
                "locket set <KEY>",
                Some("locket import <file.env>"),
            ),
            Self::NoPolicy => (
                "No policy",
                "Create a saved command policy before running through Locket.",
                "locket policy add dev -- <cmd>",
                None,
            ),
            Self::NoAgent => (
                "No agent",
                "Start the local agent to enable live status and grants.",
                "locket agent start",
                None,
            ),
            Self::NoTeamDevice => (
                "No team device",
                "Initialize this device before team invite or bundle flows.",
                "locket device init",
                None,
            ),
        };
        EmptyStateDescriptor { state: self, title, guidance, primary_command, secondary_command }
    }
}

impl TrayNotificationKind {
    /// Render the default passive notification without exact names or values.
    #[must_use]
    pub fn passive_notification(self, context: &TrayNotificationContext<'_>) -> TrayNotification {
        match self {
            Self::RevealOrCopy => TrayNotification {
                title: "Secret ready".to_owned(),
                body: "The requested secret action completed.".to_owned(),
            },
            Self::DeniedAccess => TrayNotification {
                title: "Access denied".to_owned(),
                body: "A secret or policy action needs attention in the app.".to_owned(),
            },
            Self::ScanFinding => TrayNotification {
                title: "Scan warning".to_owned(),
                body: scan_notification_body(context.finding_count),
            },
            Self::ExecutionFailure => TrayNotification {
                title: "Policy failed".to_owned(),
                body: "A saved policy failed. Open the app for details.".to_owned(),
            },
        }
    }
}

/// Return all passive tray notification kinds in desktop spec order.
#[must_use]
pub const fn tray_notification_kinds() -> &'static [TrayNotificationKind] {
    &[
        TrayNotificationKind::RevealOrCopy,
        TrayNotificationKind::DeniedAccess,
        TrayNotificationKind::ScanFinding,
        TrayNotificationKind::ExecutionFailure,
    ]
}

/// Route a passive tray notification through the generic privacy-safe
/// renderer, honoring the user's notification quiet mode.
#[must_use]
pub fn route_tray_notification(
    kind: TrayNotificationKind,
    context: &TrayNotificationContext<'_>,
    preferences: TrayNotificationPreferences,
) -> Option<TrayNotification> {
    if preferences.do_not_disturb {
        return None;
    }
    Some(kind.passive_notification(context))
}

impl TrayIconState {
    /// Return the metadata-only icon descriptor for this state.
    #[must_use]
    pub const fn descriptor(self) -> TrayIconDescriptor {
        let (lucide_icon, label) = match self {
            Self::AgentUnlocked => ("lock-open", "agent running, vault unlocked"),
            Self::AgentLocked => ("lock", "agent running, vault locked"),
            Self::AgentStopped => ("lock", "agent stopped"),
            Self::ScanWarning => ("shield-alert", "scan warning"),
            Self::ErrorDegraded => ("alert-triangle", "error or degraded"),
        };
        TrayIconDescriptor { state: self, lucide_icon, label }
    }
}

/// Access setting for a release webview capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityAccess {
    /// Capability is denied by default.
    Denied,
    /// Capability is allowed.
    Allowed,
}

/// Release-webview security defaults for the desktop app shell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseWebviewPolicy {
    /// Release builds must not load remote content.
    pub remote_content: CapabilityAccess,
    /// Release builds must not load remote fonts.
    pub remote_fonts: CapabilityAccess,
    /// Release builds must not include analytics.
    pub analytics: CapabilityAccess,
    /// Release builds must not embed third-party iframes.
    pub third_party_iframes: CapabilityAccess,
    /// Release builds must not open webview devtools.
    pub release_devtools: CapabilityAccess,
    /// Release builds must not expose broad filesystem access.
    pub broad_filesystem_access: CapabilityAccess,
    /// Release builds must not expose broad shell access.
    pub broad_shell_access: CapabilityAccess,
    /// Release builds must not expose broad network access.
    pub broad_network_access: CapabilityAccess,
    /// Release builds must not expose broad updater access.
    pub broad_updater_access: CapabilityAccess,
    /// Release builds must not expose broad clipboard access.
    pub broad_clipboard_access: CapabilityAccess,
    /// Release builds must not expose broad dialog access.
    pub broad_dialog_access: CapabilityAccess,
    /// Release builds must not expose broad notification access.
    pub broad_notification_access: CapabilityAccess,
    /// Content Security Policy applied to packaged webviews.
    pub content_security_policy: &'static str,
}

impl Default for ReleaseWebviewPolicy {
    fn default() -> Self {
        Self {
            remote_content: CapabilityAccess::Denied,
            remote_fonts: CapabilityAccess::Denied,
            analytics: CapabilityAccess::Denied,
            third_party_iframes: CapabilityAccess::Denied,
            release_devtools: CapabilityAccess::Denied,
            broad_filesystem_access: CapabilityAccess::Denied,
            broad_shell_access: CapabilityAccess::Denied,
            broad_network_access: CapabilityAccess::Denied,
            broad_updater_access: CapabilityAccess::Denied,
            broad_clipboard_access: CapabilityAccess::Denied,
            broad_dialog_access: CapabilityAccess::Denied,
            broad_notification_access: CapabilityAccess::Denied,
            content_security_policy: "default-src 'self'; base-uri 'self'; object-src 'none'; frame-src 'none'; img-src 'self' data:; style-src 'self'; font-src 'self'; script-src 'self'; connect-src 'self'",
        }
    }
}

/// All primary views in spec order.
#[must_use]
pub const fn primary_views() -> &'static [PrimaryView] {
    &[
        PrimaryView::ProjectDashboard,
        PrimaryView::ProfileSwitcher,
        PrimaryView::SecretMetadataList,
        PrimaryView::SecretEditor,
        PrimaryView::SecretVersionHistory,
        PrimaryView::CommandPolicyEditor,
        PrimaryView::ExecutionMonitor,
        PrimaryView::ScanResults,
        PrimaryView::AuditLog,
        PrimaryView::BackupRecovery,
        PrimaryView::Settings,
    ]
}

/// All tray icon states in spec order.
#[must_use]
pub const fn tray_icon_states() -> &'static [TrayIconState] {
    &[
        TrayIconState::AgentUnlocked,
        TrayIconState::AgentLocked,
        TrayIconState::AgentStopped,
        TrayIconState::ScanWarning,
        TrayIconState::ErrorDegraded,
    ]
}

/// Return the icon asset styles required for a target platform.
#[must_use]
pub const fn tray_icon_asset_styles_for_os(os: &str) -> &'static [TrayIconAssetStyle] {
    match os.as_bytes() {
        b"macos" => &[TrayIconAssetStyle::TemplateMask],
        b"windows" | b"linux" => {
            &[TrayIconAssetStyle::FullColorLight, TrayIconAssetStyle::FullColorDark]
        }
        _ => &[TrayIconAssetStyle::FullColorLight, TrayIconAssetStyle::FullColorDark],
    }
}

/// Return all tray icon descriptors in spec order.
#[must_use]
pub fn tray_icon_descriptors() -> Vec<TrayIconDescriptor> {
    tray_icon_states().iter().map(|state| state.descriptor()).collect()
}

/// All denial reasons in desktop UX spec order.
#[must_use]
pub const fn denial_reasons() -> &'static [DenialReason] {
    &[
        DenialReason::LockedVault,
        DenialReason::MissingGrant,
        DenialReason::PolicyDenied,
        DenialReason::DangerousProfile,
        DenialReason::RevokedDevice,
        DenialReason::ExpiredInvite,
    ]
}

/// Return all denial UX descriptors in spec order.
#[must_use]
pub fn denial_ux_descriptors() -> Vec<DenialUxDescriptor> {
    denial_reasons().iter().map(|reason| reason.descriptor()).collect()
}

/// All empty setup states in desktop UX spec order.
#[must_use]
pub const fn empty_states() -> &'static [EmptyState] {
    &[
        EmptyState::NoProject,
        EmptyState::NoProfile,
        EmptyState::NoSecret,
        EmptyState::NoPolicy,
        EmptyState::NoAgent,
        EmptyState::NoTeamDevice,
    ]
}

/// Return all desktop empty-state descriptors in spec order.
#[must_use]
pub fn empty_state_descriptors() -> Vec<EmptyStateDescriptor> {
    empty_states().iter().map(|state| state.descriptor()).collect()
}

/// All desktop accessibility requirements in spec order.
#[must_use]
pub const fn accessibility_requirements() -> &'static [AccessibilityRequirement] {
    &[
        AccessibilityRequirement::KeyboardNavigation,
        AccessibilityRequirement::VisibleFocus,
        AccessibilityRequirement::ScreenReaderLabels,
        AccessibilityRequirement::SufficientContrast,
        AccessibilityRequirement::ReducedMotion,
        AccessibilityRequirement::PostTtlMetadataScrub,
    ]
}

/// Return all desktop accessibility descriptors in spec order.
#[must_use]
pub fn accessibility_descriptors() -> Vec<AccessibilityDescriptor> {
    accessibility_requirements().iter().map(|requirement| requirement.descriptor()).collect()
}

/// All version history states in desktop spec order.
#[must_use]
pub const fn version_history_states() -> &'static [VersionHistoryState] {
    &[VersionHistoryState::Current, VersionHistoryState::Deprecated, VersionHistoryState::Purged]
}

/// Return all version history state descriptors in spec order.
#[must_use]
pub fn version_history_state_descriptors() -> Vec<VersionHistoryStateDescriptor> {
    version_history_states().iter().map(|state| state.descriptor()).collect()
}

/// All version history fields required by the desktop spec.
#[must_use]
pub const fn version_history_fields() -> &'static [VersionHistoryField] {
    &[
        VersionHistoryField::State,
        VersionHistoryField::DeprecatedAt,
        VersionHistoryField::GraceUntil,
        VersionHistoryField::PinnedReferenceEligibility,
        VersionHistoryField::ScanInclusion,
        VersionHistoryField::RotationAuditMetadata,
    ]
}

/// Return all version history field descriptors in spec order.
#[must_use]
pub fn version_history_field_descriptors() -> Vec<VersionHistoryFieldDescriptor> {
    version_history_fields().iter().map(|field| field.descriptor()).collect()
}

/// All execution monitor states in desktop spec order.
#[must_use]
pub const fn execution_monitor_states() -> &'static [ExecutionMonitorState] {
    &[
        ExecutionMonitorState::Running,
        ExecutionMonitorState::Completed,
        ExecutionMonitorState::Failed,
        ExecutionMonitorState::Stale,
    ]
}

/// Return all execution monitor state descriptors in spec order.
#[must_use]
pub fn execution_monitor_state_descriptors() -> Vec<ExecutionMonitorStateDescriptor> {
    execution_monitor_states().iter().map(|state| state.descriptor()).collect()
}

/// All execution monitor fields backed by `runtime_sessions`.
#[must_use]
pub const fn execution_monitor_fields() -> &'static [ExecutionMonitorField] {
    &[
        ExecutionMonitorField::SessionId,
        ExecutionMonitorField::Profile,
        ExecutionMonitorField::Policy,
        ExecutionMonitorField::ProcessBinding,
        ExecutionMonitorField::StartedAt,
        ExecutionMonitorField::EndedAt,
        ExecutionMonitorField::ExitStatus,
        ExecutionMonitorField::SecretNameCount,
        ExecutionMonitorField::AuditSequences,
    ]
}

/// Return all execution monitor field descriptors in spec order.
#[must_use]
pub fn execution_monitor_field_descriptors() -> Vec<ExecutionMonitorFieldDescriptor> {
    execution_monitor_fields().iter().map(|field| field.descriptor()).collect()
}

fn scan_notification_body(finding_count: Option<u32>) -> String {
    match finding_count {
        Some(1) => "1 scan warning needs attention.".to_owned(),
        Some(count) => format!("{count} scan warnings need attention."),
        None => "Scan warnings need attention.".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccessibilityRequirement, CapabilityAccess, DenialReason, EmptyState,
        ExecutionMonitorField, ReleaseWebviewPolicy, TrayIconAssetStyle, TrayIconState,
        TrayNotificationContext, TrayNotificationKind, TrayNotificationPreferences,
        VersionHistoryField, VersionHistoryState, accessibility_descriptors,
        accessibility_requirements, denial_reasons, denial_ux_descriptors, empty_state_descriptors,
        empty_states, execution_monitor_field_descriptors, execution_monitor_fields,
        execution_monitor_state_descriptors, execution_monitor_states, primary_views,
        route_tray_notification, tray_icon_asset_styles_for_os, tray_icon_descriptors,
        tray_icon_states, tray_notification_kinds, version_history_field_descriptors,
        version_history_fields, version_history_state_descriptors, version_history_states,
    };

    #[test]
    fn primary_views_match_desktop_spec_inventory() {
        assert_eq!(primary_views().len(), 11);
    }

    #[test]
    fn tray_icon_states_match_desktop_spec_inventory() {
        assert_eq!(
            tray_icon_states(),
            &[
                TrayIconState::AgentUnlocked,
                TrayIconState::AgentLocked,
                TrayIconState::AgentStopped,
                TrayIconState::ScanWarning,
                TrayIconState::ErrorDegraded,
            ]
        );
    }

    #[test]
    fn tray_icon_descriptors_use_lucide_spec_icons() {
        let descriptors = tray_icon_descriptors();

        assert_eq!(descriptors.len(), tray_icon_states().len());
        assert_eq!(descriptors[0].lucide_icon, "lock-open");
        assert_eq!(descriptors[1].lucide_icon, "lock");
        assert_eq!(descriptors[2].lucide_icon, "lock");
        assert_eq!(descriptors[3].lucide_icon, "shield-alert");
        assert_eq!(descriptors[4].lucide_icon, "alert-triangle");
        assert!(descriptors.iter().all(|descriptor| !descriptor.label.contains("secret")));
    }

    #[test]
    fn tray_icon_asset_styles_match_platform_requirements() {
        assert_eq!(
            tray_icon_asset_styles_for_os("freebsd"),
            &[TrayIconAssetStyle::FullColorLight, TrayIconAssetStyle::FullColorDark]
        );
        assert_eq!(tray_icon_asset_styles_for_os("macos"), &[TrayIconAssetStyle::TemplateMask]);
        assert_eq!(
            tray_icon_asset_styles_for_os("windows"),
            &[TrayIconAssetStyle::FullColorLight, TrayIconAssetStyle::FullColorDark,]
        );
        assert_eq!(
            tray_icon_asset_styles_for_os("linux"),
            &[TrayIconAssetStyle::FullColorLight, TrayIconAssetStyle::FullColorDark,]
        );
    }

    #[test]
    fn passive_tray_notifications_use_generic_labels_by_default() {
        let context = TrayNotificationContext {
            secret_name: Some("DATABASE_URL"),
            policy_name: Some("deploy-prod"),
            project_name: Some("payments-api"),
            secret_value: Some("postgres://user:pass@example.invalid/db"),
            finding_count: Some(3),
        };

        for (kind, expected_title, expected_body) in [
            (
                TrayNotificationKind::RevealOrCopy,
                "Secret ready",
                "The requested secret action completed.",
            ),
            (
                TrayNotificationKind::DeniedAccess,
                "Access denied",
                "A secret or policy action needs attention in the app.",
            ),
            (TrayNotificationKind::ScanFinding, "Scan warning", "3 scan warnings need attention."),
            (
                TrayNotificationKind::ExecutionFailure,
                "Policy failed",
                "A saved policy failed. Open the app for details.",
            ),
        ] {
            let notification = kind.passive_notification(&context);
            assert_eq!(notification.title, expected_title);
            assert_eq!(notification.body, expected_body);
        }
    }

    #[test]
    fn tray_notification_router_covers_all_passive_kinds() {
        let context = TrayNotificationContext {
            secret_name: Some("DATABASE_URL"),
            policy_name: Some("deploy-prod"),
            project_name: Some("payments-api"),
            secret_value: Some("postgres://user:pass@example.invalid/db"),
            finding_count: Some(2),
        };
        let preferences = TrayNotificationPreferences { do_not_disturb: false };

        let notifications = tray_notification_kinds()
            .iter()
            .map(|kind| route_tray_notification(*kind, &context, preferences))
            .collect::<Vec<_>>();

        assert_eq!(notifications.len(), 4);
        assert!(notifications.iter().all(Option::is_some));
        for notification in notifications.into_iter().flatten() {
            let rendered = format!("{} {}", notification.title, notification.body);
            assert!(!rendered.contains("DATABASE_URL"));
            assert!(!rendered.contains("deploy-prod"));
            assert!(!rendered.contains("payments-api"));
            assert!(!rendered.contains("postgres://"));
        }
    }

    #[test]
    fn tray_notification_router_honors_do_not_disturb() {
        let context = TrayNotificationContext {
            finding_count: Some(4),
            ..TrayNotificationContext::default()
        };
        let preferences = TrayNotificationPreferences { do_not_disturb: true };

        for kind in tray_notification_kinds() {
            assert_eq!(route_tray_notification(*kind, &context, preferences), None);
        }
    }

    #[test]
    fn scan_notifications_show_metadata_counts_only() {
        let unknown = TrayNotificationKind::ScanFinding
            .passive_notification(&TrayNotificationContext::default());
        assert_eq!(unknown.body, "Scan warnings need attention.");

        let one =
            TrayNotificationKind::ScanFinding.passive_notification(&TrayNotificationContext {
                finding_count: Some(1),
                ..TrayNotificationContext::default()
            });
        let many =
            TrayNotificationKind::ScanFinding.passive_notification(&TrayNotificationContext {
                finding_count: Some(12),
                secret_name: Some("API_TOKEN"),
                ..TrayNotificationContext::default()
            });

        assert_eq!(one.body, "1 scan warning needs attention.");
        assert_eq!(many.body, "12 scan warnings need attention.");
        assert!(!many.body.contains("API_TOKEN"));
    }

    #[test]
    fn tray_canary_context_values_do_not_render_in_notifications() {
        let canary = "lk-canary-tray-value-1234567890abcdef";
        let context = TrayNotificationContext {
            secret_name: Some("DATABASE_URL"),
            policy_name: Some("deploy-prod"),
            project_name: Some("payments-api"),
            secret_value: Some(canary),
            finding_count: Some(9),
        };
        let preferences = TrayNotificationPreferences { do_not_disturb: false };

        for kind in tray_notification_kinds() {
            let notification = route_tray_notification(*kind, &context, preferences);
            assert!(notification.is_some(), "expected notification for kind {kind:?}");
            let Some(notification) = notification else { continue };
            let rendered = format!("{} {}", notification.title, notification.body);
            for forbidden in ["DATABASE_URL", "deploy-prod", "payments-api", canary] {
                assert!(!rendered.contains(forbidden), "{kind:?} leaked {forbidden}");
            }
        }
    }

    #[test]
    fn denial_reasons_match_desktop_error_view_inventory() {
        assert_eq!(
            denial_reasons(),
            &[
                DenialReason::LockedVault,
                DenialReason::MissingGrant,
                DenialReason::PolicyDenied,
                DenialReason::DangerousProfile,
                DenialReason::RevokedDevice,
                DenialReason::ExpiredInvite,
            ]
        );
    }

    #[test]
    fn denial_ux_descriptors_have_distinct_safe_recovery_affordances() {
        let descriptors = denial_ux_descriptors();

        assert_eq!(descriptors.len(), denial_reasons().len());
        for descriptor in descriptors {
            assert_eq!(descriptor, descriptor.reason.descriptor());
            assert!(!descriptor.title.contains("DATABASE_URL"));
            assert!(!descriptor.next_action.contains("postgres://"));
            assert_ne!(descriptor.affordance, "");
        }

        let affordances = denial_ux_descriptors()
            .into_iter()
            .map(|descriptor| descriptor.affordance)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(affordances.len(), denial_reasons().len());
    }

    #[test]
    fn empty_states_match_desktop_setup_inventory() {
        assert_eq!(
            empty_states(),
            &[
                EmptyState::NoProject,
                EmptyState::NoProfile,
                EmptyState::NoSecret,
                EmptyState::NoPolicy,
                EmptyState::NoAgent,
                EmptyState::NoTeamDevice,
            ]
        );
    }

    #[test]
    fn empty_state_descriptors_offer_safe_setup_commands() {
        let descriptors = empty_state_descriptors();

        assert_eq!(descriptors.len(), empty_states().len());
        assert_eq!(descriptors[0].primary_command, "locket init");
        assert_eq!(descriptors[0].secondary_command, Some("locket team accept <invite.locket>"));
        assert_eq!(descriptors[1].primary_command, "locket profile create dev");
        assert_eq!(descriptors[2].primary_command, "locket set <KEY>");
        assert_eq!(descriptors[2].secondary_command, Some("locket import <file.env>"));
        assert_eq!(descriptors[3].primary_command, "locket policy add dev -- <cmd>");
        assert_eq!(descriptors[4].primary_command, "locket agent start");
        assert_eq!(descriptors[5].primary_command, "locket device init");

        for descriptor in descriptors {
            assert_eq!(descriptor, descriptor.state.descriptor());
            let rendered = format!(
                "{} {} {} {:?}",
                descriptor.title,
                descriptor.guidance,
                descriptor.primary_command,
                descriptor.secondary_command
            );
            assert!(!rendered.contains("DATABASE_URL"));
            assert!(!rendered.contains("deploy-prod"));
            assert!(!rendered.contains("payments-api"));
            assert!(!rendered.contains("postgres://"));
        }
    }

    #[test]
    fn accessibility_requirements_match_desktop_spec_baseline() {
        assert_eq!(
            accessibility_requirements(),
            &[
                AccessibilityRequirement::KeyboardNavigation,
                AccessibilityRequirement::VisibleFocus,
                AccessibilityRequirement::ScreenReaderLabels,
                AccessibilityRequirement::SufficientContrast,
                AccessibilityRequirement::ReducedMotion,
                AccessibilityRequirement::PostTtlMetadataScrub,
            ]
        );
    }

    #[test]
    fn accessibility_descriptors_are_metadata_only_and_cover_ttl_scrub() {
        let descriptors = accessibility_descriptors();

        assert_eq!(descriptors.len(), accessibility_requirements().len());
        assert_eq!(descriptors[0].key, "keyboard-navigation");
        assert_eq!(descriptors[1].key, "visible-focus");
        assert_eq!(descriptors[2].key, "screen-reader-labels");
        assert_eq!(descriptors[3].key, "sufficient-contrast");
        assert_eq!(descriptors[4].key, "reduced-motion");
        assert_eq!(descriptors[5].key, "post-ttl-metadata-scrub");

        for descriptor in descriptors {
            assert_eq!(descriptor, descriptor.requirement.descriptor());
            let rendered = format!("{} {}", descriptor.key, descriptor.guidance);
            assert!(!rendered.contains("DATABASE_URL"));
            assert!(!rendered.contains("postgres://"));
            assert!(!rendered.contains("recovery code"));
            assert!(!rendered.contains("grant token"));
        }

        let ttl_sensitive = accessibility_descriptors()
            .into_iter()
            .filter(|descriptor| descriptor.plaintext_ttl_sensitive)
            .collect::<Vec<_>>();
        assert_eq!(ttl_sensitive.len(), 1);
        assert_eq!(ttl_sensitive[0].requirement, AccessibilityRequirement::PostTtlMetadataScrub);
    }

    #[test]
    fn version_history_states_match_desktop_spec_inventory() {
        assert_eq!(
            version_history_states(),
            &[
                VersionHistoryState::Current,
                VersionHistoryState::Deprecated,
                VersionHistoryState::Purged,
            ]
        );
    }

    #[test]
    fn version_history_state_descriptors_capture_value_and_pin_semantics() {
        let descriptors = version_history_state_descriptors();

        assert_eq!(descriptors.len(), version_history_states().len());
        assert_eq!(descriptors[0].label, "current");
        assert!(descriptors[0].retains_value_material);
        assert!(descriptors[0].supports_pinned_reference);
        assert_eq!(descriptors[1].label, "deprecated");
        assert!(descriptors[1].retains_value_material);
        assert!(descriptors[1].supports_pinned_reference);
        assert_eq!(descriptors[2].label, "purged");
        assert!(!descriptors[2].retains_value_material);
        assert!(!descriptors[2].supports_pinned_reference);

        for descriptor in descriptors {
            assert_eq!(descriptor, descriptor.state.descriptor());
            assert!(!descriptor.label.contains("DATABASE_URL"));
            assert!(!descriptor.label.contains("postgres://"));
        }
    }

    #[test]
    fn version_history_fields_cover_required_metadata_columns() {
        assert_eq!(
            version_history_fields(),
            &[
                VersionHistoryField::State,
                VersionHistoryField::DeprecatedAt,
                VersionHistoryField::GraceUntil,
                VersionHistoryField::PinnedReferenceEligibility,
                VersionHistoryField::ScanInclusion,
                VersionHistoryField::RotationAuditMetadata,
            ]
        );

        let descriptors = version_history_field_descriptors();
        assert_eq!(descriptors[1].key, "deprecated-at");
        assert!(descriptors[1].timestamp);
        assert_eq!(descriptors[2].key, "grace-until");
        assert!(descriptors[2].timestamp);
        assert_eq!(descriptors[3].key, "pinned-reference-eligibility");
        assert_eq!(descriptors[4].key, "scan-inclusion");
        assert_eq!(descriptors[5].key, "rotation-audit-metadata");

        for descriptor in descriptors {
            assert_eq!(descriptor, descriptor.field.descriptor());
            let rendered = format!("{} {}", descriptor.key, descriptor.label);
            assert!(!rendered.contains("DATABASE_URL"));
            assert!(!rendered.contains("postgres://"));
            assert!(!rendered.contains("secret value"));
        }
    }

    #[test]
    fn execution_monitor_states_cover_running_completed_and_warning_rows() {
        let descriptors = execution_monitor_state_descriptors();

        assert_eq!(descriptors.len(), execution_monitor_states().len());
        assert_eq!(descriptors[0].label, "running");
        assert!(descriptors[0].active);
        assert_eq!(descriptors[1].label, "completed");
        assert!(!descriptors[1].warning);
        assert_eq!(descriptors[2].label, "failed");
        assert!(descriptors[2].warning);
        assert_eq!(descriptors[3].label, "stale");
        assert!(descriptors[3].warning);

        for descriptor in descriptors {
            assert_eq!(descriptor, descriptor.state.descriptor());
            assert!(!descriptor.label.contains("DATABASE_URL"));
            assert!(!descriptor.label.contains("postgres://"));
        }
    }

    #[test]
    fn execution_monitor_fields_are_backed_by_runtime_sessions_metadata() {
        let descriptors = execution_monitor_field_descriptors();

        assert_eq!(
            execution_monitor_fields(),
            &[
                ExecutionMonitorField::SessionId,
                ExecutionMonitorField::Profile,
                ExecutionMonitorField::Policy,
                ExecutionMonitorField::ProcessBinding,
                ExecutionMonitorField::StartedAt,
                ExecutionMonitorField::EndedAt,
                ExecutionMonitorField::ExitStatus,
                ExecutionMonitorField::SecretNameCount,
                ExecutionMonitorField::AuditSequences,
            ]
        );
        assert_eq!(descriptors.len(), execution_monitor_fields().len());
        assert_eq!(descriptors[1].privacy_alias_kind, Some("profile"));
        assert_eq!(descriptors[2].privacy_alias_kind, Some("policy"));
        assert!(descriptors[4].timestamp);
        assert!(descriptors[5].timestamp);
        assert!(descriptors.iter().all(|descriptor| descriptor.metadata_only));
        assert!(
            descriptors.iter().all(|descriptor| descriptor.source.contains("runtime_sessions"))
        );

        for descriptor in descriptors {
            assert_eq!(descriptor, descriptor.field.descriptor());
            let rendered = format!(
                "{} {} {} {:?}",
                descriptor.key, descriptor.label, descriptor.source, descriptor.privacy_alias_kind
            );
            assert!(!rendered.contains("DATABASE_URL"));
            assert!(!rendered.contains("postgres://"));
            assert!(!rendered.contains("secret value"));
        }
    }

    #[test]
    fn release_webview_policy_denies_broad_and_remote_capabilities() {
        let policy = ReleaseWebviewPolicy::default();

        assert_eq!(policy.remote_content, CapabilityAccess::Denied);
        assert_eq!(policy.remote_fonts, CapabilityAccess::Denied);
        assert_eq!(policy.analytics, CapabilityAccess::Denied);
        assert_eq!(policy.third_party_iframes, CapabilityAccess::Denied);
        assert_eq!(policy.release_devtools, CapabilityAccess::Denied);
        assert_eq!(policy.broad_filesystem_access, CapabilityAccess::Denied);
        assert_eq!(policy.broad_shell_access, CapabilityAccess::Denied);
        assert_eq!(policy.broad_network_access, CapabilityAccess::Denied);
        assert_eq!(policy.broad_updater_access, CapabilityAccess::Denied);
        assert_eq!(policy.broad_clipboard_access, CapabilityAccess::Denied);
        assert_eq!(policy.broad_dialog_access, CapabilityAccess::Denied);
        assert_eq!(policy.broad_notification_access, CapabilityAccess::Denied);
        assert!(!policy.content_security_policy.contains("https:"));
        assert!(!policy.content_security_policy.contains("http:"));
        assert!(policy.content_security_policy.contains("frame-src 'none'"));
        assert!(policy.content_security_policy.contains("object-src 'none'"));
    }
}
