//! Metadata-only status payloads streamed by the agent.

use serde::{Deserialize, Serialize};

/// Maximum interval between metadata-only status heartbeat events.
pub const STATUS_HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Metadata-only lock state reported by status calls.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockState {
    /// Agent is not holding unwrapped keys.
    Locked,
    /// Agent has unwrapped keys for the current user/session.
    Unlocked,
    /// Agent is unavailable or cannot determine lock state.
    Unknown,
}

/// Metadata-only health summary for recent audit writes/verification.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecentAuditStatus {
    /// No recent audit signal is available for the compact status surface.
    #[default]
    Unknown,
    /// Recent audit activity is healthy.
    Ok,
    /// Recent audit activity needs user attention.
    Warning,
}

/// Metadata-only status payload shared by `Status` and status events.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusPayload {
    /// Lock state.
    pub lock_state: LockState,
    /// Optional active project id or privacy alias.
    pub project_id: Option<String>,
    /// Optional active profile name or privacy alias.
    pub profile_name: Option<String>,
    /// Count of live grants, never grant tokens.
    pub live_grant_count: u32,
    /// Agent version string.
    pub agent_version: String,
    /// Native session observer availability, absent on older agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_monitoring: Option<String>,
    /// Remaining unlock TTL, in whole seconds, when an unlock cache
    /// entry is live. `None` when the agent is locked.
    pub unlock_ttl_seconds: Option<u64>,
    /// Count of running runtime sessions.
    #[serde(default)]
    pub running_session_count: u32,
    /// Count of unresolved scan warnings from the most recent scan signal.
    #[serde(default)]
    pub scan_warning_count: u32,
    /// Whether the scan count applies to this status scope.
    #[serde(default = "scan_count_known_by_default", skip_serializing_if = "scan_count_is_known")]
    pub scan_warning_count_known: bool,
    /// Recent audit health summary, metadata-only.
    #[serde(default)]
    pub recent_audit_status: RecentAuditStatus,
    /// Count of active warnings for expiring or expired pinned references.
    #[serde(default)]
    pub pinned_reference_warning_count: u32,
}

// serde skip_serializing_if requires a reference argument.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn scan_count_is_known(known: &bool) -> bool {
    *known
}

const fn scan_count_known_by_default() -> bool {
    true
}

impl StatusPayload {
    /// Creates a locked status payload with no active project context.
    #[must_use]
    pub fn locked(agent_version: impl Into<String>) -> Self {
        Self {
            lock_state: LockState::Locked,
            project_id: None,
            profile_name: None,
            live_grant_count: 0,
            agent_version: agent_version.into(),
            session_monitoring: None,
            unlock_ttl_seconds: None,
            running_session_count: 0,
            scan_warning_count: 0,
            scan_warning_count_known: true,
            recent_audit_status: RecentAuditStatus::Unknown,
            pinned_reference_warning_count: 0,
        }
    }
}

/// Status stream event kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatusEventKind {
    /// A meaningful status change or initial status snapshot.
    Status,
    /// Metadata-only keepalive event that must not be treated as a state change.
    Heartbeat,
}

/// Metadata-only event payload emitted by `SubscribeStatus`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusEvent {
    /// Event kind.
    pub kind: StatusEventKind,
    /// Monotonically increasing stream-local sequence counter.
    pub sequence: u64,
    /// Lock state at the time this event was emitted.
    #[serde(flatten)]
    pub status: StatusPayload,
}

impl StatusEvent {
    /// Creates a meaningful status event.
    #[must_use]
    pub const fn status(sequence: u64, status: StatusPayload) -> Self {
        Self { kind: StatusEventKind::Status, sequence, status }
    }

    /// Creates a metadata-only heartbeat event.
    #[must_use]
    pub const fn heartbeat(sequence: u64, status: StatusPayload) -> Self {
        Self { kind: StatusEventKind::Heartbeat, sequence, status }
    }

    /// Returns whether this event represents a meaningful state change.
    #[must_use]
    pub const fn is_state_change(&self) -> bool {
        matches!(self.kind, StatusEventKind::Status)
    }

    /// Returns whether this event is a heartbeat keepalive.
    #[must_use]
    pub const fn is_heartbeat(&self) -> bool {
        matches!(self.kind, StatusEventKind::Heartbeat)
    }
}

/// Stream-local monotonically increasing sequence allocator for status events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusEventSequence {
    next: u64,
}

impl Default for StatusEventSequence {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusEventSequence {
    /// Creates a new sequence allocator starting at sequence 1.
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 1 }
    }

    /// Allocates the next sequence number.
    #[must_use]
    pub const fn next_sequence(&mut self) -> u64 {
        let sequence = self.next;
        self.next = self.next.saturating_add(1);
        sequence
    }

    /// Creates the next meaningful status event.
    #[must_use]
    pub const fn status(&mut self, status: StatusPayload) -> StatusEvent {
        StatusEvent::status(self.next_sequence(), status)
    }

    /// Creates the next heartbeat event.
    #[must_use]
    pub const fn heartbeat(&mut self, status: StatusPayload) -> StatusEvent {
        StatusEvent::heartbeat(self.next_sequence(), status)
    }
}
