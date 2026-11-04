//! Local agent state, dispatcher, and Unix-domain-socket server.
//!
//! The request dispatcher and shared state are used by every local
//! transport. Unix additionally owns the per-user socket accept loop
//! and peer-credential checks in this module; Windows named-pipe
//! construction lives in `windows_pipe`.

use std::collections::BTreeMap;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(not(test))]
use locket_platform::KeyringMasterKeyStore;
use locket_platform::{MasterKeyStore, PassphraseFallbackMasterKeyStore, PlatformError};
use locket_store::{Store, StoreError};
use tokio::io::AsyncReadExt;
#[cfg(unix)]
use tokio::io::AsyncWriteExt;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Notify};

use crate::DEFAULT_MAX_MESSAGE_SIZE;
use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::error::ProtocolError;
use crate::framing::decode_request_frame;
#[cfg(unix)]
use crate::framing::encode_frame;
use crate::method::AgentMethod;
use crate::session_lock::{
    SessionLockAudit, SessionLockOutcome, SessionLockSource, append_lock_audit,
};
use crate::status::{LockState, RecentAuditStatus, StatusPayload};
use crate::status_stream::StatusHub;

#[cfg(all(test, unix))]
type PeerCredentialValidator =
    dyn Fn(&UnixStream, u32) -> Result<(), SocketServerError> + Send + Sync;

/// Resolves the default on-disk directory the passphrase-fallback
/// envelope store should use when callers don't supply one explicitly.
/// Falls back to a temp-directory subpath when `directories` cannot
/// resolve a project data dir; tests that don't perform passphrase
/// unlocks never touch the filesystem regardless.
fn default_passphrase_fallback_dir() -> PathBuf {
    directories::ProjectDirs::from("dev", "0xdoublesharp", "Locket").map_or_else(
        || std::env::temp_dir().join("locket-agent-passphrase-fallback"),
        |dirs| dirs.data_dir().join("passphrase-fallback"),
    )
}

/// Resolves the default master-key store. Production agents use the OS
/// keychain; unit tests use a process-local `MemoryMasterKeyStore` so
/// `seed_master_key` writes never touch the host keychain.
#[cfg(not(test))]
fn default_master_key_store() -> Arc<dyn MasterKeyStore + Send + Sync> {
    Arc::new(KeyringMasterKeyStore)
}

#[cfg(test)]
fn default_master_key_store() -> Arc<dyn MasterKeyStore + Send + Sync> {
    Arc::new(locket_platform::MemoryMasterKeyStore::default())
}

#[cfg(unix)]
fn current_daemon_uid() -> u32 {
    crate::peer_cred::current_process_uid()
}

#[cfg(not(unix))]
const fn current_daemon_uid() -> u32 {
    0
}

/// Permissions for a freshly bound agent socket — owner-only.
#[cfg(unix)]
const SOCKET_PERMISSIONS_MODE: u32 = 0o600;
/// Permissions for the parent directory that holds the socket — also
/// owner-only so peers can't list/probe it.
#[cfg(unix)]
const SOCKET_PARENT_PERMISSIONS_MODE: u32 = 0o700;

/// Outcome of a single accepted connection's handle loop.
#[cfg(unix)]
#[derive(Debug)]
pub enum ConnectionOutcome {
    /// Client closed the stream cleanly.
    PeerClosed,
    /// We answered one or more requests, then hit an error reading.
    Errored,
    /// The connection was rejected at accept time without a response,
    /// most commonly because the peer's UID did not match the
    /// daemon's.
    Rejected {
        /// Why the connection was dropped.
        reason: SocketServerError,
    },
}

#[cfg(unix)]
impl PartialEq for ConnectionOutcome {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::PeerClosed, Self::PeerClosed)
                | (Self::Errored, Self::Errored)
                | (Self::Rejected { .. }, Self::Rejected { .. })
        )
    }
}

#[cfg(unix)]
impl Eq for ConnectionOutcome {}

/// Errors returned by the agent socket server.
#[cfg(unix)]
#[derive(Debug, thiserror::Error)]
pub enum SocketServerError {
    /// The configured socket path is already in use by a live owner.
    /// Maps to `LocketError::AgentSocketInUse` (exit 81) at the CLI
    /// boundary.
    #[error("agent socket already bound: {path}")]
    AgentSocketInUse {
        /// Path the second daemon attempted to bind.
        path: PathBuf,
    },
    /// An existing path on the bind chain has wider Unix permissions
    /// than the agent allows. We refuse to silently tighten user
    /// directories because that could mask hostile creation by another
    /// principal; the operator has to fix the perms first.
    #[error("agent socket path {path} has mode {mode:#o}; expected at most {expected:#o}")]
    SocketPathTooWide {
        /// Path whose mode bits are too permissive.
        path: PathBuf,
        /// Mode bits found on disk (lower 9 bits).
        mode: u32,
        /// Maximum allowed mode bits (e.g., `0o700` for parents).
        expected: u32,
    },
    /// The connecting peer's effective UID did not match the daemon's
    /// UID. Maps to [`locket_core::LocketError::AccessDenied`] (exit
    /// 70) at the CLI boundary.
    #[error(
        "agent peer UID {peer_uid} does not match daemon UID {daemon_uid}; refusing cross-user connection"
    )]
    PeerCredentialDenied {
        /// UID reported by the kernel for the connecting peer.
        peer_uid: u32,
        /// UID of the running daemon process.
        daemon_uid: u32,
    },
    /// `bind`/`accept`/permission tweak failed for an OS reason.
    #[error("agent socket I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Configuration for [`bind_socket_listener`].
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct AgentSocketConfig {
    /// Filesystem path the listener should bind. Parent directory is
    /// created with `0o700` if missing.
    pub path: PathBuf,
    /// Agent version reported on `Status` responses.
    pub agent_version: String,
}

#[cfg(unix)]
impl AgentSocketConfig {
    /// Convenience constructor for tests and direct callers.
    #[must_use]
    pub fn new(path: PathBuf, agent_version: impl Into<String>) -> Self {
        Self { path, agent_version: agent_version.into() }
    }
}

/// Binds the agent's Unix domain socket and tightens permissions.
///
/// Returns [`SocketServerError::AgentSocketInUse`] when a previous
/// listener still owns the path. The caller (the spec-described
/// `locket agent start`) reaps stale sockets and retries; the bare
/// helper here treats `EADDRINUSE` as an in-use error so the caller
/// can decide what to do. This slice does not yet implement the
/// stale-socket cleanup; that lives in the upcoming agent CLI work.
///
/// If the parent directory already exists with mode bits wider than
/// `0o700`, this function refuses to bind with
/// [`SocketServerError::SocketPathTooWide`] rather than silently
/// tightening another principal's directory.
///
/// # Errors
///
/// Returns [`SocketServerError`] when binding, parent-directory
/// creation, or permission tightening fails, or when the parent
/// directory's existing permissions are wider than the agent allows.
#[cfg(unix)]
pub fn bind_socket_listener(config: &AgentSocketConfig) -> Result<UnixListener, SocketServerError> {
    if let Some(parent) = config.path.parent()
        && !parent.as_os_str().is_empty()
    {
        prepare_parent_directory(parent)?;
    }

    let listener = match UnixListener::bind(&config.path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            return Err(SocketServerError::AgentSocketInUse { path: config.path.clone() });
        }
        Err(error) => return Err(error.into()),
    };
    std::fs::set_permissions(
        &config.path,
        std::fs::Permissions::from_mode(SOCKET_PERMISSIONS_MODE),
    )?;
    let socket_mode = std::fs::metadata(&config.path)?.permissions().mode() & 0o777;
    if socket_mode & !SOCKET_PERMISSIONS_MODE != 0 {
        return Err(SocketServerError::SocketPathTooWide {
            path: config.path.clone(),
            mode: socket_mode,
            expected: SOCKET_PERMISSIONS_MODE,
        });
    }
    Ok(listener)
}

/// Ensures the socket's parent directory exists and is owner-only.
///
/// If the directory does not exist, it is created with `0o700`. If it
/// already exists with mode bits beyond `0o700`, the bind is refused
/// rather than silently tightened — that prevents an agent start from
/// quietly clamping down a user-owned directory whose wider mode might
/// be intentional (or hostile).
#[cfg(unix)]
fn prepare_parent_directory(parent: &Path) -> Result<(), SocketServerError> {
    match std::fs::metadata(parent) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & !SOCKET_PARENT_PERMISSIONS_MODE != 0 {
                return Err(SocketServerError::SocketPathTooWide {
                    path: parent.to_path_buf(),
                    mode,
                    expected: SOCKET_PARENT_PERMISSIONS_MODE,
                });
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(
                parent,
                std::fs::Permissions::from_mode(SOCKET_PARENT_PERMISSIONS_MODE),
            )?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// State shared across every accepted connection.
#[derive(Clone)]
pub struct AgentSocketState {
    /// Agent version string reported on `Status` responses.
    pub agent_version: String,
    /// UID of the running daemon process, used to validate peer
    /// credentials on every accept.
    pub daemon_uid: u32,
    /// Per-project unlock-key cache populated by `Unlock` and cleared
    /// by `Lock`. Status responses derive `lock_state` and
    /// `unlock_ttl_seconds` from the live entries here.
    pub unlock_cache: Arc<Mutex<crate::unlock_cache::UnlockCache>>,
    /// Live process-bound grant records. `RequestGrant` inserts new
    /// rows, `RevokeGrant` and `ExpireGrant` remove them, and
    /// `Status` responses surface `live_grant_count` from this table.
    pub grants: Arc<Mutex<crate::grant::GrantTable>>,
    /// Metadata-only runtime session snapshots used by desktop views.
    pub runtime_sessions: Arc<Mutex<Vec<crate::runtime_sessions::RuntimeSessionSnapshot>>>,
    /// Metadata-only saved command policy snapshots used by desktop views.
    pub command_policies: Arc<Mutex<Vec<crate::policies::CommandPolicySnapshot>>>,
    /// Compact tray/status counters that are produced by agent activity
    /// and do not contain names or values.
    status_metrics: Arc<Mutex<StatusMetrics>>,
    /// Native session observer availability, metadata only.
    session_monitoring: Arc<Mutex<Option<String>>>,
    /// In-memory automation-client challenges issued by `ClientHello`.
    pub automation_challenges: Arc<Mutex<BTreeMap<String, crate::auth::IssuedChallenge>>>,
    /// TTL-bound, names-only IDE env-session registry populated by
    /// `RegisterIdeEnvSession` and consumed by `IdeEnvSession` lookups.
    /// Values never enter this map: only the env-name allow-list and
    /// TTL.
    pub ide_env_sessions: crate::ide_env_session::IdeEnvSessionRegistry,
    /// OS keychain (or test-injected) master-key store. The agent
    /// unwraps client-less unlocks against this store; the unwrapped
    /// key is then cached via `unlock_cache`.
    pub master_key_store: Arc<dyn MasterKeyStore + Send + Sync>,
    /// Passphrase-fallback envelope store consulted when the keychain
    /// returns `MasterKeyNotFound` and the client supplied a passphrase.
    pub passphrase_store: Arc<PassphraseFallbackMasterKeyStore>,
    /// Server-side fan-out hub for `SubscribeStatus` streams.
    pub status_hub: StatusHub,
    /// In-band shutdown notification used by daemon transports.
    pub shutdown: Arc<Notify>,
    /// Serializes native session transitions with key/grant creation. Each
    /// block reason remains active until its matching OS resume notification.
    session_gate: Arc<Mutex<std::collections::BTreeSet<&'static str>>>,
    /// Counts expiry work for deterministic idle-work regression checks.
    #[cfg(test)]
    pub(crate) expiry_checks: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    pub(crate) test_expiry_clock_offset: Arc<std::sync::atomic::AtomicI64>,
    /// Test hook overriding the heartbeat cadence so unit tests can run
    /// with millisecond cadence rather than 30-second waits.
    #[cfg(all(test, unix))]
    pub test_heartbeat_interval: Arc<Mutex<Option<std::time::Duration>>>,
    /// Test hook that lets socket tests inject spoofed peer UIDs
    /// without requiring root or a second local user.
    #[cfg(all(test, unix))]
    peer_credential_validator: Arc<PeerCredentialValidator>,
}

impl AgentSocketState {
    /// Builds an initial state with an empty unlock cache.
    ///
    /// The daemon UID is captured from the live process when the
    /// state is constructed, which matches how `locket agent start`
    /// will boot the listener.
    #[must_use]
    pub fn locked(agent_version: impl Into<String>) -> Self {
        Self::with_daemon_uid(agent_version, current_daemon_uid())
    }

    /// Builds an initial state with an explicit daemon UID. Tests use
    /// this to drive the peer-validation rejection path without
    /// running as a different user.
    #[must_use]
    pub fn with_daemon_uid(agent_version: impl Into<String>, daemon_uid: u32) -> Self {
        Self::with_stores(
            agent_version,
            daemon_uid,
            default_master_key_store(),
            Arc::new(PassphraseFallbackMasterKeyStore::new(default_passphrase_fallback_dir())),
        )
    }

    /// Builds an initial state with explicit master-key and passphrase
    /// fallback stores. Production callers (`locket agent start`)
    /// inject the OS keychain and the user-data passphrase fallback
    /// store; tests inject in-memory stores.
    #[must_use]
    pub fn with_stores(
        agent_version: impl Into<String>,
        daemon_uid: u32,
        master_key_store: Arc<dyn MasterKeyStore + Send + Sync>,
        passphrase_store: Arc<PassphraseFallbackMasterKeyStore>,
    ) -> Self {
        let agent_version = agent_version.into();
        let status_hub = StatusHub::new(StatusPayload::locked(agent_version.clone()));
        Self {
            agent_version,
            daemon_uid,
            unlock_cache: Arc::new(Mutex::new(crate::unlock_cache::UnlockCache::default())),
            grants: Arc::new(Mutex::new(crate::grant::GrantTable::default())),
            runtime_sessions: Arc::new(Mutex::new(Vec::new())),
            command_policies: Arc::new(Mutex::new(Vec::new())),
            status_metrics: Arc::new(Mutex::new(StatusMetrics::default())),
            session_monitoring: Arc::new(Mutex::new(None)),
            automation_challenges: Arc::new(Mutex::new(BTreeMap::new())),
            ide_env_sessions: crate::ide_env_session::new_registry(),
            master_key_store,
            passphrase_store,
            status_hub,
            shutdown: Arc::new(Notify::new()),
            session_gate: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            #[cfg(test)]
            expiry_checks: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            #[cfg(test)]
            test_expiry_clock_offset: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            #[cfg(all(test, unix))]
            test_heartbeat_interval: Arc::new(Mutex::new(None)),
            #[cfg(all(test, unix))]
            peer_credential_validator: Arc::new(crate::peer_cred::validate_peer_stream),
        }
    }

    /// Test-only constructor that lets tests inject a shared unlock
    /// cache so they can pre-populate entries before driving the
    /// dispatcher.
    #[cfg(test)]
    pub fn for_tests(
        agent_version: impl Into<String>,
        daemon_uid: u32,
        cache: Arc<Mutex<crate::unlock_cache::UnlockCache>>,
    ) -> Self {
        let agent_version = agent_version.into();
        let status_hub = StatusHub::new(StatusPayload::locked(agent_version.clone()));
        Self {
            agent_version,
            daemon_uid,
            unlock_cache: cache,
            grants: Arc::new(Mutex::new(crate::grant::GrantTable::default())),
            runtime_sessions: Arc::new(Mutex::new(Vec::new())),
            command_policies: Arc::new(Mutex::new(Vec::new())),
            status_metrics: Arc::new(Mutex::new(StatusMetrics::default())),
            session_monitoring: Arc::new(Mutex::new(None)),
            automation_challenges: Arc::new(Mutex::new(BTreeMap::new())),
            ide_env_sessions: crate::ide_env_session::new_registry(),
            master_key_store: Arc::new(locket_platform::MemoryMasterKeyStore::default()),
            passphrase_store: Arc::new(PassphraseFallbackMasterKeyStore::new(
                default_passphrase_fallback_dir(),
            )),
            status_hub,
            shutdown: Arc::new(Notify::new()),
            session_gate: Arc::new(Mutex::new(std::collections::BTreeSet::new())),
            expiry_checks: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            test_expiry_clock_offset: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            #[cfg(unix)]
            test_heartbeat_interval: Arc::new(Mutex::new(None)),
            #[cfg(unix)]
            peer_credential_validator: Arc::new(crate::peer_cred::validate_peer_stream),
        }
    }

    /// Test-only helper that writes `master_key` into the agent's
    /// master-key store under `project_id`. Lets tests drive the
    /// `Unlock` RPC without ever touching the real OS keychain.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] when the injected master-key store
    /// cannot persist the test key.
    #[cfg(test)]
    pub fn seed_master_key(
        &self,
        project_id: &str,
        master_key: &locket_crypto::KeyBytes,
    ) -> Result<(), PlatformError> {
        self.master_key_store.store_master_key(project_id, master_key)
    }

    /// Test-only override for peer credential validation. The live
    /// socket is still used, but the peer UID passed into the policy is
    /// supplied by the test so cross-user outcomes are deterministic.
    #[cfg(all(test, unix))]
    #[must_use]
    pub fn with_test_peer_uid(mut self, peer_uid: u32) -> Self {
        self.peer_credential_validator = Arc::new(move |_stream, daemon_uid| {
            crate::peer_cred::validate_peer_uid(peer_uid, daemon_uid)
        });
        self
    }

    /// Test-only override for the heartbeat cadence. Setting this
    /// before a `SubscribeStatus` connection is accepted lets unit
    /// tests run with millisecond cadence rather than 30-second waits.
    #[cfg(all(test, unix))]
    pub async fn set_test_heartbeat_interval(&self, interval: std::time::Duration) {
        *self.test_heartbeat_interval.lock().await = Some(interval);
    }

    /// Test-only seed for metadata-only runtime session snapshots.
    #[cfg(test)]
    pub async fn set_runtime_sessions_for_tests(
        &self,
        sessions: Vec<crate::runtime_sessions::RuntimeSessionSnapshot>,
    ) {
        *self.runtime_sessions.lock().await = sessions;
    }

    /// Test-only seed for metadata-only command policy snapshots.
    #[cfg(test)]
    pub async fn set_command_policies_for_tests(
        &self,
        policies: Vec<crate::policies::CommandPolicySnapshot>,
    ) {
        *self.command_policies.lock().await = policies;
    }

    /// Builds the metadata-only `Status` payload from the current
    /// unlock-cache state. The reported `unlock_ttl_seconds` is the
    /// longest remaining TTL across live entries; the agent reports
    /// `Locked` whenever no live entry remains.
    pub async fn status_snapshot(&self, now_unix_nanos: i128) -> StatusPayload {
        let _ = self.expire_unlocks(now_unix_nanos).await;
        let summary = collect_live_summary(&self.unlock_cache, now_unix_nanos).await;
        let grant_count = {
            let grants = self.grants.lock().await;
            grants.len()
        };
        let running_session_count = {
            let sessions = self.runtime_sessions.lock().await;
            sessions.iter().filter(|session| session.ended_at.is_none()).count()
        };
        let metrics = self.status_metrics.lock().await;
        StatusPayload {
            lock_state: if summary.any_live { LockState::Unlocked } else { LockState::Locked },
            project_id: None,
            profile_name: None,
            live_grant_count: u32::try_from(grant_count).unwrap_or(u32::MAX),
            agent_version: self.agent_version.clone(),
            session_monitoring: self.session_monitoring.lock().await.clone(),
            unlock_ttl_seconds: summary.max_remaining_seconds,
            running_session_count: u32::try_from(running_session_count).unwrap_or(u32::MAX),
            scan_warning_count: metrics.scan_warning_count,
            scan_warning_count_known: true,
            recent_audit_status: metrics.recent_audit_status,
            pinned_reference_warning_count: metrics.pinned_reference_warning_count,
        }
    }

    /// Records whether the daemon is receiving native session-lock events.
    pub async fn set_session_monitoring_status(&self, status: impl Into<String>) {
        *self.session_monitoring.lock().await = Some(status.into());
        self.publish_status_snapshot(current_unix_nanos()).await;
    }

    /// Builds project-scoped health without borrowing another project's unlock.
    /// Profile labels are resolved by the caller against local project metadata.
    pub async fn status_snapshot_for_project(&self, project_id: &str, now: i128) -> StatusPayload {
        let mut snapshot = self.status_snapshot(now).await;
        snapshot.project_id = Some(project_id.to_owned());
        let remaining = self.unlock_cache.lock().await.lookup(project_id, now).map(|entry| {
            u64::try_from((entry.expires_at_unix_nanos() - now) / 1_000_000_000).unwrap_or(0)
        });
        snapshot.lock_state =
            if remaining.is_some() { LockState::Unlocked } else { LockState::Locked };
        snapshot.unlock_ttl_seconds = remaining;
        snapshot.live_grant_count =
            u32::try_from(self.grants.lock().await.count_for_project(project_id))
                .unwrap_or(u32::MAX);
        snapshot.running_session_count = u32::try_from(
            self.runtime_sessions
                .lock()
                .await
                .iter()
                .filter(|session| session.project_id == project_id && session.ended_at.is_none())
                .count(),
        )
        .unwrap_or(u32::MAX);
        // These metrics are global; unknown is more accurate than presenting a
        // different project's audit/scan result as this project's health.
        // Preserve the global warning signal for the application tray, but mark
        // it unknown for project-specific summaries.
        snapshot.scan_warning_count_known = false;
        snapshot.recent_audit_status = RecentAuditStatus::Unknown;
        snapshot.pinned_reference_warning_count = 0;
        snapshot
    }

    pub(crate) async fn publish_status_snapshot(&self, now_unix_nanos: i128) -> StatusPayload {
        let snapshot = self.status_snapshot(now_unix_nanos).await;
        self.status_hub.publish(snapshot.clone()).await;
        snapshot
    }

    /// Records the latest unresolved scan-warning count for compact
    /// status/tray clients. A zero-count scan clears the warning state.
    pub(crate) async fn record_scan_warning_count(&self, count: u32) {
        let mut metrics = self.status_metrics.lock().await;
        metrics.scan_warning_count = count;
        metrics.recent_audit_status = RecentAuditStatus::Ok;
    }

    /// Clears unlocked key material and live grants for a session-lock event.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when a cached project has audit context
    /// and its `LOCK` row cannot be appended.
    pub async fn lock_for_session_event(
        &self,
        source: SessionLockSource,
        now_unix_nanos: i128,
    ) -> Result<SessionLockOutcome, StoreError> {
        let cleared_entries = {
            let mut cache = self.unlock_cache.lock().await;
            cache.drain()
        };
        let cached_keys_cleared = cleared_entries.len();
        let audit_material = lock_audit_material(&cleared_entries);
        let live_grants_revoked = {
            let mut grants = self.grants.lock().await;
            let count = grants.len();
            grants.clear();
            count
        };
        let outcome = SessionLockOutcome { cached_keys_cleared, live_grants_revoked };
        if outcome.changed() {
            self.publish_status_snapshot(now_unix_nanos).await;
        }
        append_lock_audits(source, now_unix_nanos, outcome, &audit_material)?;
        Ok(outcome)
    }

    /// Blocks new unlocks/grants throughout a native locked or suspended session.
    /// Resuming clears any old state before permitting new authorization.
    ///
    /// # Errors
    /// Returns an audit error after key erasure and grant revocation.
    pub async fn lock_for_native_session_event(
        &self,
        source: SessionLockSource,
        session_blocked: bool,
        now: i128,
    ) -> Result<SessionLockOutcome, StoreError> {
        let mut gate = self.session_gate.lock().await;
        if session_blocked {
            gate.insert(source.as_str());
        } else {
            gate.remove(source.as_str());
        }
        let outcome = self.lock_for_session_event(source, now).await;
        drop(gate);
        outcome
    }

    // Production reads wall time; unit tests inject a per-agent clock jump.
    #[allow(clippy::unused_self)]
    fn expiry_now(&self) -> i128 {
        let now = current_unix_nanos();
        #[cfg(test)]
        let now = now
            + i128::from(self.test_expiry_clock_offset.load(std::sync::atomic::Ordering::Relaxed));
        now
    }

    /// Evicts expired project keys and revokes grants before a subsequent unlock.
    ///
    /// # Errors
    /// Returns an audit storage error after key and grant removal has completed.
    pub async fn expire_unlocks(&self, now: i128) -> Result<usize, StoreError> {
        #[cfg(test)]
        self.expiry_checks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let entries = self.unlock_cache.lock().await.drain_expired(now);
        let count = entries.len();
        let material = lock_audit_material(&entries);
        let mut revoked = 0;
        {
            let mut grants = self.grants.lock().await;
            for (project, _) in &entries {
                revoked += grants.revoke_for_project(project);
            }
        }
        drop(entries);
        append_lock_audits(
            SessionLockSource::IdleTimeout,
            now,
            SessionLockOutcome { cached_keys_cleared: count, live_grants_revoked: revoked },
            &material,
        )?;
        Ok(count)
    }

    /// Runs daemon-owned key expiry independently of status subscribers.
    #[must_use]
    pub fn spawn_unlock_expiry(&self) -> tokio::task::JoinHandle<()> {
        let state = self.clone();
        tokio::spawn(async move {
            let changed = state.unlock_cache.lock().await.change_notification();
            loop {
                let deadline = state.unlock_cache.lock().await.next_expiry_unix_nanos();
                let wait_for_expiry = async {
                    if let Some(deadline) = deadline {
                        let remaining = deadline.saturating_sub(state.expiry_now()).max(0);
                        let nanos = u64::try_from(remaining).unwrap_or(u64::MAX);
                        // Expiry timestamps also follow wall time. Recheck while
                        // keys exist so clock jumps cannot delay physical erasure.
                        let delay = std::time::Duration::from_nanos(nanos)
                            .min(std::time::Duration::from_millis(100));
                        tokio::time::sleep(delay).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                tokio::select! {
                    () = state.shutdown.notified() => break,
                    () = changed.notified() => continue,
                    () = wait_for_expiry => {}
                }
                let now = state.expiry_now();
                // Audit failures occur after keys/grants have been removed: status
                // still needs to reflect the lock instead of retaining stale UI.
                if !matches!(state.expire_unlocks(now).await, Ok(0)) {
                    state.publish_status_snapshot(now).await;
                }
            }
        })
    }
}

struct LockAuditMaterial {
    project_id: String,
    profile_id: Option<String>,
    store_path: PathBuf,
    master_key: zeroize::Zeroizing<Vec<u8>>,
}

fn lock_audit_material(
    entries: &[(String, crate::unlock_cache::UnlockEntry)],
) -> Vec<LockAuditMaterial> {
    entries
        .iter()
        .filter_map(|(project_id, entry)| {
            let context = entry.audit_context()?;
            Some(LockAuditMaterial {
                project_id: project_id.clone(),
                profile_id: context.profile_id.clone(),
                store_path: context.store_path.clone(),
                master_key: zeroize::Zeroizing::new(entry.key_bytes().to_vec()),
            })
        })
        .collect()
}

fn append_lock_audits(
    source: SessionLockSource,
    now_unix_nanos: i128,
    outcome: SessionLockOutcome,
    audit_material: &[LockAuditMaterial],
) -> Result<(), StoreError> {
    let timestamp = i64::try_from(now_unix_nanos).unwrap_or(i64::MAX);
    for material in audit_material {
        let mut store = Store::open(&material.store_path)?;
        let key_error = || StoreError::AuditIntegrity {
            sequence: 0,
            reason: "project audit key unavailable during lock".into(),
        };
        let master_key = zeroize::Zeroizing::new(
            master_key_bytes_to_array(&material.master_key).ok_or_else(key_error)?,
        );
        let audit_key = unwrap_project_audit_key(&store, &material.project_id, &master_key)
            .map_err(|_| key_error())?;
        append_lock_audit(
            &mut store,
            &SessionLockAudit {
                project_id: &material.project_id,
                profile_id: material.profile_id.as_deref(),
                audit_key: audit_key.as_ref(),
                source,
                outcome,
                timestamp,
            },
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct StatusMetrics {
    scan_warning_count: u32,
    recent_audit_status: RecentAuditStatus,
    pinned_reference_warning_count: u32,
}

/// Snapshot of live unlock-cache state used to fill a `StatusPayload`.
struct LiveCacheSummary {
    any_live: bool,
    max_remaining_seconds: Option<u64>,
}

async fn collect_live_summary(
    unlock_cache: &Arc<Mutex<crate::unlock_cache::UnlockCache>>,
    now_unix_nanos: i128,
) -> LiveCacheSummary {
    let live_expiries: Vec<i128> = {
        let cache = unlock_cache.lock().await;
        cache
            .entries_for_status()
            .filter(|entry| !entry.is_expired(now_unix_nanos))
            .map(crate::unlock_cache::UnlockEntry::expires_at_unix_nanos)
            .collect()
    };
    let any_live = !live_expiries.is_empty();
    let max_remaining_seconds = live_expiries
        .into_iter()
        .map(|expires_at| u64::try_from((expires_at - now_unix_nanos) / 1_000_000_000).unwrap_or(0))
        .max();
    LiveCacheSummary { any_live, max_remaining_seconds }
}

/// Handles a single accepted connection.
///
/// Validates peer credentials, reads framed requests, dispatches the
/// appropriate handler, and writes framed responses until the peer closes or
/// a read error occurs.
///
/// A peer whose effective UID does not match the daemon's UID is
/// dropped immediately without any response, so the existence and
/// state of the daemon are not exposed to other principals on the
/// host. Same-user connections are allowed through; the rejection is
/// surfaced through [`ConnectionOutcome::Rejected`] for tests and
/// future audit wiring.
#[cfg(unix)]
pub async fn handle_connection(
    mut stream: UnixStream,
    state: AgentSocketState,
) -> ConnectionOutcome {
    if let Err(error) = validate_connection_peer(&stream, &state) {
        return ConnectionOutcome::Rejected { reason: error };
    }
    let mut buffer = Vec::with_capacity(4 * 1024);
    loop {
        match read_one_frame(&mut stream, &mut buffer).await {
            Ok(None) => return ConnectionOutcome::PeerClosed,
            Ok(Some(envelope)) => {
                if matches!(envelope.method(), Ok(AgentMethod::SubscribeStatus)) {
                    return stream_status(stream, state, envelope.id.clone(), buffer).await;
                }
                let response = dispatch(&envelope, &state).await;
                if !write_response(&mut stream, &response).await {
                    return ConnectionOutcome::Errored;
                }
            }
            Err(_) => return ConnectionOutcome::Errored,
        }
    }
}

#[cfg(unix)]
fn validate_connection_peer(
    stream: &UnixStream,
    state: &AgentSocketState,
) -> Result<(), SocketServerError> {
    #[cfg(test)]
    {
        (state.peer_credential_validator)(stream, state.daemon_uid)
    }
    #[cfg(not(test))]
    {
        crate::peer_cred::validate_peer_stream(stream, state.daemon_uid)
    }
}

/// Streams metadata-only status events for the lifetime of a
/// `SubscribeStatus` request.
///
/// Reads from the peer in parallel with the hub: the only request
/// allowed mid-stream is `CancelSubscription`, which closes the
/// connection cleanly. Any other framed request is answered with a
/// redacted `ProtocolError` and then the connection is dropped.
#[cfg(unix)]
async fn stream_status(
    mut stream: UnixStream,
    state: AgentSocketState,
    request_id: String,
    initial_buffer: Vec<u8>,
) -> ConnectionOutcome {
    let mut subscriber = state.status_hub.subscribe().await;
    #[cfg(test)]
    let heartbeat =
        state.test_heartbeat_interval.lock().await.unwrap_or(std::time::Duration::from_secs(
            crate::status::STATUS_HEARTBEAT_INTERVAL_SECS,
        ));
    #[cfg(not(test))]
    let heartbeat = std::time::Duration::from_secs(crate::status::STATUS_HEARTBEAT_INTERVAL_SECS);

    let mut buffer = initial_buffer;
    loop {
        // Drain any already-buffered frames before blocking on the
        // socket. A peer can send `CancelSubscription` immediately
        // after `SubscribeStatus`, in which case it would already be
        // sitting in `buffer`.
        match decode_request_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
            Ok((envelope, consumed)) => {
                buffer.drain(..consumed);
                if matches!(envelope.method(), Ok(AgentMethod::CancelSubscription)) {
                    return ConnectionOutcome::PeerClosed;
                }
                let response = error_response(
                    &envelope,
                    "ProtocolError",
                    "only CancelSubscription is allowed mid-stream",
                );
                let _ = write_response(&mut stream, &response).await;
                return ConnectionOutcome::Errored;
            }
            Err(ProtocolError::IncompleteFrame) => {}
            Err(_) => return ConnectionOutcome::Errored,
        }

        let mut chunk = [0_u8; 1024];
        tokio::select! {
            event = subscriber.next_event_with_heartbeat(heartbeat) => {
                let Some(event) = event else { return ConnectionOutcome::Errored; };
                let Ok(payload) = serde_json::to_value(&event) else {
                    return ConnectionOutcome::Errored;
                };
                let response = ResponseEnvelope::Success(SuccessEnvelope::new(
                    request_id.clone(),
                    payload,
                ));
                if !write_response(&mut stream, &response).await {
                    return ConnectionOutcome::Errored;
                }
            }
            read = stream.read(&mut chunk) => {
                match read {
                    Ok(0) => return ConnectionOutcome::PeerClosed,
                    Ok(read) => {
                        buffer.extend_from_slice(&chunk[..read]);
                    }
                    Err(_) => return ConnectionOutcome::Errored,
                }
            }
        }
    }
}

// Shared by Unix sockets and Windows pipes. Only an incomplete frame can
// become valid after another read; all other decode errors close the stream.
pub(super) async fn read_one_frame<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
    buffer: &mut Vec<u8>,
) -> Result<Option<RequestEnvelope>, io::Error> {
    loop {
        match decode_request_frame(buffer, DEFAULT_MAX_MESSAGE_SIZE) {
            Ok((envelope, consumed)) => {
                buffer.drain(..consumed);
                return Ok(Some(envelope));
            }
            Err(ProtocolError::IncompleteFrame) => {}
            Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error)),
        }
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Wire payload for the `Unlock` RPC. The agent owns the unwrap path:
/// it pulls the master key from the OS keychain when `passphrase` is
/// `None`, and from the passphrase-fallback envelope when one is
/// supplied. Clients never send raw key bytes; the cached entry's
/// `UnlockMethod` is determined server-side by which path succeeded.
#[derive(serde::Deserialize)]
struct UnlockPayload {
    project_id: String,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    reuse_cached: bool,
    ttl_seconds: u64,
    /// Hint from the client for forward-compatibility. The agent
    /// derives the actual cached method from the path it took during
    /// unwrap; this field is currently ignored.
    #[serde(default)]
    #[allow(dead_code)]
    method: Option<crate::unlock_cache::UnlockMethod>,
    #[serde(default)]
    audit: Option<UnlockAuditPayload>,
}

#[derive(serde::Deserialize)]
struct UnlockAuditPayload {
    store_path: PathBuf,
    #[serde(default)]
    profile_id: Option<String>,
}

#[derive(Default, serde::Deserialize)]
struct LockPayload {
    #[serde(default)]
    source: SessionLockSource,
}

/// Returns the current Unix wall-clock time in nanoseconds, clamped to
/// the positive `i64` range so downstream arithmetic stays in `i128`.
pub fn current_unix_nanos() -> i128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| {
        let max = u128::from(u64::try_from(i64::MAX).unwrap_or(0));
        let clamped = d.as_nanos().min(max);
        i128::from(i64::try_from(clamped).unwrap_or(0))
    })
}

fn error_response(envelope: &RequestEnvelope, error: &str, message: &str) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(envelope.id.clone(), error, message, false))
}

#[allow(clippy::too_many_lines)]
/// Dispatches one validated agent request envelope against shared
/// daemon state and returns a framed-response payload.
pub async fn dispatch(envelope: &RequestEnvelope, state: &AgentSocketState) -> ResponseEnvelope {
    if let Some(response) =
        crate::auth::authenticate_request_if_present(envelope, state, current_unix_nanos()).await
    {
        return response;
    }
    match envelope.method() {
        Ok(AgentMethod::TeamSyncStatus) => {
            crate::handlers::team_sync::handle_team_sync_status(envelope, state).await
        }
        Ok(AgentMethod::TeamSyncConfigure) => {
            crate::handlers::team_sync::handle_team_sync_configure(envelope, state).await
        }
        Ok(AgentMethod::TeamSyncNow) => {
            crate::handlers::team_sync::handle_team_sync_now(envelope, state).await
        }
        Ok(AgentMethod::TeamSyncReconcile) => {
            crate::handlers::team_sync::handle_team_sync_reconcile(envelope, state).await
        }
        Ok(AgentMethod::Status) => {
            let now = current_unix_nanos();
            let snapshot = match envelope.payload.get("project_id") {
                Some(serde_json::Value::String(project_id)) if !project_id.trim().is_empty() => {
                    state.status_snapshot_for_project(project_id, now).await
                }
                Some(serde_json::Value::Null) | None => state.status_snapshot(now).await,
                _ => return error_response(envelope, "ProtocolError", "invalid Status project_id"),
            };
            let payload = serde_json::to_value(snapshot).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        Ok(AgentMethod::Unlock) => handle_unlock(envelope, state).await,
        Ok(AgentMethod::Lock) => {
            let payload: LockPayload = match serde_json::from_value(envelope.payload.clone()) {
                Ok(payload) => payload,
                Err(_) => {
                    return error_response(envelope, "ProtocolError", "invalid Lock payload");
                }
            };
            let now = current_unix_nanos();
            if state.lock_for_session_event(payload.source, now).await.is_err() {
                return error_response(envelope, "CorruptDb", "failed to append LOCK audit row");
            }
            ResponseEnvelope::Success(SuccessEnvelope::new(
                envelope.id.clone(),
                serde_json::Value::Null,
            ))
        }
        Ok(AgentMethod::Shutdown) => {
            let payload: LockPayload = match serde_json::from_value(envelope.payload.clone()) {
                Ok(payload) => payload,
                Err(_) => {
                    return error_response(envelope, "ProtocolError", "invalid Shutdown payload");
                }
            };
            let now = current_unix_nanos();
            if state.lock_for_session_event(payload.source, now).await.is_err() {
                return error_response(envelope, "CorruptDb", "failed to append LOCK audit row");
            }
            state.shutdown.notify_waiters();
            ResponseEnvelope::Success(SuccessEnvelope::new(
                envelope.id.clone(),
                serde_json::Value::Null,
            ))
        }
        Ok(AgentMethod::ClientHello) => crate::auth::handle_client_hello(envelope, state).await,
        Ok(AgentMethod::RequestGrant) => handle_request_grant(envelope, state).await,
        Ok(AgentMethod::RevokeGrant) => handle_revoke_grant(envelope, state).await,
        Ok(AgentMethod::ExpireGrant) => handle_expire_grant(envelope, state).await,
        Ok(AgentMethod::Reveal) => {
            crate::reveal::handle_reveal(envelope, state, current_unix_nanos()).await
        }
        Ok(AgentMethod::Copy) => {
            crate::reveal::handle_copy(envelope, state, current_unix_nanos()).await
        }
        Ok(AgentMethod::ScanKnownValues) => {
            crate::scan::handle_scan(envelope, state, current_unix_nanos()).await
        }
        Ok(AgentMethod::ListRuntimeSessions) => handle_list_runtime_sessions(envelope, state).await,
        Ok(AgentMethod::ListPolicies) => handle_list_policies(envelope, state).await,
        Ok(AgentMethod::ListDeviceMembers) => handle_list_device_members(envelope),
        Ok(AgentMethod::RegisterCommandPolicies) => {
            handle_register_command_policies(envelope, state).await
        }
        Ok(AgentMethod::PolicyDoctor) => {
            crate::policies::handle_policy_doctor(envelope, state, current_unix_nanos()).await
        }
        Ok(AgentMethod::ExportBundle) => crate::backup::handle_export_bundle(envelope, state).await,
        Ok(AgentMethod::ImportBundle) => crate::backup::handle_import_bundle(envelope, state).await,
        Ok(AgentMethod::VerifyBundle) => crate::backup::handle_verify_bundle(envelope),
        Ok(AgentMethod::RecoveryRotate) => {
            crate::backup::handle_recovery_rotate(envelope, state).await
        }
        Ok(AgentMethod::ResolveReference) => {
            crate::resolve::handle_resolve(envelope, state, current_unix_nanos()).await
        }
        Ok(AgentMethod::PrepareExec) => prepare_exec_dispatch(envelope, state).await,
        Ok(AgentMethod::ListSecrets) => handle_list_secrets(envelope),
        Ok(AgentMethod::ListVersions) => handle_list_versions(envelope),
        Ok(AgentMethod::ImportDotenv) => {
            crate::mutations::handle_import_dotenv(envelope, state, current_unix_nanos()).await
        }
        Ok(AgentMethod::ApplyPolicy) => {
            crate::mutations::handle_apply_policy(envelope, state, current_unix_nanos()).await
        }
        Ok(AgentMethod::SetSecret) => {
            crate::set_secret::handle_set_secret(envelope, state, current_unix_nanos()).await
        }
        Ok(AgentMethod::SetActiveProfile) => {
            crate::profile::handle_set_active_profile(envelope, state, current_unix_nanos()).await
        }
        Ok(AgentMethod::VerifyAudit) => handle_verify_audit(envelope, state).await,
        Ok(AgentMethod::ListAudit) => handle_list_audit(envelope, state).await,
        Ok(AgentMethod::ReadConfig) => crate::config::handle_read_config(envelope),
        Ok(AgentMethod::WriteConfig) => crate::config::handle_write_config(envelope, state).await,
        Ok(method @ (AgentMethod::RegisterIdeEnvSession | AgentMethod::IdeEnvSession)) => {
            ide_env_session_dispatch(method, envelope, state).await
        }
        Ok(AgentMethod::RegisterClient) => {
            crate::clients::handle_register_client(envelope, state, current_unix_nanos()).await
        }
        Ok(AgentMethod::RevokeClient) => {
            crate::clients::handle_revoke_client(envelope, state, current_unix_nanos()).await
        }
        Ok(method) => ResponseEnvelope::Error(ErrorEnvelope::new(
            envelope.id.clone(),
            "ProtocolError",
            format!("method {} is not implemented in this build", method.as_str()),
            false,
        )),
        Err(_) => ResponseEnvelope::Error(ErrorEnvelope::new(
            envelope.id.clone(),
            "ProtocolError",
            "unknown agent method",
            false,
        )),
    }
}

async fn prepare_exec_dispatch(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let session = state.session_gate.lock().await;
    if !session.is_empty() {
        return error_response(envelope, "UnlockRequired", "OS session is locked or suspended");
    }
    let response =
        crate::prepare_exec::handle_prepare_exec(envelope, state, current_unix_nanos()).await;
    drop(session);
    response
}

async fn ide_env_session_dispatch(
    method: AgentMethod,
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let now = current_unix_nanos();
    if matches!(method, AgentMethod::RegisterIdeEnvSession) {
        crate::ide_env_session::handle_register_ide_env_session(envelope, state, now).await
    } else {
        crate::ide_env_session::handle_ide_env_session(envelope, state, now).await
    }
}

const AGENT_UNLOCK_CLIENT_KIND: &str = "agent";
const AGENT_UNLOCK_COMMAND: &str = "unlock";

/// Server-side `Unlock` handler. The agent never trusts the client to
/// supply key bytes; it pulls the master key from the OS keychain or
/// the passphrase-fallback envelope itself, then derives the per-project
/// audit key, writes the `UNLOCK` audit row, and finally caches the
/// unwrapped master key so subsequent RPCs can reuse it.
async fn handle_unlock(envelope: &RequestEnvelope, state: &AgentSocketState) -> ResponseEnvelope {
    // Hold through insertion so native locking either runs after this unlock
    // and erases it, or rejects it for the entire locked/suspended session.
    let session = state.session_gate.lock().await;
    if !session.is_empty() {
        return error_response(envelope, "UnlockRequired", "OS session is locked or suspended");
    }
    let now = current_unix_nanos();
    if state.expire_unlocks(now).await.is_err() {
        return error_response(envelope, "CorruptDb", "failed to audit expired unlock");
    }
    let payload: UnlockPayload = match serde_json::from_value(envelope.payload.clone()) {
        Ok(payload) => payload,
        Err(_) => return error_response(envelope, "ProtocolError", "invalid Unlock payload"),
    };

    // Execution reuses an existing authorization without re-prompting or extending
    // its lifetime. An explicit unlock still authenticates through the key store.
    if payload.reuse_cached
        && payload.passphrase.is_none()
        && state.unlock_cache.lock().await.lookup(&payload.project_id, now).is_some()
    {
        return ResponseEnvelope::Success(SuccessEnvelope::new(
            envelope.id.clone(),
            serde_json::Value::Null,
        ));
    }

    let (master_key_bytes, resolved_method) = match resolve_master_key(
        envelope,
        state,
        payload.passphrase.as_deref(),
        &payload.project_id,
    ) {
        Ok(resolved) => resolved,
        Err(error) => return error,
    };

    if let Some(audit) = payload.audit.as_ref()
        && let Err(response) = append_unlock_audit_row(
            envelope,
            &audit.store_path,
            &payload.project_id,
            audit.profile_id.as_deref(),
            &master_key_bytes,
            resolved_method,
            payload.ttl_seconds,
            now,
        )
    {
        return response;
    }

    let mut entry = crate::unlock_cache::UnlockEntry::new(
        master_key_bytes,
        now,
        std::time::Duration::from_secs(payload.ttl_seconds),
        resolved_method,
    );
    if let Some(audit) = payload.audit {
        entry = entry.with_audit_context(crate::unlock_cache::UnlockAuditContext {
            store_path: audit.store_path,
            profile_id: audit.profile_id,
        });
    }
    state.unlock_cache.lock().await.insert(payload.project_id, entry);
    drop(session);
    state.publish_status_snapshot(now).await;
    ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), serde_json::Value::Null))
}

/// Loads the master key for `project_id` from the OS keychain, falling
/// back to the passphrase envelope when a passphrase is supplied and
/// the keychain has no entry. Returns the unwrapped key bytes plus the
/// `UnlockMethod` that should be recorded on the cached entry.
fn resolve_master_key(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
    passphrase: Option<&str>,
    project_id: &str,
) -> Result<(Vec<u8>, crate::unlock_cache::UnlockMethod), ResponseEnvelope> {
    use crate::unlock_cache::UnlockMethod;

    match state.master_key_store.load_master_key(project_id) {
        Ok(key) => Ok((key.to_vec(), UnlockMethod::OsKeychain)),
        Err(PlatformError::MasterKeyNotFound) => {
            let Some(passphrase) = passphrase else {
                return Err(error_response(
                    envelope,
                    "UnlockRequired",
                    "no master key in OS keychain; supply a passphrase to unlock from the fallback envelope",
                ));
            };
            match state.passphrase_store.load_master_key(project_id, passphrase.as_bytes()) {
                Ok(key) => Ok((key.to_vec(), UnlockMethod::Passphrase)),
                Err(PlatformError::MasterKeyNotFound) => Err(error_response(
                    envelope,
                    "UnlockRequired",
                    "no passphrase fallback envelope is registered for this project",
                )),
                Err(PlatformError::InvalidPassphrase) => Err(error_response(
                    envelope,
                    "UnlockRequired",
                    "passphrase did not authenticate the fallback envelope",
                )),
                Err(error) => Err(error_response(
                    envelope,
                    classify_platform_error(&error),
                    "passphrase fallback unwrap failed",
                )),
            }
        }
        Err(error) => Err(error_response(
            envelope,
            classify_platform_error(&error),
            "master key store unavailable",
        )),
    }
}

const fn classify_platform_error(error: &PlatformError) -> &'static str {
    match error {
        PlatformError::InvalidMasterKey
        | PlatformError::InvalidPassphraseFallback
        | PlatformError::InvalidRecoveryEnvelope(_)
        | PlatformError::RecoveryEnvelopeSchemaUnsupported(_) => "IntegrityFailure",
        _ => "KeychainUnavailable",
    }
}

#[allow(clippy::too_many_arguments)]
fn append_unlock_audit_row(
    envelope: &RequestEnvelope,
    store_path: &Path,
    project_id: &str,
    profile_id: Option<&str>,
    master_key_bytes: &[u8],
    method: crate::unlock_cache::UnlockMethod,
    ttl_seconds: u64,
    now_unix_nanos: i128,
) -> Result<(), ResponseEnvelope> {
    // The agent's UNLOCK row mirrors the CLI's metadata-only behavior:
    // if the project store cannot be opened or the audit key cannot be
    // unwrapped, the unlock itself still succeeds — the row is skipped
    // rather than poisoning the unlock path. The cached master key
    // remains correct so subsequent RPCs can still authenticate.
    let Some(master_key_array) = master_key_bytes_to_array(master_key_bytes) else {
        return Ok(());
    };
    let Ok(mut store) = Store::open(store_path) else {
        return Ok(());
    };
    let Ok(audit_key) = unwrap_project_audit_key(&store, project_id, &master_key_array) else {
        return Ok(());
    };

    let timestamp = i64::try_from(now_unix_nanos).unwrap_or(i64::MAX);
    let unlock_method_str = match method {
        crate::unlock_cache::UnlockMethod::OsKeychain => "OsKeychain",
        crate::unlock_cache::UnlockMethod::Passphrase => "Passphrase",
        crate::unlock_cache::UnlockMethod::RecoveryEnvelope => "RecoveryEnvelope",
    };
    let metadata = serde_json::json!({
        "schema_version": 1,
        "action": "UNLOCK",
        "status": "SUCCESS",
        "command": AGENT_UNLOCK_COMMAND,
        "client_kind": AGENT_UNLOCK_CLIENT_KIND,
        "method": unlock_method_str,
        "agent_available": true,
        "cached_keys": true,
        "user_verification": {
            "required": false,
            "satisfied": false,
            "method": null,
        },
        "grant_actions": [],
        "ttl_seconds": ttl_seconds,
    });
    let audit = locket_store::AuditWrite {
        project_id,
        profile_id,
        action: "UNLOCK",
        status: "SUCCESS",
        secret_name: None,
        command: Some(AGENT_UNLOCK_COMMAND),
        metadata_json: &metadata,
        timestamp,
    };
    if store.append_audit(audit_key.as_ref(), &audit).is_err() {
        return Err(error_response(envelope, "CorruptDb", "failed to append UNLOCK audit row"));
    }
    Ok(())
}

fn master_key_bytes_to_array(bytes: &[u8]) -> Option<locket_crypto::KeyBytes> {
    bytes.try_into().ok()
}

fn unwrap_project_audit_key(
    store: &Store,
    project_id: &str,
    master_key: &locket_crypto::KeyBytes,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, locket_crypto::CryptoError> {
    use locket_crypto::{
        HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, WrappedKeyMaterial,
        derive_wrapping_key_v1, key_wrap_aad_v1, unwrap_key_material_v1,
    };

    let purpose = KeyPurpose::Audit;
    let record = store
        .get_key_by_scope(project_id, None, purpose.as_str())
        .map_err(|_| locket_crypto::CryptoError::DecryptionFailed)?
        .ok_or(locket_crypto::CryptoError::DecryptionFailed)?;
    let wrapping_key =
        derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(project_id, None, purpose))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        None,
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    unwrap_key_material_v1(&wrapping_key, &wrapped, &aad)
}

async fn handle_register_command_policies(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    crate::policies::handle_register_command_policies(envelope, state, current_unix_nanos()).await
}

async fn handle_list_policies(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let request: crate::policies::ListPoliciesRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(request) => request,
            Err(_) => return crate::policies::invalid_payload_response(envelope),
        };
    let response = {
        let policies = state.command_policies.lock().await;
        crate::policies::list_policies_response(&request, &policies)
    };
    crate::policies::success_response(envelope, response)
}

async fn handle_list_runtime_sessions(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let request: crate::runtime_sessions::ListRuntimeSessionsRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(request) => request,
            Err(_) => return crate::runtime_sessions::invalid_payload_response(envelope),
        };
    let response = {
        let sessions = state.runtime_sessions.lock().await;
        crate::runtime_sessions::list_runtime_sessions_response(&request, &sessions)
    };
    crate::runtime_sessions::success_response(envelope, response)
}

fn handle_list_device_members(envelope: &RequestEnvelope) -> ResponseEnvelope {
    let payload: crate::device_members::ListDeviceMembersRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(
                    envelope,
                    "ProtocolError",
                    "invalid ListDeviceMembers payload",
                );
            }
        };
    match crate::device_members::list_device_members(&payload) {
        Ok(response) => {
            let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        Err(error) => {
            let locket_error = error.locket_error();
            ResponseEnvelope::Error(ErrorEnvelope::new(
                envelope.id.clone(),
                format!("{locket_error:?}"),
                error.to_string(),
                false,
            ))
        }
    }
}

fn handle_list_secrets(envelope: &RequestEnvelope) -> ResponseEnvelope {
    let payload: crate::secrets::ListSecretsRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid ListSecrets payload");
            }
        };
    match crate::secrets::list_secrets(&payload) {
        Ok(response) => {
            let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        Err(error) => {
            let locket_error = error.locket_error();
            ResponseEnvelope::Error(ErrorEnvelope::new(
                envelope.id.clone(),
                format!("{locket_error:?}"),
                error.to_string(),
                false,
            ))
        }
    }
}

fn handle_list_versions(envelope: &RequestEnvelope) -> ResponseEnvelope {
    let payload: crate::versions::ListVersionsRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid ListVersions payload");
            }
        };
    match crate::versions::list_versions(&payload) {
        Ok(response) => {
            let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        Err(error) => {
            let locket_error = error.locket_error();
            ResponseEnvelope::Error(ErrorEnvelope::new(
                envelope.id.clone(),
                format!("{locket_error:?}"),
                error.to_string(),
                false,
            ))
        }
    }
}

async fn handle_verify_audit(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let payload: crate::audit_verify::VerifyAuditRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid VerifyAudit payload");
            }
        };
    let audit_key = {
        let cache = state.unlock_cache.lock().await;
        cache
            .lookup(&payload.project_id, current_unix_nanos())
            .map(|entry| entry.key_bytes().to_vec())
    };
    let response = audit_key.map_or_else(
        || Ok(crate::audit_verify::VerifyAuditResponse::locked()),
        |key| crate::audit_verify::verify_audit(&payload, &key),
    );
    match response {
        Ok(response) => {
            let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        Err(error) => {
            let locket_error = error.locket_error();
            ResponseEnvelope::Error(ErrorEnvelope::new(
                envelope.id.clone(),
                format!("{locket_error:?}"),
                error.to_string(),
                false,
            ))
        }
    }
}

async fn handle_list_audit(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let payload: crate::audit::ListAuditRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid ListAudit payload");
            }
        };
    let audit_key = {
        let cache = state.unlock_cache.lock().await;
        cache
            .lookup(&payload.project_id, current_unix_nanos())
            .map(|entry| entry.key_bytes().to_vec())
    };
    match crate::audit::list_audit(&payload, audit_key.as_deref()) {
        Ok(response) => {
            let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        Err(error) => {
            let locket_error = error.locket_error();
            ResponseEnvelope::Error(ErrorEnvelope::new(
                envelope.id.clone(),
                format!("{locket_error:?}"),
                error.to_string(),
                false,
            ))
        }
    }
}

async fn handle_request_grant(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let session = state.session_gate.lock().await;
    if !session.is_empty() {
        return error_response(envelope, "UnlockRequired", "OS session is locked or suspended");
    }
    let mut payload: crate::grant::RequestGrantPayload =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid RequestGrant payload");
            }
        };
    if let Some(policy_name) = payload.policy_name.clone() {
        let policy_ttl_seconds = {
            let policies = state.command_policies.lock().await;
            policies
                .iter()
                .find(|policy| {
                    policy.project_id == payload.project_id && policy.name == policy_name
                })
                .map(|policy| policy.ttl_seconds)
        };
        let Some(policy_ttl_seconds) = policy_ttl_seconds else {
            return error_response(envelope, "PolicyNotFound", "command policy not found");
        };
        payload.ttl_seconds = policy_ttl_seconds;
    }
    let now = current_unix_nanos();
    let ttl_nanos = i128::from(payload.ttl_seconds).saturating_mul(1_000_000_000);
    let record = {
        let mut grants = state.grants.lock().await;
        match grants.issue(payload, now, now.saturating_add(ttl_nanos)) {
            Ok(record) => record,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "failed to allocate grant id");
            }
        }
    };
    drop(session);
    let response_payload = serde_json::json!({
        "grant_id": record.grant_id,
        "expires_at_unix_nanos": record.expires_at_unix_nanos.to_string(),
    });
    ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), response_payload))
}

async fn handle_revoke_grant(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let payload: crate::grant::GrantIdPayload =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid RevokeGrant payload");
            }
        };
    let removed = {
        let mut grants = state.grants.lock().await;
        grants.revoke(&payload.grant_id)
    };
    if removed.is_some() {
        ResponseEnvelope::Success(SuccessEnvelope::new(
            envelope.id.clone(),
            serde_json::Value::Null,
        ))
    } else {
        error_response(envelope, "GrantRequired", "grant not found")
    }
}

async fn handle_expire_grant(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let payload: crate::grant::GrantIdPayload =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid ExpireGrant payload");
            }
        };
    let outcome = {
        let mut grants = state.grants.lock().await;
        let now = current_unix_nanos();
        match grants.get(&payload.grant_id) {
            None => ExpireOutcome::Unknown,
            Some(record) if now >= record.expires_at_unix_nanos => {
                grants.revoke(&payload.grant_id);
                ExpireOutcome::DroppedExpired
            }
            Some(_) => ExpireOutcome::StillLive,
        }
    };
    match outcome {
        ExpireOutcome::DroppedExpired | ExpireOutcome::Unknown => ResponseEnvelope::Success(
            SuccessEnvelope::new(envelope.id.clone(), serde_json::Value::Null),
        ),
        ExpireOutcome::StillLive => {
            error_response(envelope, "ProtocolError", "grant is still live")
        }
    }
}

#[derive(Clone, Copy)]
enum ExpireOutcome {
    DroppedExpired,
    Unknown,
    StillLive,
}

#[cfg(unix)]
async fn write_response(stream: &mut UnixStream, response: &ResponseEnvelope) -> bool {
    let Ok(frame) = encode_frame(response, DEFAULT_MAX_MESSAGE_SIZE) else {
        return false;
    };
    stream.write_all(&frame).await.is_ok() && stream.flush().await.is_ok()
}

/// Returns the bound socket's filesystem permission bits.
///
/// Returns `None` when the path does not exist or `metadata` fails.
/// Surfaced as a public helper for tests and `locket doctor`.
#[must_use]
#[cfg(unix)]
pub fn socket_permission_mode(path: &Path) -> Option<u32> {
    std::fs::metadata(path).ok().map(|metadata| metadata.permissions().mode() & 0o777)
}

#[cfg(all(test, unix))]
mod cache_status_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::unlock_cache::{UnlockCache, UnlockEntry, UnlockMethod};
    use tokio::sync::Mutex;

    #[tokio::test(flavor = "current_thread")]
    async fn native_lock_waits_for_inflight_unlock_then_erases_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let state =
            AgentSocketState::for_tests("test", 0, Arc::new(Mutex::new(UnlockCache::default())));
        state.seed_master_key("project", &[4; 32])?;
        // Pause Unlock at its first cache access while it owns the session gate.
        let cache = state.unlock_cache.lock().await;
        let unlock_state = state.clone();
        let unlock = tokio::spawn(async move {
            dispatch(
                &RequestEnvelope::new(
                    "unlock",
                    AgentMethod::Unlock,
                    serde_json::json!({"project_id":"project", "ttl_seconds":60}),
                ),
                &unlock_state,
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(state.session_gate.try_lock().is_err());
        let lock_state = state.clone();
        let lock = tokio::spawn(async move {
            lock_state
                .lock_for_native_session_event(
                    SessionLockSource::SystemSleep,
                    true,
                    current_unix_nanos(),
                )
                .await
        });
        tokio::task::yield_now().await;
        drop(cache);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), unlock).await??,
            ResponseEnvelope::Success(_)
        ));
        tokio::time::timeout(Duration::from_secs(1), lock).await???;
        assert!(state.unlock_cache.lock().await.is_empty());
        assert!(!state.session_gate.lock().await.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_lock_waits_for_prepared_grant_then_revokes_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = AgentSocketState::locked("test");
        state.unlock_cache.lock().await.insert(
            "project".into(),
            UnlockEntry::new(
                vec![4; 32],
                current_unix_nanos(),
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        state.set_command_policies_for_tests(vec![serde_json::from_value(serde_json::json!({
            "project_id":"project", "name":"dev", "command_kind":"argv", "command_preview":"test",
            "required_secrets":[], "optional_secrets":[], "allowed_secrets":[], "confirm":false,
            "require_user_verification":false, "require_agent":true, "allow_remote_docker":false,
            "ttl_seconds":60, "env_mode":"minimal", "override_mode":"locket", "updated_at_unix_nanos":1
        }))?]).await;
        // Hold issuance after PrepareExec has checked the cache. Native locking
        // must wait for the whole request, then revoke its newly created grant.
        let grants = state.grants.lock().await;
        let preparing_state = state.clone();
        let preparing = tokio::spawn(async move {
            dispatch(&RequestEnvelope::new("prepare", AgentMethod::PrepareExec,
                serde_json::json!({"project_id":"project", "profile_id":"profile", "policy_name":"dev"})), &preparing_state).await
        });
        tokio::task::yield_now().await;
        assert!(state.session_gate.try_lock().is_err());
        let locking_state = state.clone();
        let locking = tokio::spawn(async move {
            locking_state
                .lock_for_native_session_event(
                    SessionLockSource::ScreenLock,
                    true,
                    current_unix_nanos(),
                )
                .await
        });
        tokio::task::yield_now().await;
        drop(grants);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), preparing).await??,
            ResponseEnvelope::Success(_)
        ));
        tokio::time::timeout(Duration::from_secs(1), locking).await???;
        assert!(state.grants.lock().await.is_empty());
        assert!(state.unlock_cache.lock().await.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn scoped_status_does_not_borrow_another_projects_unlock() {
        let cache = Arc::new(Mutex::new(UnlockCache::default()));
        cache.lock().await.insert(
            "project-a".into(),
            UnlockEntry::new(
                b"test-key".to_vec(),
                1_000_000_000,
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        let state =
            AgentSocketState::for_tests("test", crate::peer_cred::current_process_uid(), cache);
        let locked = state.status_snapshot_for_project("project-b", 1_500_000_000).await;
        assert_eq!(locked.project_id.as_deref(), Some("project-b"));
        assert_eq!(locked.lock_state, LockState::Locked);
        assert_eq!(locked.unlock_ttl_seconds, None);
        assert!(!locked.scan_warning_count_known);
        let live = state.status_snapshot_for_project("project-a", 1_500_000_000).await;
        assert_eq!(live.lock_state, LockState::Unlocked);
        assert_eq!(live.unlock_ttl_seconds, Some(59));
        assert_eq!(live.profile_name, None);
        let expired = state.status_snapshot_for_project("project-a", 61_000_000_000).await;
        assert_eq!(expired.lock_state, LockState::Locked);
        assert_eq!(expired.unlock_ttl_seconds, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn status_reports_unlocked_when_cache_has_live_entry() {
        let cache = Arc::new(Mutex::new(UnlockCache::default()));
        cache.lock().await.insert(
            "proj-1".to_owned(),
            UnlockEntry::new(
                b"k".to_vec(),
                1_000_000_000,
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        let state = AgentSocketState::for_tests(
            "test-version",
            crate::peer_cred::current_process_uid(),
            cache.clone(),
        );

        let snapshot = state.status_snapshot(1_500_000_000).await;

        assert_eq!(snapshot.lock_state, LockState::Unlocked);
        assert_eq!(snapshot.unlock_ttl_seconds, Some(59));
    }
}
