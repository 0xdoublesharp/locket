//! Typed payloads for the IDE-env-session agent RPCs.
//!
//! The VS Code (or other IDE) extension publishes a TTL-bound, names-only
//! map of environment variable names that a `LOCKET_IDE_ENV_SESSION=<uuid>`
//! integrated terminal is allowed to consume. When `locket run` (or
//! `locket exec`) inherits that env var and resolves an
//! [`ExternalEnvSource::Ide`](locket_core::ExternalEnvSource::Ide) layer,
//! it asks the agent for the env-name allow-list bound to that session
//! id. Values never cross this RPC: the consumer follows up with
//! [`ResolveReference`](crate::method::AgentMethod::ResolveReference) for
//! each authorized name. See `docs/specs/runtime.md:117-118`.
//!
//! Two RPCs cover the IDE-env-session lifecycle:
//!
//! - `RegisterIdeEnvSession` lets the IDE create a names-only session
//!   entry under a freshly minted UUID with a project id, env name list,
//!   and TTL. It writes one `AGENT_GRANT` audit row per spec (audit
//!   metadata: `client_kind = "ide"`, `grant_actions = ["IdeEnvSession"]`,
//!   `ttl_seconds`).
//! - `IdeEnvSession` is the consumer-side lookup. It returns the env
//!   name allow-list and the remaining TTL. It deliberately does NOT
//!   emit an audit row: the eventual `RUN`/`EXEC` row (written by the
//!   CLI execution path) already covers the resolved env names, so
//!   adding a per-name-fetch audit here would double-log without adding
//!   integrity value. The session lookup is metadata-only and gated by
//!   the `(session_id, project_id)` tuple plus TTL.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use locket_store::{AuditWrite, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::keys::{cached_master_key, unwrap_audit_key_with_master};

/// Maximum TTL accepted for an IDE env-session registration.
///
/// The runtime spec ties IDE env sessions to the lifetime of an
/// integrated terminal grant, which the rest of the agent caps in the
/// 30-60 minute range. This crate uses 60 minutes as the upper bound
/// and 1 second as the lower bound; out-of-range registrations are
/// rejected with `ProtocolError`.
pub const MAX_IDE_ENV_SESSION_TTL_SECONDS: u64 = 60 * 60;
/// Default TTL applied when a registration omits `ttl_seconds`.
pub const DEFAULT_IDE_ENV_SESSION_TTL_SECONDS: u64 = 30 * 60;
/// Hard cap on the number of env names in a single session registration.
///
/// The audit chain caps `metadata_json` at 64 KiB (per
/// `docs/specs/audit.md:57`); 256 names with reasonable lengths sits
/// well below that limit while leaving headroom for additional metadata
/// fields. Larger registrations fail with `ProtocolError`.
pub const MAX_IDE_ENV_SESSION_NAMES: usize = 256;

/// One TTL-bound IDE env-session entry held in memory only.
#[derive(Clone, Debug)]
pub struct IdeEnvSessionEntry {
    /// Project id this session is scoped to. A lookup that supplies a
    /// different `project_id` fails with `IdeEnvSessionUnavailable`.
    pub project_id: String,
    /// Env-variable names the IDE published for this session. Names
    /// only; no values are ever stored here.
    pub env_names: Vec<String>,
    /// Absolute expiry time in nanoseconds since the Unix epoch.
    pub expires_at_unix_nanos: i128,
}

impl IdeEnvSessionEntry {
    /// Returns `true` when `now_unix_nanos` is at or past the expiry.
    #[must_use]
    pub const fn is_expired(&self, now_unix_nanos: i128) -> bool {
        now_unix_nanos >= self.expires_at_unix_nanos
    }

    /// Returns the remaining TTL in whole seconds, clamped to `u32`.
    #[must_use]
    pub fn ttl_seconds_remaining(&self, now_unix_nanos: i128) -> u32 {
        if now_unix_nanos >= self.expires_at_unix_nanos {
            return 0;
        }
        let remaining_nanos = self.expires_at_unix_nanos.saturating_sub(now_unix_nanos);
        let remaining_secs = remaining_nanos / 1_000_000_000;
        u32::try_from(remaining_secs).unwrap_or(u32::MAX)
    }
}

/// In-memory IDE environment sessions indexed by session id.
#[derive(Default)]
pub struct IdeEnvSessionRegistry {
    entries: HashMap<String, IdeEnvSessionEntry>,
}

impl IdeEnvSessionRegistry {
    /// Registers a session under its IDE-provided id.
    pub fn insert(&mut self, id: String, entry: IdeEnvSessionEntry) -> Option<IdeEnvSessionEntry> {
        self.entries.insert(id, entry)
    }

    /// Returns whether the registry has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Revokes every session for a project and returns the number removed.
    pub fn revoke_project(&mut self, project_id: &str) -> usize {
        let count = self.entries.len();
        self.entries.retain(|_, entry| entry.project_id != project_id);
        count - self.entries.len()
    }

    /// Revokes all sessions and returns the number removed.
    pub fn clear(&mut self) -> usize {
        let count = self.entries.len();
        self.entries.clear();
        count
    }
}

/// Constructs an empty shared registry suitable for `AgentSocketState`.
#[must_use]
pub fn new_registry() -> Arc<Mutex<IdeEnvSessionRegistry>> {
    Arc::new(Mutex::new(IdeEnvSessionRegistry::default()))
}

/// Request payload for `RegisterIdeEnvSession`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterIdeEnvSessionRequest {
    /// IDE-generated session id. Must be a non-empty stable identifier
    /// (typically a UUID); the agent stores it verbatim and uses it as
    /// the lookup key for the `IdeEnvSession` RPC.
    pub session_id: String,
    /// Project id this session is scoped to.
    pub project_id: String,
    /// Path to the user-scoped `store.db`, used to append the
    /// `AGENT_GRANT` audit row.
    pub store_path: PathBuf,
    /// Optional profile id for the audit row.
    #[serde(default)]
    pub profile_id: Option<String>,
    /// Env-variable names the IDE has published for this session.
    pub env_names: Vec<String>,
    /// Requested TTL in seconds. Falls back to
    /// [`DEFAULT_IDE_ENV_SESSION_TTL_SECONDS`] when omitted, and is
    /// rejected when greater than [`MAX_IDE_ENV_SESSION_TTL_SECONDS`].
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

/// Response payload for `RegisterIdeEnvSession`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterIdeEnvSessionResponse {
    /// Echoed session id for client convenience.
    pub session_id: String,
    /// TTL the agent applied (after defaulting).
    pub ttl_seconds: u64,
}

/// Request payload for `IdeEnvSession`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdeEnvSessionRequest {
    /// Session id presented by the consumer (mirrors the
    /// `LOCKET_IDE_ENV_SESSION` env var that the IDE injected into the
    /// terminal).
    pub session_id: String,
    /// Project id the consumer expects this session to be scoped to.
    pub project_id: String,
}

/// Response payload for `IdeEnvSession`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdeEnvSessionResponse {
    /// Env-variable names the consumer is authorized to inject. Names
    /// only — values are fetched separately via `ResolveReference`.
    pub env_names: Vec<String>,
    /// Whole seconds remaining before the session expires.
    pub ttl_seconds_remaining: u32,
}

/// Handles `RegisterIdeEnvSession` requests from the IDE.
pub async fn handle_register_ide_env_session(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let payload: RegisterIdeEnvSessionRequest =
        match serde_json::from_value(request.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(
                    request,
                    "ProtocolError",
                    "invalid RegisterIdeEnvSession payload",
                );
            }
        };
    if payload.session_id.is_empty() {
        return error_response(request, "ProtocolError", "session_id must not be empty");
    }
    if payload.project_id.is_empty() {
        return error_response(request, "ProtocolError", "project_id must not be empty");
    }
    if payload.env_names.len() > MAX_IDE_ENV_SESSION_NAMES {
        return error_response(request, "ProtocolError", "env_names exceeds the per-session limit");
    }
    if payload.env_names.iter().any(String::is_empty) {
        return error_response(request, "ProtocolError", "env_names contains an empty name");
    }
    let ttl_seconds = payload.ttl_seconds.unwrap_or(DEFAULT_IDE_ENV_SESSION_TTL_SECONDS);
    if ttl_seconds == 0 || ttl_seconds > MAX_IDE_ENV_SESSION_TTL_SECONDS {
        return error_response(request, "ProtocolError", "ttl_seconds out of range");
    }

    // The audit row is HMAC-chained with the project audit key, so we
    // require an unlocked vault — `RegisterIdeEnvSession` is a write of
    // metadata-grade authorization state.
    let master_key = match cached_master_key(state, &payload.project_id, now_unix_nanos).await {
        Ok(Some(key)) => key,
        Ok(None) => {
            return error_response(
                request,
                "UnlockRequired",
                "unlock required to register an IDE env session",
            );
        }
        Err(error) => return error_response(request, "CorruptDb", error.to_string()),
    };
    let Ok(mut store) = Store::open(&payload.store_path) else {
        return error_response(request, "CorruptDb", "failed to open store");
    };
    let audit_key = match unwrap_audit_key_with_master(&store, &payload.project_id, &master_key) {
        Ok(key) => key,
        Err(error) => return error_response(request, "AuditIntegrityFailed", error.to_string()),
    };
    if append_register_audit(&mut store, &payload, audit_key.as_ref(), ttl_seconds, now_unix_nanos)
        .is_err()
    {
        return error_response(request, "CorruptDb", "failed to append AGENT_GRANT audit row");
    }

    let ttl_nanos = i128::from(ttl_seconds).saturating_mul(1_000_000_000);
    let entry = IdeEnvSessionEntry {
        project_id: payload.project_id.clone(),
        env_names: payload.env_names.clone(),
        expires_at_unix_nanos: now_unix_nanos.saturating_add(ttl_nanos),
    };
    {
        let mut registry = state.ide_env_sessions.lock().await;
        // Drop expired siblings opportunistically so the registry does
        // not grow unbounded across IDE reloads.
        registry.entries.retain(|_, existing| !existing.is_expired(now_unix_nanos));
        registry.insert(payload.session_id.clone(), entry);
    }

    success_response(
        request,
        &RegisterIdeEnvSessionResponse { session_id: payload.session_id, ttl_seconds },
    )
}

/// Handles `IdeEnvSession` lookups from a `locket run` consumer.
pub async fn handle_ide_env_session(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let payload: IdeEnvSessionRequest = match serde_json::from_value(request.payload.clone()) {
        Ok(payload) => payload,
        Err(_) => {
            return error_response(request, "ProtocolError", "invalid IdeEnvSession payload");
        }
    };
    if payload.session_id.is_empty() {
        return error_response(request, "ProtocolError", "session_id must not be empty");
    }
    if payload.project_id.is_empty() {
        return error_response(request, "ProtocolError", "project_id must not be empty");
    }

    let lookup = {
        let mut registry = state.ide_env_sessions.lock().await;
        match registry.entries.get(&payload.session_id) {
            None => SessionLookup::NotRegistered,
            Some(entry) if entry.is_expired(now_unix_nanos) => {
                registry.entries.remove(&payload.session_id);
                SessionLookup::Expired
            }
            Some(entry) if entry.project_id != payload.project_id => SessionLookup::ProjectMismatch,
            Some(entry) => SessionLookup::Live {
                env_names: entry.env_names.clone(),
                ttl_seconds_remaining: entry.ttl_seconds_remaining(now_unix_nanos),
            },
        }
    };

    // No audit row is emitted on lookup. The eventual `RUN`/`EXEC`
    // audit row written by the trusted CLI execution path already
    // records the resolved `secret_names`, so a per-fetch row here
    // would double-log without adding integrity coverage.
    match lookup {
        SessionLookup::Live { env_names, ttl_seconds_remaining } => {
            success_response(request, &IdeEnvSessionResponse { env_names, ttl_seconds_remaining })
        }
        SessionLookup::Expired => error_response(
            request,
            "IdeEnvSessionUnavailable",
            "IdeEnvSessionUnavailable: session expired",
        ),
        SessionLookup::NotRegistered => error_response(
            request,
            "IdeEnvSessionUnavailable",
            "IdeEnvSessionUnavailable: session not registered",
        ),
        SessionLookup::ProjectMismatch => error_response(
            request,
            "IdeEnvSessionUnavailable",
            "IdeEnvSessionUnavailable: project mismatch",
        ),
    }
}

enum SessionLookup {
    Live { env_names: Vec<String>, ttl_seconds_remaining: u32 },
    Expired,
    NotRegistered,
    ProjectMismatch,
}

fn append_register_audit(
    store: &mut Store,
    payload: &RegisterIdeEnvSessionRequest,
    audit_key: &[u8],
    ttl_seconds: u64,
    now_unix_nanos: i128,
) -> Result<(), locket_store::StoreError> {
    // Audit metadata is restricted to the known-field set in
    // `locket-store::audit`. We intentionally omit a numeric env-name
    // count here because the field is not on the allow-list; the
    // `RUN`/`EXEC` row written when the consumer actually injects the
    // names captures the resolved `secret_names`.
    let metadata = json!({
        "schema_version": 1,
        "action": "AGENT_GRANT",
        "status": "OK",
        "client_kind": "ide",
        "grant_actions": ["IdeEnvSession"],
        "ttl_seconds": ttl_seconds,
    });
    let timestamp = i64::try_from(now_unix_nanos).unwrap_or(i64::MAX);
    let write = AuditWrite {
        project_id: &payload.project_id,
        profile_id: payload.profile_id.as_deref(),
        action: "AGENT_GRANT",
        status: "OK",
        secret_name: None,
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key, &write)
}

fn success_response<T: Serialize>(request: &RequestEnvelope, payload: T) -> ResponseEnvelope {
    let payload = serde_json::to_value(payload).unwrap_or(serde_json::Value::Null);
    ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), payload))
}

fn error_response(
    request: &RequestEnvelope,
    error: &str,
    message: impl Into<String>,
) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), error, message, false))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::{
        DEFAULT_IDE_ENV_SESSION_TTL_SECONDS, IdeEnvSessionEntry, IdeEnvSessionRequest,
        IdeEnvSessionResponse, MAX_IDE_ENV_SESSION_TTL_SECONDS, RegisterIdeEnvSessionRequest,
        RegisterIdeEnvSessionResponse, handle_ide_env_session, handle_register_ide_env_session,
    };
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::AgentSocketState;
    use crate::unlock_cache::{UnlockCache, UnlockEntry, UnlockMethod};
    use locket_store::Store;
    use serde_json::json;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;

    fn build_store(path: &Path) {
        let mut store = Store::open(path).unwrap();
        store.initialize_schema().unwrap();
        store
            .connection()
            .execute("INSERT INTO projects(id, name, created_at) VALUES ('proj-1', 'p', 1)", [])
            .unwrap();
        store
            .connection()
            .execute(
                "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
                 VALUES ('prof-1', 'proj-1', 'default', 0, 1)",
                [],
            )
            .unwrap();
        crate::tests::insert_wrapped_audit_key(&store, "proj-1", &[7; 32], &[11; 32]).unwrap();
    }

    fn unlocked_state(project_id: &str, now: i128) -> AgentSocketState {
        let cache = Arc::new(Mutex::new(UnlockCache::default()));
        {
            let mut cache_guard = cache.try_lock().unwrap();
            cache_guard.insert(
                project_id.to_owned(),
                UnlockEntry::new(
                    vec![7_u8; 32],
                    now,
                    Duration::from_secs(600),
                    UnlockMethod::Passphrase,
                ),
            );
        }
        AgentSocketState::for_tests("test-version", crate::peer_cred::current_process_uid(), cache)
    }

    fn locked_state() -> AgentSocketState {
        let cache = Arc::new(Mutex::new(UnlockCache::default()));
        AgentSocketState::for_tests("test-version", crate::peer_cred::current_process_uid(), cache)
    }

    fn register_envelope(payload: &RegisterIdeEnvSessionRequest) -> RequestEnvelope {
        RequestEnvelope::new(
            "req-register",
            AgentMethod::RegisterIdeEnvSession,
            serde_json::to_value(payload).unwrap(),
        )
    }

    fn lookup_envelope(payload: &IdeEnvSessionRequest) -> RequestEnvelope {
        RequestEnvelope::new(
            "req-lookup",
            AgentMethod::IdeEnvSession,
            serde_json::to_value(payload).unwrap(),
        )
    }

    fn expect_success(response: ResponseEnvelope) -> serde_json::Value {
        match response {
            ResponseEnvelope::Success(success) => success.payload,
            ResponseEnvelope::Error(error) => panic!("expected success, got error: {error:?}"),
        }
    }

    fn expect_error(response: ResponseEnvelope) -> (String, String) {
        match response {
            ResponseEnvelope::Error(error) => (error.error, error.message),
            ResponseEnvelope::Success(success) => {
                panic!("expected error, got success: {success:?}")
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn register_then_lookup_returns_env_names_and_ttl() {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = tempdir.path().join("store.sqlite3");
        build_store(&store_path);
        let now: i128 = 1_700_000_000_000_000_000;
        let state = unlocked_state("proj-1", now);

        let register = RegisterIdeEnvSessionRequest {
            session_id: "sess-uuid-1".to_owned(),
            project_id: "proj-1".to_owned(),
            store_path: store_path.clone(),
            profile_id: Some("prof-1".to_owned()),
            env_names: vec!["DATABASE_URL".to_owned(), "API_TOKEN".to_owned()],
            ttl_seconds: Some(60),
        };
        let response =
            handle_register_ide_env_session(&register_envelope(&register), &state, now).await;
        let payload = expect_success(response);
        let decoded: RegisterIdeEnvSessionResponse = serde_json::from_value(payload).unwrap();
        assert_eq!(decoded.session_id, "sess-uuid-1");
        assert_eq!(decoded.ttl_seconds, 60);

        // Audit row landed.
        let audit_count: u32 = Store::open(&store_path)
            .unwrap()
            .connection()
            .query_row("SELECT COUNT(*) FROM audit_log WHERE action = 'AGENT_GRANT'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(audit_count, 1);

        let lookup = IdeEnvSessionRequest {
            session_id: "sess-uuid-1".to_owned(),
            project_id: "proj-1".to_owned(),
        };
        let response =
            handle_ide_env_session(&lookup_envelope(&lookup), &state, now + 5_000_000_000).await;
        let payload = expect_success(response);
        let decoded: IdeEnvSessionResponse = serde_json::from_value(payload).unwrap();
        assert_eq!(decoded.env_names, vec!["DATABASE_URL".to_owned(), "API_TOKEN".to_owned()]);
        assert!(decoded.ttl_seconds_remaining <= 60);
        assert!(decoded.ttl_seconds_remaining >= 54);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lookup_expired_session_returns_ide_env_session_unavailable() {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = tempdir.path().join("store.sqlite3");
        build_store(&store_path);
        let now: i128 = 1_700_000_000_000_000_000;
        let state = unlocked_state("proj-1", now);

        let register = RegisterIdeEnvSessionRequest {
            session_id: "sess-uuid-2".to_owned(),
            project_id: "proj-1".to_owned(),
            store_path,
            profile_id: None,
            env_names: vec!["X".to_owned()],
            ttl_seconds: Some(1),
        };
        let _ = handle_register_ide_env_session(&register_envelope(&register), &state, now).await;

        let later = now + 2_000_000_000_i128; // +2 seconds, past the 1-second TTL
        let lookup = IdeEnvSessionRequest {
            session_id: "sess-uuid-2".to_owned(),
            project_id: "proj-1".to_owned(),
        };
        let response = handle_ide_env_session(&lookup_envelope(&lookup), &state, later).await;
        let (error, message) = expect_error(response);
        assert_eq!(error, "IdeEnvSessionUnavailable");
        assert!(message.contains("expired"), "message: {message}");

        // Lazy eviction removed the entry.
        assert!(state.ide_env_sessions.lock().await.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lookup_unknown_session_returns_ide_env_session_unavailable() {
        let now: i128 = 1_700_000_000_000_000_000;
        let state = unlocked_state("proj-1", now);
        let lookup = IdeEnvSessionRequest {
            session_id: "not-registered".to_owned(),
            project_id: "proj-1".to_owned(),
        };
        let response = handle_ide_env_session(&lookup_envelope(&lookup), &state, now).await;
        let (error, message) = expect_error(response);
        assert_eq!(error, "IdeEnvSessionUnavailable");
        assert!(message.contains("not registered"), "message: {message}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn register_without_unlock_returns_unlock_required() {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = tempdir.path().join("store.sqlite3");
        build_store(&store_path);
        let now: i128 = 1_700_000_000_000_000_000;
        let state = locked_state();

        let register = RegisterIdeEnvSessionRequest {
            session_id: "sess-uuid-3".to_owned(),
            project_id: "proj-1".to_owned(),
            store_path,
            profile_id: None,
            env_names: vec!["A".to_owned()],
            ttl_seconds: Some(60),
        };
        let response =
            handle_register_ide_env_session(&register_envelope(&register), &state, now).await;
        let (error, _) = expect_error(response);
        assert_eq!(error, "UnlockRequired");

        assert!(state.ide_env_sessions.lock().await.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lookup_with_wrong_project_id_returns_ide_env_session_unavailable() {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = tempdir.path().join("store.sqlite3");
        build_store(&store_path);
        let now: i128 = 1_700_000_000_000_000_000;
        let state = unlocked_state("proj-1", now);

        let register = RegisterIdeEnvSessionRequest {
            session_id: "sess-uuid-4".to_owned(),
            project_id: "proj-1".to_owned(),
            store_path,
            profile_id: None,
            env_names: vec!["FOO".to_owned()],
            ttl_seconds: Some(60),
        };
        let _ = handle_register_ide_env_session(&register_envelope(&register), &state, now).await;

        let lookup = IdeEnvSessionRequest {
            session_id: "sess-uuid-4".to_owned(),
            project_id: "different-project".to_owned(),
        };
        let response = handle_ide_env_session(&lookup_envelope(&lookup), &state, now).await;
        let (error, message) = expect_error(response);
        assert_eq!(error, "IdeEnvSessionUnavailable");
        assert!(message.contains("project mismatch"), "message: {message}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn register_rejects_ttl_above_maximum() {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = tempdir.path().join("store.sqlite3");
        build_store(&store_path);
        let now: i128 = 1_700_000_000_000_000_000;
        let state = unlocked_state("proj-1", now);

        let register = RegisterIdeEnvSessionRequest {
            session_id: "sess-uuid-5".to_owned(),
            project_id: "proj-1".to_owned(),
            store_path,
            profile_id: None,
            env_names: vec!["FOO".to_owned()],
            ttl_seconds: Some(MAX_IDE_ENV_SESSION_TTL_SECONDS + 1),
        };
        let response =
            handle_register_ide_env_session(&register_envelope(&register), &state, now).await;
        let (error, _) = expect_error(response);
        assert_eq!(error, "ProtocolError");
    }

    #[test]
    fn entry_ttl_remaining_handles_expired_and_overflow() {
        let entry = IdeEnvSessionEntry {
            project_id: "p".to_owned(),
            env_names: vec!["X".to_owned()],
            expires_at_unix_nanos: 1_000,
        };
        assert_eq!(entry.ttl_seconds_remaining(2_000), 0);
        assert!(entry.is_expired(2_000));
        assert!(!entry.is_expired(500));
    }

    #[test]
    fn register_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request = RegisterIdeEnvSessionRequest {
            session_id: "sess".to_owned(),
            project_id: "proj".to_owned(),
            store_path: std::path::PathBuf::from("/tmp/store.sqlite3"),
            profile_id: Some("prof".to_owned()),
            env_names: vec!["A".to_owned(), "B".to_owned()],
            ttl_seconds: Some(DEFAULT_IDE_ENV_SESSION_TTL_SECONDS),
        };
        let value = serde_json::to_value(&request)?;
        let decoded: RegisterIdeEnvSessionRequest = serde_json::from_value(value.clone())?;
        assert_eq!(decoded, request);
        assert_eq!(value["session_id"], "sess");
        assert_eq!(value["env_names"][0], "A");
        Ok(())
    }

    #[test]
    fn lookup_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request =
            IdeEnvSessionRequest { session_id: "s".to_owned(), project_id: "p".to_owned() };
        let value = serde_json::to_value(&request)?;
        let decoded: IdeEnvSessionRequest = serde_json::from_value(value.clone())?;
        assert_eq!(decoded, request);
        assert_eq!(value["session_id"], "s");
        Ok(())
    }

    #[test]
    fn lookup_response_round_trips_through_json() -> Result<(), serde_json::Error> {
        let response =
            IdeEnvSessionResponse { env_names: vec!["X".to_owned()], ttl_seconds_remaining: 42 };
        let value = serde_json::to_value(&response)?;
        let decoded: IdeEnvSessionResponse = serde_json::from_value(value.clone())?;
        assert_eq!(decoded, response);
        assert_eq!(value["ttl_seconds_remaining"], 42);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn register_rejects_empty_session_id() {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = tempdir.path().join("store.sqlite3");
        build_store(&store_path);
        let now: i128 = 1_700_000_000_000_000_000;
        let state = unlocked_state("proj-1", now);

        let envelope = RequestEnvelope::new(
            "req",
            AgentMethod::RegisterIdeEnvSession,
            json!({
                "session_id": "",
                "project_id": "proj-1",
                "store_path": store_path,
                "env_names": [],
                "ttl_seconds": 60,
            }),
        );
        let response = handle_register_ide_env_session(&envelope, &state, now).await;
        let (error, _) = expect_error(response);
        assert_eq!(error, "ProtocolError");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn register_rejects_malformed_payload() {
        let tempdir = tempfile::tempdir().unwrap();
        let store_path = tempdir.path().join("store.sqlite3");
        build_store(&store_path);
        let now: i128 = 1_700_000_000_000_000_000;
        let state = unlocked_state("proj-1", now);

        let envelope = RequestEnvelope::new(
            "req",
            AgentMethod::RegisterIdeEnvSession,
            json!({"session_id": 1}),
        );
        let response = handle_register_ide_env_session(&envelope, &state, now).await;
        let (error, _) = expect_error(response);
        assert_eq!(error, "ProtocolError");
    }
}
