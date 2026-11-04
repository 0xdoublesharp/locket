//! Local agent and protocol types for Locket.

// age 0.11 enters through locket-core and carries older transitive crates
// alongside workspace versions. The sealed-bundle dependency owns that skew.
#![allow(clippy::multiple_crate_versions)]

mod auditing;
mod handlers;
mod protocol;
mod state;
mod transport;

pub(crate) use auditing::{audit, audit_deny, audit_verify, degraded_audit};
pub(crate) use handlers::{
    auth, backup, clients, config, device_members, mutations, policies, prepare_exec, profile,
    resolve, reveal, scan, secrets, set_secret, versions,
};
pub(crate) use protocol::{envelope, error, framing, method};
pub(crate) use state::{
    grant, ide_env_session, runtime_sessions, session_lock, status, status_stream, unlock_cache,
};
pub(crate) use transport::peer_cred;
#[cfg(any(unix, target_os = "windows"))]
pub(crate) use transport::server;
#[cfg(target_os = "windows")]
pub(crate) use transport::windows_pipe;

pub use audit::{AuditChainStatus, ListAuditRequest, ListAuditResponse, ListAuditRow};
pub use audit_verify::{VerifyAuditRequest, VerifyAuditResponse};
pub use auth::{ClientHelloRequest, ClientHelloResponse};
pub use backup::{
    BackupActionResponse, BundleConflictMode, BundleExportScope, ExportBundleRequest,
    ImportBundleRequest, RecoveryRotateRequest, RecoveryVerification, VerifyBundleRequest,
    VerifyBundleResponse,
};
pub use clients::{
    RegisterClientRequest, RegisterClientResponse, RevokeClientRequest, RevokeClientResponse,
};
pub use config::{
    AgentConfigSettings, DangerousProfileSetting, EffectiveUserVerificationSettings,
    ReadConfigRequest, UserVerificationSettings, WriteConfigChanges, WriteConfigRequest,
    WriteConfigResponse,
};
pub use device_members::{
    DeviceMemberKind, DeviceMemberRow, ListDeviceMembersRequest, ListDeviceMembersResponse,
};
pub use envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
pub use error::ProtocolError;
pub use framing::{decode_request_frame, decode_response_frame, encode_frame};
pub use grant::{
    ExecutionScope, GrantAction, GrantBinding, GrantIdPayload, GrantRecord, GrantRecordFields,
    GrantTable, GrantValidation, RequestGrantPayload,
};
pub use ide_env_session::{
    DEFAULT_IDE_ENV_SESSION_TTL_SECONDS, IdeEnvSessionEntry, IdeEnvSessionRegistry,
    IdeEnvSessionRequest, IdeEnvSessionResponse, MAX_IDE_ENV_SESSION_NAMES,
    MAX_IDE_ENV_SESSION_TTL_SECONDS, RegisterIdeEnvSessionRequest, RegisterIdeEnvSessionResponse,
};
pub use method::{AgentMethod, UnknownMethod};
pub use peer_cred::current_process_uid;
#[cfg(unix)]
pub use peer_cred::{validate_peer_stream, validate_peer_uid};
pub use policies::{
    CommandPolicyRow, CommandPolicySnapshot, ListPoliciesRequest, ListPoliciesResponse,
    PolicyDoctorRequest, PolicyDoctorResponse, RegisterCommandPoliciesRequest,
};
pub use prepare_exec::{PrepareExecRequest, PrepareExecResponse};
pub use profile::{SetActiveProfileRequest, SetActiveProfileResponse};
pub use resolve::{ResolveRequest, ResolveResponse};
pub use reveal::{CopyRequest, CopyResponse, RevealRequest, RevealResponse};
pub use runtime_sessions::{
    ListRuntimeSessionsRequest, ListRuntimeSessionsResponse, RuntimeSessionRow,
    RuntimeSessionSnapshot, RuntimeSessionState,
};
pub use scan::{ScanFinding, ScanRequest, ScanResponse};
pub use secrets::{ListSecretsRequest, ListSecretsResponse, ListSecretsRow};
#[cfg(unix)]
pub use server::{
    AgentSocketConfig, ConnectionOutcome, SocketServerError, bind_socket_listener,
    handle_connection, socket_permission_mode,
};
pub use server::{AgentSocketState, dispatch};
pub use session_lock::{
    SessionLockAudit, SessionLockOutcome, SessionLockSource, append_lock_audit, lock_audit_metadata,
};
pub use set_secret::{SetSecretRequest, SetSecretResponse};
pub use status::{
    LockState, STATUS_HEARTBEAT_INTERVAL_SECS, StatusEvent, StatusEventKind, StatusEventSequence,
    StatusPayload,
};
pub use status_stream::{StatusHub, StatusSubscriber};
pub use unlock_cache::{UnlockCache, UnlockEntry, UnlockMethod};
pub use versions::{ListVersionsRequest, ListVersionsResponse, ListVersionsRow};
#[cfg(target_os = "windows")]
pub use windows_pipe::{
    AgentPipeConfig, bind_named_pipe_instance, bind_named_pipe_listener, connect_named_pipe_client,
    handle_named_pipe_connection,
};

/// Maximum v1 protocol message size in bytes.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Agent protocol version supported by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub use mutations::{
    ApplyPolicyRequest, ApplyPolicyResponse, ImportDiagnostic, ImportDotenvRequest,
    ImportDotenvResponse, MutationError, MutationScope, apply_policy_with_master,
    import_dotenv_with_master,
};

pub mod team_sync;

pub use handlers::team_sync::{TeamSyncConfigureRequest, TeamSyncRequest, spawn_team_sync_poll};

#[cfg(test)]
use x25519_dalek as _;

pub use protocol::team_sync::{TeamSyncAction, TeamSyncReconcileRequest};
pub use team_sync::{PendingCollision, PendingProfileDetails};
