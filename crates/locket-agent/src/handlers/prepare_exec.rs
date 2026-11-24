//! Typed payloads for the `PrepareExec` agent RPC.
//!
//! `PrepareExec` resolves a saved command policy into the precise set of
//! environment variable names the trusted CLI execution path is
//! authorized to inject, plus a TTL hint for the resulting grant. See
//! `docs/specs/agent.md:91-92` and `docs/specs/runtime.md:5-122` for
//! the contract this handler satisfies.
//!
//! The handler enforces unlock + policy lookup, derives the allowed
//! env-name set from the policy's normalized `allowed_secrets` union,
//! picks the `command_kind` from the policy's command spec, issues a
//! live [`GrantAction::PrepareExec`] grant in the in-memory grant
//! table, and surfaces the grant id on the response so callers
//! (`policy doctor`, the CLI execution path) can reuse it for the
//! follow-up `ResolveReference` calls without issuing a second
//! `RequestGrant` round-trip.
//!
//! No audit row is emitted at the prepare-exec stage. The data-model
//! spec (`docs/specs/data-model.md:296-300`) classifies `PrepareExec`
//! as agent-internal, with the externally observable audit row written
//! at the eventual `RUN`/`EXEC` step. The audit ledger therefore
//! intentionally remains untouched here.

use std::process;

use locket_core::LocketError;
use serde::{Deserialize, Serialize};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::grant::{GrantAction, GrantBinding, RequestGrantPayload};
use crate::policies::CommandPolicySnapshot;

/// Default `command_kind` value emitted when the looked-up policy is
/// argv-shaped.
///
/// Saved policies most often describe an argv-style invocation; the
/// other supported value is `"shell"`, used for explicit shell
/// pipelines.
const DEFAULT_COMMAND_KIND: &str = "argv";

/// Wire `error` value used when the vault is locked.
const ERROR_UNLOCK_REQUIRED: &str = "UnlockRequired";
/// Wire `error` value used when the named policy cannot be resolved.
const ERROR_POLICY_NOT_FOUND: &str = "PolicyNotFound";
/// Wire `error` value used for transient grant id generation failures.
const ERROR_PROTOCOL: &str = "ProtocolError";

/// Redacted denial message returned to clients when the vault is
/// locked.
const UNLOCK_REQUIRED_MESSAGE: &str =
    "vault is locked; unlock required before preparing a command policy";
/// Redacted denial message returned to clients when the policy is
/// missing.
const POLICY_NOT_FOUND_MESSAGE: &str = "command policy not found";

/// Fallback TTL for prepare-exec grants when the policy itself does
/// not declare an explicit value. Saved policies always carry a TTL
/// today, so this constant is only consulted if the in-memory snapshot
/// reports `0`.
// TODO(policy-ttls): centralize prepare-exec/run-policy TTL fallbacks
// in the policy crate so the agent does not have to second-guess
// snapshots that report `ttl_seconds = 0`.
const DEFAULT_PREPARE_EXEC_TTL_SECONDS: u64 = 60;

/// Request payload for `PrepareExec`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrepareExecRequest {
    /// Name of the saved command policy to prepare.
    pub policy_name: String,
    /// Profile id whose secrets the policy should resolve against.
    pub profile_id: String,
    /// Project id whose policy registry should be consulted.
    pub project_id: String,
    /// Caller's process binding for the issued grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<GrantBinding>,
}

/// Response payload for `PrepareExec`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrepareExecResponse {
    /// Environment variable names the executor is authorized to inject.
    /// The list is metadata only: no values are exposed here.
    pub allowed_env_names: Vec<String>,
    /// Shape of the command invocation, e.g. `"argv"` or `"shell"`.
    pub command_kind: String,
    /// Time-to-live hint, in seconds, for the prepared invocation.
    pub ttl_seconds: u32,
    /// Opaque id of the live [`GrantAction::PrepareExec`] grant the
    /// agent issued for this prepare.
    pub grant_id: String,
}

/// Handler for `PrepareExec`.
///
/// Looks up the named policy for the active project, validates that
/// the agent is unlocked, issues a live grant for
/// [`GrantAction::PrepareExec`], and returns the policy's allowed env
/// names, command kind, grant TTL, and live grant id.
pub async fn handle_prepare_exec(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
    observed_pid: Option<u32>,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<PrepareExecRequest>(request.payload.clone()) else {
        return protocol_error(request, "invalid PrepareExec payload");
    };
    let project_id = typed.project_id.as_str();

    // Look up the named policy from the in-memory registry. Cloning
    // the snapshot lets us drop the lock before we touch the unlock
    // cache and grant table.
    let policy = {
        let policies = state.command_policies.lock().await;
        find_policy(&policies, project_id, &typed.policy_name).cloned()
    };
    let Some(policy) = policy else {
        return typed_error(
            request,
            ERROR_POLICY_NOT_FOUND,
            POLICY_NOT_FOUND_MESSAGE,
            LocketError::PolicyNotFound,
        );
    };

    // Verify the project is unlocked. The unlock cache lookup is the
    // same gate the reveal/copy/resolve handlers use, so prepare-exec
    // shares the same fail-closed semantics.
    let unlocked = {
        let cache = state.unlock_cache.lock().await;
        cache.lookup(project_id, now_unix_nanos).is_some()
    };
    if !unlocked {
        crate::degraded_audit::record_locked_refusal(
            "PREPARE_EXEC",
            Some(project_id),
            "agent.PrepareExec",
            None,
            now_unix_nanos,
        );
        return typed_error(
            request,
            ERROR_UNLOCK_REQUIRED,
            UNLOCK_REQUIRED_MESSAGE,
            LocketError::UnlockRequired,
        );
    }

    let ttl_seconds = ttl_seconds(&policy);
    let command_kind = command_kind(&policy);
    let allowed_env_names = policy.allowed_secrets.clone();

    let Some(binding) = typed.binding.or_else(|| prepare_binding(observed_pid)) else {
        return typed_error(
            request,
            "AccessDenied",
            "connecting process identity is unavailable",
            LocketError::AccessDenied,
        );
    };
    let mut grant_payload = RequestGrantPayload {
        project_id: project_id.to_owned(),
        profile_id: typed.profile_id.clone(),
        policy_name: Some(policy.name.clone()),
        action: GrantAction::PrepareExec,
        confirm_dangerous: false,
        ttl_seconds,
        binding,
    };
    if !crate::grant::constrain_peer_grant(&mut grant_payload, observed_pid) {
        return typed_error(
            request,
            "AccessDenied",
            "grant binding does not match the connecting process",
            LocketError::AccessDenied,
        );
    }
    let ttl_seconds = grant_payload.ttl_seconds;
    let ttl_nanos = i128::from(ttl_seconds).saturating_mul(1_000_000_000);
    let issued = {
        let mut grants = state.grants.lock().await;
        grants.issue_with_peer(
            grant_payload,
            now_unix_nanos,
            now_unix_nanos.saturating_add(ttl_nanos),
            observed_pid,
            None,
        )
    };
    let grant_id = match issued {
        Ok(record) => record.grant_id,
        Err(_) => {
            return typed_error(
                request,
                ERROR_PROTOCOL,
                "failed to allocate grant id",
                LocketError::CorruptDb,
            );
        }
    };

    let response = PrepareExecResponse {
        allowed_env_names,
        command_kind: command_kind.to_owned(),
        ttl_seconds: u32::try_from(ttl_seconds).unwrap_or(u32::MAX),
        grant_id,
    };
    serde_json::to_value(&response).map_or_else(
        |_| protocol_error(request, "failed to serialize PrepareExec response"),
        |payload| ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), payload)),
    )
}

fn prepare_binding(observed_pid: Option<u32>) -> Option<GrantBinding> {
    let Some(pid) = observed_pid else {
        return Some(GrantBinding::new(process::id(), "0"));
    };
    let live = locket_platform::process_binding_for_pid(pid).ok()?;
    Some(GrantBinding::new(pid, live.process_start_time))
}

fn find_policy<'a>(
    policies: &'a [CommandPolicySnapshot],
    project_id: &str,
    policy_name: &str,
) -> Option<&'a CommandPolicySnapshot> {
    policies.iter().find(|policy| policy.project_id == project_id && policy.name == policy_name)
}

const fn ttl_seconds(policy: &CommandPolicySnapshot) -> u64 {
    if policy.ttl_seconds == 0 { DEFAULT_PREPARE_EXEC_TTL_SECONDS } else { policy.ttl_seconds }
}

fn command_kind(policy: &CommandPolicySnapshot) -> &str {
    if policy.command_kind == "shell" { "shell" } else { DEFAULT_COMMAND_KIND }
}

fn protocol_error(request: &RequestEnvelope, message: &str) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), ERROR_PROTOCOL, message, false))
}

fn typed_error(
    request: &RequestEnvelope,
    error: &'static str,
    message: impl Into<String>,
    _kind: LocketError,
) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), error, message, false))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::{
        DEFAULT_COMMAND_KIND, DEFAULT_PREPARE_EXEC_TTL_SECONDS, PrepareExecRequest,
        PrepareExecResponse, handle_prepare_exec,
    };
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::grant::GrantBinding;
    use crate::method::AgentMethod;
    use crate::policies::CommandPolicySnapshot;
    use crate::server::AgentSocketState;
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};
    use serde_json::json;
    use std::time::Duration;

    const PROJECT_ID: &str = "lk_proj_prepare_exec";
    const PROFILE_ID: &str = "lk_prof_dev";
    const POLICY_NAME: &str = "deploy-staging";

    fn snapshot(ttl_seconds: u64, command_kind: &str, allowed: &[&str]) -> CommandPolicySnapshot {
        CommandPolicySnapshot {
            project_id: PROJECT_ID.to_owned(),
            name: POLICY_NAME.to_owned(),
            command_kind: command_kind.to_owned(),
            command_preview: "deploy".to_owned(),
            required_secrets: allowed.iter().map(|s| (*s).to_owned()).collect(),
            optional_secrets: Vec::new(),
            allowed_secrets: allowed.iter().map(|s| (*s).to_owned()).collect(),
            confirm: false,
            require_user_verification: false,
            require_agent: true,
            allow_remote_docker: false,
            ttl_seconds,
            env_mode: "minimal".to_owned(),
            override_mode: "locket".to_owned(),
            updated_at_unix_nanos: 1,
        }
    }

    async fn unlocked_state(policy: CommandPolicySnapshot) -> AgentSocketState {
        let state = AgentSocketState::locked("test-version");
        state.set_command_policies_for_tests(vec![policy]).await;
        state.unlock_cache.lock().await.insert(
            PROJECT_ID.to_owned(),
            UnlockEntry::new(vec![7_u8; 32], 0, Duration::from_secs(60), UnlockMethod::Passphrase),
        );
        state
    }

    fn request_payload(project_id: Option<&str>) -> serde_json::Value {
        let mut payload = json!({
            "policy_name": POLICY_NAME,
            "profile_id": PROFILE_ID,
            "binding": GrantBinding::new(std::process::id(), "0"),
        });
        if let Some(project_id) = project_id {
            payload.as_object_mut().unwrap().insert("project_id".to_owned(), json!(project_id));
        }
        payload
    }

    #[test]
    fn prepare_exec_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request = PrepareExecRequest {
            policy_name: "deploy-staging".to_owned(),
            profile_id: "profile-staging".to_owned(),
            project_id: PROJECT_ID.to_owned(),
            binding: Some(GrantBinding::new(123, "start")),
        };

        let value = serde_json::to_value(&request)?;
        let decoded: PrepareExecRequest = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, request);
        assert_eq!(value["policy_name"], "deploy-staging");
        assert_eq!(value["profile_id"], "profile-staging");
        assert_eq!(value["project_id"], PROJECT_ID);
        Ok(())
    }

    #[test]
    fn prepare_exec_response_round_trips_through_json() -> Result<(), serde_json::Error> {
        let response = PrepareExecResponse {
            allowed_env_names: vec!["DATABASE_URL".to_owned(), "API_TOKEN".to_owned()],
            command_kind: "argv".to_owned(),
            ttl_seconds: 60,
            grant_id: "lk_grant_0123456789abcdef0123456789abcdef".to_owned(),
        };

        let value = serde_json::to_value(&response)?;
        let decoded: PrepareExecResponse = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, response);
        assert_eq!(value["command_kind"], "argv");
        assert_eq!(value["ttl_seconds"], 60);
        assert_eq!(value["grant_id"], "lk_grant_0123456789abcdef0123456789abcdef");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_prepare_exec_returns_policy_env_names_and_ttl()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = snapshot(900, "argv", &["DATABASE_URL", "API_TOKEN"]);
        let state = unlocked_state(policy).await;
        let envelope = RequestEnvelope::new(
            "req-prepare",
            AgentMethod::PrepareExec,
            request_payload(Some(PROJECT_ID)),
        );

        let response = handle_prepare_exec(&envelope, &state, 1, None).await;
        let ResponseEnvelope::Success(success) = response else {
            return Err("expected success envelope".into());
        };
        assert_eq!(success.id, "req-prepare");
        let decoded: PrepareExecResponse = serde_json::from_value(success.payload)?;
        assert_eq!(decoded.allowed_env_names, vec!["DATABASE_URL", "API_TOKEN"]);
        assert_eq!(decoded.command_kind, DEFAULT_COMMAND_KIND);
        assert_eq!(decoded.ttl_seconds, 900);

        // The response surfaces the live grant id so callers can
        // resolve `lk://` references without a second RequestGrant
        // round-trip. The id must match the typed `lk_grant_<32 hex>`
        // shape minted by `locket_core::id::GrantId::generate`.
        assert!(
            decoded.grant_id.starts_with("lk_grant_"),
            "grant_id must be lk_grant_ prefixed: {}",
            decoded.grant_id
        );
        let suffix = decoded.grant_id.strip_prefix("lk_grant_").ok_or("grant_id prefix missing")?;
        assert_eq!(suffix.len(), 32, "lk_grant_ suffix must be 32 hex chars");
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));

        // Issuing a grant must record exactly one record in the table,
        // and the live record must have the PrepareExec action.
        let action = {
            let grants = state.grants.lock().await;
            assert_eq!(grants.len(), 1);
            grants.get(&decoded.grant_id).ok_or("grant record missing")?.action
        };
        assert_eq!(action, crate::grant::GrantAction::PrepareExec);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_prepare_exec_emits_shell_command_kind() -> Result<(), Box<dyn std::error::Error>>
    {
        let policy = snapshot(120, "shell", &["DEPLOY_TOKEN"]);
        let state = unlocked_state(policy).await;
        let envelope = RequestEnvelope::new(
            "req-shell",
            AgentMethod::PrepareExec,
            request_payload(Some(PROJECT_ID)),
        );

        let response = handle_prepare_exec(&envelope, &state, 1, None).await;
        let ResponseEnvelope::Success(success) = response else {
            return Err("expected success envelope".into());
        };
        let decoded: PrepareExecResponse = serde_json::from_value(success.payload)?;
        assert_eq!(decoded.command_kind, "shell");
        assert_eq!(decoded.ttl_seconds, 120);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_prepare_exec_falls_back_to_default_ttl_when_policy_ttl_is_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = snapshot(0, "argv", &["DATABASE_URL"]);
        let state = unlocked_state(policy).await;
        let envelope = RequestEnvelope::new(
            "req-default-ttl",
            AgentMethod::PrepareExec,
            request_payload(Some(PROJECT_ID)),
        );

        let response = handle_prepare_exec(&envelope, &state, 1, None).await;
        let ResponseEnvelope::Success(success) = response else {
            return Err("expected success envelope".into());
        };
        let decoded: PrepareExecResponse = serde_json::from_value(success.payload)?;
        assert_eq!(u64::from(decoded.ttl_seconds), DEFAULT_PREPARE_EXEC_TTL_SECONDS);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_prepare_exec_returns_unlock_required_when_locked() {
        let policy = snapshot(60, "argv", &["DATABASE_URL"]);
        let state = AgentSocketState::locked("test-version");
        state.set_command_policies_for_tests(vec![policy]).await;
        let envelope = RequestEnvelope::new(
            "req-locked",
            AgentMethod::PrepareExec,
            request_payload(Some(PROJECT_ID)),
        );

        // The degraded-audit log path falls back to the user data dir
        // when the request omits a store_path; we don't assert on the
        // file here to avoid touching the real `${LOCKET_HOME}` from
        // tests. The wiring is exercised by
        // `degraded_audit::tests::record_locked_refusal_writes_to_store_path_parent`
        // and the per-handler reveal/scan/resolve tests.
        let response = handle_prepare_exec(&envelope, &state, 1, None).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "UnlockRequired");
        assert!(state.grants.lock().await.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_prepare_exec_returns_policy_not_found_for_missing_policy() {
        let state = AgentSocketState::locked("test-version");
        let envelope = RequestEnvelope::new(
            "req-missing",
            AgentMethod::PrepareExec,
            request_payload(Some(PROJECT_ID)),
        );

        let response = handle_prepare_exec(&envelope, &state, 1, None).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "PolicyNotFound");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_prepare_exec_rejects_malformed_payload_with_protocol_error() {
        let state = AgentSocketState::locked("test-version");
        let envelope = RequestEnvelope::new(
            "req-bad",
            AgentMethod::PrepareExec,
            json!({"policy_name": 1, "profile_id": null}),
        );

        let response = handle_prepare_exec(&envelope, &state, 1, None).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "ProtocolError");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_prepare_exec_requires_project_id() {
        let state = AgentSocketState::locked("test-version");
        let envelope =
            RequestEnvelope::new("req-no-project", AgentMethod::PrepareExec, request_payload(None));

        let response = handle_prepare_exec(&envelope, &state, 1, None).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "ProtocolError");
    }
}
