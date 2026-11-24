//! Metadata-only saved command policy listing for desktop policy views.

use std::collections::BTreeSet;
use std::path::PathBuf;

use locket_core::{CommandPolicy, CommandSpec, LkReferenceUri, LocketError, privacy_alias};
use locket_store::{AuditWrite, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::resolve::{preferred_active_secret, version_is_resolvable};
use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::grant::GrantBinding;
use crate::keys::{master_key_array, unwrap_audit_key_with_master};

/// Request for saved command policy metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListPoliciesRequest {
    /// Active project identifier.
    pub project_id: String,
    /// Whether exact policy and secret names should be replaced with privacy aliases.
    pub privacy_redact_names: bool,
}

/// Response containing metadata-only saved command policy rows.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListPoliciesResponse {
    /// Rows scoped to the requested project.
    pub rows: Vec<CommandPolicyRow>,
}

/// Agent-held saved policy metadata. Never contains secret values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct CommandPolicySnapshot {
    /// Parent project identifier.
    pub project_id: String,
    /// Saved command policy name.
    pub name: String,
    /// Command representation: `argv` or `shell`.
    pub command_kind: String,
    /// Metadata-only command preview for UI display.
    pub command_preview: String,
    /// Required secret names.
    pub required_secrets: Vec<String>,
    /// Optional secret names.
    pub optional_secrets: Vec<String>,
    /// Union of required and optional secret names.
    pub allowed_secrets: Vec<String>,
    /// Whether execution requires typed confirmation.
    pub confirm: bool,
    /// Whether execution requires local user verification.
    pub require_user_verification: bool,
    /// Whether execution must go through the local agent.
    pub require_agent: bool,
    /// Whether Docker helpers may target remote contexts.
    pub allow_remote_docker: bool,
    /// Grant TTL in seconds.
    pub ttl_seconds: u64,
    /// Base child environment policy.
    pub env_mode: String,
    /// Conflict behavior for injected Locket names.
    pub override_mode: String,
    /// Updated timestamp in nanoseconds since the Unix epoch.
    pub updated_at_unix_nanos: i64,
}

impl CommandPolicySnapshot {
    /// Build metadata for a parsed policy and project-local update timestamp.
    #[must_use]
    pub fn from_policy(
        project_id: impl Into<String>,
        policy: &CommandPolicy,
        updated_at_unix_nanos: i64,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            name: policy.name.clone(),
            command_kind: command_kind(&policy.command).to_owned(),
            command_preview: command_preview(&policy.command),
            required_secrets: policy.required_secrets.iter().map(ToString::to_string).collect(),
            optional_secrets: policy.optional_secrets.iter().map(ToString::to_string).collect(),
            allowed_secrets: policy.allowed_secrets.iter().map(ToString::to_string).collect(),
            confirm: policy.confirm,
            require_user_verification: policy.require_user_verification,
            require_agent: policy.require_agent,
            allow_remote_docker: policy.allow_remote_docker,
            ttl_seconds: policy.ttl.as_secs(),
            env_mode: policy.env_mode.as_str().to_owned(),
            override_mode: policy.override_behavior.as_str().to_owned(),
            updated_at_unix_nanos,
        }
    }
}

/// Wire row consumed by desktop policy surfaces.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct CommandPolicyRow {
    /// Stable row identifier. Alias when privacy mode is enabled.
    pub id: String,
    /// Exact policy name when privacy is off; alias when privacy is on.
    pub name: String,
    /// Policy alias when privacy is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Command representation: `argv` or `shell`.
    pub command_kind: String,
    /// Metadata-only command preview.
    pub command_preview: String,
    /// Required secret names, or aliases in privacy mode.
    pub required_secrets: Vec<String>,
    /// Optional secret names, or aliases in privacy mode.
    pub optional_secrets: Vec<String>,
    /// Union of policy-visible names, or aliases in privacy mode.
    pub allowed_secrets: Vec<String>,
    /// Whether execution requires typed confirmation.
    pub confirm: bool,
    /// Whether execution requires local user verification.
    pub require_user_verification: bool,
    /// Whether execution must go through the local agent.
    pub require_agent: bool,
    /// Whether Docker helpers may target remote contexts.
    pub allow_remote_docker: bool,
    /// Grant TTL in seconds.
    pub ttl_seconds: u64,
    /// Base child environment policy.
    pub env_mode: String,
    /// Conflict behavior for injected Locket names.
    pub override_mode: String,
    /// Updated timestamp in nanoseconds since the Unix epoch.
    pub updated_at_unix_nanos: i64,
}

/// Builds the socket response for the saved policy list request.
#[must_use]
pub fn list_policies_response(
    request: &ListPoliciesRequest,
    policies: &[CommandPolicySnapshot],
) -> ListPoliciesResponse {
    let mut rows = policies
        .iter()
        .filter(|policy| policy.project_id == request.project_id)
        .map(|policy| command_policy_row(request, policy))
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| right.updated_at_unix_nanos.cmp(&left.updated_at_unix_nanos))
    });
    ListPoliciesResponse { rows }
}

fn command_policy_row(
    request: &ListPoliciesRequest,
    policy: &CommandPolicySnapshot,
) -> CommandPolicyRow {
    let alias = request.privacy_redact_names.then(|| privacy_alias("policy", &policy.name));
    CommandPolicyRow {
        id: alias.clone().unwrap_or_else(|| policy.name.clone()),
        name: alias.clone().unwrap_or_else(|| policy.name.clone()),
        alias,
        command_kind: policy.command_kind.clone(),
        command_preview: policy.command_preview.clone(),
        required_secrets: secret_labels(&policy.required_secrets, request.privacy_redact_names),
        optional_secrets: secret_labels(&policy.optional_secrets, request.privacy_redact_names),
        allowed_secrets: secret_labels(&policy.allowed_secrets, request.privacy_redact_names),
        confirm: policy.confirm,
        require_user_verification: policy.require_user_verification,
        require_agent: policy.require_agent,
        allow_remote_docker: policy.allow_remote_docker,
        ttl_seconds: policy.ttl_seconds,
        env_mode: policy.env_mode.clone(),
        override_mode: policy.override_mode.clone(),
        updated_at_unix_nanos: policy.updated_at_unix_nanos,
    }
}

fn secret_labels(names: &[String], privacy_redact_names: bool) -> Vec<String> {
    names
        .iter()
        .map(|name| if privacy_redact_names { privacy_alias("secret", name) } else { name.clone() })
        .collect()
}

const fn command_kind(command: &CommandSpec) -> &'static str {
    match command {
        CommandSpec::Argv(_) => "argv",
        CommandSpec::Shell(_) => "shell",
    }
}

fn command_preview(command: &CommandSpec) -> String {
    match command {
        CommandSpec::Argv(argv) => argv.join(" "),
        CommandSpec::Shell(shell) => shell.clone(),
    }
}

/// Handles invalid-payload conversion for the dispatcher.
#[must_use]
pub fn invalid_payload_response(envelope: &RequestEnvelope) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(
        envelope.id.clone(),
        "ProtocolError",
        "invalid ListPolicies payload",
        false,
    ))
}

/// Encodes a successful saved policy list response.
#[must_use]
pub fn success_response(
    envelope: &RequestEnvelope,
    response: ListPoliciesResponse,
) -> ResponseEnvelope {
    let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
    ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
}

/// Request payload for `RegisterCommandPolicies`.
///
/// The CLI emits this RPC after every `policy add/allow/require/edit/delete`
/// write to `locket.toml`, so the running agent's in-memory snapshot stays
/// in sync with the on-disk policy set without requiring a desktop client
/// to pump the snapshots.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterCommandPoliciesRequest {
    /// Active project identifier whose snapshot should be replaced.
    pub project_id: String,
    /// Replacement snapshots for `project_id`. The agent retains
    /// snapshots for other projects unchanged.
    pub policies: Vec<CommandPolicySnapshot>,
    /// Path to the user-scoped `store.db` used to append the
    /// metadata-only `POLICY_UPDATE` audit row.
    pub store_path: PathBuf,
    /// Optional active profile id recorded on the audit row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_profile_id: Option<String>,
}

/// Request payload for the agent-side command-policy dry-run validator.
///
/// The desktop policy editor sends the candidate metadata snapshot
/// before committing it. The response is metadata-only: it reports
/// allowed env names and reference validation status without returning
/// secret values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyDoctorRequest {
    /// Active project identifier.
    pub project_id: String,
    /// Profile id the candidate policy would execute under.
    pub profile_id: String,
    /// Candidate policy metadata to validate.
    pub policy: CommandPolicySnapshot,
    /// Explicit `lk://` references found by the caller. If empty, the
    /// agent scans `policy.command_preview` as a conservative fallback.
    #[serde(default)]
    pub references: Vec<String>,
    /// Path to the user-scoped `store.db` used for metadata-only
    /// reference existence checks.
    pub store_path: PathBuf,
    /// Optional process binding reserved for follow-up grant-aware
    /// validation. Accepted now so desktop callers can pass the same
    /// shape as `PrepareExec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<GrantBinding>,
}

/// Metadata-only response from `PolicyDoctor`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyDoctorResponse {
    /// `pass` when every reference resolves under the candidate
    /// allow-list, otherwise `fail`.
    pub status: String,
    /// Environment variable names the candidate policy can inject.
    pub allowed_env_names: Vec<String>,
    /// Grant TTL the execution path would use.
    pub ttl_seconds: u32,
    /// Number of `lk://` references that passed validation.
    pub references_ok: usize,
    /// References that failed syntax, authorization, profile, or active
    /// secret checks.
    pub references_failed: Vec<String>,
    /// Candidate secret names that would pass through from parent or
    /// external environment.
    pub env_mode_passthrough: Vec<String>,
    /// Candidate secret names resolved from `lk://` references.
    pub env_mode_resolve: Vec<String>,
    /// Candidate secret names denied by the policy allow-list.
    pub env_mode_denied: Vec<String>,
}

/// Replaces the in-memory snapshots for a single project.
///
/// All entries previously stored for `project_id` are removed; entries
/// for other project ids are preserved. The replacement is in-place to
/// keep the snapshot vector flat, matching the existing `ListPolicies`
/// path which filters by `project_id` on read.
pub fn replace_project_snapshots(
    snapshots: &mut Vec<CommandPolicySnapshot>,
    project_id: &str,
    replacements: Vec<CommandPolicySnapshot>,
) {
    snapshots.retain(|snapshot| snapshot.project_id != project_id);
    for replacement in replacements {
        if replacement.project_id == project_id {
            snapshots.push(replacement);
        }
    }
}

/// Handler for `RegisterCommandPolicies`.
///
/// The agent must have a live unlock-cache entry for `project_id` so
/// callers cannot mutate snapshots for projects they have not unlocked.
/// On success a metadata-only `POLICY_UPDATE` audit row with
/// `operation: "snapshot"` is appended to the project audit chain.
pub async fn handle_register_command_policies(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let typed: RegisterCommandPoliciesRequest =
        match serde_json::from_value(request.payload.clone()) {
            Ok(value) => value,
            Err(_) => {
                return ResponseEnvelope::Error(ErrorEnvelope::new(
                    request.id.clone(),
                    "ProtocolError",
                    "invalid RegisterCommandPolicies payload",
                    false,
                ));
            }
        };

    // Keep authorization alive through audit and snapshot publication so Lock waits.
    let cache = state.unlock_cache.lock().await;
    let Some(entry) = cache.lookup(&typed.project_id, now_unix_nanos) else {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "UnlockRequired",
            "unlock required to register command policies",
            false,
        ));
    };
    let Ok(master) = master_key_array(entry.key_bytes()) else {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "CorruptDb",
            "invalid cached key",
            false,
        ));
    };
    let policy_count = typed.policies.len();
    let metadata = json!({
        "schema_version": 1,
        "action": "POLICY_UPDATE",
        "status": "SUCCESS",
        "command": "policy",
        "operation": "snapshot",
        "change_kind": "snapshot",
        "policy": "*",
        "policy_name": "*",
        "command_policy_count": policy_count,
        "metadata_only": true,
    });
    let timestamp = i64::try_from(now_unix_nanos).unwrap_or(i64::MAX);
    let audit = AuditWrite {
        project_id: &typed.project_id,
        profile_id: typed.audit_profile_id.as_deref(),
        action: "POLICY_UPDATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("policy"),
        metadata_json: &metadata,
        timestamp,
    };
    let Ok(mut store) = Store::open(&typed.store_path) else {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "CorruptDb",
            "failed to open policy audit store",
            false,
        ));
    };
    let Ok(audit_key) = unwrap_audit_key_with_master(&store, &typed.project_id, &master) else {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "CorruptDb",
            "failed to derive policy audit key",
            false,
        ));
    };
    let mut snapshots = state.command_policies.lock().await;
    if store.append_audit(audit_key.as_ref(), &audit).is_err() {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "CorruptDb",
            "failed to append POLICY_UPDATE audit row",
            false,
        ));
    }
    replace_project_snapshots(&mut snapshots, &typed.project_id, typed.policies);
    drop(snapshots);
    drop(cache);

    ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), serde_json::Value::Null))
}

/// Handler for `PolicyDoctor`.
///
/// # Panics
///
/// Does not panic; malformed payloads and store errors are converted to
/// protocol error envelopes.
pub async fn handle_policy_doctor(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let typed: PolicyDoctorRequest = match serde_json::from_value(request.payload.clone()) {
        Ok(value) => value,
        Err(_) => {
            return ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                "ProtocolError",
                "invalid PolicyDoctor payload",
                false,
            ));
        }
    };
    if typed.policy.project_id != typed.project_id {
        return protocol_error(request, "PolicyDoctor policy project_id mismatch");
    }

    let unlocked = {
        let cache = state.unlock_cache.lock().await;
        cache.lookup(&typed.project_id, now_unix_nanos).is_some()
    };
    if !unlocked {
        return typed_error(
            request,
            "UnlockRequired",
            "unlock required to validate command policy",
            LocketError::UnlockRequired,
        );
    }

    let store = match Store::open(&typed.store_path) {
        Ok(store) => store,
        Err(error) => {
            return typed_error(
                request,
                "CorruptDb",
                format!("failed to open store: {error}"),
                LocketError::CorruptDb,
            );
        }
    };

    let references = if typed.references.is_empty() {
        collect_lk_references(&typed.policy.command_preview)
    } else {
        typed.references.clone()
    };
    let allowed_env_names: BTreeSet<String> =
        typed.policy.allowed_secrets.iter().cloned().collect();
    let mut references_ok = 0_usize;
    let mut references_failed = Vec::new();
    let mut env_mode_resolve = BTreeSet::new();
    let mut env_mode_denied = BTreeSet::new();
    let mut referenced_keys = BTreeSet::new();

    for reference in &references {
        let Ok(parsed) = LkReferenceUri::parse(reference) else {
            references_failed.push(reference.clone());
            continue;
        };
        let key = parsed.key().as_str().to_owned();
        referenced_keys.insert(key.clone());
        if !allowed_env_names.contains(&key) {
            env_mode_denied.insert(key);
            references_failed.push(reference.clone());
            continue;
        }
        if reference_points_to_active_secret(&store, &typed, &parsed, now_unix_nanos) {
            references_ok = references_ok.saturating_add(1);
            env_mode_resolve.insert(key);
        } else {
            references_failed.push(reference.clone());
        }
    }

    let mut env_mode_passthrough = typed
        .policy
        .required_secrets
        .iter()
        .chain(typed.policy.optional_secrets.iter())
        .filter(|name| allowed_env_names.contains(*name) && !referenced_keys.contains(*name))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    env_mode_passthrough.sort();

    let response = PolicyDoctorResponse {
        status: if references_failed.is_empty() { "pass" } else { "fail" }.to_owned(),
        allowed_env_names: allowed_env_names.into_iter().collect(),
        ttl_seconds: u32::try_from(typed.policy.ttl_seconds).unwrap_or(u32::MAX),
        references_ok,
        references_failed,
        env_mode_passthrough,
        env_mode_resolve: env_mode_resolve.into_iter().collect(),
        env_mode_denied: env_mode_denied.into_iter().collect(),
    };
    serde_json::to_value(response).map_or_else(
        |_| protocol_error(request, "failed to serialize PolicyDoctor response"),
        |payload| ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), payload)),
    )
}

fn reference_points_to_active_secret(
    store: &Store,
    request: &PolicyDoctorRequest,
    parsed: &LkReferenceUri,
    now_unix_nanos: i128,
) -> bool {
    let Ok(Some(profile)) =
        store.get_profile_by_name(&request.project_id, parsed.profile().as_str())
    else {
        return false;
    };
    if profile.id != request.profile_id {
        return false;
    }
    let secret = if let Some(source) = parsed.source() {
        match store.get_active_secret(
            &request.project_id,
            &profile.id,
            parsed.key().as_str(),
            source.as_str(),
        ) {
            Ok(secret) => secret,
            Err(_) => return false,
        }
    } else {
        match store.list_secrets_by_name(&request.project_id, &profile.id, parsed.key().as_str()) {
            Ok(secrets) => preferred_active_secret(secrets),
            Err(_) => return false,
        }
    };
    let Some(secret) = secret else {
        return false;
    };
    let version = parsed.version().map_or(secret.current_version, locket_core::SecretVersion::get);
    matches!(
        store.get_secret_version(&secret.id, version),
        Ok(Some(record)) if version_is_resolvable(&record, parsed.version().is_some(), now_unix_nanos)
    )
}

fn collect_lk_references(text: &str) -> Vec<String> {
    let mut references = Vec::new();
    let mut rest = text;
    while let Some(index) = rest.find("lk://") {
        let after = &rest[index..];
        let end = after
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`')
            .unwrap_or(after.len());
        let candidate = after[..end].to_owned();
        if !candidate.is_empty() {
            references.push(candidate);
        }
        rest = &after[end..];
    }
    references
}

fn protocol_error(request: &RequestEnvelope, message: impl Into<String>) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), "ProtocolError", message, false))
}

fn typed_error(
    request: &RequestEnvelope,
    error: &'static str,
    message: impl Into<String>,
    _kind: LocketError,
) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), error, message, false))
}
