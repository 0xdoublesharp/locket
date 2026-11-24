//! Automation-client challenge-response authentication for agent requests.

use std::collections::BTreeMap;
use std::path::PathBuf;

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use locket_core::LocketError;
use locket_store::{
    AuditWrite, AutomationClientNonceRecord, AutomationClientRecord, Store, StoreError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::grant::GrantAction;
use crate::keys::{KeyError, cached_master_key, unwrap_audit_key_with_master};
use crate::method::AgentMethod;

const SIGNING_CONTEXT: &[u8] = b"locket-client-auth-v1";
const CHALLENGE_NONCE_LEN: usize = 24;
const CHALLENGE_ID_LEN: usize = 16;
const MAX_AUTOMATION_CHALLENGES: usize = 1024;
const SIGNATURE_LEN: usize = 64;
const REQUEST_FRESHNESS_NANOS: u128 = 5 * 60 * 1_000_000_000;
const NONCE_RETENTION_NANOS: i128 = 10 * 60 * 1_000_000_000;

/// `ClientHello` payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientHelloRequest {
    /// Automation-client id.
    pub client_id: String,
}

/// `ClientHello` response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientHelloResponse {
    /// Automation-client id echoed from the request.
    pub client_id: String,
    /// Random challenge id used to bind the signed request.
    pub challenge_id: String,
    /// Agent-issued challenge nonce encoded as unpadded base64url.
    pub nonce: String,
}

/// In-memory challenge issued by `ClientHello`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedChallenge {
    /// Digest of the automation-client id, keeping retained entries fixed-size.
    pub client_id_digest: [u8; 32],
    /// Raw challenge nonce.
    pub nonce: [u8; CHALLENGE_NONCE_LEN],
    /// Issue timestamp in nanoseconds.
    pub issued_at: i128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AuthFields {
    client_id: String,
    challenge_id: String,
    nonce: String,
    request_timestamp: i64,
    signature: String,
    #[serde(default)]
    public_key_hint: Option<String>,
}

#[derive(Clone, Debug)]
struct AuthContext {
    request_id: String,
    project_id: String,
    store_path: PathBuf,
    requested_action: String,
    requested_policy: String,
    auth: AuthFields,
}

/// Handles unauthenticated `ClientHello`.
pub async fn handle_client_hello(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
) -> ResponseEnvelope {
    let payload: ClientHelloRequest = match serde_json::from_value(request.payload.clone()) {
        Ok(payload) => payload,
        Err(_) => return error_response(request, "ProtocolError", "invalid ClientHello payload"),
    };
    let nonce: [u8; CHALLENGE_NONCE_LEN] = rand::random();
    let challenge_bytes: [u8; CHALLENGE_ID_LEN] = rand::random();
    let challenge_id = BASE64URL_NOPAD.encode(&challenge_bytes);
    let client_id_digest = Sha256::digest(payload.client_id.as_bytes()).into();
    let mut challenges = state.automation_challenges.lock().await;
    let now = crate::server::current_unix_nanos();
    challenges.retain(|_, challenge| !timestamp_is_stale(challenge.issued_at, now));
    if challenges.len() >= MAX_AUTOMATION_CHALLENGES {
        let error = AuthError::ChallengeCapacity;
        return error_response(request, error.error_name(), error.to_string());
    }
    let issued = IssuedChallenge { client_id_digest, nonce, issued_at: now };
    challenges.insert(challenge_id.clone(), issued);
    drop(challenges);
    success_response(
        request,
        ClientHelloResponse {
            client_id: payload.client_id,
            challenge_id,
            nonce: BASE64URL_NOPAD.encode(&nonce),
        },
    )
}

/// Authenticates a request when it carries `payload.auth`.
pub async fn authenticate_request_if_present(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> Option<ResponseEnvelope> {
    let context = match auth_context(request) {
        Ok(Some(context)) => context,
        Ok(None) => return None,
        Err(message) => return Some(error_response(request, "ProtocolError", message)),
    };
    match authenticate_request(request, state, now_unix_nanos, context).await {
        Ok(()) => None,
        Err(error) => Some(error_response(request, error.error_name(), error.to_string())),
    }
}

async fn authenticate_request(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
    context: AuthContext,
) -> Result<(), AuthError> {
    let now = i64::try_from(now_unix_nanos).unwrap_or(i64::MAX);
    let (mut store, _) = crate::keys::open_verified_store_for_state(
        state,
        &context.project_id,
        &context.store_path,
        now_unix_nanos,
    )
    .await
    .map_err(StoreError::from)?;
    let client = store
        .get_automation_client(&context.project_id, &context.auth.client_id)?
        .ok_or(AuthError::NotTrusted("client not registered"))?;
    if client.revoked_at.is_some() {
        write_denial_audit(&mut store, state, &context, &client, now, "revoked").await?;
        return Err(AuthError::NotTrusted("client revoked"));
    }
    if !client.allowed_actions.iter().any(|action| action == &context.requested_action) {
        write_denial_audit(&mut store, state, &context, &client, now, "policy_denied").await?;
        return Err(AuthError::NotTrusted("action not allowed"));
    }
    if !client.allowed_policies.iter().any(|allowed| allowed == &context.requested_policy) {
        write_denial_audit(&mut store, state, &context, &client, now, "policy_denied").await?;
        return Err(AuthError::NotTrusted("policy not allowed"));
    }
    if timestamp_is_stale(i128::from(context.auth.request_timestamp), now_unix_nanos) {
        write_denial_audit(&mut store, state, &context, &client, now, "expired").await?;
        return Err(AuthError::NotTrusted("request timestamp expired"));
    }
    let nonce = decode_nonce(&context.auth.nonce)?;
    let challenge = take_challenge(state, &context.auth.challenge_id).await?;
    let client_id_digest: [u8; 32] = Sha256::digest(context.auth.client_id.as_bytes()).into();
    if challenge.client_id_digest != client_id_digest || challenge.nonce != nonce {
        write_denial_audit(&mut store, state, &context, &client, now, "challenge_mismatch").await?;
        return Err(AuthError::NotTrusted("challenge mismatch"));
    }
    if timestamp_is_stale(challenge.issued_at, now_unix_nanos) {
        write_denial_audit(&mut store, state, &context, &client, now, "expired").await?;
        return Err(AuthError::NotTrusted("challenge expired"));
    }
    if let Err(error) = verify_signature(request, &context, &client.public_key, &nonce) {
        write_denial_audit(&mut store, state, &context, &client, now, "invalid_signature").await?;
        return Err(error);
    }

    let master_key = cached_master_key(state, &context.project_id, now_unix_nanos)
        .await?
        .ok_or(AuthError::UnlockRequired)?;
    let audit_key = unwrap_audit_key_with_master(&store, &context.project_id, &master_key)?;
    let nonce_record = AutomationClientNonceRecord {
        client_id: client.id.clone(),
        nonce,
        request_timestamp: context.auth.request_timestamp,
        seen_at: now,
        expires_at: i64::try_from(
            i128::from(context.auth.request_timestamp).saturating_add(NONCE_RETENTION_NANOS),
        )
        .unwrap_or(i64::MAX),
    };
    let metadata = client_auth_metadata(&context, &client, "SUCCESS", "verified", "fresh");
    let audit = AuditWrite {
        project_id: &context.project_id,
        profile_id: None,
        action: "CLIENT_AUTH",
        status: "SUCCESS",
        secret_name: None,
        command: Some("agent client-auth"),
        metadata_json: &metadata,
        timestamp: now,
    };
    store
        .record_automation_client_auth_with_audit(&nonce_record, now, audit_key.as_ref(), &audit)
        .map_err(classify_auth_write_error)?;
    Ok(())
}

fn auth_context(request: &RequestEnvelope) -> Result<Option<AuthContext>, &'static str> {
    let Value::Object(payload) = &request.payload else {
        return Ok(None);
    };
    let Some(auth_value) = payload.get("auth") else {
        return Ok(None);
    };
    let auth: AuthFields =
        serde_json::from_value(auth_value.clone()).map_err(|_| "invalid auth payload")?;
    let project_id = required_string(payload, "project_id")?.to_owned();
    let store_path = PathBuf::from(required_string(payload, "store_path")?);
    let requested_action = required_string(payload, "requested_action")?;
    if !permitted_automation_actions(request)?.contains(&requested_action) {
        return Err("requested_action does not authorize this operation");
    }
    // Every v1 automation permission is restricted to named command policies.
    // Missing, null or non-string policy values must not skip the allow-list.
    let requested_policy = required_string(payload, "policy_name")?;
    if requested_policy.trim().is_empty() {
        return Err("automation requests require policy_name");
    }
    Ok(Some(AuthContext {
        request_id: request.id.clone(),
        project_id,
        store_path,
        requested_action: requested_action.to_owned(),
        requested_policy: requested_policy.to_owned(),
        auth,
    }))
}

fn permitted_automation_actions(
    request: &RequestEnvelope,
) -> Result<&'static [&'static str], &'static str> {
    // Permissions belong to the operation the dispatcher will execute. The
    // caller's label can select a supported flow, but cannot relabel an RPC.
    // Preparing/executing a policy includes resolving its allowed references;
    // known-value redaction uses the same scan RPC as scanner integrations.
    match request.method().map_err(|_| "unsupported automation method")? {
        AgentMethod::PrepareExec => Ok(&["run-policy"]),
        AgentMethod::ResolveReference => Ok(&["resolve-reference", "run-policy"]),
        AgentMethod::ScanKnownValues => Ok(&["scan-known-values", "redact"]),
        AgentMethod::RequestGrant => {
            let action: GrantAction = serde_json::from_value(request.payload["action"].clone())
                .map_err(|_| "invalid automation grant action")?;
            match action {
                GrantAction::RunPolicy | GrantAction::PrepareExec => Ok(&["run-policy"]),
                GrantAction::ResolveReference => Ok(&["resolve-reference", "run-policy"]),
                GrantAction::ScanKnownValues => Ok(&["scan-known-values", "redact"]),
                GrantAction::Redact => Ok(&["redact"]),
                _ => Err("grant action is not available to automation clients"),
            }
        }
        _ => Err("method is not available to automation clients"),
    }
}

fn required_string<'a>(
    payload: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, &'static str> {
    payload.get(field).and_then(Value::as_str).ok_or("missing required auth context")
}

async fn take_challenge(
    state: &crate::server::AgentSocketState,
    challenge_id: &str,
) -> Result<IssuedChallenge, AuthError> {
    state
        .automation_challenges
        .lock()
        .await
        .remove(challenge_id)
        .ok_or(AuthError::NotTrusted("unknown challenge"))
}

fn decode_nonce(encoded: &str) -> Result<[u8; CHALLENGE_NONCE_LEN], AuthError> {
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| AuthError::NotTrusted("invalid nonce"))?;
    bytes.try_into().map_err(|_| AuthError::NotTrusted("invalid nonce length"))
}

fn decode_signature(encoded: &str) -> Result<Signature, AuthError> {
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| AuthError::NotTrusted("invalid signature"))?;
    if bytes.len() != SIGNATURE_LEN {
        return Err(AuthError::NotTrusted("invalid signature length"));
    }
    Signature::from_slice(&bytes).map_err(|_| AuthError::NotTrusted("invalid signature"))
}

fn verify_signature(
    request: &RequestEnvelope,
    context: &AuthContext,
    public_key: &[u8],
    nonce: &[u8; CHALLENGE_NONCE_LEN],
) -> Result<(), AuthError> {
    let public_key: [u8; 32] =
        public_key.try_into().map_err(|_| AuthError::NotTrusted("invalid public key"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| AuthError::NotTrusted("invalid public key"))?;
    let signature = decode_signature(&context.auth.signature)?;
    let canonical_hash = canonical_request_hash(request)?;
    let mut signed = Vec::new();
    signed.extend_from_slice(SIGNING_CONTEXT);
    signed.extend_from_slice(context.auth.client_id.as_bytes());
    signed.extend_from_slice(context.auth.challenge_id.as_bytes());
    signed.extend_from_slice(nonce);
    signed.extend_from_slice(context.auth.request_timestamp.to_string().as_bytes());
    signed.extend_from_slice(request.id.as_bytes());
    signed.extend_from_slice(&canonical_hash);
    verifying_key
        .verify(&signed, &signature)
        .map_err(|_| AuthError::NotTrusted("signature verification failed"))
}

fn canonical_request_hash(request: &RequestEnvelope) -> Result<[u8; 32], AuthError> {
    let mut value = serde_json::to_value(request).map_err(|_| AuthError::Protocol)?;
    if let Some(payload) = value.get_mut("payload").and_then(Value::as_object_mut) {
        payload.remove("auth");
    }
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes)?;
    Ok(Sha256::digest(&bytes).into())
}

fn write_canonical_json(value: &Value, out: &mut Vec<u8>) -> Result<(), AuthError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Value::String(text) => {
            let encoded = serde_json::to_string(text).map_err(|_| AuthError::Protocol)?;
            out.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let sorted: BTreeMap<_, _> = map.iter().collect();
            for (index, (key, item)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_json(&Value::String(key.clone()), out)?;
                out.push(b':');
                write_canonical_json(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

const fn timestamp_is_stale(timestamp: i128, now: i128) -> bool {
    now.abs_diff(timestamp) > REQUEST_FRESHNESS_NANOS
}

fn classify_auth_write_error(error: StoreError) -> AuthError {
    // This transaction also updates client usage and appends an audit row.
    // Only a duplicate of the nonce table's composite key proves replay.
    if matches!(
        &error,
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(failure, Some(message)))
            if matches!(
                failure.extended_code,
                rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY | rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
            ) && message == "UNIQUE constraint failed: automation_client_nonces.client_id, automation_client_nonces.nonce"
    ) {
        AuthError::Replay
    } else {
        AuthError::Store(error)
    }
}

async fn write_denial_audit(
    store: &mut Store,
    state: &crate::server::AgentSocketState,
    context: &AuthContext,
    client: &AutomationClientRecord,
    now: i64,
    result: &str,
) -> Result<(), AuthError> {
    let Some(master_key) = cached_master_key(state, &context.project_id, i128::from(now)).await?
    else {
        return Ok(());
    };
    let audit_key = unwrap_audit_key_with_master(store, &context.project_id, &master_key)?;
    let mut metadata = client_auth_metadata(context, client, "DENIED", result, result);
    metadata["failure_reason"] = json!(result);
    let audit = AuditWrite {
        project_id: &context.project_id,
        profile_id: None,
        action: "CLIENT_AUTH",
        status: "DENIED",
        secret_name: None,
        command: Some("agent client-auth"),
        metadata_json: &metadata,
        timestamp: now,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn client_auth_metadata(
    context: &AuthContext,
    client: &AutomationClientRecord,
    status: &str,
    auth_result: &str,
    nonce_freshness: &str,
) -> Value {
    json!({
        "schema_version": 1,
        "action": "CLIENT_AUTH",
        "status": status,
        "command": "agent client-auth",
        "client_id": client.id,
        "public_key_fingerprint": client.fingerprint,
        "request_id": context.request_id,
        "challenge_id": context.auth.challenge_id,
        "requested_action": context.requested_action,
        "requested_policy": context.requested_policy,
        "nonce_freshness": nonce_freshness,
        "auth_result": auth_result,
    })
}

fn success_response<T: Serialize>(request: &RequestEnvelope, payload: T) -> ResponseEnvelope {
    let payload = serde_json::to_value(payload).unwrap_or(Value::Null);
    ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), payload))
}

fn error_response(
    request: &RequestEnvelope,
    error: &str,
    message: impl Into<String>,
) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), error, message, false))
}

#[derive(Debug, thiserror::Error)]
enum AuthError {
    #[error("invalid automation auth payload")]
    Protocol,
    #[error("{0}")]
    NotTrusted(&'static str),
    #[error("automation client replay detected")]
    Replay,
    #[error("too many outstanding automation challenges")]
    ChallengeCapacity,
    #[error("{}", LocketError::UnlockRequired)]
    UnlockRequired,
    #[error("automation authentication storage failed")]
    Store(#[from] StoreError),
    #[error(transparent)]
    Key(#[from] KeyError),
}

impl AuthError {
    fn error_name(&self) -> &'static str {
        match self {
            Self::Protocol => "ProtocolError",
            Self::NotTrusted(_) => "AutomationClientNotTrusted",
            Self::Replay => "AutomationClientReplayDetected",
            Self::UnlockRequired => "UnlockRequired",
            Self::ChallengeCapacity => "AutomationChallengeCapacity",
            Self::Store(error) => match error.locket_error() {
                LocketError::StorageBusy => "StorageBusy",
                LocketError::AuditIntegrityFailed => "AuditIntegrityFailed",
                LocketError::MetadataInvalid => "MetadataInvalid",
                LocketError::SchemaNewerThanBinary => "SchemaNewerThanBinary",
                _ => "CorruptDb",
            },
            Self::Key(_) => "AuditIntegrityFailed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{AgentSocketState, current_unix_nanos};

    fn hello() -> RequestEnvelope {
        RequestEnvelope::new("hello", AgentMethod::ClientHello, json!({"client_id": "client"}))
    }

    fn challenge(issued_at: i128) -> IssuedChallenge {
        IssuedChallenge {
            client_id_digest: Sha256::digest(b"client").into(),
            nonce: [0; CHALLENGE_NONCE_LEN],
            issued_at,
        }
    }

    #[tokio::test]
    async fn client_hello_prunes_expired_challenges() {
        let state = AgentSocketState::locked("auth-test");
        {
            let now = current_unix_nanos();
            let mut challenges = state.automation_challenges.lock().await;
            challenges.insert("expired".to_owned(), challenge(0));
            challenges.insert("live".to_owned(), challenge(now));
        }
        assert!(matches!(
            handle_client_hello(&hello(), &state).await,
            ResponseEnvelope::Success(_)
        ));
        let challenges = state.automation_challenges.lock().await;
        assert_eq!(challenges.len(), 2);
        assert!(challenges.contains_key("live"));
        assert!(!challenges.contains_key("expired"));
        drop(challenges);
    }

    #[tokio::test]
    async fn client_hello_rejects_when_live_challenges_fill_capacity() -> Result<(), &'static str> {
        let state = AgentSocketState::locked("auth-test");
        let now = current_unix_nanos();
        {
            let mut challenges = state.automation_challenges.lock().await;
            for index in 0..MAX_AUTOMATION_CHALLENGES {
                let id = index.to_string();
                challenges.insert(id, challenge(now));
            }
        }
        let ResponseEnvelope::Error(error) = handle_client_hello(&hello(), &state).await else {
            return Err("ClientHello accepted a challenge over the cap");
        };
        assert_eq!(error.error, "AutomationChallengeCapacity");
        {
            let mut challenges = state.automation_challenges.lock().await;
            assert_eq!(challenges.len(), MAX_AUTOMATION_CHALLENGES);
            assert!(challenges.values().all(|row| row.issued_at == now));
            challenges.get_mut("0").ok_or("missing original challenge")?.issued_at = 0;
        }
        assert!(matches!(
            handle_client_hello(&hello(), &state).await,
            ResponseEnvelope::Success(_)
        ));
        assert_eq!(state.automation_challenges.lock().await.len(), MAX_AUTOMATION_CHALLENGES);
        Ok(())
    }
}
