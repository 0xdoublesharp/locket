//! Typed payloads for the `Reveal` and `Copy` agent RPCs.
//!
//! Both methods provide gated single-value access to a secret. They
//! share request and response shapes because the only operational
//! difference is the grant action and audit row written by the agent.
//!
//! See `docs/specs/agent.md` for the gated-value-access contract and
//! `docs/specs/errors.md` for the `UnlockRequired` error semantics.
//!
use std::path::PathBuf;

use locket_core::{LocketError, SecretName};
use locket_crypto::{
    EncryptedSecretValue, KeyPurpose, KeyWrapAad, KeyWrapPurpose, decrypt_secret_value_v1,
    key_wrap_aad_v1, secret_blob_aad_v1,
};
use locket_store::{AuditWrite, SecretRecord, SecretVersionRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::grant::{GrantAction, GrantBinding, GrantValidation};
use crate::keys::{master_key_array, unwrap_audit_key_with_master, unwrap_profile_key_with_master};

/// Wire `error` value used when the vault is locked.
const ERROR_UNLOCK_REQUIRED: &str = "UnlockRequired";
const ERROR_GRANT_REQUIRED: &str = "GrantRequired";
const ERROR_INVALID_SECRET_NAME: &str = "InvalidSecretName";
const ERROR_SECRET_NOT_FOUND: &str = "SecretNotFound";
const ERROR_SECRET_DELETED: &str = "SecretDeleted";
const ERROR_SECRET_VERSION_EXPIRED: &str = "SecretVersionExpired";
const ERROR_CORRUPT_DB: &str = "CorruptDb";

/// Redacted denial message returned to clients.
///
/// The string is intentionally generic. The desktop UI promotes the
/// typed `error` field rather than this human-readable text.
const UNLOCK_REQUIRED_MESSAGE: &str = "vault is locked; unlock required before revealing values";
const GRANT_REQUIRED_MESSAGE: &str =
    "live grant required before revealing or copying secret values";

/// Request payload for `Reveal`.
///
/// `secret_name` is the canonical key name within the active project,
/// not an `lk://` URI; references go through `ResolveReference`.
/// `profile_id` selects which profile's value to read so the agent can
/// audit the request against the correct profile scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevealRequest {
    /// Canonical secret name within the active project.
    pub secret_name: String,
    /// Profile id whose value should be read.
    pub profile_id: String,
    /// Project id whose unlock-cache entry and store rows are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Path to the user-scoped `store.db`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_path: Option<PathBuf>,
    /// Live grant id authorizing reveal access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// Current process binding for the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<GrantBinding>,
}

/// Response payload for an authorized `Reveal` with a live unlock and grant.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevealResponse {
    /// Plaintext secret value. Callers must limit its display lifetime.
    pub value: String,
    /// Time-to-live hint for any caller-side caching, in seconds.
    pub ttl_seconds: u32,
}

impl std::fmt::Debug for RevealResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RevealResponse")
            .field("value", &"[REDACTED]")
            .field("ttl_seconds", &self.ttl_seconds)
            .finish()
    }
}

/// Request payload for `Copy`.
///
/// Identical shape to [`RevealRequest`]; defined separately so the
/// methods retain distinct typed surfaces and so audit wiring can
/// distinguish them without sniffing the variant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CopyRequest {
    /// Canonical secret name within the active project.
    pub secret_name: String,
    /// Profile id whose value should be copied.
    pub profile_id: String,
    /// Project id whose unlock-cache entry and store rows are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Path to the user-scoped `store.db`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_path: Option<PathBuf>,
    /// Live grant id authorizing copy access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// Current process binding for the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<GrantBinding>,
}

/// Response payload for `Copy` once the unlock cache is wired.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct CopyResponse {
    /// Resolved secret value. Treated as a redacted token by the UI.
    pub value: String,
    /// Time-to-live hint for any caller-side caching, in seconds.
    pub ttl_seconds: u32,
}

impl std::fmt::Debug for CopyResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CopyResponse")
            .field("value", &"[REDACTED]")
            .field("ttl_seconds", &self.ttl_seconds)
            .finish()
    }
}

/// Handler for `Reveal`.
pub async fn handle_reveal(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<RevealRequest>(request.payload.clone()) else {
        return protocol_error(request, "invalid Reveal payload");
    };
    handle_value_access(
        request,
        AccessKind::Reveal,
        typed.secret_name,
        typed.project_id,
        typed.profile_id,
        typed.store_path,
        typed.grant_id,
        typed.binding,
        state,
        now_unix_nanos,
    )
    .await
}

/// Handler for `Copy`.
pub async fn handle_copy(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<CopyRequest>(request.payload.clone()) else {
        return protocol_error(request, "invalid Copy payload");
    };
    handle_value_access(
        request,
        AccessKind::Copy,
        typed.secret_name,
        typed.project_id,
        typed.profile_id,
        typed.store_path,
        typed.grant_id,
        typed.binding,
        state,
        now_unix_nanos,
    )
    .await
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_value_access(
    request: &RequestEnvelope,
    access: AccessKind,
    secret_name: String,
    project_id: Option<String>,
    profile_id: String,
    store_path: Option<PathBuf>,
    grant_id: Option<String>,
    binding: Option<GrantBinding>,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    if SecretName::new(secret_name.clone()).is_err() {
        return typed_error(
            request,
            ERROR_INVALID_SECRET_NAME,
            "invalid secret name",
            LocketError::InvalidSecretName,
        );
    }
    let Some(grant_id) = grant_id.as_deref() else {
        if let (Some(project_id), Some(store_path)) = (project_id.as_deref(), store_path.as_deref())
        {
            let key = {
                let cache = state.unlock_cache.lock().await;
                cache
                    .lookup(project_id, now_unix_nanos)
                    .map(|entry| Zeroizing::new(entry.key_bytes().to_vec()))
            };
            crate::audit_deny::try_append_grant_denial(
                state,
                project_id,
                &profile_id,
                Some(store_path),
                key.as_ref().map(|key| key.as_slice()),
                access.grant_action(),
                0,
                now_unix_nanos,
                "agent",
            )
            .await;
        }
        return grant_required(request);
    };
    let Some(project_id) = project_id.as_deref() else {
        return protocol_error(request, "value access requires project_id");
    };
    let Some(store_path) = store_path.as_deref() else {
        return protocol_error(request, "value access requires store_path");
    };

    let (grant_validation, ttl_seconds) = {
        let grants = state.grants.lock().await;
        let ttl_seconds = grants
            .get(grant_id)
            .and_then(|grant| u32::try_from(grant.ttl_seconds).ok())
            .unwrap_or(u32::MAX);
        (
            grants.validate(
                grant_id,
                project_id,
                &profile_id,
                access.grant_action(),
                now_unix_nanos,
                binding.as_ref(),
            ),
            ttl_seconds,
        )
    };
    if !matches!(grant_validation, GrantValidation::Valid) {
        let key = {
            let cache = state.unlock_cache.lock().await;
            cache
                .lookup(project_id, now_unix_nanos)
                .map(|entry| Zeroizing::new(entry.key_bytes().to_vec()))
        };
        crate::audit_deny::try_append_grant_denial(
            state,
            project_id,
            &profile_id,
            Some(store_path),
            key.as_ref().map(|key| key.as_slice()),
            access.grant_action(),
            ttl_seconds,
            now_unix_nanos,
            "agent",
        )
        .await;
        return grant_required(request);
    }

    let master_key = {
        let cache = state.unlock_cache.lock().await;
        cache
            .lookup(project_id, now_unix_nanos)
            .map(|entry| Zeroizing::new(entry.key_bytes().to_vec()))
    };
    let Some(master_key) = master_key else {
        crate::degraded_audit::record_locked_refusal(
            access.action(),
            Some(project_id),
            match access {
                AccessKind::Reveal => "agent.Reveal",
                AccessKind::Copy => "agent.Copy",
            },
            Some(store_path),
            now_unix_nanos,
        );
        return typed_error(
            request,
            ERROR_UNLOCK_REQUIRED,
            UNLOCK_REQUIRED_MESSAGE,
            LocketError::UnlockRequired,
        );
    };

    let (store, store_identity) = match crate::keys::open_verified_store_for_state(
        state,
        project_id,
        store_path,
        now_unix_nanos,
    )
    .await
    {
        Ok(opened) => opened,
        Err(error) => return crate::server::store_open_error(request, &error),
    };

    let shared_unlock = {
        let cache = state.unlock_cache.lock().await;
        store
            .resolve_active_secret_link(project_id, &profile_id, &secret_name)
            .ok()
            .flatten()
            .and_then(|resolved| {
                let entry = cache.lookup(&resolved.target_secret.project_id, now_unix_nanos)?;
                if entry.store_identity.as_ref().is_some_and(|pin| pin != &store_identity) {
                    return None;
                }
                Some((
                    resolved.target_secret.project_id,
                    Zeroizing::new(entry.key_bytes().to_vec()),
                ))
            })
    };

    match read_secret_value(
        project_id,
        &profile_id,
        &secret_name,
        access,
        store,
        &master_key,
        shared_unlock.as_ref().map(|(id, key)| (id.as_str(), key.as_slice())),
        ttl_seconds,
        now_unix_nanos,
    ) {
        Ok(value) => {
            let payload = match access {
                AccessKind::Reveal => {
                    serde_json::to_value(RevealResponse { value: value.value, ttl_seconds })
                }
                AccessKind::Copy => {
                    serde_json::to_value(CopyResponse { value: value.value, ttl_seconds })
                }
            }
            .unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), payload))
        }
        Err(error) => typed_error(request, error.error, error.message, error.kind),
    }
}

fn protocol_error(request: &RequestEnvelope, message: &str) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), "ProtocolError", message, false))
}

fn grant_required(request: &RequestEnvelope) -> ResponseEnvelope {
    typed_error(request, ERROR_GRANT_REQUIRED, GRANT_REQUIRED_MESSAGE, LocketError::GrantRequired)
}

fn typed_error(
    request: &RequestEnvelope,
    error: &'static str,
    message: impl Into<String>,
    _kind: LocketError,
) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), error, message, false))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccessKind {
    Reveal,
    Copy,
}

impl AccessKind {
    const fn action(self) -> &'static str {
        match self {
            Self::Reveal => "REVEAL",
            Self::Copy => "COPY",
        }
    }

    const fn access_mode(self) -> &'static str {
        match self {
            Self::Reveal => "reveal",
            Self::Copy => "clipboard",
        }
    }

    const fn grant_action(self) -> GrantAction {
        match self {
            Self::Reveal => GrantAction::Reveal,
            Self::Copy => GrantAction::Copy,
        }
    }
}

#[derive(Debug)]
struct ValueAccessFailure {
    error: &'static str,
    message: &'static str,
    kind: LocketError,
}

impl ValueAccessFailure {
    const fn new(error: &'static str, message: &'static str, kind: LocketError) -> Self {
        Self { error, message, kind }
    }
}

struct ResolvedValue {
    value: String,
}

#[allow(clippy::too_many_arguments)]
fn read_secret_value(
    project_id: &str,
    profile_id: &str,
    secret_name: &str,
    access: AccessKind,
    mut store: Store,
    master_key: &[u8],
    shared_unlock: Option<(&str, &[u8])>,
    ttl_seconds: u32,
    timestamp: i128,
) -> Result<ResolvedValue, ValueAccessFailure> {
    let master_key = master_key_array(master_key).map_err(|_| corrupt_db())?;
    match read_secret_value_inner(
        &store,
        project_id,
        profile_id,
        secret_name,
        &master_key,
        shared_unlock,
        timestamp,
    ) {
        Ok(details) => {
            append_value_access_audit(
                &mut store,
                project_id,
                profile_id,
                secret_name,
                access,
                &master_key,
                timestamp,
                ttl_seconds,
                ValueAccessAuditOutcome::Success(&details.audit),
            )?;
            Ok(ResolvedValue { value: details.value.to_string() })
        }
        Err(error) => {
            append_value_access_audit(
                &mut store,
                project_id,
                profile_id,
                secret_name,
                access,
                &master_key,
                timestamp,
                ttl_seconds,
                ValueAccessAuditOutcome::Failure(&error),
            )?;
            Err(error)
        }
    }
}

fn read_secret_value_inner(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    secret_name: &str,
    master_key: &locket_crypto::KeyBytes,
    shared_unlock: Option<(&str, &[u8])>,
    now: i128,
) -> Result<ResolvedValueDetails, ValueAccessFailure> {
    let (secret, linked_target) = select_secret(store, project_id, profile_id, secret_name)?;
    if super::secrets::secret_has_expired(store, &secret.id, now).map_err(|_| corrupt_db())? {
        return Err(ValueAccessFailure::new(
            "MetadataInvalid",
            super::secrets::SECRET_EXPIRED_MESSAGE,
            LocketError::MetadataInvalid,
        ));
    }
    let version = store
        .get_secret_version(&secret.id, secret.current_version)
        .map_err(|_| corrupt_db())?
        .ok_or_else(|| {
            ValueAccessFailure::new(
                ERROR_SECRET_NOT_FOUND,
                "secret version not found",
                LocketError::SecretNotFound,
            )
        })?;
    validate_version(&secret, &version)?;
    let (decrypt_project, decrypt_profile, decrypt_master, source_label) = if linked_target {
        let Some((shared_id, shared_key)) = shared_unlock else {
            return Err(ValueAccessFailure::new(
                ERROR_UNLOCK_REQUIRED,
                "unlock the Global Vault before reading a linked secret",
                LocketError::UnlockRequired,
            ));
        };
        if shared_id != secret.project_id {
            return Err(ValueAccessFailure::new(
                ERROR_UNLOCK_REQUIRED,
                "unlock the Global Vault before reading a linked secret",
                LocketError::UnlockRequired,
            ));
        }
        let target_master = master_key_array(shared_key).map_err(|_| corrupt_db())?;
        (
            secret.project_id.as_str(),
            secret.profile_id.as_str(),
            target_master,
            "shared-link".to_owned(),
        )
    } else {
        (project_id, profile_id, Zeroizing::new(*master_key), secret.source.clone())
    };
    let value = decrypt_secret(
        store,
        decrypt_project,
        decrypt_profile,
        &secret,
        version.version,
        &decrypt_master,
    )
    .map_err(|_| corrupt_db())?;
    let audit = ValueAccessAuditDetails {
        source: source_label,
        version: version.version,
        target_project_id: linked_target.then(|| secret.project_id.clone()),
        target_secret_id: linked_target.then(|| secret.id.clone()),
    };
    Ok(ResolvedValueDetails { value, audit })
}

struct ResolvedValueDetails {
    value: zeroize::Zeroizing<String>,
    audit: ValueAccessAuditDetails,
}

struct ValueAccessAuditDetails {
    source: String,
    version: u32,
    target_project_id: Option<String>,
    target_secret_id: Option<String>,
}

#[derive(Clone, Copy)]
enum ValueAccessAuditOutcome<'a> {
    Success(&'a ValueAccessAuditDetails),
    Failure(&'a ValueAccessFailure),
}

#[allow(clippy::too_many_arguments)]
fn append_value_access_audit(
    store: &mut Store,
    project_id: &str,
    profile_id: &str,
    secret_name: &str,
    access: AccessKind,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i128,
    ttl_seconds: u32,
    outcome: ValueAccessAuditOutcome<'_>,
) -> Result<(), ValueAccessFailure> {
    let audit_key =
        unwrap_audit_key_with_master(store, project_id, master_key).map_err(|_| corrupt_db())?;
    let timestamp = i64::try_from(timestamp).map_err(|_| corrupt_db())?;
    let mut metadata = Map::from_iter([
        ("schema_version".to_owned(), json!(1)),
        ("action".to_owned(), json!(access.action())),
        ("project_id".to_owned(), json!(project_id)),
        ("profile_id".to_owned(), json!(profile_id)),
        ("secret_name".to_owned(), json!(secret_name)),
        ("access_mode".to_owned(), json!(access.access_mode())),
    ]);
    if matches!(access, AccessKind::Copy) {
        metadata.insert("ttl_seconds".to_owned(), json!(ttl_seconds));
    }
    let status = match outcome {
        ValueAccessAuditOutcome::Success(details) => {
            metadata.insert("status".to_owned(), json!("SUCCESS"));
            metadata.insert("source".to_owned(), json!(details.source));
            metadata.insert("version".to_owned(), json!(details.version));
            if let Some(target_project_id) = &details.target_project_id {
                metadata.insert("target_project_id".to_owned(), json!(target_project_id));
            }
            if let Some(target_secret_id) = &details.target_secret_id {
                metadata.insert("target_secret_id".to_owned(), json!(target_secret_id));
            }
            "SUCCESS"
        }
        ValueAccessAuditOutcome::Failure(error) => {
            metadata.insert("status".to_owned(), json!("FAILURE"));
            metadata.insert("source".to_owned(), json!("unknown"));
            metadata.insert("failure_reason".to_owned(), json!(error.error));
            metadata.insert("exit_code".to_owned(), json!(error.kind.exit_code()));
            "FAILURE"
        }
    };
    let metadata = Value::Object(metadata);
    let audit = AuditWrite {
        project_id,
        profile_id: Some(profile_id),
        action: access.action(),
        status,
        secret_name: Some(secret_name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit).map_err(|_| corrupt_db())?;
    Ok(())
}

fn select_secret(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    secret_name: &str,
) -> Result<(SecretRecord, bool), ValueAccessFailure> {
    let secrets = store
        .list_secrets_by_name(project_id, profile_id, secret_name)
        .map_err(|_| corrupt_db())?;
    let active_local = secrets
        .iter()
        .filter(|secret| secret.state == "active")
        .max_by_key(|secret| source_precedence(&secret.source));
    let active_link = store
        .resolve_active_secret_link(project_id, profile_id, secret_name)
        .map_err(|_| corrupt_db())?;
    match (active_local, active_link) {
        (Some(local), Some(link)) => {
            if source_precedence("shared-link") > source_precedence(&local.source) {
                Ok((link.target_secret, true))
            } else {
                Ok((local.clone(), false))
            }
        }
        (Some(local), None) => Ok((local.clone(), false)),
        (None, Some(link)) => Ok((link.target_secret, true)),
        (None, None) => {
            if secrets.iter().any(|secret| secret.state == "deleted") {
                return Err(ValueAccessFailure::new(
                    ERROR_SECRET_DELETED,
                    "secret source is deleted",
                    LocketError::SecretDeleted,
                ));
            }
            Err(ValueAccessFailure::new(
                ERROR_SECRET_NOT_FOUND,
                "secret not found",
                LocketError::SecretNotFound,
            ))
        }
    }
}

fn validate_version(
    secret: &SecretRecord,
    version: &SecretVersionRecord,
) -> Result<(), ValueAccessFailure> {
    if secret.state == "deleted" {
        return Err(ValueAccessFailure::new(
            ERROR_SECRET_DELETED,
            "secret source is deleted",
            LocketError::SecretDeleted,
        ));
    }
    if version.state == "current" && version.version == secret.current_version {
        return Ok(());
    }
    Err(ValueAccessFailure::new(
        ERROR_SECRET_VERSION_EXPIRED,
        "secret version is expired",
        LocketError::SecretVersionExpired,
    ))
}

pub(super) fn decrypt_secret(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    secret: &SecretRecord,
    version: u32,
    master_key: &locket_crypto::KeyBytes,
) -> Result<zeroize::Zeroizing<String>, locket_crypto::CryptoError> {
    let profile_secret_key = unwrap_profile_key_with_master(
        store,
        project_id,
        profile_id,
        master_key,
        KeyPurpose::ProfileSecret,
    )
    .map_err(|_| locket_crypto::CryptoError::DecryptionFailed)?;
    let blob = store
        .get_blob(&secret.id, version)
        .map_err(|_| locket_crypto::CryptoError::DecryptionFailed)?
        .ok_or(locket_crypto::CryptoError::DecryptionFailed)?;
    let value_aad = secret_blob_aad_v1(&locket_crypto::SecretBlobAad::new(
        project_id,
        profile_id,
        &secret.id,
        &secret.name,
        version,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &secret.id,
        Some(profile_id),
        version,
        KeyWrapPurpose::SecretDek,
    ))?;
    let encrypted = EncryptedSecretValue {
        encrypted_dek: blob.encrypted_dek,
        ciphertext: blob.ciphertext,
        value_nonce: blob.value_nonce,
        aad_schema_version: blob.aad_schema_version,
    };
    decrypt_secret_value_v1(&profile_secret_key, &encrypted, &value_aad, &wrap_aad)
}

const fn source_precedence(source: &str) -> u8 {
    locket_core::source_precedence(source)
}

const fn corrupt_db() -> ValueAccessFailure {
    ValueAccessFailure::new(ERROR_CORRUPT_DB, "value access failed", LocketError::CorruptDb)
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::{CopyRequest, CopyResponse, ERROR_GRANT_REQUIRED, RevealRequest, RevealResponse};
    use crate::PROTOCOL_VERSION;
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::grant::{GrantAction, GrantBinding, GrantRecord, GrantRecordFields};
    use crate::method::AgentMethod;
    use crate::server::AgentSocketState;
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};
    use locket_crypto::{
        HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, SecretBlobAad,
        derive_wrapping_key_v1, encrypt_secret_value_v1, key_wrap_aad_v1, secret_blob_aad_v1,
        secret_fingerprint_v1, wrap_key_material_v1,
    };
    use locket_store::{
        KeyRecord, SecretBlobRecord, SecretFingerprintRecord, SecretRecord, SecretVersionRecord,
        Store,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::{TempDir, tempdir};

    const PROJECT_ID: &str = "lk_proj_reveal";
    const PROFILE_ID: &str = "lk_prof_dev";
    const SECRET_ID: &str = "lk_sec_reveal";
    const SECRET_NAME: &str = "DATABASE_URL";
    const GRANT_ID: &str = "lk_grant_reveal";

    struct RevealFixture {
        _directory: TempDir,
        store_path: PathBuf,
        master_key: locket_crypto::KeyBytes,
        expected_value: String,
    }

    fn reveal_request(fixture: &RevealFixture, action: GrantAction) -> RevealRequest {
        RevealRequest {
            secret_name: SECRET_NAME.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
            project_id: Some(PROJECT_ID.to_owned()),
            store_path: Some(fixture.store_path.clone()),
            grant_id: Some(GRANT_ID.to_owned()),
            binding: Some(test_binding(action)),
        }
    }

    fn copy_request(fixture: &RevealFixture) -> CopyRequest {
        CopyRequest {
            secret_name: SECRET_NAME.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
            project_id: Some(PROJECT_ID.to_owned()),
            store_path: Some(fixture.store_path.clone()),
            grant_id: Some(GRANT_ID.to_owned()),
            binding: Some(test_binding(GrantAction::Copy)),
        }
    }

    fn test_binding(_action: GrantAction) -> GrantBinding {
        GrantBinding::new(std::process::id(), "0")
    }

    fn test_grant_record(action: GrantAction, expires_at_unix_nanos: i128) -> GrantRecord {
        GrantRecord::new(GrantRecordFields {
            grant_id: GRANT_ID.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
            action,
            binding: test_binding(action),
            issued_at_unix_nanos: 0,
            ttl_seconds: 45,
            expires_at_unix_nanos,
        })
    }

    fn build_fixture() -> Result<RevealFixture, Box<dyn std::error::Error>> {
        build_fixture_with_value("resolved test value")
    }

    fn build_fixture_with_value(value: &str) -> Result<RevealFixture, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let store_path = directory.path().join("store.db");
        let mut store = Store::open(&store_path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT_ID, "reveal-test", 1)?;
        store.insert_profile_if_absent(PROFILE_ID, PROJECT_ID, "dev", false, 1)?;

        let master_key = [7_u8; 32];
        let audit_key = [10_u8; 32];
        let profile_secret_key = [8_u8; 32];
        let profile_fingerprint_key = [9_u8; 32];
        insert_wrapped_project_key(
            &store,
            "lk_key_project_audit",
            KeyPurpose::Audit,
            &master_key,
            &audit_key,
        )?;
        insert_wrapped_profile_key(
            &store,
            "lk_key_profile_secret",
            KeyPurpose::ProfileSecret,
            &master_key,
            &profile_secret_key,
        )?;
        insert_wrapped_profile_key(
            &store,
            "lk_key_profile_fingerprint",
            KeyPurpose::ProfileFingerprint,
            &master_key,
            &profile_fingerprint_key,
        )?;

        insert_encrypted_secret(
            &mut store,
            SECRET_ID,
            "user-local",
            &profile_secret_key,
            &profile_fingerprint_key,
            value,
        )?;
        let expected_value = value.to_owned();
        Ok(RevealFixture { _directory: directory, store_path, master_key, expected_value })
    }

    fn insert_wrapped_project_key(
        store: &Store,
        key_id: &str,
        purpose: KeyPurpose,
        master_key: &locket_crypto::KeyBytes,
        key_material: &locket_crypto::KeyBytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wrapping_key =
            derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(PROJECT_ID, None, purpose))?;
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            key_id,
            None,
            0,
            KeyWrapPurpose::from(purpose),
        ))?;
        let wrapped = wrap_key_material_v1(&wrapping_key, key_material, &aad)?;
        store.insert_key(&KeyRecord {
            id: key_id.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: None,
            purpose: purpose.as_str().to_owned(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: 1,
        })?;
        Ok(())
    }

    fn insert_wrapped_profile_key(
        store: &Store,
        key_id: &str,
        purpose: KeyPurpose,
        master_key: &locket_crypto::KeyBytes,
        key_material: &locket_crypto::KeyBytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wrapping_key = derive_wrapping_key_v1(
            master_key,
            &HkdfWrapInfo::new(PROJECT_ID, Some(PROFILE_ID), purpose),
        )?;
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            key_id,
            Some(PROFILE_ID),
            0,
            KeyWrapPurpose::from(purpose),
        ))?;
        let wrapped = wrap_key_material_v1(&wrapping_key, key_material, &aad)?;
        store.insert_key(&KeyRecord {
            id: key_id.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: Some(PROFILE_ID.to_owned()),
            purpose: purpose.as_str().to_owned(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: 1,
        })?;
        Ok(())
    }

    fn insert_encrypted_secret(
        store: &mut Store,
        secret_id: &str,
        source: &str,
        profile_secret_key: &locket_crypto::KeyBytes,
        profile_fingerprint_key: &locket_crypto::KeyBytes,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
            PROJECT_ID,
            PROFILE_ID,
            secret_id,
            SECRET_NAME,
            1,
        ))?;
        let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            secret_id,
            Some(PROFILE_ID),
            1,
            KeyWrapPurpose::SecretDek,
        ))?;
        let encrypted = encrypt_secret_value_v1(profile_secret_key, value, &value_aad, &wrap_aad)?;
        let fingerprint = secret_fingerprint_v1(profile_fingerprint_key, value)?;
        let secret = SecretRecord {
            id: secret_id.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
            name: SECRET_NAME.to_owned(),
            source: source.to_owned(),
            origin: "manual".to_owned(),
            current_version: 1,
            state: "active".to_owned(),
            created_at: 1,
            updated_at: 1,
            last_rotated_at: None,
            deleted_at: None,
        };
        let version = SecretVersionRecord {
            secret_id: secret_id.to_owned(),
            version: 1,
            source: source.to_owned(),
            origin: "manual".to_owned(),
            state: "current".to_owned(),
            created_at: 1,
            deprecated_at: None,
            grace_until: None,
            purged_at: None,
        };
        let blob = SecretBlobRecord {
            secret_id: secret_id.to_owned(),
            version: 1,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: 1,
            created_at: 1,
        };
        let fingerprint = SecretFingerprintRecord {
            secret_id: secret_id.to_owned(),
            version: 1,
            fingerprint: fingerprint.to_vec(),
            created_at: 1,
        };
        store.create_active_secret(&secret, &version, &blob, &fingerprint)?;
        Ok(())
    }

    async fn state_with_grant(fixture: &RevealFixture, action: GrantAction) -> AgentSocketState {
        let state = AgentSocketState::locked("test-version");
        state.grants.lock().await.insert(test_grant_record(action, i128::MAX));
        state.unlock_cache.lock().await.insert(
            PROJECT_ID.to_owned(),
            UnlockEntry::new(
                fixture.master_key.to_vec(),
                0,
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        state
    }

    fn audit_metadata(
        fixture: &RevealFixture,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let store = Store::open(&fixture.store_path)?;
        let mut statement = store.connection().prepare(
            "SELECT action, status, secret_name, command, metadata_json
             FROM audit_log
             WHERE project_id = ?1
             ORDER BY sequence",
        )?;
        let rows = statement
            .query_map([PROJECT_ID], |row| {
                let action: String = row.get(0)?;
                let status: String = row.get(1)?;
                let secret_name: Option<String> = row.get(2)?;
                let command: Option<String> = row.get(3)?;
                let metadata: String = row.get(4)?;
                Ok((action, status, secret_name, command, metadata))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(action, status, secret_name, command, metadata)| {
                let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
                assert_eq!(metadata["action"], action);
                assert_eq!(metadata["status"], status);
                assert!(secret_name.is_some());
                assert!(command.is_none());
                Ok(metadata)
            })
            .collect()
    }

    fn error_code(response: ResponseEnvelope) -> Result<String, Box<dyn std::error::Error>> {
        let ResponseEnvelope::Error(error) = response else {
            return Err("expected error envelope".into());
        };
        Ok(error.error)
    }

    #[test]
    fn plaintext_responses_redact_debug() {
        let secret = "fixture-plaintext-never-in-debug";
        let reveal = RevealResponse { value: secret.to_owned(), ttl_seconds: 30 };
        let copy = CopyResponse { value: secret.to_owned(), ttl_seconds: 30 };
        for formatted in [format!("{reveal:?}"), format!("{copy:?}")] {
            assert!(!formatted.contains(secret));
            assert!(formatted.contains("[REDACTED]"));
        }
    }

    #[test]
    fn reveal_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request = RevealRequest {
            secret_name: "DATABASE_URL".to_owned(),
            profile_id: "profile-dev".to_owned(),
            project_id: Some("project-dev".to_owned()),
            store_path: Some(PathBuf::from("/tmp/store.db")),
            grant_id: Some("grant-dev".to_owned()),
            binding: Some(GrantBinding::new(123, "start")),
        };

        let value = serde_json::to_value(&request)?;
        let decoded: RevealRequest = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, request);
        assert_eq!(value["secret_name"], "DATABASE_URL");
        assert_eq!(value["profile_id"], "profile-dev");
        Ok(())
    }

    #[test]
    fn reveal_response_round_trips_through_json() -> Result<(), serde_json::Error> {
        let response = RevealResponse { value: "hunter2".to_owned(), ttl_seconds: 30 };

        let value = serde_json::to_value(&response)?;
        let decoded: RevealResponse = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, response);
        assert_eq!(value["value"], "hunter2");
        assert_eq!(value["ttl_seconds"], 30);
        Ok(())
    }

    #[test]
    fn copy_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request = CopyRequest {
            secret_name: "API_TOKEN".to_owned(),
            profile_id: "profile-prod".to_owned(),
            project_id: Some("project-prod".to_owned()),
            store_path: Some(PathBuf::from("/tmp/store.db")),
            grant_id: Some("grant-prod".to_owned()),
            binding: Some(GrantBinding::new(123, "start")),
        };

        let value = serde_json::to_value(&request)?;
        let decoded: CopyRequest = serde_json::from_value(value)?;

        assert_eq!(decoded, request);
        Ok(())
    }

    #[test]
    fn copy_response_round_trips_through_json() -> Result<(), serde_json::Error> {
        let response = CopyResponse { value: "k".to_owned(), ttl_seconds: 0 };

        let decoded: CopyResponse = serde_json::from_value(serde_json::to_value(&response)?)?;
        assert_eq!(decoded, response);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_reveal_returns_grant_required_error() {
        let envelope = RequestEnvelope::new(
            "req-reveal",
            AgentMethod::Reveal,
            json!({ "secret_name": "DATABASE_URL", "profile_id": "profile-dev" }),
        );

        let state = AgentSocketState::locked("test-version");
        let response = super::handle_reveal(&envelope, &state, 1).await;

        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope, got success");
        };
        assert_eq!(error.v, PROTOCOL_VERSION);
        assert_eq!(error.id, "req-reveal");
        assert!(!error.ok);
        assert_eq!(error.error, ERROR_GRANT_REQUIRED);
        assert!(!error.retryable);
        assert_ne!(error.message, "");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_copy_returns_grant_required_error() {
        let envelope = RequestEnvelope::new(
            "req-copy",
            AgentMethod::Copy,
            json!({ "secret_name": "API_TOKEN", "profile_id": "profile-prod" }),
        );

        let state = AgentSocketState::locked("test-version");
        let response = super::handle_copy(&envelope, &state, 1).await;

        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope, got success");
        };
        assert_eq!(error.id, "req-copy");
        assert_eq!(error.error, ERROR_GRANT_REQUIRED);
        assert!(!error.retryable);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_reveal_rejects_malformed_payload_with_protocol_error() {
        let envelope = RequestEnvelope::new("req-bad", AgentMethod::Reveal, json!({"oops": 1}));

        let state = AgentSocketState::locked("test-version");
        let response = super::handle_reveal(&envelope, &state, 1).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope, got success");
        };
        assert_eq!(error.error, "ProtocolError");
    }

    #[tokio::test]
    async fn denied_value_access_leaves_only_authenticated_denial_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = state_with_grant(&fixture, GrantAction::Reveal).await;
        let valid = serde_json::to_value(reveal_request(&fixture, GrantAction::Reveal))?;
        for (field, replacement, code) in [
            ("grant_id", serde_json::Value::Null, "GrantRequired"),
            ("project_id", serde_json::Value::Null, "ProtocolError"),
            ("store_path", serde_json::Value::Null, "ProtocolError"),
            (
                "binding",
                json!(GrantBinding::new(std::process::id(), "reused-pid")),
                "GrantRequired",
            ),
            ("secret_name", json!("invalid name"), "InvalidSecretName"),
        ] {
            let mut payload = valid.clone();
            payload[field] = replacement;
            let request = RequestEnvelope::new("denied", AgentMethod::Reveal, payload);
            let response = super::handle_reveal(&request, &state, 1).await;
            assert!(!serde_json::to_string(&response)?.contains(&fixture.expected_value));
            assert_eq!(error_code(response)?, code);
        }
        let request = RequestEnvelope::new("wrong-action", AgentMethod::Copy, valid);
        let response = super::handle_copy(&request, &state, 1).await;
        assert_eq!(error_code(response)?, "GrantRequired");
        let malformed = RequestEnvelope::new("bad-copy", AgentMethod::Copy, json!({}));
        assert_eq!(error_code(super::handle_copy(&malformed, &state, 1).await)?, "ProtocolError");

        let store = Store::open(&fixture.store_path)?;
        for row in store.list_audit_rows_since(PROJECT_ID, PROFILE_ID, 0)? {
            assert_eq!(row.action, "AGENT_REVOKE");
            assert_eq!(row.status, "DENIED");
            assert!(row.secret_name.is_none());
        }
        assert_eq!(store.list_audit_rows_since(PROJECT_ID, PROFILE_ID, 0)?.len(), 3);
        assert!(store.connection().query_row(
            "SELECT NOT EXISTS (SELECT 1 FROM audit_log WHERE instr(metadata_json, ?1) > 0)",
            [&fixture.expected_value],
            |row| row.get::<_, bool>(0),
        )?);
        assert!(store.verify_audit_chain_read_only(PROJECT_ID, &[10; 32])?.hmac_ok);
        Ok(())
    }

    #[tokio::test]
    async fn reveal_denies_corrupt_blob_and_withholds_valid_values_when_audit_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = state_with_grant(&fixture, GrantAction::Reveal).await;
        let store = Store::open(&fixture.store_path)?;
        let request = RequestEnvelope::new(
            "read",
            AgentMethod::Reveal,
            serde_json::to_value(reveal_request(&fixture, GrantAction::Reveal))?,
        );
        store.connection().execute_batch(
            "CREATE TRIGGER refuse_value_audit BEFORE INSERT ON audit_log
             WHEN NEW.action = 'REVEAL' BEGIN SELECT RAISE(ABORT, 'fixture denied'); END",
        )?;
        let response = super::handle_reveal(&request, &state, 1).await;
        assert!(!serde_json::to_string(&response)?.contains(&fixture.expected_value));
        assert_eq!(error_code(response)?, "CorruptDb");
        assert_eq!(audit_metadata(&fixture)?, Vec::<serde_json::Value>::new());

        store.connection().execute_batch("DROP TRIGGER refuse_value_audit")?;
        store
            .connection()
            .execute("UPDATE blobs SET ciphertext = zeroblob(length(ciphertext))", [])?;
        let response = super::handle_reveal(&request, &state, 1).await;
        assert!(!serde_json::to_string(&response)?.contains(&fixture.expected_value));
        assert_eq!(error_code(response)?, "CorruptDb");
        let audit = audit_metadata(&fixture)?;
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0]["status"], "FAILURE");
        assert_eq!(audit[0]["failure_reason"], "CorruptDb");
        assert!(store.verify_audit_chain_read_only(PROJECT_ID, &[10; 32])?.hmac_ok);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_reveal_returns_value_with_live_grant_and_unlock()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = state_with_grant(&fixture, GrantAction::Reveal).await;
        let envelope = RequestEnvelope::new(
            "req-ok",
            AgentMethod::Reveal,
            serde_json::to_value(reveal_request(&fixture, GrantAction::Reveal))?,
        );

        let response = super::handle_reveal(&envelope, &state, 1).await;
        let ResponseEnvelope::Success(success) = response else {
            return Err("expected success envelope".into());
        };
        let payload: RevealResponse = serde_json::from_value(success.payload)?;
        assert_eq!(payload.value, fixture.expected_value);
        assert_eq!(payload.ttl_seconds, 45);
        let audits = audit_metadata(&fixture)?;
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0]["action"], "REVEAL");
        assert_eq!(audits[0]["status"], "SUCCESS");
        assert_eq!(audits[0]["profile_id"], PROFILE_ID);
        assert_eq!(audits[0]["secret_name"], SECRET_NAME);
        assert_eq!(audits[0]["source"], "user-local");
        assert_eq!(audits[0]["version"], 1);
        assert!(audits[0].get("value").is_none());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_copy_returns_value_and_ttl_audit() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = state_with_grant(&fixture, GrantAction::Copy).await;
        let envelope = RequestEnvelope::new(
            "req-copy-ok",
            AgentMethod::Copy,
            serde_json::to_value(copy_request(&fixture))?,
        );

        let response = super::handle_copy(&envelope, &state, 1).await;
        let ResponseEnvelope::Success(success) = response else {
            return Err("expected success envelope".into());
        };
        let payload: CopyResponse = serde_json::from_value(success.payload)?;
        assert_eq!(payload.value, fixture.expected_value);
        assert_eq!(payload.ttl_seconds, 45);
        let audits = audit_metadata(&fixture)?;
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0]["action"], "COPY");
        assert_eq!(audits[0]["access_mode"], "clipboard");
        assert_eq!(audits[0]["ttl_seconds"], 45);
        assert!(audits[0].get("value").is_none());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn agent_reveal_copy_canary_values_stay_out_of_audit_surfaces()
    -> Result<(), Box<dyn std::error::Error>> {
        let canary = "lk-canary-agent-reveal-copy-1234567890abcdef";

        let reveal_fixture = build_fixture_with_value(canary)?;
        let reveal_state = state_with_grant(&reveal_fixture, GrantAction::Reveal).await;
        let reveal_envelope = RequestEnvelope::new(
            "req-canary-reveal",
            AgentMethod::Reveal,
            serde_json::to_value(reveal_request(&reveal_fixture, GrantAction::Reveal))?,
        );
        let ResponseEnvelope::Success(reveal_success) =
            super::handle_reveal(&reveal_envelope, &reveal_state, 1).await
        else {
            return Err("expected reveal success envelope".into());
        };
        let reveal_payload: RevealResponse = serde_json::from_value(reveal_success.payload)?;
        assert_eq!(reveal_payload.value, canary);
        let reveal_audits = serde_json::to_string(&audit_metadata(&reveal_fixture)?)?;
        assert!(!reveal_audits.contains(canary));

        let copy_fixture = build_fixture_with_value(canary)?;
        let copy_state = state_with_grant(&copy_fixture, GrantAction::Copy).await;
        let copy_envelope = RequestEnvelope::new(
            "req-canary-copy",
            AgentMethod::Copy,
            serde_json::to_value(copy_request(&copy_fixture))?,
        );
        let ResponseEnvelope::Success(copy_success) =
            super::handle_copy(&copy_envelope, &copy_state, 1).await
        else {
            return Err("expected copy success envelope".into());
        };
        let copy_payload: CopyResponse = serde_json::from_value(copy_success.payload)?;
        assert_eq!(copy_payload.value, canary);
        let copy_audits = serde_json::to_string(&audit_metadata(&copy_fixture)?)?;
        assert!(!copy_audits.contains(canary));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_reveal_requires_unlock_after_grant() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = AgentSocketState::locked("test-version");
        state.grants.lock().await.insert(test_grant_record(GrantAction::Reveal, i128::MAX));
        let envelope = RequestEnvelope::new(
            "req-locked",
            AgentMethod::Reveal,
            serde_json::to_value(reveal_request(&fixture, GrantAction::Reveal))?,
        );

        let response = super::handle_reveal(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "UnlockRequired");

        // The agent must mirror the locked-vault refusal into the
        // degraded-audit log under the store-path's parent directory.
        let degraded_log = fixture
            .store_path
            .parent()
            .ok_or("store path should have parent")?
            .join(locket_platform::DEGRADED_AUDIT_LOG_FILENAME);
        let body = std::fs::read_to_string(&degraded_log)?;
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one degraded-audit row expected");
        let row: serde_json::Value = serde_json::from_str(lines[0])?;
        assert_eq!(row["action"], "REVEAL");
        assert_eq!(row["status"], "DENIED_LOCKED");
        assert_eq!(row["failure_reason"], "vault_locked");
        assert_eq!(row["command"], "agent.Reveal");
        assert_eq!(row["project_id"], PROJECT_ID);
        assert!(row.get("secret_name").is_none(), "must never include secret_name");
        Ok(())
    }

    #[tokio::test]
    async fn reveal_and_copy_refuse_expired_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let store = Store::open(&fixture.store_path)?;
        store.set_secret_expiry_policy(
            SECRET_ID,
            locket_store::SecretExpiryPolicy { expires_at: Some(5), rotate_after_days: None },
            2,
        )?;
        let reveal_state = state_with_grant(&fixture, GrantAction::Reveal).await;
        let reveal = RequestEnvelope::new(
            "expired-reveal",
            AgentMethod::Reveal,
            serde_json::to_value(reveal_request(&fixture, GrantAction::Reveal))?,
        );
        let copy_state = state_with_grant(&fixture, GrantAction::Copy).await;
        let copy = RequestEnvelope::new(
            "expired-copy",
            AgentMethod::Copy,
            serde_json::to_value(copy_request(&fixture))?,
        );
        for response in [
            super::handle_reveal(&reveal, &reveal_state, 5).await,
            super::handle_copy(&copy, &copy_state, 5).await,
        ] {
            assert!(matches!(response, ResponseEnvelope::Error(error)
                if error.error == "MetadataInvalid" && error.message.contains("secret has expired")));
        }
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_reveal_returns_typed_secret_not_found() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = build_fixture()?;
        let state = state_with_grant(&fixture, GrantAction::Reveal).await;
        let mut request = reveal_request(&fixture, GrantAction::Reveal);
        request.secret_name = "MISSING_KEY".to_owned();
        let envelope = RequestEnvelope::new(
            "req-missing",
            AgentMethod::Reveal,
            serde_json::to_value(request)?,
        );

        let response = super::handle_reveal(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "SecretNotFound");
        let audits = audit_metadata(&fixture)?;
        assert_eq!(audits[0]["status"], "FAILURE");
        assert_eq!(audits[0]["failure_reason"], "SecretNotFound");
        assert!(audits[0].get("value").is_none());
        Ok(())
    }
}
