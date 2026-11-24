//! Typed payloads and handler for the `SetSecret` agent RPC.
//!
//! The handler accepts plaintext only in the request payload, validates a
//! live grant and unlock-cache entry first, then encrypts the value and
//! stores only encrypted rows plus metadata-only audit rows.

use std::path::Path;
use std::str::FromStr;

use locket_core::{LocketError, SecretId, SecretName, SecretSource};
use locket_crypto::{
    EncryptedSecretValue, KeyPurpose, KeyWrapAad, KeyWrapPurpose, SecretBlobAad,
    encrypt_secret_value_v1, key_wrap_aad_v1, secret_blob_aad_v1, secret_fingerprint_v1,
};
use locket_store::{
    AuditContext, AuditWrite, SecretBlobRecord, SecretFingerprintRecord, SecretRecord,
    SecretVersionRecord, Store, VersionDeprecation,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::grant::{GrantAction, GrantBinding, GrantValidation};
use crate::keys::{master_key_array, unwrap_audit_key_with_master, unwrap_profile_key_with_master};

const DEFAULT_SOURCE: &str = "user-local";
const ORIGIN: &str = "manual";
const ERROR_GRANT_REQUIRED: &str = "GrantRequired";
const ERROR_UNLOCK_REQUIRED: &str = "UnlockRequired";
const ERROR_INVALID_REFERENCE: &str = "InvalidReference";
const ERROR_INVALID_SECRET_NAME: &str = "InvalidSecretName";
const ERROR_METADATA_INVALID: &str = "MetadataInvalid";
const ERROR_SECRET_ALREADY_EXISTS: &str = "SecretAlreadyExists";
const ERROR_SECRET_DELETED: &str = "SecretDeleted";
const ERROR_SECRET_NOT_FOUND: &str = "SecretNotFound";
const ERROR_PROFILE_NOT_FOUND: &str = "ProfileNotFound";
const ERROR_SECRET_VERSION_OVERFLOW: &str = "SecretVersionOverflow";
const ERROR_CORRUPT_DB: &str = "CorruptDb";

const GRANT_REQUIRED_MESSAGE: &str =
    "live grant required to set secrets; request a grant before retrying";
const UNLOCK_REQUIRED_MESSAGE: &str =
    "unlock required to set secrets; unlock the project before retrying";

/// Request payload for `SetSecret`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SetSecretRequest {
    /// Path to the user-scoped `store.db`.
    pub store_path: String,
    /// Project id whose unlock-cache entry and store rows are used.
    pub project_id: String,
    /// Profile id authorized by the live grant.
    pub profile_id: String,
    /// Secret name to create or rotate.
    pub secret_name: String,
    /// Optional target source. Missing matches CLI behavior and defaults to `user-local`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Plaintext value from a secure input. The handler never returns or audits this value.
    pub value: String,
    /// `true` rotates an active secret; `false` creates a new secret.
    #[serde(default)]
    pub rotate: bool,
    /// Optional grace-window expiration for the deprecated version during rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_until: Option<i64>,
    /// Live grant id authorizing the mutation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// Current process binding for the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<GrantBinding>,
}

/// Response payload for `SetSecret`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SetSecretResponse {
    /// Lifecycle action applied by the handler.
    pub action: String,
    /// Secret id created or rotated.
    pub secret_id: String,
    /// Current version after the mutation.
    pub version: u32,
    /// Persisted source string.
    pub source: String,
}

/// Handler for `SetSecret`.
pub async fn handle_set_secret(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let Ok(mut typed) = serde_json::from_value::<SetSecretRequest>(request.payload.clone()) else {
        return protocol_error(request, "invalid SetSecret payload");
    };
    let value = Zeroizing::new(std::mem::take(&mut typed.value));
    let Ok(name) = SecretName::new(typed.secret_name.clone()) else {
        return typed_error(
            request,
            ERROR_INVALID_SECRET_NAME,
            "invalid secret name",
            LocketError::InvalidSecretName,
        );
    };
    let source_was_omitted = typed.source.is_none();
    let source = typed.source.as_deref().unwrap_or(DEFAULT_SOURCE);
    if SecretSource::from_str(source).is_err() {
        return typed_error(
            request,
            ERROR_METADATA_INVALID,
            "invalid secret source",
            LocketError::MetadataInvalid,
        );
    }
    if let Err(error) = validate_secret_value(&value) {
        return typed_error(request, error.error, error.message, error.kind);
    }

    let grant_validation = {
        let Some(grant_id) = typed.grant_id.as_deref() else {
            return grant_required(request);
        };
        let grants = state.grants.lock().await;
        grants.validate(
            grant_id,
            &typed.project_id,
            &typed.profile_id,
            GrantAction::SetSecret,
            now_unix_nanos,
            typed.binding.as_ref(),
        )
    };
    if !matches!(grant_validation, GrantValidation::Valid) {
        return grant_required(request);
    }

    let master_key = {
        let cache = state.unlock_cache.lock().await;
        cache
            .lookup(&typed.project_id, now_unix_nanos)
            .map(|entry| Zeroizing::new(entry.key_bytes().to_vec()))
    };
    let Some(master_key) = master_key else {
        return typed_error(
            request,
            ERROR_UNLOCK_REQUIRED,
            UNLOCK_REQUIRED_MESSAGE,
            LocketError::UnlockRequired,
        );
    };

    match set_secret(SetSecretOperation {
        store_path: Path::new(&typed.store_path),
        project_id: &typed.project_id,
        profile_id: &typed.profile_id,
        name: name.as_str(),
        source,
        source_was_omitted,
        value: &value,
        rotate: typed.rotate,
        grace_until: typed.grace_until,
        master_key: &master_key,
        timestamp: now_unix_nanos,
        imported: false,
    }) {
        Ok(response) => {
            let payload = serde_json::to_value(response).unwrap_or(Value::Null);
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

#[derive(Debug)]
pub(super) struct SetSecretFailure {
    pub(crate) error: &'static str,
    pub(crate) message: &'static str,
    kind: LocketError,
}

impl SetSecretFailure {
    const fn new(error: &'static str, message: &'static str, kind: LocketError) -> Self {
        Self { error, message, kind }
    }
}

#[derive(Clone, Copy)]
pub(super) struct SetSecretOperation<'a> {
    pub(crate) store_path: &'a Path,
    pub(crate) project_id: &'a str,
    pub(crate) profile_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) source: &'a str,
    pub(crate) source_was_omitted: bool,
    pub(crate) value: &'a str,
    pub(crate) rotate: bool,
    pub(crate) grace_until: Option<i64>,
    pub(crate) master_key: &'a [u8],
    pub(crate) timestamp: i128,
    pub(crate) imported: bool,
}

fn set_secret(operation: SetSecretOperation<'_>) -> Result<SetSecretResponse, SetSecretFailure> {
    let timestamp = i64::try_from(operation.timestamp).map_err(|_| corrupt_db())?;
    let master_key = master_key_array(operation.master_key).map_err(|_| corrupt_db())?;
    let mut store = Store::open(operation.store_path).map_err(|_| corrupt_db())?;
    set_secret_in_store(&mut store, &operation, &master_key, timestamp)
}

pub(super) fn set_secret_in_store(
    store: &mut Store,
    operation: &SetSecretOperation<'_>,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<SetSecretResponse, SetSecretFailure> {
    ensure_profile_exists(store, operation.project_id, operation.profile_id)?;
    if operation.rotate {
        rotate_secret(store, operation, master_key, timestamp)
    } else {
        create_secret(store, operation, master_key, timestamp)
    }
}

#[allow(clippy::too_many_lines)]
fn create_secret(
    store: &mut Store,
    operation: &SetSecretOperation<'_>,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<SetSecretResponse, SetSecretFailure> {
    if let Some(existing) = store
        .get_secret_by_source(
            operation.project_id,
            operation.profile_id,
            operation.name,
            operation.source,
        )
        .map_err(|_| corrupt_db())?
    {
        if existing.state == "deleted" {
            return Err(SetSecretFailure::new(
                ERROR_SECRET_DELETED,
                "secret source is deleted",
                LocketError::SecretDeleted,
            ));
        }
        return Err(SetSecretFailure::new(
            ERROR_SECRET_ALREADY_EXISTS,
            "secret exists; rotate instead",
            LocketError::SecretAlreadyExists,
        ));
    }
    if operation.source_was_omitted
        && !store
            .list_secrets_by_name(operation.project_id, operation.profile_id, operation.name)
            .map_err(|_| corrupt_db())?
            .is_empty()
    {
        return Err(SetSecretFailure::new(
            ERROR_SECRET_ALREADY_EXISTS,
            "secret exists in another source",
            LocketError::SecretAlreadyExists,
        ));
    }

    let secret_id = SecretId::generate().map_err(|_| corrupt_db())?;
    let version = 1;
    let (encrypted, fingerprint) = encrypt_secret_version(
        store,
        operation.project_id,
        operation.profile_id,
        secret_id.as_str(),
        operation.name,
        version,
        operation.value,
        master_key,
    )?;
    let audit_key = unwrap_audit_key_with_master(store, operation.project_id, master_key)
        .map_err(|_| corrupt_db())?;
    let secret_id = secret_id.into_string();
    let metadata = secret_audit_metadata(
        if operation.imported { "IMPORT" } else { "SET" },
        operation.name,
        operation.profile_id,
        operation.source,
        Some(version),
    );
    let audit = AuditWrite {
        project_id: operation.project_id,
        profile_id: Some(operation.profile_id),
        action: if operation.imported { "IMPORT" } else { "SET" },
        status: "SUCCESS",
        secret_name: Some(operation.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    store
        .create_active_secret_with_audit(
            &SecretRecord {
                id: secret_id.clone(),
                project_id: operation.project_id.to_owned(),
                profile_id: operation.profile_id.to_owned(),
                name: operation.name.to_owned(),
                source: operation.source.to_owned(),
                origin: if operation.imported { "imported" } else { ORIGIN }.to_owned(),
                current_version: version,
                state: "active".to_owned(),
                created_at: timestamp,
                updated_at: timestamp,
                last_rotated_at: None,
                deleted_at: None,
            },
            &SecretVersionRecord {
                secret_id: secret_id.clone(),
                version,
                source: operation.source.to_owned(),
                origin: if operation.imported { "imported" } else { ORIGIN }.to_owned(),
                state: "current".to_owned(),
                created_at: timestamp,
                deprecated_at: None,
                grace_until: None,
                purged_at: None,
            },
            &secret_blob(secret_id.as_str(), version, encrypted, timestamp),
            &SecretFingerprintRecord {
                secret_id: secret_id.clone(),
                version,
                fingerprint,
                created_at: timestamp,
            },
            Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
        )
        .map_err(|_| corrupt_db())?;

    Ok(SetSecretResponse {
        action: "SET".to_owned(),
        secret_id,
        version,
        source: operation.source.to_owned(),
    })
}

fn rotate_secret(
    store: &mut Store,
    operation: &SetSecretOperation<'_>,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<SetSecretResponse, SetSecretFailure> {
    let secret = store
        .get_secret_by_source(
            operation.project_id,
            operation.profile_id,
            operation.name,
            operation.source,
        )
        .map_err(|_| corrupt_db())?
        .ok_or_else(|| {
            SetSecretFailure::new(
                ERROR_SECRET_NOT_FOUND,
                "secret not found",
                LocketError::SecretNotFound,
            )
        })?;
    if secret.state == "deleted" {
        return Err(SetSecretFailure::new(
            ERROR_SECRET_DELETED,
            "secret source is deleted",
            LocketError::SecretDeleted,
        ));
    }
    let new_version = secret.current_version.checked_add(1).ok_or_else(|| {
        SetSecretFailure::new(
            ERROR_SECRET_VERSION_OVERFLOW,
            "secret version counter cannot be advanced",
            LocketError::SecretVersionOverflow,
        )
    })?;
    let (encrypted, fingerprint) = encrypt_secret_version(
        store,
        operation.project_id,
        operation.profile_id,
        &secret.id,
        operation.name,
        new_version,
        operation.value,
        master_key,
    )?;
    let audit_key = unwrap_audit_key_with_master(store, operation.project_id, master_key)
        .map_err(|_| corrupt_db())?;
    let metadata = json!({
        "schema_version": 1,
        "action": "ROTATE",
        "status": "SUCCESS",
        "secret_name": operation.name,
        "profile_id": operation.profile_id,
        "source": operation.source,
        "prior_version": secret.current_version,
        "deprecated_version": secret.current_version,
        "target_version": new_version,
        "deprecated_at": timestamp,
        "grace_until": operation.grace_until,
    });
    let audit = AuditWrite {
        project_id: operation.project_id,
        profile_id: Some(operation.profile_id),
        action: "ROTATE",
        status: "SUCCESS",
        secret_name: Some(operation.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    store
        .rotate_secret_with_audit(
            &secret,
            &SecretVersionRecord {
                secret_id: secret.id.clone(),
                version: new_version,
                source: operation.source.to_owned(),
                origin: if operation.imported { "imported" } else { ORIGIN }.to_owned(),
                state: "current".to_owned(),
                created_at: timestamp,
                deprecated_at: None,
                grace_until: None,
                purged_at: None,
            },
            &secret_blob(&secret.id, new_version, encrypted, timestamp),
            &SecretFingerprintRecord {
                secret_id: secret.id.clone(),
                version: new_version,
                fingerprint,
                created_at: timestamp,
            },
            VersionDeprecation { deprecated_at: timestamp, grace_until: operation.grace_until },
            Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
        )
        .map_err(|_| corrupt_db())?;

    Ok(SetSecretResponse {
        action: "ROTATE".to_owned(),
        secret_id: secret.id,
        version: new_version,
        source: operation.source.to_owned(),
    })
}

fn validate_secret_value(value: &str) -> Result<(), SetSecretFailure> {
    if value.is_empty() {
        return Err(SetSecretFailure::new(
            ERROR_INVALID_REFERENCE,
            "secret value cannot be empty",
            LocketError::InvalidReference,
        ));
    }
    if value.contains('\0') {
        return Err(SetSecretFailure::new(
            ERROR_METADATA_INVALID,
            "secret value cannot contain NUL bytes",
            LocketError::MetadataInvalid,
        ));
    }
    if value.contains('\n') || value.contains('\r') {
        return Err(SetSecretFailure::new(
            ERROR_METADATA_INVALID,
            "secret value cannot contain newlines",
            LocketError::MetadataInvalid,
        ));
    }
    Ok(())
}

fn ensure_profile_exists(
    store: &Store,
    project_id: &str,
    profile_id: &str,
) -> Result<(), SetSecretFailure> {
    let profile_exists = store
        .list_profiles(project_id)
        .map_err(|_| corrupt_db())?
        .into_iter()
        .any(|profile| profile.id == profile_id);
    if profile_exists {
        Ok(())
    } else {
        Err(SetSecretFailure::new(
            ERROR_PROFILE_NOT_FOUND,
            "profile not found",
            LocketError::ProfileNotFound,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
fn encrypt_secret_version(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    secret_id: &str,
    secret_name: &str,
    version: u32,
    value: &str,
    master_key: &locket_crypto::KeyBytes,
) -> Result<(EncryptedSecretValue, Vec<u8>), SetSecretFailure> {
    let profile_secret_key = unwrap_profile_key_with_master(
        store,
        project_id,
        profile_id,
        master_key,
        KeyPurpose::ProfileSecret,
    )
    .map_err(|_| corrupt_db())?;
    let profile_fingerprint_key = unwrap_profile_key_with_master(
        store,
        project_id,
        profile_id,
        master_key,
        KeyPurpose::ProfileFingerprint,
    )
    .map_err(|_| corrupt_db())?;
    let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        project_id,
        profile_id,
        secret_id,
        secret_name,
        version,
    ))
    .map_err(|_| corrupt_db())?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        secret_id,
        Some(profile_id),
        version,
        KeyWrapPurpose::SecretDek,
    ))
    .map_err(|_| corrupt_db())?;
    let encrypted = encrypt_secret_value_v1(&profile_secret_key, value, &value_aad, &wrap_aad)
        .map_err(|_| corrupt_db())?;
    let fingerprint =
        secret_fingerprint_v1(&profile_fingerprint_key, value).map_err(|_| corrupt_db())?;
    Ok((encrypted, fingerprint.to_vec()))
}

fn secret_blob(
    secret_id: &str,
    version: u32,
    encrypted: EncryptedSecretValue,
    timestamp: i64,
) -> SecretBlobRecord {
    SecretBlobRecord {
        secret_id: secret_id.to_owned(),
        version,
        encrypted_dek: encrypted.encrypted_dek,
        ciphertext: encrypted.ciphertext,
        value_nonce: encrypted.value_nonce,
        aad_schema_version: encrypted.aad_schema_version,
        created_at: timestamp,
    }
}

fn secret_audit_metadata(
    action: &str,
    secret_name: &str,
    profile_id: &str,
    source: &str,
    version: Option<u32>,
) -> Value {
    json!({
        "schema_version": 1,
        "action": action,
        "status": "SUCCESS",
        "secret_name": secret_name,
        "profile_id": profile_id,
        "source": source,
        "version": version,
    })
}

const fn corrupt_db() -> SetSecretFailure {
    SetSecretFailure::new(ERROR_CORRUPT_DB, "secret mutation failed", LocketError::CorruptDb)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::too_many_lines)]
    #![allow(clippy::unwrap_used)]

    use super::{SetSecretRequest, SetSecretResponse, handle_set_secret};
    use crate::PROTOCOL_VERSION;
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::grant::{GrantAction, GrantBinding, GrantRecord, GrantRecordFields};
    use crate::method::AgentMethod;
    use crate::server::AgentSocketState;
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};
    use locket_crypto::{
        HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, derive_wrapping_key_v1,
        key_wrap_aad_v1, wrap_key_material_v1,
    };
    use locket_store::{KeyRecord, Store};
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::{TempDir, tempdir};

    const PROJECT_ID: &str = "lk_proj_set";
    const PROFILE_ID: &str = "lk_prof_dev";
    const PROFILE_NAME: &str = "dev";
    const SECRET_NAME: &str = "DATABASE_URL";
    const GRANT_ID: &str = "lk_grant_set";
    const NOW: i128 = 10_000;

    struct Fixture {
        _directory: TempDir,
        store_path: PathBuf,
        master_key: locket_crypto::KeyBytes,
    }

    fn request(fixture: &Fixture) -> SetSecretRequest {
        SetSecretRequest {
            store_path: fixture.store_path.display().to_string(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
            secret_name: SECRET_NAME.to_owned(),
            source: Some("user-local".to_owned()),
            value: fixture_value("one"),
            rotate: false,
            grace_until: None,
            grant_id: Some(GRANT_ID.to_owned()),
            binding: Some(GrantBinding::new(std::process::id(), "0")),
        }
    }

    fn fixture_value(label: &str) -> String {
        format!("fixture-value-{label}")
    }

    fn grant_record(action: GrantAction, expires_at_unix_nanos: i128) -> GrantRecord {
        GrantRecord::new(GrantRecordFields {
            grant_id: GRANT_ID.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
            action,
            binding: GrantBinding::new(std::process::id(), "0"),
            issued_at_unix_nanos: 0,
            ttl_seconds: 30,
            expires_at_unix_nanos,
        })
    }

    fn build_fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let store_path = directory.path().join("store.db");
        let mut store = Store::open(&store_path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT_ID, "set-test", 1)?;
        store.insert_profile_if_absent(PROFILE_ID, PROJECT_ID, PROFILE_NAME, false, 1)?;

        let master_key = [7_u8; 32];
        insert_wrapped_project_key(
            &store,
            "lk_key_project_audit_set",
            KeyPurpose::Audit,
            &master_key,
            &[10_u8; 32],
        )?;
        insert_wrapped_profile_key(
            &store,
            "lk_key_profile_secret_set",
            KeyPurpose::ProfileSecret,
            &master_key,
            &[8_u8; 32],
        )?;
        insert_wrapped_profile_key(
            &store,
            "lk_key_profile_fingerprint_set",
            KeyPurpose::ProfileFingerprint,
            &master_key,
            &[9_u8; 32],
        )?;
        Ok(Fixture { _directory: directory, store_path, master_key })
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

    async fn unlocked_state(fixture: &Fixture) -> AgentSocketState {
        let state = AgentSocketState::locked("test-version");
        state.grants.lock().await.insert(grant_record(GrantAction::SetSecret, i128::MAX));
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

    async fn set_with_request(
        request: SetSecretRequest,
        fixture: &Fixture,
    ) -> Result<ResponseEnvelope, Box<dyn std::error::Error>> {
        let state = unlocked_state(fixture).await;
        let envelope =
            RequestEnvelope::new("req-set", AgentMethod::SetSecret, serde_json::to_value(request)?);
        Ok(handle_set_secret(&envelope, &state, NOW).await)
    }

    fn success_payload(
        response: ResponseEnvelope,
    ) -> Result<SetSecretResponse, Box<dyn std::error::Error>> {
        let ResponseEnvelope::Success(success) = response else {
            return Err(format!("expected success envelope, got {response:?}").into());
        };
        Ok(serde_json::from_value(success.payload)?)
    }

    fn error_code(response: ResponseEnvelope) -> Result<String, Box<dyn std::error::Error>> {
        let ResponseEnvelope::Error(error) = response else {
            return Err(format!("expected error envelope, got {response:?}").into());
        };
        Ok(error.error)
    }

    fn audit_metadata(
        fixture: &Fixture,
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
                assert_eq!(secret_name.as_deref(), Some(SECRET_NAME));
                assert!(command.is_none());
                Ok(metadata)
            })
            .collect()
    }

    #[test]
    fn set_secret_payloads_round_trip_through_json() -> Result<(), serde_json::Error> {
        let request = SetSecretRequest {
            store_path: "/tmp/store.db".to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
            secret_name: SECRET_NAME.to_owned(),
            source: Some("machine-local".to_owned()),
            value: fixture_value("round-trip"),
            rotate: true,
            grace_until: Some(42),
            grant_id: Some(GRANT_ID.to_owned()),
            binding: Some(GrantBinding::new(123, "start")),
        };

        let value = serde_json::to_value(&request)?;
        let decoded: SetSecretRequest = serde_json::from_value(value)?;

        assert_eq!(decoded, request);
        let response = SetSecretResponse {
            action: "SET".to_owned(),
            secret_id: "lk_sec_abc".to_owned(),
            version: 1,
            source: "machine-local".to_owned(),
        };
        let decoded: SetSecretResponse = serde_json::from_value(serde_json::to_value(&response)?)?;
        assert_eq!(decoded, response);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_secret_rejects_malformed_payload_with_protocol_error() {
        let state = AgentSocketState::locked("test-version");
        let envelope =
            RequestEnvelope::new("req-bad", AgentMethod::SetSecret, json!({ "secret_name": 12 }));

        let response = handle_set_secret(&envelope, &state, NOW).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.v, PROTOCOL_VERSION);
        assert_eq!(error.error, "ProtocolError");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_secret_requires_live_grant() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = AgentSocketState::locked("test-version");
        let envelope = RequestEnvelope::new(
            "req-no-grant",
            AgentMethod::SetSecret,
            serde_json::to_value(request(&fixture))?,
        );

        let response = handle_set_secret(&envelope, &state, NOW).await;
        assert_eq!(error_code(response)?, "GrantRequired");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_secret_requires_unlock_after_grant() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = AgentSocketState::locked("test-version");
        state.grants.lock().await.insert(grant_record(GrantAction::SetSecret, i128::MAX));
        let envelope = RequestEnvelope::new(
            "req-locked",
            AgentMethod::SetSecret,
            serde_json::to_value(request(&fixture))?,
        );

        let response = handle_set_secret(&envelope, &state, NOW).await;
        assert_eq!(error_code(response)?, "UnlockRequired");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_secret_rejects_invalid_name_and_value() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let mut invalid_name = request(&fixture);
        invalid_name.secret_name = "not-loud".to_owned();
        assert_eq!(
            error_code(set_with_request(invalid_name, &fixture).await?)?,
            "InvalidSecretName"
        );

        let mut empty_value = request(&fixture);
        empty_value.value.clear();
        assert_eq!(error_code(set_with_request(empty_value, &fixture).await?)?, "InvalidReference");

        let mut newline_value = request(&fixture);
        newline_value.value = "fixture\nvalue".to_owned();
        assert_eq!(
            error_code(set_with_request(newline_value, &fixture).await?)?,
            "MetadataInvalid"
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_secret_creates_encrypted_rows_and_metadata_only_audit()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let response = set_with_request(request(&fixture), &fixture).await?;
        let payload = success_payload(response)?;

        assert_eq!(payload.action, "SET");
        assert_eq!(payload.version, 1);
        assert_eq!(payload.source, "user-local");
        let store = Store::open(&fixture.store_path)?;
        let secret = store
            .get_active_secret(PROJECT_ID, PROFILE_ID, SECRET_NAME, "user-local")?
            .ok_or("missing secret")?;
        assert_eq!(secret.id, payload.secret_id);
        assert!(store.get_blob(&secret.id, 1)?.is_some());
        let audits = audit_metadata(&fixture)?;
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0]["action"], "SET");
        assert_eq!(audits[0]["secret_name"], SECRET_NAME);
        assert_eq!(audits[0]["profile_id"], PROFILE_ID);
        assert_eq!(audits[0]["source"], "user-local");
        assert!(audits[0].get("value").is_none());
        assert!(!audits[0].to_string().contains(&fixture_value("one")));
        assert!(!serde_json::to_string(&payload)?.contains(&fixture_value("one")));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_secret_rejects_duplicate_create() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let _ = set_with_request(request(&fixture), &fixture).await?;
        let duplicate = set_with_request(request(&fixture), &fixture).await?;

        assert_eq!(error_code(duplicate)?, "SecretAlreadyExists");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_secret_rotates_existing_secret_with_audit()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let _ = set_with_request(request(&fixture), &fixture).await?;
        let mut rotate = request(&fixture);
        rotate.rotate = true;
        rotate.value = fixture_value("two");
        rotate.grace_until = Some(12_345);

        let response = set_with_request(rotate, &fixture).await?;
        let payload = success_payload(response)?;

        assert_eq!(payload.action, "ROTATE");
        assert_eq!(payload.version, 2);
        let store = Store::open(&fixture.store_path)?;
        let versions = store.list_secret_versions(&payload.secret_id)?;
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].state, "deprecated");
        assert_eq!(versions[0].grace_until, Some(12_345));
        assert_eq!(versions[1].state, "current");
        let audits = audit_metadata(&fixture)?;
        assert_eq!(audits.len(), 2);
        assert_eq!(audits[1]["action"], "ROTATE");
        assert_eq!(audits[1]["prior_version"], 1);
        assert_eq!(audits[1]["target_version"], 2);
        assert!(audits[1].get("value").is_none());
        assert!(!audits[1].to_string().contains(&fixture_value("two")));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_secret_rejects_missing_rotate_target() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let mut rotate = request(&fixture);
        rotate.rotate = true;

        let response = set_with_request(rotate, &fixture).await?;

        assert_eq!(error_code(response)?, "SecretNotFound");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn set_secret_maps_deleted_and_overflow_targets() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = build_fixture()?;
        let created = success_payload(set_with_request(request(&fixture), &fixture).await?)?;
        let store = Store::open(&fixture.store_path)?;
        store
            .connection()
            .execute("UPDATE secrets SET state = 'deleted' WHERE id = ?1", [&created.secret_id])?;
        let mut rotate_deleted = request(&fixture);
        rotate_deleted.rotate = true;
        assert_eq!(error_code(set_with_request(rotate_deleted, &fixture).await?)?, "SecretDeleted");

        store.connection().execute(
            "UPDATE secrets SET state = 'active', current_version = ?2 WHERE id = ?1",
            (&created.secret_id, u32::MAX),
        )?;
        let mut rotate_overflow = request(&fixture);
        rotate_overflow.rotate = true;
        assert_eq!(
            error_code(set_with_request(rotate_overflow, &fixture).await?)?,
            "SecretVersionOverflow"
        );
        Ok(())
    }
}
