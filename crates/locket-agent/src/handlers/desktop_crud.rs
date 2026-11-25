//! Single-use, metadata-only desktop mutations.

use locket_core::{KeyId, ProfileId, ProfileName, SecretId, SecretName, source_precedence};
use locket_crypto::{
    HkdfWrapInfo, KeyBytes, KeyPurpose, KeyWrapAad, KeyWrapPurpose, derive_wrapping_key_v1,
    generate_key, key_wrap_aad_v1, wrap_key_material_v1,
};
use locket_store::{
    AuditContext, AuditWrite, KeyRecord, ProfileRecord, SecretCopyTarget, SecretFingerprintRecord,
    SecretRecord, SecretVersionRecord, Store, VersionDeprecation,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    MutationError, MutationScope, confirm_dangerous_profile, context, failure,
    is_shared_project_id, metadata, response, storage,
};
use crate::keys::{StoreFileIdentity, master_key_array, unwrap_audit_key_with_master};
use crate::set_secret::{encrypt_secret_version, secret_audit_metadata, secret_blob};
use crate::{
    AgentMethod, AgentSocketState, GrantAction, GrantValidation, RequestEnvelope, ResponseEnvelope,
    UnlockCache,
};

const USER_LOCAL: &str = "user-local";
const SOURCE_LOCKED: &str = "unlock the source vault before copying to the Global Vault";
const TARGET_LOCKED: &str = "unlock the Global Vault before copying the secret";

#[derive(Deserialize)]
struct CreateProfile {
    profile_name: String,
}

#[derive(Deserialize)]
struct DeleteSecret {
    secret_name: String,
    source: String,
    confirmation: Option<String>,
}

#[derive(Deserialize)]
struct CopySecretToShared {
    secret_name: String,
    source: Option<String>,
    #[serde(default)]
    overwrite: bool,
    confirmation: Option<String>,
}

/// Metadata for the new environment.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateProfileResponse {
    /// New profile ID.
    pub profile_id: String,
    /// New profile display name.
    pub profile_name: String,
    /// New profiles start with the dangerous marker cleared.
    pub dangerous: bool,
    /// Whether the environment was created.
    pub created: bool,
}

/// Metadata for the tombstoned secret source.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeleteSecretResponse {
    /// Name of the deleted secret.
    pub secret_name: String,
    /// Deleted source.
    pub source: String,
    /// Version current at deletion.
    pub version: u32,
    /// Whether the deletion committed.
    pub deleted: bool,
}

/// Metadata for the promoted secret's destination.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CopySecretToSharedResponse {
    /// Global Vault ID.
    pub target_project_id: String,
    /// Global Vault default profile ID.
    pub target_profile_id: String,
    /// Name of the copied secret.
    pub secret_name: String,
    /// New current version in the Global Vault.
    pub version: u32,
    /// Whether the target was created or rotated.
    pub action: String,
}

/// Dispatches a desktop CRUD operation and consumes its scoped grant.
pub async fn handle_desktop_crud(
    method: AgentMethod,
    request: &RequestEnvelope,
    state: &AgentSocketState,
    now: i128,
) -> ResponseEnvelope {
    let result = async {
        let action = match method {
            AgentMethod::CreateProfile => GrantAction::CreateProfile,
            AgentMethod::DeleteSecret => GrantAction::DeleteSecret,
            AgentMethod::CopySecretToShared => GrantAction::CopySecretToShared,
            _ => return Err(metadata()),
        };
        let scope: MutationScope =
            MutationScope::deserialize(&request.payload).map_err(|_| metadata())?;
        consume_grant(state, &scope, action, now).await?;
        let cache = state.unlock_cache.lock().await;
        let locked = if action == GrantAction::CopySecretToShared {
            SOURCE_LOCKED
        } else {
            "unlock the selected vault before retrying"
        };
        let entry = cache.lookup(&scope.project_id, now).ok_or_else(|| unlock_required(locked))?;
        let master = master_key_array(entry.key_bytes()).map_err(|_| storage())?;
        let (mut store, identity) = state
            .open_store(&scope.store_path, entry.store_identity.as_ref(), false)
            .map_err(|_| failure("AccessDenied", "could not verify mutation store"))?;
        let timestamp = i64::try_from(now).map_err(|_| storage())?;
        let result = store.with_atomic_write(|store| {
            let payload = &request.payload;
            match method {
                AgentMethod::CreateProfile => {
                    let typed = CreateProfile::deserialize(payload).map_err(|_| metadata())?;
                    serde_json::to_value(create_profile(store, &scope, typed, &master, timestamp)?)
                }
                AgentMethod::DeleteSecret => {
                    let typed = DeleteSecret::deserialize(payload).map_err(|_| metadata())?;
                    serde_json::to_value(delete_secret(store, &scope, typed, &master, timestamp)?)
                }
                AgentMethod::CopySecretToShared => {
                    let typed = CopySecretToShared::deserialize(payload).map_err(|_| metadata())?;
                    serde_json::to_value(copy_to_shared(
                        store, &scope, typed, &master, &cache, &identity, timestamp,
                    )?)
                }
                _ => return Err(metadata()),
            }
            .map_err(|_| storage())
        });
        // Keep vault locking ordered with the durable transaction.
        drop(cache);
        result
    }
    .await;
    response(request, result)
}

async fn consume_grant(
    state: &AgentSocketState,
    scope: &MutationScope,
    action: GrantAction,
    now: i128,
) -> Result<(), MutationError> {
    let required = || failure("GrantRequired", "a matching live grant is required");
    let id = scope.grant_id.as_deref().ok_or_else(required)?;
    let mut grants = state.grants.lock().await;
    if grants.validate(
        id,
        &scope.project_id,
        &scope.profile_id,
        action,
        now,
        scope.binding.as_ref(),
    ) != GrantValidation::Valid
    {
        return Err(required());
    }
    // Consume before work so a failed, concurrent, or disconnected call cannot reuse it.
    grants.revoke(id);
    drop(grants);
    Ok(())
}

const fn unlock_required(message: &'static str) -> MutationError {
    failure("UnlockRequired", message)
}

fn create_profile(
    store: &mut Store,
    scope: &MutationScope,
    request: CreateProfile,
    master: &KeyBytes,
    timestamp: i64,
) -> Result<CreateProfileResponse, MutationError> {
    if is_shared_project_id(&scope.project_id) || scope.project_root.as_os_str().is_empty() {
        return Err(failure(
            "MetadataInvalid",
            "creating an environment requires a trusted project folder",
        ));
    }
    context(store, scope)?;
    let project = &scope.project_id;
    let name = ProfileName::new(request.profile_name)
        .map_err(|_| failure("InvalidProfileName", "invalid profile name"))?;
    let id = ProfileId::generate().map_err(|_| storage())?;
    if !store.insert_profile_if_absent(id.as_str(), project, name.as_str(), false, timestamp)? {
        return Err(failure("SecretAlreadyExists", "profile already exists"));
    }
    for purpose in [KeyPurpose::ProfileSecret, KeyPurpose::ProfileFingerprint] {
        store.insert_key(&wrap_profile_key(project, id.as_str(), purpose, master, timestamp)?)?;
    }
    let key = unwrap_audit_key_with_master(store, project, master).map_err(|_| storage())?;
    let audit = AuditWrite {
        project_id: project,
        profile_id: Some(id.as_str()),
        action: "PROFILE_CREATE",
        status: "SUCCESS",
        secret_name: None,
        command: None,
        metadata_json: &json!({
            "schema_version": 1, "action": "PROFILE_CREATE", "status": "SUCCESS",
            "project_id": project, "profile_id": id.as_str(), "profile_name": name.as_str(),
            "dangerous": false, "key_purposes_initialized": ["profile-secret", "profile-fingerprint"],
        }),
        timestamp,
    };
    store.append_audit(key.as_ref(), &audit)?;
    Ok(CreateProfileResponse {
        profile_id: id.into_string(),
        profile_name: name.as_str().to_owned(),
        dangerous: false,
        created: true,
    })
}

fn wrap_profile_key(
    project: &str,
    profile: &str,
    purpose: KeyPurpose,
    master: &KeyBytes,
    timestamp: i64,
) -> Result<KeyRecord, MutationError> {
    let id = KeyId::generate().map_err(|_| storage())?;
    let material = generate_key().map_err(|_| storage())?;
    let wrapping_key =
        derive_wrapping_key_v1(master, &HkdfWrapInfo::new(project, Some(profile), purpose))
            .map_err(|_| storage())?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project,
        id.as_str(),
        Some(profile),
        0,
        KeyWrapPurpose::from(purpose),
    ))
    .map_err(|_| storage())?;
    let wrapped = wrap_key_material_v1(&wrapping_key, &material, &aad).map_err(|_| storage())?;
    Ok(KeyRecord {
        id: id.into_string(),
        project_id: project.to_owned(),
        profile_id: Some(profile.to_owned()),
        purpose: purpose.as_str().to_owned(),
        wrapped_material: wrapped.ciphertext,
        nonce: wrapped.nonce,
        created_at: timestamp,
    })
}

fn delete_secret(
    store: &mut Store,
    scope: &MutationScope,
    request: DeleteSecret,
    master: &KeyBytes,
    timestamp: i64,
) -> Result<DeleteSecretResponse, MutationError> {
    let profile = context(store, scope)?.profile;
    confirm_dangerous_profile(
        &profile,
        request.confirmation.as_deref(),
        "type the profile name to confirm deletion",
    )?;
    let name = validated_name(request.secret_name)?;
    validate_source(&request.source)?;
    let secret = store
        .get_active_secret(&scope.project_id, &profile.id, name.as_str(), &request.source)?
        .ok_or_else(secret_not_found)?;
    let key =
        unwrap_audit_key_with_master(store, &scope.project_id, master).map_err(|_| storage())?;
    let metadata = secret_audit_metadata(
        "DELETE",
        &secret.name,
        &profile.id,
        &secret.source,
        Some(secret.current_version),
    );
    let audit = AuditWrite {
        project_id: &scope.project_id,
        profile_id: Some(&profile.id),
        action: "DELETE",
        status: "SUCCESS",
        secret_name: Some(&secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    store.tombstone_current_secret_with_audit(
        &secret,
        timestamp,
        AuditContext { key: key.as_ref(), write: &audit },
    )?;
    Ok(DeleteSecretResponse {
        secret_name: secret.name,
        source: secret.source,
        version: secret.current_version,
        deleted: true,
    })
}

fn validated_name(input: String) -> Result<SecretName, MutationError> {
    SecretName::new(input).map_err(|_| failure("InvalidSecretName", "invalid secret name"))
}

const fn validate_source(source: &str) -> Result<(), MutationError> {
    if source_precedence(source) == 0 {
        return Err(failure("InvalidReference", "invalid secret source"));
    }
    Ok(())
}

const fn secret_not_found() -> MutationError {
    failure("SecretNotFound", "secret not found")
}

fn select_copy_source(
    store: &Store,
    profile: &ProfileRecord,
    name: &str,
    source: Option<&str>,
    timestamp: i64,
) -> Result<SecretRecord, MutationError> {
    let secret = if let Some(source) = source {
        validate_source(source)?;
        store.get_active_secret(&profile.project_id, &profile.id, name, source)?
    } else {
        store
            .list_secrets_by_name(&profile.project_id, &profile.id, name)?
            .into_iter()
            .filter(|secret| secret.state == "active" && source_precedence(&secret.source) > 0)
            .max_by_key(|secret| source_precedence(&secret.source))
    }
    .ok_or_else(secret_not_found)?;
    if super::super::secrets::secret_has_expired(store, &secret.id, i128::from(timestamp))? {
        return Err(failure("MetadataInvalid", super::super::secrets::SECRET_EXPIRED_MESSAGE));
    }
    if store
        .get_secret_version(&secret.id, secret.current_version)?
        .is_none_or(|version| version.state != "current")
    {
        return Err(failure(
            "SecretVersionExpired",
            "the source secret version is no longer current",
        ));
    }
    Ok(secret)
}

fn copy_to_shared(
    store: &mut Store,
    scope: &MutationScope,
    request: CopySecretToShared,
    master: &KeyBytes,
    cache: &UnlockCache,
    identity: &StoreFileIdentity,
    timestamp: i64,
) -> Result<CopySecretToSharedResponse, MutationError> {
    let source_profile = context(store, scope)?.profile;
    let target = store
        .list_projects()?
        .into_iter()
        .filter(|project| is_shared_project_id(&project.id))
        .min_by_key(|project| project.name != "@shared")
        .ok_or_else(|| {
            failure("ProjectNotFound", "set up the Global Vault before copying the secret")
        })?;
    let target_entry = cache
        .lookup(&target.id, i128::from(timestamp))
        .ok_or_else(|| unlock_required(TARGET_LOCKED))?;
    if target_entry.store_identity.as_ref().is_some_and(|pin| pin != identity) {
        return Err(failure("AccessDenied", "the Global Vault does not match the selected store"));
    }
    let target_profile = store
        .get_profile_by_name(&target.id, "default")?
        .ok_or_else(|| failure("ProfileNotFound", "the Global Vault default profile is missing"))?;
    confirm_dangerous_profile(
        &source_profile,
        request.confirmation.as_deref(),
        "type the source profile name to confirm the copy",
    )?;
    confirm_dangerous_profile(
        &target_profile,
        request.confirmation.as_deref(),
        "type the Global Vault profile name to confirm the copy",
    )?;

    let name = validated_name(request.secret_name)?;
    let source = select_copy_source(
        store,
        &source_profile,
        name.as_str(),
        request.source.as_deref(),
        timestamp,
    )?;
    let existing =
        store.get_secret_by_source(&target.id, &target_profile.id, name.as_str(), USER_LOCAL)?;
    if existing.as_ref().is_some_and(|existing| existing.state == "deleted") {
        return Err(failure("SecretDeleted", "the Global Vault secret source is deleted"));
    }
    if existing.is_some() && !request.overwrite {
        return Err(failure(
            "SecretAlreadyExists",
            "a user-local secret with this name already exists in the Global Vault",
        ));
    }
    if existing.as_ref().is_some_and(|existing| existing.id == source.id) {
        return Err(failure(
            "InvalidReference",
            "the secret is already in the target profile and source",
        ));
    }
    let target_master = master_key_array(target_entry.key_bytes()).map_err(|_| storage())?;
    promote_secret(
        store,
        &source,
        master,
        &target_profile,
        &target_master,
        existing.as_ref(),
        timestamp,
    )
}

fn promote_secret(
    store: &mut Store,
    source: &SecretRecord,
    master: &KeyBytes,
    target: &ProfileRecord,
    target_master: &KeyBytes,
    existing: Option<&SecretRecord>,
    timestamp: i64,
) -> Result<CopySecretToSharedResponse, MutationError> {
    let version =
        existing.map_or(Some(1), |record| record.current_version.checked_add(1)).ok_or_else(
            || failure("SecretVersionOverflow", "the target secret cannot be rotated again"),
        )?;
    let secret_id = match existing {
        Some(record) => record.id.clone(),
        None => SecretId::generate().map_err(|_| storage())?.into_string(),
    };
    let (encrypted, fingerprint) =
        reencrypt_for_promotion(store, source, master, target, target_master, &secret_id, version)?;
    let new_secret = SecretRecord {
        id: secret_id.clone(),
        project_id: target.project_id.clone(),
        profile_id: target.id.clone(),
        name: source.name.clone(),
        source: USER_LOCAL.into(),
        origin: "profile-copy".into(),
        current_version: version,
        state: "active".into(),
        created_at: timestamp,
        updated_at: timestamp,
        last_rotated_at: None,
        deleted_at: None,
    };
    let new_version = SecretVersionRecord {
        secret_id: secret_id.clone(),
        version,
        source: USER_LOCAL.into(),
        origin: "profile-copy".into(),
        state: "current".into(),
        created_at: timestamp,
        deprecated_at: None,
        grace_until: None,
        purged_at: None,
    };
    let blob = secret_blob(&secret_id, version, encrypted, timestamp);
    let fingerprint =
        SecretFingerprintRecord { secret_id, version, fingerprint, created_at: timestamp };
    let metadata = json!({
        "schema_version": 1, "action": "SECRET_COPY", "status": "SUCCESS", "secret_name": source.name,
        "from_project_id": source.project_id, "from_profile_id": source.profile_id,
        "from_source": source.source, "from_version": source.current_version,
        "to_project_id": target.project_id, "to_profile_id": target.id, "to_source": USER_LOCAL,
        "prior_target_version": existing.map(|record| record.current_version), "target_version": version,
    });
    let target_key = unwrap_audit_key_with_master(store, &target.project_id, target_master)
        .map_err(|_| storage())?;
    let target_audit = AuditWrite {
        project_id: &target.project_id,
        profile_id: Some(&target.id),
        action: "SECRET_COPY",
        status: "SUCCESS",
        secret_name: Some(&source.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    let (copy_target, action) =
        existing.map_or((SecretCopyTarget::Create(&new_secret), "create"), |secret| {
            (
                SecretCopyTarget::Rotate {
                    secret,
                    deprecation: VersionDeprecation { deprecated_at: timestamp, grace_until: None },
                },
                "rotate",
            )
        });
    store.copy_secret_with_audit(
        copy_target,
        &new_version,
        &blob,
        &fingerprint,
        Some(AuditContext { key: target_key.as_ref(), write: &target_audit }),
    )?;
    if source.project_id != target.project_id {
        let source_key = unwrap_audit_key_with_master(store, &source.project_id, master)
            .map_err(|_| storage())?;
        store.append_audit(
            source_key.as_ref(),
            &AuditWrite {
                project_id: &source.project_id,
                profile_id: Some(&source.profile_id),
                ..target_audit
            },
        )?;
    }
    Ok(CopySecretToSharedResponse {
        target_project_id: target.project_id.clone(),
        target_profile_id: target.id.clone(),
        secret_name: source.name.clone(),
        version,
        action: action.into(),
    })
}

fn reencrypt_for_promotion(
    store: &Store,
    source: &SecretRecord,
    master: &KeyBytes,
    target: &ProfileRecord,
    target_master: &KeyBytes,
    secret_id: &str,
    version: u32,
) -> Result<(locket_crypto::EncryptedSecretValue, Vec<u8>), MutationError> {
    // The zeroizing buffer drops before the caller constructs records or audit rows.
    let value = crate::reveal::decrypt_secret(
        store,
        &source.project_id,
        &source.profile_id,
        source,
        source.current_version,
        master,
    )
    .map_err(|_| storage())?;
    encrypt_secret_version(
        store,
        &target.project_id,
        &target.id,
        secret_id,
        &source.name,
        version,
        &value,
        target_master,
    )
    .map_err(|_| storage())
}
