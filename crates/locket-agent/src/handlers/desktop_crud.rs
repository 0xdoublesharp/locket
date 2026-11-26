//! Single-use, metadata-only desktop mutations.

use std::collections::{BTreeMap, BTreeSet};

use locket_core::{KeyId, ProfileId, ProfileName, SecretId, SecretName, source_precedence};
use locket_crypto::{
    HkdfWrapInfo, KeyBytes, KeyPurpose, KeyWrapAad, KeyWrapPurpose, derive_wrapping_key_v1,
    generate_key, key_wrap_aad_v1, local_dedup_tag_v1, wrap_key_material_v1,
};
use locket_store::{
    AuditContext, AuditWrite, KeyRecord, ProfileRecord, SecretCopyTarget, SecretFingerprintRecord,
    SecretLinkRecord, SecretRecord, SecretTransferAudit, SecretVersionRecord, Store,
    VersionDeprecation,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    MutationError, MutationScope, confirm_dangerous_profile, context, failure,
    is_shared_project_id, metadata, require_unexpired_secret, response, storage,
};
use crate::keys::{
    StoreFileIdentity, master_key_array, unwrap_audit_key_with_master,
    unwrap_profile_key_with_master,
};
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
    #[serde(default)]
    unlink_all: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_link_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct CopySecretToShared {
    secret_name: String,
    source: Option<String>,
    #[serde(default)]
    target_name: Option<String>,
    #[serde(default)]
    replace_with_link: bool,
    #[serde(default)]
    consolidate_duplicates: bool,
    #[serde(default)]
    overwrite: bool,
    confirmation: Option<String>,
}

#[derive(Deserialize)]
struct LinkSecret {
    local_name: String,
    target_secret_name: String,
    confirmation: Option<String>,
}

#[derive(Deserialize)]
struct UnlinkSecret {
    local_name: String,
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

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero_u32(value: &u32) -> bool {
    *value == 0
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
    /// Number of project links removed when deleting a linked Global Vault secret.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub unlinked_count: u32,
}

/// Metadata for the promoted secret's destination.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CopySecretToSharedResponse {
    /// Global Vault ID.
    pub target_project_id: String,
    /// Global Vault default profile ID.
    pub target_profile_id: String,
    /// Name of the copied or promoted secret in the Global Vault.
    pub secret_name: String,
    /// New or reused current version in the Global Vault.
    pub version: u32,
    /// Whether the target was created, rotated, or reused.
    pub action: String,
    /// Whether the source project now holds a live link to the Global Vault secret.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub linked: bool,
    /// Number of additional projects consolidated onto the Global Vault secret.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub consolidated_count: u32,
    /// Number of duplicate project copies skipped because their vaults were locked or dangerous.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub skipped_locked_count: u32,
}

/// Metadata for a newly created or updated shared secret link.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LinkSecretResponse {
    /// Opaque link identifier.
    pub link_id: String,
    /// Consuming project local variable name.
    pub local_name: String,
    /// Global Vault project identifier.
    pub target_project_id: String,
    /// Global Vault secret identifier.
    pub target_secret_id: String,
    /// Global Vault secret name.
    pub target_secret_name: String,
}

/// Metadata for a removed shared secret link.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UnlinkSecretResponse {
    /// Consuming project local variable name.
    pub local_name: String,
    /// Whether an active link was removed.
    pub unlinked: bool,
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
            AgentMethod::LinkSecret => GrantAction::LinkSecret,
            AgentMethod::UnlinkSecret => GrantAction::UnlinkSecret,
            _ => return Err(metadata()),
        };
        let scope: MutationScope =
            MutationScope::deserialize(&request.payload).map_err(|_| metadata())?;
        let cache = state.unlock_cache.lock().await;
        consume_grant(state, &scope, action, now).await?;
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
                    serde_json::to_value(delete_secret(
                        store, &scope, typed, &master, &cache, &identity, timestamp,
                    )?)
                }
                AgentMethod::CopySecretToShared => {
                    let typed = CopySecretToShared::deserialize(payload).map_err(|_| metadata())?;
                    serde_json::to_value(copy_to_shared(
                        store, &scope, typed, &master, &cache, &identity, timestamp,
                    )?)
                }
                AgentMethod::LinkSecret => {
                    let typed = LinkSecret::deserialize(payload).map_err(|_| metadata())?;
                    serde_json::to_value(link_secret(store, &scope, typed, &master, timestamp)?)
                }
                AgentMethod::UnlinkSecret => {
                    let typed = UnlinkSecret::deserialize(payload).map_err(|_| metadata())?;
                    serde_json::to_value(unlink_secret(store, &scope, typed, &master, timestamp)?)
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
    cache: &UnlockCache,
    identity: &StoreFileIdentity,
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
    let usages = store.list_shared_secret_usages(&secret.id)?;
    validate_deletion_usages(
        &usages,
        &secret.name,
        request.unlink_all,
        request.expected_link_ids.as_deref(),
        request.confirmation.as_deref(),
    )?;
    let key =
        unwrap_audit_key_with_master(store, &scope.project_id, master).map_err(|_| storage())?;
    let unlinked_count = u32::try_from(usages.len()).unwrap_or(u32::MAX);
    let mut metadata = secret_audit_metadata(
        "DELETE",
        &secret.name,
        &profile.id,
        &secret.source,
        Some(secret.current_version),
    );
    if unlinked_count > 0
        && let Some(object) = metadata.as_object_mut()
    {
        object.insert("unlinked_count".into(), json!(unlinked_count));
    }
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
    let delete_audit = AuditContext { key: key.as_ref(), write: &audit };
    if !usages.is_empty()
        || is_shared_project_id(&scope.project_id)
        || request.expected_link_ids.is_some()
    {
        let consumer_keys =
            consumer_audit_keys(store, &usages, cache, identity, i128::from(timestamp))?;
        let unlink_metadata: Vec<_> =
            usages.iter().map(|usage| usage.unlink_audit_metadata(&secret)).collect();
        let unlink_writes: Vec<_> = usages
            .iter()
            .zip(&unlink_metadata)
            .map(|(usage, metadata)| usage.unlink_audit(metadata, timestamp))
            .collect();
        let unlink_audits = usages
            .iter()
            .zip(&unlink_writes)
            .map(|(usage, write)| {
                let key = consumer_keys[usage.project_id.as_str()].as_ref();
                (usage.link_id.as_str(), AuditContext { key, write })
            })
            .collect();
        store.tombstone_secret_and_unlink_with_audit(
            &secret,
            timestamp,
            Some(delete_audit),
            &unlink_audits,
            request.expected_link_ids.as_deref(),
        )?;
    } else {
        store.tombstone_current_secret_with_audit(&secret, timestamp, delete_audit)?;
    }
    Ok(DeleteSecretResponse {
        secret_name: secret.name,
        source: secret.source,
        version: secret.current_version,
        deleted: true,
        unlinked_count,
    })
}

fn validate_deletion_usages(
    usages: &[locket_store::SharedSecretUsageRecord],
    secret_name: &str,
    unlink_all: bool,
    expected_link_ids: Option<&[String]>,
    confirmation: Option<&str>,
) -> Result<(), MutationError> {
    if let Some(expected) = expected_link_ids {
        let actual: BTreeSet<_> = usages.iter().map(|usage| &usage.link_id).collect();
        if actual.len() != expected.len() || !expected.iter().collect::<BTreeSet<_>>().eq(&actual) {
            return Err(locket_store::StoreError::LinkSetChanged.into());
        }
    }
    if !usages.is_empty() {
        if !unlink_all {
            return Err(failure(
                "LinkedSecretInUse",
                "this Global Vault secret is linked by active projects; confirm unlinking all usages before deleting",
            ));
        }
        let dangerous_profiles: BTreeSet<&str> = usages
            .iter()
            .filter(|usage| usage.profile_dangerous)
            .map(|usage| usage.profile_name.as_str())
            .collect();
        if !dangerous_profiles.is_empty() {
            let expected = if dangerous_profiles.len() == 1 {
                *dangerous_profiles.iter().next().unwrap_or(&secret_name)
            } else {
                secret_name
            };
            if confirmation != Some(expected) {
                return Err(failure(
                    "ConfirmationFailed",
                    "type the dangerous profile or secret name to confirm unlinking all linked usages",
                ));
            }
        }
    }
    Ok(())
}

fn consumer_audit_keys<'a>(
    store: &Store,
    usages: &'a [locket_store::SharedSecretUsageRecord],
    cache: &UnlockCache,
    identity: &StoreFileIdentity,
    now: i128,
) -> Result<BTreeMap<&'a str, zeroize::Zeroizing<KeyBytes>>, MutationError> {
    let consumers: BTreeMap<_, _> = usages
        .iter()
        .map(|usage| (usage.project_id.as_str(), usage.project_name.as_str()))
        .collect();
    let mut unlocked = Vec::new();
    let mut locked = BTreeSet::new();
    for (project_id, project_name) in consumers {
        if let Some(entry) = cache
            .lookup(project_id, now)
            .filter(|entry| entry.store_identity.as_ref() == Some(identity))
        {
            unlocked.push((project_id, entry));
        } else {
            locked.insert(project_name);
        }
    }
    if !locked.is_empty() {
        return Err(MutationError {
            code: "UnlockRequired",
            message: format!(
                "Unlock the linked project vaults ({}) before deleting the secret.",
                locked.into_iter().collect::<Vec<_>>().join(", "),
            )
            .into(),
        });
    }
    unlocked
        .into_iter()
        .map(|(project_id, entry)| {
            let master = master_key_array(entry.key_bytes()).map_err(|_| storage())?;
            let key =
                unwrap_audit_key_with_master(store, project_id, &master).map_err(|_| storage())?;
            Ok((project_id, key))
        })
        .collect()
}

fn validated_name(input: String) -> Result<SecretName, MutationError> {
    SecretName::new(input).map_err(|_| failure("InvalidSecretName", "invalid secret name"))
}

fn validate_source(source: &str) -> Result<(), MutationError> {
    if !matches!(source, "machine-local" | "user-local" | "team-managed") {
        return Err(failure("InvalidReference", "invalid secret source"));
    }
    Ok(())
}

fn generate_link_id() -> Result<String, MutationError> {
    let bytes = locket_crypto::random_bytes::<16>().map_err(|_| storage())?;
    let mut hex = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(format!("lk_link_{hex}"))
}

fn link_secret(
    store: &mut Store,
    scope: &MutationScope,
    request: LinkSecret,
    master: &KeyBytes,
    timestamp: i64,
) -> Result<LinkSecretResponse, MutationError> {
    if is_shared_project_id(&scope.project_id) {
        return Err(failure(
            "InvalidReference",
            "cannot create a shared link inside the Global Vault",
        ));
    }
    let profile = context(store, scope)?.profile;
    confirm_dangerous_profile(
        &profile,
        request.confirmation.as_deref(),
        "type the profile name to confirm linking a Global Vault secret",
    )?;
    let local_name = validated_name(request.local_name)?;
    let target_name = validated_name(request.target_secret_name)?;
    let target_project = store
        .list_projects()?
        .into_iter()
        .filter(|project| is_shared_project_id(&project.id))
        .min_by_key(|project| project.name != "@shared")
        .ok_or_else(|| {
            failure("SharedVaultNotInitialized", "set up the Global Vault before linking secrets")
        })?;
    let target_profile = store
        .get_profile_by_name(&target_project.id, "default")?
        .ok_or_else(|| failure("ProfileNotFound", "the Global Vault default profile is missing"))?;
    let target_secret = store
        .get_active_secret(
            &target_project.id,
            &target_profile.id,
            target_name.as_str(),
            USER_LOCAL,
        )?
        .ok_or_else(secret_not_found)?;
    let link = SecretLinkRecord {
        id: generate_link_id()?,
        project_id: scope.project_id.clone(),
        profile_id: profile.id.clone(),
        local_name: local_name.as_str().to_owned(),
        target_project_id: target_project.id.clone(),
        target_profile_id: target_profile.id.clone(),
        target_secret_id: target_secret.id.clone(),
        created_at: timestamp,
        updated_at: timestamp,
    };
    let key =
        unwrap_audit_key_with_master(store, &scope.project_id, master).map_err(|_| storage())?;
    let metadata = json!({
        "schema_version": 1,
        "action": "SECRET_LINK",
        "status": "SUCCESS",
        "secret_name": local_name.as_str(),
        "profile_id": profile.id,
        "target_project_id": target_project.id,
        "target_profile_id": target_profile.id,
        "target_secret_id": target_secret.id,
        "target_secret_name": target_secret.name,
    });
    let audit = AuditWrite {
        project_id: &scope.project_id,
        profile_id: Some(&profile.id),
        action: "SECRET_LINK",
        status: "SUCCESS",
        secret_name: Some(local_name.as_str()),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    let persisted_link_id = store.upsert_secret_link_with_audit(
        &link,
        Some(AuditContext { key: key.as_ref(), write: &audit }),
    )?;
    Ok(LinkSecretResponse {
        link_id: persisted_link_id,
        local_name: local_name.into_string(),
        target_project_id: target_project.id,
        target_secret_id: target_secret.id,
        target_secret_name: target_secret.name,
    })
}

fn unlink_secret(
    store: &mut Store,
    scope: &MutationScope,
    request: UnlinkSecret,
    master: &KeyBytes,
    timestamp: i64,
) -> Result<UnlinkSecretResponse, MutationError> {
    let profile = context(store, scope)?.profile;
    confirm_dangerous_profile(
        &profile,
        request.confirmation.as_deref(),
        "type the profile name to confirm unlinking this secret",
    )?;
    let local_name = validated_name(request.local_name)?;
    let Some(existing) =
        store.get_secret_link(&scope.project_id, &profile.id, local_name.as_str())?
    else {
        return Ok(UnlinkSecretResponse { local_name: local_name.into_string(), unlinked: false });
    };
    let key =
        unwrap_audit_key_with_master(store, &scope.project_id, master).map_err(|_| storage())?;
    let metadata = json!({
        "schema_version": 1,
        "action": "SECRET_UNLINK",
        "status": "SUCCESS",
        "secret_name": local_name.as_str(),
        "profile_id": profile.id,
        "target_project_id": existing.target_project_id,
        "target_profile_id": existing.target_profile_id,
        "target_secret_id": existing.target_secret_id,
    });
    let audit = AuditWrite {
        project_id: &scope.project_id,
        profile_id: Some(&profile.id),
        action: "SECRET_UNLINK",
        status: "SUCCESS",
        secret_name: Some(local_name.as_str()),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    store.delete_secret_link_with_audit(
        &scope.project_id,
        &profile.id,
        local_name.as_str(),
        Some(AuditContext { key: key.as_ref(), write: &audit }),
    )?;
    Ok(UnlinkSecretResponse { local_name: local_name.into_string(), unlinked: true })
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
    require_unexpired_secret(store, &secret.id, timestamp)?;
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

#[allow(clippy::too_many_lines)]
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
            failure(
                "SharedVaultNotInitialized",
                "set up the Global Vault before copying the secret",
            )
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
    let target_name = match request.target_name {
        Some(target_name) => validated_name(target_name)?,
        None => name.clone(),
    };
    let source = select_copy_source(
        store,
        &source_profile,
        name.as_str(),
        request.source.as_deref(),
        timestamp,
    )?;
    let existing = store.get_secret_by_source(
        &target.id,
        &target_profile.id,
        target_name.as_str(),
        USER_LOCAL,
    )?;
    if existing.as_ref().is_some_and(|existing| existing.state == "deleted") {
        return Err(failure("SecretDeleted", "the Global Vault secret source is deleted"));
    }
    if existing.as_ref().is_some_and(|existing| existing.id == source.id) {
        return Err(failure(
            "InvalidReference",
            "the secret is already in the target profile and source",
        ));
    }
    let target_master = master_key_array(target_entry.key_bytes()).map_err(|_| storage())?;
    let value = crate::reveal::decrypt_secret(
        store,
        &source.project_id,
        &source.profile_id,
        &source,
        source.current_version,
        master,
    )
    .map_err(|_| storage())?;
    let reuse_existing = if let Some(existing_secret) = existing.as_ref() {
        if request.replace_with_link || request.consolidate_duplicates {
            require_unexpired_secret(store, &existing_secret.id, timestamp)?;
        }
        let same_value = crate::reveal::decrypt_secret(
            store,
            &existing_secret.project_id,
            &existing_secret.profile_id,
            existing_secret,
            existing_secret.current_version,
            &target_master,
        )
        .is_ok_and(|existing_value| existing_value.as_str() == value.as_str());
        if same_value && request.replace_with_link {
            true
        } else if !request.overwrite {
            return Err(failure(
                "SecretAlreadyExists",
                "a user-local secret with this name already exists in the Global Vault",
            ));
        } else {
            false
        }
    } else {
        false
    };
    promote_secret(
        store,
        &source,
        &value,
        master,
        &target_profile,
        &target_master,
        target_name.as_str(),
        existing.as_ref(),
        reuse_existing,
        request.replace_with_link,
        request.consolidate_duplicates,
        cache,
        identity,
        timestamp,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn promote_secret(
    store: &mut Store,
    source: &SecretRecord,
    value: &str,
    master: &KeyBytes,
    target: &ProfileRecord,
    target_master: &KeyBytes,
    target_name: &str,
    existing: Option<&SecretRecord>,
    reuse_existing: bool,
    replace_with_link: bool,
    consolidate_duplicates: bool,
    cache: &UnlockCache,
    identity: &StoreFileIdentity,
    timestamp: i64,
) -> Result<CopySecretToSharedResponse, MutationError> {
    let (target_secret_id, version, action) = if reuse_existing {
        let existing_secret = existing.ok_or_else(storage)?;
        (existing_secret.id.clone(), existing_secret.current_version, "reuse")
    } else {
        let version =
            existing.map_or(Some(1), |record| record.current_version.checked_add(1)).ok_or_else(
                || failure("SecretVersionOverflow", "the target secret cannot be rotated again"),
            )?;
        let secret_id = match existing {
            Some(record) => record.id.clone(),
            None => SecretId::generate().map_err(|_| storage())?.into_string(),
        };
        let (encrypted, fingerprint) = encrypt_secret_version(
            store,
            &target.project_id,
            &target.id,
            &secret_id,
            target_name,
            version,
            value,
            target_master,
        )
        .map_err(|_| storage())?;
        let new_secret = SecretRecord {
            id: secret_id.clone(),
            project_id: target.project_id.clone(),
            profile_id: target.id.clone(),
            name: target_name.to_owned(),
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
        let fingerprint = SecretFingerprintRecord {
            secret_id: secret_id.clone(),
            version,
            fingerprint,
            created_at: timestamp,
        };
        let (copy_target, action) =
            existing.map_or((SecretCopyTarget::Create(&new_secret), "create"), |secret| {
                (
                    SecretCopyTarget::Rotate {
                        secret,
                        deprecation: VersionDeprecation {
                            deprecated_at: timestamp,
                            grace_until: None,
                        },
                    },
                    "rotate",
                )
            });
        store.copy_secret_with_audit(copy_target, &new_version, &blob, &fingerprint, None)?;
        (secret_id, version, action)
    };

    let target_key = unwrap_audit_key_with_master(store, &target.project_id, target_master)
        .map_err(|_| storage())?;
    let source_key =
        unwrap_audit_key_with_master(store, &source.project_id, master).map_err(|_| storage())?;
    SecretTransferAudit {
        action: if replace_with_link { "SECRET_PROMOTE" } else { "SECRET_COPY" },
        operation: action,
        from_project_id: &source.project_id,
        from_profile_id: &source.profile_id,
        from_secret: Some(source),
        target_profile: target,
        target_name,
        prior_target_version: existing.map(|record| record.current_version),
        target_version: version,
        timestamp,
    }
    .append(store, source_key.as_ref(), target_key.as_ref())?;

    let shared_fp_key = unwrap_profile_key_with_master(
        store,
        &target.project_id,
        &target.id,
        target_master,
        KeyPurpose::ProfileFingerprint,
    )
    .ok();
    let dedup_tag =
        shared_fp_key.as_ref().and_then(|fp_key| local_dedup_tag_v1(fp_key, value).ok());
    if let Some(tag) = dedup_tag.as_ref() {
        let _ = store.upsert_local_value_fingerprint(&target_secret_id, version, tag, timestamp);
    }

    let linked = if replace_with_link && source.project_id != target.project_id {
        let link = SecretLinkRecord {
            id: generate_link_id()?,
            project_id: source.project_id.clone(),
            profile_id: source.profile_id.clone(),
            local_name: source.name.clone(),
            target_project_id: target.project_id.clone(),
            target_profile_id: target.id.clone(),
            target_secret_id: target_secret_id.clone(),
            created_at: timestamp,
            updated_at: timestamp,
        };
        let source_key = unwrap_audit_key_with_master(store, &source.project_id, master)
            .map_err(|_| storage())?;
        let link_metadata = json!({
            "schema_version": 1,
            "action": "SECRET_LINK",
            "status": "SUCCESS",
            "secret_name": source.name,
            "profile_id": source.profile_id,
            "target_project_id": target.project_id,
            "target_profile_id": target.id,
            "target_secret_id": target_secret_id,
            "target_secret_name": target_name,
        });
        let link_audit = AuditWrite {
            project_id: &source.project_id,
            profile_id: Some(&source.profile_id),
            action: "SECRET_LINK",
            status: "SUCCESS",
            secret_name: Some(&source.name),
            command: None,
            metadata_json: &link_metadata,
            timestamp,
        };
        store.upsert_secret_link_with_audit(
            &link,
            Some(AuditContext { key: source_key.as_ref(), write: &link_audit }),
        )?;
        if source.source == USER_LOCAL {
            let delete_metadata = secret_audit_metadata(
                "DELETE",
                &source.name,
                &source.profile_id,
                &source.source,
                Some(source.current_version),
            );
            let delete_audit = AuditWrite {
                project_id: &source.project_id,
                profile_id: Some(&source.profile_id),
                action: "DELETE",
                status: "SUCCESS",
                secret_name: Some(&source.name),
                command: None,
                metadata_json: &delete_metadata,
                timestamp,
            };
            store.tombstone_current_secret_with_audit(
                source,
                timestamp,
                AuditContext { key: source_key.as_ref(), write: &delete_audit },
            )?;
        }
        true
    } else {
        false
    };

    let mut consolidated_count = 0_u32;
    let mut skipped_locked_count = 0_u32;
    if consolidate_duplicates && let Some(tag) = dedup_tag.as_ref() {
        let matches = store.find_active_secrets_by_dedup_tag(tag)?;
        for member in matches {
            if member.is_shared
                || member.secret_id == source.id
                || member.secret_id == target_secret_id
                || member.source != USER_LOCAL
            {
                continue;
            }
            if member.profile_dangerous {
                skipped_locked_count += 1;
                continue;
            }
            let Some(other_entry) = cache.lookup(&member.project_id, i128::from(timestamp)) else {
                skipped_locked_count += 1;
                continue;
            };
            if other_entry.store_identity.as_ref().is_some_and(|pin| pin != identity) {
                skipped_locked_count += 1;
                continue;
            }
            let Ok(other_master) = master_key_array(other_entry.key_bytes()) else {
                skipped_locked_count += 1;
                continue;
            };
            let Ok(other_audit_key) =
                unwrap_audit_key_with_master(store, &member.project_id, &other_master)
            else {
                skipped_locked_count += 1;
                continue;
            };
            let Some(other_record) = store.get_secret_by_id(&member.secret_id)? else {
                continue;
            };
            if other_record.state != "active" {
                continue;
            }
            // Replacing a local value with a link would drop its lifecycle policy.
            if store.get_secret_expiry_policy(&other_record.id)?.is_some_and(|policy| {
                policy.expires_at.is_some() || policy.rotate_after_days.is_some()
            }) {
                continue;
            }
            let link = SecretLinkRecord {
                id: generate_link_id()?,
                project_id: member.project_id.clone(),
                profile_id: member.profile_id.clone(),
                local_name: member.name.clone(),
                target_project_id: target.project_id.clone(),
                target_profile_id: target.id.clone(),
                target_secret_id: target_secret_id.clone(),
                created_at: timestamp,
                updated_at: timestamp,
            };
            let link_metadata = json!({
                "schema_version": 1,
                "action": "SECRET_LINK",
                "status": "SUCCESS",
                "secret_name": member.name,
                "profile_id": member.profile_id,
                "target_project_id": target.project_id,
                "target_profile_id": target.id,
                "target_secret_id": target_secret_id,
                "target_secret_name": target_name,
            });
            let link_audit = AuditWrite {
                project_id: &member.project_id,
                profile_id: Some(&member.profile_id),
                action: "SECRET_LINK",
                status: "SUCCESS",
                secret_name: Some(&member.name),
                command: None,
                metadata_json: &link_metadata,
                timestamp,
            };
            store.upsert_secret_link_with_audit(
                &link,
                Some(AuditContext { key: other_audit_key.as_ref(), write: &link_audit }),
            )?;
            let delete_metadata = secret_audit_metadata(
                "DELETE",
                &other_record.name,
                &other_record.profile_id,
                &other_record.source,
                Some(other_record.current_version),
            );
            let delete_audit = AuditWrite {
                project_id: &member.project_id,
                profile_id: Some(&member.profile_id),
                action: "DELETE",
                status: "SUCCESS",
                secret_name: Some(&other_record.name),
                command: None,
                metadata_json: &delete_metadata,
                timestamp,
            };
            store.tombstone_current_secret_with_audit(
                &other_record,
                timestamp,
                AuditContext { key: other_audit_key.as_ref(), write: &delete_audit },
            )?;
            consolidated_count += 1;
        }
    }

    Ok(CopySecretToSharedResponse {
        target_project_id: target.project_id.clone(),
        target_profile_id: target.id.clone(),
        secret_name: target_name.to_owned(),
        version,
        action: action.into(),
        linked,
        consolidated_count,
        skipped_locked_count,
    })
}
