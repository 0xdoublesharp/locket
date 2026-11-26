//! Agent-owned dotenv imports and durable policy edits. Results contain metadata only.

#[path = "desktop_crud.rs"]
mod desktop_crud;
pub use desktop_crud::handle_desktop_crud;
pub use desktop_crud::{
    CopySecretToSharedResponse, CreateProfileResponse, DeleteSecretResponse, LinkSecretResponse,
    UnlinkSecretResponse,
};

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use locket_core::{CommandSpec, PolicyDocument, ProjectConfig, SecretId, SecretName};
use locket_crypto::{KeyBytes, local_dedup_tag_v1};
use locket_platform::PolicyFileDocument;
use locket_store::{AuditContext, AuditWrite, SecretLinkRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::grant::{GrantAction, GrantBinding, GrantValidation};
use crate::keys::{master_key_array, unwrap_audit_key_with_master};
use crate::policies::CommandPolicySnapshot;
use crate::set_secret::{SetSecretOperation, set_secret_in_store};

const MAX_ENV_BYTES: u64 = 1024 * 1024;
const MAX_POLICY_BYTES: usize = 65_536;
static MUTATION_LOCK: Mutex<()> = Mutex::new(());

/// Exact vault, trusted folder, profile and process-bound grant for a mutation.
#[derive(Clone, Deserialize, Serialize)]
pub struct MutationScope {
    /// User-scoped store selected by the native shell.
    pub store_path: PathBuf,
    /// Selected trusted project folder, empty for a shared vault.
    pub project_root: PathBuf,
    /// Registered project id.
    pub project_id: String,
    /// Actual active profile id, never its display name.
    pub profile_id: String,
    /// Live grant for this operation.
    pub grant_id: Option<String>,
    /// Native caller process binding.
    pub binding: Option<GrantBinding>,
}

/// Request to import a selected env file without exporting its contents.
#[derive(Clone, Deserialize, Serialize)]
pub struct ImportDotenvRequest {
    /// Authorized scope.
    #[serde(flatten)]
    pub scope: MutationScope,
    /// Env file path. Relative paths require a trusted project folder.
    pub env_path: PathBuf,
    /// Rotate existing active values instead of skipping.
    pub overwrite: bool,
    /// Treat expansion expressions as literal data.
    pub literal: bool,
    /// Actual profile name typed for dangerous overwrite.
    pub confirmation: Option<String>,
    /// Exact Global Vault profile name for dangerous promotions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_confirmation: Option<String>,
    /// Live `CopySecretToShared` grant scoped to the Global Vault default profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_grant_id: Option<String>,
    /// Inspect keys and detect duplicate values without writing to the store.
    #[serde(default)]
    pub dry_run: bool,
    /// Map of `local_env_name -> shared_secret_name` to link instead of duplicating.
    #[serde(default)]
    pub link_to_shared: BTreeMap<String, String>,
    /// Map of `local_env_name -> target_shared_name` to store once in `@shared` and link.
    #[serde(default)]
    pub promote_to_shared: BTreeMap<String, String>,
}

/// Safe parser diagnostic.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImportDiagnostic {
    /// One-based input line.
    pub line: usize,
    /// Fixed text that never includes input values.
    pub message: String,
}

/// Metadata-only duplicate match found while inspecting an env file for import.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportDuplicateMatch {
    /// Variable name in the env file being imported.
    pub local_name: String,
    /// `"shared"` when the exact value already exists in `@shared`, otherwise `"project"`.
    pub match_kind: String,
    /// Matching project identifier.
    pub matched_project_id: String,
    /// Matching project display name.
    pub matched_project_name: String,
    /// Matching profile name.
    pub matched_profile_name: String,
    /// Matching secret identifier.
    pub matched_secret_id: String,
    /// Matching secret name in the matched project.
    pub matched_secret_name: String,
    /// Whether the matched secret is in the Global Vault (`@shared`).
    pub is_shared: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

/// Metadata-only import outcome.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImportDotenvResponse {
    /// Number of new names imported.
    pub imported: u32,
    /// Number of current values rotated.
    pub overwritten: u32,
    /// Number of existing values retained.
    pub skipped: u32,
    /// Number of keys linked directly to an existing Global Vault secret.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub linked: u32,
    /// Number of keys stored once in the Global Vault and linked back to the project.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub promoted: u32,
    /// Duplicate value matches detected across `@shared` and other local projects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate_matches: Vec<ImportDuplicateMatch>,
    /// Fixed parser warnings such as duplicate names.
    pub diagnostics: Vec<ImportDiagnostic>,
    /// The source file is always retained by desktop import.
    pub original_preserved: bool,
    /// Safe warning for metadata maintenance after the encrypted transaction committed.
    pub maintenance_warning: Option<String>,
}

/// One durable editor mutation. Existing UI request shape is preserved.
#[derive(Clone, Deserialize, Serialize)]
pub struct ApplyPolicyRequest {
    /// Authorized scope.
    #[serde(flatten)]
    pub scope: MutationScope,
    /// One of create, edit, delete.
    pub mode: String,
    /// Previous command name, empty when creating.
    pub original_name: String,
    /// Editor fields. Unrepresented current fields are preserved.
    pub policy: CommandPolicySnapshot,
    /// Actual dangerous profile name typed by the user.
    pub confirmation: Option<String>,
}

/// Metadata-only durable policy result.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ApplyPolicyResponse {
    /// Command affected.
    pub policy_name: String,
    /// Applied editor operation.
    pub operation: String,
}

/// Typed mutation failure with a metadata-only message.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct MutationError {
    /// Protocol error code.
    pub code: &'static str,
    /// Safe message for user display.
    pub message: std::borrow::Cow<'static, str>,
}

const fn failure(code: &'static str, message: &'static str) -> MutationError {
    MutationError { code, message: std::borrow::Cow::Borrowed(message) }
}
const fn metadata() -> MutationError {
    failure("MetadataInvalid", "project metadata is invalid or changed; refresh and retry")
}
const fn storage() -> MutationError {
    failure("CorruptDb", "mutation could not be committed")
}
impl From<locket_store::StoreError> for MutationError {
    fn from(error: locket_store::StoreError) -> Self {
        match error {
            locket_store::StoreError::LinkSetChanged => failure(
                "LinkSetChanged",
                "Linked projects changed while you were reviewing them. Refresh and confirm again.",
            ),
            _ => storage(),
        }
    }
}

#[derive(PartialEq, Eq)]
struct Context {
    root: Option<PathBuf>,
    profile: locket_store::ProfileRecord,
}
pub(super) fn is_shared_project_id(project_id: &str) -> bool {
    project_id.starts_with("lk_proj_shared_")
}
fn context(store: &Store, scope: &MutationScope) -> Result<Context, MutationError> {
    if is_shared_project_id(&scope.project_id) {
        if store.get_project(&scope.project_id)?.is_none() {
            return Err(metadata());
        }
        let profile = store
            .list_profiles(&scope.project_id)?
            .into_iter()
            .find(|profile| profile.id == scope.profile_id)
            .ok_or_else(|| {
                failure("ProfileNotFound", "active profile changed; refresh before retrying")
            })?;
        return Ok(Context { root: None, profile });
    }
    let root = scope.project_root.canonicalize().map_err(|_| metadata())?;
    if !root.is_dir() {
        return Err(metadata());
    }
    let path = root.join("locket.toml");
    if !std::fs::symlink_metadata(&path).map_err(|_| metadata())?.file_type().is_file() {
        return Err(metadata());
    }
    let config: ProjectConfig =
        toml::from_str(&std::fs::read_to_string(path).map_err(|_| metadata())?)
            .map_err(|_| metadata())?;
    if config.schema_version != locket_core::PROJECT_CONFIG_SCHEMA_VERSION
        || config.project_id.as_str() != scope.project_id
    {
        return Err(metadata());
    }
    let hash: [u8; 32] = Sha256::digest(root.to_string_lossy().as_bytes()).into();
    if !store.project_root_is_trusted(&scope.project_id, &hash)? {
        return Err(failure("ProjectNotTrusted", "selected project folder is not trusted"));
    }
    let profile = store
        .get_profile_by_name(&scope.project_id, config.default_profile.as_str())?
        .ok_or_else(metadata)?;
    if profile.id != scope.profile_id {
        return Err(failure("ProfileNotFound", "active profile changed; refresh before retrying"));
    }
    Ok(Context { root: Some(root), profile })
}

fn confirm_dangerous_profile(
    profile: &locket_store::ProfileRecord,
    confirmation: Option<&str>,
    message: &'static str,
) -> Result<(), MutationError> {
    if profile.dangerous && confirmation != Some(profile.name.as_str()) {
        return Err(failure("ConfirmationFailed", message));
    }
    Ok(())
}

async fn authorize(
    scope: &MutationScope,
    action: GrantAction,
    state: &crate::AgentSocketState,
    now: i128,
) -> Result<(tokio::sync::OwnedMutexGuard<crate::UnlockCache>, Zeroizing<KeyBytes>), MutationError>
{
    let grant = scope
        .grant_id
        .as_deref()
        .ok_or_else(|| failure("GrantRequired", "a live grant is required"))?;
    if state.grants.lock().await.validate(
        grant,
        &scope.project_id,
        &scope.profile_id,
        action,
        now,
        scope.binding.as_ref(),
    ) != GrantValidation::Valid
    {
        return Err(failure("GrantRequired", "a matching live grant is required"));
    }
    let cache = state.unlock_cache.clone().lock_owned().await;
    let entry = cache
        .lookup(&scope.project_id, now)
        .ok_or_else(|| failure("UnlockRequired", "unlock the selected project before retrying"))?;
    let master = master_key_array(entry.key_bytes()).map_err(|_| storage())?;
    Ok((cache, master))
}

fn response<T: Serialize>(
    request: &RequestEnvelope,
    result: Result<T, MutationError>,
) -> ResponseEnvelope {
    match result {
        Ok(value) => ResponseEnvelope::Success(SuccessEnvelope::new(
            request.id.clone(),
            serde_json::to_value(value).unwrap_or(Value::Null),
        )),
        Err(error) => ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            error.code,
            error.message,
            false,
        )),
    }
}

struct ImportPromotionTarget {
    profile: locket_store::ProfileRecord,
    master: Zeroizing<KeyBytes>,
}

fn import_promotion_profile(store: &Store) -> Result<locket_store::ProfileRecord, MutationError> {
    let project = store
        .list_projects()?
        .into_iter()
        .filter(|project| is_shared_project_id(&project.id))
        .min_by_key(|project| project.name != "@shared")
        .ok_or_else(|| {
            failure("ProjectNotFound", "set up the Global Vault before promoting secrets")
        })?;
    store
        .get_profile_by_name(&project.id, "default")?
        .ok_or_else(|| failure("ProfileNotFound", "the Global Vault default profile is missing"))
}

async fn authorize_import_promotion(
    state: &crate::AgentSocketState,
    request: &ImportDotenvRequest,
    profile: locket_store::ProfileRecord,
    identity: &crate::keys::StoreFileIdentity,
    cache: &crate::UnlockCache,
    now: i128,
) -> Result<ImportPromotionTarget, MutationError> {
    let required =
        || failure("GrantRequired", "a matching Global Vault promotion grant is required");
    let grant_id = request.target_grant_id.as_deref().ok_or_else(required)?;
    {
        let mut grants = state.grants.lock().await;
        if grants.validate(
            grant_id,
            &profile.project_id,
            &profile.id,
            GrantAction::CopySecretToShared,
            now,
            request.scope.binding.as_ref(),
        ) != GrantValidation::Valid
        {
            return Err(required());
        }
        grants.revoke(grant_id);
    }
    if !cache
        .lookup(&request.scope.project_id, now)
        .is_some_and(|entry| entry.store_identity.as_ref() == Some(identity))
    {
        return Err(failure("UnlockRequired", "unlock the source vault before promoting secrets"));
    }
    let target_entry = cache
        .lookup(&profile.project_id, now)
        .filter(|entry| entry.store_identity.as_ref() == Some(identity))
        .ok_or_else(|| {
            failure("UnlockRequired", "unlock the Global Vault before promoting secrets")
        })?;
    let master = master_key_array(target_entry.key_bytes()).map_err(|_| storage())?;
    Ok(ImportPromotionTarget { profile, master })
}

/// Handle an import using only a matching live grant and project unlock cache.
pub async fn handle_import_dotenv(
    request: &RequestEnvelope,
    state: &crate::AgentSocketState,
    now: i128,
) -> ResponseEnvelope {
    let result = async {
        let typed: ImportDotenvRequest =
            serde_json::from_value(request.payload.clone()).map_err(|_| metadata())?;
        let (cache_guard, master) =
            authorize(&typed.scope, GrantAction::ImportDotenv, state, now).await?;
        let pin = cache_guard
            .lookup(&typed.scope.project_id, now)
            .and_then(|entry| entry.store_identity.as_ref());
        let (store, store_identity) = state
            .open_store(&typed.scope.store_path, pin, false)
            .map_err(|_| failure("AccessDenied", "could not verify mutation store"))?;
        let promotion = if !typed.dry_run && !typed.promote_to_shared.is_empty() {
            if is_shared_project_id(&typed.scope.project_id) {
                return Err(failure("InvalidReference", "promote secrets from a project vault"));
            }
            let profile = import_promotion_profile(&store)?;
            Some(
                authorize_import_promotion(
                    state,
                    &typed,
                    profile,
                    &store_identity,
                    &cache_guard,
                    now,
                )
                .await?,
            )
        } else {
            None
        };
        import_dotenv_in_store(
            store,
            &typed,
            &master,
            Some((&cache_guard, &store_identity)),
            promotion.as_ref(),
            i64::try_from(now).map_err(|_| storage())?,
        )
    }
    .await;
    response(request, result)
}

/// Handle a durable editor mutation and publish its committed policy metadata.
pub async fn handle_apply_policy(
    request: &RequestEnvelope,
    state: &crate::AgentSocketState,
    now: i128,
) -> ResponseEnvelope {
    let result = async {
        let typed: ApplyPolicyRequest =
            serde_json::from_value(request.payload.clone()).map_err(|_| metadata())?;
        let (cache_guard, master) =
            authorize(&typed.scope, GrantAction::ApplyPolicy, state, now).await?;
        let pin = cache_guard
            .lookup(&typed.scope.project_id, now)
            .and_then(|entry| entry.store_identity.as_ref());
        let (store, _) = state
            .open_store(&typed.scope.store_path, pin, false)
            .map_err(|_| failure("AccessDenied", "could not verify mutation store"))?;
        // Serialize snapshot publication with other policy publishers. Never publish before the durable commit.
        let mut snapshots = state.command_policies.lock().await;
        let (result, fresh) = apply_policy_in_store(
            store,
            &typed,
            &master,
            i64::try_from(now).map_err(|_| storage())?,
        )?;
        snapshots.retain(|policy| policy.project_id != typed.scope.project_id);
        snapshots.extend(fresh);
        drop(snapshots);
        Ok(result)
    }
    .await;
    response(request, result)
}

/// Import a parsed batch with an already-authorized master key. The caller owns consent and key access.
///
/// # Errors
/// Rejects invalid input, scope, dangerous overwrite, encryption and audit failures without partial DB writes.
pub fn import_dotenv_with_master(
    request: &ImportDotenvRequest,
    master: &KeyBytes,
    timestamp: i64,
) -> Result<ImportDotenvResponse, MutationError> {
    let (store, _) = crate::keys::open_verified_store(&request.scope.store_path, None)
        .map_err(locket_store::StoreError::from)?;
    import_dotenv_in_store(store, request, master, None, None, timestamp)
}

#[allow(clippy::too_many_lines)]
fn import_dotenv_in_store(
    mut store: Store,
    request: &ImportDotenvRequest,
    master: &KeyBytes,
    shared_ctx: Option<(&crate::UnlockCache, &crate::keys::StoreFileIdentity)>,
    promotion: Option<&ImportPromotionTarget>,
    timestamp: i64,
) -> Result<ImportDotenvResponse, MutationError> {
    let _guard = MUTATION_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let verified = context(&store, &request.scope)?;
    if !request.dry_run
        && (request.overwrite
            || !request.link_to_shared.is_empty()
            || !request.promote_to_shared.is_empty())
    {
        confirm_dangerous_profile(
            &verified.profile,
            request.confirmation.as_deref(),
            "type the dangerous profile name to confirm overwrite",
        )?;
    }
    let path = if request.env_path.is_absolute() {
        request.env_path.clone()
    } else if let Some(root) = verified.root.as_deref() {
        root.join(&request.env_path)
    } else {
        return Err(failure(
            "MetadataInvalid",
            "choose an absolute env file path when importing into a shared vault",
        ));
    };
    let mut document = read_dotenv(&path, request.literal)?;
    let shared_fp = shared_ctx.and_then(|(cache, identity)| {
        crate::shared_links::shared_fingerprint_key_from_cache(
            &store,
            cache,
            i128::from(timestamp),
            identity,
        )
    });
    let mut result = ImportDotenvResponse {
        imported: 0,
        overwritten: 0,
        skipped: 0,
        linked: 0,
        promoted: 0,
        duplicate_matches: Vec::new(),
        diagnostics: document
            .warnings
            .iter()
            .map(|warning| ImportDiagnostic { line: warning.line, message: warning.message.into() })
            .collect(),
        original_preserved: true,
        maintenance_warning: None,
    };

    if let Some((_, _, fp_key)) = shared_fp.as_ref() {
        for entry in &document.entries {
            if let Ok(tag) = local_dedup_tag_v1(fp_key, &entry.value)
                && let Ok(matches) = store.find_active_secrets_by_dedup_tag(&tag)
            {
                for matched in matches {
                    if matched.project_id == request.scope.project_id
                        && matched.profile_id == request.scope.profile_id
                        && matched.name == entry.key
                    {
                        continue;
                    }
                    result.duplicate_matches.push(ImportDuplicateMatch {
                        local_name: entry.key.clone(),
                        match_kind: if matched.is_shared {
                            "shared".into()
                        } else {
                            "project".into()
                        },
                        matched_project_id: matched.project_id,
                        matched_project_name: matched.project_name,
                        matched_profile_name: matched.profile_name,
                        matched_secret_id: matched.secret_id,
                        matched_secret_name: matched.name,
                        is_shared: matched.is_shared,
                    });
                }
            }
        }
    }

    if request.dry_run {
        for entry in &document.entries {
            let existing = store.get_secret_by_source(
                &request.scope.project_id,
                &request.scope.profile_id,
                &entry.key,
                "user-local",
            )?;
            if let Some(existing) = existing {
                if existing.state == "deleted" {
                    return Err(failure("SecretDeleted", "an imported name has a deleted source"));
                }
                if request.overwrite {
                    result.overwritten += 1;
                } else {
                    result.skipped += 1;
                }
            } else {
                result.imported += 1;
            }
        }
        for entry in &mut document.entries {
            zeroize::Zeroize::zeroize(&mut entry.value);
        }
        return Ok(result);
    }

    let write_result = store.with_atomic_write(|store| {
        if context(store, &request.scope)? != verified {
            return Err(metadata());
        }
        if !request.promote_to_shared.is_empty() {
            let promotion = promotion.ok_or_else(|| {
                failure("GrantRequired", "a matching Global Vault promotion grant is required")
            })?;
            let target_profile = import_promotion_profile(store)?;
            if target_profile != promotion.profile {
                return Err(metadata());
            }
            confirm_dangerous_profile(
                &target_profile,
                request.target_confirmation.as_deref().or(request.confirmation.as_deref()),
                "Type default to confirm promotion into the Global Vault.",
            )?;
        }
        for entry in &document.entries {
            let value = Zeroizing::new(entry.value.clone());

            if !is_shared_project_id(&request.scope.project_id)
                && let Some(target_shared_name) = request.link_to_shared.get(&entry.key)
            {
                let target_project = store
                    .list_projects()?
                    .into_iter()
                    .filter(|project| is_shared_project_id(&project.id))
                    .min_by_key(|project| project.name != "@shared")
                    .ok_or_else(|| {
                        failure("ProjectNotFound", "set up the Global Vault before linking secrets")
                    })?;
                let target_profile =
                    store.get_profile_by_name(&target_project.id, "default")?.ok_or_else(|| {
                        failure("ProfileNotFound", "the Global Vault default profile is missing")
                    })?;
                let target_secret = store
                    .get_active_secret(
                        &target_project.id,
                        &target_profile.id,
                        target_shared_name,
                        "user-local",
                    )?
                    .ok_or_else(|| {
                        failure("SecretNotFound", "target Global Vault secret not found")
                    })?;
                let link_id = format!(
                    "lk_link_{}",
                    SecretId::generate().map_err(|_| storage())?.into_string()
                );
                let link = SecretLinkRecord {
                    id: link_id,
                    project_id: request.scope.project_id.clone(),
                    profile_id: request.scope.profile_id.clone(),
                    local_name: entry.key.clone(),
                    target_project_id: target_project.id.clone(),
                    target_profile_id: target_profile.id.clone(),
                    target_secret_id: target_secret.id.clone(),
                    created_at: timestamp,
                    updated_at: timestamp,
                };
                let source_key =
                    unwrap_audit_key_with_master(store, &request.scope.project_id, master)
                        .map_err(|_| storage())?;
                let link_metadata = json!({
                    "schema_version": 1,
                    "action": "SECRET_LINK",
                    "status": "SUCCESS",
                    "secret_name": entry.key,
                    "profile_id": request.scope.profile_id,
                    "target_project_id": target_project.id,
                    "target_profile_id": target_profile.id,
                    "target_secret_id": target_secret.id,
                    "target_secret_name": target_secret.name,
                });
                let link_audit = AuditWrite {
                    project_id: &request.scope.project_id,
                    profile_id: Some(&request.scope.profile_id),
                    action: "SECRET_LINK",
                    status: "SUCCESS",
                    secret_name: Some(&entry.key),
                    command: None,
                    metadata_json: &link_metadata,
                    timestamp,
                };
                store.upsert_secret_link_with_audit(
                    &link,
                    Some(AuditContext { key: source_key.as_ref(), write: &link_audit }),
                )?;
                result.linked += 1;
                continue;
            }

            if let Some(promotion) = promotion
                && let Some(target_shared_name) = request.promote_to_shared.get(&entry.key)
            {
                let target_profile = &promotion.profile;
                let target_project_id = &target_profile.project_id;
                let target_master = &promotion.master;
                let target_name = SecretName::new(target_shared_name.clone()).map_err(|_| {
                    failure("InvalidSecretName", "invalid Global Vault secret name")
                })?;
                let existing_shared = store.get_secret_by_source(
                    target_project_id,
                    &target_profile.id,
                    target_name.as_str(),
                    "user-local",
                )?;
                if existing_shared.as_ref().is_some_and(|secret| secret.state == "deleted") {
                    return Err(failure(
                        "SecretDeleted",
                        "the Global Vault secret source is deleted",
                    ));
                }
                let prior_target_version =
                    existing_shared.as_ref().map(|secret| secret.current_version);
                let same_value = if let Some(existing) = &existing_shared {
                    crate::reveal::decrypt_secret(
                        store,
                        target_project_id,
                        &target_profile.id,
                        existing,
                        existing.current_version,
                        target_master,
                    )
                    .map_err(|_| storage())?
                    .as_str()
                        == value.as_str()
                } else {
                    false
                };
                let (target_secret_id, target_version, operation) = if let Some(existing) =
                    existing_shared.filter(|_| same_value)
                {
                    (existing.id, existing.current_version, "reuse")
                } else {
                    let rotate = prior_target_version.is_some();
                    if rotate && !request.overwrite {
                        return Err(failure(
                            "SecretAlreadyExists",
                            "a different value with this name already exists in the Global Vault",
                        ));
                    }
                    let op = SetSecretOperation {
                        project_id: target_project_id,
                        profile_id: &target_profile.id,
                        name: target_name.as_str(),
                        source: "user-local",
                        source_was_omitted: false,
                        value: &value,
                        rotate,
                        grace_until: None,
                        master_key: target_master.as_slice(),
                        timestamp: i128::from(timestamp),
                        imported: true,
                    };
                    let written = set_secret_in_store(store, &op, target_master, timestamp)
                        .map_err(|error| failure(error.error, error.message))?;
                    (written.secret_id, written.version, if rotate { "rotate" } else { "create" })
                };
                if let Some((_, _, fp_key)) = shared_fp.as_ref()
                    && let Ok(tag) = local_dedup_tag_v1(fp_key, &value)
                {
                    let _ = store.upsert_local_value_fingerprint(
                        &target_secret_id,
                        target_version,
                        &tag,
                        timestamp,
                    );
                }
                let link_id = format!(
                    "lk_link_{}",
                    SecretId::generate().map_err(|_| storage())?.into_string()
                );
                let link = SecretLinkRecord {
                    id: link_id,
                    project_id: request.scope.project_id.clone(),
                    profile_id: request.scope.profile_id.clone(),
                    local_name: entry.key.clone(),
                    target_project_id: target_project_id.clone(),
                    target_profile_id: target_profile.id.clone(),
                    target_secret_id: target_secret_id.clone(),
                    created_at: timestamp,
                    updated_at: timestamp,
                };
                let source_key =
                    unwrap_audit_key_with_master(store, &request.scope.project_id, master)
                        .map_err(|_| storage())?;
                let target_key =
                    unwrap_audit_key_with_master(store, target_project_id, target_master)
                        .map_err(|_| storage())?;
                locket_store::SecretTransferAudit {
                    action: "SECRET_PROMOTE",
                    operation,
                    from_project_id: &request.scope.project_id,
                    from_profile_id: &request.scope.profile_id,
                    from_secret: None,
                    target_profile,
                    target_name: target_name.as_str(),
                    prior_target_version,
                    target_version,
                    timestamp,
                }
                .append(store, source_key.as_ref(), target_key.as_ref())?;
                let link_metadata = json!({
                    "schema_version": 1,
                    "action": "SECRET_LINK",
                    "status": "SUCCESS",
                    "secret_name": entry.key,
                    "profile_id": request.scope.profile_id,
                    "target_project_id": target_project_id,
                    "target_profile_id": target_profile.id,
                    "target_secret_id": target_secret_id,
                    "target_secret_name": target_name.as_str(),
                });
                let link_audit = AuditWrite {
                    project_id: &request.scope.project_id,
                    profile_id: Some(&request.scope.profile_id),
                    action: "SECRET_LINK",
                    status: "SUCCESS",
                    secret_name: Some(&entry.key),
                    command: None,
                    metadata_json: &link_metadata,
                    timestamp,
                };
                store.upsert_secret_link_with_audit(
                    &link,
                    Some(AuditContext { key: source_key.as_ref(), write: &link_audit }),
                )?;
                result.promoted += 1;
                continue;
            }

            let existing = store.get_secret_by_source(
                &request.scope.project_id,
                &request.scope.profile_id,
                &entry.key,
                "user-local",
            )?;
            if let Some(existing) = &existing {
                if existing.state == "deleted" {
                    return Err(failure("SecretDeleted", "an imported name has a deleted source"));
                }
                if !request.overwrite {
                    result.skipped += 1;
                    continue;
                }
            }
            let operation = SetSecretOperation {
                project_id: &request.scope.project_id,
                profile_id: &request.scope.profile_id,
                name: &entry.key,
                source: "user-local",
                source_was_omitted: false,
                value: &value,
                rotate: existing.is_some(),
                grace_until: None,
                master_key: master,
                timestamp: i128::from(timestamp),
                imported: true,
            };
            let written = set_secret_in_store(store, &operation, master, timestamp)
                .map_err(|error| failure(error.error, error.message))?;
            if let Some((_, _, fp_key)) = shared_fp.as_ref()
                && let Ok(tag) = local_dedup_tag_v1(fp_key, &value)
            {
                let _ = store.upsert_local_value_fingerprint(
                    &written.secret_id,
                    written.version,
                    &tag,
                    timestamp,
                );
            }
            if existing.is_some() {
                result.overwritten += 1;
            } else {
                result.imported += 1;
            }
        }
        Ok::<(), MutationError>(())
    });
    for entry in &mut document.entries {
        zeroize::Zeroize::zeroize(&mut entry.value);
    }
    write_result?;
    if let Some(root) = verified.root.as_deref()
        && locket_platform::ensure_secret_file_ignores(root).is_err()
    {
        result.maintenance_warning = Some("Import committed, but .gitignore could not be updated. Review plaintext env-file exclusions.".into());
    }
    Ok(result)
}

fn read_dotenv(
    path: &Path,
    literal: bool,
) -> Result<locket_core::dotenv::DotenvDocument, MutationError> {
    if !std::fs::symlink_metadata(path).map_err(|_| metadata())?.file_type().is_file() {
        return Err(metadata());
    }
    #[cfg(unix)]
    let file = std::fs::File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| metadata())?,
    );
    #[cfg(target_os = "windows")]
    let file = {
        use std::os::windows::fs::OpenOptionsExt as _;

        // Open a reparse point itself if the path was replaced after inspection.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        std::fs::File::options()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| metadata())?
    };
    #[cfg(not(any(unix, target_os = "windows")))]
    let file = std::fs::File::open(path).map_err(|_| metadata())?;
    if !file.metadata().map_err(|_| metadata())?.is_file() {
        return Err(metadata());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_ENV_BYTES + 1).read_to_end(&mut bytes).map_err(|_| metadata())?;
    if bytes.len() > usize::try_from(MAX_ENV_BYTES).map_err(|_| metadata())? {
        return Err(failure("MetadataInvalid", "env file exceeds 1 MiB"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| failure("MetadataInvalid", "env file is not UTF-8"))?;
    let mut document =
        locket_core::dotenv::parse_dotenv(text, locket_core::dotenv::DotenvOptions { literal });
    if !document.errors.is_empty() {
        for entry in &mut document.entries {
            zeroize::Zeroize::zeroize(&mut entry.value);
        }
        return Err(failure(
            "MetadataInvalid",
            "env file has invalid syntax or expansion; no values were imported",
        ));
    }
    Ok(document)
}

fn strings(values: &[String]) -> toml::Value {
    toml::Value::Array(values.iter().cloned().map(toml::Value::String).collect())
}
fn names(values: &[String]) -> Result<(), MutationError> {
    for name in values {
        SecretName::new(name.clone()).map_err(|_| metadata())?;
    }
    Ok(())
}
fn edit_document(
    document: &mut toml::Value,
    request: &ApplyPolicyRequest,
) -> Result<(), MutationError> {
    if request.policy.project_id != request.scope.project_id
        || !matches!(request.mode.as_str(), "create" | "edit" | "delete")
        || request.policy.name.is_empty()
        || request.policy.name.starts_with('-')
        || request.policy.name.contains('\0')
    {
        return Err(metadata());
    }
    let previous =
        PolicyDocument::from_toml_str(&toml::to_string(document).map_err(|_| metadata())?)
            .map_err(|_| metadata())?;
    let original = if request.original_name.is_empty() {
        &request.policy.name
    } else {
        &request.original_name
    };
    let table = document.as_table_mut().ok_or_else(metadata)?;
    let commands = table
        .entry("commands")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(metadata)?;
    if request.mode == "create" && commands.contains_key(&request.policy.name) {
        return Err(failure("SecretAlreadyExists", "a command already uses this name"));
    }
    if request.mode != "create" && !commands.contains_key(original) {
        return Err(failure("PolicyNotFound", "command no longer exists; refresh before editing"));
    }
    if request.mode == "edit"
        && original != &request.policy.name
        && commands.contains_key(&request.policy.name)
    {
        return Err(failure("SecretAlreadyExists", "another command already uses the new name"));
    }
    if request.mode == "delete" {
        commands.remove(original);
        return Ok(());
    }
    let mut policy =
        commands.get(original).and_then(toml::Value::as_table).cloned().unwrap_or_default();
    let preview = request.policy.command_preview.trim();
    match request.policy.command_kind.as_str() {
        "argv" => {
            let argv = previous
                .commands
                .get(original)
                .and_then(|policy| match &policy.command {
                    CommandSpec::Argv(argv) if argv.join(" ") == preview => Some(argv.clone()),
                    _ => None,
                })
                .or_else(|| shlex::split(preview))
                .filter(|argv| !argv.is_empty())
                .ok_or_else(metadata)?;
            policy.remove("shell");
            policy.insert("argv".into(), strings(&argv));
        }
        "shell" if !preview.is_empty() => {
            policy.remove("argv");
            policy.insert("shell".into(), toml::Value::String(preview.into()));
        }
        _ => return Err(metadata()),
    }
    names(&request.policy.required_secrets)?;
    names(&request.policy.optional_secrets)?;
    names(&request.policy.allowed_secrets)?;
    if request
        .policy
        .required_secrets
        .iter()
        .any(|name| request.policy.optional_secrets.contains(name))
    {
        return Err(metadata());
    }
    let mut optional = request.policy.optional_secrets.clone();
    for name in &request.policy.allowed_secrets {
        if !request.policy.required_secrets.contains(name) && !optional.contains(name) {
            optional.push(name.clone());
        }
    }
    policy.insert("required_secrets".into(), strings(&request.policy.required_secrets));
    policy.insert("optional_secrets".into(), strings(&optional));
    for (name, value) in [
        ("confirm", request.policy.confirm),
        ("require_user_verification", request.policy.require_user_verification),
        ("require_agent", request.policy.require_agent),
        ("allow_remote_docker", request.policy.allow_remote_docker),
    ] {
        policy.insert(name.into(), toml::Value::Boolean(value));
    }
    policy.insert("env_mode".into(), toml::Value::String(request.policy.env_mode.clone()));
    policy.insert("override".into(), toml::Value::String(request.policy.override_mode.clone()));
    policy.insert("ttl".into(), toml::Value::String(format!("{}s", request.policy.ttl_seconds)));
    if request.mode == "edit" && original != &request.policy.name {
        commands.remove(original);
    }
    commands.insert(request.policy.name.clone(), toml::Value::Table(policy));
    Ok(())
}

/// Apply a durable, comment-preserving policy edit with an authorized master key.
///
/// # Errors
/// Rejects invalid/stale scope, failed confirmation and concurrent file edits. A handled
/// DB failure restores the original file only if no later editor changed our candidate.
/// SQLite and file replacement are not a crash-atomic transaction.
pub fn apply_policy_with_master(
    request: &ApplyPolicyRequest,
    master: &KeyBytes,
    timestamp: i64,
) -> Result<(ApplyPolicyResponse, Vec<CommandPolicySnapshot>), MutationError> {
    let (store, _) = crate::keys::open_verified_store(&request.scope.store_path, None)
        .map_err(locket_store::StoreError::from)?;
    apply_policy_in_store(store, request, master, timestamp)
}

fn apply_policy_in_store(
    mut store: Store,
    request: &ApplyPolicyRequest,
    master: &KeyBytes,
    timestamp: i64,
) -> Result<(ApplyPolicyResponse, Vec<CommandPolicySnapshot>), MutationError> {
    let _guard = MUTATION_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if serde_json::to_vec(request).map_err(|_| metadata())?.len() > MAX_POLICY_BYTES {
        return Err(failure("MetadataInvalid", "policy request exceeds 64 KiB"));
    }
    let verified = context(&store, &request.scope)?;
    let root = verified.root.as_deref().ok_or_else(|| {
        failure("MetadataInvalid", "saving commands requires a project folder with locket.toml")
    })?;
    confirm_dangerous_profile(
        &verified.profile,
        request.confirmation.as_deref(),
        "type the dangerous profile name to confirm policy changes",
    )?;
    let audit_key = unwrap_audit_key_with_master(&store, &request.scope.project_id, master)
        .map_err(|_| storage())?;
    let path = root.join("locket.toml");
    let mut document = PolicyFileDocument::read(&path).map_err(|_| metadata())?;
    edit_document(&mut document, request)?;
    let candidate = document.rendered_source().map_err(|_| metadata())?;
    let parsed = PolicyDocument::from_toml_str(&candidate).map_err(|_| metadata())?;
    let original = if request.original_name.is_empty() {
        &request.policy.name
    } else {
        &request.original_name
    };
    let metadata_json = json!({"schema_version":1,"action":"POLICY_UPDATE","status":"SUCCESS","command":"policy","operation":request.mode,"policy":request.policy.name,"policy_name":request.policy.name,"change_kind":request.mode,"metadata_only":true});
    let audit = AuditWrite {
        project_id: &request.scope.project_id,
        profile_id: Some(&request.scope.profile_id),
        action: "POLICY_UPDATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("policy"),
        metadata_json: &metadata_json,
        timestamp,
    };
    let mut file_saved = false;
    let committed = store.with_atomic_write(|store| {
        if context(store, &request.scope)? != verified {
            return Err(metadata());
        }
        if request.mode == "delete" || (request.mode == "edit" && original != &request.policy.name)
        {
            let audit_context = (request.mode == "delete")
                .then_some(AuditContext { key: audit_key.as_ref(), write: &audit });
            store.delete_command_policy_index(
                &request.scope.project_id,
                original,
                audit_context,
            )?;
        }
        if request.mode != "delete" {
            let policy = parsed.commands.get(&request.policy.name).ok_or_else(metadata)?;
            let mut normalized = normalized_policy(policy);
            normalized["source_path"] = json!(path);
            normalized["source_digest"] = json!(
                locket_core::policy::policy_source_digest(&document, &request.policy.name)
                    .map_err(|_| metadata())?
            );
            let raw = serde_json::to_value(&document["commands"][&request.policy.name])
                .map_err(|_| metadata())?;
            store.upsert_command_policy_index(
                &request.scope.project_id,
                &request.policy.name,
                &raw,
                &normalized,
                timestamp,
                Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
            )?;
        }
        if document.save().is_err() {
            file_saved = std::fs::read_to_string(&path).is_ok_and(|current| current == candidate);
            return Err(metadata());
        }
        file_saved = true;
        Ok::<(), MutationError>(())
    });
    if let Err(error) = committed {
        if file_saved && document.restore_if_current(&candidate).is_err() {
            return Err(failure(
                "MetadataInvalid",
                "policy save has a partial outcome; reload the project before retrying",
            ));
        }
        return Err(error);
    }
    let snapshots = parsed
        .commands
        .values()
        .map(|policy| {
            CommandPolicySnapshot::from_policy(&request.scope.project_id, policy, timestamp)
        })
        .collect();
    Ok((
        ApplyPolicyResponse {
            policy_name: request.policy.name.clone(),
            operation: request.mode.clone(),
        },
        snapshots,
    ))
}

fn normalized_policy(policy: &locket_core::CommandPolicy) -> Value {
    let command = match &policy.command {
        CommandSpec::Argv(argv) => json!({"type":"argv","argv":argv}),
        CommandSpec::Shell(shell) => json!({"type":"shell","shell":shell}),
    };
    let external = policy
        .external_env_sources
        .iter()
        .map(|source| match source {
            locket_core::ExternalEnvSource::Parent => json!({"type":"parent"}),
            locket_core::ExternalEnvSource::File(path) => json!({"type":"file","path":path}),
            locket_core::ExternalEnvSource::Compose => json!({"type":"compose"}),
            locket_core::ExternalEnvSource::Ide => json!({"type":"ide"}),
        })
        .collect::<Vec<_>>();
    json!({"schema_version":1,"name":policy.name,"command":command,"allowed_secrets":policy.allowed_secrets.iter().map(SecretName::as_str).collect::<Vec<_>>(),"required_secrets":policy.required_secrets.iter().map(SecretName::as_str).collect::<Vec<_>>(),"optional_secrets":policy.optional_secrets.iter().map(SecretName::as_str).collect::<Vec<_>>(),"inherit_env":policy.inherit_env,"env_mode":policy.env_mode.as_str(),"override":policy.override_behavior.as_str(),"override_explicit":policy.override_explicit(),"external_env_sources":external,"allow_remote_docker":policy.allow_remote_docker,"confirm":policy.confirm,"require_user_verification":policy.require_user_verification,"require_agent":policy.require_agent,"ttl_seconds":policy.ttl.as_secs()})
}

#[cfg(test)]
#[path = "mutations_tests.rs"]
mod tests;
