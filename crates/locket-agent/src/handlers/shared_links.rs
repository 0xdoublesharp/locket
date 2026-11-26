//! Metadata-only queries for Global Vault (`@shared`) links and local duplicate detection,
//! plus local-only keyed deduplication tag helpers.

use std::path::PathBuf;

use locket_core::privacy_alias;
use locket_crypto::{KeyBytes, KeyPurpose, local_dedup_tag_v1};
use locket_store::{Store, StoreError};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::keys::{StoreFileIdentity, master_key_array, unwrap_profile_key_with_master};
use crate::{AgentSocketState, UnlockCache};

/// Request payload for `ListSharedUsages`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListSharedUsagesRequest {
    /// `SQLite` store path to read.
    pub store_path: PathBuf,
    /// Target Global Vault secret identifier.
    pub target_secret_id: String,
    /// Whether project, profile, and secret names should be aliased.
    #[serde(default)]
    pub redact_names: bool,
}

/// One project/profile/name bound to a Global Vault secret.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SharedUsageRow {
    /// Opaque link identifier.
    pub link_id: String,
    /// Consuming project identifier.
    pub project_id: String,
    /// Consuming project display name or privacy alias.
    pub project_name: String,
    /// Consuming profile identifier.
    pub profile_id: String,
    /// Consuming profile name or privacy alias.
    pub profile_name: String,
    /// Whether the consuming profile is marked dangerous.
    pub profile_dangerous: bool,
    /// Local environment variable name or privacy alias.
    pub local_name: String,
    /// Target Global Vault secret identifier.
    pub target_secret_id: String,
    /// Target Global Vault secret name or privacy alias.
    pub target_secret_name: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
}

/// Metadata-only `ListSharedUsages` response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListSharedUsagesResponse {
    /// Projects linked to the requested Global Vault secret.
    pub usages: Vec<SharedUsageRow>,
}

/// Request payload for `ListDuplicates`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListDuplicatesRequest {
    /// `SQLite` store path to read.
    pub store_path: PathBuf,
    /// Whether project, profile, and secret names should be aliased.
    #[serde(default)]
    pub redact_names: bool,
}

/// One active secret belonging to a cross-project duplicate value group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DuplicateMemberRow {
    /// Secret identifier.
    pub secret_id: String,
    /// Project identifier.
    pub project_id: String,
    /// Project display name or privacy alias.
    pub project_name: String,
    /// Whether this secret belongs to the Global Vault (`@shared`).
    pub is_shared: bool,
    /// Profile identifier.
    pub profile_id: String,
    /// Profile name or privacy alias.
    pub profile_name: String,
    /// Whether the profile is marked dangerous.
    pub profile_dangerous: bool,
    /// Secret name or privacy alias.
    pub name: String,
    /// Persisted secret source (`user-local`, `machine-local`, `team-managed`).
    pub source: String,
    /// Current active version number.
    pub current_version: u32,
    /// Last update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
}

/// Metadata-only group of active secrets holding the exact same value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DuplicateGroupRow {
    /// Opaque group identifier (never raw fingerprint bytes).
    pub group_id: String,
    /// Active secrets that share the same value.
    pub members: Vec<DuplicateMemberRow>,
}

/// Metadata-only `ListDuplicates` response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListDuplicatesResponse {
    /// Duplicate value groups across unlocked/indexed projects and Global Vault.
    pub groups: Vec<DuplicateGroupRow>,
}

/// Lists project usages for one Global Vault secret without reading ciphertext.
///
/// # Errors
///
/// Returns [`StoreError`] when the store cannot be queried.
pub fn list_shared_usages_from_store(
    store: &Store,
    request: &ListSharedUsagesRequest,
) -> Result<ListSharedUsagesResponse, StoreError> {
    let usages = store
        .list_shared_secret_usages(&request.target_secret_id)?
        .into_iter()
        .map(|row| SharedUsageRow {
            link_id: row.link_id,
            project_id: row.project_id,
            project_name: maybe_alias("project", &row.project_name, request.redact_names),
            profile_id: maybe_alias("profile", &row.profile_id, request.redact_names),
            profile_name: maybe_alias("profile", &row.profile_name, request.redact_names),
            profile_dangerous: row.profile_dangerous,
            local_name: maybe_alias("secret", &row.local_name, request.redact_names),
            target_secret_id: row.target_secret_id,
            target_secret_name: maybe_alias(
                "secret",
                &row.target_secret_name,
                request.redact_names,
            ),
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
        .collect();
    Ok(ListSharedUsagesResponse { usages })
}

/// Lists cross-project duplicate value groups from local dedup tags without reading ciphertext.
///
/// # Errors
///
/// Returns [`StoreError`] when the store cannot be queried.
pub fn list_duplicates_from_store(
    store: &Store,
    request: &ListDuplicatesRequest,
) -> Result<ListDuplicatesResponse, StoreError> {
    let groups = store
        .list_duplicate_value_groups()?
        .into_iter()
        .enumerate()
        .map(|(index, group)| DuplicateGroupRow {
            group_id: format!("dup-{}", index + 1),
            members: group
                .members
                .into_iter()
                .map(|member| DuplicateMemberRow {
                    secret_id: member.secret_id,
                    project_id: member.project_id,
                    project_name: maybe_alias(
                        "project",
                        &member.project_name,
                        request.redact_names,
                    ),
                    is_shared: member.is_shared,
                    profile_id: maybe_alias("profile", &member.profile_id, request.redact_names),
                    profile_name: maybe_alias(
                        "profile",
                        &member.profile_name,
                        request.redact_names,
                    ),
                    profile_dangerous: member.profile_dangerous,
                    name: maybe_alias("secret", &member.name, request.redact_names),
                    source: member.source,
                    current_version: member.current_version,
                    updated_at: member.updated_at,
                })
                .collect(),
        })
        .collect();
    Ok(ListDuplicatesResponse { groups })
}

/// Handles metadata-only `ListSharedUsages` RPCs.
pub fn handle_list_shared_usages(
    request: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<ListSharedUsagesRequest>(request.payload.clone())
    else {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "MetadataInvalid",
            "invalid ListSharedUsages payload",
            false,
        ));
    };
    let (store, _) = match state.open_store(&typed.store_path, None, true) {
        Ok(opened) => opened,
        Err(error) => return crate::server::store_open_error(request, &error),
    };
    list_shared_usages_from_store(&store, &typed).map_or_else(
        |_| {
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                "CorruptDb",
                "could not list shared secret usages",
                false,
            ))
        },
        |response| {
            ResponseEnvelope::Success(SuccessEnvelope::new(
                request.id.clone(),
                serde_json::to_value(response).unwrap_or(serde_json::Value::Null),
            ))
        },
    )
}

/// Handles metadata-only `ListDuplicates` RPCs.
pub fn handle_list_duplicates(
    request: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<ListDuplicatesRequest>(request.payload.clone()) else {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "MetadataInvalid",
            "invalid ListDuplicates payload",
            false,
        ));
    };
    let (store, _) = match state.open_store(&typed.store_path, None, true) {
        Ok(opened) => opened,
        Err(error) => return crate::server::store_open_error(request, &error),
    };
    list_duplicates_from_store(&store, &typed).map_or_else(
        |_| {
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                "CorruptDb",
                "could not list duplicate value groups",
                false,
            ))
        },
        |response| {
            ResponseEnvelope::Success(SuccessEnvelope::new(
                request.id.clone(),
                serde_json::to_value(response).unwrap_or(serde_json::Value::Null),
            ))
        },
    )
}

/// Returns the unlocked Global Vault's `(project_id, profile_id, fingerprint_key)` when available.
pub fn shared_fingerprint_key_from_cache(
    store: &Store,
    cache: &UnlockCache,
    now: i128,
    store_identity: &StoreFileIdentity,
) -> Option<(String, String, Zeroizing<KeyBytes>)> {
    let shared = store
        .list_projects()
        .ok()?
        .into_iter()
        .filter(|project| project.id.starts_with("lk_proj_shared_"))
        .min_by_key(|project| project.name != "@shared")?;
    let entry = cache.lookup(&shared.id, now)?;
    if entry.store_identity.as_ref().is_some_and(|pin| pin != store_identity) {
        return None;
    }
    let profile = store.get_profile_by_name(&shared.id, "default").ok()??;
    let master = master_key_array(entry.key_bytes()).ok()?;
    let fp_key = unwrap_profile_key_with_master(
        store,
        &shared.id,
        &profile.id,
        &master,
        KeyPurpose::ProfileFingerprint,
    )
    .ok()?;
    Some((shared.id, profile.id, fp_key))
}

/// Best-effort upsert of the local-only keyed dedup tag when the Global Vault is unlocked.
#[allow(clippy::too_many_arguments)]
pub fn try_record_local_dedup_tag(
    store: &Store,
    cache: &UnlockCache,
    now: i128,
    store_identity: &StoreFileIdentity,
    secret_id: &str,
    version: u32,
    value: &str,
    timestamp: i64,
) {
    let Some((_, _, fp_key)) = shared_fingerprint_key_from_cache(store, cache, now, store_identity)
    else {
        return;
    };
    if let Ok(tag) = local_dedup_tag_v1(&fp_key, value) {
        let _ = store.upsert_local_value_fingerprint(secret_id, version, &tag, timestamp);
    }
}

fn maybe_alias(kind: &str, value: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias(kind, value) } else { value.to_owned() }
}
