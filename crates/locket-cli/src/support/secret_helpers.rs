//! Shared helpers for working with encrypted secrets, profile secret
//! resolution, and audit metadata. These are reused across multiple CLI
//! commands (get, exec, run, set, rotate, copy, env inspect, etc.).

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use locket_core::{CommandPolicy, Duration as LocketDuration, ProfileName, SecretName};
use locket_crypto::{
    EncryptedSecretValue, KeyPurpose, KeyWrapAad, KeyWrapPurpose, decrypt_secret_value_v1,
    encrypt_secret_value_v1, key_wrap_aad_v1, secret_blob_aad_v1, secret_fingerprint_v1,
};
#[cfg(test)]
use locket_store::SecretVersionRecord;
use locket_store::{AuditWrite, ProfileRecord, SecretRecord, Store};
use serde_json::{Value, json};

use crate::commands::config::spec::{config_get_value, read_user_config};
use crate::commands::discovery::{GLOBAL_VAULT, global_vault_project};
use crate::runtime::RuntimeContext;
#[cfg(test)]
use crate::runtime::error::secret_version_expired_error;
use crate::runtime::error::{
    CliError, corrupt_db_error, invalid_profile_name_error, invalid_reference_error,
    invalid_secret_name_error, metadata_invalid_error, profile_not_found_error,
    secret_deleted_error, secret_not_found_error,
};
use crate::runtime::key_access::{default_profile, load_profile_key, load_project_key};
use crate::runtime::user_verification::UserVerificationAudit;
use crate::{
    CopyArgs, CopySelection, ResolvedProject, SecretSourceArg, active_secrets_by_name,
    ensure_trusted_project_root, now_unix_nanos, open_store, require_project, source_arg_to_str,
    source_precedence,
};

pub struct ResolvedSecret {
    pub project: ResolvedProject,
    pub profile: ProfileRecord,
    pub secret: SecretRecord,
}

pub struct PolicySecretSelection {
    pub name: String,
    pub required: bool,
    pub sources: Vec<String>,
    pub selected: Option<SecretRecord>,
    pub shared: bool,
}

impl PolicySecretSelection {
    pub fn selected_source(&self) -> Option<&str> {
        self.selected.as_ref().map(
            |secret| {
                if self.shared { GLOBAL_VAULT } else { secret.source.as_str() }
            },
        )
    }
}

pub struct ValueAccessTarget {
    pub profile: ProfileRecord,
    pub secret: SecretRecord,
}

impl From<ResolvedSecret> for ValueAccessTarget {
    fn from(resolved: ResolvedSecret) -> Self {
        Self { profile: resolved.profile, secret: resolved.secret }
    }
}

pub struct ValueAccessAudit<'a> {
    pub context: &'a RuntimeContext,
    pub resolved: &'a ValueAccessTarget,
    pub action: &'static str,
    pub status: &'static str,
    pub access_mode: &'static str,
    pub ttl_seconds: Option<u64>,
    pub force: bool,
    pub clipboard_supported: Option<bool>,
    pub clipboard_clear_supported: Option<bool>,
    pub unsupported_reason: Option<&'a str>,
    pub denial_reason: Option<&'static str>,
    pub failure_reason: Option<&'static str>,
    pub user_verification: UserVerificationAudit,
}

#[derive(Clone, Copy)]
pub struct SecretEncryptRequest<'a> {
    pub project_id: &'a str,
    pub profile_id: &'a str,
    pub secret_id: &'a str,
    pub secret_name: &'a str,
    pub version: u32,
    pub value: &'a str,
}

pub fn encrypt_secret_version(
    context: &RuntimeContext,
    store: &Store,
    request: SecretEncryptRequest<'_>,
) -> Result<(EncryptedSecretValue, Vec<u8>), CliError> {
    let profile_secret_key = load_profile_key(
        context,
        store,
        request.project_id,
        request.profile_id,
        KeyPurpose::ProfileSecret,
    )?;
    let profile_fingerprint_key = load_profile_key(
        context,
        store,
        request.project_id,
        request.profile_id,
        KeyPurpose::ProfileFingerprint,
    )?;
    encrypt_secret_version_with_keys(&profile_secret_key, &profile_fingerprint_key, request)
}

pub fn encrypt_secret_version_with_keys(
    profile_secret_key: &locket_crypto::KeyBytes,
    profile_fingerprint_key: &locket_crypto::KeyBytes,
    request: SecretEncryptRequest<'_>,
) -> Result<(EncryptedSecretValue, Vec<u8>), CliError> {
    let value_aad = secret_blob_aad_v1(&locket_crypto::SecretBlobAad::new(
        request.project_id,
        request.profile_id,
        request.secret_id,
        request.secret_name,
        request.version,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        request.project_id,
        request.secret_id,
        Some(request.profile_id),
        request.version,
        KeyWrapPurpose::SecretDek,
    ))?;
    let encrypted =
        encrypt_secret_value_v1(profile_secret_key, request.value, &value_aad, &wrap_aad)?;
    let fingerprint = secret_fingerprint_v1(profile_fingerprint_key, request.value)?;
    Ok((encrypted, fingerprint.to_vec()))
}

pub fn decrypt_secret_version(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    profile_id: &str,
    secret: &SecretRecord,
    version: u32,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    let profile_secret_key =
        load_profile_key(context, store, project_id, profile_id, KeyPurpose::ProfileSecret)?;
    let blob = store
        .get_blob(&secret.id, version)?
        .ok_or_else(|| corrupt_db_error("secret blob is missing"))?;
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
    Ok(decrypt_secret_value_v1(&profile_secret_key, &encrypted, &value_aad, &wrap_aad)?)
}

pub fn resolve_active_secret(
    context: &RuntimeContext,
    key: &str,
) -> Result<ResolvedSecret, CliError> {
    let name = SecretName::new(key.to_owned())
        .map_err(|err| invalid_secret_name_error(err.to_string()))?;
    let project = require_project(context)?;
    let store = open_store(context)?;
    ensure_trusted_project_root(&store, &project)?;
    let profile = default_profile(&store, &project.config)?;
    let secret = resolve_active_secret_in_profile(&store, &profile, &name)?;
    Ok(ResolvedSecret { project, profile, secret })
}

pub fn resolve_active_secret_in_profile(
    store: &Store,
    profile: &ProfileRecord,
    name: &SecretName,
) -> Result<SecretRecord, CliError> {
    let rows = store.list_secrets_by_name(&profile.project_id, &profile.id, name.as_str())?;
    let active_local = select_highest_precedence_secret(
        rows.into_iter().filter(|secret| secret.state == "active"),
    );
    if let Some(link) =
        store.resolve_active_secret_link(&profile.project_id, &profile.id, name.as_str())?
        && active_local
            .as_ref()
            .is_none_or(|local| source_precedence("shared-link") > source_precedence(&local.source))
    {
        return Ok(link.target_secret);
    }
    active_local.ok_or_else(|| secret_not_found_error("secret not found"))
}

pub fn resolve_active_secret_for_source(
    context: &RuntimeContext,
    key: &str,
    source: Option<SecretSourceArg>,
) -> Result<ResolvedSecret, CliError> {
    let resolved = resolve_secret_for_source(context, key, source)?;
    if resolved.secret.state == "deleted" {
        return Err(secret_deleted_error("secret source is deleted"));
    }
    Ok(resolved)
}

/// Resolves a pinned `lk://...@vN` secret version for value access.
///
/// Returns `Ok(())` when the requested version is the secret's current
/// version, or a deprecated version with `grace_until` still in the future.
///
/// Returns typed `SecretVersionExpired` (exit 75) when the version exists but
/// is deprecated past its grace window, ungraced, or purged. Returns
/// `SecretDeleted` when the secret's source is deleted.
///
/// # Errors
///
/// Returns [`CliError::Typed`] tagged with [`locket_core::LocketError::SecretVersionExpired`]
/// when the version is past grace; [`locket_core::LocketError::SecretDeleted`] when the
/// secret source is deleted.
#[cfg(test)]
pub fn resolve_pinned_version(
    secret: &SecretRecord,
    version: &SecretVersionRecord,
    timestamp: i64,
) -> Result<(), CliError> {
    if secret.state == "deleted" {
        return Err(secret_deleted_error(format!("secret source is deleted: {}", secret.name)));
    }
    match version.state.as_str() {
        "current" => Ok(()),
        "deprecated" => match version.grace_until {
            Some(grace_until) if grace_until > timestamp => Ok(()),
            _ => Err(secret_version_expired_error(format!(
                "pinned version {}@v{} is past its grace window",
                secret.name, version.version
            ))),
        },
        "purged" => Err(secret_version_expired_error(format!(
            "pinned version {}@v{} is purged",
            secret.name, version.version
        ))),
        _ => Err(secret_not_found_error(format!(
            "version not found: {}@v{}",
            secret.name, version.version
        ))),
    }
}

pub fn resolve_secret_for_source(
    context: &RuntimeContext,
    key: &str,
    source: Option<SecretSourceArg>,
) -> Result<ResolvedSecret, CliError> {
    let name = SecretName::new(key.to_owned())
        .map_err(|err| invalid_secret_name_error(err.to_string()))?;
    let project = require_project(context)?;
    let store = open_store(context)?;
    ensure_trusted_project_root(&store, &project)?;
    let profile = default_profile(&store, &project.config)?;
    let secret = select_secret_for_source(
        &store,
        project.config.project_id.as_str(),
        &profile.id,
        &name,
        source,
    )?;
    Ok(ResolvedSecret { project, profile, secret })
}

pub fn select_secret_for_source(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    name: &SecretName,
    source: Option<SecretSourceArg>,
) -> Result<SecretRecord, CliError> {
    if let Some(source) = source {
        let source = source_arg_to_str(source);
        return store
            .get_secret_by_source(project_id, profile_id, name.as_str(), source)?
            .ok_or_else(|| secret_not_found_error("secret not found"));
    }
    let mut secrets = store.list_secrets_by_name(project_id, profile_id, name.as_str())?;
    match secrets.len() {
        0 => Err(secret_not_found_error("secret not found")),
        1 => Ok(secrets.remove(0)),
        _ => Err(invalid_reference_error("multiple sources exist for this secret; pass --source")),
    }
}

pub fn select_copy_source_secret(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    name: &str,
    source: Option<SecretSourceArg>,
) -> Result<SecretRecord, CliError> {
    if let Some(source) = source {
        let source = source_arg_to_str(source);
        let secret = store
            .get_secret_by_source(project_id, profile_id, name, source)?
            .ok_or_else(|| secret_not_found_error("secret not found"))?;
        if secret.state == "deleted" {
            return Err(secret_deleted_error("secret source is deleted"));
        }
        return Ok(secret);
    }

    let active = store
        .list_secrets_by_name(project_id, profile_id, name)?
        .into_iter()
        .filter(|secret| secret.state == "active")
        .collect::<Vec<_>>();
    select_highest_precedence_secret(active)
        .ok_or_else(|| secret_not_found_error("secret not found"))
}

pub fn select_copy_target_source(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    name: &str,
    from_source: &str,
    to_source: Option<SecretSourceArg>,
) -> Result<String, CliError> {
    if let Some(to_source) = to_source {
        return Ok(source_arg_to_str(to_source).to_owned());
    }
    if store.get_secret_by_source(project_id, profile_id, name, from_source)?.is_some() {
        return Ok(from_source.to_owned());
    }
    Ok(source_arg_to_str(SecretSourceArg::UserLocal).to_owned())
}

pub fn select_copy_profiles_and_sources(
    store: &Store,
    project_id: &str,
    name: &str,
    args: &CopyArgs,
) -> Result<CopySelection, CliError> {
    let from_profile_name = ProfileName::new(args.from.clone())
        .map_err(|_| invalid_profile_name_error("invalid source profile name"))?;
    let to_profile_name = ProfileName::new(args.to.clone())
        .map_err(|_| invalid_profile_name_error("invalid target profile name"))?;
    let from_profile = store
        .get_profile_by_name(project_id, from_profile_name.as_str())?
        .ok_or_else(|| profile_not_found_error("source profile not found"))?;
    let to_profile = store
        .get_profile_by_name(project_id, to_profile_name.as_str())?
        .ok_or_else(|| profile_not_found_error("target profile not found"))?;
    let source_secret =
        select_copy_source_secret(store, project_id, &from_profile.id, name, args.from_source)?;
    let from_source = source_secret.source.clone();
    let to_source = select_copy_target_source(
        store,
        project_id,
        &to_profile.id,
        name,
        &from_source,
        args.to_source,
    )?;
    if from_profile.id == to_profile.id && from_source == to_source {
        return Err(invalid_reference_error(
            "copy source and target are the same profile and source; use rotate",
        ));
    }
    Ok(CopySelection { from_profile, to_profile, source_secret, from_source, to_source })
}

pub fn secret_audit_metadata(
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

pub fn write_value_access_audit_if_available(
    request: &ValueAccessAudit<'_>,
) -> Result<(), CliError> {
    let mut store = open_store(request.context)?;
    let project_id = request.resolved.secret.project_id.as_str();
    if store.get_project(project_id)?.is_none() {
        return Ok(());
    }
    let audit_key = load_project_key(request.context, &store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": request.action,
        "status": request.status,
        "command": "get",
        "secret_name": &request.resolved.secret.name,
        "profile": &request.resolved.profile.name,
        "profile_id": &request.resolved.profile.id,
        "source": &request.resolved.secret.source,
        "version": request.resolved.secret.current_version,
        "access_mode": request.access_mode,
        "ttl_seconds": request.ttl_seconds,
        "force": request.force,
        "clipboard_supported": request.clipboard_supported,
        "clipboard_clear_supported": request.clipboard_clear_supported,
        "unsupported_reason": request.unsupported_reason,
        "denial_reason": request.denial_reason,
        "failure_reason": request.failure_reason,
        "user_verification": &request.user_verification,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: Some(&request.resolved.profile.id),
        action: request.action,
        status: request.status,
        secret_name: Some(&request.resolved.secret.name),
        command: Some("get"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

pub fn reveal_ttl_seconds(context: &RuntimeContext) -> Result<u64, CliError> {
    let config = read_user_config(context)?;
    let Some(value) = config_get_value(&config, "reveal.ttl") else {
        return Ok(60);
    };
    let Some(value) = value.as_str() else {
        return Err(metadata_invalid_error("reveal.ttl must be a duration"));
    };
    let duration = LocketDuration::from_str(value)
        .map_err(|_| metadata_invalid_error("invalid reveal.ttl duration"))?;
    Ok(duration.as_secs().min(300))
}

/// Maximum number of names kept verbatim before the list is truncated to stay
/// safely under the 64 KiB metadata-JSON per-row cap.
const SECRET_NAMES_INLINE_LIMIT: usize = 200;

/// Returns names as a `Vec<String>` suitable for embedding in audit metadata.
/// When the list exceeds `SECRET_NAMES_INLINE_LIMIT`, only the first N names
/// are kept and a trailing `"... M more"` sentinel is appended.
pub fn summarize_names<S: AsRef<str>>(names: &[S]) -> Vec<String> {
    if names.len() <= SECRET_NAMES_INLINE_LIMIT {
        return names.iter().map(|s| s.as_ref().to_owned()).collect();
    }
    let mut out: Vec<String> =
        names[..SECRET_NAMES_INLINE_LIMIT].iter().map(|s| s.as_ref().to_owned()).collect();
    out.push(format!("... {} more", names.len() - SECRET_NAMES_INLINE_LIMIT));
    out
}

pub fn policy_secret_selections(
    store: &Store,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
) -> Result<Vec<PolicySecretSelection>, CliError> {
    let active_by_name =
        active_secrets_by_name(store, resolved.config.project_id.as_str(), &profile.id)?;
    let links_by_name: BTreeMap<String, locket_store::ResolvedSecretLink> = store
        .list_active_secret_links_by_profile(resolved.config.project_id.as_str(), &profile.id)?
        .into_iter()
        .map(|link| (link.link.local_name.clone(), link))
        .collect();
    let mut selections = Vec::new();
    for name in &policy.required_secrets {
        selections.push(policy_secret_selection_with_links(
            name.as_str(),
            true,
            &active_by_name,
            &links_by_name,
        ));
    }
    for name in &policy.optional_secrets {
        selections.push(policy_secret_selection_with_links(
            name.as_str(),
            false,
            &active_by_name,
            &links_by_name,
        ));
    }
    if !policy.shared_secrets.is_empty() {
        let shared_by_name = shared_secrets_by_name(store)?;
        for name in &policy.shared_secrets {
            let mut selection = policy_secret_selection(name.as_str(), true, &shared_by_name);
            selection.shared = true;
            if selection.selected.is_some() {
                selection.sources = vec![GLOBAL_VAULT.to_owned()];
            }
            selections.push(selection);
        }
    }
    Ok(selections)
}

fn policy_secret_selection_with_links(
    name: &str,
    required: bool,
    active_by_name: &BTreeMap<String, Vec<SecretRecord>>,
    links_by_name: &BTreeMap<String, locket_store::ResolvedSecretLink>,
) -> PolicySecretSelection {
    let mut selection = policy_secret_selection(name, required, active_by_name);
    if let Some(link) = links_by_name.get(name) {
        let mut all_sources = selection.sources.clone();
        all_sources.push("shared-link".to_owned());
        selection.sources = sources_by_precedence(all_sources);
        let local_rank =
            selection.selected.as_ref().map_or(0, |secret| source_precedence(&secret.source));
        if source_precedence("shared-link") > local_rank {
            selection.selected = Some(link.target_secret.clone());
            selection.shared = true;
        }
    }
    selection
}

fn shared_secrets_by_name(store: &Store) -> Result<BTreeMap<String, Vec<SecretRecord>>, CliError> {
    let Some(project) = global_vault_project(store)? else {
        return Ok(BTreeMap::new());
    };
    let Some(profile) = store.get_profile_by_name(&project.id, "default")? else {
        return Ok(BTreeMap::new());
    };
    crate::runtime::dangerous_profile::ensure_dangerous_profile_consent(&profile, false)?;
    active_secrets_by_name(store, &project.id, &profile.id)
}

pub fn policy_secret_selection(
    name: &str,
    required: bool,
    active_by_name: &BTreeMap<String, Vec<SecretRecord>>,
) -> PolicySecretSelection {
    let secrets = active_by_name.get(name).cloned().unwrap_or_default();
    let sources = sources_by_precedence(secrets.iter().map(|secret| secret.source.clone()));
    let selected = select_highest_precedence_secret(secrets);
    PolicySecretSelection { name: name.to_owned(), required, sources, selected, shared: false }
}

pub fn select_highest_precedence_secret(
    secrets: impl IntoIterator<Item = SecretRecord>,
) -> Option<SecretRecord> {
    secrets.into_iter().max_by_key(|secret| source_precedence(&secret.source))
}

fn sources_by_precedence(sources: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut sources = sources.into_iter().collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
    sources.sort_by(|left, right| {
        source_precedence(right).cmp(&source_precedence(left)).then_with(|| left.cmp(right))
    });
    sources
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use locket_store::SecretRecord;

    use super::{SECRET_NAMES_INLINE_LIMIT, policy_secret_selection, summarize_names};

    #[test]
    fn summarize_names_passes_through_small_list() {
        let names = vec!["SECRET_A", "SECRET_B", "SECRET_C"];
        let result = summarize_names(&names);
        assert_eq!(result, vec!["SECRET_A", "SECRET_B", "SECRET_C"]);
    }

    #[test]
    fn summarize_names_passes_through_list_at_limit() {
        let names: Vec<String> =
            (0..SECRET_NAMES_INLINE_LIMIT).map(|i| format!("SECRET_{i}")).collect();
        let result = summarize_names(&names);
        assert_eq!(result.len(), SECRET_NAMES_INLINE_LIMIT);
        assert!(!result.last().unwrap().starts_with("..."));
    }

    #[test]
    fn summarize_names_truncates_list_above_limit() {
        let count = SECRET_NAMES_INLINE_LIMIT + 50;
        let names: Vec<String> = (0..count).map(|i| format!("SECRET_{i}")).collect();
        let result = summarize_names(&names);
        assert_eq!(result.len(), SECRET_NAMES_INLINE_LIMIT + 1);
        assert_eq!(result.last().unwrap(), "... 50 more");
    }

    #[test]
    fn policy_secret_selection_orders_sources_by_precedence_and_selects_highest() {
        let mut active_by_name = BTreeMap::new();
        active_by_name.insert(
            "DATABASE_URL".to_owned(),
            vec![
                secret_record("team-managed"),
                secret_record("user-local"),
                secret_record("machine-local"),
            ],
        );

        let selection = policy_secret_selection("DATABASE_URL", true, &active_by_name);

        assert_eq!(selection.sources, vec!["machine-local", "user-local", "team-managed"]);
        assert_eq!(selection.selected.unwrap().source, "machine-local");
    }

    fn secret_record(source: &str) -> SecretRecord {
        SecretRecord {
            id: format!("sec_{source}"),
            project_id: "proj".to_owned(),
            profile_id: "prof".to_owned(),
            name: "DATABASE_URL".to_owned(),
            source: source.to_owned(),
            origin: "manual".to_owned(),
            current_version: 1,
            state: "active".to_owned(),
            created_at: 1,
            updated_at: 1,
            last_rotated_at: None,
            deleted_at: None,
        }
    }
}
