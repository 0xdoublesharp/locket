//! Agent-owned dotenv imports and durable policy edits. Results contain metadata only.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use locket_core::{CommandSpec, PolicyDocument, ProjectConfig, SecretName};
use locket_crypto::KeyBytes;
use locket_platform::PolicyFileDocument;
use locket_store::{AuditContext, AuditWrite, Store};
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
}

/// Safe parser diagnostic.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImportDiagnostic {
    /// One-based input line.
    pub line: usize,
    /// Fixed text that never includes input values.
    pub message: String,
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

/// Fixed-code, fixed-message mutation failure. Never contains input plaintext.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct MutationError {
    /// Protocol error code.
    pub code: &'static str,
    /// Safe message for user display.
    pub message: &'static str,
}

const fn failure(code: &'static str, message: &'static str) -> MutationError {
    MutationError { code, message }
}
const fn metadata() -> MutationError {
    failure("MetadataInvalid", "project metadata is invalid or changed; refresh and retry")
}
const fn storage() -> MutationError {
    failure("CorruptDb", "mutation could not be committed")
}
impl From<locket_store::StoreError> for MutationError {
    fn from(_: locket_store::StoreError) -> Self {
        storage()
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
        let (store, _) = state
            .open_store(&typed.scope.store_path, pin, false)
            .map_err(|_| failure("AccessDenied", "could not verify mutation store"))?;
        import_dotenv_in_store(store, &typed, &master, i64::try_from(now).map_err(|_| storage())?)
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
    import_dotenv_in_store(store, request, master, timestamp)
}

fn import_dotenv_in_store(
    mut store: Store,
    request: &ImportDotenvRequest,
    master: &KeyBytes,
    timestamp: i64,
) -> Result<ImportDotenvResponse, MutationError> {
    let _guard = MUTATION_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let verified = context(&store, &request.scope)?;
    if request.overwrite {
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
    let mut result = ImportDotenvResponse {
        imported: 0,
        overwritten: 0,
        skipped: 0,
        diagnostics: document
            .warnings
            .iter()
            .map(|warning| ImportDiagnostic { line: warning.line, message: warning.message.into() })
            .collect(),
        original_preserved: true,
        maintenance_warning: None,
    };
    let write_result = store.with_atomic_write(|store| {
        if context(store, &request.scope)? != verified {
            return Err(metadata());
        }
        for entry in &document.entries {
            let value = Zeroizing::new(entry.value.clone());
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
            set_secret_in_store(store, &operation, master, timestamp)
                .map_err(|error| failure(error.error, error.message))?;
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
    if !std::fs::metadata(path).map_err(|_| metadata())?.is_file() {
        return Err(metadata());
    }
    #[cfg(unix)]
    let file = std::fs::File::from(
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| metadata())?,
    );
    #[cfg(not(unix))]
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
