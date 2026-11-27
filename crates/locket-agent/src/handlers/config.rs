//! Metadata-only agent RPCs for desktop settings reads and writes.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

use locket_core::{Duration as LocketDuration, OutputRedaction, privacy_alias};
use locket_platform::write_user_only_file;
use locket_scan::{FindingKind, scan_text};
use locket_store::{AuditWrite, RuntimeSessionSecretNameRetention, Store};
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::keys::{KeyError, cached_master_key, unwrap_audit_key_with_master};

const UI_THEME: &str = "ui.theme";
const UI_DENSITY: &str = "ui.density";
const PRIVACY_REDACT_NAMES: &str = "privacy.redact_names";
const EDITOR_DEFAULT: &str = "editor.default";
const AGENT_AUTOSTART: &str = "agent.autostart";
const AGENT_UNLOCK_TTL: &str = "agent.unlock_ttl";
const RUNTIME_SESSION_SECRET_NAME_RETENTION: &str = "runtime.session_secret_name_retention";
const REVEAL_TTL: &str = "reveal.ttl";
const ROTATION_MAX_GRACE_TTL: &str = "rotation.max_grace_ttl";
const SHELL_INTEGRATION: &str = "shell.integration";
const UPDATES_CHANNEL: &str = "updates.channel";
const UPDATES_MANIFEST_URL: &str = "updates.manifest_url";
const EXAMPLE_AUTO_REFRESH: &str = "example.auto_refresh";
const RUN_REDACT_OUTPUT: &str = "run.redact_output";
const VERIFICATION_UNLOCK: &str = "user_verification_required_for.unlock";
const VERIFICATION_REVEAL: &str = "user_verification_required_for.reveal";
const VERIFICATION_COPY: &str = "user_verification_required_for.copy";
const VERIFICATION_DANGEROUS_PROFILE_SWITCH: &str =
    "user_verification_required_for.dangerous_profile_switch";
const VERIFICATION_RECOVERY: &str = "user_verification_required_for.recovery";
const VERIFICATION_TEAM_ACCEPT: &str = "user_verification_required_for.team_accept";
const VERIFICATION_DEVICE_REGISTER: &str = "user_verification_required_for.device_register";

const UI_THEME_VALUES: &[&str] = &["system", "light", "dark"];
const UI_DENSITY_VALUES: &[&str] = &["comfortable", "compact"];
const SHELL_INTEGRATION_VALUES: &[&str] = &["off", "prompt-only", "hook"];
const UPDATES_CHANNEL_VALUES: &[&str] = &["off", "stable", "beta"];
const MAX_REVEAL_TTL_SECS: u64 = 300;
const MAX_ROTATION_GRACE_TTL_SECS: u64 = 30 * 24 * 60 * 60;

const SUPPORTED_CONFIG_KEYS: &[&str] = &[
    UI_THEME,
    UI_DENSITY,
    PRIVACY_REDACT_NAMES,
    EDITOR_DEFAULT,
    AGENT_AUTOSTART,
    AGENT_UNLOCK_TTL,
    RUNTIME_SESSION_SECRET_NAME_RETENTION,
    REVEAL_TTL,
    ROTATION_MAX_GRACE_TTL,
    SHELL_INTEGRATION,
    UPDATES_CHANNEL,
    UPDATES_MANIFEST_URL,
    EXAMPLE_AUTO_REFRESH,
    RUN_REDACT_OUTPUT,
    VERIFICATION_UNLOCK,
    VERIFICATION_REVEAL,
    VERIFICATION_COPY,
    VERIFICATION_DANGEROUS_PROFILE_SWITCH,
    VERIFICATION_RECOVERY,
    VERIFICATION_TEAM_ACCEPT,
    VERIFICATION_DEVICE_REGISTER,
];

fn default_ui_theme() -> String {
    "system".to_owned()
}

fn default_ui_density() -> String {
    "comfortable".to_owned()
}

fn default_off() -> String {
    "off".to_owned()
}

const fn default_true() -> bool {
    true
}

fn default_run_redact_output() -> String {
    "auto".to_owned()
}
static CONFIG_WRITES: Mutex<()> = Mutex::new(());

fn lock_config() -> io::Result<MutexGuard<'static, ()>> {
    CONFIG_WRITES.lock().map_err(|_| io::Error::other("config write lock poisoned"))
}

pub fn requires_user_verification(
    user_config_path: Option<&Path>,
    store: Option<&Store>,
    project_id: &str,
    actions: &[&str],
) -> Result<bool, ConfigRpcError> {
    let config_requires = |config: &toml::Table| -> Result<bool, ConfigRpcError> {
        for action in actions {
            if bool_config_value(config, &format!("user_verification_required_for.{action}"))?
                == Some(true)
            {
                return Ok(true);
            }
        }
        Ok(false)
    };
    if let Some(path) = user_config_path
        && config_requires(&read_config_table(path)?)?
    {
        return Ok(true);
    }
    let Some(store) = store else { return Ok(false) };
    let stored: Option<String> = store
        .connection()
        .query_row(
            "SELECT user_verification_policy_json FROM projects WHERE id = ?1",
            [project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(locket_store::StoreError::from)?;
    if let Some(stored) = stored {
        let stored: serde_json::Value = serde_json::from_str(&stored).map_err(|_| {
            ConfigRpcError::MetadataInvalid("invalid project verification policy".into())
        })?;
        let settings = stored.get("user_verification_required_for").unwrap_or(&stored);
        for action in actions {
            match settings.get(action) {
                Some(serde_json::Value::Bool(true)) => return Ok(true),
                Some(serde_json::Value::Bool(false)) | None => {}
                Some(_) => {
                    return Err(ConfigRpcError::MetadataInvalid(
                        "invalid project verification setting".into(),
                    ));
                }
            }
        }
    }
    for root in store.list_project_roots(project_id)? {
        let Some(path) = root.display_path.and_then(|path| fs::canonicalize(path).ok()) else {
            continue;
        };
        let hash: [u8; 32] = Sha256::digest(path.to_string_lossy().as_bytes()).into();
        if hash == root.root_hash
            && config_requires(&read_config_table(&path.join("locket.toml"))?)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Request payload for `ReadConfig`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReadConfigRequest {
    /// User `config.toml` path to read.
    pub config_path: PathBuf,
    /// Optional store path used to read the active profile's dangerous marker.
    #[serde(default)]
    pub store_path: Option<PathBuf>,
    /// Project id for profile lookup.
    #[serde(default)]
    pub project_id: Option<String>,
    /// Profile name for profile lookup.
    #[serde(default)]
    pub profile_name: Option<String>,
}

/// Write payload for `WriteConfig`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WriteConfigRequest {
    /// User `config.toml` path to write.
    pub config_path: PathBuf,
    /// Store path used for audit rows and profile writes.
    pub store_path: PathBuf,
    /// Project id whose audit chain records the write.
    pub project_id: String,
    /// Profile name used when `dangerous_profile` is present.
    #[serde(default)]
    pub profile_name: Option<String>,
    /// Requested changes. Omitted fields are left untouched.
    #[serde(default)]
    pub changes: WriteConfigChanges,
}

/// Partial settings patch for `WriteConfig`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct WriteConfigChanges {
    /// Set `privacy.redact_names`.
    #[serde(default)]
    pub privacy_redact_names: Option<bool>,
    /// Set `ui.theme` (`system`, `light`, or `dark`).
    #[serde(default)]
    pub ui_theme: Option<String>,
    /// Set `ui.density` (`comfortable` or `compact`).
    #[serde(default)]
    pub ui_density: Option<String>,
    /// Set `editor.default` (command name or absolute path).
    #[serde(default)]
    pub editor_default: Option<String>,
    /// Set `agent.autostart`.
    #[serde(default)]
    pub agent_autostart: Option<bool>,
    /// Set `agent.unlock_ttl` to a duration string.
    #[serde(default)]
    pub agent_unlock_ttl: Option<String>,
    /// Set `runtime.session_secret_name_retention` (duration string or `off`).
    #[serde(default)]
    pub runtime_session_secret_name_retention: Option<String>,
    /// Set `reveal.ttl` (duration string, 5m or less).
    #[serde(default)]
    pub reveal_ttl: Option<String>,
    /// Set `rotation.max_grace_ttl` (duration string, 30d or less).
    #[serde(default)]
    pub rotation_max_grace_ttl: Option<String>,
    /// Set `shell.integration` (`off`, `prompt-only`, or `hook`).
    #[serde(default)]
    pub shell_integration: Option<String>,
    /// Set `updates.channel` (`off`, `stable`, or `beta`).
    #[serde(default)]
    pub updates_channel: Option<String>,
    /// Set `updates.manifest_url` (HTTPS URL).
    #[serde(default)]
    pub updates_manifest_url: Option<String>,
    /// Set `example.auto_refresh`.
    #[serde(default)]
    pub example_auto_refresh: Option<bool>,
    /// Set `run.redact_output` (`auto`, `always`, or `never`).
    #[serde(default)]
    pub run_redact_output: Option<String>,
    /// Set any user-verification policy booleans.
    #[serde(default)]
    pub user_verification_required_for: Option<UserVerificationSettings>,
    /// Config keys to remove from `config.toml` (reset to built-in default).
    #[serde(default)]
    pub unset_keys: Vec<String>,
    /// Set the selected profile's dangerous marker.
    #[serde(default)]
    pub dangerous_profile: Option<bool>,
}

/// User-verification gates represented by the config table.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserVerificationSettings {
    /// Require verification before unlock.
    #[serde(default)]
    pub unlock: Option<bool>,
    /// Require verification before reveal.
    #[serde(default)]
    pub reveal: Option<bool>,
    /// Require verification before copy.
    #[serde(default)]
    pub copy: Option<bool>,
    /// Require verification before dangerous-profile switch.
    #[serde(default)]
    pub dangerous_profile_switch: Option<bool>,
    /// Require verification before recovery.
    #[serde(default)]
    pub recovery: Option<bool>,
    /// Require verification before team invite acceptance.
    #[serde(default)]
    pub team_accept: Option<bool>,
    /// Require verification before device registration.
    #[serde(default)]
    pub device_register: Option<bool>,
}

/// Settings response payload shared by `ReadConfig` and `WriteConfig`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentConfigSettings {
    /// Effective `privacy.redact_names`; missing config defaults to false.
    pub privacy_redact_names: bool,
    /// Effective `ui.theme`; missing config defaults to `system`.
    #[serde(default = "default_ui_theme")]
    pub ui_theme: String,
    /// Effective `ui.density`; missing config defaults to `comfortable`.
    #[serde(default = "default_ui_density")]
    pub ui_density: String,
    /// Configured `editor.default`, if present.
    #[serde(default)]
    pub editor_default: Option<String>,
    /// Effective `agent.autostart`; missing config defaults to false.
    #[serde(default)]
    pub agent_autostart: bool,
    /// Configured `agent.unlock_ttl`, if present.
    pub agent_unlock_ttl: Option<String>,
    /// Configured `runtime.session_secret_name_retention`, if present.
    #[serde(default)]
    pub runtime_session_secret_name_retention: Option<String>,
    /// Configured `reveal.ttl`, if present.
    #[serde(default)]
    pub reveal_ttl: Option<String>,
    /// Configured `rotation.max_grace_ttl`, if present.
    #[serde(default)]
    pub rotation_max_grace_ttl: Option<String>,
    /// Effective `shell.integration`; missing config defaults to `off`.
    #[serde(default = "default_off")]
    pub shell_integration: String,
    /// Effective `updates.channel`; missing config defaults to `off`.
    #[serde(default = "default_off")]
    pub updates_channel: String,
    /// Configured `updates.manifest_url`, if present.
    #[serde(default)]
    pub updates_manifest_url: Option<String>,
    /// Effective `example.auto_refresh`; missing config defaults to true.
    #[serde(default = "default_true")]
    pub example_auto_refresh: bool,
    /// Effective `run.redact_output`; missing config defaults to `auto`.
    #[serde(default = "default_run_redact_output")]
    pub run_redact_output: String,
    /// Effective user-verification gates; missing keys default to false.
    pub user_verification_required_for: EffectiveUserVerificationSettings,
    /// Dangerous marker for the requested profile, when profile context was supplied.
    pub dangerous_profile: Option<DangerousProfileSetting>,
}

/// Effective user-verification gate values.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EffectiveUserVerificationSettings {
    /// Effective `unlock` gate.
    pub unlock: bool,
    /// Effective `reveal` gate.
    pub reveal: bool,
    /// Effective `copy` gate.
    pub copy: bool,
    /// Effective `dangerous_profile_switch` gate.
    pub dangerous_profile_switch: bool,
    /// Effective `recovery` gate.
    pub recovery: bool,
    /// Effective `team_accept` gate.
    pub team_accept: bool,
    /// Effective `device_register` gate.
    pub device_register: bool,
}

/// Dangerous-profile metadata for the requested profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DangerousProfileSetting {
    /// Profile id.
    pub profile_id: String,
    /// Profile name. This is metadata, never a secret value.
    pub profile_name: String,
    /// Privacy-aware display label for profile surfaces.
    pub profile_label: String,
    /// Current dangerous marker.
    pub dangerous: bool,
}

/// Response payload for `WriteConfig`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WriteConfigResponse {
    /// Settings after the write.
    pub settings: AgentConfigSettings,
    /// Config or profile fields supplied by the write request.
    pub changed_keys: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigRpcError {
    #[error("{0}")]
    Protocol(String),
    #[error("{0}")]
    MetadataInvalid(String),
    #[error("unlock required")]
    UnlockRequired,
    #[error("profile not found")]
    ProfileNotFound,
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Store(#[from] locket_store::StoreError),
    #[error(transparent)]
    StoreIdentity(#[from] crate::keys::StoreIdentityError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Platform(#[from] locket_platform::PlatformError),
    #[error(transparent)]
    TomlDeserialize(#[from] toml::de::Error),
    #[error(transparent)]
    TomlSerialize(#[from] toml::ser::Error),
}

impl ConfigRpcError {
    fn error_name(&self) -> &'static str {
        match self {
            Self::Protocol(_) => "ProtocolError",
            Self::MetadataInvalid(_)
            | Self::Io(_)
            | Self::Platform(_)
            | Self::TomlDeserialize(_)
            | Self::TomlSerialize(_) => "MetadataInvalid",
            Self::UnlockRequired => "UnlockRequired",
            Self::ProfileNotFound => "ProfileNotFound",
            Self::Key(_) => "AuditIntegrityFailed",
            Self::StoreIdentity(_) => "AccessDenied",
            Self::Store(error) => match error.locket_error() {
                locket_core::LocketError::StorageBusy => "StorageBusy",
                locket_core::LocketError::SchemaNewerThanBinary => "SchemaNewerThanBinary",
                locket_core::LocketError::AuditIntegrityFailed => "AuditIntegrityFailed",
                locket_core::LocketError::MetadataInvalid => "MetadataInvalid",
                _ => "CorruptDb",
            },
        }
    }
}

/// Handles a `ReadConfig` request.
pub async fn handle_read_config(
    request: &RequestEnvelope,
    state: &crate::AgentSocketState,
) -> ResponseEnvelope {
    let payload: ReadConfigRequest = match serde_json::from_value(request.payload.clone()) {
        Ok(payload) => payload,
        Err(_) => {
            return error_response(request, "ProtocolError", "invalid ReadConfig payload");
        }
    };
    match read_settings(&payload, state).await {
        Ok(settings) => success_response(request, settings),
        Err(error) => error_response(request, error.error_name(), error.to_string()),
    }
}

/// Handles a `WriteConfig` request.
pub async fn handle_write_config(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
) -> ResponseEnvelope {
    let payload: WriteConfigRequest = match serde_json::from_value(request.payload.clone()) {
        Ok(payload) => payload,
        Err(_) => {
            return error_response(request, "ProtocolError", "invalid WriteConfig payload");
        }
    };
    let now = crate::server::current_unix_nanos();
    match write_settings(&payload, state, now).await {
        Ok(response) => success_response(request, response),
        Err(error) => error_response(request, error.error_name(), error.to_string()),
    }
}

fn success_response<T: Serialize>(request: &RequestEnvelope, payload: T) -> ResponseEnvelope {
    let payload = serde_json::to_value(payload).unwrap_or(serde_json::Value::Null);
    ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), payload))
}

fn error_response(
    request: &RequestEnvelope,
    error: &str,
    message: impl Into<String>,
) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), error, message, false))
}

async fn read_settings(
    request: &ReadConfigRequest,
    state: &crate::AgentSocketState,
) -> Result<AgentConfigSettings, ConfigRpcError> {
    let store = if let (Some(path), Some(project_id), Some(_)) = (
        request.store_path.as_deref(),
        request.project_id.as_deref(),
        request.profile_name.as_deref(),
    ) {
        Some(
            crate::keys::open_verified_store_for_state_with(
                state,
                project_id,
                path,
                crate::server::current_unix_nanos(),
                true,
            )
            .await?
            .0,
        )
    } else {
        None
    };
    let _guard = lock_config()?;
    let config = read_config_table(&request.config_path)?;
    settings_from_config(
        &config,
        store.as_ref(),
        request.project_id.as_deref(),
        request.profile_name.as_deref(),
    )
}

async fn write_settings(
    request: &WriteConfigRequest,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> Result<WriteConfigResponse, ConfigRpcError> {
    let timestamp = i64::try_from(now_unix_nanos).unwrap_or(i64::MAX);
    let master_key = cached_master_key(state, &request.project_id, now_unix_nanos)
        .await?
        .ok_or(ConfigRpcError::UnlockRequired)?;
    let (mut store, _) = crate::keys::open_verified_store_for_state(
        state,
        &request.project_id,
        &request.store_path,
        now_unix_nanos,
    )
    .await?;
    let audit_key = unwrap_audit_key_with_master(&store, &request.project_id, &master_key)?;

    // The user config is shared across projects. Serialize agent reads and
    // writes across publication, audit commit, and any rollback.
    let _guard = lock_config()?;
    let config_path = match fs::symlink_metadata(&request.config_path) {
        Ok(metadata) if metadata.is_symlink() => fs::canonicalize(&request.config_path)?,
        _ => request.config_path.clone(),
    };
    let previous = read_config_text(&config_path)?;
    let mut config = toml::from_str(previous.as_deref().unwrap_or_default())?;
    let mut changed_keys = apply_settings_patch(&mut config, &request.changes)?;
    let profile_change = request
        .changes
        .dangerous_profile
        .map(|dangerous| {
            let name = request.profile_name.as_deref().ok_or_else(|| {
                ConfigRpcError::Protocol(
                    "profile_name is required for dangerous_profile".to_owned(),
                )
            })?;
            Ok::<_, ConfigRpcError>((name, dangerous))
        })
        .transpose()?;
    let settings_changed = !changed_keys.is_empty();
    let mut attempted_file_write = false;
    let result = store.with_atomic_write(|store| {
        for key in &changed_keys {
            append_config_update_audit(
                store,
                &request.project_id,
                &request.config_path,
                key,
                audit_key.as_ref(),
                timestamp,
            )?;
        }
        if let Some((name, dangerous)) = profile_change {
            update_profile_dangerous(
                store,
                &request.project_id,
                name,
                dangerous,
                audit_key.as_ref(),
                timestamp,
            )?;
            changed_keys.push("profile.dangerous".to_owned());
        }
        let settings = settings_from_config(
            &config,
            Some(store),
            Some(&request.project_id),
            request.profile_name.as_deref(),
        )?;
        if settings_changed {
            let text = toml::to_string_pretty(&config)?;
            attempted_file_write = true;
            write_config_file(&config_path, &text)?;
        }
        Ok(WriteConfigResponse { settings, changed_keys })
    });
    if let Err(error) = &result
        && attempted_file_write
        && read_config_text(&config_path).as_ref().ok() != Some(&previous)
        && let Err(rollback) = restore_config_file(&config_path, previous.as_deref())
    {
        return Err(io::Error::other(format!("{error}; config rollback failed: {rollback}")).into());
    }
    result
}

fn apply_settings_patch(
    config: &mut toml::Table,
    changes: &WriteConfigChanges,
) -> Result<Vec<String>, ConfigRpcError> {
    let mut changed_keys = Vec::new();
    apply_enum_patches(config, &mut changed_keys, changes)?;
    apply_scalar_patches(config, &mut changed_keys, changes)?;
    apply_verification_patch(
        config,
        &mut changed_keys,
        changes.user_verification_required_for.as_ref(),
    )?;
    apply_unset_keys(config, &mut changed_keys, &changes.unset_keys)?;
    Ok(changed_keys)
}

fn apply_enum_patches(
    config: &mut toml::Table,
    changed_keys: &mut Vec<String>,
    changes: &WriteConfigChanges,
) -> Result<(), ConfigRpcError> {
    let enum_fields: [(&str, Option<&str>, &[&str], &str); 5] = [
        (
            UI_THEME,
            changes.ui_theme.as_deref(),
            UI_THEME_VALUES,
            "ui.theme must be system, light, or dark",
        ),
        (
            UI_DENSITY,
            changes.ui_density.as_deref(),
            UI_DENSITY_VALUES,
            "ui.density must be comfortable or compact",
        ),
        (
            SHELL_INTEGRATION,
            changes.shell_integration.as_deref(),
            SHELL_INTEGRATION_VALUES,
            "shell.integration must be off, prompt-only, or hook",
        ),
        (
            UPDATES_CHANNEL,
            changes.updates_channel.as_deref(),
            UPDATES_CHANNEL_VALUES,
            "updates.channel must be off, stable, or beta",
        ),
        (
            RUN_REDACT_OUTPUT,
            changes.run_redact_output.as_deref(),
            OutputRedaction::VALUES,
            "run.redact_output must be auto, always, or never",
        ),
    ];
    for (key, value, allowed, message) in enum_fields {
        push_string_patch(config, changed_keys, key, value, |item| {
            validate_enum(item, allowed, message)
        })?;
    }
    Ok(())
}

fn apply_scalar_patches(
    config: &mut toml::Table,
    changed_keys: &mut Vec<String>,
    changes: &WriteConfigChanges,
) -> Result<(), ConfigRpcError> {
    push_bool_patch(config, changed_keys, PRIVACY_REDACT_NAMES, changes.privacy_redact_names)?;
    push_bool_patch(config, changed_keys, AGENT_AUTOSTART, changes.agent_autostart)?;
    push_bool_patch(config, changed_keys, EXAMPLE_AUTO_REFRESH, changes.example_auto_refresh)?;
    push_string_patch(
        config,
        changed_keys,
        EDITOR_DEFAULT,
        changes.editor_default.as_deref(),
        |v| {
            validate_not_secret_like(v)?;
            validate_editor_default(v)
        },
    )?;
    push_string_patch(
        config,
        changed_keys,
        AGENT_UNLOCK_TTL,
        changes.agent_unlock_ttl.as_deref(),
        validate_duration,
    )?;
    push_string_patch(
        config,
        changed_keys,
        RUNTIME_SESSION_SECRET_NAME_RETENTION,
        changes.runtime_session_secret_name_retention.as_deref(),
        validate_session_retention,
    )?;
    push_string_patch(config, changed_keys, REVEAL_TTL, changes.reveal_ttl.as_deref(), |v| {
        validate_duration_max(v, MAX_REVEAL_TTL_SECS, "reveal.ttl must be 5m or less")
    })?;
    push_string_patch(
        config,
        changed_keys,
        ROTATION_MAX_GRACE_TTL,
        changes.rotation_max_grace_ttl.as_deref(),
        |v| {
            validate_duration_max(
                v,
                MAX_ROTATION_GRACE_TTL_SECS,
                "rotation.max_grace_ttl must be 30d or less",
            )
        },
    )?;
    push_string_patch(
        config,
        changed_keys,
        UPDATES_MANIFEST_URL,
        changes.updates_manifest_url.as_deref(),
        |v| {
            validate_not_secret_like(v)?;
            validate_https_url(v)
        },
    )?;
    Ok(())
}

fn push_string_patch(
    config: &mut toml::Table,
    changed_keys: &mut Vec<String>,
    key: &str,
    value: Option<&str>,
    validate: impl FnOnce(&str) -> Result<(), ConfigRpcError>,
) -> Result<(), ConfigRpcError> {
    if let Some(value) = value {
        validate(value)?;
        set_config_value(config, key, toml::Value::String(value.to_owned()))?;
        changed_keys.push(key.to_owned());
    }
    Ok(())
}

fn apply_verification_patch(
    config: &mut toml::Table,
    changed_keys: &mut Vec<String>,
    verification: Option<&UserVerificationSettings>,
) -> Result<(), ConfigRpcError> {
    let Some(verification) = verification else {
        return Ok(());
    };
    push_bool_patch(config, changed_keys, VERIFICATION_UNLOCK, verification.unlock)?;
    push_bool_patch(config, changed_keys, VERIFICATION_REVEAL, verification.reveal)?;
    push_bool_patch(config, changed_keys, VERIFICATION_COPY, verification.copy)?;
    push_bool_patch(
        config,
        changed_keys,
        VERIFICATION_DANGEROUS_PROFILE_SWITCH,
        verification.dangerous_profile_switch,
    )?;
    push_bool_patch(config, changed_keys, VERIFICATION_RECOVERY, verification.recovery)?;
    push_bool_patch(config, changed_keys, VERIFICATION_TEAM_ACCEPT, verification.team_accept)?;
    push_bool_patch(
        config,
        changed_keys,
        VERIFICATION_DEVICE_REGISTER,
        verification.device_register,
    )?;
    Ok(())
}

fn apply_unset_keys(
    config: &mut toml::Table,
    changed_keys: &mut Vec<String>,
    unset_keys: &[String],
) -> Result<(), ConfigRpcError> {
    for key in unset_keys {
        if !SUPPORTED_CONFIG_KEYS.contains(&key.as_str()) {
            return Err(ConfigRpcError::Protocol("unsupported config key".to_owned()));
        }
        unset_config_value(config, key)?;
        if !changed_keys.iter().any(|existing| existing == key) {
            changed_keys.push(key.clone());
        }
    }
    Ok(())
}

fn update_profile_dangerous(
    store: &mut Store,
    project_id: &str,
    name: &str,
    dangerous: bool,
    audit_key: &[u8],
    timestamp: i64,
) -> Result<(), ConfigRpcError> {
    // The standalone audited setter starts its own SQLite transaction.
    // Compose the update and the same audit row in the caller's savepoint.
    let profile =
        store.get_profile_by_name(project_id, name)?.ok_or(ConfigRpcError::ProfileNotFound)?;
    if !store.set_profile_dangerous(project_id, name, dangerous)? {
        return Err(ConfigRpcError::ProfileNotFound);
    }
    let metadata = json!({
        "schema_version": 1,
        "action": "PROFILE_CHANGE",
        "status": "SUCCESS",
        "command": "agent config",
        "operation": "set_dangerous",
        "profile_id": profile.id,
        "profile_name": profile.name,
        "prior_dangerous": profile.dangerous,
        "new_dangerous": dangerous,
    });
    store.append_audit(
        audit_key,
        &AuditWrite {
            project_id,
            profile_id: Some(&profile.id),
            action: "PROFILE_CHANGE",
            status: "SUCCESS",
            secret_name: None,
            command: Some("agent config"),
            metadata_json: &metadata,
            timestamp,
        },
    )?;
    Ok(())
}

fn push_bool_patch(
    config: &mut toml::Table,
    changed_keys: &mut Vec<String>,
    key: &str,
    value: Option<bool>,
) -> Result<(), ConfigRpcError> {
    if let Some(value) = value {
        set_config_value(config, key, toml::Value::Boolean(value))?;
        changed_keys.push(key.to_owned());
    }
    Ok(())
}

fn append_config_update_audit(
    store: &mut Store,
    project_id: &str,
    config_path: &Path,
    key: &str,
    audit_key: &[u8],
    timestamp: i64,
) -> Result<(), ConfigRpcError> {
    let digest = Sha256::digest(config_path.to_string_lossy().as_bytes());
    let path_hash: String =
        digest.iter().fold(String::with_capacity(digest.len() * 2), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
    let metadata = json!({
        "schema_version": 1,
        "action": "CONFIG_UPDATE",
        "status": "SUCCESS",
        "command": "agent config",
        "config_path_hash": path_hash,
        "config_keys": [key],
        "updated_field_count": 1,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "CONFIG_UPDATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("agent config"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key, &audit)?;
    Ok(())
}

fn settings_from_config(
    config: &toml::Table,
    store: Option<&Store>,
    project_id: Option<&str>,
    profile_name: Option<&str>,
) -> Result<AgentConfigSettings, ConfigRpcError> {
    let privacy_redact_names = bool_config_value(config, PRIVACY_REDACT_NAMES)?.unwrap_or(false);
    let ui_theme = enum_config_value(
        config,
        UI_THEME,
        UI_THEME_VALUES,
        "ui.theme must be system, light, or dark",
    )?
    .unwrap_or_else(default_ui_theme);
    let ui_density = enum_config_value(
        config,
        UI_DENSITY,
        UI_DENSITY_VALUES,
        "ui.density must be comfortable or compact",
    )?
    .unwrap_or_else(default_ui_density);
    let editor_default = string_config_value(config, EDITOR_DEFAULT, |value| {
        validate_editor_default(value)?;
        Ok(())
    })?;
    let agent_autostart = bool_config_value(config, AGENT_AUTOSTART)?.unwrap_or(false);
    let agent_unlock_ttl = duration_config_value(config, AGENT_UNLOCK_TTL)?;
    let runtime_session_secret_name_retention = string_config_value(
        config,
        RUNTIME_SESSION_SECRET_NAME_RETENTION,
        validate_session_retention,
    )?;
    let reveal_ttl = string_config_value(config, REVEAL_TTL, |value| {
        validate_duration_max(value, MAX_REVEAL_TTL_SECS, "reveal.ttl must be 5m or less")
    })?;
    let rotation_max_grace_ttl = string_config_value(config, ROTATION_MAX_GRACE_TTL, |value| {
        validate_duration_max(
            value,
            MAX_ROTATION_GRACE_TTL_SECS,
            "rotation.max_grace_ttl must be 30d or less",
        )
    })?;
    let shell_integration = enum_config_value(
        config,
        SHELL_INTEGRATION,
        SHELL_INTEGRATION_VALUES,
        "shell.integration must be off, prompt-only, or hook",
    )?
    .unwrap_or_else(default_off);
    let updates_channel = enum_config_value(
        config,
        UPDATES_CHANNEL,
        UPDATES_CHANNEL_VALUES,
        "updates.channel must be off, stable, or beta",
    )?
    .unwrap_or_else(default_off);
    let updates_manifest_url =
        string_config_value(config, UPDATES_MANIFEST_URL, validate_https_url)?;
    let example_auto_refresh = bool_config_value(config, EXAMPLE_AUTO_REFRESH)?.unwrap_or(true);
    let run_redact_output = enum_config_value(
        config,
        RUN_REDACT_OUTPUT,
        OutputRedaction::VALUES,
        "run.redact_output must be auto, always, or never",
    )?
    .unwrap_or_else(default_run_redact_output);
    let user_verification_required_for = EffectiveUserVerificationSettings {
        unlock: bool_config_value(config, VERIFICATION_UNLOCK)?.unwrap_or(false),
        reveal: bool_config_value(config, VERIFICATION_REVEAL)?.unwrap_or(false),
        copy: bool_config_value(config, VERIFICATION_COPY)?.unwrap_or(false),
        dangerous_profile_switch: bool_config_value(config, VERIFICATION_DANGEROUS_PROFILE_SWITCH)?
            .unwrap_or(false),
        recovery: bool_config_value(config, VERIFICATION_RECOVERY)?.unwrap_or(false),
        team_accept: bool_config_value(config, VERIFICATION_TEAM_ACCEPT)?.unwrap_or(false),
        device_register: bool_config_value(config, VERIFICATION_DEVICE_REGISTER)?.unwrap_or(false),
    };
    let dangerous_profile =
        dangerous_profile_setting(store, project_id, profile_name, privacy_redact_names)?;

    Ok(AgentConfigSettings {
        privacy_redact_names,
        ui_theme,
        ui_density,
        editor_default,
        agent_autostart,
        agent_unlock_ttl,
        runtime_session_secret_name_retention,
        reveal_ttl,
        rotation_max_grace_ttl,
        shell_integration,
        updates_channel,
        updates_manifest_url,
        example_auto_refresh,
        run_redact_output,
        user_verification_required_for,
        dangerous_profile,
    })
}

fn dangerous_profile_setting(
    store: Option<&Store>,
    project_id: Option<&str>,
    profile_name: Option<&str>,
    redact_names: bool,
) -> Result<Option<DangerousProfileSetting>, ConfigRpcError> {
    let (Some(store), Some(project_id), Some(profile_name)) = (store, project_id, profile_name)
    else {
        return Ok(None);
    };
    let Some(profile) = store.get_profile_by_name(project_id, profile_name)? else {
        return Err(ConfigRpcError::ProfileNotFound);
    };
    let profile_label =
        if redact_names { privacy_alias("profile", &profile.id) } else { profile.name.clone() };
    Ok(Some(DangerousProfileSetting {
        profile_id: profile.id,
        profile_name: profile.name,
        profile_label,
        dangerous: profile.dangerous,
    }))
}

fn read_config_table(path: &Path) -> Result<toml::Table, ConfigRpcError> {
    Ok(toml::from_str(read_config_text(path)?.as_deref().unwrap_or_default())?)
}

fn read_config_text(path: &Path) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn write_config_file(path: &Path, text: &str) -> Result<(), ConfigRpcError> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    write_user_only_file(path, text.as_bytes())?;
    Ok(())
}

fn restore_config_file(path: &Path, previous: Option<&str>) -> Result<(), ConfigRpcError> {
    if let Some(previous) = previous {
        write_config_file(path, previous)
    } else {
        fs::remove_file(path)?;
        Ok(())
    }
}

fn bool_config_value(config: &toml::Table, key: &str) -> Result<Option<bool>, ConfigRpcError> {
    let Some(value) = config_value(config, key)? else {
        return Ok(None);
    };
    value
        .as_bool()
        .ok_or_else(|| {
            ConfigRpcError::MetadataInvalid(format!("invalid stored config value for {key}"))
        })
        .map(Some)
}

fn duration_config_value(
    config: &toml::Table,
    key: &str,
) -> Result<Option<String>, ConfigRpcError> {
    string_config_value(config, key, validate_duration)
}

fn string_config_value(
    config: &toml::Table,
    key: &str,
    validate: impl FnOnce(&str) -> Result<(), ConfigRpcError>,
) -> Result<Option<String>, ConfigRpcError> {
    let Some(value) = config_value(config, key)? else {
        return Ok(None);
    };
    let value = value.as_str().ok_or_else(|| {
        ConfigRpcError::MetadataInvalid(format!("invalid stored config value for {key}"))
    })?;
    validate(value)?;
    Ok(Some(value.to_owned()))
}

fn enum_config_value(
    config: &toml::Table,
    key: &str,
    values: &[&str],
    message: &str,
) -> Result<Option<String>, ConfigRpcError> {
    string_config_value(config, key, |value| validate_enum(value, values, message))
}

fn validate_enum(value: &str, values: &[&str], message: &str) -> Result<(), ConfigRpcError> {
    if values.contains(&value) {
        Ok(())
    } else {
        Err(ConfigRpcError::MetadataInvalid(message.to_owned()))
    }
}

fn validate_duration(value: &str) -> Result<(), ConfigRpcError> {
    LocketDuration::from_str(value)
        .map(|_| ())
        .map_err(|_| ConfigRpcError::MetadataInvalid("invalid config duration".to_owned()))
}

fn validate_duration_max(value: &str, max_secs: u64, message: &str) -> Result<(), ConfigRpcError> {
    let duration = LocketDuration::from_str(value)
        .map_err(|_| ConfigRpcError::MetadataInvalid("invalid config duration".to_owned()))?;
    if duration.as_secs() > max_secs {
        return Err(ConfigRpcError::MetadataInvalid(message.to_owned()));
    }
    Ok(())
}

fn validate_session_retention(value: &str) -> Result<(), ConfigRpcError> {
    RuntimeSessionSecretNameRetention::from_str(value).map(|_| ()).map_err(|_| {
        ConfigRpcError::MetadataInvalid(
            "runtime.session_secret_name_retention must be a duration or off".to_owned(),
        )
    })
}

fn validate_editor_default(value: &str) -> Result<(), ConfigRpcError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(ConfigRpcError::MetadataInvalid(
            "editor.default must be a command name or absolute path".to_owned(),
        ));
    }
    if value.starts_with('~') || value.contains('$') || value.contains('`') {
        return Err(ConfigRpcError::MetadataInvalid(
            "editor.default must not use shell expansion".to_owned(),
        ));
    }
    if Path::new(value).is_absolute() {
        return Ok(());
    }
    let shell_meta = ['/', '\\', '|', '&', ';', '<', '>', '(', ')'];
    if value.chars().any(char::is_whitespace) || value.chars().any(|c| shell_meta.contains(&c)) {
        return Err(ConfigRpcError::MetadataInvalid(
            "editor.default must be a command name or absolute path".to_owned(),
        ));
    }
    Ok(())
}

fn validate_https_url(value: &str) -> Result<(), ConfigRpcError> {
    let Some(rest) = value.strip_prefix("https://") else {
        return Err(ConfigRpcError::MetadataInvalid(
            "updates.manifest_url must be an HTTPS URL".to_owned(),
        ));
    };
    if rest.is_empty()
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(ConfigRpcError::MetadataInvalid(
            "updates.manifest_url must be an HTTPS URL".to_owned(),
        ));
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.starts_with(':') || host.contains('@') {
        return Err(ConfigRpcError::MetadataInvalid(
            "updates.manifest_url must be an HTTPS URL".to_owned(),
        ));
    }
    Ok(())
}

fn validate_not_secret_like(value: &str) -> Result<(), ConfigRpcError> {
    let secret_like = scan_text("config.toml", value).iter().any(|finding| {
        matches!(finding.kind, FindingKind::HighEntropy | FindingKind::ProviderTokenPattern)
    });
    if secret_like {
        return Err(ConfigRpcError::MetadataInvalid(
            "config value looks like a secret; refusing to store it".to_owned(),
        ));
    }
    Ok(())
}

fn unset_config_value(config: &mut toml::Table, key: &str) -> Result<(), ConfigRpcError> {
    let (section, name) = split_config_key(key)?;
    let Some(section_value) = config.get_mut(section) else {
        return Ok(());
    };
    let Some(section_table) = section_value.as_table_mut() else {
        return Err(ConfigRpcError::MetadataInvalid("config section is not a table".to_owned()));
    };
    section_table.remove(name);
    if section_table.is_empty() {
        config.remove(section);
    }
    Ok(())
}

fn config_value<'a>(
    config: &'a toml::Table,
    key: &str,
) -> Result<Option<&'a toml::Value>, ConfigRpcError> {
    let (section, name) = split_config_key(key)?;
    let Some(section_value) = config.get(section) else {
        return Ok(None);
    };
    let Some(section_table) = section_value.as_table() else {
        return Err(ConfigRpcError::MetadataInvalid("config section is not a table".to_owned()));
    };
    Ok(section_table.get(name))
}

fn set_config_value(
    config: &mut toml::Table,
    key: &str,
    value: toml::Value,
) -> Result<(), ConfigRpcError> {
    let (section, name) = split_config_key(key)?;
    let section_value =
        config.entry(section.to_owned()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let Some(section_table) = section_value.as_table_mut() else {
        return Err(ConfigRpcError::MetadataInvalid("config section is not a table".to_owned()));
    };
    section_table.insert(name.to_owned(), value);
    Ok(())
}

fn split_config_key(key: &str) -> Result<(&str, &str), ConfigRpcError> {
    let Some((section, name)) = key.split_once('.') else {
        return Err(ConfigRpcError::Protocol("unsupported config key".to_owned()));
    };
    if section.is_empty() || name.is_empty() || name.contains('.') {
        return Err(ConfigRpcError::Protocol("unsupported config key".to_owned()));
    }
    Ok((section, name))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use std::time::Duration;

    use locket_store::Store;
    use serde_json::Value;
    use tempfile::tempdir;

    use super::*;
    use crate::envelope::RequestEnvelope;
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, current_unix_nanos, dispatch};
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};

    fn initialized_store(path: &Path) -> Store {
        let mut store = Store::open(path).expect("open store");
        store.initialize_schema().expect("initialize schema");
        store.insert_project_if_absent("lk_proj_test", "test", 100).expect("insert project");
        store
            .insert_profile_if_absent("lk_prof_default", "lk_proj_test", "default", false, 200)
            .expect("insert profile");
        crate::tests::insert_wrapped_audit_key(&store, "lk_proj_test", &[42; 32], &[11; 32])
            .expect("wrap audit key");
        store
    }

    #[tokio::test]
    async fn invalid_stored_config_types_return_redacted_errors_without_rewriting_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("config.toml");
        let state = AgentSocketState::locked("test");
        let read =
            RequestEnvelope::new("read", AgentMethod::ReadConfig, json!({"config_path": path}));
        let canary = "config-secret-canary";
        for (contents, expected) in [
            (format!("privacy = '{canary}'\n"), "config section is not a table"),
            (
                format!("[privacy]\nredact_names = '{canary}'\n"),
                "invalid stored config value for privacy.redact_names",
            ),
            (
                "[agent]\nunlock_ttl = 30\n".to_owned(),
                "invalid stored config value for agent.unlock_ttl",
            ),
            (format!("[agent]\nunlock_ttl = '{canary}'\n"), "invalid config duration"),
        ] {
            fs::write(&path, &contents)?;
            assert!(matches!(dispatch(&read, &state).await, ResponseEnvelope::Error(error)
                if error.error == "MetadataInvalid" && error.message == expected
                    && !error.message.contains(canary)));
            assert_eq!(fs::read_to_string(&path)?, contents);
        }
        Ok(())
    }

    #[tokio::test]
    async fn read_config_defaults_missing_values() {
        let directory = tempdir().expect("tempdir");
        let request = ReadConfigRequest {
            config_path: directory.path().join("missing.toml"),
            store_path: None,
            project_id: None,
            profile_name: None,
        };

        let settings = read_settings(&request, &crate::AgentSocketState::locked("test"))
            .await
            .expect("read settings");

        assert!(!settings.privacy_redact_names);
        assert!(settings.agent_unlock_ttl.is_none());
        assert_eq!(
            settings.user_verification_required_for,
            EffectiveUserVerificationSettings::default()
        );
        assert!(settings.dangerous_profile.is_none());
    }

    #[tokio::test]
    async fn read_config_applies_privacy_alias_to_profile_label() {
        let directory = tempdir().expect("tempdir");
        let config_path = directory.path().join("config.toml");
        let store_path = directory.path().join("store.db");
        fs::write(&config_path, "[privacy]\nredact_names = true\n").expect("write config");
        let _store = initialized_store(&store_path);
        let request = ReadConfigRequest {
            config_path,
            store_path: Some(store_path),
            project_id: Some("lk_proj_test".to_owned()),
            profile_name: Some("default".to_owned()),
        };

        let settings = read_settings(&request, &crate::AgentSocketState::locked("test"))
            .await
            .expect("read settings");
        let dangerous = settings.dangerous_profile.expect("dangerous profile");

        assert_eq!(dangerous.profile_name, "default");
        assert!(dangerous.profile_label.starts_with("profile-"));
        assert!(!dangerous.dangerous);
    }

    #[tokio::test]
    async fn read_config_returns_profile_not_found_for_missing_profile_context() {
        let directory = tempdir().expect("tempdir");
        let config_path = directory.path().join("config.toml");
        let store_path = directory.path().join("store.db");
        fs::write(&config_path, "").expect("write config");
        let _store = initialized_store(&store_path);
        let request = RequestEnvelope::new(
            "req-1",
            AgentMethod::ReadConfig,
            json!({
                "config_path": config_path,
                "store_path": store_path,
                "project_id": "lk_proj_test",
                "profile_name": "missing"
            }),
        );

        let ResponseEnvelope::Error(error) =
            handle_read_config(&request, &crate::AgentSocketState::locked("test")).await
        else {
            panic!("missing profile should fail");
        };

        assert_eq!(error.error, "ProfileNotFound");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_config_requires_unlock_before_touching_file() {
        let directory = tempdir().expect("tempdir");
        let config_path = directory.path().join("config.toml");
        let store_path = directory.path().join("store.db");
        let _store = initialized_store(&store_path);
        let state = AgentSocketState::locked("test-version");
        let request = RequestEnvelope::new(
            "req-1",
            AgentMethod::WriteConfig,
            json!({
                "config_path": config_path,
                "store_path": store_path,
                "project_id": "lk_proj_test",
                "changes": {
                    "privacy_redact_names": true
                }
            }),
        );

        let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
            panic!("locked config write should fail");
        };

        assert_eq!(error.error, "UnlockRequired");
        assert!(!config_path.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_config_rejects_missing_profile_name_for_dangerous_update() {
        let directory = tempdir().expect("tempdir");
        let config_path = directory.path().join("config.toml");
        let store_path = directory.path().join("store.db");
        let store = initialized_store(&store_path);
        let state = AgentSocketState::locked("test-version");
        state.unlock_cache.lock().await.insert(
            "lk_proj_test".to_owned(),
            UnlockEntry::new(
                vec![42; 32],
                current_unix_nanos(),
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        let request = RequestEnvelope::new(
            "req-1",
            AgentMethod::WriteConfig,
            json!({
                "config_path": config_path,
                "store_path": store_path,
                "project_id": "lk_proj_test",
                "changes": {
                    "privacy_redact_names": true,
                    "dangerous_profile": true
                }
            }),
        );

        let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
            panic!("missing profile_name should fail");
        };

        assert_eq!(error.error, "ProtocolError");
        assert!(!config_path.exists());
        assert_eq!(
            store.list_recent_audit_actions("lk_proj_test", 10).expect("audit actions"),
            Vec::<String>::new()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_config_rolls_back_when_profile_audit_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let config_path = directory.path().join("config.toml");
        let store_path = directory.path().join("store.db");
        let store = initialized_store(&store_path);
        let original = "# preserve this comment\n[privacy]\nredact_names = false\n";
        fs::write(&config_path, original)?;
        let state = AgentSocketState::locked("test-version");
        let now = current_unix_nanos();
        state.unlock_cache.lock().await.insert(
            "lk_proj_test".to_owned(),
            UnlockEntry::new(vec![42; 32], now, Duration::from_secs(60), UnlockMethod::Passphrase),
        );
        let request = WriteConfigRequest {
            config_path: config_path.clone(),
            store_path,
            project_id: "lk_proj_test".to_owned(),
            profile_name: Some("default".to_owned()),
            changes: serde_json::from_value(
                json!({"privacy_redact_names": true, "dangerous_profile": true}),
            )?,
        };
        for (trigger, expected_error) in [
            (
                "CREATE TRIGGER deny_profile_audit BEFORE INSERT ON audit_log
                 WHEN NEW.action = 'PROFILE_CHANGE' BEGIN SELECT RAISE(ABORT, 'fixture denied'); END",
                "fixture denied",
            ),
            (
                "CREATE TABLE deferred_config (project_id TEXT REFERENCES projects(id) DEFERRABLE INITIALLY DEFERRED);
                 CREATE TRIGGER deny_profile_audit AFTER INSERT ON audit_log WHEN NEW.action = 'PROFILE_CHANGE'
                 BEGIN INSERT INTO deferred_config VALUES ('missing project'); END;",
                "FOREIGN KEY constraint failed",
            ),
        ] {
            store.connection().execute_batch(trigger)?;
            let Err(error) = write_settings(&request, &state, now).await else {
                panic!("expected {expected_error}");
            };
            assert!(error.to_string().contains(expected_error), "{error}");
            assert_eq!(fs::read_to_string(&config_path)?, original);
            assert!(!store.get_profile_by_name("lk_proj_test", "default")?.ok_or("profile")?.dangerous);
            assert_eq!(store.list_recent_audit_actions("lk_proj_test", 10)?, Vec::<String>::new());
            store.connection().execute_batch("DROP TRIGGER deny_profile_audit")?;
        }
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_config_updates_file_permissions_and_audit_rows() {
        let directory = tempdir().expect("tempdir");
        let config_path = directory.path().join("config.toml");
        let store_path = directory.path().join("store.db");
        let _store = initialized_store(&store_path);
        let state = AgentSocketState::locked("test-version");
        state.unlock_cache.lock().await.insert(
            "lk_proj_test".to_owned(),
            UnlockEntry::new(
                vec![42; 32],
                current_unix_nanos(),
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        let request = RequestEnvelope::new(
            "req-1",
            AgentMethod::WriteConfig,
            json!({
                "config_path": config_path,
                "store_path": store_path,
                "project_id": "lk_proj_test",
                "profile_name": "default",
                "changes": {
                    "privacy_redact_names": true,
                    "agent_unlock_ttl": "5m",
                    "user_verification_required_for": {
                        "unlock": true,
                        "copy": true
                    },
                    "dangerous_profile": true
                }
            }),
        );

        let success = match dispatch(&request, &state).await {
            ResponseEnvelope::Success(success) => success,
            ResponseEnvelope::Error(error) => {
                panic!("config write should succeed: {error:?}");
            }
        };
        let response: WriteConfigResponse =
            serde_json::from_value(success.payload).expect("response payload");

        assert!(response.settings.privacy_redact_names);
        assert_eq!(response.settings.agent_unlock_ttl.as_deref(), Some("5m"));
        assert!(response.settings.user_verification_required_for.unlock);
        assert!(response.settings.user_verification_required_for.copy);
        assert!(response.settings.dangerous_profile.as_ref().expect("dangerous").dangerous);
        assert!(
            fs::read_to_string(&config_path).expect("config text").contains("unlock_ttl = \"5m\"")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&config_path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let store = Store::open(&store_path).expect("open store");
        let actions = store.list_recent_audit_actions("lk_proj_test", 10).expect("audit actions");
        assert_eq!(
            actions,
            vec![
                "CONFIG_UPDATE",
                "CONFIG_UPDATE",
                "CONFIG_UPDATE",
                "CONFIG_UPDATE",
                "PROFILE_CHANGE"
            ]
        );
        let metadata: Vec<Value> = store
            .connection()
            .prepare("SELECT metadata_json FROM audit_log ORDER BY sequence")
            .expect("prepare")
            .query_map([], |row| {
                let text: String = row.get(0)?;
                Ok(serde_json::from_str::<Value>(&text).expect("json"))
            })
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        assert_eq!(metadata[0]["action"], "CONFIG_UPDATE");
        assert_eq!(metadata[0]["config_keys"], json!([PRIVACY_REDACT_NAMES]));
        assert_eq!(metadata[4]["action"], "PROFILE_CHANGE");
        assert_eq!(metadata[4]["profile_name"], "default");
        assert_eq!(metadata[4]["new_dangerous"], true);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_config_rejects_invalid_duration() {
        let directory = tempdir().expect("tempdir");
        let config_path = directory.path().join("config.toml");
        let store_path = directory.path().join("store.db");
        let _store = initialized_store(&store_path);
        let state = AgentSocketState::locked("test-version");
        state.unlock_cache.lock().await.insert(
            "lk_proj_test".to_owned(),
            UnlockEntry::new(
                vec![42; 32],
                current_unix_nanos(),
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        let request = RequestEnvelope::new(
            "req-1",
            AgentMethod::WriteConfig,
            json!({
                "config_path": config_path,
                "store_path": store_path,
                "project_id": "lk_proj_test",
                "changes": {
                    "agent_unlock_ttl": "soon"
                }
            }),
        );

        let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
            panic!("invalid duration should fail");
        };

        assert_eq!(error.error, "MetadataInvalid");
        assert!(!config_path.exists());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_and_unset_cover_all_user_config_keys() {
        let directory = tempdir().expect("tempdir");
        let config_path = directory.path().join("config.toml");
        let store_path = directory.path().join("store.db");
        let _store = initialized_store(&store_path);
        let state = AgentSocketState::locked("test-version");
        state.unlock_cache.lock().await.insert(
            "lk_proj_test".to_owned(),
            UnlockEntry::new(
                vec![42; 32],
                current_unix_nanos(),
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        let write_all = RequestEnvelope::new(
            "req-all",
            AgentMethod::WriteConfig,
            json!({
                "config_path": config_path,
                "store_path": store_path,
                "project_id": "lk_proj_test",
                "changes": {
                    "ui_theme": "dark",
                    "ui_density": "compact",
                    "editor_default": "vim",
                    "agent_autostart": true,
                    "agent_unlock_ttl": "2h",
                    "runtime_session_secret_name_retention": "30d",
                    "reveal_ttl": "2m",
                    "rotation_max_grace_ttl": "14d",
                    "shell_integration": "prompt-only",
                    "updates_channel": "stable",
                    "updates_manifest_url": "https://updates.example.test/manifest.json",
                    "example_auto_refresh": false,
                    "run_redact_output": "always",
                    "user_verification_required_for": {
                        "recovery": true,
                        "team_accept": true,
                        "device_register": true
                    }
                }
            }),
        );
        let ResponseEnvelope::Success(success) = dispatch(&write_all, &state).await else {
            panic!("full config write should succeed");
        };
        let response: WriteConfigResponse =
            serde_json::from_value(success.payload).expect("response payload");
        assert_eq!(response.settings.ui_theme, "dark");
        assert_eq!(response.settings.ui_density, "compact");
        assert_eq!(response.settings.editor_default.as_deref(), Some("vim"));
        assert!(response.settings.agent_autostart);
        assert_eq!(response.settings.agent_unlock_ttl.as_deref(), Some("2h"));
        assert_eq!(response.settings.runtime_session_secret_name_retention.as_deref(), Some("30d"));
        assert_eq!(response.settings.reveal_ttl.as_deref(), Some("2m"));
        assert_eq!(response.settings.rotation_max_grace_ttl.as_deref(), Some("14d"));
        assert_eq!(response.settings.shell_integration, "prompt-only");
        assert_eq!(response.settings.updates_channel, "stable");
        assert_eq!(
            response.settings.updates_manifest_url.as_deref(),
            Some("https://updates.example.test/manifest.json")
        );
        assert!(!response.settings.example_auto_refresh);
        assert_eq!(response.settings.run_redact_output, "always");
        assert!(response.settings.user_verification_required_for.recovery);
        assert!(response.settings.user_verification_required_for.team_accept);
        assert!(response.settings.user_verification_required_for.device_register);

        let unset = RequestEnvelope::new(
            "req-unset",
            AgentMethod::WriteConfig,
            json!({
                "config_path": config_path,
                "store_path": store_path,
                "project_id": "lk_proj_test",
                "changes": {
                    "unset_keys": ["editor.default", "updates.manifest_url", "reveal.ttl"]
                }
            }),
        );
        let ResponseEnvelope::Success(success) = dispatch(&unset, &state).await else {
            panic!("unset should succeed");
        };
        let response: WriteConfigResponse =
            serde_json::from_value(success.payload).expect("unset response");
        assert!(response.settings.editor_default.is_none());
        assert!(response.settings.updates_manifest_url.is_none());
        assert!(response.settings.reveal_ttl.is_none());
        assert_eq!(response.settings.ui_theme, "dark");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_config_rejects_invalid_and_secret_like_values() {
        let directory = tempdir().expect("tempdir");
        let config_path = directory.path().join("config.toml");
        let store_path = directory.path().join("store.db");
        let _store = initialized_store(&store_path);
        let state = AgentSocketState::locked("test-version");
        state.unlock_cache.lock().await.insert(
            "lk_proj_test".to_owned(),
            UnlockEntry::new(
                vec![42; 32],
                current_unix_nanos(),
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        for bad_changes in [
            json!({"reveal_ttl": "6m"}),
            json!({"rotation_max_grace_ttl": "31d"}),
            json!({"updates_manifest_url": "http://updates.example.test/manifest.json"}),
            json!({"editor_default": "~/bin/editor"}),
            json!({"editor_default": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"}),
            json!({"ui_theme": "purple"}),
            json!({"unset_keys": ["unknown.key"]}),
        ] {
            let bad = RequestEnvelope::new(
                "req-bad",
                AgentMethod::WriteConfig,
                json!({
                    "config_path": config_path,
                    "store_path": store_path,
                    "project_id": "lk_proj_test",
                    "changes": bad_changes
                }),
            );
            assert!(
                matches!(dispatch(&bad, &state).await, ResponseEnvelope::Error(_)),
                "expected error for {bad_changes}"
            );
        }
        assert!(!config_path.exists());
    }
}
