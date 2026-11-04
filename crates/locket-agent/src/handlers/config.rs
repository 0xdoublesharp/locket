//! Metadata-only agent RPCs for desktop settings reads and writes.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use locket_core::{Duration as LocketDuration, privacy_alias};
use locket_store::{AuditWrite, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};

const PRIVACY_REDACT_NAMES: &str = "privacy.redact_names";
const AGENT_UNLOCK_TTL: &str = "agent.unlock_ttl";
const VERIFICATION_UNLOCK: &str = "user_verification_required_for.unlock";
const VERIFICATION_REVEAL: &str = "user_verification_required_for.reveal";
const VERIFICATION_COPY: &str = "user_verification_required_for.copy";
const VERIFICATION_DANGEROUS_PROFILE_SWITCH: &str =
    "user_verification_required_for.dangerous_profile_switch";
const VERIFICATION_RECOVERY: &str = "user_verification_required_for.recovery";
const VERIFICATION_TEAM_ACCEPT: &str = "user_verification_required_for.team_accept";
const VERIFICATION_DEVICE_REGISTER: &str = "user_verification_required_for.device_register";

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
    /// Set `agent.unlock_ttl` to a duration string.
    #[serde(default)]
    pub agent_unlock_ttl: Option<String>,
    /// Set any user-verification policy booleans.
    #[serde(default)]
    pub user_verification_required_for: Option<UserVerificationSettings>,
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
    /// Configured `agent.unlock_ttl`, if present.
    pub agent_unlock_ttl: Option<String>,
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
enum ConfigRpcError {
    #[error("{0}")]
    Protocol(String),
    #[error("{0}")]
    MetadataInvalid(String),
    #[error("unlock required")]
    UnlockRequired,
    #[error("profile not found")]
    ProfileNotFound,
    #[error(transparent)]
    Store(#[from] locket_store::StoreError),
    #[error(transparent)]
    Io(#[from] io::Error),
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
            | Self::TomlDeserialize(_)
            | Self::TomlSerialize(_) => "MetadataInvalid",
            Self::UnlockRequired => "UnlockRequired",
            Self::ProfileNotFound => "ProfileNotFound",
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
pub fn handle_read_config(request: &RequestEnvelope) -> ResponseEnvelope {
    let payload: ReadConfigRequest = match serde_json::from_value(request.payload.clone()) {
        Ok(payload) => payload,
        Err(_) => {
            return error_response(request, "ProtocolError", "invalid ReadConfig payload");
        }
    };
    match read_settings(&payload) {
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

fn read_settings(request: &ReadConfigRequest) -> Result<AgentConfigSettings, ConfigRpcError> {
    let config = read_config_table(&request.config_path)?;
    settings_from_config(
        &config,
        request.store_path.as_deref(),
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
    let audit_key = audit_key_for_project(state, &request.project_id, now_unix_nanos).await?;
    let mut config = read_config_table(&request.config_path)?;
    let mut changed_keys = Vec::new();

    if let Some(value) = request.changes.privacy_redact_names {
        set_config_value(&mut config, PRIVACY_REDACT_NAMES, toml::Value::Boolean(value))?;
        changed_keys.push(PRIVACY_REDACT_NAMES.to_owned());
    }
    if let Some(value) = request.changes.agent_unlock_ttl.as_deref() {
        validate_duration(value)?;
        set_config_value(&mut config, AGENT_UNLOCK_TTL, toml::Value::String(value.to_owned()))?;
        changed_keys.push(AGENT_UNLOCK_TTL.to_owned());
    }
    if let Some(verification) = &request.changes.user_verification_required_for {
        push_bool_patch(&mut config, &mut changed_keys, VERIFICATION_UNLOCK, verification.unlock)?;
        push_bool_patch(&mut config, &mut changed_keys, VERIFICATION_REVEAL, verification.reveal)?;
        push_bool_patch(&mut config, &mut changed_keys, VERIFICATION_COPY, verification.copy)?;
        push_bool_patch(
            &mut config,
            &mut changed_keys,
            VERIFICATION_DANGEROUS_PROFILE_SWITCH,
            verification.dangerous_profile_switch,
        )?;
        push_bool_patch(
            &mut config,
            &mut changed_keys,
            VERIFICATION_RECOVERY,
            verification.recovery,
        )?;
        push_bool_patch(
            &mut config,
            &mut changed_keys,
            VERIFICATION_TEAM_ACCEPT,
            verification.team_accept,
        )?;
        push_bool_patch(
            &mut config,
            &mut changed_keys,
            VERIFICATION_DEVICE_REGISTER,
            verification.device_register,
        )?;
    }

    let mut store = Store::open(&request.store_path)?;
    if !changed_keys.is_empty() {
        write_config_table(&request.config_path, &config)?;
        for key in &changed_keys {
            append_config_update_audit(
                &mut store,
                &request.project_id,
                &request.config_path,
                key,
                &audit_key,
                timestamp,
            )?;
        }
    }

    if let Some(dangerous) = request.changes.dangerous_profile {
        let profile_name = request.profile_name.as_deref().ok_or_else(|| {
            ConfigRpcError::Protocol("profile_name is required for dangerous_profile".to_owned())
        })?;
        let audit = locket_store::ProfileDangerousAudit {
            audit_key: &audit_key,
            timestamp,
            command: "agent config",
        };
        let change = store.set_profile_dangerous_with_audit(
            &request.project_id,
            profile_name,
            dangerous,
            audit,
        )?;
        if change.is_none() {
            return Err(ConfigRpcError::ProfileNotFound);
        }
        changed_keys.push("profile.dangerous".to_owned());
    }

    let settings = settings_from_config(
        &config,
        Some(request.store_path.as_path()),
        Some(request.project_id.as_str()),
        request.profile_name.as_deref(),
    )?;
    Ok(WriteConfigResponse { settings, changed_keys })
}

async fn audit_key_for_project(
    state: &crate::server::AgentSocketState,
    project_id: &str,
    now_unix_nanos: i128,
) -> Result<Vec<u8>, ConfigRpcError> {
    let cache = state.unlock_cache.lock().await;
    let Some(entry) = cache.lookup(project_id, now_unix_nanos) else {
        return Err(ConfigRpcError::UnlockRequired);
    };
    let key_bytes = entry.key_bytes().to_vec();
    drop(cache);
    Ok(key_bytes)
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
    store_path: Option<&Path>,
    project_id: Option<&str>,
    profile_name: Option<&str>,
) -> Result<AgentConfigSettings, ConfigRpcError> {
    let privacy_redact_names = bool_config_value(config, PRIVACY_REDACT_NAMES)?.unwrap_or(false);
    let agent_unlock_ttl = duration_config_value(config, AGENT_UNLOCK_TTL)?;
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
        dangerous_profile_setting(store_path, project_id, profile_name, privacy_redact_names)?;

    Ok(AgentConfigSettings {
        privacy_redact_names,
        agent_unlock_ttl,
        user_verification_required_for,
        dangerous_profile,
    })
}

fn dangerous_profile_setting(
    store_path: Option<&Path>,
    project_id: Option<&str>,
    profile_name: Option<&str>,
    redact_names: bool,
) -> Result<Option<DangerousProfileSetting>, ConfigRpcError> {
    let (Some(store_path), Some(project_id), Some(profile_name)) =
        (store_path, project_id, profile_name)
    else {
        return Ok(None);
    };
    let store = Store::open(store_path)?;
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
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(toml::Table::new()),
        Err(error) => return Err(error.into()),
    };
    Ok(toml::from_str::<toml::Table>(&text)?)
}

fn write_config_table(path: &Path, config: &toml::Table) -> Result<(), ConfigRpcError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = toml::to_string_pretty(config)?;
    fs::write(path, text)?;
    set_user_only_file_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_user_only_file_permissions(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Keep the shared fallible interface; Windows inherits ACLs.
const fn set_user_only_file_permissions(_path: &Path) -> Result<(), io::Error> {
    Ok(())
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
    let Some(value) = config_value(config, key)? else {
        return Ok(None);
    };
    let value = value.as_str().ok_or_else(|| {
        ConfigRpcError::MetadataInvalid(format!("invalid stored config value for {key}"))
    })?;
    validate_duration(value)?;
    Ok(Some(value.to_owned()))
}

fn validate_duration(value: &str) -> Result<(), ConfigRpcError> {
    LocketDuration::from_str(value)
        .map(|_| ())
        .map_err(|_| ConfigRpcError::MetadataInvalid("invalid config duration".to_owned()))
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
        store
    }

    #[test]
    fn read_config_defaults_missing_values() {
        let directory = tempdir().expect("tempdir");
        let request = ReadConfigRequest {
            config_path: directory.path().join("missing.toml"),
            store_path: None,
            project_id: None,
            profile_name: None,
        };

        let settings = read_settings(&request).expect("read settings");

        assert!(!settings.privacy_redact_names);
        assert!(settings.agent_unlock_ttl.is_none());
        assert_eq!(
            settings.user_verification_required_for,
            EffectiveUserVerificationSettings::default()
        );
        assert!(settings.dangerous_profile.is_none());
    }

    #[test]
    fn read_config_applies_privacy_alias_to_profile_label() {
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

        let settings = read_settings(&request).expect("read settings");
        let dangerous = settings.dangerous_profile.expect("dangerous profile");

        assert_eq!(dangerous.profile_name, "default");
        assert!(dangerous.profile_label.starts_with("profile-"));
        assert!(!dangerous.dangerous);
    }

    #[test]
    fn read_config_returns_profile_not_found_for_missing_profile_context() {
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

        let ResponseEnvelope::Error(error) = handle_read_config(&request) else {
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
                    "dangerous_profile": true
                }
            }),
        );

        let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
            panic!("missing profile_name should fail");
        };

        assert_eq!(error.error, "ProtocolError");
        assert!(!config_path.exists());
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
}
