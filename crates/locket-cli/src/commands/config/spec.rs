//! User-config validation tables, parsing, and audit metadata helpers.

use std::fs;
use std::io;
use std::path::Path;
use std::str::FromStr;

use locket_core::{Duration as LocketDuration, OutputRedaction};
use locket_crypto::KeyPurpose;
use locket_scan::{FindingKind, scan_text};
use locket_store::{AuditWrite, RuntimeSessionSecretNameRetention};
use serde_json::json;

use crate::{
    CONFIG_TOML, CliError, RuntimeContext, load_project_key, metadata_invalid_error,
    metadata_looks_like_secret_error, now_unix_nanos, open_store, resolve_project,
};

#[derive(Clone, Copy)]
pub struct ConfigKeySpec {
    pub key: &'static str,
    pub kind: ConfigValueKind,
    pub audit: bool,
}

#[derive(Clone, Copy)]
pub enum ConfigValueKind {
    Bool,
    Duration,
    DurationMax { max_secs: u64, message: &'static str },
    Enum { values: &'static [&'static str], message: &'static str },
    EditorDefault,
    HttpsUrl,
    RuntimeSessionSecretNameRetention,
}

const UI_THEME_VALUES: &[&str] = &["system", "light", "dark"];
const UI_DENSITY_VALUES: &[&str] = &["comfortable", "compact"];
const SHELL_INTEGRATION_VALUES: &[&str] = &["off", "prompt-only", "hook"];
const UPDATES_CHANNEL_VALUES: &[&str] = &["off", "stable", "beta"];

pub const CONFIG_KEY_SPECS: &[ConfigKeySpec] = &[
    ConfigKeySpec {
        key: "ui.theme",
        kind: ConfigValueKind::Enum {
            values: UI_THEME_VALUES,
            message: "ui.theme must be system, light, or dark",
        },
        audit: false,
    },
    ConfigKeySpec {
        key: "ui.density",
        kind: ConfigValueKind::Enum {
            values: UI_DENSITY_VALUES,
            message: "ui.density must be comfortable or compact",
        },
        audit: false,
    },
    ConfigKeySpec { key: "privacy.redact_names", kind: ConfigValueKind::Bool, audit: false },
    ConfigKeySpec { key: "editor.default", kind: ConfigValueKind::EditorDefault, audit: false },
    ConfigKeySpec { key: "agent.autostart", kind: ConfigValueKind::Bool, audit: true },
    ConfigKeySpec { key: "agent.unlock_ttl", kind: ConfigValueKind::Duration, audit: true },
    ConfigKeySpec {
        key: "runtime.session_secret_name_retention",
        kind: ConfigValueKind::RuntimeSessionSecretNameRetention,
        audit: true,
    },
    ConfigKeySpec {
        key: "reveal.ttl",
        kind: ConfigValueKind::DurationMax {
            max_secs: 300,
            message: "reveal.ttl must be 5m or less",
        },
        audit: true,
    },
    ConfigKeySpec {
        key: "rotation.max_grace_ttl",
        kind: ConfigValueKind::DurationMax {
            max_secs: 30 * 24 * 60 * 60,
            message: "rotation.max_grace_ttl must be 30d or less",
        },
        audit: true,
    },
    ConfigKeySpec {
        key: "shell.integration",
        kind: ConfigValueKind::Enum {
            values: SHELL_INTEGRATION_VALUES,
            message: "shell.integration must be off, prompt-only, or hook",
        },
        audit: true,
    },
    ConfigKeySpec {
        key: "updates.channel",
        kind: ConfigValueKind::Enum {
            values: UPDATES_CHANNEL_VALUES,
            message: "updates.channel must be off, stable, or beta",
        },
        audit: true,
    },
    ConfigKeySpec { key: "updates.manifest_url", kind: ConfigValueKind::HttpsUrl, audit: true },
    ConfigKeySpec { key: "example.auto_refresh", kind: ConfigValueKind::Bool, audit: false },
    ConfigKeySpec {
        key: "run.redact_output",
        kind: ConfigValueKind::Enum {
            values: OutputRedaction::VALUES,
            message: "run.redact_output must be auto, always, or never",
        },
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.unlock",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.reveal",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.copy",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.dangerous_profile_switch",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.recovery",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.team_accept",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.device_register",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
];

pub fn validate_config_key(key: &str) -> Result<&'static ConfigKeySpec, CliError> {
    CONFIG_KEY_SPECS
        .iter()
        .find(|spec| spec.key == key)
        .ok_or_else(|| metadata_invalid_error("unsupported config key"))
}

pub fn validate_config_value_not_secret_like(value: &str) -> Result<(), CliError> {
    let secret_like = scan_text(CONFIG_TOML, value).iter().any(|finding| {
        matches!(finding.kind, FindingKind::HighEntropy | FindingKind::ProviderTokenPattern)
    });
    if secret_like {
        return Err(metadata_looks_like_secret_error(
            "config value looks like a secret; refusing to store it",
        ));
    }
    Ok(())
}

pub fn parse_config_value(spec: &ConfigKeySpec, value: &str) -> Result<toml::Value, CliError> {
    match spec.kind {
        ConfigValueKind::Bool => match value {
            "true" => Ok(toml::Value::Boolean(true)),
            "false" => Ok(toml::Value::Boolean(false)),
            _ => Err(metadata_invalid_error("config value must be true or false")),
        },
        ConfigValueKind::Duration => {
            LocketDuration::from_str(value)
                .map_err(|_| metadata_invalid_error("invalid config duration"))?;
            Ok(toml::Value::String(value.to_owned()))
        }
        ConfigValueKind::DurationMax { max_secs, message } => {
            let duration = LocketDuration::from_str(value)
                .map_err(|_| metadata_invalid_error("invalid config duration"))?;
            if duration.as_secs() > max_secs {
                return Err(metadata_invalid_error(message));
            }
            Ok(toml::Value::String(value.to_owned()))
        }
        ConfigValueKind::Enum { values, message } => {
            if values.contains(&value) {
                Ok(toml::Value::String(value.to_owned()))
            } else {
                Err(metadata_invalid_error(message))
            }
        }
        ConfigValueKind::EditorDefault => {
            validate_editor_default(value)?;
            Ok(toml::Value::String(value.to_owned()))
        }
        ConfigValueKind::HttpsUrl => {
            validate_https_url(value)?;
            Ok(toml::Value::String(value.to_owned()))
        }
        ConfigValueKind::RuntimeSessionSecretNameRetention => {
            RuntimeSessionSecretNameRetention::from_str(value).map_err(|_| {
                metadata_invalid_error(
                    "runtime.session_secret_name_retention must be a duration or off",
                )
            })?;
            Ok(toml::Value::String(value.to_owned()))
        }
    }
}

pub fn validate_stored_config_value(
    spec: &ConfigKeySpec,
    value: &toml::Value,
) -> Result<(), CliError> {
    match spec.kind {
        ConfigValueKind::Bool => {
            if value.as_bool().is_some() {
                Ok(())
            } else {
                Err(invalid_stored_config_value(spec.key))
            }
        }
        ConfigValueKind::Duration
        | ConfigValueKind::DurationMax { .. }
        | ConfigValueKind::Enum { .. }
        | ConfigValueKind::EditorDefault
        | ConfigValueKind::HttpsUrl
        | ConfigValueKind::RuntimeSessionSecretNameRetention => {
            let Some(value) = value.as_str() else {
                return Err(invalid_stored_config_value(spec.key));
            };
            parse_config_value(spec, value)
                .map(|_| ())
                .map_err(|_| invalid_stored_config_value(spec.key))
        }
    }
}

fn invalid_stored_config_value(key: &str) -> CliError {
    metadata_invalid_error(format!("invalid stored config value for {key}"))
}

fn validate_editor_default(value: &str) -> Result<(), CliError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(metadata_invalid_error(
            "editor.default must be a command name or absolute path",
        ));
    }
    if value.starts_with('~') || value.contains('$') || value.contains('`') {
        return Err(metadata_invalid_error("editor.default must not use shell expansion"));
    }
    if Path::new(value).is_absolute() {
        return Ok(());
    }
    let shell_meta = ['/', '\\', '|', '&', ';', '<', '>', '(', ')'];
    if value.chars().any(char::is_whitespace) || value.chars().any(|c| shell_meta.contains(&c)) {
        return Err(metadata_invalid_error(
            "editor.default must be a command name or absolute path",
        ));
    }
    Ok(())
}

fn validate_https_url(value: &str) -> Result<(), CliError> {
    let Some(rest) = value.strip_prefix("https://") else {
        return Err(metadata_invalid_error("updates.manifest_url must be an HTTPS URL"));
    };
    if rest.is_empty()
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(metadata_invalid_error("updates.manifest_url must be an HTTPS URL"));
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.starts_with(':') || host.contains('@') {
        return Err(metadata_invalid_error("updates.manifest_url must be an HTTPS URL"));
    }
    Ok(())
}

pub fn read_user_config(runtime: &RuntimeContext) -> Result<toml::Table, CliError> {
    let toml_text = match fs::read_to_string(&runtime.config_path) {
        Ok(toml_text) => toml_text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(toml::Table::new()),
        Err(error) => return Err(error.into()),
    };
    Ok(toml::from_str::<toml::Table>(&toml_text)?)
}

pub fn write_user_config(runtime: &RuntimeContext, config: &toml::Table) -> Result<(), CliError> {
    if let Some(parent) = runtime.config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let toml_text = toml::to_string_pretty(config)?;
    fs::write(&runtime.config_path, toml_text)?;
    Ok(())
}

pub fn config_get_value<'a>(config: &'a toml::Table, key: &str) -> Option<&'a toml::Value> {
    let (section, name) = split_config_key(key)?;
    config.get(section)?.as_table()?.get(name)
}

pub fn config_set_value(
    config: &mut toml::Table,
    key: &str,
    value: toml::Value,
) -> Result<(), CliError> {
    let (section, name) =
        split_config_key(key).ok_or_else(|| metadata_invalid_error("unsupported config key"))?;
    let section_value =
        config.entry(section.to_owned()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let Some(section_table) = section_value.as_table_mut() else {
        return Err(metadata_invalid_error("config section is not a table"));
    };
    section_table.insert(name.to_owned(), value);
    Ok(())
}

pub fn config_unset_value(config: &mut toml::Table, key: &str) -> Result<(), CliError> {
    let (section, name) =
        split_config_key(key).ok_or_else(|| metadata_invalid_error("unsupported config key"))?;
    let should_remove_section = if let Some(section_value) = config.get_mut(section) {
        let Some(section_table) = section_value.as_table_mut() else {
            return Err(metadata_invalid_error("config section is not a table"));
        };
        section_table.remove(name);
        section_table.is_empty()
    } else {
        false
    };
    if should_remove_section {
        config.remove(section);
    }
    Ok(())
}

pub fn split_config_key(key: &str) -> Option<(&str, &str)> {
    let (section, name) = key.split_once('.')?;
    if section.is_empty() || name.is_empty() || name.contains('.') {
        return None;
    }
    Some((section, name))
}

pub fn format_config_value(value: &toml::Value) -> String {
    match value {
        toml::Value::Boolean(value) => value.to_string(),
        toml::Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

pub fn write_config_update_audit_if_available(
    context: &RuntimeContext,
    key: &str,
    operation: &str,
) -> Result<(), CliError> {
    let Some(resolved) = resolve_project(&context.cwd)? else {
        return Ok(());
    };
    let mut store = open_store(context)?;
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let config_path_hash = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(context.config_path.to_string_lossy().as_bytes());
        crate::format_hex(&digest)
    };
    let metadata = json!({
        "schema_version": 1,
        "action": "CONFIG_UPDATE",
        "status": "SUCCESS",
        "command": "config",
        "operation": operation,
        "key": key,
        "value": "hidden",
        "config_path_hash": config_path_hash,
        "config_keys": [key],
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "CONFIG_UPDATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("config"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
