//! Per-command policy types and parsing.

use std::collections::BTreeSet;
use std::str::FromStr;

use serde::Deserialize;

use crate::{Duration, EnvMode, EnvOverrideMode, SecretName};

use super::env_source::{ExternalEnvSource, RawExternalEnvSource, parse_external_env_sources};
use super::error::PolicyParseError;

const DEFAULT_COMMAND_POLICY_TTL_SECONDS: u64 = 15 * 60;

/// Maximum command-policy grant TTL accepted by the built-in policy parser.
pub const MAX_COMMAND_POLICY_TTL_SECONDS: u64 = 8 * 60 * 60;

const NAME_FIELD: &str = "name";
const SECRETS_FIELD: &str = "secrets";
const REQUIRED_SECRETS_FIELD: &str = "required_secrets";
const OPTIONAL_SECRETS_FIELD: &str = "optional_secrets";
const SHARED_SECRETS_FIELD: &str = "shared_secrets";

/// Command representation that controls shell expansion behavior.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CommandSpec {
    /// Structured argv execution without shell expansion.
    Argv(Vec<String>),
    /// Explicit shell execution.
    Shell(String),
}

/// A normalized command policy from `[commands.<name>]`.
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct CommandPolicy {
    /// Policy name derived from the TOML table key.
    pub name: String,
    /// Command form to execute.
    pub command: CommandSpec,
    /// Normalized union of required and optional project secret names.
    pub allowed_secrets: Vec<SecretName>,
    /// Secret names that must be present before execution.
    pub required_secrets: Vec<SecretName>,
    /// Secret names that may be injected only when present.
    pub optional_secrets: Vec<SecretName>,
    /// Required names sourced from the local `@shared` vault.
    pub shared_secrets: Vec<SecretName>,
    /// Parent environment names explicitly inherited in addition to base mode.
    pub inherit_env: Vec<String>,
    /// Base child environment policy.
    pub env_mode: EnvMode,
    /// Conflict behavior for Locket secret names; TOML field name is `override`.
    pub override_behavior: EnvOverrideMode,
    /// Source of the resolved `override` field.
    pub override_source: PolicyFieldSource,
    /// External environment source descriptors.
    pub external_env_sources: Vec<ExternalEnvSource>,
    /// Whether Docker/Compose helpers may deliver secrets to remote contexts.
    pub allow_remote_docker: bool,
    /// Whether execution requires typed confirmation of the policy name.
    pub confirm: bool,
    /// Whether execution requires local user verification.
    pub require_user_verification: bool,
    /// Whether execution must use the local agent path and fail closed
    /// when the daemon is unavailable.
    pub require_agent: bool,
    /// Live agent grant duration for this policy.
    pub ttl: Duration,
}

/// Whether a policy field was set explicitly or came from a default.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PolicyFieldSource {
    /// The field was omitted and the parser supplied the default.
    Defaulted,
    /// The field was present in the policy document.
    Explicit,
}

impl CommandPolicy {
    /// Returns true when the TOML policy explicitly set `override`.
    #[must_use]
    pub const fn override_explicit(&self) -> bool {
        matches!(self.override_source, PolicyFieldSource::Explicit)
    }

    pub(super) fn from_toml_value(
        name: &str,
        value: toml::Value,
    ) -> Result<Self, PolicyParseError> {
        if name.is_empty() {
            return Err(PolicyParseError::EmptyCommandName);
        }
        let Some(table) = value.as_table() else {
            return Err(PolicyParseError::CommandMustBeTable { command: name.to_owned() });
        };
        if table.contains_key(NAME_FIELD) {
            return Err(PolicyParseError::NameFieldUnsupported { command: name.to_owned() });
        }
        if table.contains_key(SECRETS_FIELD) {
            return Err(PolicyParseError::SecretsFieldUnsupported { command: name.to_owned() });
        }

        let raw = value.try_into::<RawCommandPolicy>().map_err(|source| {
            PolicyParseError::CommandSchema {
                command: name.to_owned(),
                message: source.to_string(),
            }
        })?;

        Self::from_raw(name, raw)
    }

    fn from_raw(name: &str, raw: RawCommandPolicy) -> Result<Self, PolicyParseError> {
        let command = match (raw.argv, raw.shell) {
            (Some(argv), None) if argv.is_empty() => {
                return Err(PolicyParseError::EmptyArgv { command: name.to_owned() });
            }
            (Some(argv), None) => CommandSpec::Argv(argv),
            (None, Some(shell)) if shell.trim().is_empty() => {
                return Err(PolicyParseError::EmptyShell { command: name.to_owned() });
            }
            (None, Some(shell)) => CommandSpec::Shell(shell),
            (Some(_), Some(_)) => {
                return Err(PolicyParseError::CommandSpecConflict { command: name.to_owned() });
            }
            (None, None) => {
                return Err(PolicyParseError::MissingCommandSpec { command: name.to_owned() });
            }
        };

        let required_secrets = parse_secret_list(
            name,
            REQUIRED_SECRETS_FIELD,
            raw.required_secrets.unwrap_or_default(),
        )?;
        let optional_secrets = parse_secret_list(
            name,
            OPTIONAL_SECRETS_FIELD,
            raw.optional_secrets.unwrap_or_default(),
        )?;
        let allowed_secrets =
            normalize_allowed_secrets(name, &required_secrets, &optional_secrets)?;
        let shared_secrets =
            parse_secret_list(name, SHARED_SECRETS_FIELD, raw.shared_secrets.unwrap_or_default())?;
        if let Some(shared) =
            shared_secrets.iter().find(|secret| allowed_secrets.binary_search(secret).is_ok())
        {
            return Err(PolicyParseError::SharedAndProjectSecret {
                command: name.to_owned(),
                name: shared.to_string(),
            });
        }

        let env_mode = parse_env_mode(name, raw.env_mode)?;
        let override_source = if raw.override_behavior.is_some() {
            PolicyFieldSource::Explicit
        } else {
            PolicyFieldSource::Defaulted
        };
        let override_behavior = parse_override_behavior(name, raw.override_behavior)?;
        let ttl = parse_ttl(name, raw.ttl)?;
        let external_env_sources =
            parse_external_env_sources(name, raw.external_env_sources.unwrap_or_default())?;

        Ok(Self {
            name: name.to_owned(),
            command,
            allowed_secrets,
            required_secrets,
            optional_secrets,
            shared_secrets,
            inherit_env: raw.inherit_env.unwrap_or_default(),
            env_mode,
            override_behavior,
            override_source,
            external_env_sources,
            allow_remote_docker: raw.allow_remote_docker.unwrap_or(false),
            confirm: raw.confirm.unwrap_or(false),
            require_user_verification: raw.require_user_verification.unwrap_or(false),
            require_agent: raw.require_agent.unwrap_or(false),
            ttl,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCommandPolicy {
    argv: Option<Vec<String>>,
    shell: Option<String>,
    required_secrets: Option<Vec<String>>,
    optional_secrets: Option<Vec<String>>,
    shared_secrets: Option<Vec<String>>,
    inherit_env: Option<Vec<String>>,
    env_mode: Option<String>,
    #[serde(rename = "override")]
    override_behavior: Option<String>,
    external_env_sources: Option<Vec<RawExternalEnvSource>>,
    allow_remote_docker: Option<bool>,
    confirm: Option<bool>,
    require_user_verification: Option<bool>,
    require_agent: Option<bool>,
    ttl: Option<String>,
}

pub(super) fn parse_secret_list(
    command: &str,
    field: &'static str,
    values: Vec<String>,
) -> Result<Vec<SecretName>, PolicyParseError> {
    let mut seen = BTreeSet::new();
    let mut parsed = Vec::with_capacity(values.len());

    for value in values {
        let name =
            SecretName::new(value.clone()).map_err(|_| PolicyParseError::InvalidSecretName {
                command: command.to_owned(),
                field,
                name: value.clone(),
            })?;
        if !seen.insert(name.clone()) {
            return Err(PolicyParseError::DuplicateSecretName {
                command: command.to_owned(),
                field,
                name: name.into_string(),
            });
        }
        parsed.push(name);
    }

    Ok(parsed)
}

pub(super) fn normalize_allowed_secrets(
    command: &str,
    required_secrets: &[SecretName],
    optional_secrets: &[SecretName],
) -> Result<Vec<SecretName>, PolicyParseError> {
    let required = required_secrets.iter().collect::<BTreeSet<_>>();
    for name in optional_secrets {
        if required.contains(name) {
            return Err(PolicyParseError::SecretRequiredAndOptional {
                command: command.to_owned(),
                name: name.to_string(),
            });
        }
    }

    Ok(required_secrets
        .iter()
        .chain(optional_secrets.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn parse_env_mode(command: &str, value: Option<String>) -> Result<EnvMode, PolicyParseError> {
    value.map_or(Ok(EnvMode::Minimal), |value| {
        value
            .parse()
            .map_err(|_| PolicyParseError::InvalidEnvMode { command: command.to_owned(), value })
    })
}

fn parse_override_behavior(
    command: &str,
    value: Option<String>,
) -> Result<EnvOverrideMode, PolicyParseError> {
    value.map_or(Ok(EnvOverrideMode::Locket), |value| {
        value.parse().map_err(|_| PolicyParseError::InvalidOverrideBehavior {
            command: command.to_owned(),
            value,
        })
    })
}

fn parse_ttl(command: &str, value: Option<String>) -> Result<Duration, PolicyParseError> {
    let ttl = match value {
        Some(value) => Duration::from_str(&value)
            .map_err(|_| PolicyParseError::InvalidTtl { command: command.to_owned(), value })?,
        None => Duration::from_secs(DEFAULT_COMMAND_POLICY_TTL_SECONDS),
    };

    if ttl.as_secs() > MAX_COMMAND_POLICY_TTL_SECONDS {
        return Err(PolicyParseError::TtlExceedsMaximum {
            command: command.to_owned(),
            ttl_seconds: ttl.as_secs(),
            max_seconds: MAX_COMMAND_POLICY_TTL_SECONDS,
        });
    }

    Ok(ttl)
}
