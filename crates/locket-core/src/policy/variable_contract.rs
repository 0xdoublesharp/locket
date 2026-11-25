//! Commit-safe variable contracts and metadata-only readiness.

use super::{CommandPolicy, PolicyDocument, PolicyParseError};
use crate::SecretName;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Whether a value may be stored in project configuration.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VariableClassification {
    /// Encrypted or externally provided sensitive configuration.
    #[default]
    Secret,
    /// Configuration intentionally safe to commit and expose.
    Public,
}

/// Small, shared value validators. Errors contain names and types only.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VariableType {
    /// Any string without NUL characters.
    #[default]
    String,
    /// Signed 64-bit decimal integer.
    Integer,
    /// Exactly `true` or `false`.
    Boolean,
    /// Absolute URL accepted by the URL parser.
    Url,
}

/// Project variable description, distinct from command authorization and ACLs.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VariableContract {
    /// Portable environment name.
    pub name: SecretName,
    /// Whether this configuration is deliberately public.
    pub classification: VariableClassification,
    /// Shared value validator.
    pub value_type: VariableType,
    /// Commit-safe purpose description.
    pub description: Option<String>,
    /// Commit-safe instructions for obtaining a local value.
    pub setup_hint: Option<String>,
    /// Literal public fallback. Never included in readiness output.
    pub default: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawContract {
    #[serde(default)]
    classification: VariableClassification,
    #[serde(default, rename = "type")]
    value_type: VariableType,
    description: Option<String>,
    setup_hint: Option<String>,
    default: Option<String>,
}

fn invalid(name: &str, reason: &'static str) -> PolicyParseError {
    PolicyParseError::VariableContract { name: name.into(), reason }
}

pub(super) fn parse_variables(
    value: Option<&toml::Value>,
) -> Result<BTreeMap<String, VariableContract>, PolicyParseError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let table = value.as_table().ok_or_else(|| invalid("variables", "expected a table"))?;
    table
        .iter()
        .map(|(name, value)| {
            let parsed_name = SecretName::new(name.clone())
                .map_err(|_| invalid("<invalid-name>", "invalid environment name"))?;
            let raw: RawContract = value
                .clone()
                .try_into()
                .map_err(|_| invalid(name, "unsupported field or invalid field type"))?;
            if raw.default.is_some() && raw.classification != VariableClassification::Public {
                return Err(invalid(name, "defaults require public classification"));
            }
            let contract = VariableContract {
                name: parsed_name,
                classification: raw.classification,
                value_type: raw.value_type,
                description: raw.description,
                setup_hint: raw.setup_hint,
                default: raw.default,
            };
            if let Some(default) = &contract.default {
                if default.contains("lk://") {
                    return Err(invalid(name, "defaults must be literal public values"));
                }
                contract.validate_value(default)?;
            }
            Ok((name.clone(), contract))
        })
        .collect()
}

impl VariableContract {
    /// Checks a resolved value without putting it in diagnostics.
    ///
    /// # Errors
    /// Returns a name-only contract error if the declared type is not satisfied.
    pub fn validate_value(&self, value: &str) -> Result<(), PolicyParseError> {
        let valid = !value.contains('\0')
            && match self.value_type {
                VariableType::String => true,
                VariableType::Integer => value.parse::<i64>().is_ok(),
                VariableType::Boolean => matches!(value, "true" | "false"),
                VariableType::Url => url::Url::parse(value).is_ok(),
            };
        if valid {
            Ok(())
        } else {
            let reason = if value.contains('\0') {
                "NUL characters are invalid"
            } else {
                match self.value_type {
                    VariableType::String => "expected a string without NUL characters",
                    VariableType::Integer => "expected a signed 64-bit integer",
                    VariableType::Boolean => "expected true or false",
                    VariableType::Url => "expected an absolute URL",
                }
            };
            Err(invalid(self.name.as_str(), reason))
        }
    }
}

/// Availability established without returning a value.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VariableReadinessState {
    /// A provided name or permitted public fallback satisfies the requirement.
    Ready,
    /// Required configuration is absent.
    Missing,
    /// An optional value is absent.
    Optional,
    /// A runtime source requires a separate live check.
    Unverified,
}

/// Safe to return through CLI JSON or desktop IPC. No value/default field exists.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct VariableReadinessRow {
    /// Authorized environment name.
    pub name: String,
    /// Whether the effective command requires the name.
    pub required: bool,
    /// Explicit public classification, otherwise secret.
    pub classification: VariableClassification,
    /// Availability status.
    pub state: VariableReadinessState,
    /// Source label supplied by the caller, or public-default.
    pub selected_source: Option<String>,
    /// Commit-safe variable purpose.
    pub description: Option<String>,
    /// Commit-safe setup guidance.
    pub setup_hint: Option<String>,
    /// Name-only action for absent required values.
    pub next_action: Option<String>,
    /// Browser exposure warning based only on the name/classification.
    pub warning: Option<String>,
}

impl PolicyDocument {
    /// Reports effective allowed names only. Callers must apply scope and ACLs first.
    #[must_use]
    pub fn variable_readiness(
        &self,
        policy: &CommandPolicy,
        sources: &BTreeMap<String, String>,
        deferred_sources: bool,
    ) -> Vec<VariableReadinessRow> {
        policy
            .allowed_secrets
            .iter()
            .chain(&policy.shared_secrets)
            .map(|name| {
                let key = name.as_str();
                let contract = self.variables.get(key);
                let classification =
                    contract.map_or(VariableClassification::Secret, |item| item.classification);
                let shared = policy.shared_secrets.contains(name);
                let required = shared || policy.required_secrets.contains(name);
                let selected_source = sources.get(key).cloned().or_else(|| {
                    contract
                        .filter(|item| {
                            !shared && item.classification == VariableClassification::Public
                        })
                        .and_then(|item| item.default.as_ref())
                        .map(|_| "public-default".into())
                });
                let state = if deferred_sources && !sources.contains_key(key) {
                    VariableReadinessState::Unverified
                } else if selected_source.is_some() {
                    VariableReadinessState::Ready
                } else if required {
                    VariableReadinessState::Missing
                } else {
                    VariableReadinessState::Optional
                };
                let warning = variable_exposure_warning(key, classification);
                VariableReadinessRow {
                    name: key.into(),
                    required,
                    classification,
                    state,
                    selected_source,
                    description: contract.and_then(|item| item.description.clone()),
                    setup_hint: contract.and_then(|item| item.setup_hint.clone()),
                    next_action: (state == VariableReadinessState::Missing).then(|| {
                        if shared {
                            format!("locket set {key} --project @shared")
                        } else {
                            format!("locket set {key}")
                        }
                    }),
                    warning,
                }
            })
            .collect()
    }

    /// Applies public fallbacks only to authorized names missing from a final child map.
    /// Callers must merge existing sources and enforce ACLs before this operation.
    pub fn apply_variable_defaults(&self, policy: &CommandPolicy, env: &mut crate::EnvMap) {
        for name in &policy.allowed_secrets {
            if let Some(value) = self
                .variables
                .get(name.as_str())
                .filter(|item| item.classification == VariableClassification::Public)
                .and_then(|item| item.default.as_ref())
            {
                env.entry(name.to_string()).or_insert_with(|| crate::env_value(value.clone()));
            }
        }
    }

    /// Validates the values actually selected for an authorized child environment.
    ///
    /// # Errors
    /// Returns a value-free contract error for the first invalid variable.
    pub fn validate_variable_values(
        &self,
        policy: &CommandPolicy,
        env: &crate::EnvMap,
    ) -> Result<(), PolicyParseError> {
        for name in policy.allowed_secrets.iter().chain(&policy.shared_secrets) {
            if let (Some(contract), Some(value)) =
                (self.variables.get(name.as_str()), env.get(name.as_str()))
            {
                contract.validate_value(value)?;
            }
        }
        Ok(())
    }
}

/// Warns about browser-public prefixes on secret-classified names, without values.
#[must_use]
pub fn variable_exposure_warning(
    name: &str,
    classification: VariableClassification,
) -> Option<String> {
    (classification == VariableClassification::Secret && (name.starts_with("VITE_") || name.starts_with("NEXT_PUBLIC_")))
        .then(|| format!("{name} is classified secret. This prefix may expose its value in browser bundles. Mark genuinely public configuration public, or rename the secret before using it in browser code."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_contract_readiness_and_fallback_preserve_authorization()
    -> Result<(), Box<dyn std::error::Error>> {
        let document = PolicyDocument::from_toml_str(
            r"schema_version=1
[commands.dev]
argv=['echo']
required_secrets=['PORT','TOKEN']
optional_secrets=['NEXT_PUBLIC_TOKEN']
[variables.PORT]
classification='public'
type='integer'
default='3001'
[variables.UNAUTHORIZED]
classification='public'
default='canary-never-inject'
[variables.TOKEN]
setup_hint='Ask teammate'
",
        )?;
        let policy = &document.commands["dev"];
        let rows = document.variable_readiness(policy, &BTreeMap::new(), false);
        assert_eq!(
            rows.iter().find(|row| row.name == "PORT").ok_or("port")?.selected_source.as_deref(),
            Some("public-default")
        );
        assert_eq!(
            rows.iter().find(|row| row.name == "TOKEN").ok_or("token")?.state,
            VariableReadinessState::Missing
        );
        assert!(rows.iter().any(|row| row.warning.is_some()));
        let rendered = serde_json::to_string(&rows)?;
        assert!(!rendered.contains("3001"));
        assert!(!rendered.contains("canary-never-inject"));
        let mut env = crate::EnvMap::from_iter([("PORT".into(), crate::env_value("4000"))]);
        document.apply_variable_defaults(policy, &mut env);
        assert_eq!(env["PORT"].as_str(), "4000");
        assert!(!env.contains_key("UNAUTHORIZED"));
        Ok(())
    }

    #[test]
    fn configuration_contract_value_errors_and_malformed_toml_are_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        for (kind, good, bad) in [
            ("integer", "123", "canary-secret"),
            ("boolean", "false", "canary-secret"),
            ("url", "https://localhost/x", "canary-secret"),
        ] {
            let document = PolicyDocument::from_toml_str(&format!(
                "schema_version=1\n[variables.KEY]\ntype='{kind}'"
            ))?;
            let contract = &document.variables["KEY"];
            contract.validate_value(good)?;
            let error =
                contract.validate_value(bad).err().ok_or("invalid value must fail")?.to_string();
            assert!(error.contains("KEY"));
            assert!(!error.contains("canary-secret"));
        }
        let error = PolicyDocument::from_toml_str(
            "schema_version=1\n[variables.KEY]\ndefault='canary-secret",
        )
        .err()
        .ok_or("bad TOML must fail")?
        .to_string();
        assert!(!error.contains("canary-secret"));
        Ok(())
    }

    #[test]
    fn deferred_contracts_report_unverified_and_validation_uses_only_selected_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let document = PolicyDocument::from_toml_str(
            "schema_version=1
[commands.dev]
argv=['true']
required_secrets=['PORT']
shared_secrets=['TOKEN']
[variables.PORT]
type='integer'
[variables.TOKEN]
type='string'
[variables.UNRELATED]
type='boolean'
",
        )?;
        let policy = &document.commands["dev"];
        let rows = document.variable_readiness(policy, &BTreeMap::new(), true);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.state == VariableReadinessState::Unverified));
        let mut env = crate::EnvMap::from([
            ("PORT".into(), crate::env_value("1234")),
            ("UNRELATED".into(), crate::env_value("invalid")),
        ]);
        assert_eq!(document.validate_variable_values(policy, &env), Ok(()));
        env.insert("TOKEN".into(), crate::env_value("fixture\0secret"));
        assert_eq!(
            document.validate_variable_values(policy, &env),
            Err(invalid("TOKEN", "NUL characters are invalid"))
        );
        Ok(())
    }
}
