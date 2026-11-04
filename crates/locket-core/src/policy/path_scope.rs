//! Path-scoped environment sets from `[paths.<relative-path>]`.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use crate::{ProfileName, SecretName};

use super::command::{normalize_allowed_secrets, parse_secret_list};
use super::error::PolicyParseError;

const REQUIRED_SECRETS_FIELD: &str = "required_secrets";
const OPTIONAL_SECRETS_FIELD: &str = "optional_secrets";

/// Environment names made available while running from a project-relative path.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PathEnvSet {
    /// Project-relative directory this scope applies to.
    pub path: PathBuf,
    /// Optional profile override for this path.
    pub profile: Option<ProfileName>,
    /// Secret names that must be present before execution.
    pub required_secrets: Vec<SecretName>,
    /// Secret names that may be injected only when present.
    pub optional_secrets: Vec<SecretName>,
    /// Normalized union of required and optional secret names.
    pub allowed_secrets: Vec<SecretName>,
}

impl PathEnvSet {
    /// Adds this scope's names to a command without changing its execution options.
    pub fn apply_to(&self, policy: &mut super::CommandPolicy) {
        use std::collections::BTreeSet;
        let mut required = policy.required_secrets.iter().cloned().collect::<BTreeSet<_>>();
        let mut optional = policy.optional_secrets.iter().cloned().collect::<BTreeSet<_>>();
        for name in &self.required_secrets {
            required.insert(name.clone());
            optional.remove(name);
        }
        for name in &self.optional_secrets {
            if !required.contains(name) {
                optional.insert(name.clone());
            }
        }
        policy.required_secrets = required.into_iter().collect();
        policy.optional_secrets = optional.into_iter().collect();
        policy.allowed_secrets = policy
            .required_secrets
            .iter()
            .chain(&policy.optional_secrets)
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }

    pub(super) fn from_toml_value(
        path: &str,
        value: toml::Value,
    ) -> Result<Self, PolicyParseError> {
        let normalized_path = normalize_path_scope(path)?;
        let Some(_) = value.as_table() else {
            return Err(PolicyParseError::PathScopeMustBeTable { path: path.to_owned() });
        };
        let raw = value.try_into::<RawPathEnvSet>().map_err(|source| {
            PolicyParseError::PathScopeSchema { path: path.to_owned(), message: source.to_string() }
        })?;
        let profile = raw
            .profile
            .map(ProfileName::new)
            .transpose()
            .map_err(|_| PolicyParseError::InvalidPathScopeProfile { path: path.to_owned() })?;
        let required_secrets = parse_secret_list(
            path,
            REQUIRED_SECRETS_FIELD,
            raw.required_secrets.unwrap_or_default(),
        )?;
        let optional_secrets = parse_secret_list(
            path,
            OPTIONAL_SECRETS_FIELD,
            raw.optional_secrets.unwrap_or_default(),
        )?;
        let allowed_secrets =
            normalize_allowed_secrets(path, &required_secrets, &optional_secrets)?;
        Ok(Self {
            path: normalized_path,
            profile,
            required_secrets,
            optional_secrets,
            allowed_secrets,
        })
    }

    /// Returns true when `relative_cwd` is inside this path scope.
    #[must_use]
    pub fn matches(&self, relative_cwd: &Path) -> bool {
        self.path == Path::new(".")
            || relative_cwd == self.path
            || relative_cwd.starts_with(&self.path)
    }

    /// Returns the path depth used for longest-prefix matching.
    #[must_use]
    pub fn depth(&self) -> usize {
        if self.path == Path::new(".") {
            0
        } else {
            self.path
                .components()
                .filter(|component| matches!(component, Component::Normal(_)))
                .count()
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPathEnvSet {
    profile: Option<String>,
    required_secrets: Option<Vec<String>>,
    optional_secrets: Option<Vec<String>>,
}

fn normalize_path_scope(path: &str) -> Result<PathBuf, PolicyParseError> {
    if path.trim().is_empty() {
        return Err(PolicyParseError::EmptyPathScope);
    }
    let raw = Path::new(path);
    if raw.is_absolute() {
        return Err(PolicyParseError::InvalidPathScope { path: path.to_owned() });
    }
    let mut normalized = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PolicyParseError::InvalidPathScope { path: path.to_owned() });
            }
        }
    }
    if normalized.as_os_str().is_empty() { Ok(PathBuf::from(".")) } else { Ok(normalized) }
}
