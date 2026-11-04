//! Top-level `[commands]` document parser.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use super::command::CommandPolicy;
use super::error::PolicyParseError;
use super::path_scope::PathEnvSet;
use super::secret_acl::SecretAccessPolicy;

const COMMANDS_TABLE: &str = "commands";
const PATHS_TABLE: &str = "paths";
const SECRETS_TABLE: &str = "secrets";
const SCHEMA_VERSION_FIELD: &str = "schema_version";

/// Currently supported `locket.toml` policy document schema version.
pub const SUPPORTED_POLICY_SCHEMA_VERSION: u64 = 1;

/// Top-level keys recognized at the root of a `locket.toml` document.
///
/// The list mirrors the v1 schema: `schema_version` and `commands` come from this
/// crate; `project_id`, `name`, and `default_profile` are project metadata in
/// [`crate::ProjectConfig`]; `bootstrap`, `scan`, and `example` are CLI-side
/// configuration tables. Any other root-level key fails parsing with
/// [`PolicyParseError::UnknownTopLevelKey`].
const ALLOWED_ROOT_KEYS: &[&str] = &[
    SCHEMA_VERSION_FIELD,
    COMMANDS_TABLE,
    PATHS_TABLE,
    SECRETS_TABLE,
    "project_id",
    "name",
    "default_profile",
    "bootstrap",
    "scan",
    "example",
    "variables",
];

/// Parsed command policies from a `locket.toml` document.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PolicyDocument {
    /// Schema version declared at the document root.
    pub schema_version: u64,
    /// Commit-safe variable contracts, separate from secret ACLs.
    pub variables: BTreeMap<String, super::VariableContract>,
    /// Command policies keyed by `[commands.<name>]`.
    pub commands: BTreeMap<String, CommandPolicy>,
    /// Path-scoped environment sets keyed by `[paths."<relative-path>"]`.
    pub path_scopes: BTreeMap<String, PathEnvSet>,
    /// Secret-level command/path ACLs keyed by `[secrets.<NAME>]`.
    pub secret_access: BTreeMap<String, SecretAccessPolicy>,
}

impl PolicyDocument {
    /// Returns the requested policy with the deepest matching path scope applied.
    #[must_use]
    pub fn effective_command(&self, name: &str, root: &Path, cwd: &Path) -> Option<CommandPolicy> {
        let mut policy = self.commands.get(name)?.clone();
        if let Some(scope) = self.path_scope_for(root, cwd) {
            scope.apply_to(&mut policy);
        }
        Some(policy)
    }

    /// Lists explicitly selected names denied by the shared command, argv and path ACL rules.
    #[must_use]
    pub fn denied_secrets<'a>(
        &self,
        command: &str,
        argv: Option<&[String]>,
        relative_cwd: &Path,
        names: &'a [crate::SecretName],
    ) -> Vec<&'a crate::SecretName> {
        names
            .iter()
            .filter(|name| {
                self.secret_access
                    .get(name.as_str())
                    .is_some_and(|acl| !acl.allows(command, argv, relative_cwd))
            })
            .collect()
    }

    /// Parses command policies from a TOML document.
    ///
    /// The document must declare `schema_version = 1` at the root. Top-level keys
    /// outside the v1 schema fail parsing with [`PolicyParseError::UnknownTopLevelKey`]
    /// so future fields cannot silently downgrade existing tooling. Each command
    /// body is validated strictly.
    ///
    /// Duplicate `[commands.<name>]` headers are rejected by the underlying
    /// TOML parser before this function ever sees the parsed value, so the
    /// `BTreeMap::insert` below cannot silently overwrite a prior entry.
    /// `rejects_duplicate_command_table_at_toml_layer` in `policy::tests`
    /// pins this behavior so future TOML-crate upgrades cannot quietly relax
    /// it without surfacing a test failure.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyParseError`] for invalid TOML, missing or unsupported
    /// `schema_version`, unknown top-level keys, malformed command tables,
    /// unsupported fields, or invalid normalized policy values.
    pub fn from_toml_str(input: &str) -> Result<Self, PolicyParseError> {
        let value = toml::from_str::<toml::Value>(input).map_err(|_| PolicyParseError::Toml {
            message: "syntax error (source redacted)".into(),
        })?;
        Self::from_toml_value(&value)
    }

    /// Validates an already parsed TOML document without serializing or parsing it again.
    ///
    /// Applies the same schema, command, path, and secret ACL validation as
    /// [`Self::from_toml_str`]. Source parsers must reject duplicate table definitions.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyParseError`] for unsupported schema versions, unknown keys,
    /// malformed tables, unsupported fields, or invalid normalized policy values.
    pub fn from_toml_value(value: &toml::Value) -> Result<Self, PolicyParseError> {
        let Some(root) = value.as_table() else {
            return Err(PolicyParseError::RootMustBeTable);
        };

        let schema_version = require_schema_version(root)?;

        for key in root.keys() {
            if !ALLOWED_ROOT_KEYS.iter().any(|allowed| allowed == key) {
                return Err(PolicyParseError::UnknownTopLevelKey { key: key.clone() });
            }
        }

        let commands = parse_commands(root)?;
        let path_scopes = parse_path_scopes(root)?;
        let secret_access = parse_secret_access(root)?;

        let variables = super::variable_contract::parse_variables(root.get("variables"))?;
        Ok(Self { schema_version, variables, commands, path_scopes, secret_access })
    }

    /// Finds the path scope that best matches `cwd` under `project_root`.
    ///
    /// When multiple scopes match, the deepest project-relative path wins.
    #[must_use]
    pub fn path_scope_for(&self, project_root: &Path, cwd: &Path) -> Option<&PathEnvSet> {
        let relative_cwd = match cwd.strip_prefix(project_root) {
            Ok(path) if path.as_os_str().is_empty() => Path::new("."),
            Ok(path) => path,
            Err(_) => return None,
        };
        self.path_scopes
            .values()
            .filter(|scope| scope.matches(relative_cwd))
            .max_by_key(|scope| scope.depth())
    }
}

fn parse_secret_access(
    root: &toml::value::Table,
) -> Result<BTreeMap<String, SecretAccessPolicy>, PolicyParseError> {
    let Some(secrets) = root.get(SECRETS_TABLE) else {
        return Ok(BTreeMap::new());
    };
    let Some(secrets) = secrets.as_table() else {
        return Err(PolicyParseError::SecretsMustBeTable);
    };

    let mut parsed = BTreeMap::new();
    for (name, body) in secrets {
        let access = SecretAccessPolicy::from_toml_value(name, body.clone())?;
        parsed.insert(name.clone(), access);
    }
    Ok(parsed)
}

fn parse_commands(
    root: &toml::value::Table,
) -> Result<BTreeMap<String, CommandPolicy>, PolicyParseError> {
    let Some(commands) = root.get(COMMANDS_TABLE) else {
        return Ok(BTreeMap::new());
    };
    let Some(commands) = commands.as_table() else {
        return Err(PolicyParseError::CommandsMustBeTable);
    };

    let mut parsed = BTreeMap::new();
    for (name, body) in commands {
        let policy = CommandPolicy::from_toml_value(name, body.clone())?;
        parsed.insert(name.clone(), policy);
    }
    Ok(parsed)
}

fn parse_path_scopes(
    root: &toml::value::Table,
) -> Result<BTreeMap<String, PathEnvSet>, PolicyParseError> {
    let Some(paths) = root.get(PATHS_TABLE) else {
        return Ok(BTreeMap::new());
    };
    let Some(paths) = paths.as_table() else {
        return Err(PolicyParseError::PathsMustBeTable);
    };

    let mut parsed = BTreeMap::new();
    let mut normalized_paths = BTreeMap::new();
    for (path, body) in paths {
        let scope = PathEnvSet::from_toml_value(path, body.clone())?;
        let normalized = scope.path.to_string_lossy().into_owned();
        if normalized_paths.insert(normalized.clone(), path.clone()).is_some() {
            return Err(PolicyParseError::DuplicatePathScope { path: normalized });
        }
        parsed.insert(path.clone(), scope);
    }
    Ok(parsed)
}

fn require_schema_version(root: &toml::value::Table) -> Result<u64, PolicyParseError> {
    let Some(value) = root.get(SCHEMA_VERSION_FIELD) else {
        return Err(PolicyParseError::MissingSchemaVersion);
    };
    let Some(version) = value.as_integer() else {
        return Err(PolicyParseError::InvalidSchemaVersion);
    };
    if version <= 0 {
        return Err(PolicyParseError::InvalidSchemaVersion);
    }
    let version = u64::try_from(version).map_err(|_| PolicyParseError::InvalidSchemaVersion)?;
    if version != SUPPORTED_POLICY_SCHEMA_VERSION {
        return Err(PolicyParseError::UnsupportedSchemaVersion { version });
    }
    Ok(version)
}

impl FromStr for PolicyDocument {
    type Err = PolicyParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_toml_str(input)
    }
}
