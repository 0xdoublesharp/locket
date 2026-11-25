//! Error types for command-policy parsing and validation.

use thiserror::Error;

/// Error returned when a command policy document is invalid.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum PolicyParseError {
    /// A variable contract is invalid; diagnostic never contains its values.
    #[error("invalid variable contract {name}: {reason}")]
    VariableContract {
        /// Valid variable name, or a redacted placeholder.
        name: String,
        /// Static value-free reason.
        reason: &'static str,
    },
    /// TOML syntax or decoding failed.
    #[error("invalid policy TOML: {message}")]
    Toml {
        /// Parser error message.
        message: String,
    },
    /// The document root was not a TOML table.
    #[error("policy document root must be a table")]
    RootMustBeTable,
    /// The top-level `commands` value was not a table.
    #[error("commands must be a table")]
    CommandsMustBeTable,
    /// The top-level `paths` value was not a table.
    #[error("paths must be a table")]
    PathsMustBeTable,
    /// The top-level `secrets` value was not a table.
    #[error("secrets must be a table")]
    SecretsMustBeTable,
    /// A command table key was empty.
    #[error("command name must not be empty")]
    EmptyCommandName,
    /// A command body was not a table.
    #[error("command {command} must be a table")]
    CommandMustBeTable {
        /// Command policy name.
        command: String,
    },
    /// The command body contained the ambiguous `name` field.
    #[error("command {command} must not contain a name field")]
    NameFieldUnsupported {
        /// Command policy name.
        command: String,
    },
    /// The command body contained the unsupported `secrets` shorthand.
    #[error("command {command} must not contain a secrets field")]
    SecretsFieldUnsupported {
        /// Command policy name.
        command: String,
    },
    /// A command body did not match the v1 schema.
    #[error("command {command} schema error: {message}")]
    CommandSchema {
        /// Command policy name.
        command: String,
        /// Deserializer error message.
        message: String,
    },
    /// Neither `argv` nor `shell` was supplied.
    #[error("command {command} must define argv or shell")]
    MissingCommandSpec {
        /// Command policy name.
        command: String,
    },
    /// Both `argv` and `shell` were supplied.
    #[error("command {command} must not define both argv and shell")]
    CommandSpecConflict {
        /// Command policy name.
        command: String,
    },
    /// `argv` was present but empty.
    #[error("command {command} argv must not be empty")]
    EmptyArgv {
        /// Command policy name.
        command: String,
    },
    /// `shell` was present but blank.
    #[error("command {command} shell must not be empty")]
    EmptyShell {
        /// Command policy name.
        command: String,
    },
    /// A secret name failed validation.
    #[error("command {command} field {field} contains invalid secret name {name}")]
    InvalidSecretName {
        /// Command policy name.
        command: String,
        /// Secret-list field name.
        field: &'static str,
        /// Invalid secret name.
        name: String,
    },
    /// A secret-list field contains the same name more than once.
    #[error("command {command} field {field} contains duplicate secret name {name}")]
    DuplicateSecretName {
        /// Command policy name.
        command: String,
        /// Secret-list field name.
        field: &'static str,
        /// Duplicate secret name.
        name: String,
    },
    /// A secret name is both required and optional.
    #[error("command {command} secret {name} cannot be both required and optional")]
    SecretRequiredAndOptional {
        /// Command policy name.
        command: String,
        /// Conflicting secret name.
        name: String,
    },
    /// A command requests the same name from both vaults.
    #[error("command {command} secret {name} cannot be both a shared and a project secret")]
    SharedAndProjectSecret {
        /// Command policy name.
        command: String,
        /// Conflicting secret name.
        name: String,
    },
    /// `env_mode` was not a supported string.
    #[error("command {command} has invalid env_mode {value}")]
    InvalidEnvMode {
        /// Command policy name.
        command: String,
        /// Invalid mode string.
        value: String,
    },
    /// `override` was not a supported string.
    #[error("command {command} has invalid override {value}")]
    InvalidOverrideBehavior {
        /// Command policy name.
        command: String,
        /// Invalid override string.
        value: String,
    },
    /// `ttl` was not a valid duration string.
    #[error("command {command} has invalid ttl {value}")]
    InvalidTtl {
        /// Command policy name.
        command: String,
        /// Invalid duration string.
        value: String,
    },
    /// `ttl` exceeds the built-in policy cap.
    #[error("command {command} ttl {ttl_seconds}s exceeds maximum {max_seconds}s")]
    TtlExceedsMaximum {
        /// Command policy name.
        command: String,
        /// Parsed TTL seconds.
        ttl_seconds: u64,
        /// Maximum accepted TTL seconds.
        max_seconds: u64,
    },
    /// `external_env_sources` contained an unsupported string.
    #[error("command {command} has invalid external env source {value}")]
    InvalidExternalEnvSource {
        /// Command policy name.
        command: String,
        /// Invalid source string.
        value: String,
    },
    /// `external_env_sources` contained a blank file path.
    #[error("command {command} external env file path must not be empty")]
    EmptyExternalEnvFile {
        /// Command policy name.
        command: String,
    },
    /// The document root did not include `schema_version`.
    #[error("policy document missing required schema_version at root")]
    MissingSchemaVersion,
    /// The document root `schema_version` was not a positive integer.
    #[error("policy document schema_version must be a positive integer")]
    InvalidSchemaVersion,
    /// The document root `schema_version` was not the supported value.
    #[error("policy document schema_version {version} is not supported (expected 1)")]
    UnsupportedSchemaVersion {
        /// Schema version supplied at the root of the document.
        version: u64,
    },
    /// The document root contained a key outside the recognized v1 schema.
    #[error("policy document contains unknown top-level key {key}")]
    UnknownTopLevelKey {
        /// Unknown root-level key name.
        key: String,
    },
    /// A path scope table key was empty.
    #[error("path scope must not be empty")]
    EmptyPathScope,
    /// A path scope table key was absolute or escaped the project root.
    #[error("path scope {path} must be a project-relative path")]
    InvalidPathScope {
        /// Invalid path scope.
        path: String,
    },
    /// Multiple path scope table keys normalized to the same project-relative path.
    #[error("path scope {path} is defined more than once after normalization")]
    DuplicatePathScope {
        /// Normalized path scope.
        path: String,
    },
    /// A path scope body was not a table.
    #[error("path scope {path} must be a table")]
    PathScopeMustBeTable {
        /// Path scope key.
        path: String,
    },
    /// A path scope body did not match the v1 schema.
    #[error("path scope {path} schema error: {message}")]
    PathScopeSchema {
        /// Path scope key.
        path: String,
        /// Deserializer error message.
        message: String,
    },
    /// A path scope profile failed validation.
    #[error("path scope {path} contains invalid profile")]
    InvalidPathScopeProfile {
        /// Path scope key.
        path: String,
    },
    /// A secret ACL table key was not a valid secret name.
    #[error("secret ACL name {secret} is invalid")]
    InvalidSecretAclName {
        /// Secret ACL table key.
        secret: String,
    },
    /// A secret ACL body was not a table.
    #[error("secret ACL {secret} must be a table")]
    SecretAclMustBeTable {
        /// Secret ACL table key.
        secret: String,
    },
    /// A secret ACL body did not match the v1 schema.
    #[error("secret ACL {secret} schema error: {message}")]
    SecretAclSchema {
        /// Secret ACL table key.
        secret: String,
        /// Deserializer error message.
        message: String,
    },
    /// A secret ACL did not contain any constraints.
    #[error(
        "secret ACL {secret} must define at least one allow_commands, allow_argv, or allow_paths entry"
    )]
    EmptySecretAcl {
        /// Secret ACL table key.
        secret: String,
    },
    /// A secret ACL pattern was empty or escaped the project root.
    #[error("secret ACL {secret} field {field} contains invalid pattern {pattern}")]
    InvalidSecretAclPattern {
        /// Secret ACL table key.
        secret: String,
        /// ACL field name.
        field: &'static str,
        /// Invalid ACL pattern.
        pattern: String,
    },
}
