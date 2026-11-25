//! Process execution and environment injection for Locket.

// age 0.11 enters through locket-core and carries older transitive crates
// alongside workspace versions. The sealed-bundle dependency owns that skew.
#![allow(clippy::multiple_crate_versions)]

use std::borrow::Cow;
use std::process::Command;

pub use locket_core::{
    EnvMap, EnvMergeError, EnvMode, EnvOverrideMode, EnvValue, env_value, merge_environment,
};
use thiserror::Error;

mod egress_proxy;
mod ephemeral_env_file;
mod network_sandbox;
mod secret_encoding;
mod streaming_redactor;

pub use egress_proxy::{
    EgressBlockReason, EgressEvent, EgressProxyBroker, EgressProxyConfig, EgressProxyError,
    EgressSecretBinding,
};
pub use ephemeral_env_file::{
    EphemeralEnvFile, EphemeralEnvFileError, secure_erase_supported, write_ephemeral_env_file,
};
pub use network_sandbox::{
    NetworkContainmentError, NetworkContainmentPolicy, NetworkContainmentSupport,
    network_containment_support, wrap_command_with_network_containment,
};
pub use streaming_redactor::{
    StreamingRedactionStats, StreamingRedactor, StreamingRedactorConfig, redact_child_output,
};

/// Parent environment names considered safe in [`EnvMode::Minimal`].
pub const DEFAULT_SAFE_ALLOWLIST: &[&str] =
    &["PATH", "HOME", "USER", "SHELL", "TMPDIR", "LANG", "LC_*", "TERM", "CI"];

/// Execution request before a child process is built.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExecutionRequest {
    /// Command argv. The first item is the program name.
    pub argv: Vec<String>,
    /// Parent process environment snapshot.
    pub parent_env: EnvMap,
    /// Explicit inherited parent environment names.
    pub inherit_env: Vec<String>,
    /// External environment sources already resolved by the caller.
    pub external_env: EnvMap,
    /// Authorized Locket secret values for this process only.
    pub locket_env: EnvMap,
    /// Base environment mode.
    pub env_mode: EnvMode,
    /// Conflict behavior for Locket values.
    pub override_mode: EnvOverrideMode,
}

impl ExecutionRequest {
    /// Creates a request with strict isolation and no environment layers.
    #[must_use]
    pub const fn strict(argv: Vec<String>) -> Self {
        Self {
            argv,
            parent_env: EnvMap::new(),
            inherit_env: Vec::new(),
            external_env: EnvMap::new(),
            locket_env: EnvMap::new(),
            env_mode: EnvMode::Strict,
            override_mode: EnvOverrideMode::Locket,
        }
    }
}

/// Child process details after environment policy is applied.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PreparedExecution {
    /// Program to execute.
    pub program: String,
    /// Arguments passed after the program.
    pub args: Vec<String>,
    /// Complete child environment. It is intended to be applied after
    /// `Command::env_clear`.
    pub env: EnvMap,
}

impl PreparedExecution {
    /// Builds a [`Command`] with `env_clear` already applied.
    #[must_use]
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args).env_clear();
        for (name, value) in &self.env {
            command.env(name, value.as_str());
        }
        command
    }
}

/// Error returned while preparing process execution.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum ExecError {
    /// No program was supplied.
    #[error("empty command")]
    EmptyCommand,
    /// Environment construction failed before process spawn.
    #[error(transparent)]
    Environment(#[from] EnvMergeError),
}

/// Applies Locket environment policy and returns a spawn-ready plan.
///
/// Broad inheritance omits loader and interpreter startup controls unless named
/// in `inherit_env`. External sources are already authorized by the caller.
///
/// # Errors
///
/// Returns [`ExecError::EmptyCommand`] when `request.argv` has no program.
/// Returns [`ExecError::Environment`] when environment merge policy rejects a
/// conflict before spawn.
pub fn prepare_execution(request: &ExecutionRequest) -> Result<PreparedExecution, ExecError> {
    let Some((program, args)) = request.argv.split_first() else {
        return Err(ExecError::EmptyCommand);
    };
    let inherit_env = request.inherit_env.iter().map(String::as_str).collect::<Vec<_>>();
    let parent_env = match request.env_mode {
        EnvMode::Strict | EnvMode::Minimal => Cow::Borrowed(&request.parent_env),
        EnvMode::Merge | EnvMode::Passthrough => Cow::Owned(
            request
                .parent_env
                .iter()
                .filter(|(name, _)| {
                    !is_startup_control(name) || inherit_env.contains(&name.as_str())
                })
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        ),
    };
    let mut env = merge_environment(
        &parent_env,
        DEFAULT_SAFE_ALLOWLIST,
        &inherit_env,
        &request.external_env,
        &request.locket_env,
        request.env_mode,
        request.override_mode,
    )?;
    restrict_child_search_path(&mut env);

    Ok(PreparedExecution { program: program.clone(), args: args.to_vec(), env })
}

fn is_startup_control(name: &str) -> bool {
    #[cfg(windows)]
    let upper = name.to_ascii_uppercase();
    #[cfg(windows)]
    let name = upper.as_str();
    name.starts_with("LD_")
        || name.starts_with("DYLD_")
        || name.starts_with("BASH_FUNC_")
        || matches!(
            name,
            "BASH_ENV"
                | "ENV"
                | "IFS"
                | "NODE_OPTIONS"
                | "NODE_PATH"
                | "PYTHONPATH"
                | "PYTHONHOME"
                | "PYTHONSTARTUP"
                | "RUBYOPT"
                | "RUBYLIB"
                | "PERL5OPT"
                | "PERL5LIB"
                | "PERLLIB"
                | "GCONV_PATH"
        )
}

/// Identifies environment names that can change how the child loads or locates code.
#[must_use]
pub fn is_child_runtime_control(name: &str) -> bool {
    #[cfg(windows)]
    let is_path = name.eq_ignore_ascii_case("PATH");
    #[cfg(not(windows))]
    let is_path = name == "PATH";
    is_path || is_startup_control(name)
}

/// Removes current-directory and other relative search entries from the child PATH.
/// An emptied Unix PATH uses the standard system directories.
pub fn restrict_child_search_path(env: &mut EnvMap) {
    #[cfg(not(windows))]
    let paths = env.get_mut("PATH").into_iter();
    #[cfg(windows)]
    let paths = env
        .iter_mut()
        .filter_map(|(name, value)| name.eq_ignore_ascii_case("PATH").then_some(value));
    for path in paths {
        let absolute = std::env::split_paths(path.as_str()).filter(|entry| entry.is_absolute());
        // The entries were split from an existing PATH, so they can be joined again.
        if let Ok(joined) = std::env::join_paths(absolute) {
            let joined = joined.into_string().unwrap_or_default();
            #[cfg(unix)]
            let joined = if joined.is_empty() { "/usr/bin:/bin".to_owned() } else { joined };
            *path = env_value(joined);
        }
    }
}

/// Selects parent environment values that a policy explicitly allows through an
/// external parent source.
#[must_use]
pub fn resolve_parent_external_env<'a>(
    parent_env: &EnvMap,
    allowed_names: impl IntoIterator<Item = &'a str>,
) -> EnvMap {
    allowed_names
        .into_iter()
        .filter_map(|name| parent_env.get(name).map(|value| (name.to_owned(), value.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::{ExecError, ExecutionRequest, prepare_execution, resolve_parent_external_env};
    use crate::{EnvMap, EnvMode, EnvOverrideMode};

    fn env(values: &[(&str, &str)]) -> EnvMap {
        values.iter().map(|(name, value)| ((*name).to_owned(), crate::env_value(*value))).collect()
    }

    #[test]
    fn prepares_strict_child_environment_without_parent_leakage() -> Result<(), ExecError> {
        let mut request = ExecutionRequest::strict(vec!["node".to_owned(), "server.js".to_owned()]);
        request.parent_env = env(&[("PATH", "/bin"), ("SECRET", "parent")]);
        request.locket_env = env(&[("DATABASE_URL", "postgres://local")]);

        let prepared = prepare_execution(&request)?;

        assert_eq!(prepared.program, "node");
        assert_eq!(prepared.args, ["server.js"]);
        assert_eq!(prepared.env.len(), 1);
        assert_eq!(
            prepared.env.get("DATABASE_URL").map(|value| value.as_str()),
            Some("postgres://local")
        );
        assert!(!prepared.env.contains_key("SECRET"));
        assert!(!prepared.env.contains_key("PATH"));
        Ok(())
    }

    #[test]
    fn minimal_mode_inherits_safe_allowlist() -> Result<(), ExecError> {
        let bin_dir = if cfg!(windows) { r"C:\bin" } else { "/bin" };
        let mut request = ExecutionRequest::strict(vec!["tool".to_owned()]);
        request.parent_env = env(&[
            ("PATH", bin_dir),
            ("HOME", "/home/dev"),
            ("USER", "dev"),
            ("SHELL", "/bin/zsh"),
            ("TMPDIR", "/tmp"),
            ("LANG", "en_US.UTF-8"),
            ("LC_CTYPE", "UTF-8"),
            ("TERM", "xterm-256color"),
            ("CI", "true"),
            ("LOGNAME", "dev"),
            ("TEMP", "/tmp"),
            ("TMP", "/tmp"),
            ("SECRET", "parent"),
        ]);
        request.env_mode = EnvMode::Minimal;

        let prepared = prepare_execution(&request)?;

        assert_eq!(prepared.env.get("PATH").map(|value| value.as_str()), Some(bin_dir));
        assert_eq!(prepared.env.get("HOME").map(|value| value.as_str()), Some("/home/dev"));
        assert_eq!(prepared.env.get("USER").map(|value| value.as_str()), Some("dev"));
        assert_eq!(prepared.env.get("SHELL").map(|value| value.as_str()), Some("/bin/zsh"));
        assert_eq!(prepared.env.get("TMPDIR").map(|value| value.as_str()), Some("/tmp"));
        assert_eq!(prepared.env.get("LANG").map(|value| value.as_str()), Some("en_US.UTF-8"));
        assert_eq!(prepared.env.get("LC_CTYPE").map(|value| value.as_str()), Some("UTF-8"));
        assert_eq!(prepared.env.get("TERM").map(|value| value.as_str()), Some("xterm-256color"));
        assert_eq!(prepared.env.get("CI").map(|value| value.as_str()), Some("true"));
        assert!(!prepared.env.contains_key("LOGNAME"));
        assert!(!prepared.env.contains_key("TEMP"));
        assert!(!prepared.env.contains_key("TMP"));
        assert!(!prepared.env.contains_key("SECRET"));
        Ok(())
    }

    #[test]
    fn explicit_inherit_augments_strict_mode() -> Result<(), ExecError> {
        let mut request = ExecutionRequest::strict(vec!["tool".to_owned()]);
        request.parent_env = env(&[("NODE_ENV", "development"), ("SECRET", "parent")]);
        request.inherit_env = vec!["NODE_ENV".to_owned()];

        let prepared = prepare_execution(&request)?;

        assert_eq!(prepared.env.get("NODE_ENV").map(|value| value.as_str()), Some("development"));
        assert!(!prepared.env.contains_key("SECRET"));
        Ok(())
    }

    #[test]
    fn broad_inheritance_omits_ambient_startup_controls() -> Result<(), ExecError> {
        let mut request = ExecutionRequest::strict(vec!["tool".to_owned()]);
        request.parent_env = env(&[
            ("LD_PRELOAD", "loader-placeholder"),
            ("LD_AUDIT", "loader-placeholder"),
            ("LD_LIBRARY_PATH", "loader-placeholder"),
            ("DYLD_INSERT_LIBRARIES", "loader-placeholder"),
            ("DYLD_LIBRARY_PATH", "loader-placeholder"),
            ("DYLD_FRAMEWORK_PATH", "loader-placeholder"),
            ("BASH_ENV", "shell-placeholder"),
            ("ENV", "shell-placeholder"),
            ("IFS", "shell-placeholder"),
            ("NODE_OPTIONS", "runtime-placeholder"),
            ("PYTHONPATH", "runtime-placeholder"),
            ("PYTHONSTARTUP", "runtime-placeholder"),
            ("RUBYOPT", "runtime-placeholder"),
            ("PERL5OPT", "runtime-placeholder"),
            ("GCONV_PATH", "runtime-placeholder"),
            ("NODE_ENV", "development"),
        ]);
        request.locket_env = env(&[("APP_TOKEN", "fixture")]);
        request.inherit_env = vec!["PYTHONPATH".into()];
        request.external_env = env(&[("NODE_OPTIONS", "policy-placeholder")]);

        for mode in [EnvMode::Merge, EnvMode::Passthrough] {
            request.env_mode = mode;
            let child = prepare_execution(&request)?;
            assert_eq!(
                child.env,
                env(&[
                    ("APP_TOKEN", "fixture"),
                    ("NODE_ENV", "development"),
                    ("NODE_OPTIONS", "policy-placeholder"),
                    ("PYTHONPATH", "runtime-placeholder"),
                ])
            );
        }
        Ok(())
    }

    #[test]
    fn override_error_rejects_conflict_before_spawn() {
        let mut request = ExecutionRequest::strict(vec!["tool".to_owned()]);
        request.external_env = env(&[("DATABASE_URL", "external")]);
        request.locket_env = env(&[("DATABASE_URL", "locket")]);
        request.override_mode = EnvOverrideMode::Error;

        let result = prepare_execution(&request);

        assert!(matches!(result, Err(ExecError::Environment(_))));
    }

    #[test]
    fn default_override_mode_prefers_locket_values() -> Result<(), ExecError> {
        let external_bin = if cfg!(windows) { r"C:\external\bin" } else { "/external/bin" };
        let mut request = ExecutionRequest::strict(vec!["tool".to_owned()]);
        request.external_env = env(&[("DATABASE_URL", "external"), ("PATH", external_bin)]);
        request.locket_env = env(&[("DATABASE_URL", "locket")]);

        let prepared = prepare_execution(&request)?;

        assert_eq!(prepared.env.get("DATABASE_URL").map(|value| value.as_str()), Some("locket"));
        assert_eq!(prepared.env.get("PATH").map(|value| value.as_str()), Some(external_bin));
        Ok(())
    }

    #[test]
    fn explicit_inherit_ignores_missing_parent_values() -> Result<(), ExecError> {
        let mut request = ExecutionRequest::strict(vec!["tool".to_owned()]);
        request.parent_env = env(&[("PATH", "/bin")]);
        request.inherit_env = vec!["MISSING".to_owned()];

        let prepared = prepare_execution(&request)?;

        assert!(!prepared.env.contains_key("MISSING"));
        assert!(!prepared.env.contains_key("PATH"));
        Ok(())
    }

    #[test]
    fn prepared_command_clears_ambient_environment() -> Result<(), ExecError> {
        let mut request = ExecutionRequest::strict(vec!["tool".to_owned(), "--flag".to_owned()]);
        request.locket_env = env(&[("TOKEN", "secret")]);

        let prepared = prepare_execution(&request)?;
        let command = prepared.command();

        assert_eq!(command.get_program(), OsStr::new("tool"));
        assert_eq!(command.get_args().collect::<Vec<_>>(), [OsStr::new("--flag")]);
        assert!(
            command
                .get_envs()
                .any(|(name, value)| { name == OsStr::new("TOKEN") && value.is_some() })
        );
        Ok(())
    }

    #[test]
    fn rejects_empty_command() {
        let request = ExecutionRequest::strict(Vec::new());

        assert_eq!(prepare_execution(&request), Err(ExecError::EmptyCommand));
    }

    #[test]
    fn parent_external_env_selects_only_allowed_names() {
        let parent_env = env(&[
            ("DATABASE_URL", "postgres://parent"),
            ("API_TOKEN", "parent-token"),
            ("UNRELATED", "not-allowed"),
        ]);

        let selected = resolve_parent_external_env(&parent_env, ["DATABASE_URL", "MISSING"]);

        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected.get("DATABASE_URL").map(|value| value.as_str()),
            Some("postgres://parent")
        );
        assert!(!selected.contains_key("API_TOKEN"));
        assert!(!selected.contains_key("UNRELATED"));
    }
}
