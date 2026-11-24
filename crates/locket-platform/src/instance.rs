//! Separates installed Locket from development builds.
//!
//! Release builds use the installed instance. Debug builds always use the
//! development instance, with its own data directory, configuration
//! directory, keychain services, agent directory, and Windows pipe name.
//! A release build also uses the development instance when
//! `LOCKET_INSTANCE` is set to any non-empty value.
//!
//! The variable only ever selects the development instance. An inherited
//! value therefore cannot point a development build at the installed vault.
//! The installed names below must stay byte-identical so existing vaults
//! and keychain entries keep resolving.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use directories::ProjectDirs;

/// Environment variable that selects the development instance when set.
pub const INSTANCE_ENV: &str = "LOCKET_INSTANCE";

/// Which Locket namespace this process reads and writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocketInstance {
    /// The installed release namespace that holds real secrets.
    Installed,
    /// The development namespace used by debug builds and opted-in release builds.
    Dev,
}

impl LocketInstance {
    /// Returns this process's instance, resolved once from the build profile
    /// and [`INSTANCE_ENV`].
    #[must_use]
    pub fn current() -> Self {
        static CURRENT: OnceLock<LocketInstance> = OnceLock::new();
        *CURRENT.get_or_init(|| {
            Self::select(cfg!(debug_assertions), std::env::var_os(INSTANCE_ENV).as_deref())
        })
    }

    /// Selects an instance from the build profile and the environment value.
    ///
    /// Debug builds are always [`LocketInstance::Dev`]. Any non-empty value
    /// selects [`LocketInstance::Dev`]; no value selects the installed
    /// instance.
    #[must_use]
    pub fn select(debug_build: bool, env_value: Option<&OsStr>) -> Self {
        if debug_build || env_value.is_some_and(|value| !value.is_empty()) {
            Self::Dev
        } else {
            Self::Installed
        }
    }

    /// Short label for status output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Dev => "dev",
        }
    }

    /// Application name used for the platform data and configuration directories.
    #[must_use]
    pub const fn application_name(self) -> &'static str {
        match self {
            Self::Installed => "Locket",
            Self::Dev => "Locket Dev",
        }
    }

    /// Platform data and configuration directories for this instance.
    #[must_use]
    pub fn project_dirs(self) -> Option<ProjectDirs> {
        ProjectDirs::from("dev", "0xdoublesharp", self.application_name())
    }

    /// Keychain service for project master keys and automation-client keys.
    #[must_use]
    pub const fn keyring_service(self) -> &'static str {
        match self {
            Self::Installed => "dev.0xdoublesharp.locket",
            Self::Dev => "dev.0xdoublesharp.locket-dev",
        }
    }

    /// Windows named-pipe prefix for the agent endpoint.
    #[must_use]
    pub const fn agent_pipe_prefix(self) -> &'static str {
        match self {
            Self::Installed => r"\\.\pipe\locket-agent-",
            Self::Dev => r"\\.\pipe\locket-dev-agent-",
        }
    }

    /// Directory name for agent runtime files under a platform runtime directory.
    #[must_use]
    pub const fn agent_dir_name(self) -> &'static str {
        match self {
            Self::Installed => "locket",
            Self::Dev => "locket-dev",
        }
    }

    /// Directory name for agent runtime files directly under the home directory.
    #[must_use]
    pub const fn home_dir_name(self) -> &'static str {
        match self {
            Self::Installed => ".locket",
            Self::Dev => ".locket-dev",
        }
    }

    /// Default agent directory for `platform` (a `std::env::consts::OS` value).
    ///
    /// - Linux: `$XDG_RUNTIME_DIR/<agent dir>` when set, else `<HOME>/<home dir>`.
    /// - macOS: `<HOME>/Library/Application Support/<agent dir>`.
    /// - Other platforms: `<HOME>/<home dir>`. Windows keeps pid and log files
    ///   there; its endpoint is the named pipe.
    #[must_use]
    pub fn agent_data_dir(self, platform: &str, home: &Path, runtime: Option<&OsStr>) -> PathBuf {
        match platform {
            "linux" => runtime.filter(|value| !value.is_empty()).map_or_else(
                || home.join(self.home_dir_name()),
                |runtime| Path::new(runtime).join(self.agent_dir_name()),
            ),
            "macos" => home.join("Library").join("Application Support").join(self.agent_dir_name()),
            _ => home.join(self.home_dir_name()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LocketInstance;
    use std::ffi::OsStr;
    use std::path::Path;

    #[test]
    fn debug_builds_always_use_the_dev_instance() {
        assert_eq!(LocketInstance::select(true, None), LocketInstance::Dev);
        assert_eq!(LocketInstance::select(true, Some(OsStr::new(""))), LocketInstance::Dev);
        assert_eq!(
            LocketInstance::select(true, Some(OsStr::new("installed"))),
            LocketInstance::Dev
        );
    }

    #[test]
    fn release_builds_use_installed_unless_the_variable_is_set() {
        assert_eq!(LocketInstance::select(false, None), LocketInstance::Installed);
        assert_eq!(LocketInstance::select(false, Some(OsStr::new(""))), LocketInstance::Installed);
        assert_eq!(LocketInstance::select(false, Some(OsStr::new("dev"))), LocketInstance::Dev);
        assert_eq!(
            LocketInstance::select(false, Some(OsStr::new("installed"))),
            LocketInstance::Dev
        );
    }

    #[test]
    fn this_test_build_uses_the_dev_instance() {
        assert_eq!(LocketInstance::current(), LocketInstance::Dev);
    }

    #[test]
    fn installed_names_match_existing_vaults() {
        let installed = LocketInstance::Installed;
        assert_eq!(installed.application_name(), "Locket");
        assert_eq!(installed.keyring_service(), "dev.0xdoublesharp.locket");
        assert_eq!(installed.agent_pipe_prefix(), r"\\.\pipe\locket-agent-");
        assert_eq!(installed.agent_dir_name(), "locket");
        assert_eq!(installed.home_dir_name(), ".locket");
    }

    #[test]
    fn dev_names_never_collide_with_installed_names() {
        let (installed, dev) = (LocketInstance::Installed, LocketInstance::Dev);
        assert_ne!(installed.application_name(), dev.application_name());
        assert_ne!(installed.keyring_service(), dev.keyring_service());
        assert_ne!(installed.agent_pipe_prefix(), dev.agent_pipe_prefix());
        assert_ne!(installed.agent_dir_name(), dev.agent_dir_name());
        assert_ne!(installed.home_dir_name(), dev.home_dir_name());
        let (Some(installed_dirs), Some(dev_dirs)) = (installed.project_dirs(), dev.project_dirs())
        else {
            return;
        };
        assert_ne!(installed_dirs.data_dir(), dev_dirs.data_dir());
        assert_ne!(installed_dirs.config_dir(), dev_dirs.config_dir());
    }

    #[test]
    fn agent_data_dir_matches_each_platform_layout() {
        let home = Path::new("/home/alice");
        let runtime = Some(OsStr::new("/run/user/1000"));
        for (instance, name, dot_name) in [
            (LocketInstance::Installed, "locket", ".locket"),
            (LocketInstance::Dev, "locket-dev", ".locket-dev"),
        ] {
            assert_eq!(
                instance.agent_data_dir("linux", home, runtime),
                Path::new("/run/user/1000").join(name)
            );
            assert_eq!(instance.agent_data_dir("linux", home, None), home.join(dot_name));
            assert_eq!(
                instance.agent_data_dir("linux", home, Some(OsStr::new(""))),
                home.join(dot_name)
            );
            assert_eq!(
                instance.agent_data_dir("macos", home, runtime),
                home.join("Library").join("Application Support").join(name)
            );
            assert_eq!(instance.agent_data_dir("windows", home, runtime), home.join(dot_name));
        }
    }
}
