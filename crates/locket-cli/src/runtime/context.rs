//! Runtime context shared across CLI commands.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use locket_crypto::KeyBytes;
use zeroize::Zeroizing;

use crate::runtime::key_access::MasterKeySource;

use directories::{BaseDirs, ProjectDirs};
use locket_platform::{
    AutomationClientKeyStore, KeyringAutomationClientKeyStore, KeyringMasterKeyStore,
    LocalUserVerifier, MasterKeyStore, PassphraseFallbackMasterKeyStore, PlatformPasskeyRegistrar,
    default_local_user_verifier, default_platform_passkey_registrar,
};

use crate::CONFIG_TOML;
use crate::runtime::error::{CliError, corrupt_db_error};
use crate::runtime::prompts::{
    ConfirmationReader, EnvOrPromptPassphraseReader, PassphraseReader, RecoveryCodeReader,
    SecretValueReader, StdinConfirmationReader, StdinOrPromptSecretValueReader,
    TtyRecoveryCodeReader,
};

#[derive(Clone)]
pub struct RuntimeContext {
    pub cwd: PathBuf,
    pub store_path: PathBuf,
    pub config_path: PathBuf,
    pub template_dir: PathBuf,
    /// Optional override for the agent data directory. When set, the
    /// `agent_socket_path` / `agent_pid_path` / `agent_log_path` helpers
    /// resolve against this path. When `None`, the helpers fall back to
    /// `store_path.parent()` so existing test contexts that drop their
    /// store into a tempdir continue to derive a tempdir-local socket.
    /// Production startup populates this with the spec-mandated
    /// platform path (Linux: `$XDG_RUNTIME_DIR/locket`, macOS:
    /// `~/Library/Application Support/locket`). On Windows this remains
    /// the pid/log data directory; the agent endpoint itself is the
    /// SID-scoped named pipe returned by `agent_socket_path`.
    pub agent_data_dir: Option<PathBuf>,
    pub key_store: Arc<dyn MasterKeyStore + Send + Sync>,
    pub automation_client_key_store: Arc<dyn AutomationClientKeyStore + Send + Sync>,
    pub passphrase_store: PassphraseFallbackMasterKeyStore,
    pub passphrase_reader: Arc<dyn PassphraseReader + Send + Sync>,
    pub recovery_code_reader: Arc<dyn RecoveryCodeReader + Send + Sync>,
    pub confirmation_reader: Arc<dyn ConfirmationReader + Send + Sync>,
    pub secret_value_reader: Arc<dyn SecretValueReader + Send + Sync>,
    pub user_verifier: Arc<dyn LocalUserVerifier + Send + Sync>,
    pub passkey_registrar: Arc<dyn PlatformPasskeyRegistrar + Send + Sync>,
    /// Per-invocation cache of unlocked master keys keyed by `project_id`.
    /// Lets a single command load the master key once and reuse it across
    /// every key-derivation call in the same invocation, avoiding repeated
    /// passphrase prompts when the OS key store is unavailable.
    pub master_key_cache: MasterKeyCache,
}

type MasterKeyEntry = (Zeroizing<KeyBytes>, MasterKeySource);

/// In-memory cache of unlocked master keys for a single CLI invocation.
///
/// Shared across `RuntimeContext` clones via `Arc<Mutex<_>>`. Entries are
/// dropped when the last `RuntimeContext` clone is dropped at the end of
/// the command, and `Zeroizing` wipes the key bytes at that point.
#[derive(Clone, Default)]
pub struct MasterKeyCache {
    entries: Arc<Mutex<HashMap<String, MasterKeyEntry>>>,
}

impl MasterKeyCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn get(&self, project_id: &str) -> Option<MasterKeyEntry> {
        let guard = self.entries.lock().ok()?;
        guard.get(project_id).map(|(key, source)| (key.clone(), *source))
    }

    pub fn insert(&self, project_id: &str, key: Zeroizing<KeyBytes>, source: MasterKeySource) {
        if let Ok(mut guard) = self.entries.lock() {
            guard.insert(project_id.to_owned(), (key, source));
        }
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.entries.lock() {
            guard.clear();
        }
    }
}

impl RuntimeContext {
    pub fn default() -> Result<Self, CliError> {
        let cwd = std::env::current_dir()?;
        let Some(project_dirs) = ProjectDirs::from("dev", "0xdoublesharp", "Locket") else {
            return Err(corrupt_db_error("could not resolve a local data directory"));
        };
        let Some(base_dirs) = BaseDirs::new() else {
            return Err(corrupt_db_error("could not resolve a local home directory"));
        };
        let data_dir = project_dirs.data_dir();
        let config_dir = project_dirs.config_dir();
        fs::create_dir_all(data_dir)?;
        fs::create_dir_all(config_dir)?;
        Ok(Self {
            cwd,
            store_path: data_dir.join("store.db"),
            config_path: config_dir.join(CONFIG_TOML),
            template_dir: base_dirs.home_dir().join(".locket").join("templates"),
            agent_data_dir: resolve_default_agent_data_dir(base_dirs.home_dir()),
            key_store: Arc::new(KeyringMasterKeyStore),
            automation_client_key_store: Arc::new(KeyringAutomationClientKeyStore),
            passphrase_store: PassphraseFallbackMasterKeyStore::new(
                data_dir.join("passphrase-fallback"),
            ),
            passphrase_reader: Arc::new(EnvOrPromptPassphraseReader),
            recovery_code_reader: Arc::new(TtyRecoveryCodeReader),
            confirmation_reader: Arc::new(StdinConfirmationReader),
            secret_value_reader: Arc::new(StdinOrPromptSecretValueReader),
            user_verifier: default_local_user_verifier(),
            passkey_registrar: Arc::new(default_platform_passkey_registrar()),
            master_key_cache: MasterKeyCache::new(),
        })
    }
}

/// Resolves the spec-mandated default agent data directory for the
/// current platform. Honors `docs/specs/agent.md:18-21`:
///
/// - Linux: `$XDG_RUNTIME_DIR/locket` when set, falling back to
///   `<HOME>/.locket`. The runtime-dir path is the agent's preferred
///   location because it is per-user, ephemeral, and `0o700` by default
///   on systemd installs.
/// - macOS: `<HOME>/Library/Application Support/locket`.
/// - Windows: `<HOME>/.locket` for pid/log data. The agent endpoint is
///   the SID-scoped named pipe path resolved by `agent_socket_path`.
#[must_use]
pub fn resolve_default_agent_data_dir(home: &std::path::Path) -> Option<PathBuf> {
    resolve_agent_data_dir_for_platform(home, std::env::var_os("XDG_RUNTIME_DIR"))
}

#[allow(clippy::unnecessary_wraps)]
fn resolve_agent_data_dir_for_platform(
    home: &std::path::Path,
    xdg_runtime_dir: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    #[cfg(not(target_os = "linux"))]
    let _ = xdg_runtime_dir;
    #[cfg(target_os = "linux")]
    {
        if let Some(value) = xdg_runtime_dir {
            let path = PathBuf::from(value);
            if !path.as_os_str().is_empty() {
                return Some(path.join("locket"));
            }
        }
        Some(home.join(".locket"))
    }
    #[cfg(target_os = "macos")]
    {
        Some(home.join("Library").join("Application Support").join("locket"))
    }
    #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
    {
        Some(home.join(".locket"))
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::resolve_agent_data_dir_for_platform;
    use super::{MasterKeyCache, MasterKeySource};
    use locket_crypto::KEY_LEN;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::path::Path;
    use zeroize::Zeroizing;

    #[test]
    fn master_key_cache_returns_cloned_key_for_known_project() {
        let cache = MasterKeyCache::new();
        let key = Zeroizing::new([0x42_u8; KEY_LEN]);
        cache.insert("lk_proj_alpha", key, MasterKeySource::PassphraseFallback);

        let Some((got, source)) = cache.get("lk_proj_alpha") else {
            panic!("entry");
        };
        assert_eq!(*got, [0x42_u8; KEY_LEN]);
        assert_eq!(source, MasterKeySource::PassphraseFallback);
    }

    #[test]
    fn master_key_cache_misses_for_unknown_project() {
        let cache = MasterKeyCache::new();
        cache.insert("lk_proj_alpha", Zeroizing::new([0; KEY_LEN]), MasterKeySource::OsKeyStore);
        assert!(cache.get("lk_proj_other").is_none());
    }

    #[test]
    fn master_key_cache_clear_drops_entries() {
        let cache = MasterKeyCache::new();
        cache.insert("lk_proj_alpha", Zeroizing::new([0; KEY_LEN]), MasterKeySource::OsKeyStore);
        cache.clear();
        assert!(cache.get("lk_proj_alpha").is_none());
    }

    #[test]
    fn master_key_cache_clones_share_state() {
        let cache_a = MasterKeyCache::new();
        let cache_b = cache_a.clone();
        cache_a.insert(
            "lk_proj_alpha",
            Zeroizing::new([0xCC; KEY_LEN]),
            MasterKeySource::OsKeyStore,
        );
        assert!(cache_b.get("lk_proj_alpha").is_some());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn agent_data_dir_prefers_xdg_runtime_dir_on_linux() {
        assert_eq!(
            resolve_agent_data_dir_for_platform(
                Path::new("/home/alice"),
                Some("/run/user/1000".into())
            ),
            Some(Path::new("/run/user/1000").join("locket"))
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn agent_data_dir_falls_back_to_home_on_linux_without_xdg_runtime_dir() {
        assert_eq!(
            resolve_agent_data_dir_for_platform(Path::new("/home/alice"), None),
            Some(Path::new("/home/alice").join(".locket"))
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn agent_data_dir_uses_application_support_on_macos() {
        assert_eq!(
            resolve_agent_data_dir_for_platform(Path::new("/Users/alice"), None),
            Some(
                Path::new("/Users/alice")
                    .join("Library")
                    .join("Application Support")
                    .join("locket")
            )
        );
    }
}
