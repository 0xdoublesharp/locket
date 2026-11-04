//! Ephemeral env-file fallback for children that cannot accept an env map.
//!
//! Writes the Locket env layer to a private per-invocation directory: Unix
//! uses a 0600 file and 0700 directory; Windows uses a protected owner-only
//! ACL inherited by the file. The directory is under the system temp dir (outside the
//! project tree). The returned guard deletes the file and its parent dir
//! when dropped. The file is formatted as `KEY=VALUE\n` lines so it can be
//! consumed by `docker run --env-file <path>` and equivalents.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use locket_core::EnvMap;
use thiserror::Error;

/// Mode bits used for the parent directory holding an ephemeral env file.
#[cfg(unix)]
const PARENT_DIR_MODE: u32 = 0o700;
/// Mode bits used for the env file itself.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// Error returned when writing or cleaning up an ephemeral env file.
#[derive(Debug, Error)]
pub enum EphemeralEnvFileError {
    /// An env name contained an `=` or NUL byte.
    #[error("ephemeral env-file env name {name:?} is invalid")]
    InvalidEnvName {
        /// The invalid env variable name.
        name: String,
    },
    /// An env value contained a NUL byte or newline that would break parsing.
    #[error("ephemeral env-file value for {name:?} contains an unsupported byte")]
    InvalidEnvValue {
        /// The env variable whose value was invalid.
        name: String,
    },
    /// Filesystem operation failed.
    #[error("ephemeral env-file I/O failure: {0}")]
    Io(#[from] io::Error),
}

/// Whether a best-effort secure-erase of the file contents is supported on
/// this build.
///
/// Even on supported platforms the OS may keep cached pages or journal
/// blocks, so callers should treat this only as a best-effort hint.
#[must_use]
pub const fn secure_erase_supported() -> bool {
    cfg!(unix)
}

/// RAII handle to a written ephemeral env file.
///
/// Drop deletes the file and its parent directory. Drop is best-effort —
/// errors during deletion are silently ignored because there is no caller
/// to surface them to. Callers that want to detect cleanup failures should
/// call [`EphemeralEnvFile::cleanup`] explicitly before drop.
#[derive(Debug)]
pub struct EphemeralEnvFile {
    parent: PathBuf,
    path: PathBuf,
    cleaned: bool,
}

impl EphemeralEnvFile {
    /// Returns the absolute path that should be passed to `--env-file`.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the parent directory holding the env file.
    #[must_use]
    pub fn parent_dir(&self) -> &Path {
        &self.parent
    }

    /// Best-effort overwrite + delete + parent-dir-remove.
    ///
    /// On supported platforms the file body is overwritten with zeros before
    /// being unlinked. On unsupported platforms the body is left as-is and
    /// only the file is unlinked.
    ///
    /// # Errors
    ///
    /// Returns the first I/O error from overwrite, unlink, or parent-dir
    /// removal. Callers can ignore the error and rely on Drop, but should
    /// prefer explicit cleanup so failures surface.
    pub fn cleanup(&mut self) -> Result<(), EphemeralEnvFileError> {
        if self.cleaned {
            return Ok(());
        }
        if secure_erase_supported() && self.path.exists() {
            zero_fill_then_remove(&self.path)?;
        } else if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        if self.parent.exists() {
            fs::remove_dir(&self.parent)?;
        }
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for EphemeralEnvFile {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Writes the supplied env map to a fresh ephemeral env file.
///
/// `parent_root` selects the parent directory under which the per-invocation
/// private directory is created. Pass [`std::env::temp_dir`] in production; tests can
/// pass a controlled path. The path must already exist.
///
/// # Errors
///
/// Returns [`EphemeralEnvFileError`] when the env contains unsupported bytes
/// or when the filesystem rejects creation/permission updates.
pub fn write_ephemeral_env_file(
    env: &EnvMap,
    parent_root: &Path,
) -> Result<EphemeralEnvFile, EphemeralEnvFileError> {
    write_ephemeral_env_file_with(env, parent_root, write_env_file)
}

fn write_ephemeral_env_file_with(
    env: &EnvMap,
    parent_root: &Path,
    write: impl FnOnce(&Path, &EnvMap) -> Result<(), EphemeralEnvFileError>,
) -> Result<EphemeralEnvFile, EphemeralEnvFileError> {
    validate_env(env)?;

    let parent = create_parent_dir(parent_root)?;
    let path = parent.join("env");
    let handle = EphemeralEnvFile { parent, path, cleaned: false };
    write(&handle.path, env)?;
    Ok(handle)
}

fn validate_env(env: &EnvMap) -> Result<(), EphemeralEnvFileError> {
    for (name, value) in env {
        if name.is_empty() || name.contains('=') || name.as_bytes().contains(&0) {
            return Err(EphemeralEnvFileError::InvalidEnvName { name: name.clone() });
        }
        let value_bytes = value.as_str().as_bytes();
        if value_bytes.contains(&0) || value_bytes.contains(&b'\n') {
            return Err(EphemeralEnvFileError::InvalidEnvValue { name: name.clone() });
        }
    }
    Ok(())
}

fn create_parent_dir(root: &Path) -> Result<PathBuf, EphemeralEnvFileError> {
    let parent = unique_parent_path(&fs::canonicalize(root)?);
    create_private_directory(&parent)?;
    Ok(parent)
}

#[cfg(unix)]
fn create_private_directory(parent: &Path) -> Result<(), EphemeralEnvFileError> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(PARENT_DIR_MODE).create(parent)?;
    Ok(())
}

#[cfg(windows)]
fn create_private_directory(parent: &Path) -> Result<(), EphemeralEnvFileError> {
    locket_platform::create_user_only_windows_directory(parent)?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn create_private_directory(_parent: &Path) -> Result<(), EphemeralEnvFileError> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "private env files are unavailable").into())
}

fn unique_parent_path(root: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    root.join(format!("locket-env-{pid}-{nanos}-{count}"))
}

#[cfg(unix)]
fn write_env_file(path: &Path, env: &EnvMap) -> Result<(), EphemeralEnvFileError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file =
        fs::OpenOptions::new().create_new(true).write(true).mode(FILE_MODE).open(path)?;
    for (name, value) in env {
        writeln!(file, "{name}={}", value.as_str())?;
    }
    file.flush()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_env_file(path: &Path, env: &EnvMap) -> Result<(), EphemeralEnvFileError> {
    let mut file = fs::OpenOptions::new().create_new(true).write(true).open(path)?;
    for (name, value) in env {
        writeln!(file, "{name}={}", value.as_str())?;
    }
    file.flush()?;
    Ok(())
}

#[cfg(unix)]
fn zero_fill_then_remove(path: &Path) -> Result<(), EphemeralEnvFileError> {
    use std::io::Read;
    let len = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let overwrite = (|| -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }
        let mut file = fs::OpenOptions::new().write(true).open(path)?;
        io::copy(&mut io::repeat(0).take(len), &mut file)?;
        file.flush()?;
        Ok(())
    })();
    // Overwriting is best effort. Even when it fails, attempt to unlink the
    // plaintext and report the overwrite error after deletion has succeeded.
    fs::remove_file(path)?;
    overwrite?;
    Ok(())
}

#[cfg(not(unix))]
fn zero_fill_then_remove(path: &Path) -> Result<(), EphemeralEnvFileError> {
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use locket_core::EnvValue;

    fn temp_root() -> Result<PathBuf, EphemeralEnvFileError> {
        let mut root = std::env::temp_dir();
        root.push(format!("locket-env-test-root-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn make_env(pairs: &[(&str, &str)]) -> EnvMap {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), EnvValue::from((*value).to_owned())))
            .collect()
    }

    #[test]
    fn writes_env_file_in_docker_format() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("DATABASE_URL", "postgres://example"), ("API_TOKEN", "abc123")]);
        let mut handle = write_ephemeral_env_file(&env, &temp_root()?)?;

        let contents = fs::read_to_string(handle.path())?;
        assert!(contents.contains("DATABASE_URL=postgres://example\n"));
        assert!(contents.contains("API_TOKEN=abc123\n"));

        handle.cleanup()?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn parent_dir_is_0700_and_file_is_0600() -> Result<(), EphemeralEnvFileError> {
        use std::os::unix::fs::PermissionsExt;
        let env = make_env(&[("KEY", "value")]);
        let mut handle = write_ephemeral_env_file(&env, &temp_root()?)?;

        let parent_mode = fs::metadata(handle.parent_dir())?.permissions().mode() & 0o777;
        let file_mode = fs::metadata(handle.path())?.permissions().mode() & 0o777;
        assert_eq!(parent_mode, PARENT_DIR_MODE);
        assert_eq!(file_mode, FILE_MODE);

        handle.cleanup()?;
        Ok(())
    }

    #[test]
    fn cleanup_removes_file_and_parent() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "value")]);
        let mut handle = write_ephemeral_env_file(&env, &temp_root()?)?;
        let path = handle.path().to_path_buf();
        let parent = handle.parent_dir().to_path_buf();

        handle.cleanup()?;

        assert!(!path.exists(), "env file should be deleted");
        assert!(!parent.exists(), "parent dir should be deleted");
        Ok(())
    }

    #[test]
    fn drop_cleans_up_file_and_parent() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "value")]);
        let (path, parent) = {
            let handle = write_ephemeral_env_file(&env, &temp_root()?)?;
            (handle.path().to_path_buf(), handle.parent_dir().to_path_buf())
        };
        assert!(!path.exists(), "env file should be deleted on drop");
        assert!(!parent.exists(), "parent dir should be deleted on drop");
        Ok(())
    }

    #[test]
    fn rejects_env_name_containing_equals() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("BAD=NAME", "value")]);
        assert!(matches!(
            write_ephemeral_env_file(&env, &temp_root()?),
            Err(EphemeralEnvFileError::InvalidEnvName { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_env_value_containing_newline() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "line-1\nline-2")]);
        assert!(matches!(
            write_ephemeral_env_file(&env, &temp_root()?),
            Err(EphemeralEnvFileError::InvalidEnvValue { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_empty_env_name() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("", "value")]);
        assert!(matches!(
            write_ephemeral_env_file(&env, &temp_root()?),
            Err(EphemeralEnvFileError::InvalidEnvName { .. })
        ));
        Ok(())
    }

    #[test]
    fn parent_path_is_outside_an_arbitrary_project_tree() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "value")]);
        let mut handle = write_ephemeral_env_file(&env, &temp_root()?)?;
        let project = std::path::Path::new("/path/to/some/project");
        assert!(!handle.path().starts_with(project));
        handle.cleanup()?;
        Ok(())
    }

    #[test]
    fn cleanup_is_idempotent() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "value")]);
        let mut handle = write_ephemeral_env_file(&env, &temp_root()?)?;
        handle.cleanup()?;
        handle.cleanup()?;
        Ok(())
    }

    #[test]
    fn write_failure_removes_partial_plaintext_and_parent() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "secret")]);
        let mut attempted = None;
        let result = write_ephemeral_env_file_with(&env, &temp_root()?, |path, _| {
            attempted = Some(path.to_path_buf());
            fs::write(path, "KEY=partial-secret")?;
            Err(io::Error::other("injected write failure").into())
        });
        assert!(result.is_err());
        let path = attempted.ok_or_else(|| io::Error::other("writer was not called"))?;
        assert!(!path.exists(), "failed write retained partial plaintext");
        assert!(!path.parent().is_some_and(Path::exists), "failed write retained its directory");
        Ok(())
    }

    #[test]
    fn failed_cleanup_can_be_retried() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "secret")]);
        let mut handle = write_ephemeral_env_file(&env, &temp_root()?)?;
        let blocker = handle.parent_dir().join("unexpected-child");
        fs::write(&blocker, [])?;
        assert!(handle.cleanup().is_err(), "nonempty parent should reject deletion");
        assert!(!handle.path().exists(), "plaintext should already be removed");
        fs::remove_file(blocker)?;
        handle.cleanup()?;
        assert!(!handle.parent_dir().exists(), "failed cleanup could not be retried");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_unlinks_even_when_overwrite_fails() -> Result<(), EphemeralEnvFileError> {
        use std::os::unix::fs::PermissionsExt;
        let mut handle = write_ephemeral_env_file(&make_env(&[("KEY", "secret")]), &temp_root()?)?;
        fs::set_permissions(handle.path(), fs::Permissions::from_mode(0o400))?;
        assert!(handle.cleanup().is_err(), "read-only file should reject overwrite");
        assert!(!handle.path().exists(), "overwrite failure prevented unlinking plaintext");
        handle.cleanup()?;
        assert!(!handle.parent_dir().exists());
        Ok(())
    }

    #[test]
    fn private_directory_creation_preserves_existing_paths() -> Result<(), EphemeralEnvFileError> {
        let mut existing = write_ephemeral_env_file(&make_env(&[("KEY", "value")]), &temp_root()?)?;
        assert!(create_private_directory(existing.parent_dir()).is_err());
        assert_eq!(fs::read_to_string(existing.path())?, "KEY=value\n");
        existing.cleanup()?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_env_file_rejects_inherited_public_read_access() -> Result<(), EphemeralEnvFileError>
    {
        let mut root = write_ephemeral_env_file(&EnvMap::new(), &temp_root()?)?;
        run_acl_script(
            root.parent_dir(),
            r"
            $ErrorActionPreference = 'Stop'
            $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
            $acl = [System.Security.AccessControl.DirectorySecurity]::new()
            $acl.SetOwner($user)
            $acl.SetAccessRuleProtection($true, $false)
            $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
            $none = [System.Security.AccessControl.PropagationFlags]::None
            $allow = [System.Security.AccessControl.AccessControlType]::Allow
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($user, 'FullControl', $inherit, $none, $allow))
            $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($everyone, 'ReadAndExecute', $inherit, $none, $allow))
            Set-Acl -LiteralPath $env:LOCKET_ACL_TEST_PATH -AclObject $acl
            $actual = Get-Acl -LiteralPath $env:LOCKET_ACL_TEST_PATH
            if (-not ($actual.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' })) {
                throw 'fixture did not grant public inherited read access'
            }
        ",
        )?;
        let mut handle =
            write_ephemeral_env_file(&make_env(&[("KEY", "secret")]), root.parent_dir())?;
        run_acl_script(
            handle.parent_dir(),
            r"
            $ErrorActionPreference = 'Stop'
            $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $directory = Get-Acl -LiteralPath $env:LOCKET_ACL_TEST_PATH
            if (-not $directory.AreAccessRulesProtected) { throw 'directory DACL is not protected' }
            if ($directory.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $user) { throw 'unexpected directory owner' }
            foreach ($path in @($env:LOCKET_ACL_TEST_PATH, (Join-Path $env:LOCKET_ACL_TEST_PATH 'env'))) {
                $acl = Get-Acl -LiteralPath $path
                # Elevated Windows tokens can default newly created file ownership to
                # Administrators. Those privileged host principals are already trusted;
                # the file DACL must still grant access only to the current user.
                $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
                if ($owner -notin @($user, 'S-1-5-18', 'S-1-5-32-544')) { throw 'unexpected file owner' }
                $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
                if ($rules.Count -ne 1) { throw 'unexpected access rule count' }
                $rule = $rules[0]
                if ($rule.IdentityReference.Value -ne $user -or $rule.AccessControlType -ne 'Allow') { throw 'non-owner access rule' }
                $full = [System.Security.AccessControl.FileSystemRights]::FullControl
                if (($rule.FileSystemRights -band $full) -ne $full) { throw 'owner lacks full control' }
            }
        ",
        )?;
        handle.cleanup()?;
        let mut nested_root = write_ephemeral_env_file(&EnvMap::new(), root.parent_dir())?;
        run_acl_script(
            root.parent_dir(),
            r"
            $ErrorActionPreference = 'Stop'
            $acl = Get-Acl -LiteralPath $env:LOCKET_ACL_TEST_PATH
            $everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
            $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($everyone, 'FullControl', $inherit, 'None', 'Allow')
            $acl.SetAccessRule($rule)
            Set-Acl -LiteralPath $env:LOCKET_ACL_TEST_PATH -AclObject $acl
        ",
        )?;
        let env = make_env(&[("KEY", "must-not-be-written")]);
        let before = fs::read_dir(root.parent_dir())?.count();
        assert!(
            write_ephemeral_env_file(&env, root.parent_dir()).is_err(),
            "publicly writable parent was accepted"
        );
        assert!(
            write_ephemeral_env_file(&env, nested_root.parent_dir()).is_err(),
            "replaceable ancestor was accepted"
        );
        assert_eq!(
            fs::read_dir(root.parent_dir())?.count(),
            before,
            "rejected parent retained output"
        );
        assert_eq!(
            fs::read_dir(nested_root.parent_dir())?.count(),
            1,
            "rejected ancestor retained output"
        );
        nested_root.cleanup()?;
        root.cleanup()?;
        Ok(())
    }

    #[cfg(windows)]
    fn run_acl_script(path: &Path, script: &str) -> Result<(), EphemeralEnvFileError> {
        let output = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .env("LOCKET_ACL_TEST_PATH", path)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "ACL assertion failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
        Ok(())
    }

    #[test]
    fn secure_erase_capability_matches_target() {
        assert_eq!(secure_erase_supported(), cfg!(unix));
    }
}
