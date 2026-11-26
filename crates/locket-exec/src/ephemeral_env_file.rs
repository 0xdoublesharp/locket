//! Ephemeral env-file fallback for children that cannot accept an env map.
//!
//! Writes the Locket env layer to a private per-invocation directory: Unix
//! uses a 0600 file and 0700 directory; Windows uses a protected owner-only
//! ACL inherited by the file. The directory is under the system temp dir (outside the
//! project tree). The returned guard deletes the file and its parent dir
//! when dropped. The file is formatted as `KEY=VALUE\n` lines so it can be
//! consumed by `docker run --env-file <path>` and equivalents.

use std::fs::{self, File};
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
    /// An env name was empty or contained an equals sign, NUL, or line break.
    #[error("ephemeral env-file env name {name:?} is invalid")]
    InvalidEnvName {
        /// The invalid env variable name.
        name: String,
    },
    /// An env value contained a NUL byte or line break that would break parsing.
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
    file: Option<File>,
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
        let file = self.file.take();
        #[cfg(unix)]
        let overwrite = file.map_or(Ok(()), |mut file| zero_fill(&mut file));
        #[cfg(not(unix))]
        drop(file);
        ignore_not_found(fs::remove_file(&self.path))?;
        #[cfg(unix)]
        overwrite?;
        ignore_not_found(fs::remove_dir(&self.parent))?;
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
    write: impl FnOnce(&mut File, &EnvMap) -> Result<(), EphemeralEnvFileError>,
) -> Result<EphemeralEnvFile, EphemeralEnvFileError> {
    validate_env(env)?;

    let parent = create_parent_dir(parent_root)?;
    let path = parent.join("env");
    let mut handle = EphemeralEnvFile { parent, path, file: None, cleaned: false };
    let file = create_env_file(&handle.path)?;
    write(handle.file.insert(file), env)?;
    #[cfg(not(unix))]
    drop(handle.file.take());
    Ok(handle)
}

fn validate_env(env: &EnvMap) -> Result<(), EphemeralEnvFileError> {
    for (name, value) in env {
        if name.is_empty() || name.contains(['=', '\0', '\n', '\r']) {
            return Err(EphemeralEnvFileError::InvalidEnvName { name: name.clone() });
        }
        if value.as_str().contains(['\0', '\n', '\r']) {
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

fn create_env_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(FILE_MODE);
    options.open(path)
}

fn write_env_file(file: &mut File, env: &EnvMap) -> Result<(), EphemeralEnvFileError> {
    for (name, value) in env {
        writeln!(file, "{name}={}", value.as_str())?;
    }
    file.flush()?;
    Ok(())
}

fn ignore_not_found(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

#[cfg(unix)]
fn zero_fill(file: &mut File) -> io::Result<()> {
    use std::io::{Read, Seek};
    // Use the descriptor for the file we created. The child can replace the
    // directory entry, which must never redirect this overwrite.
    let len = file.metadata()?.len();
    if len != 0 {
        file.rewind()?;
        io::copy(&mut io::repeat(0).take(len), file)?;
    }
    file.flush()
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
    fn rejects_line_breaks_in_env_names() {
        for name in ["BAD\nNAME", "BAD\rNAME"] {
            let env = make_env(&[(name, "value")]);
            assert!(matches!(
                validate_env(&env),
                Err(EphemeralEnvFileError::InvalidEnvName { .. })
            ));
        }
    }

    #[test]
    fn rejects_carriage_return_in_env_values() {
        let env = make_env(&[("KEY", "line-1\rline-2")]);
        assert!(matches!(validate_env(&env), Err(EphemeralEnvFileError::InvalidEnvValue { .. })));
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

    #[cfg(unix)]
    #[test]
    fn cleanup_preserves_unrelated_files_when_the_env_path_changes()
    -> Result<(), EphemeralEnvFileError> {
        use std::io::Read;

        let directory = tempfile::tempdir()?;
        let unrelated = directory.path().join("unrelated");
        fs::write(&unrelated, b"existing content")?;
        let mut handle =
            write_ephemeral_env_file(&make_env(&[("KEY", "fixture")]), directory.path())?;
        let mut original = File::open(handle.path())?;
        fs::remove_file(handle.path())?;
        std::os::unix::fs::symlink(&unrelated, handle.path())?;

        handle.cleanup()?;
        let mut wiped = Vec::new();
        original.read_to_end(&mut wiped)?;
        assert_eq!(wiped, vec![0; b"KEY=fixture\n".len()]);
        assert_eq!(fs::read(unrelated)?, b"existing content");
        assert!(!handle.parent_dir().exists());
        Ok(())
    }

    #[test]
    fn cleanup_removes_the_directory_after_empty_or_missing_file()
    -> Result<(), EphemeralEnvFileError> {
        for remove_before_cleanup in [false, true] {
            let mut handle = write_ephemeral_env_file(&EnvMap::new(), &temp_root()?)?;
            assert_eq!(fs::metadata(handle.path())?.len(), 0);
            if remove_before_cleanup {
                fs::remove_file(handle.path())?;
            }
            handle.cleanup()?;
            assert!(!handle.path().exists());
            assert!(!handle.parent_dir().exists());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn secure_cleanup_distinguishes_absence_from_invalid_parent()
    -> Result<(), EphemeralEnvFileError> {
        let mut handle = write_ephemeral_env_file(&EnvMap::new(), &temp_root()?)?;
        let path = handle.path().to_owned();
        handle.path = path.join("cannot-have-a-child");
        assert!(matches!(
            handle.cleanup(),
            Err(EphemeralEnvFileError::Io(error)) if error.kind() == io::ErrorKind::NotADirectory
        ));
        assert!(path.is_file());
        handle.path = path;
        handle.cleanup()?;
        Ok(())
    }

    #[test]
    fn write_failure_removes_partial_plaintext_and_parent() -> Result<(), EphemeralEnvFileError> {
        let env = make_env(&[("KEY", "secret")]);
        let directory = tempfile::tempdir()?;
        let mut attempted = false;
        let result = write_ephemeral_env_file_with(&env, directory.path(), |file, _| {
            file.write_all(b"KEY=partial-secret")?;
            attempted = true;
            Err(io::Error::other("injected write failure").into())
        });
        assert!(result.is_err());
        assert!(attempted, "writer did not write the partial plaintext");
        assert_eq!(fs::read_dir(directory.path())?.count(), 0, "failed write retained output");
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
        let mut handle = write_ephemeral_env_file(&make_env(&[("KEY", "secret")]), &temp_root()?)?;
        handle.file = Some(File::open(handle.path())?);
        assert!(handle.cleanup().is_err(), "read-only descriptor should reject overwrite");
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
            foreach ($path in @($env:LOCKET_ACL_TEST_PATH, [System.IO.Path]::Combine($env:LOCKET_ACL_TEST_PATH, 'env'))) {
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
            // A PowerShell 7 parent can pass incompatible module paths through
            // Cargo. Let Windows PowerShell reconstruct its own module search.
            .env_remove("PSModulePath")
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
