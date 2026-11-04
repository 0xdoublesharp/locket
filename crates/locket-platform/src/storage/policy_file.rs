//! Atomic, comment-preserving writes of project command metadata.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use locket_core::PolicyDocument;
use locket_core::policy::{PolicyEditError, render_policy_document};
use thiserror::Error;

/// Failure to read or atomically replace project policy metadata.
#[derive(Debug, Error)]
pub enum PolicyFileError {
    /// A filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The document failed parsing or policy validation.
    #[error(transparent)]
    Invalid(#[from] PolicyEditError),
    /// Another writer changed the source since this snapshot was read.
    #[error("project configuration changed; reload it before saving")]
    ConcurrentModification,
    /// The project configuration must be an ordinary local file.
    #[error("project configuration must be a regular file, not a symbolic link")]
    NotRegularFile,
}

/// Editable snapshot of a project file, with optimistic concurrency checking.
#[derive(Debug)]
pub struct PolicyFileDocument {
    path: PathBuf,
    source: String,
    document: toml::Value,
}

impl PolicyFileDocument {
    /// Reads a regular project file without discarding its comments.
    ///
    /// # Errors
    ///
    /// Rejects unreadable, symbolic-link, or malformed TOML files.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, PolicyFileError> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_file() {
            return Err(PolicyFileError::NotRegularFile);
        }
        let source = fs::read_to_string(path)?;
        let document = toml::from_str(&source).map_err(|_| PolicyEditError::InvalidDocument)?;
        Ok(Self { path: path.to_path_buf(), source, document })
    }

    /// Validates and atomically saves this snapshot, preserving file permissions.
    ///
    /// # Errors
    ///
    /// Refuses invalid policy or concurrent edits. Failed replacement leaves the
    /// original intact. A new snapshot is required for another save.
    pub fn save(&self) -> Result<PolicyDocument, PolicyFileError> {
        let rendered = render_policy_document(&self.source, &self.document)?;
        let parsed = PolicyDocument::from_toml_str(&rendered).map_err(PolicyEditError::from)?;
        self.replace_source(&rendered)?;
        Ok(parsed)
    }

    /// Render the validated candidate while retaining unchanged comments.
    ///
    /// # Errors
    /// Rejects an invalid candidate policy document.
    pub fn rendered_source(&self) -> Result<String, PolicyFileError> {
        Ok(render_policy_document(&self.source, &self.document)?)
    }

    /// Restore this original snapshot only while the file still equals our candidate.
    ///
    /// A later external edit is never overwritten during compensation.
    ///
    /// # Errors
    /// Rejects concurrent changes, invalid files and failed atomic replacement.
    pub fn restore_if_current(&self, expected: &str) -> Result<(), PolicyFileError> {
        let current = Self::read(&self.path)?;
        if current.source != expected {
            return Err(PolicyFileError::ConcurrentModification);
        }
        current.replace_source(&self.source)
    }

    fn replace_source(&self, rendered: &str) -> Result<(), PolicyFileError> {
        let mut original = OpenOptions::new().read(true).write(true).open(&self.path)?;
        original.lock()?;
        self.check_locked_source(&mut original)?;
        if rendered == self.source {
            return Ok(());
        }
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary =
            tempfile::Builder::new().prefix(".locket-policy-").tempfile_in(parent)?;
        temporary.as_file().set_permissions(original.metadata()?.permissions())?;
        temporary.write_all(rendered.as_bytes())?;
        temporary.as_file().sync_all()?;
        // Recheck after preparing the replacement so a detected concurrent editor
        // cannot be overwritten by a stale snapshot.
        self.check_locked_source(&mut original)?;
        persist_replacement(temporary, &self.path)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn check_locked_source(&self, original: &mut File) -> Result<(), PolicyFileError> {
        if !fs::symlink_metadata(&self.path)?.file_type().is_file() {
            return Err(PolicyFileError::NotRegularFile);
        }
        let current = File::open(&self.path)?;
        if !same_file(original, &current)? {
            return Err(PolicyFileError::ConcurrentModification);
        }
        // Windows byte-range locks are mandatory even for another handle in
        // this process. Read through the handle that owns the lock. The file
        // identity check above also catches atomic pathname replacement.
        original.rewind()?;
        let mut source = String::new();
        original.read_to_string(&mut source)?;
        if source != self.source {
            return Err(PolicyFileError::ConcurrentModification);
        }
        Ok(())
    }
}

#[cfg(windows)]
fn persist_replacement(mut temporary: tempfile::NamedTempFile, path: &Path) -> std::io::Result<()> {
    // Rust's Windows rename supports replacing an open destination through
    // FileRenameInfoEx/POSIX semantics. tempfile's MoveFileEx-only persist does
    // not, so retain the original lock and the cleanup guard during this call.
    // The copied source permissions above also clear FILE_ATTRIBUTE_TEMPORARY.
    fs::rename(temporary.path(), path)?;
    temporary.disable_cleanup(true);
    Ok(())
}

#[cfg(not(windows))]
fn persist_replacement(temporary: tempfile::NamedTempFile, path: &Path) -> std::io::Result<()> {
    temporary.persist(path).map(|_| ()).map_err(|error| error.error)
}

#[cfg(unix)]
fn same_file(left: &File, right: &File) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(windows)]
fn same_file(left: &File, right: &File) -> std::io::Result<bool> {
    super::windows_file_identity::same_file(left, right)
}

#[cfg(not(any(unix, windows)))]
fn same_file(_left: &File, _right: &File) -> std::io::Result<bool> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "file identity is unavailable"))
}

impl Deref for PolicyFileDocument {
    type Target = toml::Value;
    fn deref(&self) -> &Self::Target {
        &self.document
    }
}

impl DerefMut for PolicyFileDocument {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.document
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const SOURCE: &str = "# project notes\nschema_version = 1\n[commands.dev]\nargv = [\"npm\", \"run\", \"dev\"] # app\n";

    #[test]
    fn policy_file_preserves_comments_and_validates_before_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("locket.toml");
        fs::write(&path, SOURCE)?;
        let mut document = PolicyFileDocument::read(&path)?;
        document["commands"]["dev"]
            .as_table_mut()
            .ok_or("command table")?
            .insert("confirm".into(), toml::Value::Boolean(true));
        document.save()?;
        let saved = fs::read_to_string(&path)?;
        assert!(saved.contains("# project notes"));
        assert!(saved.contains("# app"));
        assert!(locket_core::PolicyDocument::from_toml_str(&saved)?.commands["dev"].confirm);
        document["commands"]["dev"]
            .as_table_mut()
            .ok_or("command table")?
            .insert("ttl".into(), toml::Value::String("99h".into()));
        assert!(document.save().is_err());
        assert_eq!(fs::read_to_string(path)?, saved);
        Ok(())
    }

    #[test]
    fn policy_file_refuses_to_overwrite_a_concurrent_edit() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let path = directory.path().join("locket.toml");
        fs::write(&path, SOURCE)?;
        let mut document = PolicyFileDocument::read(&path)?;
        document["commands"]["dev"]
            .as_table_mut()
            .ok_or("command table")?
            .insert("confirm".into(), toml::Value::Boolean(true));
        let external = format!("{SOURCE}# changed by an editor\n");
        fs::write(&path, &external)?;
        assert!(matches!(document.save(), Err(PolicyFileError::ConcurrentModification)));
        assert_eq!(fs::read_to_string(path)?, external);
        Ok(())
    }

    #[test]
    fn policy_lock_rejects_a_replaced_file_with_identical_contents()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("locket.toml");
        fs::write(&path, SOURCE)?;
        let document = PolicyFileDocument::read(&path)?;
        let mut locked = OpenOptions::new().read(true).write(true).open(&path)?;
        locked.lock()?;
        let mut replacement = tempfile::NamedTempFile::new_in(directory.path())?;
        replacement.write_all(SOURCE.as_bytes())?;
        replacement.as_file().set_permissions(locked.metadata()?.permissions())?;
        persist_replacement(replacement, &path)?;
        assert!(matches!(
            document.check_locked_source(&mut locked),
            Err(PolicyFileError::ConcurrentModification)
        ));
        assert_eq!(fs::read_to_string(&path)?, SOURCE);
        Ok(())
    }
}

#[cfg(test)]
mod compensation_tests {
    use super::*;
    #[test]
    fn compensation_restores_exact_source_and_refuses_a_later_external_edit()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("locket.toml");
        let source = "# original formatting\nschema_version=1\n[commands.dev]\nargv=['node','a b.js'] # exact\n";
        fs::write(&path, source)?;
        let mut document = PolicyFileDocument::read(&path)?;
        document["commands"]["dev"]
            .as_table_mut()
            .ok_or("table")?
            .insert("confirm".into(), toml::Value::Boolean(true));
        let candidate = document.rendered_source()?;
        document.save()?;
        document.restore_if_current(&candidate)?;
        assert_eq!(fs::read_to_string(&path)?, source);
        document.save()?;
        fs::write(&path, format!("{candidate}# external editor\n"))?;
        assert!(matches!(
            document.restore_if_current(&candidate),
            Err(PolicyFileError::ConcurrentModification)
        ));
        assert!(fs::read_to_string(&path)?.contains("# external editor"));
        Ok(())
    }
}

/// Patterns protecting local plaintext environment and vault helper files.
pub const SECRET_FILE_IGNORE_PATTERNS: [&str; 4] =
    [".env", ".env.*", ".locket.local", ".locketignore"];

/// Add missing secret-file patterns without removing existing project ignore rules.
///
/// # Errors
/// Rejects symbolic links and concurrent edits, or reports a failed atomic replacement.
pub fn ensure_secret_file_ignores(root: &Path) -> std::io::Result<()> {
    let path = root.join(".gitignore");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => Some(metadata),
        Ok(_) => return Err(std::io::Error::other("gitignore must be a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let previous = if metadata.is_some() { fs::read_to_string(&path)? } else { String::new() };
    let mut next = previous.clone();
    for pattern in SECRET_FILE_IGNORE_PATTERNS {
        if !previous.lines().any(|line| line.trim() == pattern) {
            if !next.is_empty() && !next.ends_with('\n') {
                next.push('\n');
            }
            next.push_str(pattern);
            next.push('\n');
        }
    }
    if next == previous {
        return Ok(());
    }
    let mut temporary = tempfile::Builder::new().prefix(".locket-ignore-").tempfile_in(root)?;
    if let Some(metadata) = &metadata {
        temporary.as_file().set_permissions(metadata.permissions())?;
    }
    temporary.write_all(next.as_bytes())?;
    temporary.as_file().sync_all()?;
    let unchanged = match fs::symlink_metadata(&path) {
        Ok(current) if current.file_type().is_file() && metadata.is_some() => {
            fs::read_to_string(&path)? == previous
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && metadata.is_none() => true,
        _ => false,
    };
    if !unchanged {
        return Err(std::io::Error::other("gitignore changed before replacement"));
    }
    temporary.persist(&path).map_err(|error| error.error)?;
    #[cfg(unix)]
    std::fs::File::open(root)?.sync_all()?;
    Ok(())
}
