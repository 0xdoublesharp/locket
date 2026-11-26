//! Atomic, comment-preserving writes of project command metadata.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
pub const SECRET_FILE_IGNORE_PATTERNS: &[&str] = &[
    ".env",
    ".env.*",
    ".locket.local",
    ".locketignore",
    "!.env.example",
    "!.env.sample",
    "!.env.template",
    "!.env.dist",
    "!.env.defaults",
    "!.env.*.example",
    "!.env.*.sample",
    "!.env.*.template",
];

// Representative paths in the same order as the ignore and exception rules above.
const PROTECTION_SAMPLES: [&str; 4] =
    [".env", ".env.production.local", ".locket.local", ".locketignore"];
const TEMPLATE_SAMPLES: [&str; 8] = [
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.defaults",
    ".env.local.example",
    ".env.local.sample",
    ".env.local.template",
];

struct IgnoreCoverage {
    protected: [bool; PROTECTION_SAMPLES.len()],
    ignored_templates: [bool; TEMPLATE_SAMPLES.len()],
}

#[derive(PartialEq, Eq)]
struct IgnoreMatch {
    source: String,
    line: String,
    pattern: String,
}

impl IgnoreMatch {
    fn is_ignored(&self) -> bool {
        !self.pattern.is_empty() && !self.pattern.starts_with('!')
    }
}

fn git_in(directory: &Path) -> Command {
    let mut git = Command::new("git");
    git.arg("-C")
        .arg(directory)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .stdin(Stdio::null());
    git
}

fn git_ignore_coverage(root: &Path, local: &str) -> Option<IgnoreCoverage> {
    let output = git_in(root).args(["rev-parse", "--show-toplevel"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let worktree = std::str::from_utf8(&output.stdout).ok()?.strip_suffix('\n')?;
    let worktree = Path::new(worktree);
    let canonical_worktree = worktree.canonicalize().ok()?;
    let canonical_root = root.canonicalize().ok()?;
    let relative = canonical_root.strip_prefix(&canonical_worktree).ok()?;
    let mut prefix = String::new();
    for component in relative.components() {
        prefix.push_str(component.as_os_str().to_str()?);
        prefix.push('/');
    }
    let local_source = format!("{prefix}.gitignore");
    let (ignore_rules, exception_rules) =
        SECRET_FILE_IGNORE_PATTERNS.split_at(PROTECTION_SAMPLES.len());
    let samples: Vec<_> = PROTECTION_SAMPLES
        .into_iter()
        .chain(TEMPLATE_SAMPLES)
        .map(|sample| format!("./{prefix}{sample}"))
        .collect();
    let actual = check_git_ignore(worktree, &samples, false)?;
    let (protection, templates) = actual.split_at(PROTECTION_SAMPLES.len());

    // A relative core.excludesFile can have the same reported name as a worktree
    // .gitignore. Confirm the winning match with global excludes disabled.
    let without_global_excludes = protection
        .iter()
        .any(|rule| rule.is_ignored() && is_worktree_gitignore(&rule.source))
        .then(|| check_git_ignore(worktree, &samples, true))
        .flatten();
    let mut tracked = BTreeMap::new();
    Some(IgnoreCoverage {
        protected: std::array::from_fn(|index| {
            let rule = &protection[index];
            if !rule.is_ignored() {
                return false;
            }
            // An exact local entry is already written, even before the user stages it.
            if rule.source == local_source && rule.pattern == ignore_rules[index] {
                return true;
            }
            // Git skips the local file if an ancestor directory is ignored.
            // Preserve explicit local entries on repeated runs in that case.
            if rule.source != local_source && local_protection_present(local, ignore_rules[index]) {
                return true;
            }
            without_global_excludes.as_ref().is_some_and(|rules| rules[index] == *rule)
                && *tracked.entry(&rule.source).or_insert_with(|| {
                    is_tracked_gitignore(worktree, &canonical_worktree, &rule.source)
                })
        }),
        ignored_templates: std::array::from_fn(|index| {
            let rule = &templates[index];
            rule.is_ignored()
                && (rule.source == local_source
                    || !local_exception_present(local, exception_rules[index]))
        }),
    })
}

fn check_git_ignore(
    worktree: &Path,
    samples: &[String],
    disable_global_excludes: bool,
) -> Option<Vec<IgnoreMatch>> {
    let mut command = git_in(worktree);
    if disable_global_excludes {
        command.args(["-c", "core.excludesFile="]);
    }
    let mut input = samples.join("\0");
    input.push('\0');
    let mut child = command
        .args(["check-ignore", "-v", "-z", "--no-index", "--non-matching", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    // Git can stream matches while still reading paths from stdin.
    let written = std::thread::Builder::new().spawn(move || stdin.write_all(input.as_bytes()));
    let output = child.wait_with_output().ok()?;
    written.ok()?.join().ok()?.ok()?;
    if !matches!(output.status.code(), Some(0 | 1)) {
        return None;
    }
    let mut fields = std::str::from_utf8(&output.stdout).ok()?.strip_suffix('\0')?.split('\0');
    let mut matches = Vec::with_capacity(samples.len());
    for sample in samples {
        let source = fields.next()?;
        let line = fields.next()?;
        let pattern = fields.next()?;
        if fields.next()? != sample || (!pattern.is_empty() && !output.status.success()) {
            return None;
        }
        matches.push(IgnoreMatch {
            source: source.to_owned(),
            line: line.to_owned(),
            pattern: pattern.to_owned(),
        });
    }
    fields.next().is_none().then_some(matches)
}

fn is_worktree_gitignore(source: &str) -> bool {
    let path = Path::new(source);
    !path.is_absolute() && path.file_name().is_some_and(|name| name == ".gitignore")
}

fn is_tracked_gitignore(worktree: &Path, canonical_worktree: &Path, source: &str) -> bool {
    if !is_worktree_gitignore(source) {
        return false;
    }
    let path = worktree.join(source);
    fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file())
        && path.canonicalize().is_ok_and(|path| path.starts_with(canonical_worktree))
        && git_in(worktree)
            .args(["--literal-pathspecs", "ls-files", "-z", "--error-unmatch", "--", source])
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && output
                        .stdout
                        .split(|&byte| byte == 0)
                        .any(|entry| entry == source.as_bytes())
            })
}

fn append_ignore_pattern(contents: &mut String, pattern: &str) {
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(pattern);
    contents.push('\n');
}

fn local_protection_present(contents: &str, pattern: &str) -> bool {
    contents.lines().rev().find(|line| *line == pattern || line.strip_prefix('!') == Some(pattern))
        == Some(pattern)
}

fn local_exception_present(contents: &str, pattern: &str) -> bool {
    contents.lines().rev().find(|line| *line == pattern || *line == ".env.*") == Some(pattern)
}

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
    let coverage = git_ignore_coverage(root, &previous);
    let (protection, templates) = SECRET_FILE_IGNORE_PATTERNS.split_at(PROTECTION_SAMPLES.len());
    let mut added_wildcard = false;
    for (index, &pattern) in protection.iter().enumerate() {
        let covered = coverage.as_ref().map_or_else(
            || local_protection_present(&previous, pattern),
            |coverage| coverage.protected[index],
        );
        if !covered {
            append_ignore_pattern(&mut next, pattern);
            added_wildcard |= pattern == ".env.*";
        }
    }
    for (index, &pattern) in templates.iter().enumerate() {
        if added_wildcard
            || coverage.as_ref().map_or_else(
                || !local_exception_present(&previous, pattern),
                |coverage| coverage.ignored_templates[index],
            )
        {
            append_ignore_pattern(&mut next, pattern);
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

#[cfg(test)]
#[path = "policy_file_tests.rs"]
mod ignore_tests;
