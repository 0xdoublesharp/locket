//! Bounded dotenv reads and metadata-only workspace discovery.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use locket_core::dotenv::{DotenvDiagnostic, DotenvOptions, parse_dotenv};
use serde::{Serialize, Serializer};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::runtime::error::{CliError, metadata_invalid_error};

const MAX_ENV_BYTES: usize = 1024 * 1024;
const SKIP_DIRECTORIES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".venv",
    "venv",
    "__pycache__",
    ".turbo",
    ".cache",
    "vendor",
];
const ENV_TEMPLATES: &[&str] =
    &[".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults"];
const SHARED_PROVIDER_KEYS: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    "VERCEL_TOKEN",
    "OPENROUTER_API_KEY",
    "HF_TOKEN",
    "HUGGINGFACE_API_KEY",
    "PERPLEXITY_API_KEY",
    "XAI_API_KEY",
    "LINEAR_API_KEY",
];

#[derive(Serialize)]
pub(super) struct Diagnostic {
    pub line: usize,
    pub message: &'static str,
}

impl From<DotenvDiagnostic> for Diagnostic {
    fn from(diagnostic: DotenvDiagnostic) -> Self {
        Self { line: diagnostic.line, message: diagnostic.message }
    }
}

pub(super) struct ParsedEnvFile {
    pub entries: Vec<(String, Zeroizing<String>)>,
    pub warnings: Vec<Diagnostic>,
    pub errors: Vec<Diagnostic>,
}

pub(super) fn open_env_file(path: &Path) -> Result<File, CliError> {
    let (parent, name) = input_parent(path)?;
    let directory = InputDirectory::open(&parent.canonicalize()?)?;
    directory.open_file(name)
}

pub fn open_scoped_file(canonical: &Path) -> Result<File, CliError> {
    let (parent, name) = input_parent(canonical)?;
    InputDirectory::open(parent)?.open_file(name)
}

pub(super) fn read_env_file(mut file: File, literal: bool) -> Result<ParsedEnvFile, CliError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(metadata_invalid_error("dotenv input must be a regular file"));
    }
    if metadata.len() > MAX_ENV_BYTES as u64 {
        return Err(metadata_invalid_error("dotenv input exceeds 1 MiB"));
    }

    // Allocate once so growing input cannot cause a plaintext buffer to be reallocated.
    let mut bytes = Zeroizing::new(vec![0_u8; MAX_ENV_BYTES + 1]);
    let mut length = 0;
    while length < bytes.len() {
        match file.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(read) => length += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    if length > MAX_ENV_BYTES {
        return Err(metadata_invalid_error("dotenv input exceeds 1 MiB"));
    }
    let text = std::str::from_utf8(&bytes[..length])
        .map_err(|_| metadata_invalid_error("dotenv input must be UTF-8"))?;
    let document = parse_dotenv(text, DotenvOptions { literal });
    drop(bytes);
    Ok(ParsedEnvFile {
        entries: document
            .entries
            .into_iter()
            .map(|entry| (entry.key, Zeroizing::new(entry.value)))
            .collect(),
        warnings: document.warnings.into_iter().map(Diagnostic::from).collect(),
        errors: document.errors.into_iter().map(Diagnostic::from).collect(),
    })
}

pub fn input_parent(path: &Path) -> Result<(&Path, &OsStr), CliError> {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => Ok((parent, name)),
        _ => Err(metadata_invalid_error("input must name a file")),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    File,
    Directory,
    Other,
}

/// Files and directory entries are looked up relative to an opened directory.
pub struct InputDirectory {
    path: PathBuf,
    #[cfg(unix)]
    handle: File,
    #[cfg(windows)]
    _handles: Vec<File>,
}

impl InputDirectory {
    pub fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};
            use std::path::Component;

            let mut components = path.components();
            if components.next() != Some(Component::RootDir) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected absolute path"));
            }
            let mut handle = File::open("/")?;
            for part in components {
                let Component::Normal(name) = part else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid path component",
                    ));
                };
                handle = openat(
                    &handle,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(File::from)?;
            }
            Ok(Self { path: path.to_owned(), handle })
        }
        #[cfg(windows)]
        {
            // Keep every ancestor open without FILE_SHARE_DELETE for pathname-based operations.
            let mut handles = Vec::new();
            let ancestors: Vec<_> = path.ancestors().collect();
            for ancestor in ancestors.into_iter().rev() {
                let handle = open_windows_entry(ancestor)?;
                if !windows_entry_is_plain(&handle)? || !handle.metadata()?.is_dir() {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected directory"));
                }
                handles.push(handle);
            }
            Ok(Self { path: path.to_owned(), _handles: handles })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(io::Error::new(io::ErrorKind::Unsupported, "secure file opening unavailable"))
        }
    }

    fn child_directory(&self, name: &OsStr) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};
            let handle = openat(
                &self.handle,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            Ok(Self { path: self.path.join(name), handle: File::from(handle) })
        }
        #[cfg(not(unix))]
        Self::open(&self.path.join(name))
    }

    pub fn open_file(&self, name: &OsStr) -> Result<File, CliError> {
        let file = self.file_handle(name).map_err(|error| {
            #[cfg(unix)]
            if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
                return metadata_invalid_error("dotenv input must be a regular file");
            }
            #[cfg(windows)]
            if error.kind() == io::ErrorKind::InvalidInput {
                return metadata_invalid_error("dotenv input must be a regular file");
            }
            error.into()
        })?;
        if !file.metadata()?.is_file() {
            return Err(metadata_invalid_error("dotenv input must be a regular file"));
        }
        Ok(file)
    }

    fn file_handle(&self, name: &OsStr) -> io::Result<File> {
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};
            openat(
                &self.handle,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from)
        }
        #[cfg(windows)]
        {
            let file = open_windows_entry(&self.path.join(name))?;
            if windows_entry_is_plain(&file)? {
                Ok(file)
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidInput, "input is a reparse point"))
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = name;
            Err(io::Error::new(io::ErrorKind::Unsupported, "secure file opening unavailable"))
        }
    }

    fn entry_kind(&self, name: &OsStr) -> io::Result<EntryKind> {
        #[cfg(unix)]
        {
            use rustix::fs::{AtFlags, FileType, statat};
            let stat = statat(&self.handle, name, AtFlags::SYMLINK_NOFOLLOW)?;
            Ok(match FileType::from_raw_mode(stat.st_mode) {
                FileType::RegularFile => EntryKind::File,
                FileType::Directory => EntryKind::Directory,
                _ => EntryKind::Other,
            })
        }
        #[cfg(not(unix))]
        {
            let metadata = std::fs::symlink_metadata(self.path.join(name))?;
            Ok(if metadata.is_file() {
                EntryKind::File
            } else if metadata.is_dir() {
                EntryKind::Directory
            } else {
                EntryKind::Other
            })
        }
    }

    pub fn is_regular(&self, name: &str) -> bool {
        self.entry_kind(OsStr::new(name)).is_ok_and(|kind| kind == EntryKind::File)
    }

    pub fn child_has_file(&self, directory: &str, name: &str) -> bool {
        self.child_directory(OsStr::new(directory)).is_ok_and(|dir| dir.is_regular(name))
    }

    fn names(&self) -> io::Result<Vec<OsString>> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            rustix::fs::Dir::read_from(&self.handle)?
                .filter_map(|entry| match entry {
                    Ok(entry) if matches!(entry.file_name().to_bytes(), b"." | b"..") => None,
                    Ok(entry) => {
                        Some(Ok(OsStr::from_bytes(entry.file_name().to_bytes()).to_owned()))
                    }
                    Err(error) => Some(Err(error.into())),
                })
                .collect()
        }
        #[cfg(not(unix))]
        std::fs::read_dir(&self.path)?.map(|entry| entry.map(|entry| entry.file_name())).collect()
    }
}

#[cfg(windows)]
fn open_windows_entry(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_SHARE_READ_WRITE: u32 = 0x0000_0003;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

#[cfg(windows)]
fn windows_entry_is_plain(file: &File) -> io::Result<bool> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    Ok(file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0)
}

#[derive(Serialize)]
struct EnvFileKeys {
    keys: BTreeSet<String>,
    warnings: Vec<Diagnostic>,
    invalid: usize,
    metadata_only: bool,
}

fn read_keys(file: File, literal: bool) -> Result<EnvFileKeys, CliError> {
    let ParsedEnvFile { entries, warnings, errors } = read_env_file(file, literal)?;
    let keys = entries
        .into_iter()
        .map(|(name, value)| {
            drop(value);
            name
        })
        .collect();
    Ok(EnvFileKeys { keys, warnings, invalid: errors.len(), metadata_only: true })
}

/// Read the names and safe diagnostics from a standalone dotenv file.
pub fn inspect_env_file_keys(path: &Path, literal: bool) -> Result<Value, CliError> {
    inspect_open_env_file(open_env_file(path)?, literal)
}

pub fn inspect_open_env_file(file: File, literal: bool) -> Result<Value, CliError> {
    Ok(serde_json::to_value(read_keys(file, literal)?)?)
}

pub(super) fn write_env_keys(
    output: &mut impl Write,
    path: &Path,
    literal: bool,
) -> Result<(), CliError> {
    let report = read_keys(open_env_file(path)?, literal)?;
    for name in report.keys {
        writeln!(output, "{name}")?;
    }
    write_warnings(output, &report.warnings)?;
    writeln!(output, "invalid: {}", report.invalid)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

pub(super) fn write_warnings(
    output: &mut impl Write,
    warnings: &[Diagnostic],
) -> Result<(), CliError> {
    for warning in warnings {
        writeln!(output, "warning: line {}: {}", warning.line, warning.message)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct ScannedEnvFile {
    #[serde(serialize_with = "serialize_path")]
    path: PathBuf,
    #[serde(serialize_with = "serialize_path")]
    project_root: PathBuf,
    has_locket_config: bool,
    suggested_profile: &'static str,
    suggested_source: &'static str,
    keys: BTreeSet<String>,
    key_count: usize,
    warnings_count: usize,
    invalid: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn serialize_path<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&path.display())
}

#[derive(Default)]
struct KeyLocations {
    files: BTreeSet<PathBuf>,
    projects: BTreeSet<PathBuf>,
}

#[derive(Serialize)]
struct SharedCandidate {
    key: String,
    files: Vec<String>,
    projects: Vec<String>,
}

#[derive(Serialize)]
struct EnvScanReport {
    root: String,
    files: Vec<ScannedEnvFile>,
    shared_candidates: Vec<SharedCandidate>,
    total_files: usize,
    total_keys: usize,
    metadata_only: bool,
}

/// Discover dotenv metadata and shared-key candidates without opening a vault.
pub fn scan_workspace_env_files(
    root: &Path,
    max_depth: usize,
    literal: bool,
) -> Result<Value, CliError> {
    Ok(serde_json::to_value(scan_env_files(root, max_depth, literal)?)?)
}

fn scan_env_files(root: &Path, max_depth: usize, literal: bool) -> Result<EnvScanReport, CliError> {
    // Resolve a trailing "." before screening the root so "symlink/." cannot bypass it.
    let root = root.components().collect::<PathBuf>();
    if !std::fs::symlink_metadata(&root)?.is_dir() {
        return Err(metadata_invalid_error("dotenv scan root must be a directory"));
    }
    let parent = root.parent().map(Path::canonicalize).transpose()?;
    let root = match (parent, root.file_name()) {
        (Some(parent), Some(name)) => parent.join(name),
        _ => root.canonicalize()?,
    };
    build_scan_report(&InputDirectory::open(&root)?, max_depth, literal)
}

pub fn scan_open_workspace(
    root: &InputDirectory,
    max_depth: usize,
    literal: bool,
) -> Result<Value, CliError> {
    Ok(serde_json::to_value(build_scan_report(root, max_depth, literal)?)?)
}

fn scan_directory(
    directory: &InputDirectory,
    inherited_root: &Path,
    inherited_config: bool,
    remaining_depth: usize,
    literal: bool,
    files: &mut Vec<ScannedEnvFile>,
) -> Result<(), CliError> {
    if remaining_depth == 0 {
        return Ok(());
    }
    let has_config = directory.is_regular(crate::LOCKET_TOML);
    let has_git =
        directory.entry_kind(OsStr::new(".git")).is_ok_and(|kind| kind != EntryKind::Other);
    let (project_root, has_locket_config) = if has_config || has_git {
        (directory.path.as_path(), has_config)
    } else {
        (inherited_root, inherited_config)
    };
    let names =
        directory.names().map_err(|_| metadata_invalid_error("could not walk dotenv scan root"))?;
    for name in names {
        match directory.entry_kind(&name) {
            Ok(EntryKind::Directory)
                if remaining_depth > 1
                    && !name.to_str().is_some_and(|name| SKIP_DIRECTORIES.contains(&name)) =>
            {
                // A directory replaced after enumeration is no longer part of this scan.
                if let Ok(child) = directory.child_directory(&name) {
                    scan_directory(
                        &child,
                        project_root,
                        has_locket_config,
                        remaining_depth - 1,
                        literal,
                        files,
                    )?;
                }
            }
            Ok(EntryKind::File) if name.to_str().is_some_and(is_env_filename) => {
                let path = directory.path.join(&name);
                let (keys, warnings_count, invalid, error) =
                    match directory.open_file(&name).and_then(|file| read_keys(file, literal)) {
                        Ok(report) => (report.keys, report.warnings.len(), report.invalid, None),
                        Err(error) => (BTreeSet::new(), 0, 1, Some(error.to_string())),
                    };
                files.push(ScannedEnvFile {
                    suggested_profile: suggested_profile(&path),
                    path,
                    project_root: project_root.to_owned(),
                    has_locket_config,
                    suggested_source: "user-local",
                    key_count: keys.len(),
                    keys,
                    warnings_count,
                    invalid,
                    error,
                });
            }
            _ => {}
        }
    }
    Ok(())
}

fn build_scan_report(
    root: &InputDirectory,
    max_depth: usize,
    literal: bool,
) -> Result<EnvScanReport, CliError> {
    let mut locations = BTreeMap::<String, KeyLocations>::new();
    let mut files = Vec::new();
    scan_directory(root, &root.path, false, max_depth, literal, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    for file in &files {
        for key in &file.keys {
            let found = locations.entry(key.clone()).or_default();
            found.files.insert(file.path.clone());
            found.projects.insert(file.project_root.clone());
        }
    }
    let shared_candidates = locations
        .into_iter()
        .filter(|(key, found)| {
            found.projects.len() >= 2 || SHARED_PROVIDER_KEYS.contains(&key.as_str())
        })
        .map(|(key, found)| SharedCandidate {
            key,
            files: found.files.iter().map(|path| path.display().to_string()).collect(),
            projects: found.projects.iter().map(|path| path.display().to_string()).collect(),
        })
        .collect();
    Ok(EnvScanReport {
        root: root.path.display().to_string(),
        total_files: files.len(),
        total_keys: files.iter().map(|file| file.key_count).sum(),
        files,
        shared_candidates,
        metadata_only: true,
    })
}

fn is_env_filename(name: &str) -> bool {
    (name == ".env" || name.starts_with(".env."))
        && !ENV_TEMPLATES.contains(&name)
        && !Path::new(name).extension().is_some_and(|ext| ext.eq_ignore_ascii_case("bak"))
}

fn suggested_profile(path: &Path) -> &'static str {
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    match name.strip_suffix(".local").unwrap_or(name) {
        ".env.production" | ".env.prod" => "prod",
        ".env.staging" => "staging",
        ".env.test" => "test",
        _ => "dev",
    }
}

pub(super) fn write_env_scan(
    output: &mut impl Write,
    root: &Path,
    max_depth: usize,
    literal: bool,
) -> Result<(), CliError> {
    let report = scan_env_files(root, max_depth, literal)?;
    writeln!(output, "root: {:?}", report.root)?;
    writeln!(output, "total_files: {}  total_keys: {}", report.total_files, report.total_keys)?;
    for file in report.files {
        writeln!(
            output,
            "{:?}  project_root={:?}  profile={}  source={}  keys={}  warnings={}  invalid={}",
            file.path.display().to_string(),
            file.project_root.display().to_string(),
            file.suggested_profile,
            file.suggested_source,
            file.key_count,
            file.warnings_count,
            file.invalid,
        )?;
        if let Some(error) = file.error {
            writeln!(output, "  {error}")?;
        }
    }
    writeln!(output, "shared_candidates: {}", report.shared_candidates.len())?;
    for candidate in report.shared_candidates {
        writeln!(output, "  {}  files={:?}", candidate.key, candidate.files)?;
    }
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn scan_and_reads_use_the_open_directory_after_its_path_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?.join("workspace");
        fs::create_dir(&root)?;
        fs::write(root.join(".env"), "ORIGINAL=fixture\n")?;
        let directory = InputDirectory::open(&root)?;

        fs::rename(&root, fixture.path().join("old-workspace"))?;
        fs::create_dir(&root)?;
        fs::write(root.join(".env"), "REPLACEMENT=fixture\n")?;

        let keys = inspect_open_env_file(directory.open_file(OsStr::new(".env"))?, false)?;
        assert_eq!(keys["keys"], serde_json::json!(["ORIGINAL"]));
        let scan = scan_open_workspace(&directory, 1, false)?;
        assert_eq!(scan["total_files"], 1);
        assert_eq!(scan["files"][0]["keys"], serde_json::json!(["ORIGINAL"]));
        Ok(())
    }
}
