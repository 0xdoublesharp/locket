//! Bounded dotenv reads and metadata-only workspace discovery.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use locket_core::dotenv::{DotenvDiagnostic, DotenvOptions, parse_dotenv};
use serde::Serialize;
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

pub(super) fn read_env_file(path: &Path, literal: bool) -> Result<ParsedEnvFile, CliError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(metadata_invalid_error("dotenv input must be a regular file"));
    }
    let mut file = open_env_file(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
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

fn open_env_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(io::Error::from)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        fs::OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path)
    }
    #[cfg(not(any(unix, windows)))]
    File::open(path)
}

#[derive(Serialize)]
struct EnvFileKeys {
    keys: BTreeSet<String>,
    warnings: Vec<Diagnostic>,
    invalid: usize,
    metadata_only: bool,
}

fn read_keys(path: &Path, literal: bool) -> Result<EnvFileKeys, CliError> {
    let ParsedEnvFile { entries, warnings, errors } = read_env_file(path, literal)?;
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
    Ok(serde_json::to_value(read_keys(path, literal)?)?)
}

pub(super) fn write_env_keys(
    output: &mut impl Write,
    path: &Path,
    literal: bool,
) -> Result<(), CliError> {
    let report = read_keys(path, literal)?;
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
    path: String,
    project_root: String,
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
    if !fs::symlink_metadata(&root)?.is_dir() {
        return Err(metadata_invalid_error("dotenv scan root must be a directory"));
    }
    let root = root.canonicalize()?;
    let mut walker = ignore::WalkBuilder::new(&root);
    walker.standard_filters(false).follow_links(false).max_depth(Some(max_depth)).filter_entry(
        |entry| {
            entry.depth() == 0
                || entry.file_type().is_some_and(|kind| {
                    let skipped_directory = kind.is_dir()
                        && entry
                            .file_name()
                            .to_str()
                            .is_some_and(|name| SKIP_DIRECTORIES.contains(&name));
                    !kind.is_symlink() && !skipped_directory
                })
        },
    );

    let mut paths = Vec::new();
    for entry in walker.build() {
        let entry = entry.map_err(|_| metadata_invalid_error("could not walk dotenv scan root"))?;
        if entry.file_type().is_some_and(|kind| kind.is_file())
            && entry.file_name().to_str().is_some_and(is_env_filename)
        {
            paths.push(entry.into_path());
        }
    }
    paths.sort();
    Ok(scan_paths(&root, paths, literal))
}

fn scan_paths(root: &Path, paths: Vec<PathBuf>, literal: bool) -> EnvScanReport {
    let mut locations = BTreeMap::<String, KeyLocations>::new();
    let mut files = Vec::new();
    for path in paths {
        let (project_root, has_locket_config) = scan_project_root(root, &path);
        let (keys, warnings_count, invalid, error) = match read_keys(&path, literal) {
            Ok(report) => (report.keys, report.warnings.len(), report.invalid, None),
            Err(error) => (BTreeSet::new(), 0, 1, Some(error.to_string())),
        };
        for key in &keys {
            let found = locations.entry(key.clone()).or_default();
            found.files.insert(path.clone());
            found.projects.insert(project_root.to_path_buf());
        }
        files.push(ScannedEnvFile {
            path: path.display().to_string(),
            project_root: project_root.display().to_string(),
            has_locket_config,
            suggested_profile: suggested_profile(&path),
            suggested_source: "user-local",
            key_count: keys.len(),
            keys,
            warnings_count,
            invalid,
            error,
        });
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
    EnvScanReport {
        root: root.display().to_string(),
        total_files: files.len(),
        total_keys: files.iter().map(|file| file.key_count).sum(),
        files,
        shared_candidates,
        metadata_only: true,
    }
}

fn is_env_filename(name: &str) -> bool {
    (name == ".env" || name.starts_with(".env."))
        && !ENV_TEMPLATES.contains(&name)
        && !Path::new(name).extension().is_some_and(|ext| ext.eq_ignore_ascii_case("bak"))
}

fn scan_project_root<'a>(root: &'a Path, path: &'a Path) -> (&'a Path, bool) {
    for ancestor in path.ancestors().skip(1) {
        let has_config =
            fs::symlink_metadata(ancestor.join(crate::LOCKET_TOML)).is_ok_and(|m| m.is_file());
        let has_git =
            fs::symlink_metadata(ancestor.join(".git")).is_ok_and(|m| m.is_file() || m.is_dir());
        if has_config || has_git || ancestor == root {
            return (ancestor, has_config);
        }
    }
    (root, false)
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
            file.path,
            file.project_root,
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
