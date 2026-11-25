//! Scoped desktop operations. Child output never crosses the webview boundary.

#[path = "command_detection.rs"]
mod command_detection;
use command_detection::DetectedCommand;

#[cfg(not(any(target_os = "windows", test)))]
use base64 as _;
use locket_agent::{
    AgentMethod, CopySecretToSharedResponse, CreateProfileResponse, DeleteSecretResponse,
    GrantAction,
};
use locket_core::ProjectConfig;

use super::AgentClientError;
use locket_platform::{INSTANCE_ENV, LocketInstance};
use locket_store::Store;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const CHILD_TIMEOUT: Duration = Duration::from_secs(30);
const PLAIN_CLIPBOARD_MAX_BYTES: usize = 16 * 1024;
const SHARED_PROJECT_ID_PREFIX: &str = "lk_proj_shared_";
static RESOURCE_ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
static SELECTED_PROJECT: std::sync::Mutex<Option<DesktopProjectContext>> =
    std::sync::Mutex::new(None);

type CopySecretFuture =
    std::pin::Pin<Box<dyn Future<Output = Result<(), super::ClipboardError>> + Send>>;

/// Native effects are supplied by the desktop, outside webview IPC.
pub(crate) struct DesktopHandoff {
    pub(crate) terminal: fn(&Path, &Path, &[&str]) -> Result<(), String>,
    #[cfg(target_os = "macos")]
    pub(crate) picker_program: PathBuf,
    pub(crate) copy_text: fn(String) -> Result<(), super::ClipboardError>,
    pub(crate) copy_secret: fn(String, Duration) -> CopySecretFuture,
}

impl Default for DesktopHandoff {
    fn default() -> Self {
        Self {
            terminal: launch_terminal,
            #[cfg(target_os = "macos")]
            picker_program: "/usr/bin/osascript".into(),
            copy_text: super::clipboard::copy_plain_text,
            copy_secret: |value, ttl| Box::pin(super::clipboard::copy_with_ttl(value, ttl)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct DesktopProjectContext {
    root: String,
    project_id: String,
    project_name: String,
    profile_id: String,
    profile_name: String,
    is_shared: bool,
}

impl DesktopProjectContext {
    fn project_root(&self) -> Option<&Path> {
        (!self.is_shared && !self.root.is_empty()).then(|| Path::new(&self.root))
    }
}

pub(crate) fn is_shared_project_id(id: &str) -> bool {
    id.starts_with(SHARED_PROJECT_ID_PREFIX)
}

#[derive(Deserialize, Default)]
pub(crate) struct DesktopOpenSharedVaultRequest {
    #[serde(default)]
    project_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct DesktopFolderInspection {
    path: String,
    has_config: bool,
    folder_name: String,
}

#[derive(Deserialize)]
pub(crate) struct DesktopPathRequest {
    path: PathBuf,
}
#[derive(Deserialize)]
pub(crate) struct DesktopImportEnvRequest {
    project_id: String,
    path: PathBuf,
    overwrite: bool,
    literal: bool,
    #[serde(default)]
    confirmation: Option<String>,
}
#[derive(Deserialize)]
pub(crate) struct DesktopStartAgentRequest {
    project_id: Option<String>,
}
#[derive(Deserialize)]
pub(crate) struct DesktopRunPolicyRequest {
    project_id: String,
    policy_name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DesktopScanProjectRequest {
    project_id: String,
}
#[derive(Serialize)]
pub(crate) struct DesktopImportSummary {
    summary: String,
}
#[derive(Serialize)]
pub(crate) struct DesktopRunResponse {
    launched: bool,
    command: String,
}

struct CliPlan {
    cwd: PathBuf,
    args: Vec<String>,
    input: Option<Vec<u8>>,
}

fn metadata_error(_: impl std::fmt::Display) -> String {
    "Cannot read registered project metadata. Check locket.toml and run `locket doctor` in the project.".into()
}

fn root_hash(root: &Path) -> [u8; 32] {
    Sha256::digest(root.to_string_lossy().as_bytes()).into()
}

fn selected_root(path: &Path) -> Result<PathBuf, String> {
    let path = path
        .canonicalize()
        .map_err(|_| "Select an existing project folder or locket.toml file.".to_string())?;
    if path.is_dir() {
        return Ok(path);
    }
    if path.is_file() && path.file_name() == Some(OsStr::new("locket.toml")) {
        return path
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "Project folder is unavailable.".into());
    }
    Err("Select a project folder or its locket.toml file.".into())
}

fn open_project_at(store_path: &Path, path: &Path) -> Result<DesktopProjectContext, String> {
    let root = selected_root(path)?;
    if !store_path.is_file() {
        return Err("No local vault exists. Initialize this project with Locket first.".into());
    }
    let source = fs::read_to_string(root.join("locket.toml")).map_err(|_| {
        "No readable locket.toml exists in the selected folder. Initialize it first.".to_string()
    })?;
    let config: ProjectConfig = toml::from_str(&source).map_err(metadata_error)?;
    if config.schema_version != locket_core::PROJECT_CONFIG_SCHEMA_VERSION {
        return Err("Unsupported locket.toml schema. Update Locket.".into());
    }
    let store = Store::open(store_path).map_err(metadata_error)?;
    let project_id = config.project_id.as_str();
    if is_shared_project_id(project_id) {
        return Err("Open the Global Vault from the vault list.".into());
    }
    if !store.project_root_is_trusted(project_id, &root_hash(&root)).map_err(metadata_error)? {
        return Err(
            "This folder is not trusted for the project. Run `locket trust` in this folder first."
                .into(),
        );
    }
    let project = store
        .get_project(project_id)
        .map_err(metadata_error)?
        .ok_or_else(|| "Project is not registered in this vault.".to_string())?;
    let profile = store
        .get_profile_by_name(project_id, config.default_profile.as_str())
        .map_err(metadata_error)?
        .ok_or_else(|| {
            "The configured profile is missing from this vault. Run `locket doctor`.".to_string()
        })?;
    let root = root
        .to_str()
        .ok_or_else(|| "Project folder must have a valid Unicode path.".to_string())?
        .into();
    Ok(DesktopProjectContext {
        root,
        project_id: project.id,
        project_name: project.name,
        profile_id: profile.id,
        profile_name: profile.name,
        is_shared: false,
    })
}

fn shared_metadata_error(_: impl std::fmt::Display) -> String {
    "Cannot read Global Vault metadata. Check the local vault with `locket doctor`.".into()
}

fn shared_projects(store: &Store) -> Result<Vec<locket_store::ProjectRecord>, String> {
    let mut projects = store.list_projects().map_err(shared_metadata_error)?;
    projects.retain(|project| is_shared_project_id(&project.id));
    // The store orders by name and ID. Keep that order after the Global Vault.
    projects.sort_by_key(|project| project.name != "@shared");
    Ok(projects)
}

fn shared_vault_context(
    store: &Store,
    project: locket_store::ProjectRecord,
    profile_id: Option<&str>,
) -> Result<Option<DesktopProjectContext>, String> {
    let profiles = store.list_profiles(&project.id).map_err(shared_metadata_error)?;
    let profile = match profile_id {
        Some(id) => Some(profiles.iter().find(|profile| profile.id == id).ok_or_else(|| {
            "The selected Global Vault profile changed. Open the vault again.".to_string()
        })?),
        None => profiles.iter().find(|profile| profile.name == "default").or(profiles.first()),
    };
    Ok(profile.map(|profile| DesktopProjectContext {
        root: String::new(),
        project_id: project.id,
        project_name: project.name,
        profile_id: profile.id.clone(),
        profile_name: profile.name.clone(),
        is_shared: true,
    }))
}

fn find_shared_vault_at(
    store_path: &Path,
    project_id: Option<&str>,
    profile_id: Option<&str>,
) -> Result<Option<DesktopProjectContext>, String> {
    if project_id.is_some_and(|id| !is_shared_project_id(id)) {
        return Err("Requested vault ID must identify a Global Vault.".into());
    }
    match fs::symlink_metadata(store_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(shared_metadata_error(error)),
    }
    let store = Store::open_read_only(store_path).map_err(shared_metadata_error)?;
    let project = if let Some(id) = project_id {
        store.get_project(id).map_err(shared_metadata_error)?
    } else {
        shared_projects(&store)?.into_iter().next()
    };
    let Some(project) = project else {
        return Ok(None);
    };
    shared_vault_context(&store, project, profile_id)?.map(Some).ok_or_else(|| {
        "Global Vault has no profile. Check the local vault with `locket doctor`.".into()
    })
}

fn open_shared_vault_at(
    store_path: &Path,
    project_id: Option<&str>,
    initialize: impl FnOnce() -> Result<(), String>,
) -> Result<DesktopProjectContext, String> {
    if let Some(context) = find_shared_vault_at(store_path, project_id, None)? {
        return Ok(context);
    }
    if project_id.is_some() {
        return Err("Global Vault is not registered in this store.".into());
    }
    initialize()?;
    find_shared_vault_at(store_path, None, None)?
        .ok_or_else(|| "Global Vault is missing after initialization.".into())
}

fn refresh_context_at(
    store_path: &Path,
    selected: &DesktopProjectContext,
) -> Result<DesktopProjectContext, String> {
    if selected.is_shared || is_shared_project_id(&selected.project_id) {
        return find_shared_vault_at(
            store_path,
            Some(&selected.project_id),
            Some(&selected.profile_id),
        )?
        .ok_or_else(|| "Global Vault is not registered in this store.".into());
    }
    let root = selected.project_root().ok_or_else(|| "Open a project folder again.".to_string())?;
    open_project_at(store_path, root)
}

fn inspect_project_folder_at(path: &Path) -> Result<DesktopFolderInspection, String> {
    if !path.is_absolute() {
        return Err("Select an existing project folder by its absolute path.".into());
    }
    let root = selected_root(path)?;
    let config = root.join("locket.toml");
    let has_config = match fs::symlink_metadata(&config) {
        Ok(_) if config.is_file() => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        _ => return Err("Cannot inspect locket.toml in the selected folder.".into()),
    };
    let folder_name = root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| root.to_string_lossy().into_owned());
    let path = root
        .to_str()
        .ok_or_else(|| "Project folder must have a valid Unicode path.".to_string())?
        .into();
    Ok(DesktopFolderInspection { path, has_config, folder_name })
}

fn list_projects_at(store_path: &Path) -> Result<Vec<DesktopProjectContext>, String> {
    if !store_path.exists() {
        return Ok(Vec::new());
    }
    let store = Store::open(store_path).map_err(metadata_error)?;
    let mut projects = Vec::new();
    for project in shared_projects(&store)? {
        if let Some(context) = shared_vault_context(&store, project, None)? {
            projects.push(context);
        }
    }
    let mut query = store.connection().prepare("SELECT DISTINCT display_path FROM project_roots WHERE display_path IS NOT NULL ORDER BY display_path").map_err(metadata_error)?;
    let roots = query
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(metadata_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(metadata_error)?;
    // Stale, moved, or untrusted copies are omitted instead of guessed.
    projects
        .extend(roots.iter().filter_map(|root| open_project_at(store_path, Path::new(root)).ok()));
    Ok(projects)
}

fn application_directory() -> Result<PathBuf, String> {
    Ok(std::env::current_exe()
        .map_err(metadata_error)?
        .parent()
        .ok_or_else(|| "Cannot find application directory.".to_string())?
        .into())
}

fn shared_init_plan() -> Result<CliPlan, String> {
    let cwd = application_directory()?;
    Ok(CliPlan { cwd, args: vec!["shared".into(), "init".into(), "--json".into()], input: None })
}

fn project_context(store_path: &Path, project_id: &str) -> Result<DesktopProjectContext, String> {
    let selected =
        SELECTED_PROJECT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    project_context_with_selection(store_path, project_id, selected.as_ref())
}

fn initialize_plan(path: &Path) -> Result<CliPlan, String> {
    let cwd =
        path.canonicalize().map_err(|_| "Select an existing folder to initialize.".to_string())?;
    if !cwd.is_dir() {
        return Err("Initialize requires an existing folder.".into());
    }
    if cwd.ancestors().skip(1).any(|parent| parent.join("locket.toml").exists()) {
        return Err("A parent folder already contains locket.toml. Open that project or select a folder outside it before initializing.".into());
    }
    Ok(CliPlan { cwd, args: vec!["init".into(), "--no-passkey".into()], input: None })
}

fn start_plan(store_path: &Path, project_id: Option<&str>) -> Result<CliPlan, String> {
    let context = project_id.map(|id| project_context(store_path, id)).transpose()?;
    let cwd = context
        .as_ref()
        .and_then(DesktopProjectContext::project_root)
        .map_or_else(application_directory, |root| Ok(root.to_path_buf()))?;
    Ok(CliPlan { cwd, args: vec!["agent".into(), "start".into()], input: None })
}

fn policy_context(
    store_path: &Path,
    project_id: &str,
    name: &str,
) -> Result<DesktopProjectContext, String> {
    let context = project_context(store_path, project_id)?;
    let root = context.project_root().ok_or_else(|| {
        "Commands require a connected project folder with locket.toml.".to_string()
    })?;
    if name.is_empty() || name.starts_with('-') || name.contains('\0') {
        return Err("Choose a policy whose name does not begin with a dash.".into());
    }
    let source = fs::read_to_string(root.join("locket.toml")).map_err(metadata_error)?;
    let policies = locket_core::PolicyDocument::from_toml_str(&source).map_err(metadata_error)?;
    if !policies.commands.contains_key(name) {
        return Err("The policy no longer exists in locket.toml. Refresh the command list.".into());
    }
    Ok(context)
}

fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
    }
}

fn find_cli_from(candidates: &[PathBuf], search_path: Option<&OsStr>) -> Result<PathBuf, String> {
    let installed = search_path
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .filter(|path| path.is_absolute())
        .map(|path| path.join(if cfg!(windows) { "locket.exe" } else { "locket" }));
    candidates.iter().cloned().chain(installed).find(|path| executable_file(path)).and_then(|path| path.canonicalize().ok())
        .ok_or_else(|| "Locket CLI was not found. Install `locket` on PATH or place it beside the desktop application, then retry.".into())
}

pub(crate) fn set_resource_root(path: PathBuf) {
    let _ = RESOURCE_ROOT.set(path);
}

fn verify_cli_version(executable: &Path, timeout: Duration) -> Result<(), String> {
    use std::io::Read as _;
    let mut child = Command::new(executable)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot inspect the bundled CLI version.".to_owned())?;
    let stdout = child.stdout.take().ok_or_else(|| "Cannot read the CLI version.".to_owned())?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout.take(128).read_to_end(&mut output).map(|_| output);
        let _ = sender.send(result);
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => {
                return Err("The CLI version check failed. Reinstall Locket.".into());
            }
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("The CLI version check timed out.".into());
            }
        }
    }
    let output = receiver
        .recv_timeout(Duration::from_millis(500))
        .map_err(|_| "The CLI version response timed out.".to_owned())?
        .map_err(|_| "Cannot read the CLI version.".to_owned())?;
    if output == format!("locket {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
        || output == format!("locket {}\r\n", env!("CARGO_PKG_VERSION")).as_bytes()
    {
        Ok(())
    } else {
        Err("The Locket CLI version differs from this desktop application. Reinstall the matching release.".into())
    }
}

fn resolve_cli() -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(metadata_error)?;
    let parent =
        executable.parent().ok_or_else(|| "Cannot find application directory.".to_string())?;
    let filename = if cfg!(windows) { "locket.exe" } else { "locket" };
    let mut candidates = Vec::new();
    if let Some(root) = RESOURCE_ROOT.get() {
        candidates.push(root.join(filename));
    }
    candidates.extend([
        parent.join(filename),
        parent.join("../Resources").join(filename),
        parent.join("resources").join(filename),
    ]);
    // The development desktop uses only the CLI built beside it; the CLI on
    // PATH is usually the installed one.
    let search_path = match LocketInstance::current() {
        LocketInstance::Installed => std::env::var_os("PATH"),
        LocketInstance::Dev => None,
    };
    let cli = find_cli_from(&candidates, search_path.as_deref())?;
    verify_cli_version(&cli, Duration::from_secs(2))?;
    Ok(cli)
}

#[derive(Serialize)]
pub(crate) struct DesktopMcpConfigSnippet {
    command: String,
    args: Vec<String>,
    json: String,
}

fn mcp_config_snippet(command: String) -> Result<DesktopMcpConfigSnippet, String> {
    let args = vec!["mcp".into()];
    let config =
        serde_json::json!({ "mcpServers": { "locket": { "command": command, "args": args } } });
    let json = serde_json::to_string_pretty(&config)
        .map_err(|_| "Cannot encode the Locket MCP configuration.".to_owned())?;
    Ok(DesktopMcpConfigSnippet { command, args, json })
}

#[tauri::command]
pub(crate) async fn desktop_mcp_config_snippet() -> Result<DesktopMcpConfigSnippet, String> {
    blocking(|| {
        let command = resolve_cli()
            .ok()
            .and_then(|path| path.into_os_string().into_string().ok())
            .unwrap_or_else(|| "locket".to_owned());
        mcp_config_snippet(command)
    })
    .await
}

#[tauri::command]
pub(crate) async fn desktop_copy_text_plain(
    handoff: tauri::State<'_, DesktopHandoff>,
    text: String,
) -> Result<(), String> {
    copy_plain_text_with(text, handoff.copy_text).await
}

async fn copy_plain_text_with(
    text: String,
    copy: fn(String) -> Result<(), super::ClipboardError>,
) -> Result<(), String> {
    if text.is_empty() || text.len() > PLAIN_CLIPBOARD_MAX_BYTES {
        return Err("Clipboard text must be between 1 byte and 16 KiB.".into());
    }
    blocking(move || copy(text).map_err(|error| error.to_string())).await
}

#[tauri::command]
pub(crate) async fn desktop_get_launch_at_login() -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        blocking(|| {
            super::launch_agent::LaunchAgent::current()?
                .enabled()
                .map_err(|error| format!("Cannot read launch at login setting: {error}"))
        })
        .await
    }
    #[cfg(not(target_os = "macos"))]
    Ok(false)
}

#[tauri::command]
pub(crate) async fn desktop_set_launch_at_login(enabled: bool) -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        // Serialize callers so the returned state describes this change.
        static SETTINGS: std::sync::Mutex<()> = std::sync::Mutex::new(());
        blocking(move || {
            let _guard = SETTINGS.lock().map_err(|_| "Launch at login setting is unavailable.")?;
            let agent = super::launch_agent::LaunchAgent::current()?;
            if enabled {
                let executable = std::env::current_exe()
                    .map_err(|error| format!("Cannot locate the Locket executable: {error}"))?;
                agent
                    .enable(&executable)
                    .map_err(|error| format!("Cannot enable launch at login: {error}"))?;
            } else {
                agent
                    .disable()
                    .map_err(|error| format!("Cannot disable launch at login: {error}"))?;
            }
            Ok(enabled)
        })
        .await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = enabled;
        Err("Launch at login is available on macOS.".into())
    }
}

#[cfg(any(target_os = "macos", test))]
const PICK_PATH_SCRIPT: &str = r#"on run argv
    set pickerMode to item 1 of argv
    set pickerPrompt to item 2 of argv
    if pickerMode is "directory" then
        set selectedPath to choose folder with prompt pickerPrompt
    else if pickerMode is "save" then
        set defaultName to item 3 of argv
        if defaultName is "" then
            set selectedPath to choose file name with prompt pickerPrompt
        else
            set selectedPath to choose file name with prompt pickerPrompt default name defaultName
        end if
    else
        set selectedPath to choose file with prompt pickerPrompt
    end if
    return POSIX path of selectedPath
end run"#;

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy)]
enum PickerMode {
    Directory,
    File,
    Save,
}

#[cfg(any(target_os = "macos", test))]
fn picker_arguments<'a>(
    mode: PickerMode,
    title: Option<&'a str>,
    default_name: Option<&'a str>,
) -> [&'a str; 8] {
    let (mode, prompt, default_name) = match mode {
        PickerMode::Directory => ("directory", "Choose a folder", ""),
        PickerMode::File => ("file", "Choose a file", ""),
        PickerMode::Save => ("save", "Save a file", default_name.unwrap_or_default()),
    };
    ["-s", "he", "-e", PICK_PATH_SCRIPT, "--", mode, title.unwrap_or(prompt), default_name]
}

#[cfg(any(target_os = "macos", test))]
fn parse_picker_output(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Option<String>, String> {
    if !success {
        if String::from_utf8_lossy(stderr).trim_end().ends_with("(-128)") {
            return Ok(None);
        }
        return Err("Could not open the macOS picker.".into());
    }
    // osascript appends a single newline to human-readable results. Preserve
    // whitespace and any embedded newlines in the selected filename.
    std::str::from_utf8(stdout)
        .ok()
        .and_then(|output| output.strip_suffix('\n'))
        .filter(|path| path.starts_with('/') && !path.contains('\0'))
        .map(|path| Some(path.to_owned()))
        .ok_or_else(|| "The macOS picker returned an invalid path.".into())
}

#[cfg(target_os = "macos")]
async fn pick_path(
    program: PathBuf,
    mode: PickerMode,
    title: Option<String>,
    default_name: Option<String>,
) -> Result<Option<String>, String> {
    blocking(move || {
        let output = Command::new(program)
            .args(picker_arguments(mode, title.as_deref(), default_name.as_deref()))
            .output()
            .map_err(|_| "Could not start the macOS picker.".to_owned())?;
        parse_picker_output(output.status.success(), &output.stdout, &output.stderr)
    })
    .await
}

#[tauri::command]
pub(crate) async fn desktop_pick_directory(
    handoff: tauri::State<'_, DesktopHandoff>,
    title: Option<String>,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        pick_path(handoff.picker_program.clone(), PickerMode::Directory, title, None).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (handoff, title);
        Err("The native folder picker is available on macOS.".into())
    }
}

#[tauri::command]
pub(crate) async fn desktop_pick_file(
    handoff: tauri::State<'_, DesktopHandoff>,
    title: Option<String>,
    save: Option<bool>,
    default_name: Option<String>,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        let mode = if save == Some(true) { PickerMode::Save } else { PickerMode::File };
        pick_path(handoff.picker_program.clone(), mode, title, default_name).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (handoff, title, save, default_name);
        Err("The native file picker is available on macOS.".into())
    }
}

fn execute_cli(executable: &Path, plan: &CliPlan, timeout: Duration) -> Result<(), String> {
    if !executable_file(executable) {
        return Err(
            "The Locket executable is missing or is not executable. Reinstall Locket CLI.".into()
        );
    }
    // CLI output may include init/recovery material or malformed user input. Keep
    // it out of logs and IPC entirely; this action returns only process status.
    let mut command = Command::new(executable);
    // A development desktop must never drive the installed vault, even
    // through a release-built CLI.
    if LocketInstance::current() == LocketInstance::Dev {
        command.env(INSTANCE_ENV, LocketInstance::Dev.label());
    }
    let mut child = command
        .args(&plan.args)
        .current_dir(&plan.cwd)
        .stdin(if plan.input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| {
            "Cannot launch Locket CLI. Check its installation and permissions.".to_string()
        })?;
    let (sender, receiver) = std::sync::mpsc::channel();
    if let Some(input) = plan.input.clone()
        && let Some(mut stdin) = child.stdin.take()
    {
        std::thread::spawn(move || {
            let result = stdin.write_all(&input);
            drop(stdin);
            let _ = sender.send(result);
        });
    }
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(cli_failure_guidance(
                        plan.args.first().map_or("action", String::as_str),
                        &status.to_string(),
                    ));
                }
                if plan.input.is_some()
                    && !matches!(receiver.recv_timeout(Duration::from_millis(250)), Ok(Ok(())))
                {
                    return Err("Locket CLI did not accept the complete policy request.".into());
                }
                return Ok(());
            }
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Locket CLI timed out. Retry in a terminal if an interactive prompt is required.".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Cannot wait for Locket CLI to finish.".into());
            }
        }
    }
}

fn posix_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(any(target_os = "macos", test))]
fn terminal_script(cli: &Path, root: &Path, args: &[&str]) -> String {
    format!("#!/bin/sh\n/bin/rm -- \"$0\"\n{}", terminal_command_script(cli, root, args))
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn terminal_command_script(cli: &Path, root: &Path, args: &[&str]) -> String {
    terminal_command_script_for(LocketInstance::current(), cli, root, args)
}

// Terminal applications do not reliably pass the desktop's environment to the
// command, so a development desktop names its instance in the command itself.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn terminal_command_script_for(
    instance: LocketInstance,
    cli: &Path,
    root: &Path,
    args: &[&str],
) -> String {
    let instance_line = match instance {
        LocketInstance::Installed => String::new(),
        LocketInstance::Dev => format!("export {INSTANCE_ENV}={}\n", posix_quote(instance.label())),
    };
    let command = format!(
        "{} {}",
        posix_quote(&cli.to_string_lossy()),
        args.iter().map(|arg| posix_quote(arg)).collect::<Vec<_>>().join(" ")
    );
    let root = posix_quote(&root.to_string_lossy());
    if args.first() == Some(&"scan") {
        format!(
            "{instance_line}cd -- {root} && {command}\nscan_status=$?\nprintf '\\nScan finished (exit %s). Press Enter to close.\\n' \"$scan_status\"\nIFS= read -r scan_dismiss\nexit \"$scan_status\"\n"
        )
    } else {
        format!("{instance_line}cd -- {root} || exit 1\n{command}\n")
    }
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn posix_terminal_command(cli: &Path, root: &Path, args: &[&str]) -> Vec<std::ffi::OsString> {
    posix_terminal_command_for(LocketInstance::current(), cli, root, args)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn posix_terminal_command_for(
    instance: LocketInstance,
    cli: &Path,
    root: &Path,
    args: &[&str],
) -> Vec<std::ffi::OsString> {
    if args.first() == Some(&"scan") {
        return vec![
            "/bin/sh".into(),
            "-c".into(),
            terminal_command_script_for(instance, cli, root, args).into(),
        ];
    }
    let instance_prefix = match instance {
        LocketInstance::Installed => Vec::new(),
        LocketInstance::Dev => {
            vec!["/usr/bin/env".into(), format!("{INSTANCE_ENV}={}", instance.label()).into()]
        }
    };
    instance_prefix
        .into_iter()
        .chain(std::iter::once(cli.as_os_str().to_owned()))
        .chain(args.iter().map(Into::into))
        .collect()
}

#[cfg(target_os = "macos")]
fn launch_terminal(cli: &Path, root: &Path, args: &[&str]) -> Result<(), String> {
    launch_macos_terminal(
        cli,
        root,
        args,
        |plan| execute_cli(Path::new("/usr/bin/open"), plan, Duration::from_secs(10)),
        |path| {
            // Terminal normally removes the script when it opens. Reap
            // abandoned launchers too, including when Terminal declines the file.
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(300));
                let _ = fs::remove_file(path);
            });
        },
    )
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn launch_macos_terminal(
    cli: &Path,
    root: &Path,
    args: &[&str],
    open: impl FnOnce(&CliPlan) -> Result<(), String>,
    expire: impl FnOnce(PathBuf),
) -> Result<(), String> {
    let file = write_terminal_launcher(cli, root, args)?;
    let (_handle, path) = file.keep().map_err(metadata_error)?;
    let result = open(&CliPlan {
        cwd: root.into(),
        args: vec!["-a".into(), "Terminal".into(), path.to_string_lossy().into_owned()],
        input: None,
    });
    if result.is_err() {
        let _ = fs::remove_file(&path);
        return Err("Cannot open Terminal. Check that Terminal is installed and try again.".into());
    }
    expire(path);
    Ok(())
}

#[cfg(target_os = "linux")]
fn launch_terminal(cli: &Path, root: &Path, args: &[&str]) -> Result<(), String> {
    for (terminal, separator) in [("gnome-terminal", "--"), ("konsole", "-e"), ("xterm", "-e")] {
        let Some(path) = std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .filter(|path| path.is_absolute())
                .map(|path| path.join(terminal))
                .find(|path| executable_file(path))
        }) else {
            continue;
        };
        let mut command = Command::new(path);
        command.current_dir(root);
        match terminal {
            "gnome-terminal" => {
                command.arg("--working-directory").arg(root);
            }
            "konsole" => {
                command.arg("--workdir").arg(root);
            }
            _ => {}
        }
        let mut child = command
            .arg(separator)
            .args(posix_terminal_command(cli, root, args))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "Cannot launch the terminal application.".to_string())?;
        std::thread::sleep(Duration::from_millis(200));
        if child.try_wait().map_err(metadata_error)?.is_some_and(|status| !status.success()) {
            return Err(
                "The terminal application rejected the command. Install a working terminal.".into(),
            );
        }
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        return Ok(());
    }
    Err("Install gnome-terminal, konsole, or xterm to run an interactive command.".into())
}

#[cfg(target_os = "windows")]
fn launch_terminal(cli: &Path, root: &Path, args: &[&str]) -> Result<(), String> {
    let terminal = std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .filter(|path| path.is_absolute())
                .map(|path| path.join("wt.exe"))
                .find(|path| executable_file(path))
        })
        .ok_or_else(|| "Install Windows Terminal to run an interactive command.".to_string())?;
    execute_cli(
        &terminal,
        &CliPlan { cwd: root.into(), args: windows_terminal_args(cli, root, args), input: None },
        Duration::from_secs(10),
    )
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn launch_terminal(_: &Path, _: &Path, _: &[&str]) -> Result<(), String> {
    Err("Interactive launch is unsupported on this platform. Use the Locket CLI in a terminal."
        .into())
}

async fn blocking<T: Send + 'static>(
    action: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(action)
        .await
        .map_err(|_| "Desktop action failed unexpectedly.".to_string())?
}

async fn set_agent_context(context: &DesktopProjectContext) -> Result<(), String> {
    let Some(root) = context.project_root() else {
        return Ok(());
    };
    let request = locket_agent::SetActiveProfileRequest {
        // The existing agent RPC expects locket.toml, despite its generic name.
        config_path: root.join("locket.toml"),
        store_path: super::default_store_path().map_err(|error| error.to_string())?,
        project_id: context.project_id.clone(),
        profile_name: context.profile_name.clone(),
        confirmation: None,
        privacy_redact_names: false,
        root_hash: Some(root_hash(root).iter().map(|byte| format!("{byte:02x}")).collect()),
    };
    let result: Result<locket_agent::SetActiveProfileResponse, _> = super::invoke_method(
        &super::resolve_socket_path(),
        locket_agent::AgentMethod::SetActiveProfile,
        &request,
    )
    .await;
    match result {
        Ok(_) | Err(super::AgentClientError::Unavailable { .. }) => Ok(()),
        // Metadata browsing must work while locked. No grant or unlock is made.
        Err(super::AgentClientError::Rejected { code, .. }) if code == "UnlockRequired" => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

#[tauri::command]
pub(crate) async fn desktop_list_projects() -> Result<Vec<DesktopProjectContext>, String> {
    let store = super::default_store_path().map_err(|error| error.to_string())?;
    blocking(move || list_projects_at(&store)).await
}
#[tauri::command]
pub(crate) async fn desktop_open_project(
    request: DesktopPathRequest,
) -> Result<DesktopProjectContext, String> {
    let store = super::default_store_path().map_err(|error| error.to_string())?;
    let context = blocking(move || open_project_at(&store, &request.path)).await?;
    set_agent_context(&context).await?;
    *SELECTED_PROJECT.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(context.clone());
    Ok(context)
}
#[tauri::command]
pub(crate) async fn desktop_open_shared_vault(
    request: Option<DesktopOpenSharedVaultRequest>,
) -> Result<DesktopProjectContext, String> {
    let store = super::default_store_path().map_err(|error| error.to_string())?;
    let project_id = request.and_then(|req| req.project_id);
    let context = blocking(move || {
        open_shared_vault_at(&store, project_id.as_deref(), || {
            let plan = shared_init_plan()?;
            execute_cli(&resolve_cli()?, &plan, CHILD_TIMEOUT).map_err(|error| {
                format!("{error} Initializing the Global Vault needs OS keychain access.")
            })
        })
    })
    .await?;
    *SELECTED_PROJECT.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(context.clone());
    Ok(context)
}
#[tauri::command]
pub(crate) async fn desktop_inspect_project_folder(
    request: DesktopPathRequest,
) -> Result<DesktopFolderInspection, String> {
    blocking(move || inspect_project_folder_at(&request.path)).await
}
#[tauri::command]
pub(crate) async fn desktop_initialize_project(
    request: DesktopPathRequest,
) -> Result<DesktopProjectContext, String> {
    let store = super::default_store_path().map_err(|error| error.to_string())?;
    let context = blocking(move || {
        let plan = initialize_plan(&request.path)?;
        execute_cli(&resolve_cli()?, &plan, CHILD_TIMEOUT).map_err(|error| format!("{error} Desktop initialization needs OS keychain access. For passphrase fallback, run `locket init` in this folder's terminal."))?;
        open_project_at(&store, &plan.cwd)
    }).await?;
    set_agent_context(&context).await?;
    *SELECTED_PROJECT.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(context.clone());
    Ok(context)
}
#[tauri::command]
pub(crate) async fn desktop_import_env(
    request: DesktopImportEnvRequest,
) -> Result<DesktopImportSummary, String> {
    let store = super::default_store_path().map_err(|error| error.to_string())?;
    let context = project_context(&store, &request.project_id)?;
    let payload = import_env_payload(&store, &context, request)?;
    let result: locket_agent::ImportDotenvResponse = invoke_granted(
        locket_agent::AgentMethod::ImportDotenv,
        locket_agent::GrantAction::ImportDotenv,
        payload,
        &store,
        &context.project_id,
        &context.profile_id,
    )
    .await
    .map_err(|error| error.to_string())?;
    let mut summary = format!(
        "Imported {}, overwritten {}, skipped {}. Original file preserved.",
        result.imported, result.overwritten, result.skipped
    );
    if let Some(warning) = result.maintenance_warning {
        summary.push(' ');
        summary.push_str(&warning);
    }
    Ok(DesktopImportSummary { summary })
}

fn import_env_payload(
    store: &Path,
    context: &DesktopProjectContext,
    request: DesktopImportEnvRequest,
) -> Result<serde_json::Value, String> {
    if context.is_shared && !request.path.is_absolute() {
        return Err("Choose an absolute env file path when importing into the Global Vault.".into());
    }
    Ok(serde_json::json!({
        "store_path": store, "project_root": context.root, "project_id": context.project_id,
        "profile_id": context.profile_id, "env_path": request.path,
        "overwrite": request.overwrite, "literal": request.literal, "confirmation": request.confirmation,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DesktopCreateProfileRequest {
    project_id: String,
    profile_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DesktopDeleteSecretRequest {
    project_id: String,
    profile_id: String,
    secret_name: String,
    source: String,
    confirmation: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DesktopCopySecretToSharedRequest {
    from_project_id: String,
    from_profile_id: String,
    secret_name: String,
    source: Option<String>,
    #[serde(default)]
    overwrite: bool,
    confirmation: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DesktopDetectCommandsRequest {
    project_id: String,
}

#[tauri::command]
pub(crate) async fn desktop_create_profile(
    request: DesktopCreateProfileRequest,
) -> Result<CreateProfileResponse, AgentClientError> {
    let store = super::default_store_path()?;
    let context = granted_project_context(&store, &request.project_id, None)?;
    if context.project_root().is_none() {
        return Err(AgentClientError::Protocol {
            reason: "Creating an environment requires a trusted project folder.".into(),
        });
    }
    let payload = desktop_crud_payload(
        &store,
        &context,
        serde_json::json!({
            "profile_name": request.profile_name,
        }),
    );
    invoke_granted_at(
        &super::resolve_socket_path(),
        AgentMethod::CreateProfile,
        GrantAction::CreateProfile,
        payload,
        &store,
        &context,
    )
    .await
}

#[tauri::command]
pub(crate) async fn desktop_delete_secret(
    request: DesktopDeleteSecretRequest,
) -> Result<DeleteSecretResponse, AgentClientError> {
    let store = super::default_store_path()?;
    let context = granted_project_context(&store, &request.project_id, Some(&request.profile_id))?;
    let payload = delete_secret_payload(&store, &context, request);
    invoke_granted_at(
        &super::resolve_socket_path(),
        AgentMethod::DeleteSecret,
        GrantAction::DeleteSecret,
        payload,
        &store,
        &context,
    )
    .await
}

#[tauri::command]
pub(crate) async fn desktop_copy_secret_to_shared(
    request: DesktopCopySecretToSharedRequest,
) -> Result<CopySecretToSharedResponse, AgentClientError> {
    let store = super::default_store_path()?;
    let context =
        granted_project_context(&store, &request.from_project_id, Some(&request.from_profile_id))?;
    let payload = copy_to_shared_payload(&store, &context, request);
    invoke_granted_at(
        &super::resolve_socket_path(),
        AgentMethod::CopySecretToShared,
        GrantAction::CopySecretToShared,
        payload,
        &store,
        &context,
    )
    .await
    .map_err(|mut error| {
        if let AgentClientError::Rejected { code, message, display_reason, .. } = &mut error
            && code == "UnlockRequired"
        {
            display_reason.clone_from(message);
        }
        error
    })
}

fn delete_secret_payload(
    store: &Path,
    context: &DesktopProjectContext,
    request: DesktopDeleteSecretRequest,
) -> serde_json::Value {
    desktop_crud_payload(
        store,
        context,
        serde_json::json!({
            "secret_name": request.secret_name,
            "source": request.source,
            "confirmation": request.confirmation,
        }),
    )
}

fn copy_to_shared_payload(
    store: &Path,
    context: &DesktopProjectContext,
    request: DesktopCopySecretToSharedRequest,
) -> serde_json::Value {
    desktop_crud_payload(
        store,
        context,
        serde_json::json!({
            "secret_name": request.secret_name,
            "source": request.source,
            "overwrite": request.overwrite,
            "confirmation": request.confirmation,
        }),
    )
}

fn desktop_crud_payload(
    store: &Path,
    context: &DesktopProjectContext,
    mut fields: serde_json::Value,
) -> serde_json::Value {
    fields["store_path"] = serde_json::json!(store);
    fields["project_root"] = serde_json::json!(context.root);
    fields["project_id"] = serde_json::json!(context.project_id);
    fields["profile_id"] = serde_json::json!(context.profile_id);
    fields
}

#[tauri::command]
pub(crate) async fn desktop_detect_commands(
    request: DesktopDetectCommandsRequest,
) -> Result<Vec<DetectedCommand>, String> {
    let store = super::default_store_path().map_err(|error| error.to_string())?;
    blocking(move || {
        if is_shared_project_id(&request.project_id) {
            return Err("The Global Vault has no project folder for command detection.".into());
        }
        let context = granted_project_context(&store, &request.project_id, None)
            .map_err(|error| error.to_string())?;
        detect_commands_for_context(&context)
    })
    .await
}

fn detect_commands_for_context(
    context: &DesktopProjectContext,
) -> Result<Vec<DetectedCommand>, String> {
    let root = context
        .project_root()
        .ok_or_else(|| "Command detection requires a trusted project folder.".to_string())?;
    command_detection::detect(root, &context.project_id)
}

#[tauri::command]
pub(crate) async fn desktop_start_agent(request: DesktopStartAgentRequest) -> Result<(), String> {
    let store = super::default_store_path().map_err(|error| error.to_string())?;
    blocking(move || {
        execute_cli(
            &resolve_cli()?,
            &start_plan(&store, request.project_id.as_deref())?,
            CHILD_TIMEOUT,
        )
    })
    .await
}
#[tauri::command]
pub(crate) async fn desktop_run_policy(
    handoff: tauri::State<'_, DesktopHandoff>,
    request: DesktopRunPolicyRequest,
) -> Result<DesktopRunResponse, String> {
    let store = super::default_store_path().map_err(|error| error.to_string())?;
    let launch = handoff.terminal;
    blocking(move || {
        let context = policy_context(&store, &request.project_id, &request.policy_name)?;
        let cli = resolve_cli()?;
        launch(&cli, Path::new(&context.root), &["run", &request.policy_name])?;
        Ok(DesktopRunResponse {
            launched: true,
            command: format!("locket run {}", posix_quote(&request.policy_name)),
        })
    })
    .await
}

// Only the native side chooses argv and resolves the trusted root and CLI. A
// terminal handoff says nothing about the scanner's outcome or findings.
fn scan_project_with(
    store: &Path,
    project_id: &str,
    resolve: impl FnOnce() -> Result<PathBuf, String>,
    launch: impl FnOnce(&Path, &Path, &[&str]) -> Result<(), String>,
) -> Result<DesktopRunResponse, String> {
    let context = project_context(store, project_id)?;
    let root = context.project_root().ok_or_else(|| {
        "Scanning requires a connected project folder with locket.toml.".to_string()
    })?;
    let cli = resolve()?;
    launch(&cli, root, &["scan", "--require-known"])?;
    Ok(DesktopRunResponse { launched: true, command: "locket scan --require-known".into() })
}

#[tauri::command]
pub(crate) async fn desktop_scan_project(
    handoff: tauri::State<'_, DesktopHandoff>,
    request: DesktopScanProjectRequest,
) -> Result<DesktopRunResponse, String> {
    let store = super::default_store_path().map_err(|error| error.to_string())?;
    let launch = handoff.terminal;
    blocking(move || scan_project_with(&store, &request.project_id, resolve_cli, launch)).await
}

#[tauri::command]
pub(crate) async fn desktop_save_policy(request: serde_json::Value) -> Result<(), String> {
    let store = super::default_store_path().map_err(|error| error.to_string())?;
    let project_id = request
        .get("project_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "A project id is required.".to_owned())?
        .to_owned();
    let context = project_context(&store, &project_id)?;
    let payload = save_policy_payload(&store, &context, request)?;
    let _: locket_agent::ApplyPolicyResponse = invoke_granted(
        locket_agent::AgentMethod::ApplyPolicy,
        locket_agent::GrantAction::ApplyPolicy,
        payload,
        &store,
        &project_id,
        &context.profile_id,
    )
    .await
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn save_policy_payload(
    store: &Path,
    context: &DesktopProjectContext,
    mut payload: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let root = context.project_root().ok_or_else(|| {
        "Saving commands requires a connected project folder with locket.toml.".to_string()
    })?;
    let object = payload.as_object_mut().ok_or_else(|| "Invalid policy request.".to_owned())?;
    object.insert("store_path".into(), serde_json::json!(store));
    object.insert("project_root".into(), serde_json::json!(root));
    object.insert("profile_id".into(), serde_json::json!(context.profile_id));
    Ok(payload)
}

#[cfg(test)]
#[path = "desktop_action_tests.rs"]
mod action_tests;

fn scoped_status(
    mut status: locket_agent::StatusPayload,
    context: &DesktopProjectContext,
) -> Result<locket_agent::StatusPayload, String> {
    if status.project_id.as_deref() != Some(context.project_id.as_str()) {
        return Err("Agent status did not match the selected project. Restart the agent after updating Locket.".into());
    }
    status.profile_name = Some(context.profile_name.clone());
    Ok(status)
}
#[cfg(any(target_os = "windows", test))]
fn windows_terminal_args(cli: &Path, root: &Path, args: &[&str]) -> Vec<String> {
    use base64::Engine as _;
    fn quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }
    let ending = if args.first() == Some(&"scan") {
        "$scanExit = $LASTEXITCODE; Read-Host \"Scan finished (exit $scanExit). Press Enter to close\" | Out-Null; exit $scanExit"
    } else {
        "exit $LASTEXITCODE"
    };
    let instance = match LocketInstance::current() {
        LocketInstance::Installed => String::new(),
        LocketInstance::Dev => {
            format!("$env:{INSTANCE_ENV} = {}; ", quote(LocketInstance::Dev.label()))
        }
    };
    let script = format!(
        "{instance}Set-Location -LiteralPath {} -ErrorAction Stop; & {} {}; {ending}",
        quote(&root.to_string_lossy()),
        quote(&cli.to_string_lossy()),
        args.iter().map(|arg| quote(arg)).collect::<Vec<_>>().join(" ")
    );
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    vec![
        "-w".into(),
        "new".into(),
        "new-tab".into(),
        "powershell.exe".into(),
        "-NoProfile".into(),
        "-NoExit".into(),
        "-EncodedCommand".into(),
        base64::engine::general_purpose::STANDARD.encode(bytes),
    ]
}
#[cfg(any(target_os = "macos", all(test, unix)))]
fn write_terminal_launcher(
    cli: &Path,
    root: &Path,
    args: &[&str],
) -> Result<tempfile::NamedTempFile, String> {
    use std::os::unix::fs::PermissionsExt;
    let mut file = tempfile::Builder::new()
        .prefix("locket-terminal-")
        .suffix(".command")
        .tempfile()
        .map_err(|_| "Cannot create the scoped Terminal launcher.".to_string())?;
    file.write_all(terminal_script(cli, root, args).as_bytes()).map_err(metadata_error)?;
    file.as_file().set_permissions(fs::Permissions::from_mode(0o700)).map_err(metadata_error)?;
    file.as_file().sync_all().map_err(metadata_error)?;
    Ok(file)
}

pub(crate) async fn selected_agent_status(
    socket: &Path,
) -> Result<locket_agent::StatusPayload, super::AgentClientError> {
    let selected =
        SELECTED_PROJECT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    let Some(selected) = selected else {
        return super::fetch_status(socket).await;
    };
    let store = super::default_store_path()?;
    let context = blocking(move || {
        project_context_with_selection(&store, &selected.project_id, Some(&selected))
    })
    .await
    .map_err(|reason| super::AgentClientError::Protocol { reason })?;
    fetch_context_status(socket, &context).await
}
fn project_context_with_selection(
    store: &Path,
    id: &str,
    selected: Option<&DesktopProjectContext>,
) -> Result<DesktopProjectContext, String> {
    if let Some(selected) = selected.filter(|selected| selected.project_id == id) {
        let refreshed = refresh_context_at(store, selected)?;
        if refreshed.project_id != id {
            return Err("The selected folder now belongs to another project. Open it again.".into());
        }
        return Ok(refreshed);
    }
    if is_shared_project_id(id) {
        return find_shared_vault_at(store, Some(id), None)?
            .ok_or_else(|| "Global Vault is not registered in this store.".into());
    }
    let mut matches =
        list_projects_at(store)?.into_iter().filter(|context| context.project_id == id);
    let first = matches.next().ok_or_else(|| {
        "No trusted local folder is registered for this project. Open the project first."
            .to_string()
    })?;
    if matches.next().is_some() {
        return Err(
            "Multiple trusted folders use this project id. Open the intended project folder first."
                .into(),
        );
    }
    Ok(first)
}

pub(crate) fn project_config_path(store: &Path, id: &str) -> Result<PathBuf, String> {
    let context = project_context(store, id)?;
    context
        .project_root()
        .map(|root| root.join("locket.toml"))
        .ok_or_else(|| "Environments require a connected project folder with locket.toml.".into())
}
async fn fetch_context_status(
    socket: &Path,
    context: &DesktopProjectContext,
) -> Result<locket_agent::StatusPayload, super::AgentClientError> {
    let payload = serde_json::json!({"project_id": context.project_id});
    let status = super::invoke_method(socket, locket_agent::AgentMethod::Status, &payload).await?;
    scoped_status(status, context).map_err(|reason| super::AgentClientError::Protocol { reason })
}

fn cli_failure_guidance(operation: &str, status: &str) -> String {
    format!(
        "Locket CLI failed during {operation} ({status}). Check that the matching CLI release is installed and this project can be initialized or started."
    )
}

/// Obtain the actual native process binding. Never accept an identity from the webview.
pub(crate) fn native_binding() -> Result<locket_agent::GrantBinding, super::AgentClientError> {
    let binding = locket_platform::current_process_binding().map_err(|_| {
        super::AgentClientError::Protocol { reason: "Cannot identify the native process.".into() }
    })?;
    Ok(locket_agent::GrantBinding::new(binding.pid, binding.process_start_time))
}

/// Resolve selected project metadata and authorize exactly one native user action.
pub(crate) async fn invoke_granted<R: serde::de::DeserializeOwned>(
    method: locket_agent::AgentMethod,
    action: locket_agent::GrantAction,
    payload: impl GrantPayload,
    store: &Path,
    project_id: &str,
    profile_id: &str,
) -> Result<R, super::AgentClientError> {
    let context = granted_project_context(store, project_id, Some(profile_id))?;
    invoke_granted_at(&super::resolve_socket_path(), method, action, payload, store, &context).await
}

fn granted_project_context(
    store: &Path,
    project_id: &str,
    profile_id: Option<&str>,
) -> Result<DesktopProjectContext, super::AgentClientError> {
    let selected =
        SELECTED_PROJECT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    if selected.as_ref().is_some_and(|selected| selected.project_id != project_id) {
        return Err(super::AgentClientError::Protocol {
            reason: "The selected project changed. Refresh before retrying.".into(),
        });
    }
    let context = project_context_with_selection(store, project_id, selected.as_ref())
        .map_err(|reason| super::AgentClientError::Protocol { reason })?;
    if profile_id.is_some_and(|profile_id| context.profile_id != profile_id) {
        return Err(super::AgentClientError::Protocol {
            reason: "The active profile changed. Refresh before retrying.".into(),
        });
    }
    Ok(context)
}

pub(crate) async fn export_bundle(
    store: &Path,
    mut request: locket_agent::ExportBundleRequest,
) -> Result<locket_agent::BackupActionResponse, super::AgentClientError> {
    let context =
        granted_project_context(store, &request.project_id, request.profile_id.as_deref())?;
    request.profile_id = Some(context.profile_id.clone());
    invoke_granted_at(
        &super::resolve_socket_path(),
        locket_agent::AgentMethod::ExportBundle,
        locket_agent::GrantAction::Export,
        request,
        store,
        &context,
    )
    .await
}

pub(crate) async fn import_bundle(
    store: &Path,
    request: locket_agent::ImportBundleRequest,
) -> Result<locket_agent::BackupActionResponse, super::AgentClientError> {
    let context = granted_project_context(store, &request.project_id, None)?;
    invoke_granted_at(
        &super::resolve_socket_path(),
        locket_agent::AgentMethod::ImportBundle,
        locket_agent::GrantAction::ImportDotenv,
        request,
        store,
        &context,
    )
    .await
}

pub(crate) trait GrantPayload: serde::Serialize {
    fn confirms_dangerous(&self, _profile_name: &str) -> bool {
        false
    }

    fn grant_profile_id<'a>(&self, active_profile: &'a str) -> &'a str {
        active_profile
    }

    fn authorize(
        &mut self,
        grant: &locket_agent::GrantIdPayload,
        binding: locket_agent::GrantBinding,
    );
}

impl GrantPayload for locket_agent::ExportBundleRequest {
    fn confirms_dangerous(&self, _profile_name: &str) -> bool {
        self.confirm_dangerous
    }

    fn grant_profile_id<'a>(&self, active_profile: &'a str) -> &'a str {
        match self.scope {
            locket_agent::BundleExportScope::ActiveProfile => active_profile,
            locket_agent::BundleExportScope::AllProfiles => {
                locket_agent::BUNDLE_PROJECT_GRANT_SCOPE
            }
        }
    }

    fn authorize(
        &mut self,
        grant: &locket_agent::GrantIdPayload,
        binding: locket_agent::GrantBinding,
    ) {
        self.grant_id = Some(grant.grant_id.clone());
        self.binding = Some(binding);
    }
}

impl GrantPayload for locket_agent::ImportBundleRequest {
    fn confirms_dangerous(&self, _profile_name: &str) -> bool {
        self.confirm_dangerous
    }

    fn grant_profile_id<'a>(&self, _active_profile: &'a str) -> &'a str {
        locket_agent::BUNDLE_PROJECT_GRANT_SCOPE
    }

    fn authorize(
        &mut self,
        grant: &locket_agent::GrantIdPayload,
        binding: locket_agent::GrantBinding,
    ) {
        self.grant_id = Some(grant.grant_id.clone());
        self.binding = Some(binding);
    }
}

impl GrantPayload for serde_json::Value {
    fn confirms_dangerous(&self, profile_name: &str) -> bool {
        self.get("confirmation").and_then(serde_json::Value::as_str) == Some(profile_name)
            || self.get("confirm_dangerous").and_then(serde_json::Value::as_bool) == Some(true)
    }

    fn authorize(
        &mut self,
        grant: &locket_agent::GrantIdPayload,
        binding: locket_agent::GrantBinding,
    ) {
        self["grant_id"] = serde_json::json!(grant.grant_id);
        self["binding"] = serde_json::json!(binding);
    }
}

async fn invoke_granted_at<R: serde::de::DeserializeOwned>(
    socket: &Path,
    method: locket_agent::AgentMethod,
    action: locket_agent::GrantAction,
    mut payload: impl GrantPayload,
    store: &Path,
    context: &DesktopProjectContext,
) -> Result<R, super::AgentClientError> {
    let project_id = context.project_id.as_str();
    let profile_id = payload.grant_profile_id(&context.profile_id);
    let binding = native_binding()?;
    let grant: locket_agent::GrantIdPayload = super::invoke_method(
        socket,
        locket_agent::AgentMethod::RequestGrant,
        &locket_agent::RequestGrantPayload {
            project_id: project_id.into(),
            profile_id: profile_id.into(),
            policy_name: None,
            action,
            confirm_dangerous: payload.confirms_dangerous(&context.profile_name),
            ttl_seconds: 30,
            binding: binding.clone(),
        },
    )
    .await?;
    let fresh = refresh_context_at(store, context);
    if fresh.as_ref() != Ok(context) {
        let _: Result<serde_json::Value, _> =
            super::invoke_method(socket, locket_agent::AgentMethod::RevokeGrant, &grant).await;
        return Err(super::AgentClientError::Protocol {
            reason: fresh.err().unwrap_or_else(|| {
                "Project metadata changed before authorization. Refresh and retry.".into()
            }),
        });
    }
    payload.authorize(&grant, binding);
    let result = super::invoke_method(socket, method, &payload).await;
    // The grant belongs only to this explicit user action, including a failed action.
    let _: Result<serde_json::Value, _> =
        super::invoke_method(socket, locket_agent::AgentMethod::RevokeGrant, &grant).await;
    result
}

pub(crate) fn selected_project_id() -> Result<String, super::AgentClientError> {
    SELECTED_PROJECT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map(|context| context.project_id.clone())
        .ok_or_else(|| super::AgentClientError::Protocol {
            reason: "Open a trusted project before requesting secret access.".into(),
        })
}

#[derive(Deserialize)]
pub(crate) struct DesktopReadinessRequest {
    project_id: String,
    policy_name: Option<String>,
}
#[derive(Serialize)]
pub(crate) struct DesktopPolicyReadiness {
    policy_name: String,
    profile_id: String,
    rows: Vec<locket_core::VariableReadinessRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}
#[derive(Serialize)]
pub(crate) struct DesktopReadinessResponse {
    project_id: String,
    profile_id: String,
    profile_name: String,
    policies: Vec<DesktopPolicyReadiness>,
}
fn variable_readiness_at(
    store_path: &Path,
    request: &DesktopReadinessRequest,
) -> Result<DesktopReadinessResponse, String> {
    let context = project_context(store_path, &request.project_id)?;
    let Some(root) = context.project_root() else {
        return Ok(DesktopReadinessResponse {
            project_id: context.project_id,
            profile_id: context.profile_id,
            profile_name: context.profile_name,
            policies: Vec::new(),
        });
    };
    // Desktop Run starts at the selected trusted root. Cwd is native-owned,
    // never accepted from the webview or inherited from the app process.
    variable_readiness_for_context(store_path, request, &context, root)
}

fn variable_readiness_for_context(
    store_path: &Path,
    request: &DesktopReadinessRequest,
    context: &DesktopProjectContext,
    cwd: &Path,
) -> Result<DesktopReadinessResponse, String> {
    let root = Path::new(&context.root).canonicalize().map_err(metadata_error)?;
    let cwd = cwd.canonicalize().map_err(metadata_error)?;
    if !cwd.is_dir() || !cwd.starts_with(&root) {
        return Err("Command directory is outside the selected trusted project.".into());
    }
    let relative = cwd.strip_prefix(&root).map_err(metadata_error)?;
    let relative_cwd = if relative.as_os_str().is_empty() { Path::new(".") } else { relative };
    let text = fs::read_to_string(root.join("locket.toml")).map_err(metadata_error)?;
    let document = locket_core::PolicyDocument::from_toml_str(&text).map_err(metadata_error)?;
    let store = Store::open(store_path).map_err(metadata_error)?;
    let scope = document.path_scope_for(&root, &cwd);
    let profile_id = if let Some(name) = scope.and_then(|scope| scope.profile.as_ref()) {
        store
            .get_profile_by_name(&context.project_id, name.as_str())
            .map_err(metadata_error)?
            .ok_or_else(|| "The scoped profile is missing.".to_owned())?
            .id
    } else {
        context.profile_id.clone()
    };
    let mut available = std::collections::BTreeMap::new();
    // Query contains names/source labels only. It never fetches ciphertext or values.
    for secret in store
        .list_active_secret_metadata_by_profile(&context.project_id, &profile_id)
        .map_err(metadata_error)?
    {
        available.entry(secret.name).or_insert(secret.source);
    }
    if request.policy_name.as_ref().is_some_and(|name| !document.commands.contains_key(name)) {
        return Err("The selected command no longer exists. Refresh commands.".into());
    }
    let mut policies = Vec::new();
    for base in document
        .commands
        .values()
        .filter(|policy| request.policy_name.as_ref().is_none_or(|name| policy.name == *name))
    {
        let mut policy = base.clone();
        if let Some(scope) = scope {
            for name in &scope.required_secrets {
                if !policy.required_secrets.contains(name) {
                    policy.required_secrets.push(name.clone());
                }
                policy.optional_secrets.retain(|optional| optional != name);
            }
            for name in &scope.optional_secrets {
                if !policy.required_secrets.contains(name)
                    && !policy.optional_secrets.contains(name)
                {
                    policy.optional_secrets.push(name.clone());
                }
            }
            policy.allowed_secrets =
                policy.required_secrets.iter().chain(&policy.optional_secrets).cloned().collect();
        }
        let argv = match &policy.command {
            locket_core::CommandSpec::Argv(argv) => Some(argv.as_slice()),
            locket_core::CommandSpec::Shell(_) => None,
        };
        if policy.allowed_secrets.iter().any(|name| {
            document
                .secret_access
                .get(name.as_str())
                .is_some_and(|acl| !acl.allows(&policy.name, argv, relative_cwd))
        }) {
            policies.push(DesktopPolicyReadiness {
                policy_name: policy.name,
                profile_id: profile_id.clone(),
                rows: Vec::new(),
                error: Some("Command variable access is denied by its configured rules.".into()),
            });
            continue;
        }
        let deferred = !policy.external_env_sources.is_empty()
            || !policy.inherit_env.is_empty()
            || matches!(
                policy.env_mode,
                locket_core::EnvMode::Merge | locket_core::EnvMode::Passthrough
            );
        let rows = document.variable_readiness(&policy, &available, deferred);
        policies.push(DesktopPolicyReadiness {
            policy_name: policy.name,
            profile_id: profile_id.clone(),
            rows,
            error: None,
        });
    }
    Ok(DesktopReadinessResponse {
        project_id: context.project_id.clone(),
        profile_id: context.profile_id.clone(),
        profile_name: context.profile_name.clone(),
        policies,
    })
}

#[tauri::command]
pub(crate) async fn desktop_variable_readiness(
    request: DesktopReadinessRequest,
) -> Result<DesktopReadinessResponse, String> {
    let store = super::default_store_path().map_err(|error| error.to_string())?;
    blocking(move || variable_readiness_at(&store, &request)).await
}

#[derive(Deserialize)]
pub(crate) struct DesktopTeamSyncRequest {
    project_id: String,
    folder: Option<PathBuf>,
    #[serde(default)]
    allow_dangerous: bool,
    #[serde(default)]
    confirm_dangerous: bool,
}
async fn team_sync_request(
    request: DesktopTeamSyncRequest,
    method: locket_agent::AgentMethod,
) -> Result<serde_json::Value, super::AgentClientError> {
    let store = super::default_store_path()?;
    let context = project_context(&store, &request.project_id)
        .map_err(|reason| super::AgentClientError::Protocol { reason })?;
    let mut payload = serde_json::json!({"project_id": context.project_id, "profile_id": context.profile_id, "store_path": store});
    if method == locket_agent::AgentMethod::TeamSyncStatus {
        return super::invoke_method(&super::resolve_socket_path(), method, &payload).await;
    }
    if method == locket_agent::AgentMethod::TeamSyncConfigure {
        let folder = request.folder.ok_or_else(|| super::AgentClientError::Protocol {
            reason: "Choose a shared folder first.".into(),
        })?;
        payload["folder"] = serde_json::json!(folder);
        payload["allow_dangerous"] = serde_json::json!(request.allow_dangerous);
    }
    payload["confirm_dangerous"] = serde_json::json!(request.confirm_dangerous);
    invoke_granted(
        method,
        locket_agent::GrantAction::TeamSync,
        payload,
        &store,
        &context.project_id,
        &context.profile_id,
    )
    .await
}
#[tauri::command]
pub(crate) async fn desktop_team_sync_status(
    request: DesktopTeamSyncRequest,
) -> Result<serde_json::Value, super::AgentClientError> {
    team_sync_request(request, locket_agent::AgentMethod::TeamSyncStatus).await
}
#[tauri::command]
pub(crate) async fn desktop_team_sync_configure(
    request: DesktopTeamSyncRequest,
) -> Result<serde_json::Value, super::AgentClientError> {
    team_sync_request(request, locket_agent::AgentMethod::TeamSyncConfigure).await
}
#[tauri::command]
pub(crate) async fn desktop_team_sync_now(
    request: DesktopTeamSyncRequest,
) -> Result<serde_json::Value, super::AgentClientError> {
    team_sync_request(request, locket_agent::AgentMethod::TeamSyncNow).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DesktopRenameProfileRequest {
    project_id: String,
    incoming_profile_id: String,
    local_profile_id: String,
    new_name: String,
    #[serde(default)]
    confirm_dangerous: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DesktopPreserveOverrideRequest {
    project_id: String,
    incoming_profile_id: String,
    local_secret_id: String,
    #[serde(default)]
    confirm_dangerous: bool,
}

fn pending_reconcile_payload(
    context: &DesktopProjectContext,
    store: &Path,
    incoming_profile_id: String,
    action: locket_agent::TeamSyncAction,
) -> Result<serde_json::Value, super::AgentClientError> {
    serde_json::to_value(locket_agent::TeamSyncReconcileRequest {
        scope: locket_agent::TeamSyncRequest {
            project_id: context.project_id.clone(),
            store_path: Some(store.into()),
            profile_id: Some(context.profile_id.clone()),
            grant_id: None,
            binding: None,
        },
        incoming_profile_id,
        action,
    })
    .map_err(|_| super::AgentClientError::Protocol {
        reason: "Invalid pending profile resolution request.".into(),
    })
}

async fn reconcile_pending_profile(
    project_id: &str,
    incoming_profile_id: String,
    action: locket_agent::TeamSyncAction,
    confirm_dangerous: bool,
) -> Result<locket_agent::team_sync::SyncStatus, super::AgentClientError> {
    let store = super::default_store_path()?;
    let context = project_context(&store, project_id)
        .map_err(|reason| super::AgentClientError::Protocol { reason })?;
    let mut payload = pending_reconcile_payload(&context, &store, incoming_profile_id, action)?;
    payload["confirm_dangerous"] = serde_json::json!(confirm_dangerous);
    invoke_granted(
        locket_agent::AgentMethod::TeamSyncReconcile,
        locket_agent::GrantAction::TeamSync,
        payload,
        &store,
        &context.project_id,
        &context.profile_id,
    )
    .await
}

#[tauri::command]
pub(crate) async fn desktop_team_sync_rename_profile(
    request: DesktopRenameProfileRequest,
) -> Result<locket_agent::team_sync::SyncStatus, super::AgentClientError> {
    reconcile_pending_profile(
        &request.project_id,
        request.incoming_profile_id,
        locket_agent::TeamSyncAction::RenameProfile {
            local_profile_id: request.local_profile_id,
            new_name: request.new_name,
        },
        request.confirm_dangerous,
    )
    .await
}

#[tauri::command]
pub(crate) async fn desktop_team_sync_preserve_override(
    request: DesktopPreserveOverrideRequest,
) -> Result<locket_agent::team_sync::SyncStatus, super::AgentClientError> {
    reconcile_pending_profile(
        &request.project_id,
        request.incoming_profile_id,
        locket_agent::TeamSyncAction::PreserveOverride { local_secret_id: request.local_secret_id },
        request.confirm_dangerous,
    )
    .await
}
