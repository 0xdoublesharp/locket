//! Stdio MCP server for metadata queries and encrypted vault writes.

use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

use locket_agent::DiscoveryFilters;
use locket_core::{LocketError, PolicyDocument, SecretName};
use locket_crypto::KeyPurpose;
use locket_store::{AuditContext, AuditWrite, SecretMetadataUpdate, SecretRecord, Store};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::commands::discovery::{
    discover_rows, error_json, project_rows, read_metadata_store, require_metadata_store,
    select_project,
};
use crate::commands::project::detect::PolicyDetection;
use crate::commands::secrets::generate::{GenerateFormat, generate_value};
use crate::commands::secrets::import::{
    EnvImportOptions, InputDirectory, import_env_to_target, input_parent, inspect_open_env_file,
    open_scoped_file, scan_open_workspace,
};
use crate::commands::secrets::set::{
    SecretWriteKeys, WriteRequest, WriteTarget, confirm_write, validate_write_metadata, write_value,
};
use crate::runtime::error::{access_denied_error, typed_cli_error};
use crate::{
    CliError, LOCKET_TOML, PROJECT_CONFIG_SCHEMA_VERSION, ProjectConfig, RuntimeContext,
    SecretMetadataFlags, SecretSourceArg, load_project_key, metadata_invalid_error, now_unix_nanos,
    open_store, secret_deleted_error, secret_not_found_error, source_arg_to_str, source_precedence,
};

const MAX_INPUT_BYTES: u64 = 1_048_576;
const DEFAULT_ENV_SCAN_DEPTH: i64 = 5;
const MAX_ENV_SCAN_DEPTH: i64 = 10;
const ENV_PATH_SCOPE: &str =
    "dotenv path must be inside the working directory or a trusted project root";

pub fn serve(
    input: &mut impl BufRead,
    output: &mut impl Write,
    context: &RuntimeContext,
) -> Result<(), CliError> {
    let context = RuntimeContext { cwd: context.cwd.canonicalize()?, ..context.clone() };
    let mut frame = Zeroizing::new(Vec::new());
    loop {
        // Clear each frame before reading the next request, including reused buffer capacity.
        zeroize::Zeroize::zeroize(&mut *frame);
        let size = input.take(MAX_INPUT_BYTES + 1).read_until(b'\n', &mut frame)?;
        if size == 0 {
            return Ok(());
        }
        if size as u64 > MAX_INPUT_BYTES {
            send(output, &rpc_error(&Value::Null, -32600, "request exceeds size limit"))?;
            return Ok(());
        }
        let response = serde_json::from_slice(&frame).map_or_else(
            |_| Some(rpc_error(&Value::Null, -32700, "invalid JSON")),
            |message| dispatch(&context, message),
        );
        if let Some(response) = response {
            send(output, &response)?;
        }
    }
}

fn send(output: &mut impl Write, value: &Value) -> Result<(), CliError> {
    serde_json::to_writer(&mut *output, value)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

fn dispatch(context: &RuntimeContext, mut message: Value) -> Option<Value> {
    let id = message.get("id").cloned();
    if message["jsonrpc"] != "2.0"
        || message["method"].as_str().is_none()
        || id.as_ref().is_some_and(|id| !(id.is_null() || id.is_string() || id.is_number()))
    {
        return Some(rpc_error(&Value::Null, -32600, "invalid JSON-RPC request"));
    }
    let id = id?;
    let params = message["params"].take();
    let reply = match message["method"].as_str()? {
        "initialize" => {
            let protocol = match params["protocolVersion"].as_str() {
                Some("2025-03-26") => "2025-03-26",
                Some("2025-06-18") => "2025-06-18",
                Some("2025-11-25") => "2025-11-25",
                _ => "2024-11-05",
            };
            json!({
                "protocolVersion": protocol, "capabilities": {"tools": {}},
                "serverInfo": {"name": "locket", "version": env!("CARGO_PKG_VERSION")},
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools": tools()}),
        "tools/call" => {
            let mut params = params;
            let args = params.get_mut("arguments").map_or(Value::Null, Value::take);
            let Some(name) = params["name"].as_str() else {
                return Some(rpc_error(&id, -32602, "tool name required"));
            };
            // A new request must observe current keyring state.
            context.master_key_cache.clear();
            let response = call_tool(context, name, args);
            context.master_key_cache.clear();
            let (value, is_error) = match response {
                Ok(value) => (value, false),
                Err(error) => (error_json(&error), true),
            };
            json!({"content": [{"type": "text", "text": value.to_string()}], "isError": is_error})
        }
        _ => return Some(rpc_error(&id, -32601, "method not found")),
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": reply}))
}

fn rpc_error(id: &Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message }})
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    #[serde(default)]
    redact_names: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectArgs {
    project: String,
}

#[derive(Deserialize)]
struct SecretArgs {
    project: String,
    profile: Option<String>,
    name: String,
    source: Option<String>,
    confirm_dangerous_profile: Option<String>,
}

impl SecretArgs {
    fn target(&self, context: &RuntimeContext, store: &Store) -> Result<WriteTarget, CliError> {
        select_mcp_target(context, store, &self.project, self.profile.as_deref())
    }

    fn confirm(&self, target: &WriteTarget) -> Result<(), CliError> {
        confirm_write(
            &target.profile,
            self.confirm_dangerous_profile.as_deref() == Some(&target.profile.name),
            "supply the exact profile name in confirm_dangerous_profile",
        )
    }

    fn source(&self) -> Result<Option<SecretSourceArg>, CliError> {
        self.source.as_deref().map(parse_secret_source).transpose()
    }

    fn record(&self, store: &Store, target: &WriteTarget) -> Result<SecretRecord, CliError> {
        let name = SecretName::new(self.name.clone())
            .map_err(|_| crate::invalid_secret_name_error("invalid secret name"))?;
        let mut records =
            store.list_secrets_by_name(&target.project.id, &target.profile.id, name.as_str())?;
        if let Some(source) = self.source()? {
            records.retain(|record| record.source == source_arg_to_str(source));
        }
        if records.is_empty() {
            return Err(secret_not_found_error("secret not found"));
        }
        records
            .into_iter()
            .filter(|row| row.state == "active")
            .max_by_key(|row| source_precedence(&row.source))
            .ok_or_else(|| secret_deleted_error("secret source is deleted"))
    }
}

fn parse_secret_source(source: &str) -> Result<SecretSourceArg, CliError> {
    match source {
        "user-local" => Ok(SecretSourceArg::UserLocal),
        "machine-local" => Ok(SecretSourceArg::MachineLocal),
        "team-managed" => Ok(SecretSourceArg::TeamManaged),
        _ => Err(metadata_invalid_error("invalid secret source")),
    }
}

#[derive(Default, Deserialize)]
struct MetadataArgs {
    description: Option<String>,
    owner: Option<String>,
    tags: Option<Vec<String>>,
    required: Option<bool>,
}

impl MetadataArgs {
    fn flags(self) -> SecretMetadataFlags {
        SecretMetadataFlags {
            description: self.description,
            owner: self.owner,
            tags: self.tags.unwrap_or_default(),
            required: self.required == Some(true),
            optional: self.required == Some(false),
            ..SecretMetadataFlags::default()
        }
    }
}

#[derive(Deserialize)]
struct WriteArgs {
    #[serde(flatten)]
    secret: SecretArgs,
    #[serde(flatten)]
    metadata: MetadataArgs,
    #[serde(default)]
    upsert: bool,
    value_file: Option<String>,
    bytes: Option<u16>,
    #[serde(default)]
    format: GenerateFormat,
}

#[derive(Deserialize)]
struct UpdateArgs {
    #[serde(flatten)]
    secret: SecretArgs,
    #[serde(flatten)]
    metadata: MetadataArgs,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectEnvArgs {
    path: PathBuf,
    #[serde(default)]
    literal: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanEnvArgs {
    path: Option<PathBuf>,
    max_depth: Option<i64>,
    #[serde(default)]
    literal: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectCommandsArgs {
    path: Option<PathBuf>,
    project: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Independent MCP options.
struct ImportEnvArgs {
    project: String,
    path: PathBuf,
    profile: Option<String>,
    source: Option<String>,
    #[serde(default)]
    only: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    overwrite: bool,
    #[serde(default)]
    literal: bool,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    confirm_dangerous: bool,
}

fn args_as<T: DeserializeOwned>(args: Value) -> Result<T, CliError> {
    serde_json::from_value(if args.is_null() { json!({}) } else { args })
        .map_err(|_| metadata_invalid_error("invalid MCP tool arguments"))
}

fn call_tool(context: &RuntimeContext, name: &str, mut args: Value) -> Result<Value, CliError> {
    // Move the value into a zeroizing holder even if later argument validation fails.
    let value = match args.as_object_mut().and_then(|args| args.remove("value")) {
        Some(Value::String(value)) => Some(Zeroizing::new(value)),
        Some(_) => return Err(metadata_invalid_error("value must be a string")),
        None => None,
    };
    if value.is_some() && name != "locket_store_secret" {
        return Err(metadata_invalid_error("value is only accepted by the store tool"));
    }
    match name {
        "locket_list_projects" => project_rows(context, args_as::<ListArgs>(args)?.redact_names),
        "locket_discover_secrets" => discover_rows(context, args_as::<DiscoveryFilters>(args)?),
        "locket_get_secret_metadata" => get_secret_metadata(context, &args_as::<SecretArgs>(args)?),
        "locket_store_secret" | "locket_generate_secret" => store_secret(
            context,
            args_as::<WriteArgs>(args)?,
            value,
            name == "locket_generate_secret",
        ),
        "locket_update_secret_metadata" => update_metadata(context, args_as::<UpdateArgs>(args)?),
        "locket_list_project_policies" => {
            list_policies(context, &args_as::<ProjectArgs>(args)?.project)
        }
        "locket_inspect_env_keys" => inspect_env(context, &args_as::<InspectEnvArgs>(args)?),
        "locket_scan_env_files" => scan_env(context, &args_as::<ScanEnvArgs>(args)?),
        "locket_detect_commands" => detect_commands(context, args_as(args)?),
        "locket_import_env" => import_env(context, args_as::<ImportEnvArgs>(args)?),
        _ => Err(metadata_invalid_error("unknown MCP tool")),
    }
}

fn inspect_env(context: &RuntimeContext, args: &InspectEnvArgs) -> Result<Value, CliError> {
    let path = canonical_input_path(context, &args.path, InputPathKind::File("dotenv input"))?;
    require_workspace_path(context, input_parent(&path)?.0, None, ENV_PATH_SCOPE)?;
    inspect_open_env_file(open_scoped_file(&path)?, args.literal)
}

fn scan_env(context: &RuntimeContext, args: &ScanEnvArgs) -> Result<Value, CliError> {
    let path = args.path.as_deref().unwrap_or_else(|| Path::new("."));
    let root = canonical_input_path(
        context,
        path,
        InputPathKind::Directory("dotenv scan root must be a directory"),
    )?;
    require_workspace_path(context, &root, None, ENV_PATH_SCOPE)?;
    let directory = InputDirectory::open(&root)?;
    let max_depth = args.max_depth.unwrap_or(DEFAULT_ENV_SCAN_DEPTH).clamp(1, MAX_ENV_SCAN_DEPTH);
    scan_open_workspace(&directory, usize::try_from(max_depth).unwrap_or(5), args.literal)
}

fn detect_commands(context: &RuntimeContext, args: DetectCommandsArgs) -> Result<Value, CliError> {
    let (root, directory) = if let Some(selector) = args.project {
        if args.path.is_some() {
            return Err(metadata_invalid_error("supply either path or project"));
        }
        let store = require_metadata_store(context)?;
        let project = select_project(&store, &context.cwd, &selector)?;
        let resolved =
            trusted_mcp_configs(&store, &project.id)?.into_iter().next().ok_or_else(|| {
                typed_cli_error(
                    LocketError::ProjectRootUntrusted,
                    "project has no trusted workspace root",
                )
            })?;
        (resolved.root, resolved.directory)
    } else {
        let path = args.path.as_deref().unwrap_or_else(|| Path::new("."));
        let root = canonical_input_path(
            context,
            path,
            InputPathKind::Directory("command detection root must be a directory"),
        )?;
        require_workspace_path(
            context,
            &root,
            None,
            "command detection path must be inside the working directory or a trusted project root",
        )?;
        let directory = InputDirectory::open(&root)?;
        (root, directory)
    };
    let commands = detect_open_workspace(&directory)?;
    Ok(json!({"root": root.display().to_string(), "commands": commands, "metadata_only": true}))
}

fn read_workspace_manifest(
    directory: &InputDirectory,
    name: &str,
) -> Result<Option<Zeroizing<String>>, CliError> {
    if !directory.is_regular(name) {
        return Ok(None);
    }
    let file = directory.open_file(OsStr::new(name))?;
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_INPUT_BYTES + 1).read_to_string(&mut text)?;
    if text.len() as u64 > MAX_INPUT_BYTES {
        return Err(metadata_invalid_error(format!("{name} exceeds size limit")));
    }
    Ok(Some(text))
}

fn detect_open_workspace(directory: &InputDirectory) -> Result<Vec<PolicyDetection>, CliError> {
    // Keep manifest reads on the directory handle. Only fixed task and runner names reach MCP.
    let config = read_workspace_manifest(directory, LOCKET_TOML)?
        .map(|text| toml::from_str::<toml::Value>(&text))
        .transpose()
        .map_err(|_| metadata_invalid_error("could not parse locket.toml"))?;
    let configured = config.as_ref().and_then(|value| value.get("commands"));
    let mut commands = Vec::new();
    let mut add = |name, argv: Vec<&'static str>, source_file| {
        commands.push(PolicyDetection {
            name,
            command_preview: argv.join(" "),
            argv,
            source_file,
            already_configured: configured
                .and_then(|value| value.get(name))
                .is_some_and(toml::Value::is_table),
        });
    };

    if let Some(manifest) = read_workspace_manifest(directory, "package.json")? {
        let document: Value = serde_json::from_str(&manifest)
            .map_err(|_| metadata_invalid_error("could not parse package.json"))?;
        let runner = if directory.is_regular("pnpm-lock.yaml") {
            "pnpm"
        } else if directory.is_regular("yarn.lock") {
            "yarn"
        } else if directory.is_regular("bun.lock") || directory.is_regular("bun.lockb") {
            "bun"
        } else {
            "npm"
        };
        for name in ["dev", "start", "build", "test", "lint", "typecheck", "migrate", "db:migrate"]
        {
            if document["scripts"][name].as_str().is_some_and(|script| !script.trim().is_empty()) {
                add(name, vec![runner, "run", name], "package.json");
            }
        }
    }
    if let Some(manifest) = read_workspace_manifest(directory, "Cargo.toml")? {
        let cargo: toml::Value = toml::from_str(&manifest)
            .map_err(|_| metadata_invalid_error("could not parse Cargo.toml"))?;
        add("test", vec!["cargo", "test"], "Cargo.toml");
        if cargo
            .get("bin")
            .and_then(toml::Value::as_array)
            .is_some_and(|bins| bins.iter().any(toml::Value::is_table))
            || directory.child_has_file("src", "main.rs")
        {
            add("run", vec!["cargo", "run"], "Cargo.toml");
        }
    }
    if let Some(makefile) = read_workspace_manifest(directory, "Makefile")? {
        let targets: std::collections::BTreeSet<_> = makefile
            .lines()
            .filter_map(|line| {
                let (name, remainder) = line.split_once(':')?;
                (!remainder.trim_start_matches(':').starts_with('=')).then_some(name)
            })
            .collect();
        for name in ["dev", "test", "build", "lint", "run"] {
            if targets.contains(name) {
                add(name, vec!["make", name], "Makefile");
            }
        }
    }
    if directory.is_regular("pyproject.toml") {
        let argv = if directory.is_regular("uv.lock") {
            vec!["uv", "run", "pytest"]
        } else {
            vec!["pytest"]
        };
        add("test", argv, "pyproject.toml");
    }
    Ok(commands)
}

fn import_env(context: &RuntimeContext, args: ImportEnvArgs) -> Result<Value, CliError> {
    let source =
        args.source.as_deref().map_or(Ok(SecretSourceArg::UserLocal), parse_secret_source)?;
    let mut store =
        if args.dry_run { require_metadata_store(context)? } else { open_store(context)? };
    let target = select_mcp_target(context, &store, &args.project, args.profile.as_deref())?;
    let path = canonical_input_path(context, &args.path, InputPathKind::File("dotenv input"))?;
    let (parent, _) = input_parent(&path)?;
    if target.project.id.starts_with("lk_proj_shared_") {
        require_workspace_path(context, parent, Some(&store), ENV_PATH_SCOPE)?;
    } else if !path_in_project_roots(&store, &target.project.id, parent)? {
        return Err(access_denied_error(
            "dotenv file must be inside a trusted target project root",
        ));
    }
    if args.overwrite && !args.dry_run {
        confirm_write(&target.profile, args.confirm_dangerous, "set confirm_dangerous to true")?;
    }
    let options = EnvImportOptions {
        only: args.only,
        exclude: args.exclude,
        overwrite: args.overwrite,
        literal: args.literal,
        dry_run: args.dry_run,
        confirmed_profile: args.confirm_dangerous.then(|| target.profile.name.clone()),
        source,
    };
    import_env_to_target(context, &mut store, &target, open_scoped_file(&path)?, &options)
}

#[derive(Clone, Copy)]
enum InputPathKind {
    File(&'static str),
    Directory(&'static str),
}

fn canonical_input_path(
    context: &RuntimeContext,
    path: &Path,
    kind: InputPathKind,
) -> Result<PathBuf, CliError> {
    // Strip trailing separators and dots so they cannot hide a final symlink.
    let path = context.cwd.join(path).components().collect::<PathBuf>();
    let metadata = fs::symlink_metadata(&path)?;
    match kind {
        InputPathKind::File(label) if !metadata.is_file() => {
            return Err(metadata_invalid_error(format!("{label} must be a regular file")));
        }
        InputPathKind::Directory(message) if !metadata.is_dir() => {
            return Err(metadata_invalid_error(message));
        }
        _ => {}
    }
    // Resolve ancestors for scope checks, then open every component without following links.
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => Ok(parent.canonicalize()?.join(name)),
        _ => Ok(path.canonicalize()?),
    }
}

fn require_workspace_path(
    context: &RuntimeContext,
    canonical: &Path,
    store: Option<&Store>,
    outside_scope_message: &str,
) -> Result<(), CliError> {
    if canonical.starts_with(&context.cwd) {
        return Ok(());
    }
    let metadata_store = if store.is_none() { read_metadata_store(context)? } else { None };
    if let Some(store) = store.or(metadata_store.as_ref()) {
        for project in store.list_projects()? {
            if path_in_project_roots(store, &project.id, canonical)? {
                return Ok(());
            }
        }
    }
    Err(access_denied_error(outside_scope_message))
}

fn registered_project_roots(store: &Store, project_id: &str) -> Result<Vec<PathBuf>, CliError> {
    Ok(store
        .list_project_roots(project_id)?
        .into_iter()
        .filter_map(|root| {
            let path = fs::canonicalize(root.display_path?).ok()?;
            // The stored authorization is over this exact canonical path.
            (Sha256::digest(path.to_string_lossy().as_bytes())[..] == root.root_hash)
                .then_some(path)
        })
        .collect())
}

fn path_in_project_roots(
    store: &Store,
    project_id: &str,
    canonical: &Path,
) -> Result<bool, CliError> {
    Ok(registered_project_roots(store, project_id)?
        .into_iter()
        .any(|path| canonical.starts_with(path)))
}

struct TrustedMcpConfig {
    root: PathBuf,
    directory: InputDirectory,
    config: ProjectConfig,
    text: Zeroizing<String>,
}

fn trusted_mcp_configs(store: &Store, project_id: &str) -> Result<Vec<TrustedMcpConfig>, CliError> {
    let mut configs = Vec::new();
    for root in registered_project_roots(store, project_id)? {
        let directory = InputDirectory::open(&root)?;
        let Some(text) = read_workspace_manifest(&directory, LOCKET_TOML)? else { continue };
        let config: ProjectConfig = toml::from_str(&text)
            .map_err(|_| metadata_invalid_error("could not read trusted project configuration"))?;
        if config.schema_version != PROJECT_CONFIG_SCHEMA_VERSION {
            return Err(metadata_invalid_error("could not read trusted project configuration"));
        }
        if config.project_id.as_str() == project_id {
            configs.push(TrustedMcpConfig { root, directory, config, text });
        }
    }
    Ok(configs)
}

fn select_mcp_target(
    context: &RuntimeContext,
    store: &Store,
    selector: &str,
    profile: Option<&str>,
) -> Result<WriteTarget, CliError> {
    let project = select_project(store, &context.cwd, selector)?;
    let default_profile = if profile.is_none() {
        trusted_mcp_configs(store, &project.id)?
            .into_iter()
            .next()
            .map(|resolved| resolved.config.default_profile)
    } else {
        None
    };
    let name = profile
        .or_else(|| default_profile.as_ref().map(locket_core::ProfileName::as_str))
        .unwrap_or("default");
    let profile = store.get_profile_by_name(&project.id, name)?.ok_or_else(|| {
        crate::profile_not_found_error(
            "target profile not found; pass --profile to select a profile",
        )
    })?;
    Ok(WriteTarget { project, profile })
}

fn get_secret_metadata(context: &RuntimeContext, args: &SecretArgs) -> Result<Value, CliError> {
    let store = require_metadata_store(context)?;
    let target = args.target(context, &store)?;
    let secret = args.record(&store, &target)?;
    secret_metadata(&store, &target, &secret)
}

fn secret_metadata(
    store: &Store,
    target: &WriteTarget,
    secret: &SecretRecord,
) -> Result<Value, CliError> {
    let metadata = store
        .get_secret_mutable_metadata(&secret.id)?
        .ok_or_else(|| secret_not_found_error("secret not found"))?;
    let versions = store.list_secret_versions(&secret.id)?.into_iter().map(|row| json!({
        "version": row.version, "state": row.state, "source": row.source, "origin": row.origin,
        "created_at": row.created_at, "deprecated_at": row.deprecated_at,
        "grace_until": row.grace_until, "purged_at": row.purged_at,
    })).collect::<Vec<_>>();
    Ok(json!({
        "project_id": target.project.id, "project_name": target.project.name,
        "profile": target.profile.name, "name": secret.name, "source": secret.source,
        "version": secret.current_version, "versions": versions,
        "reference": format!("lk://{}/{}", target.profile.name, secret.name),
        "description": metadata.description, "owner": metadata.owner, "tags": metadata.tags,
        "required": metadata.required, "created_at": secret.created_at, "updated_at": secret.updated_at,
        "last_rotated_at": secret.last_rotated_at,
    }))
}

fn store_secret(
    context: &RuntimeContext,
    args: WriteArgs,
    value: Option<Zeroizing<String>>,
    generate: bool,
) -> Result<Value, CliError> {
    let mut store = open_store(context)?;
    let target = args.secret.target(context, &store)?;
    args.secret.confirm(&target)?;
    let flags = args.metadata.flags();
    validate_write_metadata(&flags, None)?;
    let request = WriteRequest::new(&args.secret.name, args.secret.source()?, args.upsert, &flags)?;
    let (value, origin) = if generate {
        if args.value_file.is_some() {
            return Err(metadata_invalid_error("generate takes no value_file"));
        }
        (generate_value(args.bytes, args.format)?, "generated")
    } else {
        let value = match (value, args.value_file) {
            (Some(value), None) => value,
            (None, Some(path)) => read_value_file(context, &store, &target.project.id, &path)?,
            _ => return Err(metadata_invalid_error("provide exactly one of value or value_file")),
        };
        (value, "manual")
    };
    write_value(context, &mut store, &target, &request, &value, origin, now_unix_nanos()?)
}

fn read_value_file(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    path: &str,
) -> Result<Zeroizing<String>, CliError> {
    let canonical =
        canonical_input_path(context, Path::new(path), InputPathKind::File("value_file"))?;
    if !path_in_project_roots(store, project_id, input_parent(&canonical)?.0)? {
        return Err(access_denied_error("value_file must be inside a trusted project root"));
    }
    let file = open_scoped_file(&canonical)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(metadata_invalid_error("value file exceeds size limit"));
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| metadata_invalid_error("value file must contain UTF-8"))?;
    Ok(Zeroizing::new(value.trim_end_matches(['\r', '\n']).to_owned()))
}

fn update_metadata(context: &RuntimeContext, args: UpdateArgs) -> Result<Value, CliError> {
    let store = open_store(context)?;
    let target = args.secret.target(context, &store)?;
    args.secret.confirm(&target)?;
    let secret = args.secret.record(&store, &target)?;
    let tags_provided = args.metadata.tags.is_some();
    let required = args.metadata.required;
    let flags = args.metadata.flags();
    if !tags_provided && !crate::metadata_flags_have_updates(&flags) {
        return Err(metadata_invalid_error("provide at least one metadata field"));
    }
    validate_write_metadata(&flags, None)?;
    SecretWriteKeys::validate_existing_metadata(
        context,
        &store,
        &secret.project_id,
        &secret.profile_id,
        &flags,
    )?;
    let timestamp = now_unix_nanos()?;
    let key = load_project_key(context, &store, &target.project.id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1, "action": "SECRET_META_UPDATE", "status": "SUCCESS",
        "secret_name": secret.name, "profile_id": secret.profile_id, "source": secret.source,
        "description_updated": flags.description.is_some(), "owner_updated": flags.owner.is_some(),
        "tag_update_count": flags.tags.len(), "required_update": required,
    });
    let audit = AuditWrite {
        project_id: &secret.project_id,
        profile_id: Some(&secret.profile_id),
        action: "SECRET_META_UPDATE",
        status: "SUCCESS",
        secret_name: Some(&secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    if !store.update_secret_metadata_with_options(
        &secret.id,
        SecretMetadataUpdate {
            description: flags.description.as_deref(),
            owner: flags.owner.as_deref(),
            tags: tags_provided.then_some(flags.tags.as_slice()),
            required,
            updated_at: Some(timestamp),
            audit: Some(AuditContext { key: key.as_ref(), write: &audit }),
        },
    )? {
        return Err(secret_not_found_error("active secret not found"));
    }
    let updated = store
        .get_secret_by_source(&secret.project_id, &secret.profile_id, &secret.name, &secret.source)?
        .ok_or_else(|| secret_not_found_error("active secret not found"))?;
    secret_metadata(&store, &target, &updated)
}

fn list_policies(context: &RuntimeContext, selector: &str) -> Result<Value, CliError> {
    let store = require_metadata_store(context)?;
    let project = select_project(&store, &context.cwd, selector)?;
    let mut policies = Vec::new();
    for resolved in trusted_mcp_configs(&store, &project.id)? {
        let document = PolicyDocument::from_toml_str(&resolved.text).map_err(|_| {
            crate::runtime::error::typed_cli_error(
                LocketError::InvalidPolicy,
                "could not read project policy metadata",
            )
        })?;
        policies.extend(document.commands.into_values().map(|policy| json!({
            "name": policy.name, "cwd": resolved.root,
            "required_secrets": policy.required_secrets.iter().map(SecretName::as_str).collect::<Vec<_>>(),
            "optional_secrets": policy.optional_secrets.iter().map(SecretName::as_str).collect::<Vec<_>>(),
            "require_user_verification": policy.require_user_verification,
            "confirm": policy.confirm, "require_agent": policy.require_agent,
            "invocation": ["locket", "run", "--redact-output", &policy.name],
        })));
    }
    Ok(json!({
        "project_id": project.id,
        "policies": policies,
        "execution_guidance": "Use locket run --redact-output POLICY. For a client that sends plaintext HTTP requests through a proxy, add --egress-host SECRET=host before POLICY to replace the environment value with a host-bound token.",
    }))
}

fn tool(name: &str, description: &str, properties: &Value, required: &[&str]) -> Value {
    json!({
        "name": name, "description": description,
        "inputSchema": {"type": "object", "properties": properties, "required": required},
    })
}

fn detect_commands_tool() -> Value {
    let mut definition = tool(
        "locket_detect_commands",
        "Detect runnable commands from manifests and return metadata only. Defaults to the working directory.",
        &json!({
            "path": {"type": "string", "description": "Directory within the working directory or a trusted project root."},
            "project": {"type": "string", "description": "Project ID, name, or trusted root."},
        }),
        &[],
    );
    definition["inputSchema"]["additionalProperties"] = json!(false);
    definition["inputSchema"]["not"] = json!({"required": ["path", "project"]});
    definition
}

fn tools() -> Vec<Value> {
    let string = json!({"type": "string"});
    let boolean = json!({"type": "boolean"});
    let optional_flag = json!({"type": "boolean", "default": false});
    let key_list = json!({"type": "array", "items": string});
    let target = json!({
        "project": string, "profile": string, "name": string, "source": string,
        "confirm_dangerous_profile": string,
    });
    let mut metadata = target.clone();
    metadata["description"] = string.clone();
    metadata["owner"] = string.clone();
    metadata["tags"] = json!({"type": "array", "items": string});
    metadata["required"] = boolean.clone();
    let mut storage = metadata.clone();
    storage["upsert"] = boolean.clone();
    let mut generation = storage.clone();
    storage["value"] = string.clone();
    storage["value_file"] = string.clone();
    generation["bytes"] = json!({"type": "integer", "minimum": 16, "maximum": 256});
    generation["format"] =
        json!({"type": "string", "enum": ["base64url", "hex", "alphanumeric", "uuid"]});
    let required = ["project", "name"];
    vec![
        tool(
            "locket_list_projects",
            "List local project metadata.",
            &json!({"redact_names": boolean}),
            &[],
        ),
        tool(
            "locket_inspect_env_keys",
            "Read dotenv key names and diagnostics from a file in the working directory or a trusted project root.",
            &json!({"path": string, "literal": optional_flag}),
            &["path"],
        ),
        tool(
            "locket_scan_env_files",
            "Find dotenv files, keys, profile hints, and shared-key candidates in the working directory or a trusted project root.",
            &json!({
                "path": string, "literal": optional_flag,
                "max_depth": {"type": "integer", "minimum": 1, "maximum": MAX_ENV_SCAN_DEPTH, "default": DEFAULT_ENV_SCAN_DEPTH},
            }),
            &[],
        ),
        detect_commands_tool(),
        tool(
            "locket_import_env",
            "Import dotenv keys into an encrypted vault and return metadata. Use dry_run to preview changes. Confirm overwrites in dangerous profiles with confirm_dangerous.",
            &json!({
                "project": string, "path": string, "profile": string,
                "source": {"type": "string", "enum": ["team-managed", "user-local", "machine-local"], "default": "user-local"},
                "only": key_list, "exclude": key_list, "overwrite": optional_flag,
                "literal": optional_flag, "dry_run": optional_flag, "confirm_dangerous": optional_flag,
            }),
            &["project", "path"],
        ),
        tool(
            "locket_discover_secrets",
            "Find secret references and metadata.",
            &json!({
                "project": string, "profile": string, "query": string, "name_glob": string,
                "tag": string, "owner": string, "source": string, "include_deleted": boolean,
                "limit": {"type": "integer", "minimum": 0, "maximum": 1000}, "redact_names": boolean,
            }),
            &[],
        ),
        tool(
            "locket_get_secret_metadata",
            "Read secret metadata and version history.",
            &target,
            &required,
        ),
        tool(
            "locket_store_secret",
            "Encrypt a supplied value or local value file into the vault.",
            &storage,
            &required,
        ),
        tool(
            "locket_generate_secret",
            "Generate a new secret directly inside the vault.",
            &generation,
            &required,
        ),
        tool(
            "locket_update_secret_metadata",
            "Update descriptive metadata for an active secret.",
            &metadata,
            &required,
        ),
        tool(
            "locket_list_project_policies",
            "List metadata and run hints for saved command policies.",
            &json!({"project": string}),
            &["project"],
        ),
    ]
}
