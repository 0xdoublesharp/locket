//! Local project listing, cross-project discovery, and shared vault setup.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use clap::{Args, Subcommand};
use locket_agent::{DiscoveryError, DiscoveryFilters};
use locket_core::{ProfileName, ProjectConfig, ProjectId};
use locket_store::{ProjectRecord, ProjectSelectorResolution, Store, StoreError};
use rusqlite::{Transaction, TransactionBehavior};
use serde_json::{Value, json};

use crate::{
    CliError, LOCKET_TOML, ResolvedProject, RuntimeContext, ensure_project_metadata,
    initialize_project_keys, metadata_invalid_error, now_unix_nanos, open_store,
    project_not_found_error, read_project_config, root_hash,
};

#[derive(Args, Debug)]
pub struct DiscoverArgs {
    /// Search project names, key names and descriptive metadata.
    query: Option<String>,
    /// Project id, name, or trusted root.
    #[arg(long)]
    project: Option<String>,
    /// Profile name.
    #[arg(long)]
    profile: Option<String>,
    /// Key name glob.
    #[arg(long = "name")]
    name_glob: Option<String>,
    /// Exact tag.
    #[arg(long)]
    tag: Option<String>,
    /// Owner substring.
    #[arg(long)]
    owner: Option<String>,
    /// Secret source.
    #[arg(long, value_enum)]
    source: Option<crate::SecretSourceArg>,
    /// Include deleted metadata.
    #[arg(long)]
    all: bool,
    /// Maximum number of matches.
    #[arg(long)]
    limit: Option<usize>,
    /// Alias names and paths.
    #[arg(long)]
    redact_names: bool,
    /// Print JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
pub enum SharedCommand {
    /// Ensure a shared project with an isolated local keyring entry.
    Init {
        /// Name of the shared project.
        #[arg(long, default_value = "@shared")]
        name: String,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
}

pub fn read_metadata_store(context: &RuntimeContext) -> Result<Option<Store>, CliError> {
    match fs::metadata(&context.store_path) {
        Ok(_) => Ok(Some(Store::open_read_only(&context.store_path)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn require_metadata_store(context: &RuntimeContext) -> Result<Store, CliError> {
    read_metadata_store(context)?.ok_or_else(project_not_found_error)
}

pub fn select_project(
    store: &Store,
    cwd: &Path,
    selector: &str,
) -> Result<ProjectRecord, CliError> {
    let mut result = store.resolve_project_selector(selector)?;
    let path = Path::new(selector);
    if result == ProjectSelectorResolution::NotFound && path.is_relative() {
        result = store.resolve_project_selector(&cwd.join(path).to_string_lossy())?;
    }
    match result {
        ProjectSelectorResolution::Found(project) => Ok(project),
        ProjectSelectorResolution::NotFound => Err(project_not_found_error()),
        ProjectSelectorResolution::Ambiguous(_) => Err(crate::invalid_reference_error(
            "project selector is ambiguous; select by project id",
        )),
    }
}

pub fn trusted_project_configs(
    store: &Store,
    project_id: &str,
) -> Result<Vec<ResolvedProject>, CliError> {
    let mut configs = Vec::new();
    for root in store.list_project_roots(project_id)? {
        let Some(path) = root.display_path else { continue };
        let Ok(path) = Path::new(&path).canonicalize() else { continue };
        if root_hash(&path)?.as_slice() != root.root_hash {
            continue;
        }
        let config_path = path.join(LOCKET_TOML);
        if !config_path.is_file() {
            continue;
        }
        let config = read_project_config(&config_path)
            .map_err(|_| metadata_invalid_error("could not read trusted project configuration"))?;
        if config.project_id.as_str() == project_id {
            configs.push(ResolvedProject { root: path, config });
        }
    }
    Ok(configs)
}

pub fn trusted_project_config(
    store: &Store,
    project_id: &str,
) -> Result<Option<ResolvedProject>, CliError> {
    Ok(trusted_project_configs(store, project_id)?.into_iter().next())
}

pub fn project_rows(context: &RuntimeContext, redact: bool) -> Result<Value, CliError> {
    let Some(store) = read_metadata_store(context)? else { return Ok(json!([])) };
    locket_agent::list_projects(&store, redact).map_err(|error| discovery_error(&error))
}

pub fn discover_rows(
    context: &RuntimeContext,
    mut filters: DiscoveryFilters,
) -> Result<Value, CliError> {
    let Some(store) = read_metadata_store(context)? else {
        return if filters.project.is_some() {
            Err(project_not_found_error())
        } else {
            Ok(json!([]))
        };
    };
    if let Some(selector) = filters.project.as_deref() {
        filters.project = Some(select_project(&store, &context.cwd, selector)?.id);
    }
    locket_agent::discover_secrets(&store, filters).map_err(|error| discovery_error(&error))
}

fn discovery_error(error: &DiscoveryError) -> CliError {
    match error {
        DiscoveryError::ProjectNotFound => project_not_found_error(),
        DiscoveryError::AmbiguousProject => crate::invalid_reference_error(error.to_string()),
        DiscoveryError::Store(_) => crate::corrupt_db_error(error.to_string()),
    }
}

pub fn write_json_result(
    output: &mut impl Write,
    result: Result<Value, CliError>,
) -> Result<u8, CliError> {
    let (value, code) = match result {
        Ok(value) => (value, 0),
        Err(error) => (error_json(&error), error.exit_code()),
    };
    serde_json::to_writer(&mut *output, &value)?;
    writeln!(output)?;
    Ok(code)
}

pub fn error_json(error: &CliError) -> Value {
    let message = if matches!(error, CliError::Typed { .. }) {
        error.to_string()
    } else {
        "vault operation failed".to_owned()
    };
    let code = match error {
        CliError::Typed { kind, .. } => format!("{kind:?}"),
        _ => "VaultOperationFailed".to_owned(),
    };
    json!({ "error": { "code": code, "message": message, "exit_code": error.exit_code() } })
}

pub fn project_list_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    json: bool,
    redact_names: bool,
) -> Result<(), CliError> {
    let projects =
        project_rows(context, crate::privacy_redact_names_enabled(context, redact_names)?)?;
    if json {
        write_json_result(output, Ok(projects))?;
        return Ok(());
    }
    for project in projects.as_array().into_iter().flatten() {
        writeln!(
            output,
            "{} ({}) — {} active secrets",
            field(project, "name"),
            field(project, "project_id"),
            project["active_secret_count"]
        )?;
        for profile in project["profiles"].as_array().into_iter().flatten() {
            let dangerous = if profile["dangerous"] == true { " [dangerous]" } else { "" };
            writeln!(output, "  profile {}{dangerous}", field(profile, "name"))?;
        }
        for root in
            project["trusted_roots"].as_array().into_iter().flatten().filter_map(Value::as_str)
        {
            writeln!(output, "  root {root}")?;
        }
    }
    Ok(())
}

pub fn discover_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: DiscoverArgs,
) -> Result<u8, CliError> {
    let result = (|| {
        discover_rows(
            context,
            DiscoveryFilters {
                project: args.project,
                profile: args.profile,
                query: args.query,
                name_glob: args.name_glob,
                tag: args.tag,
                owner: args.owner,
                source: args.source.map(crate::source_arg_to_str).map(str::to_owned),
                include_deleted: args.all,
                limit: args.limit,
                redact_names: crate::privacy_redact_names_enabled(context, args.redact_names)?,
            },
        )
    })();
    if args.json {
        return write_json_result(output, result);
    }
    for row in result?.as_array().into_iter().flatten() {
        let dangerous = if row["dangerous"] == true { " [dangerous]" } else { "" };
        writeln!(
            output,
            "{} {} ({} v{} {}){dangerous}",
            field(row, "project_name"),
            field(row, "reference"),
            field(row, "source"),
            row["version"],
            field(row, "state")
        )?;
    }
    Ok(0)
}

fn field<'a>(row: &'a Value, key: &str) -> &'a str {
    row[key].as_str().unwrap_or_default()
}

pub fn shared_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: SharedCommand,
) -> Result<u8, CliError> {
    let SharedCommand::Init { name, json } = command;
    let result = shared_init(context, &name);
    if json {
        return write_json_result(output, result);
    }
    let row = result?;
    writeln!(
        output,
        "shared vault {} ({})",
        field(&row, "project_name"),
        field(&row, "project_id")
    )?;
    Ok(0)
}

pub const SHARED_PROJECT_PREFIX: &str = "lk_proj_shared_";
pub const GLOBAL_VAULT: &str = "@shared";

fn shared_init(context: &RuntimeContext, name: &str) -> Result<Value, CliError> {
    if name.is_empty() || name.trim() != name || name.chars().any(char::is_control) {
        return Err(metadata_invalid_error("invalid shared project name"));
    }
    let store = open_store(context)?;
    // Reserve the name while initializing the keyring entry and its wrapped store keys.
    let transaction =
        Transaction::new_unchecked(store.connection(), TransactionBehavior::Immediate)
            .map_err(StoreError::from)?;
    let prefix = SHARED_PROJECT_PREFIX;
    match store.resolve_project_selector(name)? {
        ProjectSelectorResolution::Found(project)
            if project.id.starts_with(prefix) && project.name == name =>
        {
            return Ok(json!({
                "project_id": project.id, "project_name": name, "profile": "default", "created": false,
            }));
        }
        ProjectSelectorResolution::NotFound => {}
        _ => return Err(metadata_invalid_error("shared project name is already in use")),
    }
    let generated = ProjectId::generate().map_err(|_| CliError::Time)?;
    let id = ProjectId::new(format!("{prefix}{}", &generated.as_str()[ProjectId::PREFIX.len()..]))
        .map_err(|_| CliError::Time)?;
    let profile = ProfileName::new("default").map_err(|_| CliError::Time)?;
    let config = ProjectConfig::new(id, name.to_owned(), profile);
    let timestamp = now_unix_nanos()?;
    ensure_project_metadata(&store, &config, timestamp)?;
    let result = initialize_project_keys(context, &store, &config, timestamp).and_then(|_| {
        transaction.commit().map_err(StoreError::from)?;
        Ok(())
    });
    if let Err(error) = result {
        let _ = context.key_store.delete_master_key(config.project_id.as_str());
        let _ = context.passphrase_store.delete_master_key(config.project_id.as_str());
        return Err(error);
    }
    Ok(json!({
        "project_id": config.project_id, "project_name": name,
        "profile": config.default_profile, "created": true,
    }))
}
