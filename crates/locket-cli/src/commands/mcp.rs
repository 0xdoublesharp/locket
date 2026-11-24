//! Stdio MCP server for metadata queries and encrypted vault writes.

use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::Path;

use locket_agent::DiscoveryFilters;
use locket_core::{LocketError, SecretName};
use locket_crypto::KeyPurpose;
use locket_store::{AuditContext, AuditWrite, SecretMetadataUpdate, SecretRecord, Store};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::commands::discovery::{
    discover_rows, error_json, project_rows, require_metadata_store, select_project,
    trusted_project_configs,
};
use crate::commands::secrets::generate::{GenerateFormat, generate_value};
use crate::commands::secrets::set::{
    SecretWriteKeys, WriteRequest, WriteTarget, confirm_write, select_target,
    validate_write_metadata, write_value,
};
use crate::{
    CliError, RuntimeContext, SecretMetadataFlags, SecretSourceArg, load_project_key,
    metadata_invalid_error, now_unix_nanos, open_store, secret_deleted_error,
    secret_not_found_error, source_arg_to_str, source_precedence,
};

const MAX_INPUT_BYTES: u64 = 1_048_576;

pub fn serve(
    input: &mut impl BufRead,
    output: &mut impl Write,
    context: &RuntimeContext,
) -> Result<(), CliError> {
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
            |message| dispatch(context, message),
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
        select_target(context, store, Some(&self.project), self.profile.as_deref())
    }

    fn confirm(&self, target: &WriteTarget) -> Result<(), CliError> {
        confirm_write(
            &target.profile,
            self.confirm_dangerous_profile.as_deref() == Some(&target.profile.name),
            "supply the exact profile name in confirm_dangerous_profile",
        )
    }

    fn source(&self) -> Result<Option<SecretSourceArg>, CliError> {
        self.source
            .as_deref()
            .map(|source| match source {
                "user-local" => Ok(SecretSourceArg::UserLocal),
                "machine-local" => Ok(SecretSourceArg::MachineLocal),
                "team-managed" => Ok(SecretSourceArg::TeamManaged),
                _ => Err(metadata_invalid_error("invalid secret source")),
            })
            .transpose()
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
        _ => Err(metadata_invalid_error("unknown MCP tool")),
    }
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
            (None, Some(path)) => read_value_file(context, &path)?,
            _ => return Err(metadata_invalid_error("provide exactly one of value or value_file")),
        };
        (value, "manual")
    };
    write_value(context, &mut store, &target, &request, &value, origin, now_unix_nanos()?)
}

fn read_value_file(context: &RuntimeContext, path: &str) -> Result<Zeroizing<String>, CliError> {
    let path = context.cwd.join(Path::new(path));
    if !fs::metadata(&path)?.is_file() {
        return Err(metadata_invalid_error("value_file must be a regular file"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
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
    for resolved in trusted_project_configs(&store, &project.id)? {
        let document = crate::read_policy_document(&resolved.root.join(crate::LOCKET_TOML))
            .map_err(|_| {
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
            "invocation": ["locket", "run", &policy.name],
        })));
    }
    Ok(json!({"project_id": project.id, "policies": policies}))
}

fn tool(name: &str, description: &str, properties: &Value, required: &[&str]) -> Value {
    json!({
        "name": name, "description": description,
        "inputSchema": {"type": "object", "properties": properties, "required": required},
    })
}

fn tools() -> Vec<Value> {
    let string = json!({"type": "string"});
    let boolean = json!({"type": "boolean"});
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
