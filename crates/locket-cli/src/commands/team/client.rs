//! Automation client command implementations.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::SigningKey;
use locket_core::ClientId;
use locket_crypto::{
    KeyPurpose, derive_recovery_key_v1, generate_key, open_recovery_entry_v1, wrap_dek_v1,
};
use locket_platform::{
    RecoveryEnvelope, load_recovery_envelope, load_recovery_kdf_toml, save_recovery_envelope,
    secure_directory, write_user_only_file,
};
use locket_store::{
    AuditWrite, AutomationClientPrivateKeyRefRecord, AutomationClientRecord, Store,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::runtime::error::corrupt_db_error;
use crate::{
    CliError, ClientAddArgs, ClientCommand, ClientCreateArgs, ResolvedProject, RuntimeContext,
    ensure_project_exists, ensure_trusted_project_root, format_hex, format_unix_nanos,
    hex_nibble_with_message, invalid_reference_error, load_command_policy, load_project_key,
    metadata_invalid_error, now_unix_nanos, open_store, policy_not_found_error,
    recovery_code_decode, require_project, seal_recovery_envelope_entry,
};

const AUTOMATION_CLIENT_PRIVATE_KEY_PREFIX: &str = "automation_client_private_key:";

pub fn client_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: ClientCommand,
) -> Result<(), CliError> {
    match command {
        ClientCommand::Create(args) => client_create_command(context, output, &args),
        ClientCommand::Add(args) => client_add_command(context, output, &args),
        ClientCommand::List(args) => client_list_command(context, output, args.all),
        ClientCommand::Revoke { client } => client_revoke_command(context, output, &client),
    }
}

fn client_create_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ClientCreateArgs,
) -> Result<(), CliError> {
    let seed = generate_key()?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    register_client_metadata(
        context,
        output,
        ClientRegistrationRequest {
            name: &args.name,
            public_key: &public_key,
            storage: args.storage.as_str(),
            actions: &args.actions,
            policies: &args.policies,
            created_by_locket: true,
            private_key: Some(&seed),
        },
    )
}

fn client_add_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ClientAddArgs,
) -> Result<(), CliError> {
    let public_key = parse_client_public_key(&args.pubkey)?;
    register_client_metadata(
        context,
        output,
        ClientRegistrationRequest {
            name: &args.name,
            public_key: &public_key,
            storage: "external",
            actions: &args.actions,
            policies: &args.policies,
            created_by_locket: false,
            private_key: None,
        },
    )
}

#[derive(Clone, Copy)]
struct ClientRegistrationRequest<'a> {
    name: &'a str,
    public_key: &'a [u8; 32],
    storage: &'a str,
    actions: &'a [String],
    policies: &'a [String],
    created_by_locket: bool,
    private_key: Option<&'a locket_crypto::KeyBytes>,
}

fn register_client_metadata(
    context: &RuntimeContext,
    output: &mut impl Write,
    request: ClientRegistrationRequest<'_>,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    ensure_trusted_project_root(&store, &resolved)?;
    let name = validate_client_name(request.name)?;
    let actions = validate_client_actions(request.actions)?;
    let policies = validate_client_policies(&resolved, request.policies)?;
    let timestamp = now_unix_nanos()?;
    let id = ClientId::generate().map_err(|error| corrupt_db_error(error.to_string()))?;
    let fingerprint = client_public_key_fingerprint(request.public_key);
    let private_key_ref = if request.created_by_locket {
        let Some(private_key) = request.private_key else {
            return Err(corrupt_db_error("missing generated automation client private key"));
        };
        Some(store_client_private_key(
            context,
            &store,
            &resolved,
            id.as_str(),
            request.storage,
            private_key,
            timestamp,
        )?)
    } else {
        None
    };
    let client = AutomationClientRecord {
        id: id.as_str().to_owned(),
        project_id: resolved.config.project_id.to_string(),
        name: name.to_owned(),
        public_key: request.public_key.to_vec(),
        fingerprint: fingerprint.clone(),
        storage: request.storage.to_owned(),
        allowed_actions: actions.clone(),
        allowed_policies: policies.clone(),
        created_at: timestamp,
        last_used_at: None,
        revoked_at: None,
    };
    if let Err(error) =
        store.insert_automation_client_with_private_key_ref(&client, private_key_ref.as_ref())
    {
        if request.created_by_locket {
            cleanup_client_private_key(context, request.storage, &client.id);
        }
        return Err(error.into());
    }
    let metadata = json!({
        "schema_version": 1,
        "action": "CLIENT_ADD",
        "status": "SUCCESS",
        "command": "client",
        "project_id": resolved.config.project_id.as_str(),
        "client_id": &client.id,
        "client_name": &client.name,
        "public_key_fingerprint": &fingerprint,
        "storage": request.storage,
        "allowed_actions": &actions,
        "allowed_policies": &policies,
        "created_by_locket": request.created_by_locket,
    });
    write_client_audit_if_available(
        context,
        &mut store,
        &resolved,
        "CLIENT_ADD",
        &metadata,
        timestamp,
    )?;

    writeln!(output, "client: {}", client.name)?;
    writeln!(output, "client_id: {}", client.id)?;
    writeln!(output, "fingerprint: {}", client.fingerprint)?;
    writeln!(output, "storage: {}", client.storage)?;
    writeln!(output, "allowed_actions: {}", client.allowed_actions.join(","))?;
    writeln!(output, "allowed_policies: {}", client.allowed_policies.join(","))?;
    writeln!(output, "private_key_material: never displayed")?;
    if request.created_by_locket {
        writeln!(output, "private_key_storage: {}", client.storage)?;
    }
    Ok(())
}

fn client_list_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    include_revoked: bool,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    let clients =
        store.list_automation_clients(resolved.config.project_id.as_str(), include_revoked)?;
    if clients.is_empty() {
        writeln!(output, "clients: none")?;
        writeln!(output, "include_revoked: {}", if include_revoked { "yes" } else { "no" })?;
        writeln!(output, "private_key_material: never displayed")?;
        return Ok(());
    }
    for client in clients {
        writeln!(
            output,
            "{} {} fingerprint={} actions={} policies={} created_at={} last_used_at={} revoked_at={}",
            client.id,
            client.name,
            truncated_fingerprint(&client.fingerprint),
            client.allowed_actions.join(","),
            client.allowed_policies.join(","),
            format_unix_nanos(client.created_at),
            client.last_used_at.map_or_else(|| "never".to_owned(), format_unix_nanos),
            client.revoked_at.map_or_else(|| "active".to_owned(), format_unix_nanos),
        )?;
    }
    writeln!(output, "private_key_material: never displayed")?;
    Ok(())
}

fn client_revoke_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    client_ref: &str,
) -> Result<(), CliError> {
    if client_ref.trim().is_empty() {
        return Err(invalid_reference_error("client identifier cannot be empty"));
    }
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    ensure_trusted_project_root(&store, &resolved)?;
    let Some(client) =
        store.get_automation_client(resolved.config.project_id.as_str(), client_ref)?
    else {
        return Err(policy_not_found_error(format!("automation client not found: {client_ref}")));
    };
    let revoked_at = if client.revoked_at.is_some() {
        None
    } else {
        let timestamp = now_unix_nanos()?;
        let project_id = resolved.config.project_id.as_str();
        let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
        let metadata = json!({
            "schema_version": 1,
            "action": "CLIENT_REVOKE",
            "status": "SUCCESS",
            "command": "client",
            "project_id": project_id,
            "client_id": &client.id,
            "client_name": &client.name,
            "public_key_fingerprint": &client.fingerprint,
            "storage": &client.storage,
            "allowed_actions": &client.allowed_actions,
            "allowed_policies": &client.allowed_policies,
            "revoked_at": timestamp,
        });
        let audit = AuditWrite {
            project_id,
            profile_id: None,
            action: "CLIENT_REVOKE",
            status: "SUCCESS",
            secret_name: None,
            command: Some("client"),
            metadata_json: &metadata,
            timestamp,
        };
        store.with_atomic_write(|store| -> Result<_, CliError> {
            let revoked = store.revoke_automation_client(project_id, &client.id, timestamp)?;
            if revoked {
                store.append_audit(audit_key.as_ref(), &audit)?;
            }
            Ok(revoked.then_some(timestamp))
        })?
    };
    // Preserve the reference across a failed deletion so a later revoke can retry cleanup.
    if let Some(reference) = store.get_automation_client_private_key_ref(&client.id)? {
        delete_client_private_key(context, &reference)?;
        store.delete_automation_client_private_key_ref(&client.id)?;
    }
    writeln!(output, "client: {}", client.name)?;
    writeln!(output, "client_id: {}", client.id)?;
    if let Some(timestamp) = revoked_at {
        writeln!(output, "revoked_at: {}", format_unix_nanos(timestamp))?;
        writeln!(output, "private_key_material: never displayed")?;
    } else {
        writeln!(output, "status: already revoked")?;
    }
    Ok(())
}

fn store_client_private_key(
    context: &RuntimeContext,
    store: &Store,
    resolved: &ResolvedProject,
    client_id: &str,
    storage: &str,
    private_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<AutomationClientPrivateKeyRefRecord, CliError> {
    let reference = match storage {
        "os-keychain" => {
            let reference =
                context.automation_client_key_store.store_client_key(client_id, private_key)?;
            AutomationClientPrivateKeyRefRecord {
                client_id: client_id.to_owned(),
                storage: storage.to_owned(),
                keychain_service: Some(reference.service),
                keychain_account: Some(reference.account),
                local_path_hash: None,
                metadata_json: json!({
                    "schema_version": 1,
                    "storage": storage,
                })
                .to_string(),
                created_at: timestamp,
                updated_at: timestamp,
            }
        }
        "wrapped-local-file" => {
            let path = automation_client_key_path(context, client_id)?;
            let project_key = load_project_key(
                context,
                store,
                resolved.config.project_id.as_str(),
                KeyPurpose::ProjectMetadata,
            )?;
            let aad =
                automation_client_private_key_aad(resolved.config.project_id.as_str(), client_id);
            let wrapped_key = wrap_dek_v1(&project_key, private_key, &aad)?;
            let path_hash = path_hash(&path);
            let parent =
                path.parent().ok_or_else(|| corrupt_db_error("invalid client key path"))?;
            secure_directory(parent)?;
            let file = json!({
                "schema_version": 1,
                "algorithm": "xchacha20poly1305-key-wrap-v1",
                "project_id": resolved.config.project_id.as_str(),
                "client_id": client_id,
                "wrapped_private_key": BASE64URL_NOPAD.encode(&wrapped_key),
            });
            let contents = serde_json::to_vec_pretty(&file)?;
            write_user_only_file(&path, &contents)?;
            AutomationClientPrivateKeyRefRecord {
                client_id: client_id.to_owned(),
                storage: storage.to_owned(),
                keychain_service: None,
                keychain_account: None,
                local_path_hash: Some(path_hash.clone()),
                metadata_json: json!({
                    "schema_version": 1,
                    "storage": storage,
                    "local_path_hash": path_hash,
                    "wrapped_key_schema": 1,
                })
                .to_string(),
                created_at: timestamp,
                updated_at: timestamp,
            }
        }
        _ => {
            return Err(metadata_invalid_error(
                "unsupported automation client private-key storage",
            ));
        }
    };
    if let Err(error) =
        write_client_private_key_recovery_envelope(context, resolved, client_id, private_key)
    {
        cleanup_client_private_key(context, storage, client_id);
        return Err(error);
    }
    Ok(reference)
}

fn write_client_private_key_recovery_envelope(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    client_id: &str,
    private_key: &locket_crypto::KeyBytes,
) -> Result<(), CliError> {
    let project_id = resolved.config.project_id.as_str();
    let recovery_dir = resolved.root.join(".locket").join("recovery");
    let kdf = load_recovery_kdf_toml(&recovery_dir)
        .map_err(|error| metadata_invalid_error(format!("recovery/envelope.bin: {error}")))?;
    let envelope = load_recovery_envelope(&recovery_dir)
        .map_err(|error| metadata_invalid_error(format!("recovery/envelope.bin: {error}")))?;
    kdf.validate()?;
    if envelope.kdf_profile_id != kdf.kdf_profile_id {
        return Err(metadata_invalid_error("recovery envelope kdf profile mismatch"));
    }
    let code = context.recovery_code_reader.read_recovery_code("current recovery code")?;
    let code_bytes = recovery_code_decode(code.trim())?;
    let salt = kdf
        .decode_salt()
        .map_err(|error| metadata_invalid_error(format!("recovery kdf salt: {error}")))?;
    let recovery_root = derive_recovery_key_v1(&code_bytes, &salt, kdf.to_crypto_params())?;
    let master_entry = envelope
        .entries
        .iter()
        .find(|entry| entry.entry_kind == "master_key" && entry.entry_id == project_id)
        .ok_or_else(|| metadata_invalid_error("recovery envelope missing master_key entry"))?;
    let _ = open_recovery_entry_v1(
        &recovery_root,
        &kdf.kdf_profile_id,
        &master_entry.entry_kind,
        &master_entry.entry_id,
        &master_entry.nonce,
        &master_entry.ciphertext,
    )?;
    let entry_kind = format!("{AUTOMATION_CLIENT_PRIVATE_KEY_PREFIX}{client_id}");
    let mut entries = Vec::with_capacity(envelope.entries.len() + 1);
    for entry in envelope.entries {
        if entry.entry_id == client_id
            && (entry.entry_kind == "automation_client_private_key"
                || entry.entry_kind == entry_kind)
        {
            continue;
        }
        entries.push(entry);
    }
    entries.push(seal_recovery_envelope_entry(
        &recovery_root,
        &kdf.kdf_profile_id,
        &entry_kind,
        client_id,
        private_key,
    )?);
    let envelope = RecoveryEnvelope {
        kdf_profile_id: kdf.kdf_profile_id,
        created_at_unix_nanos: envelope.created_at_unix_nanos,
        entries,
    };
    save_recovery_envelope(&recovery_dir, &envelope)
        .map_err(|error| metadata_invalid_error(format!("save recovery envelope: {error}")))?;
    Ok(())
}

fn delete_client_private_key(
    context: &RuntimeContext,
    reference: &AutomationClientPrivateKeyRefRecord,
) -> Result<(), CliError> {
    match reference.storage.as_str() {
        "os-keychain" => {
            context.automation_client_key_store.delete_client_key(&reference.client_id)?;
        }
        "wrapped-local-file" => {
            let path = automation_client_key_path(context, &reference.client_id)?;
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        _ => {
            return Err(metadata_invalid_error(
                "unsupported automation client private-key storage",
            ));
        }
    }
    Ok(())
}

fn cleanup_client_private_key(context: &RuntimeContext, storage: &str, client_id: &str) {
    match storage {
        "os-keychain" => {
            let _ = context.automation_client_key_store.delete_client_key(client_id);
        }
        "wrapped-local-file" => {
            if let Ok(path) = automation_client_key_path(context, client_id) {
                let _ = fs::remove_file(path);
            }
        }
        _ => {}
    }
}

fn automation_client_key_path(
    context: &RuntimeContext,
    client_id: &str,
) -> Result<PathBuf, CliError> {
    let parent = context
        .store_path
        .parent()
        .ok_or_else(|| corrupt_db_error("could not resolve automation client key directory"))?;
    Ok(parent.join("automation-clients").join(format!("{client_id}.key")))
}

fn automation_client_private_key_aad(project_id: &str, client_id: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"locket-automation-client-private-key-v1");
    aad.extend_from_slice(project_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(client_id.as_bytes());
    aad
}

fn path_hash(path: &Path) -> String {
    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    format_hex(&digest[..16])
}

fn parse_client_public_key(value: &str) -> Result<[u8; 32], CliError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        return Err(metadata_invalid_error("public key must be 64 hex characters"));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble_with_message(chunk[0], "public key must be hex encoded")?;
        let low = hex_nibble_with_message(chunk[1], "public key must be hex encoded")?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn client_public_key_fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format_hex(&digest[..16])
}

fn truncated_fingerprint(fingerprint: &str) -> &str {
    fingerprint.get(..16).unwrap_or(fingerprint)
}

fn validate_client_name(name: &str) -> Result<&str, CliError> {
    let name = name.trim();
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(invalid_reference_error("client name cannot be empty"));
    };
    if !first.is_ascii_lowercase()
        || !chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_')
        || name.len() > 64
    {
        return Err(metadata_invalid_error("client name must match ^[a-z][a-z0-9_-]{0,63}$"));
    }
    Ok(name)
}

fn validate_client_actions(actions: &[String]) -> Result<Vec<String>, CliError> {
    if actions.is_empty() {
        return Err(metadata_invalid_error("InvalidPolicy: at least one --action is required"));
    }
    let mut normalized = BTreeSet::new();
    for action in actions {
        match action.as_str() {
            "run-policy" | "resolve-reference" | "scan-known-values" | "redact" => {
                normalized.insert(action.clone());
            }
            unsupported => {
                return Err(metadata_invalid_error(format!(
                    "InvalidPolicy: unsupported automation-client action: {unsupported}"
                )));
            }
        }
    }
    Ok(normalized.into_iter().collect())
}

fn validate_client_policies(
    resolved: &ResolvedProject,
    policies: &[String],
) -> Result<Vec<String>, CliError> {
    if policies.is_empty() {
        return Err(metadata_invalid_error("InvalidPolicy: at least one --policy is required"));
    }
    let mut normalized = BTreeSet::new();
    for policy in policies {
        if policy == "*" || policy.trim().is_empty() {
            return Err(metadata_invalid_error(
                "InvalidPolicy: wildcard or empty client policies are not supported",
            ));
        }
        load_command_policy(resolved, policy)?;
        normalized.insert(policy.clone());
    }
    Ok(normalized.into_iter().collect())
}

fn write_client_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    action: &'static str,
    metadata: &Value,
    timestamp: i64,
) -> Result<(), CliError> {
    let audit_key =
        load_project_key(context, store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action,
        status: "SUCCESS",
        secret_name: None,
        command: Some("client"),
        metadata_json: metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
