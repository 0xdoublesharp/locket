//! Secret write targeting and encrypted lifecycle operations.

use std::io::Write;

use clap::Args;
use locket_core::{LocketError, SecretId, SecretName, validate_metadata_field};
use locket_crypto::{KeyBytes, KeyPurpose};
use locket_store::{
    AuditContext, AuditWrite, ProfileRecord, ProjectRecord, SecretBlobRecord,
    SecretFingerprintRecord, SecretInitialMetadata, SecretRecord, SecretVersionRecord, Store,
    VersionDeprecation,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::commands::discovery::{
    GLOBAL_VAULT, SHARED_PROJECT_PREFIX, select_project, write_json_result,
};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{CliError, invalid_secret_name_error, typed_cli_error};
use crate::runtime::key_access::{load_profile_key, load_project_key};
use crate::runtime::prompts::validate_secret_value_str;
use crate::support::project_files::refresh_example_for_project_if_enabled;
use crate::support::secret_helpers::{SecretEncryptRequest, encrypt_secret_version_with_keys};
use crate::{
    SecretMetadataFlags, SecretSourceArg, SecretWriteArgs, ensure_trusted_project_root,
    metadata_flags_have_updates, metadata_privacy_finding, metadata_required_update,
    metadata_validation_error, next_secret_version, now_unix_nanos, open_store, require_project,
    secret_already_exists_error, secret_deleted_error, secret_metadata_text_fields,
    source_arg_to_str,
};

#[derive(Args, Debug, Default)]
pub struct WriteTargetArgs {
    /// Project id, name, or trusted root.
    #[arg(long)]
    pub project: Option<String>,
    /// Target profile name.
    #[arg(long)]
    pub profile: Option<String>,
    /// Rotate an active secret at the selected source.
    #[arg(long)]
    pub upsert: bool,
    /// Confirm a write to a dangerous profile.
    #[arg(long)]
    pub use_dangerous: bool,
    /// Print a metadata-only JSON result.
    #[arg(long)]
    pub json: bool,
}

pub fn set_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &SecretWriteArgs,
) -> Result<u8, CliError> {
    let result = (|| {
        let mut store = open_store(context)?;
        let target = cli_target(context, &store, &args.target)?;
        let request =
            WriteRequest::new(&args.key, args.source.source, args.target.upsert, &args.metadata)?;
        validate_write_metadata(request.metadata, None)?;
        existing_for_write(&store, &target, &request)?;
        let value = context
            .secret_value_reader
            .read_secret_value(&format!("set secret value for {}", args.key))?;
        let result = write_value(
            context,
            &mut store,
            &target,
            &request,
            &value,
            "manual",
            now_unix_nanos()?,
        )?;
        if args.target.project.is_none() {
            refresh_example_for_project_if_enabled(context)?;
        }
        Ok(result)
    })();
    write_write_result(output, args.target.json, result)
}

pub fn write_write_result(
    output: &mut impl Write,
    json: bool,
    result: Result<Value, CliError>,
) -> Result<u8, CliError> {
    if json {
        return write_json_result(output, result);
    }
    let result = result?;
    let operation = result["operation"].as_str().unwrap_or("set");
    let name = result["name"].as_str().unwrap_or_default();
    let source = result["source"].as_str().unwrap_or_default();
    if result["origin_detail"] == "generated" {
        writeln!(output, "generated {name} ({source}, v{})", result["version"])?;
    } else {
        writeln!(output, "{operation} {name} ({source})")?;
    }
    Ok(0)
}

#[cfg(test)]
pub fn set_secret_value(
    context: &RuntimeContext,
    args: &SecretWriteArgs,
    value: &str,
    origin: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    let target = select_target(
        context,
        &store,
        args.target.project.as_deref(),
        args.target.profile.as_deref(),
    )?;
    let request =
        WriteRequest::new(&args.key, args.source.source, args.target.upsert, &args.metadata)?;
    write_value(context, &mut store, &target, &request, value, origin, timestamp)?;
    Ok(())
}

pub struct WriteTarget {
    pub project: ProjectRecord,
    pub profile: ProfileRecord,
}

pub fn cli_target(
    context: &RuntimeContext,
    store: &Store,
    args: &WriteTargetArgs,
) -> Result<WriteTarget, CliError> {
    let target = select_target(context, store, args.project.as_deref(), args.profile.as_deref())?;
    confirm_write(
        &target.profile,
        args.use_dangerous,
        "pass --use-dangerous to confirm the write",
    )?;
    Ok(target)
}

pub fn select_target(
    context: &RuntimeContext,
    store: &Store,
    selector: Option<&str>,
    profile: Option<&str>,
) -> Result<WriteTarget, CliError> {
    let (project, default_profile) = if let Some(selector) = selector {
        let project = select_project(store, &context.cwd, selector)?;
        let default = if profile.is_some() {
            "default".to_owned()
        } else {
            crate::commands::discovery::trusted_project_config(store, &project.id)?.map_or_else(
                || "default".to_owned(),
                |resolved| resolved.config.default_profile.to_string(),
            )
        };
        (project, default)
    } else {
        let resolved = require_project(context)?;
        ensure_trusted_project_root(store, &resolved)?;
        let project = store
            .get_project(resolved.config.project_id.as_str())?
            .ok_or_else(crate::project_not_found_error)?;
        (project, resolved.config.default_profile.to_string())
    };
    let profile_name = profile.unwrap_or(&default_profile);
    let profile = store.get_profile_by_name(&project.id, profile_name)?.ok_or_else(|| {
        crate::profile_not_found_error(
            "target profile not found; pass --profile to select a profile",
        )
    })?;
    Ok(WriteTarget { project, profile })
}

pub fn confirm_write(profile: &ProfileRecord, confirmed: bool, hint: &str) -> Result<(), CliError> {
    if profile.dangerous && !confirmed {
        return Err(typed_cli_error(
            LocketError::DangerousProfileConfirmationRequired,
            format!("profile {} is marked dangerous; {hint}", profile.name),
        ));
    }
    Ok(())
}

pub struct WriteRequest<'a> {
    name: SecretName,
    source: Option<SecretSourceArg>,
    upsert: bool,
    metadata: &'a SecretMetadataFlags,
}

impl<'a> WriteRequest<'a> {
    pub fn new(
        name: &str,
        source: Option<SecretSourceArg>,
        upsert: bool,
        metadata: &'a SecretMetadataFlags,
    ) -> Result<Self, CliError> {
        let name = SecretName::new(name.to_owned())
            .map_err(|_| invalid_secret_name_error("invalid secret name"))?;
        Ok(Self { name, source, upsert, metadata })
    }

    fn source(&self) -> &'static str {
        source_arg_to_str(self.source.unwrap_or(SecretSourceArg::UserLocal))
    }
}

fn existing_for_write(
    store: &Store,
    target: &WriteTarget,
    request: &WriteRequest<'_>,
) -> Result<Option<SecretRecord>, CliError> {
    let project_id = &target.project.id;
    let profile_id = &target.profile.id;
    let name = request.name.as_str();
    let existing = store.get_secret_by_source(project_id, profile_id, name, request.source())?;
    if let Some(secret) = existing {
        if secret.state != "active" {
            return Err(secret_deleted_error("secret source is deleted"));
        }
        if !request.upsert {
            let (command, rotation_scope) = if target.project.name == GLOBAL_VAULT
                && target.project.id.starts_with(SHARED_PROJECT_PREFIX)
            {
                ("locket shared", " for the default Global Vault profile")
            } else {
                ("locket", " from the target project's root and profile")
            };
            let source = request
                .source
                .map_or_else(String::new, |_| format!(" --source {}", request.source()));
            return Err(secret_already_exists_error(format!(
                "secret {name} already exists. Use `{command} set {name} --upsert{source}` with the same target flags, or run `{command} rotate {name}{source}`{rotation_scope}."
            )));
        }
        return Ok(Some(secret));
    }
    if request.source.is_none()
        && !store.list_secrets_by_name(project_id, profile_id, name)?.is_empty()
    {
        return Err(secret_already_exists_error(
            "secret already exists in another source; pass --source to choose a target",
        ));
    }
    Ok(None)
}

pub fn write_value(
    context: &RuntimeContext,
    store: &mut Store,
    target: &WriteTarget,
    request: &WriteRequest<'_>,
    value: &str,
    origin: &str,
    timestamp: i64,
) -> Result<Value, CliError> {
    validate_secret_value_str(value)?;
    validate_write_metadata(request.metadata, Some(value))?;
    let keys = SecretWriteKeys::load(context, store, &target.project.id, &target.profile.id)?;
    let (operation, version) = store.with_atomic_write(|store| -> Result<_, CliError> {
        if let Some(secret) = existing_for_write(store, target, request)? {
            let version = rotate_value(
                store,
                &keys,
                &secret,
                &Rotation {
                    value,
                    origin,
                    timestamp,
                    grace_until: None,
                    metadata: request.metadata,
                    action: "ROTATE",
                },
            )?;
            Ok(("rotate", version))
        } else {
            validate_fingerprints(
                store,
                &target.project.id,
                &target.profile.id,
                &keys.fingerprint,
                request.metadata,
            )?;
            create_value(
                store,
                &keys,
                &NewSecret {
                    project_id: &target.project.id,
                    profile_id: &target.profile.id,
                    name: request.name.as_str(),
                    source: request.source(),
                    value,
                    origin,
                    timestamp,
                    metadata: request.metadata,
                    action: "SET",
                },
            )?;
            Ok(("set", 1))
        }
    })?;
    if let Ok(Some(written)) = store.get_active_secret(
        &target.project.id,
        &target.profile.id,
        request.name.as_str(),
        request.source(),
    ) {
        super::links::try_record_cli_dedup_tag(
            context,
            store,
            &written.id,
            version,
            value,
            timestamp,
        );
    }
    let mut result = json!({
        "project_id": target.project.id, "project_name": target.project.name,
        "profile": target.profile.name, "name": request.name.as_str(), "source": request.source(),
        "version": version, "operation": operation,
        "reference": format!("lk://{}/{}", target.profile.name, request.name.as_str()),
    });
    if origin == "generated" {
        result["origin_detail"] = json!("generated");
    }
    Ok(result)
}

pub fn validate_write_metadata(
    metadata: &SecretMetadataFlags,
    value: Option<&str>,
) -> Result<(), CliError> {
    for (field, text) in secret_metadata_text_fields(metadata) {
        let findings = locket_scan::scan_text(field, text);
        validate_metadata_field(
            field,
            text,
            value,
            findings.iter().filter_map(metadata_privacy_finding),
        )
        .map_err(|error| metadata_validation_error(&error))?;
    }
    Ok(())
}

pub struct SecretWriteKeys {
    audit: Zeroizing<KeyBytes>,
    secret: Zeroizing<KeyBytes>,
    pub(super) fingerprint: Zeroizing<KeyBytes>,
}

impl SecretWriteKeys {
    pub fn load(
        context: &RuntimeContext,
        store: &Store,
        project_id: &str,
        profile_id: &str,
    ) -> Result<Self, CliError> {
        Ok(Self {
            audit: load_project_key(context, store, project_id, KeyPurpose::Audit)?,
            secret: load_profile_key(
                context,
                store,
                project_id,
                profile_id,
                KeyPurpose::ProfileSecret,
            )?,
            fingerprint: load_profile_key(
                context,
                store,
                project_id,
                profile_id,
                KeyPurpose::ProfileFingerprint,
            )?,
        })
    }

    pub fn validate_existing_metadata(
        context: &RuntimeContext,
        store: &Store,
        project_id: &str,
        profile_id: &str,
        metadata: &SecretMetadataFlags,
    ) -> Result<(), CliError> {
        if secret_metadata_text_fields(metadata).is_empty() {
            return Ok(());
        }
        let key = load_profile_key(
            context,
            store,
            project_id,
            profile_id,
            KeyPurpose::ProfileFingerprint,
        )?;
        validate_fingerprints(store, project_id, profile_id, &key, metadata)
    }

    fn encrypt(
        &self,
        request: SecretEncryptRequest<'_>,
        timestamp: i64,
    ) -> Result<(SecretBlobRecord, SecretFingerprintRecord), CliError> {
        let (encrypted, fingerprint) =
            encrypt_secret_version_with_keys(&self.secret, &self.fingerprint, request)?;
        Ok((
            SecretBlobRecord {
                secret_id: request.secret_id.to_owned(),
                version: request.version,
                encrypted_dek: encrypted.encrypted_dek,
                ciphertext: encrypted.ciphertext,
                value_nonce: encrypted.value_nonce,
                aad_schema_version: encrypted.aad_schema_version,
                created_at: timestamp,
            },
            SecretFingerprintRecord {
                secret_id: request.secret_id.to_owned(),
                version: request.version,
                fingerprint,
                created_at: timestamp,
            },
        ))
    }
}

fn validate_fingerprints(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    key: &KeyBytes,
    metadata: &SecretMetadataFlags,
) -> Result<(), CliError> {
    for (field, text) in secret_metadata_text_fields(metadata) {
        let fingerprint = locket_crypto::secret_fingerprint_v1(key, text)?;
        if locket_agent::has_secret_fingerprint(store, project_id, profile_id, &fingerprint)? {
            return Err(crate::metadata_looks_like_secret_error(format!(
                "metadata field {field} matches an existing secret value; refusing to store it"
            )));
        }
    }
    Ok(())
}

pub struct NewSecret<'a> {
    pub project_id: &'a str,
    pub profile_id: &'a str,
    pub name: &'a str,
    pub source: &'a str,
    pub value: &'a str,
    pub origin: &'a str,
    pub timestamp: i64,
    pub metadata: &'a SecretMetadataFlags,
    pub action: &'a str,
}

pub fn create_value(
    store: &mut Store,
    keys: &SecretWriteKeys,
    request: &NewSecret<'_>,
) -> Result<(), CliError> {
    let id = SecretId::generate().map_err(|_| CliError::Time)?.into_string();
    let secret = SecretRecord {
        id,
        project_id: request.project_id.to_owned(),
        profile_id: request.profile_id.to_owned(),
        name: request.name.to_owned(),
        source: request.source.to_owned(),
        origin: persisted_origin(request.origin).to_owned(),
        current_version: 1,
        state: "active".to_owned(),
        created_at: request.timestamp,
        updated_at: request.timestamp,
        last_rotated_at: None,
        deleted_at: None,
    };
    let (blob, fingerprint) =
        keys.encrypt(encrypt_request(&secret, 1, request.value), request.timestamp)?;
    let mut audit_metadata = crate::secret_audit_metadata(
        request.action,
        request.name,
        request.profile_id,
        request.source,
        Some(1),
    );
    record_generation(&mut audit_metadata, request.origin);
    let audit = write_audit(&secret, request.action, request.timestamp, &audit_metadata);
    store.with_atomic_write(|store| -> Result<(), CliError> {
        store.create_active_secret_with_metadata_and_audit(
            &secret,
            &version_record(&secret, 1, request.origin, request.timestamp),
            &blob,
            &fingerprint,
            SecretInitialMetadata {
                description: request.metadata.description.as_deref(),
                owner: request.metadata.owner.as_deref(),
                tags: &request.metadata.tags,
                required: metadata_required_update(request.metadata).unwrap_or(false),
            },
            Some(AuditContext { key: keys.audit.as_ref(), write: &audit }),
        )?;
        super::expiry::update_expiry_policy(store, &secret.id, request.metadata, request.timestamp)
    })
}

pub struct Rotation<'a> {
    pub value: &'a str,
    pub origin: &'a str,
    pub timestamp: i64,
    pub grace_until: Option<i64>,
    pub metadata: &'a SecretMetadataFlags,
    pub action: &'a str,
}

pub fn rotate_value(
    store: &mut Store,
    keys: &SecretWriteKeys,
    secret: &SecretRecord,
    rotation: &Rotation<'_>,
) -> Result<u32, CliError> {
    let version = next_secret_version(secret.current_version)?;
    let (blob, fingerprint) =
        keys.encrypt(encrypt_request(secret, version, rotation.value), rotation.timestamp)?;
    let mut audit_metadata = json!({
        "schema_version": 1, "action": rotation.action, "status": "SUCCESS",
        "secret_name": secret.name, "profile_id": secret.profile_id, "source": secret.source,
        "prior_version": secret.current_version, "deprecated_version": secret.current_version,
        "target_version": version, "deprecated_at": rotation.timestamp, "grace_until": rotation.grace_until,
    });
    record_generation(&mut audit_metadata, rotation.origin);
    let audit = write_audit(secret, rotation.action, rotation.timestamp, &audit_metadata);
    store.with_atomic_write(|store| -> Result<(), CliError> {
        let update = rotation.metadata;
        validate_fingerprints(
            store,
            &secret.project_id,
            &secret.profile_id,
            &keys.fingerprint,
            update,
        )?;
        let current = if metadata_flags_have_updates(update) {
            Some(
                store
                    .get_secret_mutable_metadata(&secret.id)?
                    .ok_or_else(|| crate::secret_not_found_error("secret not found"))?,
            )
        } else {
            None
        };
        let metadata = current.as_ref().map(|current| SecretInitialMetadata {
            description: update.description.as_deref().or(current.description.as_deref()),
            owner: update.owner.as_deref().or(current.owner.as_deref()),
            tags: if update.tags.is_empty() { &current.tags } else { &update.tags },
            required: metadata_required_update(update).unwrap_or(current.required),
        });
        store.rotate_secret_with_metadata_and_audit(
            secret,
            &version_record(secret, version, rotation.origin, rotation.timestamp),
            &blob,
            &fingerprint,
            VersionDeprecation {
                deprecated_at: rotation.timestamp,
                grace_until: rotation.grace_until,
            },
            metadata,
            Some(AuditContext { key: keys.audit.as_ref(), write: &audit }),
        )?;
        super::expiry::update_expiry_policy(store, &secret.id, update, rotation.timestamp)
    })?;
    Ok(version)
}

fn encrypt_request<'a>(
    secret: &'a SecretRecord,
    version: u32,
    value: &'a str,
) -> SecretEncryptRequest<'a> {
    SecretEncryptRequest {
        project_id: &secret.project_id,
        profile_id: &secret.profile_id,
        secret_id: &secret.id,
        secret_name: &secret.name,
        version,
        value,
    }
}

fn version_record(
    secret: &SecretRecord,
    version: u32,
    origin: &str,
    timestamp: i64,
) -> SecretVersionRecord {
    SecretVersionRecord {
        secret_id: secret.id.clone(),
        version,
        source: secret.source.clone(),
        origin: persisted_origin(origin).to_owned(),
        state: "current".to_owned(),
        created_at: timestamp,
        deprecated_at: None,
        grace_until: None,
        purged_at: None,
    }
}

fn record_generation(metadata: &mut Value, origin: &str) {
    if origin == "generated" {
        metadata["command"] = json!("generate");
    }
}

// The store's origin constraint predates generated secrets. The audit
// command and write response retain generation provenance.
fn persisted_origin(origin: &str) -> &str {
    if origin == "generated" { "manual" } else { origin }
}

fn write_audit<'a>(
    secret: &'a SecretRecord,
    action: &'a str,
    timestamp: i64,
    metadata: &'a Value,
) -> AuditWrite<'a> {
    AuditWrite {
        project_id: &secret.project_id,
        profile_id: Some(&secret.profile_id),
        action,
        status: "SUCCESS",
        secret_name: Some(&secret.name),
        command: metadata["command"].as_str(),
        metadata_json: metadata,
        timestamp,
    }
}
