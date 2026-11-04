use data_encoding::BASE64URL_NOPAD;
use locket_core::{DeviceId, LocketError, ProjectConfig, safety_words_from_fingerprint_hex};
use locket_crypto::{
    KeyPurpose, derive_recovery_key_v1, generate_key, generate_recovery_code_bytes,
    generate_recovery_salt, open_recovery_entry_v1,
};
use locket_platform::{
    LocalDevicePrivateKeyStorage, PlatformError, RecoveryEnvelope, RecoveryKdfToml,
    WrappedLocalFileDevicePrivateKeyStorage, load_recovery_envelope, load_recovery_kdf_toml,
    save_recovery_envelope, save_recovery_kdf_toml,
};
use locket_store::{AuditContext, AuditWrite, DeviceRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::runtime::error::{confirmation_failed_error, corrupt_db_error, typed_cli_error};
use crate::runtime::user_verification::{
    UserVerificationAudit, configured_user_verification, require_user_verification,
};
use crate::support::style::{self, Tone};
use crate::{
    CliError, DeviceAddArgs, DeviceCommand, DeviceInitArgs, DeviceListArgs, DeviceRemoveArgs,
    ResolvedProject, RuntimeContext, access_denied_error, ensure_project_exists,
    ensure_project_metadata, format_hex, formatted_recovery_code, insert_wrapped_key,
    invalid_reference_error, load_project_key, metadata_invalid_error, now_unix_nanos, open_store,
    require_project, seal_recovery_envelope_entry, store_master_key_with_fallback, trust_root,
};

pub fn device_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: DeviceCommand,
) -> Result<(), CliError> {
    match command {
        DeviceCommand::Init(args) => device_init_command(context, output, &args),
        DeviceCommand::RotateSigning => device_rotate_signing_command(context, output),
        DeviceCommand::Pubkey => device_pubkey_command(context, output),
        DeviceCommand::Add(args) => device_add_command(context, output, &args),
        DeviceCommand::List(args) => device_list_command(context, output, &args),
        DeviceCommand::Remove(args) => device_remove_command(context, output, &args),
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn device_init_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DeviceInitArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    let timestamp = now_unix_nanos()?;
    let bootstrap_recovery =
        maybe_bootstrap_first_run_on_machine(context, &mut store, &resolved, timestamp)?;
    if bootstrap_recovery.is_none() {
        ensure_project_exists(&store, project_id)?;
    }

    let existing_replacement = if let Some(existing) = store.get_active_local_device(project_id)? {
        if !args.force {
            write_device_init_summary(output, "already initialized", &existing, None)?;
            return Ok(());
        }
        refuse_anchored_identity_change(&store, project_id)?;
        let verification =
            require_user_verification(context, "device init --force", "Replace local device key")?;
        Some((existing, verification))
    } else {
        None
    };
    let user_verification = if let Some((_, verification)) = existing_replacement.as_ref() {
        *verification
    } else {
        configured_user_verification(
            context,
            "user_verification_required_for.device_register",
            "device init",
            "register a local device",
        )?
    };
    let GeneratedLocalDevice { record: device, signing_private_key, sealing_private_key } =
        generate_local_device_record(project_id, timestamp)?;
    let storage = build_device_private_key_storage(context, project_id)?;
    storage.store(&device.id, &sealing_private_key)?;
    storage.for_signing().store(&device.fingerprint, &signing_private_key)?;
    if let Some((existing, verification)) = existing_replacement {
        replace_local_device_with_audit(
            context,
            &mut store,
            project_id,
            &existing,
            &device,
            verification,
            timestamp,
        )?;
        // Both new private envelopes were staged before changing the active device row.
        update_recovery_envelope_for_replacement_device(
            context,
            &resolved,
            &device,
            &signing_private_key,
            &sealing_private_key,
        )?;
        // Retain the old sealing envelope for deliberate recovery of old bundles.
    } else {
        store.insert_device(&device)?;
        write_device_audit_if_available(
            context,
            &mut store,
            project_id,
            "DEVICE_ADD",
            "device init",
            &device,
            user_verification,
        )?;
        if let Some(bootstrap_recovery) = bootstrap_recovery {
            save_bootstrap_recovery_envelope_with_device(
                &resolved.root,
                &resolved.config,
                &bootstrap_recovery,
                &device,
                &signing_private_key,
                &sealing_private_key,
                timestamp,
            )?;
            display_bootstrap_recovery_code(
                context,
                output,
                &resolved.config,
                &bootstrap_recovery.code_bytes,
            )?;
        }
    }
    store.mark_device_signing_v2(&device.id)?;
    let descriptor = encode_device_descriptor(&device)?;

    write_device_init_summary(output, "initialized", &device, Some(&descriptor))?;
    Ok(())
}

fn write_device_init_summary(
    output: &mut impl Write,
    status: &str,
    device: &DeviceRecord,
    descriptor: Option<&str>,
) -> Result<(), CliError> {
    if style::enabled() {
        style::write_banner(output, "device", status)?;
        style::write_kv(output, "device_id", device.id.as_str())?;
        style::write_kv(output, "fingerprint", device.fingerprint.as_str())?;
        if !device.safety_words.is_empty() {
            style::write_kv(output, "safety_words", device.safety_words.join(" "))?;
        }
        if let Some(descriptor) = descriptor {
            style::write_kv(output, "descriptor", descriptor)?;
            style::write_kv(output, "private_key_storage", "wrapped-local-file")?;
        }
        style::write_kv(output, "metadata_only", "yes")?;
    } else {
        writeln!(output, "device: {status}")?;
        writeln!(output, "device_id: {}", device.id)?;
        writeln!(output, "fingerprint: {}", device.fingerprint)?;
        if !device.safety_words.is_empty() {
            writeln!(output, "safety_words: {}", device.safety_words.join(" "))?;
        }
        if let Some(descriptor) = descriptor {
            writeln!(output, "descriptor: {descriptor}")?;
            writeln!(output, "private_key_storage: wrapped-local-file")?;
        }
        writeln!(output, "metadata_only: yes")?;
    }
    Ok(())
}

fn device_pubkey_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let (device, descriptor, derived_public) = active_local_device_descriptor(context)?;

    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    writeln!(output, "safety_words: {}", device.safety_words.join(" "))?;
    writeln!(output, "sealing_public_key_x25519: {}", BASE64URL_NOPAD.encode(&derived_public))?;
    writeln!(output, "descriptor: {descriptor}")?;
    writeln!(output, "private_key_storage: wrapped-local-file")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

pub fn active_local_device_descriptor(
    context: &RuntimeContext,
) -> Result<(DeviceRecord, String, [u8; 32]), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let device = store
        .get_active_local_device(project_id)?
        .ok_or_else(|| invalid_reference_error("local device is not initialized"))?;
    require_v2_signing(&store, &device)?;
    let descriptor = encode_device_descriptor(&device)?;
    let storage = build_device_private_key_storage(context, project_id)?;
    let private_key = storage.load(&device.id)?;
    let secret = X25519StaticSecret::from(*private_key);
    let derived_public = X25519PublicKey::from(&secret).to_bytes();
    let stored_public: [u8; 32] = device
        .sealing_public_key
        .as_slice()
        .try_into()
        .map_err(|_| corrupt_db_error("device sealing public key has unexpected length"))?;
    if derived_public != stored_public {
        return Err(corrupt_db_error("device private key does not match stored public key"));
    }
    Ok((device, descriptor, derived_public))
}

fn device_add_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DeviceAddArgs,
) -> Result<(), CliError> {
    validate_device_name(&args.name)?;
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let verified = decode_verified_device_descriptor(&args.device, "device descriptor")?;
    let user_verification = configured_user_verification(
        context,
        "user_verification_required_for.device_register",
        "device add",
        format!("register device {}", args.name),
    )?;
    let device = DeviceRecord {
        id: verified.descriptor.device_id,
        project_id: project_id.to_owned(),
        member_id: None,
        name: args.name.clone(),
        // Added devices use their registration name as the display label.
        label: args.name.clone(),
        signing_public_key: verified.signing_public_key.to_vec(),
        sealing_public_key: verified.sealing_public_key.to_vec(),
        fingerprint: verified.fingerprint,
        safety_words: verified.descriptor.safety_words,
        local: false,
        created_at: now_unix_nanos()?,
        last_seen_at: None,
        revoked_at: None,
    };
    store.insert_device(&device)?;
    if verified.descriptor.v == 2 {
        store.mark_device_signing_v2(&device.id)?;
    }
    write_device_audit_if_available(
        context,
        &mut store,
        project_id,
        "DEVICE_ADD",
        "device add",
        &device,
        user_verification,
    )?;

    writeln!(output, "device: added")?;
    writeln!(output, "name: {}", device.name)?;
    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn device_list_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DeviceListArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let devices = store.list_devices(project_id, args.all)?;
    if devices.is_empty() {
        writeln!(output, "devices: none")?;
    } else {
        writeln!(output, "devices:")?;
        for device in devices {
            let state = if device.revoked_at.is_some() { "revoked" } else { "active" };
            let local = if device.local { " local" } else { "" };
            writeln!(
                output,
                "- {} id={} fingerprint={} state={}{}",
                device.name, device.id, device.fingerprint, state, local
            )?;
        }
    }
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn device_remove_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DeviceRemoveArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let device = store
        .find_device(project_id, &args.device)?
        .ok_or_else(|| invalid_reference_error("device not found"))?;
    if locket_agent::team_sync::status(&store, project_id)
        .map_err(|error| metadata_invalid_error(error.to_string()))?
        .owner_fingerprint
        .is_some()
    {
        if device.local {
            return Err(access_denied_error(
                "this device has pinned team history; disable updates with `locket team sync disable`. Identity replacement requires fresh-device onboarding in a separate store",
            ));
        }
        let team = store
            .get_team_by_project(project_id)?
            .ok_or_else(|| metadata_invalid_error("team missing"))?;
        let member = store
            .get_team_member_by_device(&team.id, &device.id)?
            .ok_or_else(|| metadata_invalid_error("device has no team membership"))?;
        return super::sync::remove_authenticated(
            context, output, &mut store, project_id, &member.id,
        );
    }
    if device.local && !args.force {
        return Err(access_denied_error("removing the active local device requires --force"));
    }
    if device.revoked_at.is_some() {
        writeln!(output, "device: already revoked")?;
        writeln!(output, "device_id: {}", device.id)?;
        writeln!(output, "metadata_only: yes")?;
        return Ok(());
    }
    store.revoke_device(project_id, &device.id, now_unix_nanos()?)?;
    write_device_audit_if_available(
        context,
        &mut store,
        project_id,
        "DEVICE_REVOKE",
        "device remove",
        &device,
        UserVerificationAudit::not_required(),
    )?;
    // Local-device revocation also drops the wrapped private-key envelope.
    // We only ever held a private key for the local device; remote teammate
    // device records never have an envelope to clean up.
    if device.local {
        let storage = build_device_private_key_storage(context, project_id)?;
        let _ = storage.delete(&device.id);
    }
    writeln!(output, "device: revoked")?;
    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

/// Best-effort delete of a wrapped-local-file device private-key envelope when
/// the revoked device row was the active local device.
///
/// Sibling commands (e.g. `team revoke-device`) use this to keep the local
/// envelope store consistent with the `team_devices` table. Remote teammate
/// device records never have an envelope on this host, so callers should pass
/// `device.local` as the gate.
pub(super) fn cleanup_local_device_envelope_if_local(
    context: &RuntimeContext,
    project_id: &str,
    device: &DeviceRecord,
) -> Result<(), CliError> {
    if !device.local {
        // Remote teammate device record: we never had its private key on this
        // host; nothing to delete.
        return Ok(());
    }
    let storage = build_device_private_key_storage(context, project_id)?;
    let _ = storage.delete(&device.id);
    Ok(())
}

struct GeneratedLocalDevice {
    record: DeviceRecord,
    signing_private_key: zeroize::Zeroizing<[u8; 32]>,
    sealing_private_key: zeroize::Zeroizing<[u8; 32]>,
}

fn generate_local_device_record(
    project_id: &str,
    timestamp: i64,
) -> Result<GeneratedLocalDevice, CliError> {
    let signing_seed = generate_key()?;
    let signing_public_key =
        ed25519_dalek::SigningKey::from_bytes(&signing_seed).verifying_key().to_bytes();
    let mut signing_private_key = zeroize::Zeroizing::new([0_u8; 32]);
    signing_private_key.copy_from_slice(signing_seed.as_ref());
    let sealing_seed = generate_key()?;
    let sealing_secret = X25519StaticSecret::from(*sealing_seed);
    let sealing_public_key = X25519PublicKey::from(&sealing_secret);
    let mut sealing_private_key = zeroize::Zeroizing::new([0_u8; 32]);
    sealing_private_key.copy_from_slice(sealing_secret.as_bytes());
    let sealing_public_bytes = sealing_public_key.to_bytes();
    let fingerprint = device_fingerprint_hex(&signing_public_key, &sealing_public_bytes);
    let device_name = default_device_name();
    let record = DeviceRecord {
        id: DeviceId::generate()
            .map_err(|_| corrupt_db_error("device id generation failed"))?
            .into_string(),
        project_id: project_id.to_owned(),
        member_id: None,
        // Local device records mirror `name` into `label` until a
        // dedicated label flow exists. See data-model.md lines 254-265.
        label: device_name.clone(),
        name: device_name,
        signing_public_key: signing_public_key.to_vec(),
        sealing_public_key: sealing_public_bytes.to_vec(),
        safety_words: safety_words_from_fingerprint(&fingerprint),
        fingerprint,
        local: true,
        created_at: timestamp,
        last_seen_at: Some(timestamp),
        revoked_at: None,
    };
    Ok(GeneratedLocalDevice { record, signing_private_key, sealing_private_key })
}

pub fn device_private_key_root(context: &RuntimeContext) -> Result<PathBuf, CliError> {
    context
        .store_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| corrupt_db_error("could not resolve device private key root"))
}

pub fn build_device_private_key_storage(
    context: &RuntimeContext,
    project_id: &str,
) -> Result<WrappedLocalFileDevicePrivateKeyStorage, CliError> {
    Ok(WrappedLocalFileDevicePrivateKeyStorage::new(
        device_private_key_root(context)?,
        project_id.to_owned(),
        std::sync::Arc::new(DeviceMasterKey {
            project: project_id.to_owned(),
            key: crate::runtime::key_access::load_master_key(context, project_id)?.0,
        }),
    ))
}

// Reuse the CLI's verified passphrase/keychain cache for private envelopes.
// The agent never exports its cache to this process.
struct DeviceMasterKey {
    project: String,
    key: zeroize::Zeroizing<locket_crypto::KeyBytes>,
}
impl locket_platform::MasterKeyStore for DeviceMasterKey {
    fn load_master_key(
        &self,
        project: &str,
    ) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, PlatformError> {
        if project != self.project {
            return Err(PlatformError::MasterKeyNotFound);
        }
        Ok(self.key.clone())
    }
    fn store_master_key(&self, _: &str, _: &locket_crypto::KeyBytes) -> Result<(), PlatformError> {
        Err(PlatformError::InvalidMasterKey)
    }
    fn delete_master_key(&self, _: &str) -> Result<(), PlatformError> {
        Err(PlatformError::InvalidMasterKey)
    }
}

/// Prepare a receiver with project/audit keys only. Shared keys arrive from its owner.
pub fn join_request(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project = resolved.config.project_id.as_str();
    if let Some(device) = store.get_active_local_device(project)? {
        require_v2_signing(&store, &device)?;
        return write_device_init_summary(
            output,
            "ready for team join",
            &device,
            Some(&encode_device_descriptor(&device)?),
        );
    }
    let now = now_unix_nanos()?;
    let existing = store.get_project(project)?.is_some();
    let has_fallback = context.passphrase_store.contains_project(project)?;
    let master = if existing || has_fallback {
        crate::runtime::key_access::load_master_key(context, project)?.0
    } else {
        if recovery_envelope_present(&resolved.root) {
            return Err(ambiguous_bootstrap_state_error(true, false));
        }
        match context.key_store.load_master_key(project) {
            Ok(key) => key,
            Err(PlatformError::MasterKeyNotFound) => {
                let key = generate_key()?;
                let source = store_master_key_with_fallback(context, project, &key, now)?;
                context.master_key_cache.insert(project, key.clone(), source);
                key
            }
            Err(error) => return Err(error.into()),
        }
    };
    store.with_atomic_write::<_, CliError>(|store| {
        store.insert_project_if_absent(project, &resolved.config.name, now)?;
        for purpose in [KeyPurpose::ProjectMetadata, KeyPurpose::Audit] {
            if store.get_key_by_scope(project, None, purpose.as_str())?.is_none() {
                insert_wrapped_key(store, project, None, purpose, &master, now)?;
            }
        }
        Ok(())
    })?;
    let GeneratedLocalDevice { record, signing_private_key, sealing_private_key } =
        generate_local_device_record(project, now)?;
    let storage = build_device_private_key_storage(context, project)?;
    storage.store(&record.id, &sealing_private_key)?;
    storage.for_signing().store(&record.fingerprint, &signing_private_key)?;
    store.insert_device(&record)?;
    store.mark_device_signing_v2(&record.id)?;
    trust_root(&store, &resolved.config, &resolved.root, now)?;
    let material = create_bootstrap_recovery_material(&resolved.root, now)?;
    let material = BootstrapRecoveryMaterial { master_key: master, ..material };
    save_bootstrap_recovery_envelope_with_device(
        &resolved.root,
        &resolved.config,
        &material,
        &record,
        &signing_private_key,
        &sealing_private_key,
        now,
    )?;
    display_bootstrap_recovery_code(context, output, &resolved.config, &material.code_bytes)?;
    write_device_init_summary(
        output,
        "ready for team join",
        &record,
        Some(&encode_device_descriptor(&record)?),
    )
}

pub fn encode_device_descriptor(device: &DeviceRecord) -> Result<String, CliError> {
    let descriptor = DeviceDescriptorV1 {
        v: 2,
        device_id: device.id.clone(),
        label: device.name.clone(),
        signing_public_key_ed25519: BASE64URL_NOPAD.encode(&device.signing_public_key),
        sealing_public_key_x25519: BASE64URL_NOPAD.encode(&device.sealing_public_key),
        fingerprint_sha256: device.fingerprint.clone(),
        safety_words: device.safety_words.clone(),
    };
    let json = serde_json::to_vec(&descriptor)?;
    Ok(format!("lkdev2_{}", BASE64URL_NOPAD.encode(&json)))
}

pub fn decode_device_descriptor(value: &str) -> Result<DeviceDescriptorV1, CliError> {
    let (encoded, version) = if let Some(encoded) = value.strip_prefix("lkdev2_") {
        (encoded, 2)
    } else if let Some(encoded) = value.strip_prefix("lkdev1_") {
        (encoded, 1)
    } else {
        return Err(metadata_invalid_error(
            "device descriptor must start with lkdev2_ or legacy lkdev1_",
        ));
    };
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| metadata_invalid_error("device descriptor is not valid base64url"))?;
    let descriptor: DeviceDescriptorV1 = serde_json::from_slice(&bytes)?;
    if descriptor.v != version {
        return Err(metadata_invalid_error("unsupported device descriptor version"));
    }
    DeviceId::new(descriptor.device_id.clone())
        .map_err(|_| metadata_invalid_error("device descriptor id is invalid"))?;
    Ok(descriptor)
}

pub struct VerifiedDeviceDescriptor {
    pub descriptor: DeviceDescriptorV1,
    pub signing_public_key: [u8; 32],
    pub sealing_public_key: [u8; 32],
    pub fingerprint: String,
}

pub fn decode_verified_device_descriptor(
    value: &str,
    label: &str,
) -> Result<VerifiedDeviceDescriptor, CliError> {
    let descriptor = decode_device_descriptor(value)?;
    let signing_public_key = decode_descriptor_key(&descriptor.signing_public_key_ed25519)?;
    let sealing_public_key = decode_descriptor_key(&descriptor.sealing_public_key_x25519)?;
    let fingerprint = device_fingerprint_hex(&signing_public_key, &sealing_public_key);
    if fingerprint != descriptor.fingerprint_sha256 {
        return Err(metadata_invalid_error(format!("{label} fingerprint mismatch")));
    }
    Ok(VerifiedDeviceDescriptor { descriptor, signing_public_key, sealing_public_key, fingerprint })
}

pub fn decode_descriptor_key(value: &str) -> Result<[u8; 32], CliError> {
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| metadata_invalid_error("device descriptor key is not valid base64url"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        metadata_invalid_error(format!(
            "device descriptor key must be 32 bytes, got {}",
            bytes.len()
        ))
    })
}

pub fn device_fingerprint_hex(
    signing_public_key: &[u8; 32],
    sealing_public_key: &[u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"locket-device-v1");
    hasher.update(32_u16.to_le_bytes());
    hasher.update(signing_public_key);
    hasher.update(32_u16.to_le_bytes());
    hasher.update(sealing_public_key);
    format_hex(&hasher.finalize())
}

pub(super) fn safety_words_from_fingerprint(fingerprint: &str) -> Vec<String> {
    safety_words_from_fingerprint_hex(fingerprint).into_iter().map(str::to_owned).collect()
}

fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "local-device".to_owned())
}

fn validate_device_name(name: &str) -> Result<(), CliError> {
    if name.trim().is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(metadata_invalid_error("invalid device name"));
    }
    Ok(())
}

fn write_device_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    project_id: &str,
    action: &'static str,
    command: &'static str,
    device: &DeviceRecord,
    user_verification: UserVerificationAudit,
) -> Result<(), CliError> {
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    let metadata = device_audit_metadata(action, command, device, user_verification);
    let timestamp = now_unix_nanos()?;
    let audit = device_audit_write(project_id, action, command, &metadata, timestamp);
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn replace_local_device_with_audit(
    context: &RuntimeContext,
    store: &mut Store,
    project_id: &str,
    existing: &DeviceRecord,
    replacement: &DeviceRecord,
    user_verification: UserVerificationAudit,
    timestamp: i64,
) -> Result<(), CliError> {
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    let revoke_metadata =
        device_audit_metadata("DEVICE_REVOKE", "device init --force", existing, user_verification);
    let add_metadata =
        device_audit_metadata("DEVICE_ADD", "device init --force", replacement, user_verification);
    let revoke_audit = device_audit_write(
        project_id,
        "DEVICE_REVOKE",
        "device init --force",
        &revoke_metadata,
        timestamp,
    );
    let add_audit = device_audit_write(
        project_id,
        "DEVICE_ADD",
        "device init --force",
        &add_metadata,
        timestamp,
    );
    let replaced = store.replace_local_device(
        project_id,
        &existing.id,
        timestamp,
        replacement,
        Some(AuditContext { key: audit_key.as_ref(), write: &revoke_audit }),
        Some(AuditContext { key: audit_key.as_ref(), write: &add_audit }),
    )?;
    if !replaced {
        return Err(invalid_reference_error("local device is not initialized"));
    }
    Ok(())
}

fn device_audit_metadata(
    action: &'static str,
    command: &'static str,
    device: &DeviceRecord,
    user_verification: UserVerificationAudit,
) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "action": action,
        "status": "SUCCESS",
        "command": command,
        "device_id": device.id,
        "device_name": device.name,
        "fingerprint": device.fingerprint,
        "local": device.local,
        "user_verification": user_verification,
    })
}

const fn device_audit_write<'a>(
    project_id: &'a str,
    action: &'static str,
    command: &'static str,
    metadata: &'a serde_json::Value,
    timestamp: i64,
) -> AuditWrite<'a> {
    AuditWrite {
        project_id,
        profile_id: None,
        action,
        status: "SUCCESS",
        secret_name: None,
        command: Some(command),
        metadata_json: metadata,
        timestamp,
    }
}

/// Detects whether `device init` is the first invocation on this machine and,
/// if so, bootstraps the local master key, recovery envelope, recovery code,
/// and project records before the regular `device init` flow proceeds.
///
/// Returns `Ok(true)` when the bootstrap was performed, `Ok(false)` when the
/// existing-master-key path applies, and an `AmbiguousBootstrapState`-flavored
/// error (mapped to `LostKeychainEntry`) when partial state is detected.
fn maybe_bootstrap_first_run_on_machine(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    timestamp: i64,
) -> Result<Option<BootstrapRecoveryMaterial>, CliError> {
    let project_id = resolved.config.project_id.as_str();
    match context.key_store.load_master_key(project_id) {
        Ok(_) => Ok(None),
        Err(PlatformError::MasterKeyNotFound) => {
            if context.passphrase_store.contains_project(project_id)? {
                return Ok(None);
            }
            let envelope_present = recovery_envelope_present(&resolved.root);
            let team_row_present =
                store.get_project(project_id)?.is_some() && team_row_exists(store, project_id)?;
            if envelope_present || team_row_present {
                return Err(ambiguous_bootstrap_state_error(envelope_present, team_row_present));
            }
            let material = bootstrap_first_run_on_machine(context, store, resolved, timestamp)?;
            Ok(Some(material))
        }
        Err(error) => Err(CliError::Platform(error)),
    }
}

fn recovery_envelope_present(root: &Path) -> bool {
    let recovery_dir = root.join(".locket").join("recovery");
    recovery_dir.join("envelope.bin").exists() || recovery_dir.join("kdf.toml").exists()
}

fn team_row_exists(store: &Store, project_id: &str) -> Result<bool, CliError> {
    Ok(store.get_team_by_project(project_id)?.is_some())
}

fn ambiguous_bootstrap_state_error(envelope_present: bool, team_row_present: bool) -> CliError {
    let message = match (envelope_present, team_row_present) {
        (true, true) => {
            "ambiguous bootstrap state: recovery envelope and team membership both present \
             without a local master key; run `locket recover` to restore the keychain entry, \
             or `locket team accept` if you have a fresh invite"
        }
        (true, false) => {
            "ambiguous bootstrap state: recovery envelope is present but the local master key \
             is missing; run `locket recover` to restore the keychain entry"
        }
        (false, true) => {
            "ambiguous bootstrap state: a team record exists for this project but no local \
             master key is present; run `locket team accept <invite>` or `locket recover`"
        }
        (false, false) => {
            "ambiguous bootstrap state: master key is missing and partial state was detected"
        }
    };
    typed_cli_error(LocketError::LostKeychainEntry, message)
}

/// Performs the first-run-on-machine bootstrap for `device init`.
///
/// This is invoked when no local master key exists and no partial state
/// (recovery envelope, team membership) is detected. It generates a fresh
/// master key, persists it via the configured master-key store with passphrase
/// fallback, creates the project records, project key material, recovery
/// envelope, and displays the recovery code under the same one-time-display
/// rules used by `locket init`.
fn bootstrap_first_run_on_machine(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    timestamp: i64,
) -> Result<BootstrapRecoveryMaterial, CliError> {
    let config = &resolved.config;
    let project_id = config.project_id.as_str();

    ensure_project_metadata(store, config, timestamp)?;

    let master_key = generate_key()?;
    store_master_key_with_fallback(context, project_id, &master_key, timestamp)?;

    insert_wrapped_key(
        store,
        project_id,
        None,
        KeyPurpose::ProjectMetadata,
        &master_key,
        timestamp,
    )?;
    insert_wrapped_key(store, project_id, None, KeyPurpose::Audit, &master_key, timestamp)?;

    let profile = store
        .get_profile_by_name(project_id, config.default_profile.as_str())?
        .ok_or_else(|| corrupt_db_error("default profile is missing after bootstrap"))?;
    insert_wrapped_key(
        store,
        project_id,
        Some(&profile.id),
        KeyPurpose::ProfileSecret,
        &master_key,
        timestamp,
    )?;
    insert_wrapped_key(
        store,
        project_id,
        Some(&profile.id),
        KeyPurpose::ProfileFingerprint,
        &master_key,
        timestamp,
    )?;

    let bootstrap_recovery = create_bootstrap_recovery_material(&resolved.root, timestamp)?;

    trust_root(store, config, &resolved.root, timestamp)?;

    write_bootstrap_audit(context, store, resolved, &profile.id, timestamp)?;

    Ok(BootstrapRecoveryMaterial { master_key, ..bootstrap_recovery })
}

struct BootstrapRecoveryMaterial {
    code_bytes: [u8; locket_crypto::RECOVERY_CODE_BYTES],
    kdf: RecoveryKdfToml,
    recovery_root: locket_crypto::KeyBytes,
    master_key: zeroize::Zeroizing<locket_crypto::KeyBytes>,
}

fn create_bootstrap_recovery_material(
    root: &Path,
    timestamp: i64,
) -> Result<BootstrapRecoveryMaterial, CliError> {
    let recovery_dir = root.join(".locket").join("recovery");
    let code_bytes = generate_recovery_code_bytes()?;
    let salt = generate_recovery_salt()?;
    let kdf_profile_id = format!("lk_kdf_{}", format_hex(&salt[..16]));
    let kdf = RecoveryKdfToml::new_v1(kdf_profile_id, &salt, timestamp);
    let recovery_root = derive_recovery_key_v1(&code_bytes, &salt, kdf.to_crypto_params())?;
    save_recovery_kdf_toml(&recovery_dir, &kdf)
        .map_err(|error| metadata_invalid_error(format!("save recovery kdf: {error}")))?;
    Ok(BootstrapRecoveryMaterial {
        code_bytes,
        kdf,
        recovery_root: *recovery_root,
        master_key: zeroize::Zeroizing::new([0_u8; locket_crypto::KEY_LEN]),
    })
}

fn save_bootstrap_recovery_envelope_with_device(
    root: &Path,
    config: &ProjectConfig,
    material: &BootstrapRecoveryMaterial,
    device: &DeviceRecord,
    signing_private_key: &locket_crypto::KeyBytes,
    sealing_private_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<(), CliError> {
    let recovery_dir = root.join(".locket").join("recovery");
    let envelope = RecoveryEnvelope {
        kdf_profile_id: material.kdf.kdf_profile_id.clone(),
        created_at_unix_nanos: i128::from(timestamp),
        entries: recovery_entries_for_device(
            &material.recovery_root,
            &material.kdf.kdf_profile_id,
            config.project_id.as_str(),
            material.master_key.as_ref(),
            device,
            signing_private_key,
            sealing_private_key,
        )?,
    };
    locket_platform::save_recovery_state(&recovery_dir, &material.kdf, &envelope)
        .map_err(|error| metadata_invalid_error(format!("save recovery envelope: {error}")))?;
    Ok(())
}

fn recovery_entries_for_device(
    recovery_root: &locket_crypto::KeyBytes,
    kdf_profile_id: &str,
    project_id: &str,
    master_key: &[u8],
    device: &DeviceRecord,
    signing_private_key: &locket_crypto::KeyBytes,
    sealing_private_key: &locket_crypto::KeyBytes,
) -> Result<Vec<locket_platform::RecoveryEnvelopeEntry>, CliError> {
    Ok(vec![
        seal_recovery_envelope_entry(
            recovery_root,
            kdf_profile_id,
            "master_key",
            project_id,
            master_key,
        )?,
        seal_recovery_envelope_entry(
            recovery_root,
            kdf_profile_id,
            "device_signing_private_key",
            &device.id,
            signing_private_key,
        )?,
        seal_recovery_envelope_entry(
            recovery_root,
            kdf_profile_id,
            "device_sealing_private_key",
            &device.id,
            sealing_private_key,
        )?,
    ])
}

fn update_recovery_envelope_for_replacement_device(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    device: &DeviceRecord,
    signing_private_key: &locket_crypto::KeyBytes,
    sealing_private_key: &locket_crypto::KeyBytes,
) -> Result<(), CliError> {
    let recovery_dir = resolved.root.join(".locket").join("recovery");
    if !recovery_dir.join("envelope.bin").exists() {
        return Ok(());
    }
    let kdf = load_recovery_kdf_toml(&recovery_dir)
        .map_err(|error| metadata_invalid_error(format!("recovery/kdf.toml: {error}")))?;
    let old_envelope = load_recovery_envelope(&recovery_dir)
        .map_err(|error| metadata_invalid_error(format!("recovery/envelope.bin: {error}")))?;
    let code = context.recovery_code_reader.read_recovery_code("current recovery code")?;
    let code_bytes = crate::recovery_code_decode(code.trim())?;
    let salt = kdf
        .decode_salt()
        .map_err(|error| metadata_invalid_error(format!("recovery kdf salt: {error}")))?;
    let recovery_root = derive_recovery_key_v1(&code_bytes, &salt, kdf.to_crypto_params())?;
    let master_entry = old_envelope
        .entries
        .iter()
        .find(|entry| {
            entry.entry_kind == "master_key"
                && entry.entry_id == resolved.config.project_id.as_str()
        })
        .ok_or_else(|| metadata_invalid_error("recovery envelope missing master_key entry"))?;
    let _ = open_recovery_entry_v1(
        &recovery_root,
        &kdf.kdf_profile_id,
        &master_entry.entry_kind,
        &master_entry.entry_id,
        &master_entry.nonce,
        &master_entry.ciphertext,
    )?;
    let mut entries = Vec::with_capacity(old_envelope.entries.len() + 2);
    for entry in &old_envelope.entries {
        if matches!(
            entry.entry_kind.as_str(),
            "device_signing_private_key" | "device_sealing_private_key"
        ) {
            continue;
        }
        entries.push(entry.clone());
    }
    entries.push(seal_recovery_envelope_entry(
        &recovery_root,
        &kdf.kdf_profile_id,
        "device_signing_private_key",
        &device.id,
        signing_private_key,
    )?);
    entries.push(seal_recovery_envelope_entry(
        &recovery_root,
        &kdf.kdf_profile_id,
        "device_sealing_private_key",
        &device.id,
        sealing_private_key,
    )?);
    let new_envelope = RecoveryEnvelope {
        kdf_profile_id: kdf.kdf_profile_id,
        created_at_unix_nanos: old_envelope.created_at_unix_nanos,
        entries,
    };
    save_recovery_envelope(&recovery_dir, &new_envelope)
        .map_err(|error| metadata_invalid_error(format!("save recovery envelope: {error}")))?;
    Ok(())
}

fn display_bootstrap_recovery_code(
    context: &RuntimeContext,
    output: &mut impl Write,
    config: &ProjectConfig,
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
) -> Result<(), CliError> {
    let code = formatted_recovery_code(code_bytes)?;
    if style::enabled() {
        style::write_banner(output, "device bootstrap", "recovery-code shown once")?;
        style::write_kv(output, "device_init_bootstrap", "success")?;
        writeln!(output, "  {}", style::paint(Tone::Secret, &code))?;
        writeln!(
            output,
            "  {} {}",
            style::paint(Tone::Warn, "warning"),
            style::paint(Tone::Value, "terminal scrollback may retain this code")
        )?;
        writeln!(
            output,
            "  {}",
            style::paint(
                Tone::Muted,
                format!("type project name '{}' after recording the recovery code", config.name)
            )
        )?;
    } else {
        writeln!(output, "device_init_bootstrap: success")?;
        writeln!(output, "recovery_code (shown once, store securely):")?;
        writeln!(output, "{code}")?;
        writeln!(output, "Write this down. It will not be shown again.")?;
        writeln!(output, "warning: terminal scrollback may retain this code")?;
        writeln!(output, "type project name '{}' after recording the recovery code", config.name)?;
    }
    let confirmation =
        context.confirmation_reader.read_confirmation("device init recovery code")?;
    if confirmation.trim_end_matches(['\r', '\n']) != config.name {
        return Err(confirmation_failed_error("confirmation did not match project name"));
    }
    if io::stdout().is_terminal() {
        let _ = io::stdout().write_all(b"\x1b[2J\x1b[H");
    }
    Ok(())
}

fn write_bootstrap_audit(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    default_profile_id: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let project_id = resolved.config.project_id.as_str();
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "BOOTSTRAP",
        "status": "SUCCESS",
        "command": "device init",
        "project_id": project_id,
        "default_profile_id": default_profile_id,
        "generated_files": Vec::<&str>::new(),
        "recovery_code_displayed": true,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: Some(default_profile_id),
        action: "BOOTSTRAP",
        status: "SUCCESS",
        secret_name: None,
        command: Some("device init"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceDescriptorV1 {
    pub v: u16,
    pub device_id: String,
    pub label: String,
    pub signing_public_key_ed25519: String,
    pub sealing_public_key_x25519: String,
    pub fingerprint_sha256: String,
    pub safety_words: Vec<String>,
}

pub fn require_v2_signing(store: &Store, device: &DeviceRecord) -> Result<(), CliError> {
    if !store.device_signing_is_v2(&device.id)? {
        return Err(access_denied_error(
            "legacy signing seed was exposed; run `locket device rotate-signing` before publishing a descriptor or issuing invites",
        ));
    }
    Ok(())
}

pub fn load_device_signing_key(
    context: &RuntimeContext,
    store: &Store,
    device: &DeviceRecord,
) -> Result<ed25519_dalek::SigningKey, CliError> {
    require_v2_signing(store, device)?;
    let seed = build_device_private_key_storage(context, &device.project_id)?
        .for_signing()
        .load(&device.fingerprint)?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    if key.verifying_key().as_bytes().as_slice() != device.signing_public_key {
        return Err(corrupt_db_error("protected signing key does not match device public key"));
    }
    Ok(key)
}

pub fn rotate_signing_identity(
    context: &RuntimeContext,
    store: &mut Store,
    device: &DeviceRecord,
) -> Result<DeviceRecord, CliError> {
    let seed = generate_key()?;
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let sealing: [u8; 32] = device
        .sealing_public_key
        .as_slice()
        .try_into()
        .map_err(|_| corrupt_db_error("invalid sealing key"))?;
    let fingerprint = device_fingerprint_hex(&public, &sealing);
    let words = safety_words_from_fingerprint(&fingerprint);
    let storage = build_device_private_key_storage(context, &device.project_id)?.for_signing();
    storage.store(&fingerprint, &seed)?;
    if let Err(error) =
        store.rotate_device_signing(device, &public, &fingerprint, &words, now_unix_nanos()?)
    {
        let _ = storage.delete(&fingerprint);
        return Err(error.into());
    }
    store
        .get_active_local_device(&device.project_id)?
        .ok_or_else(|| corrupt_db_error("rotated device missing"))
}

fn refuse_anchored_identity_change(store: &Store, project: &str) -> Result<(), CliError> {
    if locket_agent::team_sync::status(store, project)
        .map_err(|error| metadata_invalid_error(error.to_string()))?
        .owner_fingerprint
        .is_some()
    {
        return Err(access_denied_error(
            "this device has pinned team history; automatic identity handover is unsupported. Prepare and verify a new device in a separate store before retiring this identity",
        ));
    }
    Ok(())
}

fn device_rotate_signing_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let device = store
        .get_active_local_device(resolved.config.project_id.as_str())?
        .ok_or_else(|| invalid_reference_error("local device is not initialized"))?;
    refuse_anchored_identity_change(&store, &device.project_id)?;
    require_user_verification(
        context,
        "device rotate-signing",
        "Rotate exposed device signing key",
    )?;
    let storage = build_device_private_key_storage(context, &device.project_id)?;
    let sealing = storage.load(&device.id)?;
    if X25519PublicKey::from(&X25519StaticSecret::from(*sealing)).as_bytes().as_slice()
        != device.sealing_public_key
    {
        return Err(corrupt_db_error("device sealing key mismatch"));
    }
    let rotated = rotate_signing_identity(context, &mut store, &device)?;
    write_device_init_summary(
        output,
        "signing key rotated; sealing key preserved",
        &rotated,
        Some(&encode_device_descriptor(&rotated)?),
    )?;
    writeln!(output, "pending_invites: revoked; reissue invites with the new fingerprint")?;
    writeln!(output, "recovery: run `locket recovery rotate` to back up the new signing key")?;
    Ok(())
}

#[cfg(test)]
mod signing_safety_tests {
    use super::*;

    #[test]
    fn generated_identity_publishes_verifying_key_not_seed()
    -> Result<(), Box<dyn std::error::Error>> {
        let generated = generate_local_device_record("project-test", 1)?;
        let expected = ed25519_dalek::SigningKey::from_bytes(&generated.signing_private_key)
            .verifying_key()
            .to_bytes();
        assert_eq!(generated.record.signing_public_key, expected);
        assert_ne!(generated.record.signing_public_key, *generated.signing_private_key);
        assert!(encode_device_descriptor(&generated.record)?.starts_with("lkdev2_"));
        Ok(())
    }
    #[test]
    fn legacy_rotation_preserves_sealing_and_rejects_disclosed_signer()
    -> Result<(), Box<dyn std::error::Error>> {
        use clap::Parser;
        let directory = tempfile::tempdir()?;
        let context = crate::tests::test_context(&directory);
        crate::run_with_context(
            crate::Cli::try_parse_from(["locket", "init", "--name", "app"])?,
            &context,
            &mut Vec::new(),
        )?;
        let resolved = require_project(&context)?;
        let project = resolved.config.project_id.as_str();
        let mut store = open_store(&context)?;
        let device =
            store.get_active_local_device(project)?.ok_or("active local device missing")?;
        let storage = build_device_private_key_storage(&context, project)?;
        let sealing = storage.load(&device.id)?;
        let leaked = [17_u8; 32];
        let seal_pub: [u8; 32] = device.sealing_public_key.as_slice().try_into()?;
        let legacy_fp = device_fingerprint_hex(&leaked, &seal_pub);
        store.connection().execute(
            "UPDATE devices SET signing_public_key = ?1, fingerprint = ?2 WHERE id = ?3",
            rusqlite::params![leaked.as_slice(), legacy_fp, device.id],
        )?;
        store
            .connection()
            .execute("DELETE FROM device_signing_versions WHERE device_id = ?1", [&device.id])?;
        let legacy =
            store.get_active_local_device(project)?.ok_or("active local device missing")?;
        assert!(active_local_device_descriptor(&context).is_err());
        assert!(load_device_signing_key(&context, &store, &legacy).is_err());
        let ciphertext =
            locket_core::encrypt_bundle_payload_for_age_recipients(b"old bundle", &[seal_pub])?;
        let rotated = rotate_signing_identity(&context, &mut store, &legacy)?;
        assert_eq!(rotated.id, legacy.id);
        assert_eq!(rotated.sealing_public_key, legacy.sealing_public_key);
        assert_ne!(
            rotated.signing_public_key,
            ed25519_dalek::SigningKey::from_bytes(&leaked).verifying_key().as_bytes()
        );
        assert_eq!(*storage.load(&device.id)?, *sealing);
        assert_eq!(
            locket_core::decrypt_bundle_payload_with_x25519_secret(&ciphertext, &sealing)?
                .as_slice(),
            b"old bundle"
        );
        assert!(store.device_matches_bundle_recipient(&rotated, &legacy_fp)?);
        let signer = load_device_signing_key(&context, &store, &rotated)?;
        assert_eq!(signer.verifying_key().as_bytes().as_slice(), rotated.signing_public_key);
        assert!(active_local_device_descriptor(&context)?.1.starts_with("lkdev2_"));
        Ok(())
    }
}
