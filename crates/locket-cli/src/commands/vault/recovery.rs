use data_encoding::BASE64URL_NOPAD;
use locket_core::LocketError;
use locket_crypto::{KeyPurpose, derive_recovery_key_v1, open_recovery_entry_v1, wrap_dek_v1};
use locket_platform::{
    LocalDevicePrivateKeyStorage, RecoveryEnvelope, RecoveryEnvelopeEntry, RecoveryKdfToml,
    load_recovery_envelope, load_recovery_kdf_toml, save_recovery_state, secure_directory,
    write_user_only_file,
};
use locket_store::AuditWrite;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use crate::runtime::error::typed_cli_error;
use crate::runtime::user_verification::{UserVerificationAudit, require_user_verification};
use crate::{
    CliError, RecoverArgs, RecoveryCommand, ResolvedProject, RuntimeContext, format_hex,
    formatted_recovery_code, generate_recovery_code_bytes, generate_recovery_salt, load_master_key,
    load_project_key, metadata_invalid_error, now_unix_nanos, open_store, recovery_code_decode,
    require_project, seal_recovery_envelope_entry,
};

const AUTOMATION_CLIENT_PRIVATE_KEY_ENTRY_KIND: &str = "automation_client_private_key";
const AUTOMATION_CLIENT_PRIVATE_KEY_PREFIX: &str = "automation_client_private_key:";
const DEVICE_SIGNING_PRIVATE_KEY_ENTRY_KIND: &str = "device_signing_private_key";
const DEVICE_SEALING_PRIVATE_KEY_ENTRY_KIND: &str = "device_sealing_private_key";

pub fn recover_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &RecoverArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let recovery_dir = recovery_dir(&resolved);
    let kdf = load_recovery_kdf_toml(&recovery_dir)
        .map_err(|error| metadata_invalid_error(format!("recovery/kdf.toml: {error}")))?;
    let envelope = load_recovery_envelope(&recovery_dir)
        .map_err(|error| metadata_invalid_error(format!("recovery/envelope.bin: {error}")))?;
    let code = context.recovery_code_reader.read_recovery_code("recovery code")?;
    let code_bytes = recovery_code_decode(code.trim())?;
    restore_from_recovery_code(context, output, &resolved, &kdf, &envelope, &code_bytes, args.force)
}

pub fn recovery_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: RecoveryCommand,
) -> Result<(), CliError> {
    match command {
        RecoveryCommand::Rotate => recovery_rotate_command(context, output),
    }
}

pub fn recovery_rotate_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let project_id = resolved.config.project_id.as_str();
    let user_verification =
        require_user_verification(context, "recovery rotate", "Rotate the local recovery code")?;
    let recovery_dir = recovery_dir(&resolved);
    let timestamp = now_unix_nanos()?;
    let code_bytes = generate_recovery_code_bytes()?;
    let salt = generate_recovery_salt()?;
    let kdf_profile_id = format!("lk_kdf_{}", format_hex(&salt[..16]));
    let new_kdf = RecoveryKdfToml::new_v1(kdf_profile_id, &salt, timestamp);
    let new_root = derive_recovery_key_v1(&code_bytes, &salt, new_kdf.to_crypto_params())?;

    let entries = if recovery_dir.join("envelope.bin").exists() {
        let old_kdf = load_recovery_kdf_toml(&recovery_dir)
            .map_err(|error| metadata_invalid_error(format!("recovery/kdf.toml: {error}")))?;
        let old_envelope = load_recovery_envelope(&recovery_dir)
            .map_err(|error| metadata_invalid_error(format!("recovery/envelope.bin: {error}")))?;
        validate_recovery_metadata(project_id, &old_kdf, &old_envelope)?;
        let old_code = context.recovery_code_reader.read_recovery_code("current recovery code")?;
        let old_code_bytes = recovery_code_decode(old_code.trim())?;
        let old_salt = old_kdf
            .decode_salt()
            .map_err(|error| metadata_invalid_error(format!("recovery kdf salt: {error}")))?;
        let old_root =
            derive_recovery_key_v1(&old_code_bytes, &old_salt, old_kdf.to_crypto_params())?;
        let mut entries = rewrap_recovery_entries(
            &old_envelope,
            &old_kdf.kdf_profile_id,
            &old_root,
            &new_kdf,
            &new_root,
        )?;
        replace_device_recovery_entries(context, &resolved, &new_kdf, &new_root, &mut entries)?;
        entries
    } else {
        let (master_key, _source) = load_master_key(context, project_id)?;
        let mut entries = vec![seal_recovery_envelope_entry(
            &new_root,
            &new_kdf.kdf_profile_id,
            "master_key",
            project_id,
            master_key.as_ref(),
        )?];
        replace_device_recovery_entries(context, &resolved, &new_kdf, &new_root, &mut entries)?;
        entries
    };

    let new_envelope = RecoveryEnvelope {
        kdf_profile_id: new_kdf.kdf_profile_id.clone(),
        created_at_unix_nanos: i128::from(timestamp),
        entries,
    };
    display_recovery_code(context, output, &resolved.config.name, &code_bytes)?;
    let mut store = open_store(context)?;
    store.with_atomic_write(|store| {
        write_recovery_rotate_audit(
            context,
            store,
            &resolved,
            &new_kdf.kdf_profile_id,
            timestamp,
            user_verification,
        )?;
        save_recovery_state(&recovery_dir, &new_kdf, &new_envelope)
            .map_err(|error| metadata_invalid_error(format!("save recovery envelope: {error}")))?;
        Ok::<_, CliError>(())
    })?;
    writeln!(output, "recovery_code_rotate: success")?;
    Ok(())
}

pub fn restore_from_recovery_code(
    context: &RuntimeContext,
    output: &mut impl Write,
    resolved: &ResolvedProject,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
    force: bool,
) -> Result<(), CliError> {
    let project_id = resolved.config.project_id.as_str();
    validate_recovery_metadata(project_id, kdf, envelope)?;
    if !force {
        match context.key_store.load_master_key(project_id) {
            Ok(_) => {
                return Err(crate::secret_already_exists_error(
                    "master key already exists; use --force to overwrite",
                ));
            }
            Err(locket_platform::PlatformError::MasterKeyNotFound) => {}
            Err(error) => return Err(CliError::Platform(error)),
        }
    }
    let force_verification = force_recovery_user_verification(context, project_id, force)?;

    let salt = kdf
        .decode_salt()
        .map_err(|error| metadata_invalid_error(format!("recovery kdf salt: {error}")))?;
    let unwrap_root = derive_recovery_key_v1(code_bytes, &salt, kdf.to_crypto_params())?;
    let mut restored = RecoveryRestoreSummary::default();
    for entry in &envelope.entries {
        if entry.entry_kind != "master_key" {
            continue;
        }
        if entry.entry_id != project_id {
            return Err(metadata_invalid_error("recovery envelope project id mismatch"));
        }
        let plaintext = open_recovery_entry_v1(
            &unwrap_root,
            &kdf.kdf_profile_id,
            &entry.entry_kind,
            &entry.entry_id,
            &entry.nonce,
            &entry.ciphertext,
        )?;
        if plaintext.len() != locket_crypto::KEY_LEN {
            return Err(CliError::Crypto(locket_crypto::CryptoError::InvalidWrappedKey));
        }
        let mut master_key = zeroize::Zeroizing::new([0_u8; locket_crypto::KEY_LEN]);
        master_key.copy_from_slice(&plaintext);
        context.key_store.store_master_key(project_id, &master_key)?;
        restored.master += 1;
    }
    if restored.master == 0 {
        return Err(metadata_invalid_error("no master_key entries found in recovery envelope"));
    }
    restore_automation_client_private_keys(
        context,
        resolved,
        kdf,
        envelope,
        &unwrap_root,
        &mut restored,
    )?;
    restore_device_private_keys(context, resolved, kdf, envelope, &unwrap_root, &mut restored)?;
    write_recover_audit(
        context,
        resolved,
        kdf,
        envelope,
        &restored,
        force,
        force_verification.as_ref(),
    )?;
    writeln!(output, "recovered: master_key")?;
    if restored.automation_client_private > 0 || restored.skipped_automation_client_private > 0 {
        writeln!(
            output,
            "recovered: automation_client_private_keys={} skipped={}",
            restored.automation_client_private, restored.skipped_automation_client_private
        )?;
    }
    if restored.device_sealing_private > 0 {
        writeln!(output, "recovered: device_private_keys=1")?;
    }
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

#[derive(Default)]
struct RecoveryRestoreSummary {
    master: usize,
    device_signing_private: usize,
    device_sealing_private: usize,
    automation_client_private: usize,
    skipped_automation_client_private: usize,
}

fn restore_device_private_keys(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
    unwrap_root: &locket_crypto::KeyBytes,
    restored: &mut RecoveryRestoreSummary,
) -> Result<(), CliError> {
    let project_id = resolved.config.project_id.as_str();
    let mut store = open_store(context)?;
    let Some(device) = store.get_active_local_device(project_id)? else {
        return Ok(());
    };
    let signing = open_required_device_recovery_entry(
        envelope,
        unwrap_root,
        kdf,
        DEVICE_SIGNING_PRIVATE_KEY_ENTRY_KIND,
        &device.id,
    )?;
    if signing.len() != locket_crypto::KEY_LEN {
        return Err(CliError::Crypto(locket_crypto::CryptoError::InvalidWrappedKey));
    }
    let mut signing_key = zeroize::Zeroizing::new([0_u8; locket_crypto::KEY_LEN]);
    signing_key.copy_from_slice(&signing);
    let signing_public =
        ed25519_dalek::SigningKey::from_bytes(&signing_key).verifying_key().to_bytes();
    let legacy = !store.device_signing_is_v2(&device.id)?;
    if (legacy && signing.as_slice() != device.signing_public_key.as_slice())
        || (!legacy && signing_public.as_slice() != device.signing_public_key.as_slice())
    {
        // A recovery envelope from before explicit rotation may contain the disclosed seed.
        // It proves sealing-key ownership only; never restore that seed as an active signer.
        let sealing_public: [u8; 32] = device
            .sealing_public_key
            .as_slice()
            .try_into()
            .map_err(|_| metadata_invalid_error("invalid sealing key"))?;
        let old_fingerprint =
            crate::commands::team::device::device_fingerprint_hex(&signing_key, &sealing_public);
        let old_public_fingerprint =
            crate::commands::team::device::device_fingerprint_hex(&signing_public, &sealing_public);
        if !store.device_matches_bundle_recipient(&device, &old_fingerprint)?
            && !store.device_matches_bundle_recipient(&device, &old_public_fingerprint)?
        {
            return Err(metadata_invalid_error("recovery envelope device signing key mismatch"));
        }
    }

    let sealing = open_required_device_recovery_entry(
        envelope,
        unwrap_root,
        kdf,
        DEVICE_SEALING_PRIVATE_KEY_ENTRY_KIND,
        &device.id,
    )?;
    if sealing.len() != locket_crypto::KEY_LEN {
        return Err(CliError::Crypto(locket_crypto::CryptoError::InvalidWrappedKey));
    }
    let mut sealing_key = zeroize::Zeroizing::new([0_u8; locket_crypto::KEY_LEN]);
    sealing_key.copy_from_slice(&sealing);
    let storage =
        crate::commands::team::device::build_device_private_key_storage(context, project_id)?;
    let derived = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*sealing_key));
    if derived.as_bytes().as_slice() != device.sealing_public_key.as_slice() {
        return Err(metadata_invalid_error("recovery envelope device sealing key mismatch"));
    }
    storage.store(&device.id, &sealing_key)?;
    if legacy || signing_public.as_slice() != device.signing_public_key.as_slice() {
        crate::commands::team::device::rotate_signing_identity(context, &mut store, &device)?;
    } else {
        storage.for_signing().store(&device.fingerprint, &signing_key)?;
    }
    restored.device_signing_private += 1;
    restored.device_sealing_private += 1;
    Ok(())
}

fn open_required_device_recovery_entry(
    envelope: &RecoveryEnvelope,
    unwrap_root: &locket_crypto::KeyBytes,
    kdf: &RecoveryKdfToml,
    entry_kind: &str,
    entry_id: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
    let entry = envelope
        .entries
        .iter()
        .find(|entry| entry.entry_kind == entry_kind && entry.entry_id == entry_id)
        .ok_or_else(|| {
            typed_cli_error(
                LocketError::UnrecoverableVault,
                format!("recovery envelope is missing required {entry_kind} entry"),
            )
        })?;
    open_recovery_entry_v1(
        unwrap_root,
        &kdf.kdf_profile_id,
        &entry.entry_kind,
        &entry.entry_id,
        &entry.nonce,
        &entry.ciphertext,
    )
    .map_err(CliError::Crypto)
}

fn restore_automation_client_private_keys(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
    unwrap_root: &locket_crypto::KeyBytes,
    restored: &mut RecoveryRestoreSummary,
) -> Result<(), CliError> {
    let project_id = resolved.config.project_id.as_str();
    let store = open_store(context)?;
    for entry in &envelope.entries {
        let Some(client_id) = automation_client_id_from_recovery_entry(entry) else {
            continue;
        };
        let Some(client) = store.get_automation_client(project_id, client_id)? else {
            restored.skipped_automation_client_private += 1;
            continue;
        };
        if client.revoked_at.is_some() {
            restored.skipped_automation_client_private += 1;
            continue;
        }
        let Some(reference) = store.get_automation_client_private_key_ref(&client.id)? else {
            restored.skipped_automation_client_private += 1;
            continue;
        };
        let Ok(plaintext) = open_recovery_entry_v1(
            unwrap_root,
            &kdf.kdf_profile_id,
            &entry.entry_kind,
            &entry.entry_id,
            &entry.nonce,
            &entry.ciphertext,
        ) else {
            restored.skipped_automation_client_private += 1;
            continue;
        };
        if plaintext.len() != locket_crypto::KEY_LEN {
            restored.skipped_automation_client_private += 1;
            continue;
        }
        let mut private_key = zeroize::Zeroizing::new([0_u8; locket_crypto::KEY_LEN]);
        private_key.copy_from_slice(&plaintext);
        if restore_automation_client_private_key(
            context,
            &store,
            resolved,
            &reference,
            &private_key,
        )
        .is_ok()
        {
            restored.automation_client_private += 1;
        } else {
            restored.skipped_automation_client_private += 1;
        }
    }
    Ok(())
}

fn automation_client_id_from_recovery_entry(entry: &RecoveryEnvelopeEntry) -> Option<&str> {
    if entry.entry_kind == AUTOMATION_CLIENT_PRIVATE_KEY_ENTRY_KIND {
        return Some(entry.entry_id.as_str());
    }
    entry.entry_kind.strip_prefix(AUTOMATION_CLIENT_PRIVATE_KEY_PREFIX)
}

fn restore_automation_client_private_key(
    context: &RuntimeContext,
    store: &locket_store::Store,
    resolved: &ResolvedProject,
    reference: &locket_store::AutomationClientPrivateKeyRefRecord,
    private_key: &locket_crypto::KeyBytes,
) -> Result<(), CliError> {
    match reference.storage.as_str() {
        "os-keychain" => {
            context
                .automation_client_key_store
                .store_client_key(&reference.client_id, private_key)?;
            Ok(())
        }
        "wrapped-local-file" => restore_wrapped_local_client_key(
            context,
            store,
            resolved,
            &reference.client_id,
            private_key,
        ),
        _ => Err(metadata_invalid_error("unsupported automation client private-key storage")),
    }
}

fn restore_wrapped_local_client_key(
    context: &RuntimeContext,
    store: &locket_store::Store,
    resolved: &ResolvedProject,
    client_id: &str,
    private_key: &locket_crypto::KeyBytes,
) -> Result<(), CliError> {
    let path = automation_client_key_path(context, client_id)?;
    let parent = path.parent().ok_or_else(|| crate::corrupt_db_error("invalid client key path"))?;
    secure_directory(parent)?;
    let project_key = load_project_key(
        context,
        store,
        resolved.config.project_id.as_str(),
        KeyPurpose::ProjectMetadata,
    )?;
    let aad = automation_client_private_key_aad(resolved.config.project_id.as_str(), client_id);
    let wrapped_key = wrap_dek_v1(&project_key, private_key, &aad)?;
    let file = json!({
        "schema_version": 1,
        "algorithm": "xchacha20poly1305-key-wrap-v1",
        "project_id": resolved.config.project_id.as_str(),
        "client_id": client_id,
        "wrapped_private_key": BASE64URL_NOPAD.encode(&wrapped_key),
    });
    let contents = serde_json::to_vec_pretty(&file)?;
    write_user_only_file(&path, &contents)?;
    Ok(())
}

fn automation_client_key_path(
    context: &RuntimeContext,
    client_id: &str,
) -> Result<PathBuf, CliError> {
    let parent = context.store_path.parent().ok_or_else(|| {
        crate::corrupt_db_error("could not resolve automation client key directory")
    })?;
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

fn force_recovery_user_verification(
    context: &RuntimeContext,
    project_id: &str,
    force: bool,
) -> Result<Option<UserVerificationAudit>, CliError> {
    if !force {
        return Ok(None);
    }
    match context.key_store.load_master_key(project_id) {
        Ok(_) => require_user_verification(
            context,
            "recover --force",
            "Overwrite an intact recovery target",
        )
        .map(Some),
        Err(locket_platform::PlatformError::MasterKeyNotFound) => Ok(None),
        Err(error) => Err(CliError::Platform(error)),
    }
}

fn validate_recovery_metadata(
    project_id: &str,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
) -> Result<(), CliError> {
    kdf.validate()?;
    if envelope.kdf_profile_id != kdf.kdf_profile_id {
        return Err(metadata_invalid_error("recovery envelope kdf profile mismatch"));
    }
    if !envelope
        .entries
        .iter()
        .any(|entry| entry.entry_kind == "master_key" && entry.entry_id == project_id)
    {
        return Err(metadata_invalid_error(
            "recovery envelope does not contain this project master key",
        ));
    }
    Ok(())
}

fn rewrap_recovery_entries(
    old_envelope: &RecoveryEnvelope,
    old_kdf_profile_id: &str,
    old_root: &locket_crypto::KeyBytes,
    new_kdf: &RecoveryKdfToml,
    new_root: &locket_crypto::KeyBytes,
) -> Result<Vec<RecoveryEnvelopeEntry>, CliError> {
    let mut entries = Vec::with_capacity(old_envelope.entries.len());
    for entry in &old_envelope.entries {
        let plaintext = open_recovery_entry_v1(
            old_root,
            old_kdf_profile_id,
            &entry.entry_kind,
            &entry.entry_id,
            &entry.nonce,
            &entry.ciphertext,
        )?;
        entries.push(seal_recovery_envelope_entry(
            new_root,
            &new_kdf.kdf_profile_id,
            &entry.entry_kind,
            &entry.entry_id,
            &plaintext,
        )?);
    }
    Ok(entries)
}

pub fn replace_device_recovery_entries(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    new_kdf: &RecoveryKdfToml,
    new_root: &locket_crypto::KeyBytes,
    entries: &mut Vec<RecoveryEnvelopeEntry>,
) -> Result<(), CliError> {
    entries.retain(|entry| {
        !matches!(
            entry.entry_kind.as_str(),
            DEVICE_SIGNING_PRIVATE_KEY_ENTRY_KIND | DEVICE_SEALING_PRIVATE_KEY_ENTRY_KIND
        )
    });
    let project_id = resolved.config.project_id.as_str();
    let store = open_store(context)?;
    let Some(device) = store.get_active_local_device(project_id)? else {
        return Ok(());
    };
    if device.revoked_at.is_some() {
        return Ok(());
    }
    let signing_private_key = zeroize::Zeroizing::new(
        crate::commands::team::device::load_device_signing_key(context, &store, &device)?
            .to_bytes(),
    );
    let storage =
        crate::commands::team::device::build_device_private_key_storage(context, project_id)?;
    let sealing_private_key = storage.load(&device.id)?;
    entries.push(seal_recovery_envelope_entry(
        new_root,
        &new_kdf.kdf_profile_id,
        DEVICE_SIGNING_PRIVATE_KEY_ENTRY_KIND,
        &device.id,
        signing_private_key.as_ref(),
    )?);
    entries.push(seal_recovery_envelope_entry(
        new_root,
        &new_kdf.kdf_profile_id,
        DEVICE_SEALING_PRIVATE_KEY_ENTRY_KIND,
        &device.id,
        sealing_private_key.as_ref(),
    )?);
    Ok(())
}

pub fn recovery_dir(resolved: &ResolvedProject) -> PathBuf {
    resolved.root.join(".locket").join("recovery")
}

fn display_recovery_code(
    context: &RuntimeContext,
    output: &mut impl Write,
    project_name: &str,
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
) -> Result<(), CliError> {
    let code = formatted_recovery_code(code_bytes)?;
    writeln!(output, "recovery_code (shown once, store securely):")?;
    writeln!(output, "{code}")?;
    writeln!(output, "warning: terminal scrollback may retain this code")?;
    writeln!(output, "type project name '{project_name}' after recording the recovery code")?;
    output.flush()?;
    let confirmation = context.confirmation_reader.read_confirmation("recovery rotate code")?;
    if confirmation.trim_end_matches(['\r', '\n']) != project_name {
        return Err(crate::confirmation_failed_error("confirmation did not match project name"));
    }
    if io::stdout().is_terminal() {
        let _ = io::stdout().write_all(b"\x1b[2J\x1b[H");
    }
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn write_recovery_rotate_audit(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    resolved: &ResolvedProject,
    kdf_profile_id: &str,
    timestamp: i64,
    user_verification: UserVerificationAudit,
) -> Result<(), CliError> {
    let audit_key =
        load_project_key(context, store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let device_id = store
        .get_active_local_device(resolved.config.project_id.as_str())?
        .map_or_else(|| "unknown".to_owned(), |d| d.id);
    let metadata = json!({
        "schema_version": 1,
        "action": "RECOVERY_ROTATE",
        "status": "SUCCESS",
        "command": "recovery rotate",
        "kdf_profile_id": kdf_profile_id,
        "device_id": device_id,
        "user_verification": user_verification,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "RECOVERY_ROTATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("recovery rotate"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn write_recover_audit(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
    restored: &RecoveryRestoreSummary,
    force: bool,
    user_verification: Option<&UserVerificationAudit>,
) -> Result<(), CliError> {
    let timestamp = now_unix_nanos()?;
    let mut store = open_store(context)?;
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let envelope_bytes = envelope.serialize()?;
    let envelope_checksum = format_hex(&Sha256::digest(&envelope_bytes));
    let mut restored_entry_kinds = vec!["master_key"];
    if restored.device_sealing_private > 0 {
        restored_entry_kinds.push("device_signing_private_key");
        restored_entry_kinds.push("device_sealing_private_key");
    }
    if restored.automation_client_private > 0 {
        restored_entry_kinds.push("automation_client_private_key");
    }
    let device_id = store
        .get_active_local_device(resolved.config.project_id.as_str())?
        .map_or_else(|| "unknown".to_owned(), |d| d.id);
    let mut metadata = json!({
        "schema_version": 1,
        "action": "RECOVER",
        "status": "SUCCESS",
        "command": "recover",
        "project_id": resolved.config.project_id.as_str(),
        "kdf_profile_id": &kdf.kdf_profile_id,
        "envelope_checksum_sha256": envelope_checksum,
        "restored_entry_kinds": restored_entry_kinds,
        "restored_entry_counts": {
            "master_key": restored.master,
            "device_signing_private_key": restored.device_signing_private,
            "device_sealing_private_key": restored.device_sealing_private,
            "automation_client_private_key": restored.automation_client_private,
            "automation_client_private_key_skipped": restored.skipped_automation_client_private,
        },
        "force": force,
        "device_id": device_id,
    });
    if let Some(user_verification) = user_verification {
        metadata["user_verification"] = serde_json::to_value(user_verification)?;
        metadata["intact_keychain_override"] = json!(true);
    }
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "RECOVER",
        status: "SUCCESS",
        secret_name: None,
        command: Some("recover"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
