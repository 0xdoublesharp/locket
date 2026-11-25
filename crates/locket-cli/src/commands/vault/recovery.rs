use data_encoding::BASE64URL_NOPAD;
use locket_core::LocketError;
use locket_crypto::{KeyPurpose, derive_recovery_key_v1, open_recovery_entry_v1, wrap_dek_v1};
use locket_platform::{
    LocalDevicePrivateKeyStorage, PlatformError, RecoveryEnvelope, RecoveryEnvelopeEntry,
    RecoveryKdfToml, WrappedLocalFileDevicePrivateKeyStorage, load_recovery_state,
    save_recovery_state, secure_directory, write_user_only_file,
};
use locket_store::{AuditWrite, Store};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::runtime::error::typed_cli_error;
use crate::runtime::key_access::{MasterKeySource, load_project_key_with_master};
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
    let (requested_kdf, _) = load_recovery_state(&recovery_dir)
        .map_err(|error| metadata_invalid_error(format!("recovery/envelope.bin: {error}")))?;
    let code = context.recovery_code_reader.read_recovery_code("recovery code")?;
    let code_bytes = recovery_code_decode(code.trim())?;
    let _lock = lock_recovery(context)?;
    let (kdf, envelope) = load_recovery_state(&recovery_dir)
        .map_err(|error| metadata_invalid_error(format!("recovery/envelope.bin: {error}")))?;
    if requested_kdf.kdf_profile_id != kdf.kdf_profile_id {
        return Err(metadata_invalid_error(
            "recovery envelope changed while reading the code; retry with the current code",
        ));
    }
    restore_keys(context, output, &resolved, &kdf, &envelope, &code_bytes, args.force)
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
    let _lock = lock_recovery(context)?;
    let envelope_path = recovery_dir.join("envelope.bin");
    let has_envelope = match fs::symlink_metadata(&envelope_path) {
        Ok(metadata) if metadata.is_file() => true,
        Ok(_) => return Err(metadata_invalid_error("recovery envelope must be a regular file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let timestamp = now_unix_nanos()?;
    let code_bytes = generate_recovery_code_bytes()?;
    let salt = generate_recovery_salt()?;
    let kdf_profile_id = format!("lk_kdf_{}", format_hex(&salt[..16]));
    let new_kdf = RecoveryKdfToml::new_v1(kdf_profile_id, &salt, timestamp);
    let new_root = derive_recovery_key_v1(&code_bytes, &salt, new_kdf.to_crypto_params())?;

    let entries = if has_envelope {
        let (old_kdf, old_envelope) = load_recovery_state(&recovery_dir)
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
    secure_directory(&recovery_dir)?;
    let staged = tempfile::Builder::new().prefix(".rotate-").tempdir_in(&recovery_dir)?;
    save_recovery_state(staged.path(), &new_kdf, &new_envelope)
        .map_err(|error| metadata_invalid_error(format!("stage recovery envelope: {error}")))?;
    let mut store = open_store(context)?;
    write_recovery_rotate_audit(
        context,
        &mut store,
        &resolved,
        &new_kdf.kdf_profile_id,
        timestamp,
        user_verification,
    )?;
    // The old code remains valid through audit commit. An unsuccessful rename
    // leaves the old envelope in place, including after a process restart.
    fs::rename(staged.path().join("envelope.bin"), envelope_path)?;
    writeln!(output, "recovery_code_rotate: success")?;
    Ok(())
}

fn lock_recovery(context: &RuntimeContext) -> Result<fs::File, CliError> {
    let root = crate::commands::team::device::device_private_key_root(context)?;
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let lock = options.open(root.join("recovery.lock"))?;
    lock.lock()?;
    Ok(lock)
}

#[cfg(test)]
pub fn restore_from_recovery_code(
    context: &RuntimeContext,
    output: &mut impl Write,
    resolved: &ResolvedProject,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
    force: bool,
) -> Result<(), CliError> {
    let _lock = lock_recovery(context)?;
    restore_keys(context, output, resolved, kdf, envelope, code_bytes, force)
}

fn restore_keys(
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
    let previous_master = match context.key_store.load_master_key(project_id) {
        Ok(key) => Some(key),
        Err(PlatformError::MasterKeyNotFound) => None,
        Err(error) => return Err(error.into()),
    };
    if !force && previous_master.is_some() {
        return Err(crate::secret_already_exists_error(
            "master key already exists; use --force to overwrite",
        ));
    }
    let force_verification = if previous_master.is_some() {
        Some(require_user_verification(
            context,
            "recover --force",
            "Overwrite an intact recovery target",
        )?)
    } else {
        None
    };

    let salt = kdf
        .decode_salt()
        .map_err(|error| metadata_invalid_error(format!("recovery kdf salt: {error}")))?;
    let unwrap_root = derive_recovery_key_v1(code_bytes, &salt, kdf.to_crypto_params())?;
    let (master_key, master_count) =
        read_master_recovery_key(project_id, kdf, envelope, &unwrap_root)?;
    let mut store = open_store(context)?;
    let device_keys = read_device_recovery_keys(&store, project_id, kdf, envelope, &unwrap_root)?;
    let mut device =
        device_keys.map(|keys| DeviceRecoveryWrite::new(context, project_id, keys)).transpose()?;
    let audit_key =
        load_project_key_with_master(&store, project_id, KeyPurpose::Audit, &master_key)?;
    let audit = RestoreAudit {
        project_id,
        kdf_profile_id: &kdf.kdf_profile_id,
        checksum: format_hex(&Sha256::digest(envelope.serialize()?)),
        device_id: device
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |write| write.keys.device_id.clone()),
        force,
        verification: force_verification.as_ref(),
        key: audit_key.as_ref(),
        timestamp: now_unix_nanos()?,
    };
    // A process stop can interrupt compensation across SQLite and the keychain.
    // Record the attempt before touching either local key backend.
    audit.append(&mut store, "RECOVERY_RESTORE_BEGIN", "STARTED", None)?;
    let mut attempted_master = false;
    let result = store.with_atomic_write(|store| {
        let mut restored = RecoveryRestoreSummary { master: master_count, ..Default::default() };
        attempted_master = true;
        context.key_store.store_master_key(project_id, &master_key)?;
        if let Some(device) = &mut device {
            device.write()?;
            restored.device_signing_private = 1;
            restored.device_sealing_private = 1;
        }
        restore_automation_client_private_keys(
            context,
            store,
            project_id,
            envelope,
            &unwrap_root,
            &master_key,
            &mut restored,
        )?;
        audit.append(store, "RECOVER", "SUCCESS", Some(&restored))?;
        Ok(restored)
    });
    let restored = match result {
        Ok(restored) => restored,
        Err(error) => {
            let mut rollback_failures = Vec::new();
            if let Some(device) = device {
                device.rollback(&mut rollback_failures);
            }
            if attempted_master {
                let rollback = previous_master.map_or_else(
                    || context.key_store.delete_master_key(project_id),
                    |previous| context.key_store.store_master_key(project_id, &previous),
                );
                if let Err(rollback) = rollback {
                    rollback_failures.push(format!("master key: {rollback}"));
                }
            }
            if rollback_failures.is_empty() {
                return Err(error);
            }
            return Err(crate::corrupt_db_error(format!(
                "{error}; recovery rollback failed: {}",
                rollback_failures.join(", ")
            )));
        }
    };
    context.master_key_cache.insert(project_id, master_key, MasterKeySource::OsKeyStore);
    write_recovery_result(output, &restored)
}

fn read_master_recovery_key(
    project_id: &str,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
    unwrap_root: &locket_crypto::KeyBytes,
) -> Result<(Zeroizing<locket_crypto::KeyBytes>, usize), CliError> {
    let mut recovered_master = None;
    let mut count = 0;
    for entry in &envelope.entries {
        if entry.entry_kind != "master_key" {
            continue;
        }
        if entry.entry_id != project_id {
            return Err(metadata_invalid_error("recovery envelope project id mismatch"));
        }
        let plaintext = open_recovery_entry_v1(
            unwrap_root,
            &kdf.kdf_profile_id,
            &entry.entry_kind,
            &entry.entry_id,
            &entry.nonce,
            &entry.ciphertext,
        )?;
        if plaintext.len() != locket_crypto::KEY_LEN {
            return Err(CliError::Crypto(locket_crypto::CryptoError::InvalidWrappedKey));
        }
        let mut master_key = Zeroizing::new([0_u8; locket_crypto::KEY_LEN]);
        master_key.copy_from_slice(&plaintext);
        recovered_master = Some(master_key);
        count += 1;
    }
    let master_key = recovered_master.ok_or_else(|| {
        metadata_invalid_error("no master_key entries found in recovery envelope")
    })?;
    Ok((master_key, count))
}

fn write_recovery_result(
    output: &mut impl Write,
    restored: &RecoveryRestoreSummary,
) -> Result<(), CliError> {
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

struct DeviceRecoveryKeys {
    device_id: String,
    fingerprint: String,
    signing: zeroize::Zeroizing<locket_crypto::KeyBytes>,
    sealing: zeroize::Zeroizing<locket_crypto::KeyBytes>,
}

struct DeviceRecoveryWrite {
    keys: DeviceRecoveryKeys,
    storage: WrappedLocalFileDevicePrivateKeyStorage,
    previous: [DeviceEnvelopeSnapshot; 2],
    attempted: usize,
}

impl DeviceRecoveryWrite {
    fn new(
        context: &RuntimeContext,
        project_id: &str,
        keys: DeviceRecoveryKeys,
    ) -> Result<Self, CliError> {
        let storage = WrappedLocalFileDevicePrivateKeyStorage::new(
            crate::commands::team::device::device_private_key_root(context)?,
            project_id.to_owned(),
            context.key_store.clone(),
        );
        let previous = [
            DeviceEnvelopeSnapshot::read(storage.envelope_path(&keys.device_id)?)?,
            DeviceEnvelopeSnapshot::read(
                storage.clone().for_signing().envelope_path(&keys.fingerprint)?,
            )?,
        ];
        Ok(Self { keys, storage, previous, attempted: 0 })
    }

    fn write(&mut self) -> Result<(), CliError> {
        self.attempted = 1;
        self.storage.store(&self.keys.device_id, &self.keys.sealing)?;
        self.attempted = 2;
        self.storage.clone().for_signing().store(&self.keys.fingerprint, &self.keys.signing)?;
        Ok(())
    }

    fn rollback(self, failures: &mut Vec<String>) {
        for snapshot in self.previous.into_iter().take(self.attempted).rev() {
            if let Err(error) = snapshot.restore() {
                failures.push(format!("device private-key envelope: {error}"));
            }
        }
    }
}

struct DeviceEnvelopeSnapshot {
    path: PathBuf,
    contents: Option<Vec<u8>>,
}

impl DeviceEnvelopeSnapshot {
    fn read(path: PathBuf) -> Result<Self, CliError> {
        let contents = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => Some(fs::read(&path)?),
            Ok(_) => {
                return Err(metadata_invalid_error("device key envelope must be a regular file"));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        Ok(Self { path, contents })
    }

    fn restore(self) -> Result<(), CliError> {
        if let Some(contents) = self.contents {
            write_user_only_file(&self.path, &contents)?;
        } else {
            match fs::remove_file(self.path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

fn read_device_recovery_keys(
    store: &Store,
    project_id: &str,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
    unwrap_root: &locket_crypto::KeyBytes,
) -> Result<Option<DeviceRecoveryKeys>, CliError> {
    let Some(device) = store.get_active_local_device(project_id)? else {
        return Ok(None);
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
    if signing_public.as_slice() != device.signing_public_key.as_slice() {
        return Err(metadata_invalid_error("recovery envelope device signing key mismatch"));
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
    let derived = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*sealing_key));
    if derived.as_bytes().as_slice() != device.sealing_public_key.as_slice() {
        return Err(metadata_invalid_error("recovery envelope device sealing key mismatch"));
    }
    Ok(Some(DeviceRecoveryKeys {
        device_id: device.id,
        fingerprint: device.fingerprint,
        signing: signing_key,
        sealing: sealing_key,
    }))
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
    store: &Store,
    project_id: &str,
    envelope: &RecoveryEnvelope,
    unwrap_root: &locket_crypto::KeyBytes,
    master_key: &locket_crypto::KeyBytes,
    restored: &mut RecoveryRestoreSummary,
) -> Result<(), CliError> {
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
            &envelope.kdf_profile_id,
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
            store,
            project_id,
            &reference,
            &private_key,
            master_key,
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
    store: &Store,
    project_id: &str,
    reference: &locket_store::AutomationClientPrivateKeyRefRecord,
    private_key: &locket_crypto::KeyBytes,
    master_key: &locket_crypto::KeyBytes,
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
            project_id,
            &reference.client_id,
            private_key,
            master_key,
        ),
        _ => Err(metadata_invalid_error("unsupported automation client private-key storage")),
    }
}

fn restore_wrapped_local_client_key(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    client_id: &str,
    private_key: &locket_crypto::KeyBytes,
    master_key: &locket_crypto::KeyBytes,
) -> Result<(), CliError> {
    let path = automation_client_key_path(context, client_id)?;
    let parent = path.parent().ok_or_else(|| crate::corrupt_db_error("invalid client key path"))?;
    secure_directory(parent)?;
    let project_key =
        load_project_key_with_master(store, project_id, KeyPurpose::ProjectMetadata, master_key)?;
    let aad = automation_client_private_key_aad(project_id, client_id);
    let wrapped_key = wrap_dek_v1(&project_key, private_key, &aad)?;
    let file = json!({
        "schema_version": 1,
        "algorithm": "xchacha20poly1305-key-wrap-v1",
        "project_id": project_id,
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
        crate::commands::team::device::load_device_signing_key(context, &device)?.to_bytes(),
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
    store: &mut Store,
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

struct RestoreAudit<'a> {
    project_id: &'a str,
    kdf_profile_id: &'a str,
    checksum: String,
    device_id: String,
    force: bool,
    verification: Option<&'a UserVerificationAudit>,
    key: &'a [u8],
    timestamp: i64,
}

impl RestoreAudit<'_> {
    fn append(
        &self,
        store: &mut Store,
        action: &str,
        status: &str,
        restored: Option<&RecoveryRestoreSummary>,
    ) -> Result<(), CliError> {
        let mut metadata = json!({
            "schema_version": 1,
            "action": action,
            "status": status,
            "command": "recover",
            "project_id": self.project_id,
            "kdf_profile_id": self.kdf_profile_id,
            "envelope_checksum_sha256": self.checksum,
            "force": self.force,
            "device_id": self.device_id,
        });
        if let Some(user_verification) = self.verification {
            metadata["user_verification"] = serde_json::to_value(user_verification)?;
            metadata["intact_keychain_override"] = json!(true);
        }
        if let Some(restored) = restored {
            let mut kinds = vec!["master_key"];
            if restored.device_sealing_private > 0 {
                kinds.extend([
                    DEVICE_SIGNING_PRIVATE_KEY_ENTRY_KIND,
                    DEVICE_SEALING_PRIVATE_KEY_ENTRY_KIND,
                ]);
            }
            if restored.automation_client_private > 0 {
                kinds.push(AUTOMATION_CLIENT_PRIVATE_KEY_ENTRY_KIND);
            }
            metadata["restored_entry_kinds"] = json!(kinds);
            metadata["restored_entry_counts"] = json!({
                "master_key": restored.master,
                "device_signing_private_key": restored.device_signing_private,
                "device_sealing_private_key": restored.device_sealing_private,
                "automation_client_private_key": restored.automation_client_private,
                "automation_client_private_key_skipped": restored.skipped_automation_client_private,
            });
        }
        store.append_audit(
            self.key,
            &AuditWrite {
                project_id: self.project_id,
                profile_id: None,
                action,
                status,
                secret_name: None,
                command: Some("recover"),
                metadata_json: &metadata,
                timestamp: self.timestamp,
            },
        )?;
        Ok(())
    }
}
