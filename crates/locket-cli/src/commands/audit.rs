//! Audit command implementation.

use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, HEXLOWER, HEXUPPER};
use ed25519_dalek::SigningKey;
use locket_core::{
    AUDIT_CHECKPOINT_MAX_BYTES, AUDIT_WITNESS_SCHEMA_VERSION, AuditCheckpoint, AuditWitnessReceipt,
    AuditWitnessStatement, LocketError, sign_audit_witness_statement, verify_audit_witness_receipt,
};
use locket_crypto::{KeyBytes, KeyPurpose, generate_key};
use locket_store::{AuditWrite, Store, StoreError};
use rusqlite::OptionalExtension;
use serde_json::json;
use zeroize::Zeroizing;

use crate::{
    AuditCommand, CliError, RuntimeContext, load_project_key, now_unix_nanos, open_store,
    require_project,
};

pub fn audit_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: AuditCommand,
) -> Result<(), CliError> {
    match command {
        AuditCommand::Verify { witness_key: Some(key), receipt, .. } => {
            verify_witnesses(context, output, &key, receipt.as_deref())
        }
        AuditCommand::Verify { checkpoint, witness_key: None, .. } => {
            let checkpoint = checkpoint
                .map(|path| read_checkpoint(&resolve_path(context, &path)))
                .transpose()?;
            let resolved = require_project(context)?;
            let mut store = open_store(context)?;
            let audit_key = load_project_key(
                context,
                &store,
                resolved.config.project_id.as_str(),
                KeyPurpose::Audit,
            )?;
            let rows = if let Some(checkpoint) = &checkpoint {
                store.verify_audit_checkpoint_and_append(
                    &resolved.config.project_id,
                    &audit_key,
                    checkpoint,
                    now_unix_nanos()?,
                )?
            } else {
                store.verify_audit_chain_and_append(
                    resolved.config.project_id.as_str(),
                    audit_key.as_ref(),
                    now_unix_nanos()?,
                )?
            };
            writeln!(output, "audit: verified {rows} row(s)")?;
            if checkpoint.is_some() {
                writeln!(output, "checkpoint: verified")?;
            } else {
                writeln!(
                    output,
                    "checkpoint: not supplied; rollback detection requires --checkpoint or an independently retained --receipt with --witness-key"
                )?;
            }
            Ok(())
        }
        AuditCommand::Checkpoint { output: path } => {
            let resolved = require_project(context)?;
            let store = open_store(context)?;
            let audit_key = load_project_key(
                context,
                &store,
                resolved.config.project_id.as_str(),
                KeyPurpose::Audit,
            )?;
            let checkpoint = store.audit_checkpoint(&resolved.config.project_id, &audit_key)?;
            write_checkpoint(&resolve_path(context, &path), &checkpoint)?;
            writeln!(output, "audit: checkpoint saved at sequence {}", checkpoint.sequence)?;
            writeln!(output, "Retain this checkpoint independently of the vault and its backups.")?;
            Ok(())
        }
        AuditCommand::Witness { generate_key: Some(path), json, .. } => {
            generate_witness_key(&resolve_path(context, &path), output, json)
        }
        AuditCommand::Witness { key_file: Some(key), witness_id, output: path, json, .. } => {
            witness(context, output, &key, witness_id, path.as_deref(), json)
        }
        AuditCommand::Witness { .. } => Err(checkpoint_error("a witness key file is required")),
    }
}

fn generate_witness_key(
    path: &Path,
    output: &mut impl Write,
    json_output: bool,
) -> Result<(), CliError> {
    let seed = generate_key()?;
    let key = SigningKey::from_bytes(&seed);
    let keypair = Zeroizing::new(key.to_keypair_bytes());
    write_new_file(path, keypair.as_slice(), "witness key output")?;
    let public = BASE64URL_NOPAD.encode(key.verifying_key().as_bytes());
    if json_output {
        writeln!(output, "{}", json!({"witness_public_key_b64": public}))?;
    } else {
        writeln!(output, "witness public key: {public}")?;
    }
    Ok(())
}

fn witness(
    context: &RuntimeContext,
    output: &mut impl Write,
    key_file: &Path,
    witness_id: Option<String>,
    receipt_path: Option<&Path>,
    json_output: bool,
) -> Result<(), CliError> {
    let signing_key = read_signing_key(&resolve_path(context, key_file))?;
    let public_key = signing_key.verifying_key().to_bytes();
    let resolved = require_project(context)?;
    let project = &resolved.config.project_id;
    let store = open_store(context)?;
    let audit_key = load_project_key(context, &store, project.as_str(), KeyPurpose::Audit)?;
    let latest = store.get_latest_audit_witness_receipt(project.as_str())?;
    let verified = verify_receipt_chain(&store, project.as_str(), &public_key, None)?;
    if latest.as_ref().map(|record| record.receipt_sha256_hex.as_str())
        != verified.as_ref().map(|head| head.digest.as_str())
    {
        return Err(checkpoint_error("audit witness history changed; retry"));
    }
    let checkpoint = store.audit_checkpoint(project, &audit_key)?;
    let timestamp = now_unix_nanos()?;
    let nonce_hex = HEXLOWER.encode(generate_key()?.as_ref());
    let statement = AuditWitnessStatement {
        schema_version: AUDIT_WITNESS_SCHEMA_VERSION,
        project_id: project.to_string(),
        seq_no: checkpoint.sequence,
        checkpoint_hmac_hex: HEXLOWER.encode(&checkpoint.row_hmac),
        prev_receipt_sha256_hex: latest.as_ref().map(|head| head.receipt_sha256_hex.clone()),
        signer_id: store
            .get_active_local_device(project.as_str())?
            .map_or_else(|| "locket-cli".to_owned(), |device| device.id),
        witness_id: witness_id.unwrap_or_else(|| BASE64URL_NOPAD.encode(&public_key)),
        nonce_hex: nonce_hex.clone(),
        issued_at_unix_nanos: timestamp,
    };
    let receipt = sign_audit_witness_statement(statement, &signing_key)
        .map_err(|error| checkpoint_error(&error.to_string()))?;
    verify_audit_witness_receipt(
        &receipt,
        &public_key,
        project.as_str(),
        latest.as_ref().map(|head| &head.receipt),
    )
    .map_err(|error| checkpoint_error(&error.to_string()))?;
    let path = receipt_path.map(|path| resolve_path(context, path));
    let bytes = serde_json::to_vec_pretty(&receipt)?;
    if bytes.len() > AUDIT_CHECKPOINT_MAX_BYTES {
        return Err(checkpoint_error("audit witness receipt exceeds 4096 bytes"));
    }
    let prepared_output = path
        .as_ref()
        .map(|path| prepare_new_file(path, &bytes, "witness receipt output"))
        .transpose()?;
    store.insert_audit_witness_receipt(
        &format!("lk_witness_{nonce_hex}"),
        project.as_str(),
        &receipt,
        &public_key,
        timestamp,
    )?;
    if let (Some(path), Some(temporary)) = (&path, prepared_output) {
        persist_new_file(path, temporary, "witness receipt output").map_err(|error| {
            checkpoint_error(&format!(
                "witness receipt was stored in the vault but could not be saved externally: {error}"
            ))
        })?;
    }
    if json_output {
        writeln!(output, "{}", serde_json::to_string(&receipt)?)?;
    } else {
        writeln!(output, "audit: witnessed sequence {}", receipt.statement.seq_no)?;
        writeln!(output, "witness public key: {}", receipt.witness_public_key_b64)?;
    }
    Ok(())
}

struct VerifiedWitnessHead {
    receipt: AuditWitnessReceipt,
    digest: String,
    count: usize,
}

fn verify_receipt_chain(
    store: &Store,
    project: &str,
    key: &KeyBytes,
    supplied: Option<AuditWitnessReceipt>,
) -> Result<Option<VerifiedWitnessHead>, CliError> {
    let mut receipts = store
        .list_audit_witness_receipts(project)?
        .into_iter()
        .map(|record| (record.receipt, Some(record.receipt_sha256_hex)))
        .collect::<Vec<_>>();
    if let Some(receipt) = supplied {
        let sequence = receipt.statement.seq_no;
        let index = receipts
            .iter()
            .position(|(stored, _)| stored.statement.seq_no >= sequence)
            .unwrap_or(receipts.len());
        if let Some((stored, _)) =
            receipts.get(index).filter(|(stored, _)| stored.statement.seq_no == sequence)
        {
            if *stored != receipt {
                return Err(checkpoint_error(
                    "retained witness receipt conflicts with the stored receipt",
                ));
            }
        } else {
            receipts.insert(index, (receipt, None));
        }
    }
    let mut head: Option<VerifiedWitnessHead> = None;
    let mut nonces = std::collections::BTreeSet::new();
    for (index, (receipt, stored_digest)) in receipts.into_iter().enumerate() {
        let digest = verify_audit_witness_receipt(
            &receipt,
            key,
            project,
            head.as_ref().map(|head| &head.receipt),
        )
        .map_err(|error| checkpoint_error(&error.to_string()))?;
        if stored_digest.is_some_and(|stored| stored != digest) {
            return Err(checkpoint_error("stored witness receipt digest does not match"));
        }
        if !nonces.insert(receipt.statement.nonce_hex.clone()) {
            return Err(checkpoint_error("audit witness nonce was already used"));
        }
        verify_witness_anchor(store, project, &receipt)?;
        head = Some(VerifiedWitnessHead { receipt, digest, count: index + 1 });
    }
    Ok(head)
}

fn verify_witness_anchor(
    store: &Store,
    project: &str,
    receipt: &AuditWitnessReceipt,
) -> Result<(), CliError> {
    let sequence = i64::try_from(receipt.statement.seq_no)
        .map_err(|_| checkpoint_error("invalid witnessed audit sequence"))?;
    let hmac: Option<Vec<u8>> = store
        .connection()
        .query_row(
            "SELECT hmac FROM audit_log WHERE project_id = ?1 AND sequence = ?2",
            rusqlite::params![project, sequence],
            |row| row.get(0),
        )
        .optional()
        .map_err(StoreError::from)?;
    if hmac.is_none_or(|hmac| HEXLOWER.encode(&hmac) != receipt.statement.checkpoint_hmac_hex) {
        return Err(checkpoint_error(&format!(
            "local audit history does not match witnessed sequence {sequence}"
        )));
    }
    Ok(())
}

fn verify_witnesses(
    context: &RuntimeContext,
    output: &mut impl Write,
    key: &str,
    receipt_path: Option<&Path>,
) -> Result<(), CliError> {
    let key = read_witness_public_key(context, key)?;
    let supplied = receipt_path
        .map(|path| {
            let bytes = read_audit_file(&resolve_path(context, path))?;
            serde_json::from_slice(&bytes)
                .map_err(|_| checkpoint_error("invalid audit witness receipt"))
        })
        .transpose()?;
    let resolved = require_project(context)?;
    let project = resolved.config.project_id.as_str();
    let mut store = open_store(context)?;
    let key_for_audit = load_project_key(context, &store, project, KeyPurpose::Audit)?;
    let reader = Store::open_read_only(&context.store_path)?;
    let (rows, head) = store.with_atomic_write(|store| -> Result<_, CliError> {
        let head = verify_receipt_chain(store, project, &key, supplied)?
            .ok_or_else(|| checkpoint_error("no audit witness receipts found"))?;
        // The receipt and anchor reads above establish the write connection's
        // snapshot. A concurrent audit write invalidates its upgrade to a
        // writer, so the verification and success row cannot span a fork.
        let verification = reader.verify_audit_chain_read_only(project, key_for_audit.as_ref())?;
        if !verification.hmac_ok {
            return Err(checkpoint_error(
                verification
                    .first_break_reason
                    .as_deref()
                    .unwrap_or("audit HMAC verification failed"),
            ));
        }
        let rows = verification.rows_verified;
        let metadata = json!({
            "schema_version": 1, "action": "AUDIT_VERIFY", "status": "SUCCESS",
            "check_names": ["audit_hmac_chain", "external_audit_witness"],
            "pass_count": 2, "warn_count": 0, "fail_count": 0, "skip_count": 0,
            "rows_verified": rows,
        });
        store.append_audit(
            key_for_audit.as_ref(),
            &AuditWrite {
                project_id: project,
                profile_id: None,
                action: "AUDIT_VERIFY",
                status: "SUCCESS",
                secret_name: None,
                command: None,
                metadata_json: &metadata,
                timestamp: now_unix_nanos()?,
            },
        )?;
        Ok((rows, head))
    })?;
    writeln!(output, "audit: verified {rows} row(s)")?;
    writeln!(
        output,
        "witness: verified {} receipt(s) through sequence {}",
        head.count, head.receipt.statement.seq_no
    )?;
    Ok(())
}

fn read_signing_key(path: &Path) -> Result<SigningKey, CliError> {
    let bytes = read_audit_file(path)?;
    if let Some(keypair) = decode_key_text::<64>(&bytes) {
        return SigningKey::from_keypair_bytes(&keypair)
            .map_err(|_| checkpoint_error("invalid Ed25519 witness keypair"));
    }
    if let Some(seed) = decode_key_text::<32>(&bytes) {
        return Ok(SigningKey::from_bytes(&seed));
    }
    if let Ok(keypair) = <&[u8; 64]>::try_from(bytes.as_slice()) {
        return SigningKey::from_keypair_bytes(keypair)
            .map_err(|_| checkpoint_error("invalid Ed25519 witness keypair"));
    }
    let seed = <&[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        checkpoint_error("witness key file must contain an Ed25519 seed or keypair")
    })?;
    Ok(SigningKey::from_bytes(seed))
}

fn read_witness_public_key(context: &RuntimeContext, argument: &str) -> Result<KeyBytes, CliError> {
    let path = resolve_path(context, Path::new(argument));
    let key = match fs::symlink_metadata(&path) {
        Ok(_) => decode_key::<32>(&read_audit_file(&path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            decode_key_text::<32>(argument.as_bytes())
        }
        Err(error) => return Err(error.into()),
    };
    key.map(|key| *key).ok_or_else(|| checkpoint_error("invalid Ed25519 witness public key"))
}

fn decode_key<const N: usize>(bytes: &[u8]) -> Option<Zeroizing<[u8; N]>> {
    decode_key_text(bytes).or_else(|| <[u8; N]>::try_from(bytes).ok().map(Zeroizing::new))
}

fn decode_key_text<const N: usize>(bytes: &[u8]) -> Option<Zeroizing<[u8; N]>> {
    let text = std::str::from_utf8(bytes).ok()?.trim().as_bytes();
    [&HEXLOWER, &HEXUPPER, &BASE64URL, &BASE64URL_NOPAD, &BASE64, &BASE64_NOPAD]
        .into_iter()
        .find_map(|format| {
            let decoded = Zeroizing::new(format.decode(text).ok()?);
            <[u8; N]>::try_from(decoded.as_slice()).ok().map(Zeroizing::new)
        })
}

fn resolve_path(context: &RuntimeContext, path: &Path) -> PathBuf {
    if path.is_absolute() { path.to_path_buf() } else { context.cwd.join(path) }
}

fn checkpoint_error(message: &str) -> CliError {
    CliError::Typed { kind: LocketError::AuditIntegrityFailed, message: message.to_owned() }
}

fn read_checkpoint(path: &Path) -> Result<AuditCheckpoint, CliError> {
    let bytes = read_audit_file(path)?;
    serde_json::from_slice(&bytes).map_err(|_| checkpoint_error("invalid audit checkpoint format"))
}

fn read_audit_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags};
        File::from(
            rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(std::io::Error::from)?,
        )
    };
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the final reparse point itself, so symlinks are rejected below.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        fs::OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path)?
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > AUDIT_CHECKPOINT_MAX_BYTES as u64
    {
        return Err(checkpoint_error(
            "audit checkpoint must be a regular file of at most 4096 bytes",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(AUDIT_CHECKPOINT_MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > AUDIT_CHECKPOINT_MAX_BYTES {
        return Err(checkpoint_error("audit checkpoint exceeds 4096 bytes"));
    }
    Ok(bytes)
}

fn write_checkpoint(path: &Path, checkpoint: &AuditCheckpoint) -> Result<(), CliError> {
    let bytes = serde_json::to_vec_pretty(checkpoint)?;
    if bytes.len() > AUDIT_CHECKPOINT_MAX_BYTES {
        return Err(checkpoint_error("audit checkpoint exceeds 4096 bytes"));
    }
    write_new_file(path, &bytes, "audit checkpoint output")
}

fn write_new_file(path: &Path, bytes: &[u8], purpose: &str) -> Result<(), CliError> {
    let temporary = prepare_new_file(path, bytes, purpose)?;
    persist_new_file(path, temporary, purpose)
}

fn file_parent(path: &Path) -> &Path {
    path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."))
}

fn prepare_new_file(
    path: &Path,
    bytes: &[u8],
    purpose: &str,
) -> Result<tempfile::NamedTempFile, CliError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(checkpoint_error(&format!("{purpose} already exists; choose a new path")));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut temporary =
        tempfile::Builder::new().prefix(".locket-audit-").tempfile_in(file_parent(path))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    Ok(temporary)
}

fn persist_new_file(
    path: &Path,
    temporary: tempfile::NamedTempFile,
    purpose: &str,
) -> Result<(), CliError> {
    temporary.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            checkpoint_error(&format!("{purpose} already exists; choose a new path"))
        } else {
            CliError::Io(error.error)
        }
    })?;
    #[cfg(unix)]
    File::open(file_parent(path))?.sync_all()?;
    Ok(())
}
