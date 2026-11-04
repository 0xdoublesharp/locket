//! Audit command implementation.

#[cfg(windows)]
use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use locket_core::{AUDIT_CHECKPOINT_MAX_BYTES, AuditCheckpoint, LocketError};
use locket_crypto::KeyPurpose;

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
        AuditCommand::Verify { checkpoint } => {
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
                    "checkpoint: not supplied; rollback detection requires --checkpoint"
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
    }
}

fn resolve_path(context: &RuntimeContext, path: &Path) -> PathBuf {
    if path.is_absolute() { path.to_path_buf() } else { context.cwd.join(path) }
}

fn checkpoint_error(message: &str) -> CliError {
    CliError::Typed { kind: LocketError::AuditIntegrityFailed, message: message.to_owned() }
}

fn read_checkpoint(path: &Path) -> Result<AuditCheckpoint, CliError> {
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
    let mut bytes = Vec::new();
    file.take(AUDIT_CHECKPOINT_MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > AUDIT_CHECKPOINT_MAX_BYTES {
        return Err(checkpoint_error("audit checkpoint exceeds 4096 bytes"));
    }
    serde_json::from_slice(&bytes).map_err(|_| checkpoint_error("invalid audit checkpoint format"))
}

fn write_checkpoint(path: &Path, checkpoint: &AuditCheckpoint) -> Result<(), CliError> {
    let bytes = serde_json::to_vec_pretty(checkpoint)?;
    if bytes.len() > AUDIT_CHECKPOINT_MAX_BYTES {
        return Err(checkpoint_error("audit checkpoint exceeds 4096 bytes"));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary =
        tempfile::Builder::new().prefix(".locket-audit-checkpoint-").tempfile_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            checkpoint_error("audit checkpoint output already exists; choose a new path")
        } else {
            CliError::Io(error.error)
        }
    })?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}
