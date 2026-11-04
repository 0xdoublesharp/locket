//! `locket install-hooks` command and pre-commit hook helpers.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use locket_crypto::KeyPurpose;
use locket_store::AuditWrite;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    CliError, HOOK_BEGIN, HOOK_END, ResolvedProject, RuntimeContext, confirmation_failed_error,
    invalid_reference_error, load_project_key, metadata_invalid_error, now_unix_nanos, open_store,
    require_project,
};

pub fn install_hooks_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let git_dir = git_dir_for_worktree(&resolved.root)?;
    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)?;
    let hook_path = hooks_dir.join("pre-commit");
    let existing = match fs::read_to_string(&hook_path) {
        Ok(existing) => existing,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    let plan = plan_pre_commit_hook(&existing)?;
    if plan.change == HookInstallChange::PrependUnmanaged {
        confirm_unmanaged_pre_commit_hook(
            context,
            output,
            resolved.config.name.as_str(),
            &hook_path,
            &existing,
        )?;
    }
    if plan.updated != existing {
        fs::write(&hook_path, plan.updated)?;
    }
    make_executable(&hook_path)?;
    write_hook_install_audit_if_available(context, &resolved, &hook_path, plan.change)?;

    writeln!(output, "installed {}", hook_path.display())?;
    writeln!(output, "hook_change: {}", plan.change.as_str())?;
    writeln!(output, "hook: locket scan --staged")?;
    writeln!(output, "secrets: not written")?;
    Ok(())
}

fn managed_pre_commit_block() -> String {
    format!("{HOOK_BEGIN}\nlocket scan --staged\n{HOOK_END}\n")
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HookInstallChange {
    Created,
    RewroteManaged,
    PrependUnmanaged,
    Unchanged,
}

impl HookInstallChange {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::RewroteManaged => "rewrote-managed-block",
            Self::PrependUnmanaged => "prepended-after-confirmation",
            Self::Unchanged => "unchanged",
        }
    }
}

#[derive(Debug)]
struct HookInstallPlan {
    updated: String,
    change: HookInstallChange,
}

fn plan_pre_commit_hook(existing: &str) -> Result<HookInstallPlan, CliError> {
    let block = managed_pre_commit_block();
    if existing.is_empty() {
        return Ok(HookInstallPlan {
            updated: format!("#!/bin/sh\n\n{block}"),
            change: HookInstallChange::Created,
        });
    }
    if let Some(begin) = existing.find(HOOK_BEGIN) {
        let Some(relative_end) = existing[begin..].find(HOOK_END) else {
            return Err(metadata_invalid_error(
                ".git/hooks/pre-commit has an unterminated Locket pre-commit block",
            ));
        };
        let end = begin + relative_end + HOOK_END.len();
        let replace_end =
            if existing[end..].starts_with('\n') { end + '\n'.len_utf8() } else { end };
        let mut updated = String::new();
        updated.push_str(&existing[..begin]);
        updated.push_str(&block);
        updated.push_str(&existing[replace_end..]);
        let change = if updated == existing {
            HookInstallChange::Unchanged
        } else {
            HookInstallChange::RewroteManaged
        };
        return Ok(HookInstallPlan { updated, change });
    }

    let updated = if let Some(rest) = existing.strip_prefix("#!") {
        let Some(newline_index) = rest.find('\n') else {
            return Ok(HookInstallPlan {
                updated: format!("{existing}\n\n{block}"),
                change: HookInstallChange::PrependUnmanaged,
            });
        };
        let shebang_end = "#!".len() + newline_index + 1;
        let mut updated = String::new();
        updated.push_str(&existing[..shebang_end]);
        updated.push('\n');
        updated.push_str(&block);
        updated.push('\n');
        updated.push_str(&existing[shebang_end..]);
        updated
    } else {
        format!("{block}\n{existing}")
    };
    Ok(HookInstallPlan { updated, change: HookInstallChange::PrependUnmanaged })
}

fn confirm_unmanaged_pre_commit_hook(
    context: &RuntimeContext,
    output: &mut dyn Write,
    project_name: &str,
    hook_path: &Path,
    existing: &str,
) -> Result<(), CliError> {
    writeln!(output, "pre_commit_hook: unmanaged")?;
    writeln!(output, "path: {}", hook_path.display())?;
    writeln!(output, "existing_lines: {}", existing.lines().count())?;
    writeln!(output, "existing_bytes: {}", existing.len())?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "preview: prepend Locket managed block and preserve existing hook content")?;
    writeln!(output, "managed_begin: {HOOK_BEGIN}")?;
    writeln!(output, "managed_command: locket scan --staged")?;
    writeln!(output, "managed_end: {HOOK_END}")?;
    writeln!(output, "type project name '{project_name}' to confirm")?;
    let confirmation = context
        .confirmation_reader
        .read_confirmation("install-hooks unmanaged hook replacement")?;
    if confirmation.trim_end_matches(['\r', '\n']) != project_name {
        return Err(confirmation_failed_error("confirmation did not match project name"));
    }
    Ok(())
}

pub fn git_dir_for_worktree(start: &Path) -> Result<PathBuf, CliError> {
    let mut current = start.canonicalize()?;
    loop {
        let dot_git = current.join(".git");
        if let Ok(metadata) = fs::metadata(&dot_git) {
            if metadata.is_dir() {
                return Ok(dot_git);
            }

            let pointer = fs::read_to_string(&dot_git)?;
            let Some(path) = pointer.trim().strip_prefix("gitdir:") else {
                return Err(metadata_invalid_error("unsupported .git worktree pointer"));
            };
            let path = path.trim();
            return Ok(if Path::new(path).is_absolute() {
                PathBuf::from(path)
            } else {
                current.join(path)
            });
        }

        if !current.pop() {
            return Err(invalid_reference_error("git worktree required for install-hooks"));
        }
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() | 0o700);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Executable mode bits apply only on Unix.
const fn make_executable(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

fn write_hook_install_audit_if_available(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    hook_path: &Path,
    change: HookInstallChange,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let hook_path_hash = metadata_path_hash(hook_path);
    let metadata = json!({
        "schema_version": 1,
        "action": "HOOK_INSTALL",
        "status": "SUCCESS",
        "command": "install-hooks",
        "hook": "pre-commit",
        "hook_change": change.as_str(),
        "hook_command": "locket scan --staged",
        "hook_path_kind": "git-hooks/pre-commit",
        "hook_path_hash": hook_path_hash,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "HOOK_INSTALL",
        status: "SUCCESS",
        secret_name: None,
        command: Some("install-hooks"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn metadata_path_hash(path: &Path) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(HEX[usize::from(byte >> 4)] as char);
        hex.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    hex
}
