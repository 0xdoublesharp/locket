//! Project trust-root command implementations.

use std::io::Write;

use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, Store};
use serde_json::json;

use crate::{
    CliError, ProjectCommand, ResolvedProject, RuntimeContext, confirmation_failed_error,
    ensure_project_exists, format_hex, load_project_key, now_unix_nanos, open_store, optional_i64,
    parse_root_hash, require_project, root_hash,
};

pub fn project_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: ProjectCommand,
) -> Result<(), CliError> {
    match command {
        ProjectCommand::List { json, redact_names } => {
            crate::commands::discovery::project_list_command(context, output, json, redact_names)
        }
        ProjectCommand::TrustRoot => trust_root_command(context, output),
        ProjectCommand::ListRoots => list_roots_command(context, output),
        ProjectCommand::UntrustRoot { root_hash } => {
            untrust_root_command(context, output, &root_hash)
        }
    }
}

fn trust_root_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;

    let hash = root_hash(&resolved.root)?;
    let was_trusted = store.project_root_is_trusted(resolved.config.project_id.as_str(), &hash)?;
    let timestamp = now_unix_nanos()?;
    let display_path = resolved.root.to_string_lossy();
    confirm_trust_root(context, output, &resolved, &hash)?;
    store.trust_project_root(
        resolved.config.project_id.as_str(),
        &hash,
        Some(display_path.as_ref()),
        timestamp,
    )?;
    write_trust_root_audit(
        context,
        &mut store,
        &resolved,
        &hash,
        if was_trusted { "refresh" } else { "trust" },
        0,
        timestamp,
    )?;

    writeln!(
        output,
        "{}",
        if was_trusted { "trusted root already present" } else { "trusted root added" }
    )?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "root_hash: {}", format_hex(&hash))?;
    writeln!(output, "display_path: {}", resolved.root.display())?;
    writeln!(output, "last_seen_at: {timestamp}")?;
    Ok(())
}

fn list_roots_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;

    let roots = store.list_project_roots(resolved.config.project_id.as_str())?;
    if roots.is_empty() {
        writeln!(output, "no trusted roots")?;
        return Ok(());
    }

    for root in roots {
        writeln!(output, "root_hash: {}", format_hex(&root.root_hash))?;
        writeln!(output, "display_path: {}", root.display_path.as_deref().unwrap_or("-"))?;
        writeln!(output, "created_at: {}", root.created_at)?;
        writeln!(output, "last_seen_at: {}", optional_i64(root.last_seen_at))?;
    }
    Ok(())
}

fn untrust_root_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    root_hash: &str,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;

    let hash = parse_root_hash(root_hash)?;
    confirm_untrust_root(context, output, &hash)?;
    let timestamp = now_unix_nanos()?;
    let removed = store.untrust_project_root(resolved.config.project_id.as_str(), &hash)?;
    let revoked = store.deny_directory_grants_for_root(
        resolved.config.project_id.as_str(),
        &hash,
        timestamp,
    )?;
    write_trust_root_audit(context, &mut store, &resolved, &hash, "untrust", revoked, timestamp)?;
    writeln!(
        output,
        "{}",
        if removed { "trusted root removed" } else { "trusted root not found" }
    )?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "root_hash: {}", format_hex(&hash))?;
    writeln!(output, "directory_grants_revoked: {revoked}")?;
    writeln!(output, "live_grants: unavailable")?;
    Ok(())
}

fn confirm_trust_root(
    context: &RuntimeContext,
    output: &mut impl Write,
    resolved: &ResolvedProject,
    root_hash: &[u8; 32],
) -> Result<(), CliError> {
    writeln!(output, "canonical_path: {}", resolved.root.display())?;
    writeln!(output, "root_hash: {}", format_hex(root_hash))?;
    writeln!(output, "type project name '{}' to confirm trusted root", resolved.config.name)?;
    let confirmation = context.confirmation_reader.read_confirmation("project trust-root")?;
    if confirmation.trim_end_matches(['\r', '\n']) != resolved.config.name {
        return Err(confirmation_failed_error("confirmation did not match project name"));
    }
    Ok(())
}

fn confirm_untrust_root(
    context: &RuntimeContext,
    output: &mut impl Write,
    root_hash: &[u8; 32],
) -> Result<(), CliError> {
    let root_hash = format_hex(root_hash);
    writeln!(output, "root_hash: {root_hash}")?;
    writeln!(output, "type root hash '{root_hash}' to confirm removal")?;
    let confirmation = context.confirmation_reader.read_confirmation("project untrust-root")?;
    if confirmation.trim_end_matches(['\r', '\n']) != root_hash {
        return Err(confirmation_failed_error("confirmation did not match root hash"));
    }
    Ok(())
}

fn write_trust_root_audit(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    root_hash: &[u8; 32],
    operation: &str,
    directory_grants_revoked: usize,
    timestamp: i64,
) -> Result<(), CliError> {
    let audit_key =
        load_project_key(context, store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "TRUST_ROOT",
        "status": "SUCCESS",
        "command": "project",
        "operation": operation,
        "trust_operation": operation,
        "root_hash": format_hex(root_hash),
        "directory_grants_revoked": directory_grants_revoked,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "TRUST_ROOT",
        status: "SUCCESS",
        secret_name: None,
        command: Some("project"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
