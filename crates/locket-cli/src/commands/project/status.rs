//! `locket status` command.

use std::io::Write;
use std::path::Path;

use locket_store::ProfileRecord;
use serde_json::{Value, json};

use crate::commands::agent::{request_project_status_snapshot, request_status_snapshot};
use crate::commands::config::spec::read_user_config;
use crate::commands::discovery::{global_vault_project, read_metadata_store};
use crate::commands::scan::scanner;
use crate::{
    CliError, EXAMPLE_FILE, LOCKET_TOML, ResolvedProject, RuntimeContext, active_secrets_by_name,
    agent_socket_path, config_bool_value, invalid_policy_error, open_store, privacy_alias,
    read_policy_document, resolve_project, root_hash,
};

pub fn status_json(context: &RuntimeContext, scan: bool) -> Result<Value, CliError> {
    let resolved = resolve_project(&context.cwd)?;
    let store = read_metadata_store(context)?;
    let redact_names = status_privacy_redact_names_enabled(context)?;
    let shared_project_id = match &store {
        Some(store) => global_vault_project(store)?
            .map(|project| status_project_id_label(&project.id, redact_names)),
        None => None,
    };
    let socket = agent_socket_path(context);
    let Some(resolved) = resolved else {
        return Ok(json!({
            "has_locket_config": false,
            "project_id": null,
            "project_name": null,
            "profile": null,
            "has_shared_vault": shared_project_id.is_some(),
            "shared_project_id": shared_project_id,
            "agent_running": request_status_snapshot(&socket).is_ok(),
            "secret_count": 0,
            "policy_names": [],
            "metadata_only": true,
        }));
    };

    let project_id = resolved.config.project_id.as_str();
    let snapshot = request_project_status_snapshot(&socket, project_id).ok();
    let project_snapshot = matching_project_snapshot(snapshot.as_ref(), project_id);
    let vault_unlocked = match project_snapshot.and_then(|snapshot| snapshot["lock_state"].as_str())
    {
        Some("locked") => Some(false),
        Some("unlocked") => Some(true),
        _ => None,
    };
    let profile_name = project_snapshot
        .and_then(|snapshot| snapshot["profile_name"].as_str())
        .unwrap_or(resolved.config.default_profile.as_str());
    let (profile, secret_count) = match &store {
        Some(store) => {
            let profile = store.get_profile_by_name(project_id, profile_name)?;
            let count = match &profile {
                Some(profile) => active_secrets_by_name(store, project_id, &profile.id)?.len(),
                None => 0,
            };
            (profile, count)
        }
        None => (None, 0),
    };
    let policy_names = read_policy_document(&resolved.root.join(LOCKET_TOML))
        .map_err(|_| invalid_policy_error("could not read project policy metadata"))?
        .commands
        .into_keys()
        .map(|name| if redact_names { privacy_alias("policy", &name) } else { name })
        .collect::<Vec<_>>();
    let mut status = json!({
        "has_locket_config": true,
        "project_id": status_project_id_label(project_id, redact_names),
        "project_name": status_project_label(&resolved, redact_names),
        "profile": status_profile_label(profile.as_ref(), profile_name, redact_names),
        "has_shared_vault": shared_project_id.is_some(),
        "shared_project_id": shared_project_id,
        "agent_running": snapshot.is_some(),
        "vault_unlocked": vault_unlocked,
        "secret_count": secret_count,
        "policy_names": policy_names,
        "metadata_only": true,
    });
    if scan {
        status["scan_warnings"] = json!(status_scan_warning_count(&resolved.root)?);
    }
    Ok(status)
}

pub fn status_with_scan(
    context: &RuntimeContext,
    output: &mut impl Write,
    scan: bool,
) -> Result<(), CliError> {
    let Some(resolved) = resolve_project(&context.cwd)? else {
        writeln!(output, "locket: not initialized")?;
        writeln!(output, "next_action: run locket init")?;
        return Ok(());
    };

    let store = open_store(context)?;
    let project = store.get_project(resolved.config.project_id.as_str())?;
    let root_hash = root_hash(&resolved.root)?;
    let trusted = store.project_root_is_trusted(resolved.config.project_id.as_str(), &root_hash)?;
    let profile = store.get_profile_by_name(
        resolved.config.project_id.as_str(),
        resolved.config.default_profile.as_str(),
    )?;
    let redact_names = status_privacy_redact_names_enabled(context)?;
    let project_label = status_project_label(&resolved, redact_names);
    let profile_label = status_profile_label(
        profile.as_ref(),
        resolved.config.default_profile.as_str(),
        redact_names,
    );
    let running_sessions =
        store.list_incomplete_runtime_sessions(resolved.config.project_id.as_str())?.len();
    let project_id = resolved.config.project_id.as_str();
    let snapshot = request_project_status_snapshot(&agent_socket_path(context), project_id).ok();
    let project_snapshot = matching_project_snapshot(snapshot.as_ref(), project_id);
    let active_name = project_snapshot
        .and_then(|snapshot| snapshot.get("profile_name"))
        .and_then(serde_json::Value::as_str);
    let active_profile_label = active_name.map_or_else(
        || "unknown".to_owned(),
        |name| {
            if redact_names { privacy_alias("profile", name) } else { name.to_owned() }
        },
    );
    let lock_state = project_snapshot
        .and_then(|snapshot| snapshot.get("lock_state"))
        .and_then(serde_json::Value::as_str)
        .filter(|state| matches!(*state, "locked" | "unlocked"))
        .unwrap_or("unknown");
    let scan_warning_count =
        if scan { Some(status_scan_warning_count(&resolved.root)?) } else { None };
    let example_exists = resolved.root.join(EXAMPLE_FILE).exists();
    let next_action = status_next_action(
        project.as_ref(),
        profile.as_ref(),
        trusted,
        example_exists,
        scan_warning_count.unwrap_or(0),
    );

    writeln!(output, "project: {project_label}")?;
    writeln!(
        output,
        "project_id: {}",
        status_project_id_label(resolved.config.project_id.as_str(), redact_names)
    )?;
    writeln!(output, "root: {}", resolved.root.display())?;
    let canonical_cwd = context.cwd.canonicalize().ok();
    let cwd_display = canonical_cwd
        .as_deref()
        .map_or_else(|| context.cwd.display().to_string(), |path| path.display().to_string());
    let cwd_matches_root = canonical_cwd.as_deref() == Some(&resolved.root);
    writeln!(output, "cwd: {cwd_display}")?;
    writeln!(output, "cwd_matches_root: {}", if cwd_matches_root { "yes" } else { "no" })?;
    if !cwd_matches_root {
        writeln!(
            output,
            "cwd_hint: locket.toml resolved from a parent directory; commands act on the project at root:"
        )?;
    }
    writeln!(output, "default_profile: {profile_label}")?;
    writeln!(output, "active_profile: {active_profile_label}")?;
    writeln!(output, "lock_state: {lock_state}")?;
    let agent_state = if snapshot.is_some() { "running" } else { "unavailable" };
    writeln!(output, "agent: {agent_state}")?;
    writeln!(output, "agent_state: {agent_state}")?;
    writeln!(output, "running_sessions: {running_sessions}")?;
    write_secret_expiry_summary(&store, resolved.config.project_id.as_str(), output)?;
    match scan_warning_count {
        Some(count) => writeln!(output, "scan_warnings: {count}")?,
        None => writeln!(output, "scan_warnings: unknown")?,
    }
    writeln!(output, "store: {}", if project.is_some() { "ready" } else { "partial" })?;
    writeln!(output, "trusted_root: {}", if trusted { "yes" } else { "no" })?;
    writeln!(output, "profile: {}", if profile.is_some() { "ready" } else { "missing" })?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "next_action: {next_action}")?;
    Ok(())
}

fn matching_project_snapshot<'a>(
    snapshot: Option<&'a Value>,
    project_id: &str,
) -> Option<&'a Value> {
    snapshot
        .filter(|snapshot| snapshot.get("project_id").and_then(Value::as_str) == Some(project_id))
}

fn write_secret_expiry_summary(
    store: &locket_store::Store,
    project_id: &str,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let notices = crate::commands::secrets::expiry::expiry_notices(
        store,
        project_id,
        crate::now_unix_nanos()?,
    )?;
    let expired = notices
        .iter()
        .filter(|notice| notice.expiry_status == Some(locket_store::SecretExpiryStatus::Expired))
        .count();
    let expiring_soon = notices
        .iter()
        .filter(|notice| {
            notice.expiry_status == Some(locket_store::SecretExpiryStatus::ExpiringSoon)
        })
        .count();
    let stale = notices.iter().filter(|notice| notice.stale).count();
    writeln!(
        output,
        "secret_expiry: expired={expired} expiring_soon={expiring_soon} stale={stale}"
    )?;
    Ok(())
}

fn status_privacy_redact_names_enabled(context: &RuntimeContext) -> Result<bool, CliError> {
    let config = read_user_config(context)?;
    Ok(config_bool_value(&config, "privacy.redact_names")?.unwrap_or(false))
}

fn status_project_label(resolved: &ResolvedProject, redact_names: bool) -> String {
    if redact_names {
        privacy_alias("project", resolved.config.project_id.as_str())
    } else {
        resolved.config.name.clone()
    }
}

fn status_project_id_label(project_id: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("project", project_id) } else { project_id.to_owned() }
}

fn status_profile_label(
    profile: Option<&ProfileRecord>,
    default_profile: &str,
    redact_names: bool,
) -> String {
    if redact_names {
        let profile_id = profile.map_or(default_profile, |profile| profile.id.as_str());
        privacy_alias("profile", profile_id)
    } else {
        default_profile.to_owned()
    }
}

fn status_scan_warning_count(root: &Path) -> Result<usize, CliError> {
    let mut findings = Vec::new();
    let mut suppressed = Vec::new();
    let entropy_rule = scanner::read_scan_entropy_rule(&root.join(LOCKET_TOML))?;
    scanner::scan_path(root, root, &[], entropy_rule, true, &mut findings, &mut suppressed)?;
    findings.retain(|finding| !matches!(finding.path_label.as_str(), LOCKET_TOML | EXAMPLE_FILE));
    Ok(findings.len())
}

const fn status_next_action(
    project: Option<&locket_store::ProjectRecord>,
    profile: Option<&ProfileRecord>,
    trusted_root: bool,
    example_exists: bool,
    scan_warning_count: usize,
) -> &'static str {
    if project.is_none() || profile.is_none() {
        "run locket init to resume local metadata setup"
    } else if !trusted_root {
        "run locket project trust-root"
    } else if !example_exists {
        "run locket emit-example"
    } else if scan_warning_count > 0 {
        "run locket scan"
    } else {
        "run locket setup"
    }
}
