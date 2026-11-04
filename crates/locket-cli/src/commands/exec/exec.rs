//! Implementation of the `locket exec` command and its private helpers.

use std::collections::BTreeMap;
use std::io::Write;

use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, ProfileRecord};
use serde_json::json;

use super::run::{
    RuntimeExecutionRequest, execute_prepared_with_runtime_session, unique_secret_names,
};
use crate::commands::agent::ensure_agent_running_for_execution;
use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, child_exit_error, confirmation_failed_error, exec_prepare_error,
    invalid_reference_error,
};
use crate::runtime::key_access::{default_profile, load_project_key};
use crate::support::secret_helpers::{
    decrypt_current_secret, resolve_active_secret, summarize_names,
};
use crate::{
    ExecArgs, ResolvedProject, active_profile_secret_names, now_unix_nanos, open_store,
    require_project,
};

pub fn exec_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ExecArgs,
) -> Result<(), CliError> {
    if !args.all && args.secrets.is_empty() {
        return Err(invalid_reference_error("exec requires --all or at least one --secret"));
    }

    let resolved_project = require_project(context)?;
    let store = open_store(context)?;
    let profile = default_profile(&store, &resolved_project.config)?;

    let secret_names = if args.all {
        let mut names = active_profile_secret_names(
            &store,
            resolved_project.config.project_id.as_str(),
            &profile.id,
        )?
        .into_iter()
        .collect::<Vec<_>>();
        names.sort();
        names
    } else {
        args.secrets.clone()
    };

    enforce_exec_access(context, &resolved_project, &secret_names, &args.command)?;

    if args.all && !args.force {
        confirm_exec_all_scope(context, output, &profile, &args.command, &secret_names)?;
    }

    ensure_agent_running_for_execution(context)?;

    let mut resolved_secrets = Vec::with_capacity(args.secrets.len());
    let mut locket_env = locket_exec::EnvMap::new();
    let mut injected_names = Vec::with_capacity(secret_names.len());
    let mut injected_sources = BTreeMap::new();
    for key in &secret_names {
        let resolved = resolve_active_secret(context, key)?;
        let value = decrypt_current_secret(context, &resolved)?;
        injected_names.push(resolved.secret.name.clone());
        injected_sources.insert(resolved.secret.name.clone(), resolved.secret.source.clone());
        locket_env.insert(resolved.secret.name.clone(), value);
        resolved_secrets.push(resolved);
    }
    injected_names.sort();
    injected_names.dedup();
    let unique_names = unique_secret_names(injected_names.iter().map(String::as_str));
    let first_secret = resolved_secrets.first();

    let argv_program = args.command.first().cloned().unwrap_or_default();
    let arg_count = args.command.len();
    let request = locket_exec::ExecutionRequest {
        argv: args.command.clone(),
        parent_env: std::env::vars()
            .map(|(name, value)| (name, locket_exec::env_value(value)))
            .collect(),
        inherit_env: vec!["PATH".to_owned()],
        external_env: locket_exec::EnvMap::new(),
        locket_env,
        env_mode: locket_exec::EnvMode::Strict,
        override_mode: locket_exec::EnvOverrideMode::Locket,
    };
    let prepared = locket_exec::prepare_execution(&request).map_err(exec_prepare_error)?;
    validate_exec_configuration(&resolved_project, &secret_names, &prepared.env, output)?;
    let _ = first_secret;
    let status = if unique_names.is_empty() {
        prepared.command().status()?
    } else {
        execute_prepared_with_runtime_session(
            context,
            &RuntimeExecutionRequest {
                store: &store,
                resolved: &resolved_project,
                profile: &profile,
                policy_name: None,
                secret_names: &unique_names,
                prepared: &prepared,
                current_dir: Some(&context.cwd),
                run_policy_grant: None,
            },
        )?
        .status
    };
    let exit_code = status.code();

    write_exec_audit_if_available(
        context,
        &resolved_project,
        &profile,
        &argv_program,
        arg_count,
        &injected_names,
        &injected_sources,
        args.all,
        exit_code,
        if status.success() { "SUCCESS" } else { "FAILED" },
    )?;

    if status.success() {
        return Ok(());
    }
    writeln!(output, "child exited with status {status}")?;
    Err(child_exit_error(status))
}

fn enforce_exec_access(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    secret_names: &[String],
    command: &[String],
) -> Result<(), CliError> {
    // Explicit selection does not bypass the project's restrictions. Evaluate
    // every requested name before decrypting anything or starting the child.
    let document = crate::read_policy_document(&resolved.root.join(crate::LOCKET_TOML))?;
    let cwd = context.cwd.canonicalize()?;
    let relative = cwd.strip_prefix(&resolved.root).map_err(|_| {
        crate::runtime::error::invalid_policy_error("exec directory is outside the project")
    })?;
    let relative =
        if relative.as_os_str().is_empty() { std::path::Path::new(".") } else { relative };
    let names = secret_names
        .iter()
        .map(|name| locket_core::SecretName::new(name.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| crate::runtime::error::invalid_policy_error("invalid selected secret name"))?;
    let denied = document.denied_secrets("exec", Some(command), relative, &names);
    if !denied.is_empty() {
        return Err(crate::runtime::error::invalid_policy_error(format!(
            "secret ACL denied command exec for: {}",
            denied.into_iter().map(locket_core::SecretName::as_str).collect::<Vec<_>>().join(",")
        )));
    }
    Ok(())
}

fn validate_exec_configuration(
    resolved: &ResolvedProject,
    secret_names: &[String],
    env: &locket_exec::EnvMap,
    output: &mut impl Write,
) -> Result<(), CliError> {
    // Ad-hoc exec selects existing vault names explicitly. Contracts validate these
    // values but do not authorize additional names or apply saved-command defaults.
    let document = crate::read_policy_document(&resolved.root.join(crate::LOCKET_TOML))?;
    for name in secret_names {
        let contract = document.variables.get(name);
        if let (Some(contract), Some(value)) = (contract, env.get(name)) {
            contract
                .validate_value(value)
                .map_err(|error| crate::runtime::error::invalid_policy_error(error.to_string()))?;
        }
        let classification = contract
            .map_or(locket_core::VariableClassification::Secret, |contract| {
                contract.classification
            });
        if let Some(warning) = locket_core::variable_exposure_warning(name, classification) {
            writeln!(output, "warning: {warning}")?;
        }
    }
    Ok(())
}

fn confirm_exec_all_scope(
    context: &RuntimeContext,
    output: &mut impl Write,
    profile: &ProfileRecord,
    command: &[String],
    secret_names: &[String],
) -> Result<(), CliError> {
    let argv_program = command.first().map_or("", String::as_str);
    writeln!(output, "exec_profile: {}", profile.name)?;
    writeln!(output, "exec_argv_program: {argv_program}")?;
    writeln!(output, "exec_arg_count: {}", command.len())?;
    writeln!(output, "exec_secret_count: {}", secret_names.len())?;
    writeln!(output, "exec_secret_names: {}", join_or_none(secret_names))?;
    writeln!(output, "metadata_only: yes")?;
    let expected = format!("exec --all {}", profile.name);
    writeln!(output, "type '{expected}' to confirm injection")?;
    let confirmation = context.confirmation_reader.read_confirmation("exec --all")?;
    if confirmation.trim_end_matches(['\r', '\n']) != expected {
        return Err(confirmation_failed_error("confirmation did not match exec --all scope"));
    }
    Ok(())
}

fn join_or_none(names: &[String]) -> String {
    if names.is_empty() { "none".to_owned() } else { names.join(",") }
}

#[allow(clippy::too_many_arguments)]
fn write_exec_audit_if_available(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    argv_program: &str,
    arg_count: usize,
    injected_names: &[String],
    injected_sources: &BTreeMap<String, String>,
    all_mode: bool,
    exit_code: Option<i32>,
    status: &str,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "EXEC",
        "command": "exec",
        "status": status,
        "profile_id": profile.id,
        "argv_program": argv_program,
        "arg_count": arg_count,
        "secret_names": summarize_names(injected_names),
        "secret_sources": injected_sources,
        "all_mode": all_mode,
        "exit_code": exit_code,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: Some(&profile.id),
        action: "EXEC",
        status,
        secret_name: None,
        command: Some("exec"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
