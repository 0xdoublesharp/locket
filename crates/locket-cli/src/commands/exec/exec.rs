//! Implementation of the `locket exec` command and its private helpers.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use locket_core::{PolicyDocument, SecretName};
use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, ProfileRecord, Store};
use serde_json::json;

use super::run::{
    RuntimeExecutionRequest, execute_prepared_with_runtime_session, require_shared_vault_unlocked,
    unique_secret_names,
};
use crate::commands::agent::ensure_agent_running_for_execution;
use crate::commands::discovery::{SHARED_PROJECT_PREFIX, select_project, trusted_project_configs};
use crate::runtime::RuntimeContext;
use crate::runtime::dangerous_profile::ensure_dangerous_profile_consent;
use crate::runtime::error::{
    CliError, child_exit_error, confirmation_failed_error, exec_prepare_error,
    invalid_policy_error, invalid_reference_error, profile_not_found_error,
    project_root_untrusted_error, secret_not_found_error,
};
use crate::runtime::key_access::load_project_key;
use crate::support::secret_helpers::{
    decrypt_secret_version, select_highest_precedence_secret, summarize_names,
};
use crate::{
    ExecArgs, ResolvedProject, active_secrets_by_name, ensure_trusted_project_root, now_unix_nanos,
    open_store, require_project,
};

pub fn exec_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ExecArgs,
) -> Result<(), CliError> {
    if !args.all && args.secrets.is_empty() {
        return Err(invalid_reference_error("exec requires --all or at least one --secret"));
    }

    let implicit = args.project.is_none().then(|| require_project(context)).transpose()?;
    let store = open_store(context)?;
    let cwd = context.cwd.canonicalize()?;
    let (project_id, configs) =
        resolve_exec_target(&store, &cwd, implicit, args.project.as_deref())?;
    let default_profile =
        configs.first().map_or("default", |config| config.config.default_profile.as_str());
    let profile_name = args.profile.as_deref().unwrap_or(default_profile);
    let profile = store.get_profile_by_name(&project_id, profile_name)?.ok_or_else(|| {
        profile_not_found_error("target profile not found; pass --profile to select a profile")
    })?;
    if args.project.is_some() || args.profile.is_some() {
        ensure_dangerous_profile_consent(&profile, args.use_dangerous)?;
    }
    let mut active = active_secrets_by_name(&store, &project_id, &profile.id)?;
    let secret_names =
        if args.all { active.keys().cloned().collect::<Vec<_>>() } else { args.secrets.clone() };
    let documents = load_exec_configurations(&configs, &cwd, &secret_names, &args.command)?;

    if args.all && !args.force {
        confirm_exec_all_scope(context, output, &profile, &args.command, &secret_names)?;
    }

    let shared_project = authorize_exec_target(context, &project_id)?;

    let mut locket_env = locket_exec::EnvMap::new();
    let mut injected_sources = BTreeMap::new();
    for name in unique_secret_names(secret_names.iter().map(String::as_str)) {
        let secret = active
            .remove(&name)
            .and_then(select_highest_precedence_secret)
            .ok_or_else(|| secret_not_found_error(format!("secret not found: {name}")))?;
        let value = decrypt_secret_version(
            context,
            &store,
            &project_id,
            &profile.id,
            &secret,
            secret.current_version,
        )?;
        injected_sources.insert(name.clone(), secret.source);
        locket_env.insert(name, value);
    }
    let injected_names = injected_sources.keys().cloned().collect::<Vec<_>>();

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
    for document in &documents {
        validate_exec_configuration(document, &secret_names, &prepared.env, output)?;
    }
    let status = if injected_names.is_empty() {
        prepared.command().status()?
    } else {
        execute_prepared_with_runtime_session(
            context,
            &RuntimeExecutionRequest {
                store: &store,
                profile: &profile,
                policy_name: None,
                secret_names: &injected_names,
                prepared: &prepared,
                current_dir: Some(&context.cwd),
                run_policy_grant: None,
                shared_project,
            },
        )?
        .status
    };
    let exit_code = status.code();

    write_exec_audit_if_available(
        context,
        configs.is_empty(),
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

fn authorize_exec_target<'a>(
    context: &RuntimeContext,
    project_id: &'a str,
) -> Result<Option<&'a str>, CliError> {
    ensure_agent_running_for_execution(context)?;
    if project_id.starts_with(SHARED_PROJECT_PREFIX) {
        require_shared_vault_unlocked(context, project_id)?;
        return Ok(Some(project_id));
    }
    Ok(None)
}

fn resolve_exec_target(
    store: &Store,
    cwd: &Path,
    implicit: Option<ResolvedProject>,
    selector: Option<&str>,
) -> Result<(String, Vec<ResolvedProject>), CliError> {
    if let Some(project) = implicit {
        ensure_trusted_project_root(store, &project)?;
        return Ok((project.config.project_id.to_string(), vec![project]));
    }

    let selector = selector.ok_or_else(crate::project_not_found_error)?;
    let project = select_project(store, cwd, selector)?;
    let mut configs = trusted_project_configs(store, &project.id)?;
    if configs.is_empty() {
        if project.id.starts_with(SHARED_PROJECT_PREFIX)
            && store.list_project_roots(&project.id)?.is_empty()
        {
            return Ok((project.id, configs));
        }
        return Err(project_root_untrusted_error());
    }
    if let Some(index) = configs
        .iter()
        .enumerate()
        .filter(|(_, config)| cwd.starts_with(&config.root))
        .max_by_key(|(_, config)| config.root.components().count())
        .map(|(index, _)| index)
    {
        let config = configs.swap_remove(index);
        configs = vec![config];
    }
    Ok((project.id, configs))
}

fn load_exec_configurations(
    configs: &[ResolvedProject],
    cwd: &Path,
    secret_names: &[String],
    command: &[String],
) -> Result<Vec<PolicyDocument>, CliError> {
    let names = secret_names
        .iter()
        .map(|name| SecretName::new(name.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid_policy_error("invalid selected secret name"))?;
    configs
        .iter()
        .map(|config| {
            let document = crate::read_policy_document(&config.root.join(crate::LOCKET_TOML))?;
            let relative = cwd
                .strip_prefix(&config.root)
                .ok()
                .map(|path| if path.as_os_str().is_empty() { Path::new(".") } else { path });
            enforce_exec_access(&document, relative, &names, command)?;
            Ok(document)
        })
        .collect()
}

fn enforce_exec_access(
    document: &PolicyDocument,
    relative_cwd: Option<&Path>,
    secret_names: &[SecretName],
    command: &[String],
) -> Result<(), CliError> {
    // Outside the project, an execution cannot satisfy a project-relative path rule.
    let denied = secret_names
        .iter()
        .filter(|name| {
            document.secret_access.get(name.as_str()).is_some_and(|acl| {
                (relative_cwd.is_none() && !acl.allow_paths.is_empty())
                    || !acl.allows(
                        "exec",
                        Some(command),
                        relative_cwd.unwrap_or_else(|| Path::new(".")),
                    )
            })
        })
        .map(SecretName::as_str)
        .collect::<Vec<_>>();
    if !denied.is_empty() {
        return Err(invalid_policy_error(format!(
            "secret ACL denied command exec for: {}",
            denied.join(", ")
        )));
    }
    Ok(())
}

fn validate_exec_configuration(
    document: &PolicyDocument,
    secret_names: &[String],
    env: &locket_exec::EnvMap,
    output: &mut impl Write,
) -> Result<(), CliError> {
    // Ad-hoc exec selects existing vault names explicitly. Contracts validate these
    // values but do not authorize additional names or apply saved-command defaults.
    for name in secret_names {
        let contract = document.variables.get(name);
        if let (Some(contract), Some(value)) = (contract, env.get(name)) {
            contract
                .validate_value(value)
                .map_err(|error| invalid_policy_error(error.to_string()))?;
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
    rootless: bool,
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
    let project_id = &profile.project_id;
    if rootless && store.get_key_by_scope(project_id, None, KeyPurpose::Audit.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
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
        project_id,
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
