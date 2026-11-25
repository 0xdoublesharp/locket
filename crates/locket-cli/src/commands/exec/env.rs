//! Implementation of the `locket env` command and inspection helpers.

use std::io::Write;

use locket_core::CommandPolicy;

use super::docker::{prepare_docker_policy_execution, write_docker_policy_audit_if_available};
use super::run::resolve_policy_external_env;
use crate::runtime::RuntimeContext;
use crate::runtime::error::{CliError, child_exit_error};
use crate::support::secret_helpers::{PolicySecretSelection, policy_secret_selections};
use crate::{
    EnvCommand, EnvDockerArgs, EnvInspectArgs, command_type, effective_policy_profile,
    ensure_trusted_project_root, external_env_source_label, load_effective_command_policy,
    open_store, require_project,
};

pub fn env_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: EnvCommand,
) -> Result<(), CliError> {
    match command {
        EnvCommand::Validate(args) => env_validate_command(context, output, &args),
        EnvCommand::Inspect(args) => env_inspect_command(context, output, &args),
        EnvCommand::Docker(args) => env_docker_command(context, output, &args),
    }
}

pub fn env_inspect_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &EnvInspectArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let effective = load_effective_command_policy(&resolved, &args.policy, &context.cwd)?;
    let policy = &effective.policy;
    let store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let profile = effective_policy_profile(&store, &resolved, &effective)?;
    let selections = policy_secret_selections(&store, &resolved, &profile, policy)?;
    let parent_env = std::env::vars()
        .map(|(name, value)| (name, locket_exec::env_value(value)))
        .collect::<locket_exec::EnvMap>();
    let external_env = resolve_policy_external_env(policy, &parent_env, &resolved.root)?;

    writeln!(output, "policy {}", policy.name)?;
    writeln!(output, "command_type={}", command_type(&policy.command))?;
    writeln!(output, "env_mode={}", policy.env_mode)?;
    writeln!(output, "override={}", policy.override_behavior)?;
    if let Some(path) = &effective.path_scope_path {
        writeln!(output, "path_scope={}", path.display())?;
    }
    if let Some(profile) = &effective.path_scope_profile {
        writeln!(output, "path_scope_profile={profile}")?;
    }
    if !policy.external_env_sources.is_empty() {
        writeln!(output, "external_layers names={}", inspect_env_names(&external_env))?;
    }
    for source in &policy.external_env_sources {
        writeln!(
            output,
            "external_source {} decision=resolved",
            external_env_source_label(source)
        )?;
    }

    let document = crate::read_policy_document(&resolved.root.join(crate::LOCKET_TOML))?;
    let selected_sources =
        inspect_selected_sources(policy, &parent_env, &external_env, &selections)?;
    writeln!(output, "configuration_values_checked=false")?;
    for row in document.variable_readiness(policy, &selected_sources, false) {
        writeln!(
            output,
            "configuration {} state={:?} source={}",
            row.name,
            row.state,
            row.selected_source.as_deref().unwrap_or("none")
        )?;
        for guidance in [&row.description, &row.setup_hint, &row.next_action, &row.warning]
            .into_iter()
            .flatten()
        {
            writeln!(output, "  {guidance}")?;
        }
    }
    for selection in &selections {
        let sources = if selection.sources.is_empty() {
            "none".to_owned()
        } else {
            selection.sources.join(",")
        };
        let selected = selection.selected_source().unwrap_or("none");
        let conflicts = inspect_conflicts(selection, &parent_env, &external_env, policy);
        let decision = if selection.shared && selection.selected.is_none() {
            "missing-required"
        } else if selection.selected.is_none() && !external_env.contains_key(&selection.name) {
            if selected_sources.contains_key(&selection.name) {
                "inherit"
            } else if document
                .variables
                .get(&selection.name)
                .is_some_and(|contract| contract.default.is_some())
            {
                "public-default"
            } else {
                inspect_decision(selection, &parent_env, &external_env, policy)
            }
        } else {
            inspect_decision(selection, &parent_env, &external_env, policy)
        };
        writeln!(
            output,
            "secret {} kind={} sources={} selected={} conflicts={} decision={}",
            selection.name,
            if selection.required { "required" } else { "optional" },
            sources,
            selected,
            conflicts,
            decision
        )?;
    }
    Ok(())
}

fn inspect_selected_sources(
    policy: &CommandPolicy,
    parent_env: &locket_exec::EnvMap,
    external_env: &locket_exec::EnvMap,
    selections: &[PolicySecretSelection],
) -> Result<std::collections::BTreeMap<String, String>, CliError> {
    let inherited_names = policy.inherit_env.iter().map(String::as_str).collect::<Vec<_>>();
    let inherited = locket_exec::merge_environment(
        parent_env,
        locket_exec::DEFAULT_SAFE_ALLOWLIST,
        &inherited_names,
        &locket_exec::EnvMap::new(),
        &locket_exec::EnvMap::new(),
        policy.env_mode,
        policy.override_behavior,
    )
    .map_err(|_| crate::runtime::error::invalid_policy_error("environment resolution failed"))?;
    let mut selected_sources = inherited
        .keys()
        .map(|name| (name.clone(), "inherited".to_string()))
        .collect::<std::collections::BTreeMap<_, _>>();
    selected_sources
        .extend(external_env.keys().map(|name| (name.clone(), "external-source".into())));
    for selection in selections {
        if selection.shared && selection.selected.is_none() {
            selected_sources.remove(&selection.name);
        }
        if let Some(source) = selection.selected_source()
            && (!selected_sources.contains_key(&selection.name)
                || policy.override_behavior != locket_core::EnvOverrideMode::Preserve)
        {
            selected_sources.insert(selection.name.clone(), source.into());
        }
    }
    Ok(selected_sources)
}

pub fn env_docker_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &EnvDockerArgs,
) -> Result<(), CliError> {
    let parent_env = std::env::vars()
        .map(|(name, value)| (name, locket_exec::env_value(value)))
        .collect::<locket_exec::EnvMap>();
    let mut prepared =
        prepare_docker_policy_execution(context, &args.policy, &args.command, parent_env)?;
    super::run::write_configuration_warnings(&prepared.resolved, &prepared.policy, output)?;
    let status = prepared.execution.command().current_dir(&context.cwd).status()?;
    let audit_status = if status.success() { "SUCCESS" } else { "FAILED" };
    write_docker_policy_audit_if_available(context, &mut prepared, audit_status)?;
    if status.success() {
        return Ok(());
    }

    writeln!(output, "child exited with status {status}")?;
    Err(child_exit_error(status))
}

fn inspect_conflicts(
    selection: &PolicySecretSelection,
    parent_env: &locket_exec::EnvMap,
    external_env: &locket_exec::EnvMap,
    policy: &CommandPolicy,
) -> String {
    let mut conflicts = Vec::new();
    if selection.sources.len() > 1 {
        conflicts.push("multiple-active-sources");
    }
    if parent_env_conflicts_with_secret(parent_env, policy, &selection.name) {
        conflicts.push("environment");
    }
    if external_env.contains_key(&selection.name) {
        conflicts.push("external-source");
    }
    if conflicts.is_empty() { "none".to_owned() } else { conflicts.join(",") }
}

fn inspect_decision(
    selection: &PolicySecretSelection,
    parent_env: &locket_exec::EnvMap,
    external_env: &locket_exec::EnvMap,
    policy: &CommandPolicy,
) -> &'static str {
    if selection.selected.is_none() {
        if external_env.contains_key(&selection.name) {
            return "external-source";
        }
        return if selection.required { "missing-required" } else { "skip-missing" };
    }
    if parent_env_conflicts_with_secret(parent_env, policy, &selection.name)
        || external_env.contains_key(&selection.name)
    {
        return match policy.override_behavior {
            locket_exec::EnvOverrideMode::Error => "error-conflict",
            locket_exec::EnvOverrideMode::Preserve => "preserve-existing",
            locket_exec::EnvOverrideMode::Locket => "inject-overwrite",
        };
    }
    "inject"
}

fn inspect_env_names(env: &locket_exec::EnvMap) -> String {
    let mut names = env.keys().map(String::as_str).collect::<Vec<_>>();
    names.sort_unstable();
    if names.is_empty() { "none".to_owned() } else { names.join(",") }
}

fn parent_env_conflicts_with_secret(
    parent_env: &locket_exec::EnvMap,
    policy: &CommandPolicy,
    name: &str,
) -> bool {
    if !parent_env.contains_key(name) {
        return false;
    }
    match policy.env_mode {
        locket_exec::EnvMode::Strict => {
            policy.inherit_env.iter().any(|inherited| inherited == name)
        }
        locket_exec::EnvMode::Minimal => {
            locket_exec::DEFAULT_SAFE_ALLOWLIST.contains(&name)
                || policy.inherit_env.iter().any(|inherited| inherited == name)
        }
        locket_exec::EnvMode::Merge | locket_exec::EnvMode::Passthrough => true,
    }
}

/// Validates committed contracts and explicitly supplied names without local values.
pub fn env_validate_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &crate::EnvValidateArgs,
) -> Result<(), CliError> {
    let validation = offline_variable_readiness(&context.cwd, args);
    let (rows, path_scope, profile) = match validation {
        Ok(result) => result,
        Err(error) => {
            let detail = match &error {
                CliError::Typed { message, .. } if message.starts_with("invalid variable contract ") => message.clone(),
                _ => "Invalid configuration contract, provided name, policy, or path authorization. Check locket.toml and the selected command.".into(),
            };
            if args.json {
                writeln!(
                    output,
                    "{}",
                    serde_json::json!({
                        "mode": "names-only", "values_checked": false, "ready": false,
                        "error": detail
                    })
                )?;
            }
            return Err(CliError::ConfigurationValidation { code: 2, message: detail });
        }
    };
    let ready = rows.iter().all(|row| row.state != locket_core::VariableReadinessState::Missing);
    if args.json {
        writeln!(
            output,
            "{}",
            serde_json::json!({
                "mode": "names-only", "values_checked": false, "ready": ready,
                "policy": args.policy, "path_scope": path_scope, "profile": profile, "variables": rows
            })
        )?;
    } else {
        writeln!(
            output,
            "configuration_validation: {} mode=names-only values_checked=false",
            if ready { "ready" } else { "missing" }
        )?;
        for row in &rows {
            writeln!(
                output,
                "variable {} state={:?} source={}",
                row.name,
                row.state,
                row.selected_source.as_deref().unwrap_or("none")
            )?;
            for text in [&row.description, &row.setup_hint, &row.next_action, &row.warning]
                .into_iter()
                .flatten()
            {
                writeln!(output, "  {text}")?;
            }
        }
    }
    if ready {
        Ok(())
    } else {
        Err(CliError::ConfigurationValidation {
            code: 1,
            message: "Required configuration names are missing. See setup guidance above.".into(),
        })
    }
}

type OfflineReadiness = (Vec<locket_core::VariableReadinessRow>, Option<String>, Option<String>);

fn offline_variable_readiness(
    cwd: &std::path::Path,
    args: &crate::EnvValidateArgs,
) -> Result<OfflineReadiness, CliError> {
    let canonical_cwd = cwd.canonicalize()?;
    let root = canonical_cwd
        .ancestors()
        .find(|root| root.join(crate::LOCKET_TOML).is_file())
        .ok_or_else(crate::runtime::error::project_not_found_error)?;
    let document = crate::read_policy_document(&root.join(crate::LOCKET_TOML))?;
    let mut policy =
        document.commands.get(&args.policy).cloned().ok_or_else(|| {
            crate::runtime::error::invalid_policy_error("command policy not found")
        })?;
    let scope = document.path_scope_for(root, &canonical_cwd);
    if let Some(scope) = scope {
        crate::apply_path_scope_to_policy(&mut policy, scope);
    }
    crate::enforce_secret_access_policies(&document, &policy, root, &canonical_cwd)?;
    let sources = args
        .provided_name
        .iter()
        .map(|name| {
            locket_core::SecretName::new(name.clone())
                .map(|_| (name.clone(), "provided-name".into()))
                .map_err(|_| {
                    crate::runtime::error::invalid_policy_error("invalid provided variable name")
                })
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
    Ok((
        document.variable_readiness(&policy, &sources, false),
        scope.map(|scope| scope.path.to_string_lossy().into_owned()),
        scope.and_then(|scope| scope.profile.as_ref().map(ToString::to_string)),
    ))
}
