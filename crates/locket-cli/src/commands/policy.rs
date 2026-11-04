use clap::{Args, Subcommand};
use locket_core::{
    CommandPolicy, CommandSpec, ExternalEnvSource, LkReferenceUri, LocketError, PolicyDocument,
    SecretName,
};
use locket_crypto::KeyPurpose;
use locket_scan::EntropyRule;
use locket_store::{AuditContext, AuditWrite};
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use crate::commands::config::spec::{
    config_get_value, read_user_config, validate_config_key, validate_stored_config_value,
};
use crate::commands::exec::run::agent_invoke;
use crate::commands::scan::scanner::{ScanPolicy, read_scan_policy};
use crate::runtime::error::typed_cli_error;
use crate::{
    CliError, LOCKET_TOML, ResolvedProject, RuntimeContext, confirmation_failed_error,
    default_profile, invalid_policy_error, invalid_reference_error, invalid_secret_name_error,
    load_project_key, metadata_invalid_error, now_unix_nanos, open_store, policy_not_found_error,
    require_project, secret_already_exists_error, set_user_only_file_options,
    set_user_only_file_permissions,
};

#[derive(Debug, Subcommand)]
#[command(after_help = "Command policies live under [commands.<name>] in locket.toml.\n\
                        Path-scoped env sets live under [paths.\"relative/path\"] and are merged\n\
                        into the selected command policy only when execution starts from that subtree.")]
pub enum PolicyCommand {
    /// Apply one explicitly approved desktop editor mutation from stdin.
    #[command(hide = true)]
    Apply,
    /// Add an argv command policy.
    Add(PolicyAddArgs),
    /// Append optional secret names to a policy.
    Allow(PolicySecretsArgs),
    /// Append required secret names to a policy.
    Require(PolicySecretsArgs),
    /// Delete a command policy.
    Delete(PolicyDeleteArgs),
    /// Edit a command policy in the configured editor.
    Edit(PolicyEditArgs),
    /// Review and approve the current policy source for agent reference access.
    Refresh(PolicyEditArgs),
    /// Validate policy metadata in locket.toml.
    Doctor,
}

#[derive(Debug, Args)]
pub struct PolicyAddArgs {
    /// Command policy name.
    name: String,
    /// Command and arguments after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct PolicySecretsArgs {
    /// Command policy name.
    name: String,
    /// Secret names to add.
    #[arg(required = true)]
    keys: Vec<String>,
}

#[derive(Debug, Args)]
pub struct PolicyDeleteArgs {
    /// Command policy name.
    name: String,
}

#[derive(Debug, Args)]
pub struct PolicyEditArgs {
    /// Command policy name.
    name: String,
}

pub fn command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: PolicyCommand,
) -> Result<(), CliError> {
    match command {
        PolicyCommand::Apply => apply_editor_command(context, output),
        PolicyCommand::Add(args) => add(context, output, args),
        PolicyCommand::Allow(args) => allow(context, output, args),
        PolicyCommand::Require(args) => require(context, output, args),
        PolicyCommand::Delete(args) => delete(context, output, args),
        PolicyCommand::Edit(args) => edit(context, output, &args),
        PolicyCommand::Refresh(args) => refresh(context, output, &args),
        PolicyCommand::Doctor => doctor(context, output),
    }
}

fn add(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: PolicyAddArgs,
) -> Result<(), CliError> {
    validate_policy_name(&args.name)?;
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let mut document = read_locket_toml(&path)?;
    let commands = commands_table_mut(&mut document)?;
    if commands.contains_key(&args.name) {
        return Err(secret_already_exists_error(format!(
            "command policy already exists: {}",
            args.name
        )));
    }

    let mut policy = toml::map::Map::new();
    policy.insert("argv".to_owned(), string_array(args.command));
    commands.insert(args.name.clone(), toml::Value::Table(policy));
    let policy_document = write_validated_locket_toml(&path, &document)?;
    write_policy_index_update_if_available(
        context,
        resolved.config.project_id.as_str(),
        &document,
        &policy_document,
        &args.name,
        "add",
    )?;
    pump_policies_to_agent(context, resolved.config.project_id.as_str(), &policy_document);
    write_policy_update(output, &args.name, "add")
}

fn allow(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: PolicySecretsArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let mut document = read_locket_toml(&path)?;
    let policy = policy_table_mut(&mut document, &args.name)?;
    let keys = validate_secret_names(args.keys)?;
    append_without_duplicates(policy, "optional_secrets", &keys)?;
    let policy_document = write_validated_locket_toml(&path, &document)?;
    write_policy_index_update_if_available(
        context,
        resolved.config.project_id.as_str(),
        &document,
        &policy_document,
        &args.name,
        "allow",
    )?;
    pump_policies_to_agent(context, resolved.config.project_id.as_str(), &policy_document);
    write_policy_update(output, &args.name, "allow")
}

fn require(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: PolicySecretsArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let mut document = read_locket_toml(&path)?;
    let policy = policy_table_mut(&mut document, &args.name)?;
    let keys = validate_secret_names(args.keys)?;
    append_without_duplicates(policy, "required_secrets", &keys)?;
    remove_values(policy, "optional_secrets", &keys)?;
    let policy_document = write_validated_locket_toml(&path, &document)?;
    write_policy_index_update_if_available(
        context,
        resolved.config.project_id.as_str(),
        &document,
        &policy_document,
        &args.name,
        "require",
    )?;
    pump_policies_to_agent(context, resolved.config.project_id.as_str(), &policy_document);
    write_policy_update(output, &args.name, "require")
}

fn delete(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: PolicyDeleteArgs,
) -> Result<(), CliError> {
    let PolicyDeleteArgs { name } = args;
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let mut document = read_locket_toml(&path)?;
    let commands = commands_table_mut(&mut document)?;
    if !commands.contains_key(&name) {
        return Err(policy_not_found_error(format!("command policy not found: {name}")));
    }
    write_policy_delete_confirmation(output, &name)?;
    let confirmation = context.confirmation_reader.read_confirmation("policy delete")?;
    if confirmation.trim_end_matches(['\r', '\n']) != name {
        return Err(confirmation_failed_error("confirmation did not match policy name"));
    }
    commands.remove(&name);
    let policy_document = write_validated_locket_toml(&path, &document)?;
    write_policy_index_delete_if_available(context, resolved.config.project_id.as_str(), &name)?;
    pump_policies_to_agent(context, resolved.config.project_id.as_str(), &policy_document);
    write_policy_update(output, &name, "delete")
}

fn edit(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &PolicyEditArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let document = read_locket_toml(&path)?;
    ensure_policy_exists(&document, &args.name)?;
    let editor = configured_editor(context)?;
    let edit_path = write_edit_copy(&path, &document)?;
    let edit_result = run_policy_editor(&editor, &edit_path)
        .and_then(|()| apply_edited_policy(&path, &edit_path, &args.name));
    let cleanup_result = fs::remove_file(&edit_path);
    if let Err(error) = cleanup_result
        && error.kind() != io::ErrorKind::NotFound
        && edit_result.is_ok()
    {
        return Err(error.into());
    }
    edit_result?;
    let updated_document = read_locket_toml(&path)?;
    let policy_document = PolicyDocument::from_toml_value(&updated_document)
        .map_err(|error| metadata_invalid_error(error.to_string()))?;
    write_policy_index_update_if_available(
        context,
        resolved.config.project_id.as_str(),
        &updated_document,
        &policy_document,
        &args.name,
        "edit",
    )?;
    pump_policies_to_agent(context, resolved.config.project_id.as_str(), &policy_document);
    write_policy_update(output, &args.name, "edit")
}

fn refresh(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &PolicyEditArgs,
) -> Result<(), CliError> {
    validate_policy_name(&args.name)?;
    let resolved = require_project(context)?;
    crate::ensure_trusted_project_root(&open_store(context)?, &resolved)?;
    let path = resolved.root.join(LOCKET_TOML);
    let source = read_locket_toml(&path)?;
    let parsed = PolicyDocument::from_toml_value(&source)
        .map_err(|error| metadata_invalid_error(error.to_string()))?;
    let policy = parsed.commands.get(&args.name).ok_or_else(|| {
        policy_not_found_error(format!("command policy not found: {}", args.name))
    })?;
    writeln!(output, "policy_refresh: {}", args.name)?;
    writeln!(output, "review_source: {}", path.display())?;
    writeln!(
        output,
        "allowed_secret_names: {}",
        policy.allowed_secrets.iter().map(ToString::to_string).collect::<Vec<_>>().join(" ")
    )?;
    writeln!(
        output,
        "path_scopes: {}",
        parsed.path_scopes.keys().cloned().collect::<Vec<_>>().join(" ")
    )?;
    writeln!(output, "review the command, path scopes, and secret ACLs in this file")?;
    writeln!(output, "type '{}' to approve the current policy source", args.name)?;
    let confirmation = context.confirmation_reader.read_confirmation("policy refresh")?;
    if confirmation.trim_end_matches(['\r', '\n']) != args.name {
        return Err(confirmation_failed_error("confirmation did not match policy name"));
    }
    let current = read_locket_toml(&path)?;
    if *current != *source {
        return Err(metadata_invalid_error(
            "command configuration changed during approval; retry policy refresh",
        ));
    }
    write_policy_index_update_if_available(
        context,
        resolved.config.project_id.as_str(),
        &source,
        &parsed,
        &args.name,
        "refresh",
    )?;
    pump_policies_to_agent(context, resolved.config.project_id.as_str(), &parsed);
    write_policy_update(output, &args.name, "refresh")
}

fn doctor(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let policy_text = fs::read_to_string(&path)?;
    let raw: toml::Value = toml::from_str(&policy_text)
        .map_err(|_| metadata_invalid_error("invalid project configuration"))?;
    let document = PolicyDocument::from_toml_value(&raw)
        .map_err(|error| metadata_invalid_error(error.to_string()))?;
    let refreshes = policy_indexes_needing_refresh(context, &resolved, &raw, &document)?;

    let has_lk_references = policy_text.contains("lk://");
    let validation = if document.commands.is_empty() {
        DoctorValidation::default()
    } else {
        validate_policies_via_agent(context, &resolved, &document)
    };

    let header_status = if !refreshes.is_empty()
        || validation.has_failures()
        || (validation.fatal_error.is_some() && has_lk_references)
    {
        "incomplete"
    } else {
        "ok"
    };
    writeln!(output, "policy_doctor: {header_status}")?;
    writeln!(output, "policies: {}", document.commands.len())?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "minimal_env_allowlist: {}", locket_exec::DEFAULT_SAFE_ALLOWLIST.join(" "))?;
    write_doctor_scanner_warnings(output, &path)?;
    for policy in document.commands.values().filter(|policy| !policy.override_explicit()) {
        writeln!(
            output,
            "warning: policy {} uses implicit override=locket; set override explicitly",
            policy.name
        )?;
    }

    for report in &validation.reports {
        write_policy_doctor_report(output, report)?;
    }
    for name in &refreshes {
        writeln!(output, "warning: policy {name} needs local approval of its current source")?;
        writeln!(output, "next_step: review locket.toml, then run `locket policy refresh {name}`")?;
    }

    write_doctor_audit_if_available(context, &resolved, &validation)?;

    if matches!(validation.fatal_error.as_ref(), Some(FatalDoctorError::AgentUnavailable)) {
        writeln!(
            output,
            "next_step: run `locket agent start`, `locket unlock`, then `locket policy doctor`"
        )?;
        if has_lk_references {
            writeln!(output, "warning: lk:// validation skipped because agent is unavailable")?;
            writeln!(output, "unvalidated_lk_references: present")?;
            return Err(typed_cli_error(
                LocketError::AgentUnavailable,
                "AgentUnavailable: policy doctor could not validate lk:// references",
            ));
        }
        // No agent and no lk:// references → keep the legacy "ok"
        // outcome so projects that have not yet started the agent can
        // still run `policy doctor` for the scanner checks.
        if refreshes.is_empty() {
            return Ok(());
        }
    }
    if matches!(validation.fatal_error.as_ref(), Some(FatalDoctorError::UnlockRequired)) {
        writeln!(output, "next_step: run `locket unlock`, then `locket policy doctor`")?;
    }
    if !refreshes.is_empty() {
        return Err(typed_cli_error(
            LocketError::PolicyValidationIncomplete,
            "policy indexes need approval; review locket.toml and run the listed policy refresh commands",
        ));
    }

    if let Some(error) = validation.exit_error {
        return Err(error);
    }
    Ok(())
}

fn write_doctor_scanner_warnings(output: &mut impl Write, path: &Path) -> Result<(), CliError> {
    let scan_policy = read_scan_policy(path)?;
    let entropy_rule = scan_policy.entropy_rule;
    if entropy_rule != EntropyRule::default() {
        writeln!(
            output,
            "warning: non-default scanner thresholds high_entropy min_length={} entropy_threshold={}",
            entropy_rule.min_len, entropy_rule.threshold
        )?;
    }
    let default_scan_policy = ScanPolicy::default();
    if scan_policy.provider_token_severity() != default_scan_policy.provider_token_severity()
        || scan_policy.env_file_severity() != default_scan_policy.env_file_severity()
    {
        writeln!(
            output,
            "warning: non-default scanner severity provider_token={} env_file={}",
            scan_policy.provider_token_severity().as_str(),
            scan_policy.env_file_severity().as_str()
        )?;
    }
    Ok(())
}

fn policy_indexes_needing_refresh(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    source: &toml::Value,
    parsed: &PolicyDocument,
) -> Result<Vec<String>, CliError> {
    let store = open_store(context)?;
    let mut names = Vec::new();
    for name in parsed.commands.keys() {
        if let Some(index) =
            store.get_command_policy_index(resolved.config.project_id.as_str(), name)?
            && !policy_index_matches_source(&index, resolved, source, name)?
        {
            names.push(name.clone());
        }
    }
    Ok(names)
}

fn policy_index_matches_source(
    index: &locket_store::CommandPolicyIndexRecord,
    resolved: &ResolvedProject,
    source: &toml::Value,
    name: &str,
) -> Result<bool, CliError> {
    let digest = locket_core::policy::policy_source_digest(source, name)?;
    Ok(index.normalized_json.get("source_path") == Some(&json!(resolved.root.join(LOCKET_TOML)))
        && index.normalized_json.get("source_digest").and_then(serde_json::Value::as_str)
            == Some(&digest)
        && index.policy_json == policy_json(source, name)?)
}

/// Outcome of an agent-driven validation pass over the project's
/// command policies.
#[derive(Default)]
struct DoctorValidation {
    reports: Vec<PolicyDoctorReport>,
    fatal_error: Option<FatalDoctorError>,
    exit_error: Option<CliError>,
    pass_count: usize,
    fail_count: usize,
}

impl DoctorValidation {
    const fn has_failures(&self) -> bool {
        self.fail_count > 0
    }
}

/// Sticky errors that suppress per-policy reports because the agent is
/// not in a shape that can answer further validation calls.
enum FatalDoctorError {
    AgentUnavailable,
    UnlockRequired,
}

struct PolicyDoctorReport {
    name: String,
    status: PolicyDoctorStatus,
    allowed_env_names_count: usize,
    ttl_seconds: u32,
    references_ok_count: usize,
    references_failed: Vec<String>,
    env_mode_passthrough: Vec<String>,
    env_mode_resolve: Vec<String>,
    env_mode_denied: Vec<String>,
    error_kind: Option<String>,
    error_message: Option<String>,
}

#[derive(Clone, Copy)]
enum PolicyDoctorStatus {
    Pass,
    Fail,
    Skipped,
}

fn validate_policies_via_agent(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    document: &PolicyDocument,
) -> DoctorValidation {
    let mut validation = DoctorValidation::default();

    let mut store = match open_store(context) {
        Ok(store) => store,
        Err(error) => {
            validation.exit_error = Some(error);
            return validation;
        }
    };
    let profile = match default_profile(&store, &resolved.config) {
        Ok(profile) => profile,
        Err(error) => {
            validation.exit_error = Some(error);
            return validation;
        }
    };
    // The profile lookup also implicitly verifies the store is
    // reachable; we then drop our exclusive write borrow so the agent
    // can do its own writes during validation.
    let _ = &mut store;

    let binding = match locket_platform::current_process_binding() {
        Ok(binding) => locket_agent::GrantBinding::new(binding.pid, binding.process_start_time),
        Err(error) => {
            validation.exit_error = Some(error.into());
            return validation;
        }
    };

    let policies: Vec<&CommandPolicy> = document.commands.values().collect();

    for policy in &policies {
        let report =
            validate_one_policy(context, resolved, &profile, policy, &binding, &mut validation);
        match report.status {
            PolicyDoctorStatus::Pass => validation.pass_count += 1,
            PolicyDoctorStatus::Fail => validation.fail_count += 1,
            PolicyDoctorStatus::Skipped => {}
        }
        validation.reports.push(report);
        if validation.fatal_error.is_some() {
            break;
        }
    }

    if validation.fatal_error.is_none() && validation.fail_count > 0 {
        validation.exit_error = Some(typed_cli_error(
            LocketError::PolicyValidationIncomplete,
            format!(
                "PolicyValidationIncomplete: {} of {} policies failed validation",
                validation.fail_count,
                policies.len()
            ),
        ));
    }

    validation
}

fn validate_one_policy(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    profile: &locket_store::ProfileRecord,
    policy: &CommandPolicy,
    binding: &locket_agent::GrantBinding,
    validation: &mut DoctorValidation,
) -> PolicyDoctorReport {
    // Step 1: PrepareExec. This double-duties as our reachability
    // probe for the agent. AgentUnavailable / UnlockRequired escalate
    // to fatal_error so subsequent policies skip the call.
    let prepare_request = locket_agent::PrepareExecRequest {
        policy_name: policy.name.clone(),
        profile_id: profile.id.clone(),
        project_id: Some(resolved.config.project_id.to_string()),
        binding: Some(binding.clone()),
    };
    let prepare = match agent_invoke::<_, locket_agent::PrepareExecResponse>(
        context,
        locket_agent::AgentMethod::PrepareExec,
        &prepare_request,
        "prepare exec for doctor",
    ) {
        Ok(response) => response,
        Err(error) => {
            return record_fatal_or_failed(validation, policy, &error);
        }
    };

    // Step 2: ResolveReference for each lk:// reference embedded in the
    // policy command. We classify references not on the policy
    // allow-list as `denied`, references whose value resolves as
    // `resolve`, and required/optional secret names that are not
    // referenced as `passthrough`.
    let allowed_env_names: BTreeSet<String> = prepare.allowed_env_names.iter().cloned().collect();
    let references = collect_command_lk_references(policy);
    let mut references_failed = Vec::new();
    let mut env_mode_resolve = BTreeSet::new();
    let mut env_mode_denied = BTreeSet::new();
    let mut references_ok = 0_usize;

    let needs_grant = !references.is_empty();
    let resolve_grant = if needs_grant {
        if let Some(reused) = reuse_prepare_exec_grant_for_resolve(&prepare.grant_id) {
            // The agent surfaced the live PrepareExec grant id, so we
            // skip the redundant `RequestGrant(ResolveReference)` and
            // pass the umbrella grant straight through to the
            // `ResolveReference` calls below.
            Some(reused)
        } else {
            // TODO(prepare-exec-grant-fallback-removal): drop this
            // legacy branch once a release has shipped where every
            // running agent populates `PrepareExecResponse::grant_id`.
            // The fallback exists so a newer CLI keeps working against
            // an older agent that returns an empty `grant_id` field.
            match agent_invoke::<_, locket_agent::GrantIdPayload>(
                context,
                locket_agent::AgentMethod::RequestGrant,
                &locket_agent::RequestGrantPayload {
                    project_id: resolved.config.project_id.to_string(),
                    profile_id: profile.id.clone(),
                    policy_name: Some(policy.name.clone()),
                    action: locket_agent::GrantAction::ResolveReference,
                    ttl_seconds: policy.ttl.as_secs(),
                    binding: binding.clone(),
                },
                "request resolve grant for doctor",
            ) {
                Ok(response) => Some(response),
                Err(error) => return record_fatal_or_failed(validation, policy, &error),
            }
        }
    } else {
        None
    };

    classify_references(
        context,
        resolved,
        profile,
        policy,
        binding,
        &references,
        &allowed_env_names,
        resolve_grant.as_ref(),
        &mut references_ok,
        &mut references_failed,
        &mut env_mode_resolve,
        &mut env_mode_denied,
    );

    // Required + optional secret names that are not embedded as
    // lk:// references are pass-through candidates: their value comes
    // from the parent or external env at run time, but PrepareExec
    // confirms the policy is willing to authorize them.
    let referenced_keys: BTreeSet<String> = references
        .iter()
        .filter_map(|reference| LkReferenceUri::parse(reference).ok())
        .map(|parsed| parsed.key().as_str().to_owned())
        .collect();
    let mut env_mode_passthrough: Vec<String> = policy
        .required_secrets
        .iter()
        .chain(policy.optional_secrets.iter())
        .map(|name| name.as_str().to_owned())
        .filter(|name| allowed_env_names.contains(name) && !referenced_keys.contains(name))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    env_mode_passthrough.sort();

    let status = if references_failed.is_empty() {
        PolicyDoctorStatus::Pass
    } else {
        PolicyDoctorStatus::Fail
    };

    PolicyDoctorReport {
        name: policy.name.clone(),
        status,
        allowed_env_names_count: prepare.allowed_env_names.len(),
        ttl_seconds: prepare.ttl_seconds,
        references_ok_count: references_ok,
        references_failed,
        env_mode_passthrough,
        env_mode_resolve: env_mode_resolve.into_iter().collect(),
        env_mode_denied: env_mode_denied.into_iter().collect(),
        error_kind: None,
        error_message: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn classify_references(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    profile: &locket_store::ProfileRecord,
    policy: &CommandPolicy,
    binding: &locket_agent::GrantBinding,
    references: &[String],
    allowed_env_names: &BTreeSet<String>,
    resolve_grant: Option<&locket_agent::GrantIdPayload>,
    references_ok: &mut usize,
    references_failed: &mut Vec<String>,
    env_mode_resolve: &mut BTreeSet<String>,
    env_mode_denied: &mut BTreeSet<String>,
) {
    for reference in references {
        let Ok(parsed) = LkReferenceUri::parse(reference) else {
            references_failed.push(reference.clone());
            continue;
        };
        let key_str = parsed.key().as_str().to_owned();
        if !allowed_env_names.contains(&key_str) {
            env_mode_denied.insert(key_str.clone());
            references_failed.push(reference.clone());
            continue;
        }
        let request = locket_agent::ResolveRequest {
            reference: reference.clone(),
            project_id: Some(resolved.config.project_id.to_string()),
            profile_id: Some(profile.id.clone()),
            policy_name: Some(policy.name.clone()),
            store_path: Some(context.store_path.display().to_string()),
            grant_id: resolve_grant.map(|grant| grant.grant_id.clone()),
            binding: Some(binding.clone()),
        };
        if agent_invoke::<_, locket_agent::ResolveResponse>(
            context,
            locket_agent::AgentMethod::ResolveReference,
            &request,
            "resolve reference for doctor",
        )
        .is_ok()
        {
            *references_ok += 1;
            env_mode_resolve.insert(key_str);
        } else {
            references_failed.push(reference.clone());
        }
    }
}

/// Decides whether `policy doctor` can reuse the live `PrepareExec`
/// grant for the follow-up `ResolveReference` calls. Returns
/// `Some(GrantIdPayload)` when the agent surfaced a non-empty
/// `grant_id` (the post-shipping path), and `None` when the field is
/// empty (legacy fallback that re-issues a `RequestGrant` round-trip).
fn reuse_prepare_exec_grant_for_resolve(grant_id: &str) -> Option<locket_agent::GrantIdPayload> {
    if grant_id.is_empty() {
        None
    } else {
        Some(locket_agent::GrantIdPayload { grant_id: grant_id.to_owned() })
    }
}

fn record_fatal_or_failed(
    validation: &mut DoctorValidation,
    policy: &CommandPolicy,
    error: &CliError,
) -> PolicyDoctorReport {
    let kind = match error {
        CliError::Typed { kind, .. } => Some(*kind),
        _ => None,
    };
    let message = error.to_string();
    if matches!(kind, Some(LocketError::AgentUnavailable)) {
        validation.fatal_error = Some(FatalDoctorError::AgentUnavailable);
    } else if matches!(kind, Some(LocketError::UnlockRequired)) {
        validation.fatal_error = Some(FatalDoctorError::UnlockRequired);
        validation.exit_error = Some(typed_cli_error(LocketError::UnlockRequired, message.clone()));
    }
    PolicyDoctorReport {
        name: policy.name.clone(),
        status: PolicyDoctorStatus::Skipped,
        allowed_env_names_count: 0,
        ttl_seconds: 0,
        references_ok_count: 0,
        references_failed: Vec::new(),
        env_mode_passthrough: Vec::new(),
        env_mode_resolve: Vec::new(),
        env_mode_denied: Vec::new(),
        error_kind: kind.map(|kind| format!("{kind:?}")),
        error_message: Some(message),
    }
}

fn collect_command_lk_references(policy: &CommandPolicy) -> Vec<String> {
    let mut out = Vec::new();
    let scan = |text: &str, into: &mut Vec<String>| {
        let mut rest = text;
        while let Some(idx) = rest.find("lk://") {
            let after = &rest[idx..];
            // Capture up to the next whitespace or quote — argv
            // entries are already separated, but shell scripts can
            // embed the reference inside a larger token.
            let end = after
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`')
                .unwrap_or(after.len());
            let candidate = after[..end].to_owned();
            if !candidate.is_empty() {
                into.push(candidate);
            }
            rest = &after[end..];
        }
    };
    match &policy.command {
        CommandSpec::Argv(args) => {
            for arg in args {
                if arg.contains("lk://") {
                    scan(arg, &mut out);
                }
            }
        }
        CommandSpec::Shell(script) => scan(script, &mut out),
    }
    out
}

fn write_policy_doctor_report(
    output: &mut impl Write,
    report: &PolicyDoctorReport,
) -> Result<(), CliError> {
    writeln!(output, "policy: {}", report.name)?;
    if let (Some(kind), Some(message)) =
        (report.error_kind.as_deref(), report.error_message.as_deref())
    {
        writeln!(output, "  status: skipped ({kind})")?;
        writeln!(output, "  detail: {message}")?;
        return Ok(());
    }
    writeln!(output, "  allowed_env_names: {}", report.allowed_env_names_count)?;
    writeln!(output, "  ttl_seconds: {}", report.ttl_seconds)?;
    writeln!(output, "  references_ok: {}", report.references_ok_count)?;
    if report.references_failed.is_empty() {
        writeln!(output, "  references_failed: none")?;
    } else {
        writeln!(output, "  references_failed: {}", report.references_failed.join(","))?;
    }
    writeln!(
        output,
        "  env_mode_expansion: passthrough=[{}] resolve=[{}] denied=[{}]",
        report.env_mode_passthrough.join(","),
        report.env_mode_resolve.join(","),
        report.env_mode_denied.join(","),
    )?;
    Ok(())
}

fn write_doctor_audit_if_available(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    validation: &DoctorValidation,
) -> Result<(), CliError> {
    if validation.reports.is_empty() {
        return Ok(());
    }
    let mut store = open_store(context)?;
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let timestamp = now_unix_nanos()?;
    let check_names: Vec<String> =
        validation.reports.iter().map(|report| format!("policy.{}", report.name)).collect();
    let metadata = json!({
        "schema_version": 1,
        "action": "DOCTOR",
        "status": if validation.fail_count == 0 { "SUCCESS" } else { "FAILED" },
        "command": "policy doctor",
        "check_names": check_names,
        "pass_count": validation.pass_count,
        "fail_count": validation.fail_count,
        "skip_count": validation.reports.iter().filter(|report| {
            matches!(report.status, PolicyDoctorStatus::Skipped)
        }).count(),
        "warn_count": 0,
        "critical_fail_count": validation.fail_count,
    });
    let status = if validation.fail_count == 0 { "SUCCESS" } else { "FAILED" };
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "DOCTOR",
        status,
        secret_name: None,
        command: Some("policy doctor"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn read_locket_toml(path: &Path) -> Result<locket_platform::PolicyFileDocument, CliError> {
    locket_platform::PolicyFileDocument::read(path)
        .map_err(|error| metadata_invalid_error(error.to_string()))
}

fn write_validated_locket_toml(
    _path: &Path,
    document: &locket_platform::PolicyFileDocument,
) -> Result<PolicyDocument, CliError> {
    document.save().map_err(|error| metadata_invalid_error(error.to_string()))
}

fn ensure_policy_exists(document: &toml::Value, name: &str) -> Result<(), CliError> {
    let exists = document
        .get("commands")
        .and_then(toml::Value::as_table)
        .and_then(|commands| commands.get(name))
        .and_then(toml::Value::as_table)
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(policy_not_found_error(format!("command policy not found: {name}")))
    }
}

fn configured_editor(context: &RuntimeContext) -> Result<String, CliError> {
    let config = read_user_config(context)?;
    let spec = validate_config_key("editor.default")?;
    if let Some(value) = config_get_value(&config, "editor.default") {
        validate_stored_config_value(spec, value)?;
        let Some(editor) = value.as_str() else {
            return Err(metadata_invalid_error("invalid stored config value for editor.default"));
        };
        return Ok(editor.to_owned());
    }
    std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .map_err(|_| {
            metadata_invalid_error("policy edit requires editor.default, VISUAL, or EDITOR")
        })
        .and_then(|editor| validate_editor_command(&editor).map(|()| editor))
}

fn validate_editor_command(editor: &str) -> Result<(), CliError> {
    if editor.is_empty()
        || editor.chars().any(char::is_control)
        || editor.chars().any(char::is_whitespace)
    {
        return Err(metadata_invalid_error(
            "policy editor must be a command name or absolute path without arguments",
        ));
    }
    if editor.starts_with('~') || editor.contains('$') || editor.contains('`') {
        return Err(metadata_invalid_error("policy editor must not use shell expansion"));
    }
    Ok(())
}

fn write_edit_copy(path: &Path, document: &toml::Value) -> Result<PathBuf, CliError> {
    let edit_path = path.with_file_name(format!(
        ".locket-policy-edit-{}-{}.toml",
        std::process::id(),
        now_unix_nanos()?
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    set_user_only_file_options(&mut options);
    let mut file = options.open(&edit_path)?;
    file.write_all(toml::to_string_pretty(document)?.as_bytes())?;
    set_user_only_file_permissions(&edit_path)?;
    Ok(edit_path)
}

fn run_policy_editor(editor: &str, edit_path: &Path) -> Result<(), CliError> {
    let status = ProcessCommand::new(editor).arg(edit_path).status().map_err(CliError::from)?;
    if status.success() {
        Ok(())
    } else {
        Err(invalid_policy_error("policy editor exited unsuccessfully"))
    }
}

fn apply_edited_policy(path: &Path, edit_path: &Path, name: &str) -> Result<(), CliError> {
    let edited_text = fs::read_to_string(edit_path)?;
    let edited = toml::from_str::<toml::Value>(&edited_text)
        .map_err(|error| invalid_policy_error(format!("invalid edited policy TOML: {error}")))?;
    ensure_policy_exists(&edited, name)?;
    let content = toml::to_string_pretty(&edited)?;
    PolicyDocument::from_toml_value(&edited)
        .map_err(|error| invalid_policy_error(format!("invalid edited policy: {error}")))?;
    fs::write(path, content)?;
    Ok(())
}

fn commands_table_mut(
    document: &mut toml::Value,
) -> Result<&mut toml::map::Map<String, toml::Value>, CliError> {
    let Some(root) = document.as_table_mut() else {
        return Err(metadata_invalid_error("locket.toml root must be a table"));
    };
    let commands = root
        .entry("commands".to_owned())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    commands.as_table_mut().ok_or_else(|| metadata_invalid_error("commands must be a table"))
}

fn policy_table_mut<'a>(
    document: &'a mut toml::Value,
    name: &str,
) -> Result<&'a mut toml::map::Map<String, toml::Value>, CliError> {
    let commands = commands_table_mut(document)?;
    commands
        .get_mut(name)
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| policy_not_found_error(format!("command policy not found: {name}")))
}

fn validate_policy_name(name: &str) -> Result<(), CliError> {
    if name.is_empty() {
        return Err(invalid_reference_error("policy name must not be empty"));
    }
    Ok(())
}

fn validate_secret_names(keys: Vec<String>) -> Result<Vec<String>, CliError> {
    keys.into_iter()
        .map(|key| {
            if SecretName::new(key.clone()).is_err() {
                return Err(invalid_secret_name_error(format!("invalid secret name: {key}")));
            }
            Ok(key)
        })
        .collect()
}

fn append_without_duplicates(
    policy: &mut toml::map::Map<String, toml::Value>,
    field: &str,
    keys: &[String],
) -> Result<(), CliError> {
    let array = string_array_mut(policy, field)?;
    for key in keys {
        if !array.iter().any(|value| value.as_str() == Some(key.as_str())) {
            array.push(toml::Value::String(key.clone()));
        }
    }
    Ok(())
}

fn remove_values(
    policy: &mut toml::map::Map<String, toml::Value>,
    field: &str,
    keys: &[String],
) -> Result<(), CliError> {
    let Some(value) = policy.get_mut(field) else {
        return Ok(());
    };
    let Some(array) = value.as_array_mut() else {
        return Err(metadata_invalid_error(format!("{field} must be an array")));
    };
    array.retain(|value| !value.as_str().is_some_and(|name| keys.iter().any(|key| key == name)));
    Ok(())
}

fn string_array_mut<'a>(
    policy: &'a mut toml::map::Map<String, toml::Value>,
    field: &str,
) -> Result<&'a mut Vec<toml::Value>, CliError> {
    let value = policy.entry(field.to_owned()).or_insert_with(|| toml::Value::Array(Vec::new()));
    value.as_array_mut().ok_or_else(|| metadata_invalid_error(format!("{field} must be an array")))
}

fn string_array(values: Vec<String>) -> toml::Value {
    toml::Value::Array(values.into_iter().map(toml::Value::String).collect())
}

fn write_policy_update(
    output: &mut impl Write,
    name: &str,
    operation: &str,
) -> Result<(), CliError> {
    writeln!(output, "policy: {name}")?;
    writeln!(output, "operation: {operation}")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn write_policy_delete_confirmation(output: &mut impl Write, name: &str) -> Result<(), CliError> {
    writeln!(output, "policy_delete: {name}")?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "affected_shell_hooks: live grants revoked when available")?;
    writeln!(output, "affected_tray_actions: policy shortcuts removed")?;
    writeln!(output, "affected_automation_clients: policy grants revoked when available")?;
    writeln!(output, "affected_vscode_tasks: policy tasks removed")?;
    writeln!(output, "type '{name}' to confirm policy delete")?;
    Ok(())
}

fn write_policy_index_update_if_available(
    context: &RuntimeContext,
    project_id: &str,
    raw_document: &toml::Value,
    policy_document: &PolicyDocument,
    policy_name: &str,
    operation: &str,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(project_id)?.is_none() {
        return Ok(());
    }
    let raw_policy_json = policy_json(raw_document, policy_name)?;
    let policy = policy_document.commands.get(policy_name).ok_or_else(|| {
        metadata_invalid_error(format!("command policy missing after validation: {policy_name}"))
    })?;
    let mut normalized_json = normalized_policy_json(policy);
    let source = require_project(context)?;
    if source.config.project_id.as_str() != project_id {
        return Err(metadata_invalid_error("command source project changed before index refresh"));
    }
    normalized_json["source_path"] = json!(source.root.join(LOCKET_TOML));
    normalized_json["source_digest"] =
        json!(locket_core::policy::policy_source_digest(raw_document, policy_name)?);
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let timestamp = now_unix_nanos()?;
    let metadata = policy_update_metadata(operation, policy_name);
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "POLICY_UPDATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("policy"),
        metadata_json: &metadata,
        timestamp,
    };
    store.upsert_command_policy_index(
        project_id,
        policy_name,
        &raw_policy_json,
        &normalized_json,
        timestamp,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    Ok(())
}

fn write_policy_index_delete_if_available(
    context: &RuntimeContext,
    project_id: &str,
    policy_name: &str,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(project_id)?.is_none() {
        return Ok(());
    }
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let timestamp = now_unix_nanos()?;
    let metadata = policy_update_metadata("delete", policy_name);
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "POLICY_UPDATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("policy"),
        metadata_json: &metadata,
        timestamp,
    };
    store.delete_command_policy_index(
        project_id,
        policy_name,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    Ok(())
}

fn policy_update_metadata(operation: &str, policy: &str) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "action": "POLICY_UPDATE",
        "status": "SUCCESS",
        "command": "policy",
        "operation": operation,
        "policy": policy,
        "policy_name": policy,
        "change_kind": operation,
        "metadata_only": true,
    })
}

fn policy_json(document: &toml::Value, policy_name: &str) -> Result<serde_json::Value, CliError> {
    let policy = document
        .get("commands")
        .and_then(toml::Value::as_table)
        .and_then(|commands| commands.get(policy_name))
        .ok_or_else(|| metadata_invalid_error(format!("command policy missing: {policy_name}")))?;
    serde_json::to_value(policy).map_err(CliError::from)
}

fn normalized_policy_json(policy: &CommandPolicy) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "name": policy.name,
        "command": command_json(&policy.command),
        "allowed_secrets": secret_name_strings(&policy.allowed_secrets),
        "required_secrets": secret_name_strings(&policy.required_secrets),
        "optional_secrets": secret_name_strings(&policy.optional_secrets),
        "inherit_env": policy.inherit_env,
        "env_mode": policy.env_mode.as_str(),
        "override": policy.override_behavior.as_str(),
        "override_explicit": policy.override_explicit(),
        "external_env_sources": policy
            .external_env_sources
            .iter()
            .map(external_env_source_json)
            .collect::<Vec<_>>(),
        "allow_remote_docker": policy.allow_remote_docker,
        "confirm": policy.confirm,
        "require_user_verification": policy.require_user_verification,
        "require_agent": policy.require_agent,
        "ttl_seconds": policy.ttl.as_secs(),
    })
}

fn command_json(command: &CommandSpec) -> serde_json::Value {
    match command {
        CommandSpec::Argv(argv) => json!({ "type": "argv", "argv": argv }),
        CommandSpec::Shell(shell) => json!({ "type": "shell", "shell": shell }),
    }
}

fn secret_name_strings(names: &[SecretName]) -> Vec<&str> {
    names.iter().map(SecretName::as_str).collect()
}

fn external_env_source_json(source: &ExternalEnvSource) -> serde_json::Value {
    match source {
        ExternalEnvSource::Parent => json!({ "type": "parent" }),
        ExternalEnvSource::File(path) => {
            json!({ "type": "file", "path": path.display().to_string() })
        }
        ExternalEnvSource::Compose => json!({ "type": "compose" }),
        ExternalEnvSource::Ide => json!({ "type": "ide" }),
    }
}

/// Best-effort: pump the post-write policy snapshot to the running agent so
/// `policy doctor` and `locket run` resolve the new policy set without
/// requiring a desktop client to push the snapshot. The agent is fire-and-
/// forget: when it is unreachable, locked, or otherwise rejects the call,
/// the user-facing CLI command must still succeed. Failures are logged to
/// stderr at debug level so operators have a breadcrumb without polluting
/// scripted output.
pub fn pump_policies_to_agent(
    context: &RuntimeContext,
    project_id: &str,
    policy_document: &PolicyDocument,
) {
    #[cfg(any(unix, windows))]
    {
        let snapshots = build_snapshots(project_id, policy_document);
        let payload = json!({
            "project_id": project_id,
            "policies": snapshots,
            "store_path": context.store_path,
            "audit_profile_id": serde_json::Value::Null,
        });
        if let Err(error) = pump_policies_endpoint(context, payload)
            && std::env::var_os("LOCKET_DEBUG").is_some()
        {
            let mut stderr = io::stderr();
            let _ignored = writeln!(
                stderr,
                "locket: debug: agent RegisterCommandPolicies pump failed: {error}",
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (context, project_id, policy_document);
    }
}

fn build_snapshots(
    project_id: &str,
    document: &PolicyDocument,
) -> Vec<locket_agent::CommandPolicySnapshot> {
    let updated_at = now_unix_nanos().unwrap_or(0);
    document
        .commands
        .values()
        .map(|policy| {
            locket_agent::CommandPolicySnapshot::from_policy(project_id, policy, updated_at)
        })
        .collect()
}

#[cfg(any(unix, windows))]
fn pump_policies_endpoint(
    context: &RuntimeContext,
    payload: serde_json::Value,
) -> Result<(), io::Error> {
    use locket_agent::{
        AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, RequestEnvelope, ResponseEnvelope, encode_frame,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[cfg(unix)]
    use tokio::net::UnixStream;

    let socket_path = crate::agent_socket_path(context);
    #[cfg(unix)]
    if !socket_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("agent socket missing at {}", socket_path.display()),
        ));
    }

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async move {
        #[cfg(unix)]
        let mut stream = UnixStream::connect(&socket_path).await?;
        #[cfg(windows)]
        let mut stream = locket_agent::connect_named_pipe_client(&socket_path).await?;
        let request = RequestEnvelope::new(
            "cli-pump-policies",
            AgentMethod::RegisterCommandPolicies,
            payload,
        );
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid agent request frame")
        })?;
        stream.write_all(&frame).await?;
        stream.flush().await?;

        let mut buffer = Vec::with_capacity(1024);
        loop {
            if let Some(response) = crate::commands::agent::decode_agent_frame(&buffer)? {
                return match response {
                    ResponseEnvelope::Success(_) => Ok(()),
                    ResponseEnvelope::Error(error) => Err(io::Error::other(format!(
                        "agent error {}: {}",
                        error.error, error.message
                    ))),
                };
            }
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "agent closed connection without a response",
                ));
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
    })
}

#[cfg(all(test, unix))]
mod framing_tests {
    #![allow(clippy::panic)]

    use crate::commands::agent::framing_tests::{
        CANARY, fragmented_success, invalid_frame, with_open_peer,
    };
    use serde_json::json;

    fn rejects_frame(kind: &str) {
        let result = with_open_peer(vec![invalid_frame(kind)], |context| {
            super::pump_policies_endpoint(context, json!({}))
        });
        let Err(error) = result else {
            panic!("permanent frame error expected");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("invalid agent response frame"));
        assert!(!error.to_string().contains(CANARY));
    }

    #[test]
    fn policy_reader_rejects_oversized_frame_while_peer_stays_open() {
        rejects_frame("oversized");
    }

    #[test]
    fn policy_reader_rejects_malformed_frame_while_peer_stays_open() {
        rejects_frame("malformed");
    }

    #[test]
    fn policy_reader_rejects_version_frame_while_peer_stays_open() {
        rejects_frame("version");
    }

    #[test]
    fn policy_reader_accepts_fragmented_frame_while_peer_stays_open() {
        let result = with_open_peer(fragmented_success(), |context| {
            super::pump_policies_endpoint(context, json!({}))
        });
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::reuse_prepare_exec_grant_for_resolve;

    #[test]
    fn reuse_prepare_exec_grant_skips_request_grant_when_grant_id_present() {
        // After the prepare-exec-grant-return slice ships, the doctor
        // path receives the live PrepareExec grant on the response and
        // must not issue a separate `RequestGrant(ResolveReference)`.
        // The helper returns `Some(...)` so the caller takes the reuse
        // branch, dropping the second RPC entirely.
        let reused =
            reuse_prepare_exec_grant_for_resolve("lk_grant_0123456789abcdef0123456789abcdef");
        assert_eq!(
            reused.as_ref().map(|payload| payload.grant_id.as_str()),
            Some("lk_grant_0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn reuse_prepare_exec_grant_falls_back_when_grant_id_is_empty() {
        // Older agents return an empty `grant_id`; the doctor must
        // fall back to the legacy `RequestGrant(ResolveReference)`
        // round-trip, which is signalled by the helper returning
        // `None`. This branch is removed once the
        // `prepare-exec-grant-fallback-removal` TODO is closed.
        assert!(reuse_prepare_exec_grant_for_resolve("").is_none());
    }
}

/// Saves an explicitly approved command using the shared durable policy writer.
/// Refreshes derived reference permissions before an explicit local CLI run.
pub fn refresh_command_policy_for_run(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    name: &str,
) -> Result<(), CliError> {
    let document = read_locket_toml(&resolved.root.join(LOCKET_TOML))?;
    let parsed = PolicyDocument::from_toml_value(&document)
        .map_err(|error| metadata_invalid_error(error.to_string()))?;
    let store = open_store(context)?;
    crate::ensure_trusted_project_root(&store, resolved)?;
    if let Some(index) =
        store.get_command_policy_index(resolved.config.project_id.as_str(), name)?
        && policy_index_matches_source(&index, resolved, &document, name)?
    {
        return Ok(());
    }
    write_policy_index_update_if_available(
        context,
        resolved.config.project_id.as_str(),
        &document,
        &parsed,
        name,
        "refresh",
    )?;
    pump_policies_to_agent(context, resolved.config.project_id.as_str(), &parsed);
    Ok(())
}

pub fn persist_command_policy(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    policy: &CommandPolicy,
) -> Result<(), CliError> {
    validate_policy_name(&policy.name)?;
    let store = open_store(context)?;
    crate::ensure_trusted_project_root(&store, resolved)?;
    let path = resolved.root.join(LOCKET_TOML);
    let mut document = locket_platform::PolicyFileDocument::read(&path)
        .map_err(|error| metadata_invalid_error(error.to_string()))?;
    commands_table_mut(&mut document)?
        .insert(policy.name.clone(), locket_core::policy::command_policy_value(policy));
    let parsed = document.save().map_err(|error| metadata_invalid_error(error.to_string()))?;
    write_policy_index_update_if_available(
        context,
        resolved.config.project_id.as_str(),
        &document,
        &parsed,
        &policy.name,
        "approve",
    )?;
    pump_policies_to_agent(context, resolved.config.project_id.as_str(), &parsed);
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EditorPolicyMutation {
    project_id: String,
    mode: String,
    original_name: String,
    policy: locket_agent::CommandPolicySnapshot,
    confirmation: Option<String>,
}

fn apply_editor_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    use std::io::Read as _;
    const MAX_REQUEST_BYTES: u64 = 65_536;
    let mut input = Vec::new();
    io::stdin().take(MAX_REQUEST_BYTES + 1).read_to_end(&mut input)?;
    if input.len() > usize::try_from(MAX_REQUEST_BYTES).unwrap_or(65_536) {
        return Err(metadata_invalid_error("policy editor request exceeds 64 KiB"));
    }
    let request: EditorPolicyMutation = serde_json::from_slice(&input)
        .map_err(|_| metadata_invalid_error("invalid policy editor request"))?;
    apply_editor_policy(context, output, &request)
}

fn apply_editor_policy(
    context: &RuntimeContext,
    output: &mut impl Write,
    request: &EditorPolicyMutation,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    let profile = default_profile(&store, &resolved.config)?;
    let (master, _) = crate::runtime::key_access::load_master_key_verified_by_project_key(
        context,
        &store,
        project_id,
        KeyPurpose::Audit,
    )?;
    let mutation = locket_agent::ApplyPolicyRequest {
        scope: locket_agent::MutationScope {
            store_path: context.store_path.clone(),
            project_root: resolved.root.clone(),
            project_id: request.project_id.clone(),
            profile_id: profile.id,
            grant_id: None,
            binding: None,
        },
        mode: request.mode.clone(),
        original_name: request.original_name.clone(),
        policy: request.policy.clone(),
        confirmation: request.confirmation.clone(),
    };
    locket_agent::apply_policy_with_master(&mutation, &master, now_unix_nanos()?).map_err(
        |error| match error.code {
            "ConfirmationFailed" => confirmation_failed_error(error.message),
            "SecretAlreadyExists" => secret_already_exists_error(error.message),
            "PolicyNotFound" => policy_not_found_error(error.message),
            _ => metadata_invalid_error(error.message),
        },
    )?;
    let saved = fs::read_to_string(resolved.root.join(LOCKET_TOML))?;
    let parsed = PolicyDocument::from_toml_str(&saved)
        .map_err(|_| metadata_invalid_error("saved policy could not be read"))?;
    pump_policies_to_agent(context, project_id, &parsed);
    write_policy_update(output, &request.policy.name, &request.mode)
}

#[cfg(test)]
mod persistence_tests {
    use clap::Parser;

    #[test]
    fn policy_cli_preserves_project_comments() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let context = crate::tests::test_context(&directory);
        crate::run_with_context(
            crate::Cli::try_parse_from([
                "locket",
                "init",
                "--no-device",
                "--no-passkey",
                "--name",
                "comments",
            ])?,
            &context,
            &mut Vec::new(),
        )?;
        let path = directory.path().join("locket.toml");
        let source = std::fs::read_to_string(&path)?;
        std::fs::write(&path, format!("# Keep our team notes\n{source}"))?;
        crate::run_with_context(
            crate::Cli::try_parse_from([
                "locket", "policy", "add", "dev", "--", "npm", "run", "dev",
            ])?,
            &context,
            &mut Vec::new(),
        )?;
        let saved = std::fs::read_to_string(path)?;
        assert!(saved.contains("# Keep our team notes"));
        Ok(())
    }
    #[test]
    fn editor_policy_edit_persists_authorization_without_losing_argv_or_gates()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let context = crate::tests::test_context(&directory);
        crate::run_with_context(
            crate::Cli::try_parse_from([
                "locket",
                "init",
                "--no-device",
                "--no-passkey",
                "--name",
                "editor",
            ])?,
            &context,
            &mut Vec::new(),
        )?;
        let resolved = crate::require_project(&context)?;
        let path = directory.path().join("locket.toml");
        let mut source = std::fs::read_to_string(&path)?;
        source.push_str(
            r#"
# Keep command annotations
[commands.dev]
argv = ["node", "a b.js"]
require_agent = true
inherit_env = ["PATH", "HOME"]
external_env_sources = ["ide"]
"#,
        );
        std::fs::write(&path, &source)?;
        let parsed = locket_core::PolicyDocument::from_toml_str(&source)?;
        let mut snapshot = locket_agent::CommandPolicySnapshot::from_policy(
            resolved.config.project_id.as_str(),
            &parsed.commands["dev"],
            1,
        );
        snapshot.required_secrets = vec!["DATABASE_URL".into()];
        snapshot.allowed_secrets = snapshot.required_secrets.clone();
        let request = super::EditorPolicyMutation {
            project_id: resolved.config.project_id.to_string(),
            mode: "edit".into(),
            original_name: "dev".into(),
            policy: snapshot,
            confirmation: None,
        };
        super::apply_editor_policy(&context, &mut Vec::new(), &request)?;
        let saved = std::fs::read_to_string(&path)?;
        assert!(saved.contains("# Keep command annotations"));
        let raw: toml::Value = toml::from_str(&saved)?;
        assert_eq!(raw["commands"]["dev"]["argv"][1].as_str(), Some("a b.js"));
        let policy = locket_core::PolicyDocument::from_toml_str(&saved)?;
        assert!(policy.commands["dev"].require_agent);
        assert_eq!(policy.commands["dev"].inherit_env, ["PATH", "HOME"]);
        let index = crate::open_store(&context)?
            .get_command_policy_index(resolved.config.project_id.as_str(), "dev")?
            .ok_or("policy index")?;
        assert_eq!(index.normalized_json["allowed_secrets"], serde_json::json!(["DATABASE_URL"]));
        Ok(())
    }
}
