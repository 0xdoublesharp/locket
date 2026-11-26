//! Shared helpers for `locket env docker` and `locket compose run`.
//!
//! Centralizes policy-backed Docker/Compose execution preparation, allow-remote
//! gating, runtime-policy compatibility checks, and the canonical RUN audit
//! payload for docker helpers.

use std::io::Write;
use std::path::Path;
use std::process::ExitStatus;

use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, ProfileRecord, Store};
use serde_json::{Value, json};

use crate::commands::policy::{ApprovedPolicySource, require_approved_policy_source};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, access_denied_error, invalid_reference_error, metadata_invalid_error,
    unimplemented_in_build_error,
};
use crate::runtime::key_access::load_project_key;
use crate::support::secret_helpers::{
    PolicySecretSelection, decrypt_secret_version, policy_secret_selections, summarize_names,
};
use crate::{EffectiveCommandPolicy, ResolvedProject};
use crate::{
    effective_command_policy, effective_policy_profile, now_unix_nanos, open_store, require_project,
};

use locket_core::{CommandPolicy, CommandSpec};

/// Indicates whether a docker helper invocation targets `docker run` or `docker compose`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerHelperKind {
    /// `docker run`.
    DockerRun,
    /// `docker compose`.
    Compose,
}

/// Prepared state for invoking a docker helper under a command policy.
#[derive(Debug)]
pub struct PreparedDockerPolicyExecution {
    /// The opened backing store used for policy resolution and audit append.
    pub store: Store,
    /// Project resolved for the active working directory.
    pub resolved: ResolvedProject,
    /// Profile whose secrets are being injected.
    pub profile: ProfileRecord,
    /// The command policy controlling the execution.
    pub policy: CommandPolicy,
    /// The prepared execution plan ready to spawn.
    pub execution: locket_exec::PreparedExecution,
    /// Plan describing how the docker helper will inject secrets.
    pub plan: locket_docker::DockerInjectionPlan,
    /// Which docker helper this prepared execution targets.
    pub helper_kind: DockerHelperKind,
    source: ApprovedPolicySource,
}

impl PreparedDockerPolicyExecution {
    pub fn status(
        &self,
        context: &RuntimeContext,
        output: &mut impl Write,
    ) -> Result<ExitStatus, CliError> {
        super::run::write_configuration_warnings(&self.source.document, &self.policy, output)?;
        self.source.require_current(&self.store, &self.resolved, &self.policy.name)?;
        Ok(self.execution.command().current_dir(&context.cwd).status()?)
    }
}

pub fn prepare_docker_policy_execution(
    context: &RuntimeContext,
    policy_name: &str,
    argv: &[String],
    parent_env: locket_exec::EnvMap,
) -> Result<PreparedDockerPolicyExecution, CliError> {
    prepare_docker_helper_policy_execution(
        context,
        policy_name,
        argv,
        parent_env,
        DockerHelperKind::DockerRun,
    )
}

pub fn prepare_compose_policy_execution(
    context: &RuntimeContext,
    policy_name: &str,
    argv: &[String],
    parent_env: locket_exec::EnvMap,
) -> Result<PreparedDockerPolicyExecution, CliError> {
    prepare_docker_helper_policy_execution(
        context,
        policy_name,
        argv,
        parent_env,
        DockerHelperKind::Compose,
    )
}

fn prepare_docker_helper_policy_execution(
    context: &RuntimeContext,
    policy_name: &str,
    argv: &[String],
    parent_env: locket_exec::EnvMap,
    helper_kind: DockerHelperKind,
) -> Result<PreparedDockerPolicyExecution, CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let source = require_approved_policy_source(&store, &resolved, policy_name)?;
    let effective =
        effective_command_policy(&source.document, &resolved, policy_name, &context.cwd)?;
    let mut policy = effective.policy.clone();
    ensure_runtime_policy_supported(&policy)?;
    // Docker helpers accept pass-through arguments. The saved command cannot
    // stand in for the actual recipient when evaluating per-secret argv ACLs.
    policy.command = CommandSpec::Argv(argv.to_vec());
    crate::enforce_secret_access_policies(
        &source.document,
        &policy,
        &resolved.root,
        &context.cwd.canonicalize()?,
    )?;
    super::docker_context::validate_destination_arguments(argv)?;
    locket_docker::validate_injected_names(
        policy.allowed_secrets.iter().map(locket_core::SecretName::as_str),
    )
    .map_err(docker_error)?;
    let (profile, _selections, locket_env) =
        resolve_policy_locket_env(context, &store, &resolved, &effective, &policy)?;
    let request = locket_exec::ExecutionRequest {
        argv: argv.to_vec(),
        parent_env,
        inherit_env: policy.inherit_env.clone(),
        external_env: locket_exec::EnvMap::new(),
        locket_env,
        env_mode: policy.env_mode,
        override_mode: policy.override_behavior,
    };
    let mut execution = super::prepare_vault_execution(&request)?;
    super::run::finalize_configuration_environment(&source.document, &policy, &mut execution.env)?;
    let endpoint = super::docker_context::resolve_endpoint(&execution.env, &context.cwd)?;
    let mut delivery_env = execution.env.clone();
    delivery_env
        .retain(|name, _| policy.allowed_secrets.iter().any(|allowed| allowed.as_str() == name));
    let mut plan = match helper_kind {
        DockerHelperKind::DockerRun => locket_docker::prepare_docker_run(
            argv,
            &locket_exec::EnvMap::new(),
            &delivery_env,
            Some(&endpoint),
            policy.allow_remote_docker,
        ),
        DockerHelperKind::Compose => locket_docker::prepare_compose(
            argv,
            &locket_exec::EnvMap::new(),
            &delivery_env,
            Some(&endpoint),
            policy.allow_remote_docker,
        ),
    }
    .map_err(docker_error)?;
    if plan.context_class == locket_docker::DockerContextClass::Local {
        // Pin the checked destination so a later context-file change cannot
        // redirect this prepared invocation to a different daemon.
        plan.argv.splice(1..1, ["--host".to_owned(), endpoint]);
    } else {
        let expected = format!("remote {}", policy.name);
        writeln!(
            std::io::stderr(),
            "Docker will receive local secrets on a remote daemon. Type '{expected}' to confirm."
        )?;
        let confirmation = context.confirmation_reader.read_confirmation("remote Docker")?;
        if confirmation.trim_end_matches(['\r', '\n']) != expected {
            return Err(crate::runtime::error::confirmation_failed_error(
                "confirmation did not match remote Docker scope",
            ));
        }
    }
    // Keep the exact environment whose destination was checked. Re-resolving
    // defaults after confirmation could change the prepared child environment.
    execution.args = plan.argv.iter().skip(1).cloned().collect();
    if plan.context_class == locket_docker::DockerContextClass::Local {
        execution.env.remove("DOCKER_CONTEXT");
    }

    Ok(PreparedDockerPolicyExecution {
        store,
        resolved,
        profile,
        policy,
        execution,
        plan,
        helper_kind,
        source,
    })
}

pub fn ensure_runtime_policy_supported(policy: &CommandPolicy) -> Result<(), CliError> {
    if matches!(policy.command, CommandSpec::Shell(_)) {
        return Err(unimplemented_in_build_error(
            "shell policy execution is not wired in this build",
        ));
    }
    if policy.confirm {
        return Err(unimplemented_in_build_error("policy confirmation is not wired in this build"));
    }
    if policy.require_user_verification {
        return Err(unimplemented_in_build_error(
            "policy user verification is not wired in this build",
        ));
    }
    if !policy.external_env_sources.is_empty() {
        return Err(unimplemented_in_build_error(
            "policy external environment sources are not wired in this build",
        ));
    }
    Ok(())
}

pub fn resolve_policy_locket_env(
    context: &RuntimeContext,
    store: &Store,
    resolved: &ResolvedProject,
    effective: &EffectiveCommandPolicy,
    policy: &CommandPolicy,
) -> Result<(ProfileRecord, Vec<PolicySecretSelection>, locket_exec::EnvMap), CliError> {
    if !policy.shared_secrets.is_empty() {
        return Err(crate::runtime::error::invalid_policy_error(
            "shared_secrets are supported by locket run; Docker and Compose delivery require project secrets",
        ));
    }
    let profile = effective_policy_profile(store, resolved, effective)?;
    let selections = policy_secret_selections(store, resolved, &profile, policy)?;
    super::run::require_shared_policy_vaults_unlocked(context, store, &profile, &selections)?;

    let mut locket_env = locket_exec::EnvMap::new();
    for selection in &selections {
        if let Some(secret) = &selection.selected {
            let value = decrypt_secret_version(
                context,
                store,
                &secret.project_id,
                &secret.profile_id,
                secret,
                secret.current_version,
            )?;
            locket_env.insert(selection.name.clone(), value);
        }
    }
    Ok((profile, selections, locket_env))
}

pub fn compose_argv_with_options(
    argv: Vec<String>,
    project_directory: Option<&Path>,
    profiles: &[String],
) -> Result<Vec<String>, CliError> {
    if argv.len() < 2
        || argv.first().map(String::as_str) != Some("docker")
        || argv.get(1).map(String::as_str) != Some("compose")
    {
        return Ok(argv);
    }
    let mut prepared = Vec::with_capacity(argv.len() + 2 + profiles.len() * 2);
    prepared.push(argv[0].clone());
    prepared.push(argv[1].clone());
    if let Some(project_directory) = project_directory {
        prepared.push("--project-directory".to_owned());
        prepared.push(project_directory.to_string_lossy().into_owned());
    }
    for profile in profiles {
        if profile.is_empty() {
            return Err(invalid_reference_error("compose profile must not be empty"));
        }
        prepared.push("--profile".to_owned());
        prepared.push(profile.clone());
    }
    prepared.extend(argv.into_iter().skip(2));
    Ok(prepared)
}

pub fn docker_error(error: locket_docker::DockerError) -> CliError {
    match error {
        locket_docker::DockerError::RemoteContextDenied => access_denied_error(
            "remote Docker context is denied by default; policy allow_remote_docker support is default-deny unless explicitly enabled",
        ),
        other => metadata_invalid_error(other.to_string()),
    }
}

pub fn write_docker_policy_audit_if_available(
    context: &RuntimeContext,
    prepared: &mut PreparedDockerPolicyExecution,
    status: &str,
) -> Result<(), CliError> {
    if prepared.store.get_project(prepared.resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key = load_project_key(
        context,
        &prepared.store,
        prepared.resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let metadata = docker_policy_audit_metadata(prepared, status);
    let audit = AuditWrite {
        project_id: prepared.resolved.config.project_id.as_str(),
        profile_id: Some(&prepared.profile.id),
        action: "RUN",
        status,
        secret_name: None,
        command: Some(docker_helper_command_label(prepared.helper_kind)),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    prepared.store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

pub fn docker_policy_audit_metadata(
    prepared: &PreparedDockerPolicyExecution,
    status: &str,
) -> Value {
    json!({
        "schema_version": 1,
        "action": "RUN",
        "status": status,
        "command": docker_helper_command_label(prepared.helper_kind),
        "policy": prepared.policy.name,
        "helper": docker_helper_command_label(prepared.helper_kind),
        "delivery_mode": docker_delivery_mode_label(prepared.plan.delivery_mode),
        "docker_context_class": docker_context_class_label(prepared.plan.context_class),
        "argv_program": prepared.plan.argv.first().map_or("", String::as_str),
        "arg_count": prepared.plan.argv.len(),
        "secret_names": summarize_names(&prepared.plan.injected_names),
    })
}

const fn docker_helper_command_label(kind: DockerHelperKind) -> &'static str {
    match kind {
        DockerHelperKind::DockerRun => "env docker",
        DockerHelperKind::Compose => "compose run",
    }
}

const fn docker_delivery_mode_label(mode: locket_docker::DockerDeliveryMode) -> &'static str {
    match mode {
        locket_docker::DockerDeliveryMode::EnvironmentNames => "environment_names",
        locket_docker::DockerDeliveryMode::EphemeralEnvFile => "ephemeral_env_file",
    }
}

const fn docker_context_class_label(class: locket_docker::DockerContextClass) -> &'static str {
    match class {
        locket_docker::DockerContextClass::Local => "local",
        locket_docker::DockerContextClass::Remote => "remote",
        locket_docker::DockerContextClass::Unknown => "unknown",
    }
}
