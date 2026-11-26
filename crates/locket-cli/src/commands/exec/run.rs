//! Implementation of the `locket run` command and runtime session helpers
//! shared with the `exec` command.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::process::{Command as ProcessCommand, ExitStatus, Stdio};
use std::str::FromStr;

use locket_core::{
    CommandPolicy, CommandSpec, ExternalEnvSource, LkReferenceUri, LocketError, OutputRedaction,
    PolicyDocument, SecretName, SessionId,
};
use locket_crypto::KeyPurpose;
use locket_exec::{
    EgressEvent, EgressProxyBroker, EgressProxyConfig, EgressSecretBinding,
    StreamingRedactorConfig, redact_child_output,
};
use locket_platform::{LocalUserVerificationRequest, PlatformError};
use locket_store::{
    ProfileRecord, RuntimeSessionRecord, RuntimeSessionSecretNameRetention, SecretRecord, Store,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::commands::agent::{ensure_agent_running_for_execution, request_project_status_snapshot};
use crate::commands::config::spec::{config_get_value, read_user_config};
use crate::commands::policy::{
    ApprovedPolicySource, read_locket_toml, require_approved_policy_source,
};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, child_exit_error, confirmation_failed_error, corrupt_db_error, exec_prepare_error,
    external_source_unavailable_error, ide_env_session_unavailable_error, invalid_policy_error,
    metadata_invalid_error, typed_cli_error, user_verification_failed_error,
};
use crate::runtime::key_access::{default_profile, load_profile_key};
use crate::support::secret_helpers::{
    PolicySecretSelection, decrypt_secret_version, policy_secret_selections,
};
use crate::{
    EffectiveCommandPolicy, ResolvedProject, RunArgs, effective_command_policy,
    effective_command_policy_for_argv, effective_policy_profile, ensure_trusted_project_root,
    now_unix_nanos, open_store, require_project, write_runtime_policy_audit_if_available,
    write_runtime_policy_denial_audit_if_available,
};
use locket_core::dotenv::{DotenvOptions, parse_dotenv};

/// Inputs needed to run a prepared command under a runtime session record.
pub struct RuntimeExecutionRequest<'a> {
    /// The opened backing store used to track the runtime session.
    pub store: &'a Store,
    /// Profile whose secrets are being injected.
    pub profile: &'a ProfileRecord,
    /// Optional policy name when the execution is policy-driven.
    pub policy_name: Option<&'a str>,
    /// Sorted, deduplicated secret names that were injected.
    pub secret_names: &'a [String],
    /// Prepared execution plan ready to spawn.
    pub prepared: &'a locket_exec::PreparedExecution,
    /// Optional working directory to apply when spawning.
    pub current_dir: Option<&'a Path>,
    /// Optional live grant request for policy-driven `locket run`.
    pub run_policy_grant: Option<RunPolicyGrantRequest<'a>>,
    /// Global Vault unlock scope required for shared-secret delivery.
    pub shared_projects: BTreeSet<&'a str>,
}

/// Policy-grant data needed before spawning a runtime child.
#[derive(Clone, Copy, Debug)]
pub struct RunPolicyGrantRequest<'a> {
    /// Trusted project configuration used to verify the approved policy.
    pub resolved: &'a ResolvedProject,
    /// Source whose policy and access rules were used to prepare the child.
    source: &'a ApprovedPolicySource,
    /// Live grant TTL from the command policy.
    pub ttl_seconds: u64,
}

/// Metadata-only grant fields included in the runtime audit row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunPolicyGrantMetadata {
    /// Live grant TTL from the command policy.
    pub ttl_seconds: u64,
    /// Exact launcher process binding and execution scope returned by the agent.
    pub binding: locket_agent::GrantBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RunPolicyGrant {
    grant_id: String,
    metadata: RunPolicyGrantMetadata,
}

/// Result of a runtime child execution.
pub struct RuntimeExecutionOutcome {
    /// Child exit status.
    pub status: ExitStatus,
    /// Metadata-only grant fields when a policy run issued a live grant.
    pub run_policy_grant: Option<RunPolicyGrantMetadata>,
}

struct PreparedPolicyExecution {
    selections: Vec<PolicySecretSelection>,
    secret_names: Vec<String>,
    /// Names sourced from `policy.external_env_sources` (Parent/File/Compose/Ide).
    /// Recorded as metadata-only `external_env_names` in the `RUN_POLICY`
    /// audit row; never includes values.
    external_env_names: Vec<String>,
    protection_inputs: Option<ProtectionInputs>,
    prepared: locket_exec::PreparedExecution,
}

struct ApprovedRunPolicy {
    source: ApprovedPolicySource,
    effective: EffectiveCommandPolicy,
}

struct ProtectionInputs {
    injected_env_names: BTreeSet<String>,
    known_secrets: Vec<(String, Zeroizing<String>)>,
}

impl ProtectionInputs {
    fn collect(
        request: &locket_exec::ExecutionRequest,
        prepared: &locket_exec::PreparedExecution,
        policy: &CommandPolicy,
    ) -> Self {
        let mut known_secrets = request
            .locket_env
            .iter()
            .chain(&request.external_env)
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Vec<_>>();
        if let CommandSpec::Argv(arguments) = &policy.command {
            known_secrets.extend(
                arguments
                    .iter()
                    .zip(&request.argv)
                    .filter(|(original, _)| original.contains("lk://"))
                    .map(|(_, value)| (String::new(), Zeroizing::new(value.clone()))),
            );
        }
        let mut injected_env_names = BTreeSet::new();
        for (name, value) in &prepared.env {
            let locket = request.locket_env.get(name);
            let external = request.external_env.get(name);
            if locket.is_some() || external.is_some() {
                injected_env_names.insert(name.clone());
                if locket != Some(value) && external != Some(value) {
                    known_secrets.push((name.clone(), value.clone()));
                }
            }
        }
        Self { injected_env_names, known_secrets }
    }
}

pub(super) fn child_output_redaction(
    context: &RuntimeContext,
    flags: &crate::OutputRedactionArgs,
    project_mode: Option<OutputRedaction>,
    egress: bool,
) -> Result<Option<OutputRedaction>, CliError> {
    let mode = if egress || flags.redact_output {
        OutputRedaction::Always
    } else if flags.no_redact_output {
        OutputRedaction::Never
    } else if let Some(value) = std::env::var_os("LOCKET_REDACT_OUTPUT") {
        match value.to_str().unwrap_or_default().to_ascii_lowercase().as_str() {
            "1" | "true" | "always" => OutputRedaction::Always,
            "0" | "false" | "never" => OutputRedaction::Never,
            "auto" => OutputRedaction::Auto,
            _ => {
                return Err(metadata_invalid_error(
                    "LOCKET_REDACT_OUTPUT must be auto, always, or never",
                ));
            }
        }
    } else if let Some(mode) = project_mode {
        mode
    } else {
        let config = read_user_config(context)?;
        config_get_value(&config, "run.redact_output")
            .map(|value| {
                value.as_str().unwrap_or_default().parse().map_err(|_| {
                    metadata_invalid_error("run.redact_output must be auto, always, or never")
                })
            })
            .transpose()?
            .unwrap_or_default()
    };
    match mode {
        OutputRedaction::Always => Ok(Some(mode)),
        OutputRedaction::Auto if !io::stdout().is_terminal() || !io::stderr().is_terminal() => {
            Ok(Some(mode))
        }
        OutputRedaction::Auto | OutputRedaction::Never => Ok(None),
    }
}

pub(super) fn child_redactor(
    mode: OutputRedaction,
    known_secrets: Vec<(String, Zeroizing<String>)>,
) -> StreamingRedactorConfig {
    let strict = mode == OutputRedaction::Always;
    StreamingRedactorConfig {
        known_secrets,
        include_encoded_variants: true,
        redact_generic_patterns: strict,
        min_secret_len: if strict { 1 } else { 8 },
        ..StreamingRedactorConfig::default()
    }
}

struct RunProtection {
    redactor: StreamingRedactorConfig,
    broker: Option<EgressProxyBroker>,
}

impl RunProtection {
    fn configure(
        args: &RunArgs,
        policy: &mut PreparedPolicyExecution,
        redaction: Option<OutputRedaction>,
    ) -> Result<Option<Self>, CliError> {
        let (Some(ProtectionInputs { injected_env_names, mut known_secrets }), Some(mode)) =
            (policy.protection_inputs.take(), redaction)
        else {
            return Ok(None);
        };
        let broker = if args.egress_host.is_empty() {
            None
        } else {
            let broker = EgressProxyBroker::start(
                egress_bindings(&args.egress_host, &policy.prepared, &injected_env_names)?,
                EgressProxyConfig {
                    allow_private_destinations_for_allowed_hosts: false,
                    strict_connect_allowlist: !args.egress_allow_unlisted_connect,
                    tls_mitm_enabled: !args.no_egress_tls_mitm,
                    ..EgressProxyConfig::default()
                },
            )
            .map_err(|error| {
                metadata_invalid_error(format!("could not start egress broker: {error}"))
            })?;
            let overrides = broker.child_env_overrides();
            // Redact the broker's credentials and placeholders from child output as well.
            if let Some(proxy) = overrides.get("HTTP_PROXY")
                && let Some((credentials, _)) =
                    proxy.strip_prefix("http://").and_then(|url| url.split_once('@'))
            {
                known_secrets.push((String::new(), Zeroizing::new(credentials.to_owned())));
                if let Some((_, password)) = credentials.split_once(':') {
                    known_secrets.push((String::new(), Zeroizing::new(password.to_owned())));
                }
            }
            known_secrets.extend(
                overrides
                    .iter()
                    .filter(|(name, _)| injected_env_names.contains(*name))
                    .map(|(name, value)| (name.clone(), value.clone())),
            );
            policy.prepared.env.extend(overrides);
            if !args.allow_uncontained_egress {
                policy.prepared = locket_exec::wrap_command_with_network_containment(
                    &policy.prepared,
                    &locket_exec::NetworkContainmentPolicy {
                        allowed_loopback_ports: vec![broker.local_addr().port()],
                        allow_unix_sockets: false,
                    },
                )
                .map_err(|error| {
                    metadata_invalid_error(format!(
                        "{error}; pass --allow-uncontained-egress to run without kernel network containment"
                    ))
                })?;
            }
            Some(broker)
        };
        Ok(Some(Self { redactor: child_redactor(mode, known_secrets), broker }))
    }
}

fn egress_bindings(
    specs: &[String],
    prepared: &locket_exec::PreparedExecution,
    injected_env_names: &BTreeSet<String>,
) -> Result<Vec<EgressSecretBinding>, CliError> {
    let mut hosts_by_name = BTreeMap::<&str, Vec<String>>::new();
    for spec in specs {
        let (name, host) = spec.split_once('=').ok_or_else(|| {
            metadata_invalid_error("--egress-host requires SECRET_NAME=HOST_PATTERN")
        })?;
        if SecretName::new(name).is_err() || host.is_empty() || host.contains('=') {
            return Err(metadata_invalid_error("--egress-host requires SECRET_NAME=HOST_PATTERN"));
        }
        hosts_by_name.entry(name).or_default().push(host.to_owned());
    }
    let bound_names: BTreeSet<_> = hosts_by_name.keys().copied().collect();
    hosts_by_name
        .into_iter()
        .map(|(name, allowed_hosts)| {
            let Some(value) = prepared.env.get(name).filter(|_| injected_env_names.contains(name))
            else {
                return Err(metadata_invalid_error(
                    "--egress-host must name a secret injected by the run policy",
                ));
            };
            if !value.is_empty()
                && (prepared.program == value.as_str()
                    || prepared.args.iter().any(|arg| arg == value.as_str())
                    || prepared.env.iter().any(|(other_name, other_value)| {
                        other_value.as_str() == value.as_str()
                            && !bound_names.contains(other_name.as_str())
                    }))
            {
                return Err(metadata_invalid_error(
                    "egress-bound secret would also be delivered outside its binding",
                ));
            }
            Ok(EgressSecretBinding {
                env_name: name.to_owned(),
                secret_value: value.clone(),
                allowed_hosts,
            })
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpandedRunnerCommand {
    policy_name: String,
    argv: Vec<String>,
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) struct AgentPolicyAccess {
    resolve_grant_id: Option<String>,
    binding: locket_agent::GrantBinding,
}

#[derive(serde::Deserialize)]
struct AgentGrantResponse {
    grant_id: String,
}

pub fn run_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    run_args: &RunArgs,
) -> Result<(), CliError> {
    run_command_with_diagnostics(context, output, &mut io::stderr(), run_args)
}

pub fn run_command_with_diagnostics(
    context: &RuntimeContext,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    run_args: &RunArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let approved = resolve_run_policy(context, output, &mut store, &resolved, run_args)?;
    let policy = &approved.effective.policy;
    let profile = effective_policy_profile(&store, &resolved, &approved.effective)?;
    let insecure_argv = match argv_reference_access(&policy.command, run_args.allow_insecure_argv) {
        Ok(allowed) => allowed,
        Err(error) => {
            let _ignored = write_runtime_policy_denial_audit_if_available(
                context,
                &mut store,
                &resolved,
                Some(&profile),
                Some(policy),
                &policy.name,
                "insecure_argv_denied",
            );
            return Err(error);
        }
    };

    let (confirmation_source, user_verification) =
        authorize_run_invocation(context, output, policy, &profile)?;
    if insecure_argv {
        writeln!(
            diagnostics,
            "warning: secret values in process argv are visible via ps or /proc"
        )?;
    }
    let redaction = child_output_redaction(
        context,
        &run_args.output_redaction,
        approved.source.document.output_redaction,
        !run_args.egress_host.is_empty(),
    )?;
    let mut prepared_policy = match prepare_policy_execution(
        context,
        output,
        &store,
        &resolved,
        &profile,
        &approved,
        redaction.is_some(),
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            let failure_reason = denial_failure_reason(&error);
            let _ignored = write_runtime_policy_denial_audit_if_available(
                context,
                &mut store,
                &resolved,
                Some(&profile),
                Some(policy),
                &policy.name,
                failure_reason,
            );
            return Err(error);
        }
    };
    let protection = RunProtection::configure(run_args, &mut prepared_policy, redaction)?;
    let outcome = execute_runtime_child(
        context,
        &RuntimeExecutionRequest {
            store: &store,
            profile: &profile,
            policy_name: Some(&policy.name),
            secret_names: &prepared_policy.secret_names,
            prepared: &prepared_policy.prepared,
            current_dir: Some(&context.cwd),
            run_policy_grant: Some(RunPolicyGrantRequest {
                resolved: &resolved,
                source: &approved.source,
                ttl_seconds: policy.ttl.as_secs(),
            }),
            shared_projects: shared_projects(&prepared_policy.selections),
        },
        protection,
    )?;
    let status = outcome.status;
    let audit_status = if status.success() { "SUCCESS" } else { "FAILED" };
    write_runtime_policy_audit_if_available(
        context,
        &mut store,
        &resolved,
        &profile,
        policy,
        audit_status,
        &prepared_policy.selections,
        &prepared_policy.external_env_names,
        status.code(),
        confirmation_source,
        user_verification.as_ref(),
        outcome.run_policy_grant.as_ref(),
        insecure_argv,
    )?;
    if status.success() {
        return Ok(());
    }

    writeln!(output, "child exited with status {status}")?;
    Err(child_exit_error(status))
}

fn authorize_run_invocation(
    context: &RuntimeContext,
    output: &mut impl Write,
    policy: &CommandPolicy,
    profile: &ProfileRecord,
) -> Result<(Option<&'static str>, Option<locket_platform::LocalUserVerification>), CliError> {
    let confirmation_source = if policy.confirm || profile.dangerous {
        if profile.dangerous {
            writeln!(output, "dangerous_environment: {}", profile.name)?;
        }
        let expected = format!("run {}", policy.name);
        writeln!(output, "type '{expected}' to confirm run")?;
        let confirmation = context.confirmation_reader.read_confirmation("run")?;
        if confirmation.trim_end_matches(['\r', '\n']) != expected {
            return Err(confirmation_failed_error("confirmation did not match run scope"));
        }
        Some("interactive")
    } else {
        None
    };
    let user_verification = if policy.require_user_verification {
        let request =
            LocalUserVerificationRequest::new("run", format!("authorize policy {}", policy.name));
        match context.user_verifier.verify_user(&request) {
            Ok(verified) => Some(verified),
            Err(
                PlatformError::LocalUserVerificationFailed
                | PlatformError::LocalUserVerificationUnavailable,
            ) => {
                return Err(user_verification_failed_error(
                    "policy requires local user verification",
                ));
            }
            Err(error) => return Err(error.into()),
        }
    } else {
        None
    };
    Ok((confirmation_source, user_verification))
}

/// Reviews and saves a detected project command without running it.
pub fn approve_project_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    resolved: &ResolvedProject,
    argv: Vec<String>,
) -> Result<(), CliError> {
    resolve_run_policy(
        context,
        output,
        &mut open_store(context)?,
        resolved,
        &RunArgs { argv, ..RunArgs::default() },
    )?;
    Ok(())
}

fn resolve_run_policy(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &mut Store,
    resolved: &ResolvedProject,
    run_args: &RunArgs,
) -> Result<ApprovedRunPolicy, CliError> {
    let explicit_argv = run_args.policy.is_empty();
    if !explicit_argv && run_args.runner_args.is_empty() && run_args.argv.is_empty() {
        return load_command_policy_or_audit_denial(context, store, resolved, &run_args.policy);
    }
    let argv = requested_run_argv(run_args, &resolved.root)?;
    argv_reference_access(&CommandSpec::Argv(argv.clone()), run_args.allow_insecure_argv)?;
    let source = read_locket_toml(&resolved.root.join(crate::LOCKET_TOML))?;
    let document = PolicyDocument::from_toml_value(&source)
        .map_err(|error| invalid_policy_error(error.to_string()))?;
    let matched = document
        .commands
        .get("dev")
        .filter(|policy| policy.command == CommandSpec::Argv(argv.clone()))
        .or_else(|| {
            document
                .commands
                .values()
                .find(|policy| policy.command == CommandSpec::Argv(argv.clone()))
        });
    if let Some(policy) = matched {
        let approved = load_command_policy_or_audit_denial(context, store, resolved, &policy.name)?;
        if approved.effective.policy.command != CommandSpec::Argv(argv) {
            return Err(invalid_policy_error("command configuration changed; retry the command"));
        }
        return Ok(approved);
    }
    let policy_name = next_command_name(&document);
    // Match and persist authorization using the same resolved directory. In
    // particular, Windows canonical paths include a verbatim prefix that the
    // caller's cwd spelling may omit.
    let canonical_cwd = context.cwd.canonicalize()?;
    let mut effective =
        effective_command_policy_for_argv(&document, resolved, policy_name, argv, &canonical_cwd)?;
    ensure_trusted_project_root(store, resolved)?;
    let profile = effective_policy_profile(store, resolved, &effective)?;
    let names = crate::active_profile_secret_names(
        store,
        resolved.config.project_id.as_str(),
        &profile.id,
    )?;
    let mut required = names
        .into_iter()
        .map(|name| {
            SecretName::new(name).map_err(|_| invalid_policy_error("invalid secret metadata"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    required.extend(effective.policy.required_secrets.iter().cloned());
    effective.policy.optional_secrets.retain(|name| !required.contains(name));
    effective.policy.required_secrets = required.iter().cloned().collect();
    required.extend(effective.policy.optional_secrets.iter().cloned());
    effective.policy.allowed_secrets = required.into_iter().collect();
    effective.policy.confirm |= profile.dangerous;
    // Re-evaluate ACLs with the proposed names. Existing path-scope requirements are
    // preserved, and the durable writer will validate the full policy again.
    let mut proposed_document = document;
    proposed_document.commands.insert(effective.policy.name.clone(), effective.policy.clone());
    crate::enforce_secret_access_policies(
        &proposed_document,
        &effective.policy,
        &resolved.root,
        &canonical_cwd,
    )?;
    writeln!(output, "proposed_command: {}", effective.policy.name)?;
    writeln!(output, "argv: {}", serde_json::to_string(&policy_argv(&effective.policy))?)?;
    writeln!(output, "working_directory: {}", context.cwd.display())?;
    writeln!(output, "profile: {}", profile.name)?;
    writeln!(
        output,
        "secret_names: {}",
        effective
            .policy
            .required_secrets
            .iter()
            .map(SecretName::as_str)
            .collect::<Vec<_>>()
            .join(",")
    )?;
    if profile.dangerous {
        writeln!(output, "dangerous_profile: {}", profile.name)?;
    }
    let expected = format!("approve {}", effective.policy.name);
    writeln!(output, "type '{expected}' to save this command and approve these names")?;
    output.flush()?;
    let confirmation = context.confirmation_reader.read_confirmation("command approval")?;
    if confirmation.trim_end_matches(['\r', '\n']) != expected {
        return Err(confirmation_failed_error("command approval confirmation did not match"));
    }
    if profile.dangerous {
        writeln!(output, "type '{}' to confirm access to this dangerous profile", profile.name)?;
        output.flush()?;
        let confirmation = context.confirmation_reader.read_confirmation("dangerous profile")?;
        if confirmation.trim_end_matches(['\r', '\n']) != profile.name {
            return Err(confirmation_failed_error("dangerous profile confirmation did not match"));
        }
    }
    let mut base_policy = effective.policy.clone();
    if let Some(scope) = proposed_document.path_scope_for(&resolved.root, &canonical_cwd) {
        let scoped =
            scope.required_secrets.iter().chain(&scope.optional_secrets).collect::<BTreeSet<_>>();
        base_policy.required_secrets.retain(|name| !scoped.contains(name));
        base_policy.optional_secrets.retain(|name| !scoped.contains(name));
        base_policy.allowed_secrets.retain(|name| !scoped.contains(name));
    }
    crate::commands::policy::persist_command_policy(context, resolved, &base_policy, source)?;
    load_command_policy_or_audit_denial(context, store, resolved, &effective.policy.name)
}

fn requested_run_argv(run_args: &RunArgs, project_root: &Path) -> Result<Vec<String>, CliError> {
    let argv = if run_args.policy.is_empty() {
        if run_args.argv.is_empty() {
            return Err(invalid_policy_error("provide a saved command or -- <command>"));
        }
        run_args.argv.clone()
    } else {
        let mut args = run_args.runner_args.clone();
        args.extend(run_args.argv.iter().cloned());
        expand_runner_command(&run_args.policy, &args, project_root)?.argv
    };
    Ok(argv)
}

fn next_command_name(document: &locket_core::PolicyDocument) -> String {
    let mut policy_name = "dev".to_owned();
    if document.commands.contains_key(&policy_name) {
        let mut suffix = 2;
        while document.commands.contains_key(&format!("dev_{suffix}")) {
            suffix += 1;
        }
        policy_name = format!("dev_{suffix}");
    }
    policy_name
}

fn expand_runner_command(
    runner: &str,
    runner_args: &[String],
    project_root: &Path,
) -> Result<ExpandedRunnerCommand, CliError> {
    if runner_args.is_empty() {
        return Err(invalid_policy_error(format!("runner {runner} requires a target")));
    }
    let command_argv = match runner {
        "npm" | "pnpm" | "yarn" | "bun" => expand_node_runner(runner, runner_args, project_root)?,
        "cargo" | "make" | "just" | "task" | "python" => {
            let mut command_argv = Vec::with_capacity(runner_args.len() + 1);
            command_argv.push(runner.to_owned());
            command_argv.extend(runner_args.iter().cloned());
            command_argv
        }
        "poetry" | "uv" => expand_run_prefix_runner(runner, runner_args),
        _ => {
            return Err(invalid_policy_error(format!(
                "unsupported runner adapter: {runner}; use `locket run <policy>` or `locket exec -- <command>`"
            )));
        }
    };
    Ok(ExpandedRunnerCommand {
        policy_name: runner_policy_name(runner, runner_args),
        argv: command_argv,
    })
}

fn expand_node_runner(
    runner: &str,
    runner_args: &[String],
    project_root: &Path,
) -> Result<Vec<String>, CliError> {
    let (script, command_argv) = if runner_args.first().is_some_and(|value| value == "run") {
        let Some(script) = runner_args.get(1) else {
            return Err(invalid_policy_error(format!("{runner} run requires a script name")));
        };
        let mut command_argv = Vec::with_capacity(runner_args.len() + 1);
        command_argv.push(runner.to_owned());
        command_argv.extend(runner_args.iter().cloned());
        (script.as_str(), command_argv)
    } else {
        let script = runner_args[0].as_str();
        let mut command_argv = Vec::with_capacity(runner_args.len() + 2);
        command_argv.push(runner.to_owned());
        command_argv.push("run".to_owned());
        command_argv.extend(runner_args.iter().cloned());
        (script, command_argv)
    };
    validate_package_script(project_root, script)?;
    Ok(command_argv)
}

fn expand_run_prefix_runner(runner: &str, runner_args: &[String]) -> Vec<String> {
    let mut command_argv = Vec::with_capacity(runner_args.len() + 2);
    command_argv.push(runner.to_owned());
    if runner_args.first().is_none_or(|value| value != "run") {
        command_argv.push("run".to_owned());
    }
    command_argv.extend(runner_args.iter().cloned());
    command_argv
}

fn validate_package_script(project_root: &Path, script: &str) -> Result<(), CliError> {
    let package_json = project_root.join("package.json");
    if !package_json.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(&package_json)?;
    let manifest: Value = serde_json::from_str(&content)?;
    if manifest
        .get("scripts")
        .and_then(Value::as_object)
        .is_some_and(|scripts| scripts.contains_key(script))
    {
        return Ok(());
    }
    Err(invalid_policy_error(format!(
        "npm script not found in {}: {script}",
        package_json.display()
    )))
}

fn runner_policy_name(runner: &str, args: &[String]) -> String {
    let target = if args.first().is_some_and(|value| value == "run") {
        args.get(1).map_or("run", String::as_str)
    } else {
        args.first().map_or("run", String::as_str)
    };
    format!("{runner}:{target}")
}

#[cfg(test)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn expand_runner_command_for_tests(
    runner: &str,
    args: &[String],
    project_root: &Path,
) -> Result<Vec<String>, CliError> {
    expand_runner_command(runner, args, project_root).map(|expanded| expanded.argv)
}

#[cfg(test)]
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn runner_policy_name_for_tests(runner: &str, args: &[String]) -> String {
    runner_policy_name(runner, args)
}

/// Names whose availability can be checked without running external commands.
pub struct RequiredVariableAvailability {
    pub missing: Vec<String>,
    pub missing_shared: Vec<String>,
    pub unknown: Vec<String>,
}

pub fn required_variable_availability(
    store: &Store,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
) -> Result<RequiredVariableAvailability, CliError> {
    let selections = policy_secret_selections(store, resolved, profile, policy)?;
    let mut external_names = BTreeSet::new();
    let mut deferred_source = false;
    for source in &policy.external_env_sources {
        match source {
            ExternalEnvSource::Parent => {
                external_names.extend(
                    policy
                        .allowed_secrets
                        .iter()
                        .filter(|name| std::env::var_os(name.as_str()).is_some())
                        .map(|name| name.as_str().to_owned()),
                );
            }
            ExternalEnvSource::File(path) => {
                external_names
                    .extend(resolve_external_env_file(path, &resolved.root, policy)?.into_keys());
            }
            ExternalEnvSource::Compose | ExternalEnvSource::Ide => deferred_source = true,
        }
    }
    let document = crate::read_policy_document(&resolved.root.join(crate::LOCKET_TOML))?;
    external_names.extend(
        document
            .variables
            .iter()
            .filter(|(name, contract)| {
                contract.default.is_some()
                    && policy
                        .allowed_secrets
                        .iter()
                        .any(|allowed| allowed.as_str() == name.as_str())
            })
            .map(|(name, _)| name.clone()),
    );
    let parent =
        std::env::vars().map(|(name, value)| (name, locket_exec::env_value(value))).collect();
    let inherit = policy.inherit_env.iter().map(String::as_str).collect::<Vec<_>>();
    let inherited = locket_exec::merge_environment(
        &parent,
        locket_exec::DEFAULT_SAFE_ALLOWLIST,
        &inherit,
        &locket_exec::EnvMap::new(),
        &locket_exec::EnvMap::new(),
        policy.env_mode,
        policy.override_behavior,
    )
    .map_err(|_| invalid_policy_error("environment resolution failed"))?;
    external_names.extend(inherited.into_keys());
    let mut result = RequiredVariableAvailability {
        missing: Vec::new(),
        missing_shared: Vec::new(),
        unknown: Vec::new(),
    };
    for selection in selections {
        if selection.shared && selection.selected.is_none() {
            result.missing_shared.push(selection.name);
        } else if selection.required
            && selection.selected.is_none()
            && !external_names.contains(&selection.name)
        {
            if deferred_source {
                result.unknown.push(selection.name);
            } else {
                result.missing.push(selection.name);
            }
        }
    }
    Ok(result)
}

fn prepare_policy_execution(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &Store,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    approved: &ApprovedRunPolicy,
    protect_output: bool,
) -> Result<PreparedPolicyExecution, CliError> {
    let policy = &approved.effective.policy;
    let document = &approved.source.document;
    approved.source.require_current(store, resolved, &policy.name)?;
    let selections = policy_secret_selections(store, resolved, profile, policy)?;
    check_policy_secret_availability(store, &selections)?;
    ensure_agent_running_for_execution(context)?;
    let parent_env = std::env::vars()
        .map(|(name, value)| (name, locket_exec::env_value(value)))
        .collect::<locket_exec::EnvMap>();
    let (agent_access, external_env) = prepare_policy_sources(
        context,
        store,
        resolved,
        profile,
        approved,
        &selections,
        &parent_env,
    )?;
    write_configuration_warnings(document, policy, output)?;

    let mut locket_env =
        policy_locket_env(context, store, profile, &selections, agent_access.is_some())?;
    if let Some(agent_access) = agent_access.as_ref() {
        locket_env.extend(policy_locket_env_via_agent(
            context,
            resolved,
            profile,
            policy,
            &selections,
            agent_access,
        )?);
    }
    warn_implicit_locket_override_conflicts(
        output,
        policy,
        &parent_env,
        &external_env,
        &locket_env,
    )?;
    let mut reference_secret_names = Vec::new();
    let argv = if let Some(agent_access) = agent_access.as_ref() {
        policy_argv_with_resolved_references(
            context,
            resolved,
            profile,
            policy,
            agent_access,
            &mut reference_secret_names,
        )?
    } else {
        policy_argv(policy)
    };
    let request = locket_exec::ExecutionRequest {
        argv,
        parent_env,
        inherit_env: policy.inherit_env.clone(),
        external_env: external_env.clone(),
        locket_env,
        env_mode: policy.env_mode,
        override_mode: policy.override_behavior,
    };
    let mut prepared = super::prepare_vault_execution(&request)?;
    finalize_configuration_environment(document, policy, &mut prepared.env)?;
    let external_env_names = external_env.keys().map(ToOwned::to_owned).collect::<Vec<_>>();
    let secret_names = unique_secret_names(
        selections
            .iter()
            .filter_map(|selection| selection.selected.as_ref().map(|secret| secret.name.as_str()))
            .chain(external_env_names.iter().map(String::as_str))
            .chain(reference_secret_names.iter().map(String::as_str))
            .chain(
                policy
                    .allowed_secrets
                    .iter()
                    .filter(|name| prepared.env.contains_key(name.as_str()))
                    .map(SecretName::as_str),
            ),
    );
    let external_env_names = unique_secret_names(external_env_names.iter().map(String::as_str));

    let protection_inputs =
        protect_output.then(|| ProtectionInputs::collect(&request, &prepared, policy));
    Ok(PreparedPolicyExecution {
        selections,
        secret_names,
        external_env_names,
        protection_inputs,
        prepared,
    })
}

fn prepare_policy_sources(
    context: &RuntimeContext,
    store: &Store,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    approved: &ApprovedRunPolicy,
    selections: &[PolicySecretSelection],
    parent_env: &locket_exec::EnvMap,
) -> Result<(Option<AgentPolicyAccess>, locket_exec::EnvMap), CliError> {
    let policy = &approved.effective.policy;
    // The IDE source needs a grant for its session map and reference lookups.
    let has_ide_source = policy_has_ide_source(policy);
    let agent_access =
        if policy.require_agent || policy_command_has_lk_references(policy) || has_ide_source {
            Some(prepare_agent_policy_access(
                context,
                store,
                resolved,
                profile,
                policy,
                &approved.source,
                selections,
            )?)
        } else {
            None
        };
    let ide_ctx = agent_access.as_ref().filter(|_| has_ide_source).map(|access| {
        IdeEnvSourceContext { context, resolved, profile, policy, agent_access: access }
    });
    let external_env = resolve_policy_external_env_with_compose_config_command(
        policy,
        parent_env,
        &resolved.root,
        &ComposeConfigCommand::docker(),
        ide_ctx.as_ref(),
    )?;
    Ok((agent_access, external_env))
}

fn check_policy_secret_availability(
    store: &Store,
    selections: &[PolicySecretSelection],
) -> Result<(), CliError> {
    let missing_shared = selections
        .iter()
        .filter(|selection| selection.shared && selection.selected.is_none())
        .map(|selection| selection.name.as_str())
        .collect::<Vec<_>>();
    if !missing_shared.is_empty() {
        return Err(invalid_policy_error(format!(
            "required secret(s) missing from @shared: {}",
            missing_shared.join(", ")
        )));
    }
    for secret in selections.iter().filter_map(|selection| selection.selected.as_ref()) {
        crate::commands::secrets::expiry::check_secret_expiry(store, &secret.id)?;
    }
    Ok(())
}

fn shared_projects(selections: &[PolicySecretSelection]) -> BTreeSet<&str> {
    selections
        .iter()
        .filter(|selection| selection.shared)
        .filter_map(|selection| {
            selection.selected.as_ref().map(|secret| secret.project_id.as_str())
        })
        .collect()
}

pub(super) fn require_shared_policy_vaults_unlocked(
    context: &RuntimeContext,
    store: &Store,
    profile: &ProfileRecord,
    selections: &[PolicySecretSelection],
) -> Result<(), CliError> {
    let shared_projects = shared_projects(selections);
    if !shared_projects.is_empty() {
        for project_id in shared_projects {
            require_vault_unlocked(
                context,
                project_id,
                "the Global Vault",
                "executing with shared secrets",
            )?;
        }
        require_consumer_vault_access(
            context,
            store,
            profile,
            "the policy's project vault",
            "executing with shared secrets",
            false,
        )?;
    }
    Ok(())
}

pub(in crate::commands) fn require_linked_secret_access(
    context: &RuntimeContext,
    store: &Store,
    consumer: &ProfileRecord,
    secret: &SecretRecord,
    consumer_unlock_verified: bool,
) -> Result<(), CliError> {
    if secret.project_id != consumer.project_id {
        require_vault_unlocked(
            context,
            &secret.project_id,
            "the Global Vault",
            "accessing shared secrets",
        )?;
        require_consumer_vault_access(
            context,
            store,
            consumer,
            "the consuming project vault",
            "accessing shared secrets",
            consumer_unlock_verified,
        )?;
    }
    Ok(())
}

fn require_consumer_vault_access(
    context: &RuntimeContext,
    store: &Store,
    profile: &ProfileRecord,
    vault_name: &str,
    action: &str,
    unlock_verified: bool,
) -> Result<(), CliError> {
    if !unlock_verified {
        require_vault_unlocked(context, &profile.project_id, vault_name, action)?;
    }
    load_profile_key(context, store, &profile.project_id, &profile.id, KeyPurpose::ProfileSecret)?;
    Ok(())
}

pub(super) fn require_shared_vault_unlocked(
    context: &RuntimeContext,
    project_id: &str,
) -> Result<(), CliError> {
    require_vault_unlocked(context, project_id, "the Global Vault", "executing with shared secrets")
}

fn require_vault_unlocked(
    context: &RuntimeContext,
    project_id: &str,
    vault_name: &str,
    action: &str,
) -> Result<(), CliError> {
    // In-process command fixtures without an agent exercise local decryption.
    #[cfg(test)]
    if context.agent_data_dir.is_none() {
        return Ok(());
    }
    let snapshot = request_project_status_snapshot(&crate::agent_socket_path(context), project_id)
        .map_err(|error| {
            typed_cli_error(
                LocketError::AgentUnavailable,
                format!("could not verify the unlock for {vault_name}: {error}"),
            )
        })?;
    if snapshot["project_id"].as_str() != Some(project_id)
        || snapshot["lock_state"].as_str() != Some("unlocked")
    {
        let command = if project_id.starts_with(crate::commands::discovery::SHARED_PROJECT_PREFIX) {
            "locket unlock --shared".to_owned()
        } else {
            format!("locket unlock --project {project_id}")
        };
        return Err(typed_cli_error(
            LocketError::UnlockRequired,
            format!("unlock {vault_name} with `{command}` before {action}"),
        ));
    }
    Ok(())
}

pub fn resolve_policy_external_env(
    policy: &CommandPolicy,
    parent_env: &locket_exec::EnvMap,
    project_root: &Path,
) -> Result<locket_exec::EnvMap, CliError> {
    resolve_policy_external_env_with_compose_config_command(
        policy,
        parent_env,
        project_root,
        &ComposeConfigCommand::docker(),
        None,
    )
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) struct ComposeConfigCommand<'a> {
    program: &'a Path,
    args: &'a [&'a str],
}

#[allow(clippy::elidable_lifetime_names)]
impl<'a> ComposeConfigCommand<'a> {
    #[cfg(test)]
    pub(crate) const fn new(program: &'a Path, args: &'a [&'a str]) -> Self {
        Self { program, args }
    }

    fn docker() -> Self {
        Self { program: Path::new("docker"), args: &["compose", "config", "--format", "json"] }
    }
}

/// Inputs needed to resolve the `ide` external env source against the
/// running agent. `None` is passed by the `env` and `env inspect`
/// commands, which intentionally do not bring an agent socket into the
/// picture; they keep returning the typed `IdeEnvSessionUnavailable`
/// error so the caller is reminded to run the policy through `locket
/// run`.
#[allow(clippy::redundant_pub_crate)]
pub(crate) struct IdeEnvSourceContext<'a> {
    context: &'a RuntimeContext,
    resolved: &'a ResolvedProject,
    profile: &'a ProfileRecord,
    policy: &'a CommandPolicy,
    agent_access: &'a AgentPolicyAccess,
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn resolve_policy_external_env_with_compose_config_command(
    policy: &CommandPolicy,
    parent_env: &locket_exec::EnvMap,
    project_root: &Path,
    compose_config_command: &ComposeConfigCommand<'_>,
    ide: Option<&IdeEnvSourceContext<'_>>,
) -> Result<locket_exec::EnvMap, CliError> {
    let mut external_env = locket_exec::EnvMap::new();
    for source in &policy.external_env_sources {
        match source {
            ExternalEnvSource::Parent => {
                external_env.extend(locket_exec::resolve_parent_external_env(
                    parent_env,
                    policy.allowed_secrets.iter().map(SecretName::as_str),
                ));
            }
            ExternalEnvSource::File(path) => {
                external_env.extend(resolve_external_env_file(path, project_root, policy)?);
            }
            ExternalEnvSource::Compose => {
                external_env.extend(resolve_external_env_compose(
                    compose_config_command,
                    parent_env,
                    project_root,
                    policy,
                )?);
            }
            ExternalEnvSource::Ide => {
                let Some(ide) = ide else {
                    return Err(ide_env_session_unavailable_error(
                        "agent IDE env-session resolution requires `locket run`",
                    ));
                };
                external_env.extend(resolve_external_env_ide(ide, parent_env)?);
            }
        }
    }
    Ok(external_env)
}

fn resolve_external_env_ide(
    ide: &IdeEnvSourceContext<'_>,
    parent_env: &locket_exec::EnvMap,
) -> Result<locket_exec::EnvMap, CliError> {
    // Prefer the parent_env snapshot the caller already collected so
    // tests can drive the consumer with a deterministic session id even
    // when the live process environment is empty.
    let session_id = parent_env
        .get("LOCKET_IDE_ENV_SESSION")
        .map(|value| value.as_str().to_owned())
        .or_else(|| std::env::var("LOCKET_IDE_ENV_SESSION").ok())
        .ok_or_else(|| ide_env_session_unavailable_error("LOCKET_IDE_ENV_SESSION not set"))?;
    resolve_external_env_ide_with_session_id(ide, &session_id)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn resolve_external_env_ide_with_session_id(
    ide: &IdeEnvSourceContext<'_>,
    session_id: &str,
) -> Result<locket_exec::EnvMap, CliError> {
    if session_id.is_empty() {
        return Err(ide_env_session_unavailable_error("LOCKET_IDE_ENV_SESSION not set"));
    }
    let request = locket_agent::IdeEnvSessionRequest {
        session_id: session_id.to_owned(),
        project_id: ide.resolved.config.project_id.to_string(),
    };
    let response: locket_agent::IdeEnvSessionResponse = agent_invoke(
        ide.context,
        locket_agent::AgentMethod::IdeEnvSession,
        &request,
        "look up IDE env session",
    )?;
    let allowed_names: BTreeSet<&str> =
        ide.policy.allowed_secrets.iter().map(SecretName::as_str).collect();
    let mut env = locket_exec::EnvMap::new();
    for name in response.env_names {
        if !allowed_names.contains(name.as_str()) {
            // Names not on the policy allow-list never enter the env
            // map. The agent's session map carries IDE-side intent, but
            // the policy is the final authority.
            continue;
        }
        super::ensure_vault_env_name(&name)?;
        let reference = format!("lk://{}/{}", ide.profile.name, name);
        let resolved = resolve_reference_via_agent(
            ide.context,
            ide.resolved,
            ide.profile,
            ide.policy,
            ide.agent_access,
            &reference,
        )?;
        env.insert(name, locket_exec::env_value(resolved.value));
    }
    Ok(env)
}

/// Test-only constructor for an `IdeEnvSourceContext`. Exposed so unit
/// tests can drive `resolve_external_env_ide_with_session_id` against a
/// real in-process agent without going through the full `locket run`
/// pipeline.
#[cfg(all(test, unix))]
#[allow(clippy::redundant_pub_crate)]
pub(crate) const fn ide_env_source_context_for_tests<'a>(
    context: &'a RuntimeContext,
    resolved: &'a ResolvedProject,
    profile: &'a ProfileRecord,
    policy: &'a CommandPolicy,
    agent_access: &'a AgentPolicyAccess,
) -> IdeEnvSourceContext<'a> {
    IdeEnvSourceContext { context, resolved, profile, policy, agent_access }
}

/// Test-only helper that drives the same agent unlock and grant
/// sequence the production `prepare_policy_execution` path uses.
#[cfg(all(test, unix))]
#[allow(clippy::redundant_pub_crate)]
pub(crate) fn prepare_agent_policy_access_for_tests(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
) -> Result<AgentPolicyAccess, CliError> {
    let store = open_store(context)?;
    let source = require_approved_policy_source(&store, resolved, &policy.name)?;
    prepare_agent_policy_access(context, &store, resolved, profile, policy, &source, &[])
}

const COMPOSE_ROUTING_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "TMPDIR",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "COMPOSE_PROJECT_NAME",
    "COMPOSE_FILE",
    "COMPOSE_PROFILES",
    "COMPOSE_ENV_FILES",
    "COMPOSE_PATH_SEPARATOR",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
];

fn resolve_external_env_compose(
    compose_config_command: &ComposeConfigCommand<'_>,
    parent_env: &locket_exec::EnvMap,
    project_root: &Path,
    policy: &CommandPolicy,
) -> Result<locket_exec::EnvMap, CliError> {
    let mut compose_env = parent_env
        .iter()
        .filter(|(name, _)| {
            COMPOSE_ROUTING_ENV.contains(&name.as_str())
                || policy.inherit_env.contains(name)
                || (!locket_exec::is_child_runtime_control(name)
                    && policy
                        .allowed_secrets
                        .iter()
                        .any(|allowed| allowed.as_str() == name.as_str()))
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    locket_exec::restrict_child_search_path(&mut compose_env);
    let output = ProcessCommand::new(compose_config_command.program)
        .args(compose_config_command.args)
        .current_dir(project_root)
        .env_clear()
        .envs(compose_env.iter().map(|(name, value)| (name, value.as_str())))
        .output()
        .map_err(|error| {
            external_source_unavailable_error(format!(
                "ExternalSourceUnavailable: docker compose config could not be started: {error}"
            ))
        })?;
    let stdout = Zeroizing::new(output.stdout);
    drop(Zeroizing::new(output.stderr));
    if !output.status.success() {
        return Err(external_source_unavailable_error(format!(
            "ExternalSourceUnavailable: docker compose config failed with status {}",
            output.status
        )));
    }
    resolve_external_env_compose_json(policy, &stdout)
}

fn warn_implicit_locket_override_conflicts(
    output: &mut impl Write,
    policy: &CommandPolicy,
    parent_env: &locket_exec::EnvMap,
    external_env: &locket_exec::EnvMap,
    locket_env: &locket_exec::EnvMap,
) -> Result<(), CliError> {
    if policy.override_explicit() {
        return Ok(());
    }
    let inherit_env = policy.inherit_env.iter().map(String::as_str).collect::<Vec<_>>();
    let base_env = locket_exec::merge_environment(
        parent_env,
        locket_exec::DEFAULT_SAFE_ALLOWLIST,
        &inherit_env,
        external_env,
        &locket_exec::EnvMap::new(),
        policy.env_mode,
        policy.override_behavior,
    )
    .map_err(|error| exec_prepare_error(locket_exec::ExecError::Environment(error)))?;
    let conflicts = locket_env
        .keys()
        .filter(|name| base_env.contains_key(*name))
        .cloned()
        .collect::<BTreeSet<_>>();
    if conflicts.is_empty() {
        return Ok(());
    }
    writeln!(
        output,
        "warning: implicit override=locket will replace existing env name(s): {}",
        conflicts.into_iter().collect::<Vec<_>>().join(", ")
    )?;
    Ok(())
}

fn resolve_external_env_file(
    declared_path: &Path,
    project_root: &Path,
    policy: &CommandPolicy,
) -> Result<locket_exec::EnvMap, CliError> {
    if declared_path.is_absolute() {
        return Err(invalid_policy_error(format!(
            "external env file {} must be a project-relative path",
            declared_path.display()
        )));
    }

    let canonical_root = project_root.canonicalize().map_err(|error| {
        invalid_policy_error(format!(
            "could not canonicalize project root {}: {error}",
            project_root.display()
        ))
    })?;
    let candidate = project_root.join(declared_path);
    let canonical_candidate = candidate.canonicalize().map_err(|error| {
        invalid_policy_error(format!(
            "external env file {} could not be opened: {error}",
            declared_path.display()
        ))
    })?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(invalid_policy_error(format!(
            "external env file {} resolves outside the project root",
            declared_path.display()
        )));
    }

    let allowed_names =
        policy.allowed_secrets.iter().map(|name| name.as_str().to_owned()).collect::<BTreeSet<_>>();
    let mut contents = Zeroizing::new(String::new());
    crate::commands::secrets::import::open_scoped_file(&canonical_candidate)?
        .read_to_string(&mut contents)?;
    let mut env = locket_exec::EnvMap::new();
    // External sources are data, never shell programs. Only a malformed
    // assignment to a name this command can receive affects its execution.
    let document = parse_dotenv(&contents, DotenvOptions { literal: true });
    if let Some(error) = document.errors.iter().find(|error| {
        let line = contents.lines().nth(error.line.saturating_sub(1)).unwrap_or("").trim_start();
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let key = line
            .split_once('=')
            .map_or_else(|| line.split_whitespace().next().unwrap_or(""), |(key, _)| key.trim());
        allowed_names.contains(key)
    }) {
        return Err(metadata_invalid_error(format!(
            "external env file line {}: {}",
            error.line, error.message
        )));
    }
    for entry in document.entries {
        if allowed_names.contains(&entry.key) {
            env.insert(entry.key, locket_exec::env_value(entry.value));
        }
    }
    Ok(env)
}

fn resolve_external_env_compose_json(
    policy: &CommandPolicy,
    stdout: &[u8],
) -> Result<locket_exec::EnvMap, CliError> {
    let config: Value = serde_json::from_slice(stdout).map_err(|error| {
        external_source_unavailable_error(format!(
            "ExternalSourceUnavailable: docker compose config returned invalid JSON: {error}"
        ))
    })?;
    let allowed_names =
        policy.allowed_secrets.iter().map(|name| name.as_str().to_owned()).collect::<BTreeSet<_>>();
    let mut env = locket_exec::EnvMap::new();
    if let Some(environment) = config.get("environment") {
        extend_env_from_compose_environment(&mut env, &allowed_names, environment);
    }
    if let Some(services) = config.get("services").and_then(Value::as_object) {
        for service in services.values() {
            if let Some(environment) = service.get("environment") {
                extend_env_from_compose_environment(&mut env, &allowed_names, environment);
            }
        }
    }
    Ok(env)
}

fn extend_env_from_compose_environment(
    env: &mut locket_exec::EnvMap,
    allowed_names: &BTreeSet<String>,
    environment: &Value,
) {
    match environment {
        Value::Object(entries) => {
            for (name, value) in entries {
                if allowed_names.contains(name)
                    && let Some(value) = compose_env_value_as_string(value)
                {
                    env.insert(name.clone(), locket_exec::env_value(value));
                }
            }
        }
        Value::Array(entries) => {
            for entry in entries {
                let Some(entry) = entry.as_str() else {
                    continue;
                };
                let Some((name, value)) = entry.split_once('=') else {
                    continue;
                };
                if allowed_names.contains(name) {
                    env.insert(name.to_owned(), locket_exec::env_value(value.to_owned()));
                }
            }
        }
        _ => {}
    }
}

fn compose_env_value_as_string(value: &serde_json::Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn policy_locket_env(
    context: &RuntimeContext,
    store: &Store,
    profile: &ProfileRecord,
    selections: &[PolicySecretSelection],
    via_agent: bool,
) -> Result<locket_exec::EnvMap, CliError> {
    require_shared_policy_vaults_unlocked(context, store, profile, selections)?;
    let mut locket_env = locket_exec::EnvMap::new();
    for selection in selections.iter().filter(|selection| selection.shared || !via_agent) {
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
    Ok(locket_env)
}

fn policy_locket_env_via_agent(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
    selections: &[PolicySecretSelection],
    agent_access: &AgentPolicyAccess,
) -> Result<locket_exec::EnvMap, CliError> {
    let mut locket_env = locket_exec::EnvMap::new();
    for selection in selections {
        if !selection.shared && selection.selected.is_some() {
            let reference = format!("lk://{}/{}", profile.name, selection.name);
            let response = resolve_reference_via_agent(
                context,
                resolved,
                profile,
                policy,
                agent_access,
                &reference,
            )?;
            locket_env.insert(selection.name.clone(), locket_exec::env_value(response.value));
        }
    }
    Ok(locket_env)
}

fn prepare_agent_policy_access(
    context: &RuntimeContext,
    store: &Store,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
    source: &ApprovedPolicySource,
    selections: &[PolicySecretSelection],
) -> Result<AgentPolicyAccess, CliError> {
    unlock_agent_for_policy(context, resolved, policy)?;
    source.require_current(store, resolved, &policy.name)?;
    let binding = agent_grant_binding()?.with_execution(&policy.name, context.cwd.canonicalize()?);
    let needs_reference_grant = policy_command_has_lk_references(policy)
        || selections.iter().any(|s| !s.shared && s.selected.is_some())
        || policy_has_ide_source(policy);
    let resolve_grant_id = if needs_reference_grant {
        Some(
            request_agent_grant(
                context,
                resolved,
                profile,
                policy,
                locket_agent::GrantAction::ResolveReference,
                &binding,
            )?
            .grant_id,
        )
    } else {
        None
    };
    Ok(AgentPolicyAccess { resolve_grant_id, binding })
}

fn unlock_agent_for_policy(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    policy: &CommandPolicy,
) -> Result<(), CliError> {
    // The agent owns the unwrap path. The CLI no longer hands raw key
    // bytes across the socket; it asks the agent to try the OS keychain
    // and (if the keychain is empty) the passphrase fallback. The
    // `method` field below is a hint for the cached entry — the agent
    // overrides it on the audit row when it actually uses the
    // passphrase path.
    let payload = serde_json::json!({
        "project_id": resolved.config.project_id.as_str(),
        "passphrase": serde_json::Value::Null,
        "reuse_cached": true,
        "ttl_seconds": policy.ttl.as_secs(),
        "method": locket_agent::UnlockMethod::OsKeychain,
    });
    let _: serde_json::Value = agent_invoke(
        context,
        locket_agent::AgentMethod::Unlock,
        &payload,
        "unlock agent for policy execution",
    ).map_err(|error| {
        if let CliError::Typed { kind: LocketError::UnlockRequired, message } = error {
            typed_cli_error(
                LocketError::UnlockRequired,
                format!("unlock the policy's project vault with `locket unlock --project {}` before executing: {message}", resolved.config.project_id),
            )
        } else {
            error
        }
    })?;
    Ok(())
}

fn request_agent_grant(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
    action: locket_agent::GrantAction,
    binding: &locket_agent::GrantBinding,
) -> Result<AgentGrantResponse, CliError> {
    let payload = locket_agent::RequestGrantPayload {
        project_id: resolved.config.project_id.to_string(),
        profile_id: profile.id.clone(),
        policy_name: None,
        action,
        confirm_dangerous: profile.dangerous,
        ttl_seconds: policy.ttl.as_secs(),
        binding: binding.clone(),
    };
    agent_invoke(context, locket_agent::AgentMethod::RequestGrant, &payload, "request agent grant")
}

fn resolve_reference_via_agent(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
    agent_access: &AgentPolicyAccess,
    reference: &str,
) -> Result<locket_agent::ResolveResponse, CliError> {
    let Some(grant_id) = agent_access.resolve_grant_id.as_deref() else {
        return Err(typed_cli_error(
            LocketError::GrantRequired,
            "GrantRequired: ResolveReference grant was not issued",
        ));
    };
    let request = locket_agent::ResolveRequest {
        reference: reference.to_owned(),
        project_id: Some(resolved.config.project_id.to_string()),
        profile_id: Some(profile.id.clone()),
        policy_name: Some(policy.name.clone()),
        store_path: Some(context.store_path.display().to_string()),
        grant_id: Some(grant_id.to_owned()),
        binding: Some(agent_access.binding.clone()),
    };
    agent_invoke(
        context,
        locket_agent::AgentMethod::ResolveReference,
        &request,
        "resolve lk reference",
    )
}

fn policy_argv_with_resolved_references(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
    agent_access: &AgentPolicyAccess,
    reference_secret_names: &mut Vec<String>,
) -> Result<Vec<String>, CliError> {
    match &policy.command {
        CommandSpec::Argv(arguments) => arguments
            .iter()
            .map(|argument| {
                resolve_policy_argument_reference(
                    context,
                    resolved,
                    profile,
                    policy,
                    agent_access,
                    argument,
                    reference_secret_names,
                )
            })
            .collect(),
        CommandSpec::Shell(script) if script.contains("lk://") => Err(invalid_policy_error(
            "embedded lk:// references in shell policies are not supported yet",
        )),
        CommandSpec::Shell(script) => Ok(shell_argv(script)),
    }
}

fn resolve_policy_argument_reference(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
    agent_access: &AgentPolicyAccess,
    argument: &str,
    reference_secret_names: &mut Vec<String>,
) -> Result<String, CliError> {
    if !argument.contains("lk://") {
        return Ok(argument.to_owned());
    }
    let parsed = LkReferenceUri::parse(argument)
        .map_err(|_| crate::runtime::error::invalid_reference_error("invalid lk:// reference"))?;
    reference_secret_names.push(parsed.key().as_str().to_owned());
    let response =
        resolve_reference_via_agent(context, resolved, profile, policy, agent_access, argument)?;
    Ok(response.value)
}

fn policy_has_ide_source(policy: &CommandPolicy) -> bool {
    policy.external_env_sources.iter().any(|source| matches!(source, ExternalEnvSource::Ide))
}

fn policy_command_has_lk_references(policy: &CommandPolicy) -> bool {
    match &policy.command {
        CommandSpec::Argv(arguments) => arguments.iter().any(|argument| argument.contains("lk://")),
        CommandSpec::Shell(script) => script.contains("lk://"),
    }
}

fn argv_reference_access(
    command: &CommandSpec,
    allow_insecure_argv: bool,
) -> Result<bool, CliError> {
    if let CommandSpec::Argv(arguments) = command
        && arguments.first().is_some_and(|program| program.contains("lk://"))
    {
        return Err(invalid_policy_error("a secret reference cannot select the executable"));
    }
    let contains_reference = match command {
        CommandSpec::Argv(arguments) => arguments.iter().any(|arg| arg.contains("lk://")),
        CommandSpec::Shell(script) => script.contains("lk://"),
    };
    if !contains_reference {
        return Ok(false);
    }
    if !allow_insecure_argv {
        return Err(invalid_policy_error(
            "secret values in process argv are visible via ps or /proc. Use environment injection or stdin, or pass --allow-insecure-argv to permit substitution",
        ));
    }
    if matches!(command, CommandSpec::Shell(_)) {
        return Err(invalid_policy_error(
            "embedded lk:// references in shell policies are unsupported",
        ));
    }
    Ok(true)
}

fn agent_grant_binding() -> Result<locket_agent::GrantBinding, CliError> {
    let binding = locket_platform::current_process_binding()?;
    Ok(locket_agent::GrantBinding::new(binding.pid, binding.process_start_time))
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn agent_invoke<T, R>(
    context: &RuntimeContext,
    method: locket_agent::AgentMethod,
    payload: &T,
    operation: &'static str,
) -> Result<R, CliError>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let payload = serde_json::to_value(payload)?;
    let response = agent_invoke_value(context, method, payload, operation)?;
    serde_json::from_value(response).map_err(CliError::from)
}

#[cfg(any(unix, windows))]
fn agent_invoke_value(
    context: &RuntimeContext,
    method: locket_agent::AgentMethod,
    payload: serde_json::Value,
    operation: &'static str,
) -> Result<serde_json::Value, CliError> {
    agent_invoke_endpoint_value(&crate::agent_socket_path(context), method, payload, operation)
}

#[cfg(any(unix, windows))]
fn agent_invoke_endpoint_value(
    socket_path: &Path,
    method: locket_agent::AgentMethod,
    payload: serde_json::Value,
    operation: &'static str,
) -> Result<serde_json::Value, CliError> {
    use locket_agent::{RequestEnvelope, ResponseEnvelope};

    let timeout = if method == locket_agent::AgentMethod::Unlock {
        if io::stdin().is_terminal() && !crate::runtime::prompts::prompts_disabled() {
            let _ = writeln!(io::stderr(), "locket: waiting for vault unlock...");
        }
        std::time::Duration::from_secs(120)
    } else {
        std::time::Duration::from_secs(15)
    };
    let request = RequestEnvelope::new(format!("run-{operation}"), method, payload);
    match crate::commands::agent::exchange_agent_request(socket_path, request, Some(timeout))
        .map_err(|error| agent_unavailable(operation, &error))?
    {
        ResponseEnvelope::Success(success) => Ok(success.payload),
        ResponseEnvelope::Error(error) => Err(agent_error_to_cli(&error)),
    }
}

#[cfg(not(any(unix, windows)))]
fn agent_invoke_value(
    _context: &RuntimeContext,
    _method: locket_agent::AgentMethod,
    _payload: serde_json::Value,
    operation: &'static str,
) -> Result<serde_json::Value, CliError> {
    Err(typed_cli_error(
        LocketError::AgentUnavailable,
        format!("AgentUnavailable: {operation} requires the local agent"),
    ))
}

fn agent_unavailable(operation: &'static str, error: &io::Error) -> CliError {
    typed_cli_error(
        LocketError::AgentUnavailable,
        format!("AgentUnavailable: could not {operation}: {error}"),
    )
}

#[cfg(all(test, unix))]
mod framing_tests {
    #![allow(clippy::panic, clippy::unwrap_used)]

    use crate::commands::agent::framing_tests::{
        CANARY, fragmented_success, invalid_frame, with_open_peer,
    };
    use serde_json::json;

    fn rejects_frame(kind: &str) {
        let result = with_open_peer(vec![invalid_frame(kind)], |context| {
            super::agent_invoke_value(context, locket_agent::AgentMethod::Status, json!({}), "test")
        });
        let Err(error) = result else {
            panic!("permanent frame error expected");
        };
        assert!(matches!(
            error,
            crate::CliError::Typed { kind: locket_core::LocketError::AgentUnavailable, .. }
        ));
        assert!(!error.to_string().contains(CANARY));
    }

    #[test]
    fn exec_reader_rejects_oversized_frame_while_peer_stays_open() {
        rejects_frame("oversized");
    }

    #[test]
    fn exec_reader_rejects_malformed_frame_while_peer_stays_open() {
        rejects_frame("malformed");
    }

    #[test]
    fn exec_reader_rejects_version_frame_while_peer_stays_open() {
        rejects_frame("version");
    }

    #[test]
    fn exec_reader_accepts_fragmented_frame_while_peer_stays_open() {
        let result = with_open_peer(fragmented_success(), |context| {
            super::agent_invoke_value(context, locket_agent::AgentMethod::Status, json!({}), "test")
        });
        assert_eq!(result.unwrap(), json!({"ok": true}));
    }
}

fn agent_error_to_cli(error: &locket_agent::ErrorEnvelope) -> CliError {
    let kind = LocketError::from_code_name(&error.error).unwrap_or(LocketError::AgentUnavailable);
    typed_cli_error(kind, format!("{}: {}", error.error, error.message))
}

#[cfg(all(test, windows))]
mod windows_agent_tests {
    use std::io;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use locket_agent::{
        AgentMethod, AgentPipeConfig, DEFAULT_MAX_MESSAGE_SIZE, ErrorEnvelope, ResponseEnvelope,
        SuccessEnvelope, bind_named_pipe_listener, encode_frame,
    };
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn invoke_with_response(
        response: &ResponseEnvelope,
    ) -> Result<Result<serde_json::Value, crate::CliError>, Box<dyn std::error::Error>> {
        let endpoint = PathBuf::from(format!(
            r"\\.\pipe\locket-cli-run-test-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        ));
        let config = AgentPipeConfig::current_user(endpoint.clone())?;
        let frame = encode_frame(response, DEFAULT_MAX_MESSAGE_SIZE)?;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || -> io::Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            runtime.block_on(async move {
                let mut stream = bind_named_pipe_listener(&config)?;
                ready_tx.send(()).map_err(io::Error::other)?;
                tokio::time::timeout(Duration::from_secs(5), async move {
                    stream.connect().await?;
                    let size = stream.read_u32_le().await?;
                    let mut request = vec![0; usize::try_from(size).map_err(io::Error::other)?];
                    stream.read_exact(&mut request).await?;
                    let request: locket_agent::RequestEnvelope =
                        serde_json::from_slice(&request).map_err(io::Error::other)?;
                    assert_eq!(request.kind, AgentMethod::Status.as_str());
                    stream.write_all(&frame).await?;
                    stream.flush().await?;
                    // Keep the server alive until the client consumed its reply.
                    let _closed = stream.read(&mut [0; 1]).await;
                    Ok::<_, io::Error>(())
                })
                .await
                .map_err(io::Error::other)?
            })
        });
        ready_rx.recv_timeout(Duration::from_secs(5))?;
        let result = super::agent_invoke_endpoint_value(
            &endpoint,
            AgentMethod::Status,
            json!({}),
            "windows test",
        );
        server.join().map_err(|_| io::Error::other("named-pipe fixture panicked"))??;
        Ok(result)
    }

    #[test]
    fn windows_agent_rpc_preserves_success_and_typed_denial()
    -> Result<(), Box<dyn std::error::Error>> {
        let success = ResponseEnvelope::Success(SuccessEnvelope::new(
            "run-windows test",
            json!({"lock_state": "locked"}),
        ));
        assert_eq!(invoke_with_response(&success)??, json!({"lock_state": "locked"}));
        let denied = ResponseEnvelope::Error(ErrorEnvelope::new(
            "run-windows test",
            "UserVerificationFailed",
            "verification required",
            false,
        ));
        assert!(matches!(
            invoke_with_response(&denied)?,
            Err(crate::CliError::Typed {
                kind: locket_core::LocketError::UserVerificationFailed,
                ..
            })
        ));
        Ok(())
    }
}

fn policy_argv(policy: &CommandPolicy) -> Vec<String> {
    match &policy.command {
        CommandSpec::Argv(arguments) => arguments.clone(),
        CommandSpec::Shell(script) => shell_argv(script),
    }
}

#[cfg(unix)]
fn shell_argv(script: &str) -> Vec<String> {
    vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()]
}

#[cfg(windows)]
fn shell_argv(script: &str) -> Vec<String> {
    vec!["cmd.exe".to_owned(), "/C".to_owned(), script.to_owned()]
}

pub(super) fn execute_exec_child(
    context: &RuntimeContext,
    request: &RuntimeExecutionRequest<'_>,
    redactor: Option<StreamingRedactorConfig>,
) -> Result<ExitStatus, CliError> {
    if !request.secret_names.is_empty() {
        let protection = redactor.map(|redactor| RunProtection { redactor, broker: None });
        return execute_runtime_child(context, request, protection).map(|outcome| outcome.status);
    }
    let mut command = request.prepared.command();
    if let Some(current_dir) = request.current_dir {
        command.current_dir(current_dir);
    }
    let Some(redactor) = redactor else { return Ok(command.status()?) };
    let mut child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let redaction = redact_child_output(&mut child, io::stdout(), io::stderr(), redactor);
    if redaction.is_err() {
        let _ignored = child.kill();
    }
    let status = child.wait();
    redaction?;
    Ok(status?)
}

fn execute_runtime_child(
    context: &RuntimeContext,
    request: &RuntimeExecutionRequest<'_>,
    protection: Option<RunProtection>,
) -> Result<RuntimeExecutionOutcome, CliError> {
    let started_at = now_unix_nanos()?;
    let session_id = SessionId::generate()
        .map_err(|_| corrupt_db_error("runtime session id generation failed"))?
        .into_string();
    let secret_names =
        runtime_session_retention(context)?.secret_names_for_storage(request.secret_names);
    let mut command = request.prepared.command();
    if let Some(current_dir) = request.current_dir {
        command.current_dir(current_dir);
    }
    if protection.is_some() {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let run_policy_grant = request
        .run_policy_grant
        .map(|grant| request_run_policy_grant(context, request, grant))
        .transpose()?;
    if let Err(error) = recheck_execution_vaults(context, request) {
        revoke_run_policy_grant(context, run_policy_grant.as_ref());
        return Err(error);
    }
    let mut child = match spawn_runtime_child(&mut command, request) {
        Ok(child) => child,
        Err(error) => {
            revoke_run_policy_grant(context, run_policy_grant.as_ref());
            return Err(error);
        }
    };
    drop(command);
    let process_id = child.id();
    let session = RuntimeSessionRecord {
        id: session_id,
        project_id: request.profile.project_id.clone(),
        profile_id: request.profile.id.clone(),
        policy_name: request.policy_name.map(ToOwned::to_owned),
        process_id,
        process_start_time: started_at,
        started_at,
        ended_at: None,
        exit_status: None,
        secret_names,
        spawn_audit_sequence: None,
        completion_audit_sequence: None,
    };

    if let Err(error) = request.store.insert_runtime_session(&session) {
        revoke_run_policy_grant(context, run_policy_grant.as_ref());
        let _ignored = child.kill();
        let _ignored = child.wait();
        return Err(error.into());
    }

    let (redaction, broker) = protection.map_or((Ok(()), None), |protection| {
        (
            redact_child_output(&mut child, io::stdout(), io::stderr(), protection.redactor)
                .map(|_| ()),
            protection.broker,
        )
    });
    if redaction.is_err() {
        let _ignored = child.kill();
    }
    let status = child.wait();
    let blocked = broker.map_or(0, |broker| {
        broker
            .shutdown()
            .into_iter()
            .filter(|event| matches!(event, EgressEvent::Blocked { .. }))
            .count()
    });
    revoke_run_policy_grant(context, run_policy_grant.as_ref());
    let status = status?;
    request.store.mark_runtime_session_completed(
        &session.id,
        now_unix_nanos()?,
        status.code(),
        None,
    )?;
    redaction?;
    if blocked > 0 {
        let _ignored =
            writeln!(io::stderr(), "warning: Locket blocked {blocked} egress request(s)");
    }
    Ok(RuntimeExecutionOutcome {
        status,
        run_policy_grant: run_policy_grant.map(|grant| grant.metadata),
    })
}

fn recheck_execution_vaults(
    context: &RuntimeContext,
    request: &RuntimeExecutionRequest<'_>,
) -> Result<(), CliError> {
    for project in &request.shared_projects {
        require_shared_vault_unlocked(context, project)?;
    }
    if request.shared_projects.iter().any(|project| *project != request.profile.project_id) {
        require_vault_unlocked(
            context,
            &request.profile.project_id,
            "the consuming project vault",
            "executing with shared secrets",
        )?;
    }
    Ok(())
}

fn spawn_runtime_child(
    command: &mut ProcessCommand,
    request: &RuntimeExecutionRequest<'_>,
) -> Result<std::process::Child, CliError> {
    if let (Some(grant), Some(name)) = (request.run_policy_grant, request.policy_name) {
        grant.source.require_current(request.store, grant.resolved, name)?;
    }
    Ok(command.spawn()?)
}

#[derive(serde::Deserialize)]
struct RunPolicyGrantResponse {
    grant_id: String,
    project_id: String,
    profile_id: String,
    action: locket_agent::GrantAction,
    expires_at_unix_nanos: String,
    ttl_seconds: u64,
    binding: locket_agent::GrantBinding,
}

fn request_run_policy_grant(
    context: &RuntimeContext,
    request: &RuntimeExecutionRequest<'_>,
    grant: RunPolicyGrantRequest<'_>,
) -> Result<RunPolicyGrant, CliError> {
    let ttl_seconds = grant.ttl_seconds;
    let policy_name =
        request.policy_name.ok_or_else(|| invalid_policy_error("run grant needs a policy"))?;
    grant.source.require_current(request.store, grant.resolved, policy_name)?;
    let cwd = request.current_dir.unwrap_or(&context.cwd).canonicalize()?;
    let binding = agent_grant_binding()?.with_execution(policy_name, cwd);
    // Unit fixtures without an agent exercise local child behavior. Fixtures
    // with an explicit endpoint use the same grant exchange as production.
    #[cfg(test)]
    if context.agent_data_dir.is_none() {
        return Ok(RunPolicyGrant {
            grant_id: "lk_grant_test".to_owned(),
            metadata: RunPolicyGrantMetadata { ttl_seconds, binding },
        });
    }
    let payload = locket_agent::RequestGrantPayload {
        project_id: grant.resolved.config.project_id.to_string(),
        profile_id: request.profile.id.clone(),
        policy_name: Some(policy_name.to_owned()),
        action: locket_agent::GrantAction::RunPolicy,
        confirm_dangerous: request.profile.dangerous,
        ttl_seconds,
        binding: binding.clone(),
    };
    let response: RunPolicyGrantResponse = agent_invoke(
        context,
        locket_agent::AgentMethod::RequestGrant,
        &payload,
        "authorize policy launch",
    )?;
    let now = now_unix_nanos()?;
    if response.binding != binding
        || response.project_id != payload.project_id
        || response.profile_id != payload.profile_id
        || response.action != payload.action
        || locket_core::id::GrantId::new(&response.grant_id).is_err()
        || !response.expires_at_unix_nanos.parse::<i64>().is_ok_and(|expiry| expiry > now)
        || !(1..=3600).contains(&response.ttl_seconds)
    {
        revoke_run_policy_grant_id(context, &response.grant_id);
        return Err(typed_cli_error(
            LocketError::GrantRequired,
            "agent returned an invalid policy grant",
        ));
    }
    Ok(RunPolicyGrant {
        grant_id: response.grant_id,
        metadata: RunPolicyGrantMetadata {
            ttl_seconds: response.ttl_seconds,
            binding: response.binding,
        },
    })
}

fn revoke_run_policy_grant(context: &RuntimeContext, grant: Option<&RunPolicyGrant>) {
    if let Some(grant) = grant {
        revoke_run_policy_grant_id(context, &grant.grant_id);
    }
}

fn revoke_run_policy_grant_id(context: &RuntimeContext, grant_id: &str) {
    #[cfg(test)]
    if context.agent_data_dir.is_none() {
        return;
    }
    let _ignored: Result<serde_json::Value, _> = agent_invoke(
        context,
        locket_agent::AgentMethod::RevokeGrant,
        &serde_json::json!({"grant_id": grant_id}),
        "revoke policy launch grant",
    );
}

fn runtime_session_retention(
    context: &RuntimeContext,
) -> Result<RuntimeSessionSecretNameRetention, CliError> {
    let config = read_user_config(context)?;
    let Some(value) = config_get_value(&config, "runtime.session_secret_name_retention") else {
        return Ok(RuntimeSessionSecretNameRetention::default());
    };
    let Some(value) = value.as_str() else {
        return Err(metadata_invalid_error(
            "runtime.session_secret_name_retention must be a duration or off",
        ));
    };
    RuntimeSessionSecretNameRetention::from_str(value).map_err(|_| {
        metadata_invalid_error("runtime.session_secret_name_retention must be a duration or off")
    })
}

pub fn unique_secret_names<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    names.map(ToOwned::to_owned).collect::<BTreeSet<_>>().into_iter().collect()
}

/// Loads the named command policy or, on failure, writes a metadata-only
/// DENIED `RUN_POLICY` audit row before propagating the typed error. Audit
/// bookkeeping never masks the original error.
fn load_command_policy_or_audit_denial(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    policy_name: &str,
) -> Result<ApprovedRunPolicy, CliError> {
    let load = || {
        let source = require_approved_policy_source(store, resolved, policy_name)?;
        let effective =
            effective_command_policy(&source.document, resolved, policy_name, &context.cwd)?;
        Ok(ApprovedRunPolicy { source, effective })
    };
    match load() {
        Ok(policy) => Ok(policy),
        Err(error) => {
            let reason = match error {
                CliError::Typed { kind: LocketError::PolicyNotFound, .. } => "policy_not_found",
                CliError::Typed { kind: LocketError::AccessDenied, .. } => "policy_unapproved",
                _ => "policy_rejected",
            };
            let profile = default_profile(store, &resolved.config).ok();
            let _ignored = write_runtime_policy_denial_audit_if_available(
                context,
                store,
                resolved,
                profile.as_ref(),
                None,
                policy_name,
                reason,
            );
            Err(error)
        }
    }
}

/// Maps a `prepare_policy_execution` failure to the metadata-only
/// `failure_reason` recorded in the DENIED `RUN_POLICY` audit row. Names are
/// stable identifiers and never include human-readable messages or values.
fn denial_failure_reason(error: &CliError) -> &'static str {
    match error {
        CliError::Typed { kind, message } => match kind {
            LocketError::InvalidPolicy => {
                // External env file path validation also raises InvalidPolicy
                // per runtime.md:117. Disambiguate via the canonical message
                // prefix used by `resolve_external_env_file` so the audit
                // failure_reason stays distinct from generic missing-secret
                // denials.
                if message.starts_with("external env file ")
                    || message.starts_with("could not canonicalize project root ")
                {
                    "external_source_metadata_invalid"
                } else {
                    "missing_required_secret"
                }
            }
            LocketError::ExternalSourceUnavailable => "external_source_unavailable",
            LocketError::MetadataInvalid
                if message == crate::commands::secrets::expiry::SECRET_EXPIRED_MESSAGE =>
            {
                "secret_expired"
            }
            LocketError::MetadataInvalid => "external_source_metadata_invalid",
            LocketError::InvalidReference => "invalid_lk_reference",
            LocketError::AgentUnavailable => "agent_unavailable",
            LocketError::GrantRequired => "grant_required",
            LocketError::AccessDenied => "access_denied",
            _ => "policy_rejected",
        },
        _ => "policy_rejected",
    }
}

/// Applies authorized public fallbacks, then checks only the final selected values.
pub fn finalize_configuration_environment(
    document: &PolicyDocument,
    policy: &CommandPolicy,
    env: &mut locket_exec::EnvMap,
) -> Result<(), CliError> {
    document.apply_variable_defaults(policy, env);
    locket_exec::restrict_child_search_path(env);
    let missing = policy
        .required_secrets
        .iter()
        .filter(|name| !env.contains_key(name.as_str()))
        .map(|name| {
            let guidance = document.variables.get(name.as_str());
            let mut item = format!("{name}; run `locket set {name}`");
            if let Some(description) = guidance.and_then(|contract| contract.description.as_deref())
            {
                item.push_str("; ");
                item.push_str(description);
            }
            if let Some(hint) = guidance.and_then(|contract| contract.setup_hint.as_deref()) {
                item.push_str("; ");
                item.push_str(hint);
            }
            item
        })
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(invalid_policy_error(format!(
            "required secret(s) missing: {}",
            missing.join(", ")
        )));
    }
    document
        .validate_variable_values(policy, env)
        .map_err(|error| invalid_policy_error(error.to_string()))
}

pub fn write_configuration_warnings(
    document: &PolicyDocument,
    policy: &CommandPolicy,
    output: &mut impl Write,
) -> Result<(), CliError> {
    for row in document.variable_readiness(policy, &std::collections::BTreeMap::new(), false) {
        if let Some(warning) = row.warning {
            writeln!(output, "warning: {warning}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod approval_tests {
    use clap::Parser;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[test]
    fn reference_opt_in_applies_to_arguments_only() -> Result<(), crate::CliError> {
        use locket_core::CommandSpec;

        let program = CommandSpec::Argv(vec!["lk://dev/TOOL".into(), "argument".into()]);
        assert!(super::argv_reference_access(&program, true).is_err());
        let argument = CommandSpec::Argv(vec!["tool".into(), "lk://dev/TOKEN".into()]);
        assert!(super::argv_reference_access(&argument, true)?);
        Ok(())
    }

    struct Confirmations(Mutex<VecDeque<String>>);
    impl crate::ConfirmationReader for Confirmations {
        fn read_confirmation(&self, _prompt: &str) -> Result<String, crate::CliError> {
            self.0
                .lock()
                .map_err(|_| crate::confirmation_failed_error("fixture lock"))?
                .pop_front()
                .ok_or_else(|| crate::confirmation_failed_error("unexpected prompt"))
        }
    }

    #[test]
    fn compose_config_only_imports_allowed_scalar_or_assignment_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let doc = locket_core::PolicyDocument::from_toml_str(
            "schema_version=1\n[commands.dev]\nargv=[\"true\"]\noptional_secrets=[\"PORT\",\"DEBUG\",\"ABSENT\",\"HOST\"]",
        )?;
        let policy = &doc.commands["dev"];
        let environment = super::resolve_external_env_compose_json(
            policy,
            br#"{
                "environment": {"PORT": 3000, "DEBUG": true, "ABSENT": {"ignored": true}, "PRIVATE": "excluded"},
                "services": {
                    "app": {"environment": ["HOST=local=fixture", "ABSENT", 5, "PRIVATE=excluded"]},
                    "worker": {"environment": null}
                }
            }"#,
        )?;
        assert_eq!(environment.get("PORT").map(|value| value.as_str()), Some("3000"));
        assert_eq!(environment.get("DEBUG").map(|value| value.as_str()), Some("true"));
        assert_eq!(environment.get("HOST").map(|value| value.as_str()), Some("local=fixture"));
        assert_eq!(environment.len(), 3);
        let Err(error) = super::resolve_external_env_compose_json(policy, b"{") else {
            return Err("malformed Compose output was accepted".into());
        };
        assert!(error.to_string().contains("docker compose config returned invalid JSON"));
        Ok(())
    }

    #[test]
    fn external_file_preserves_literal_data_and_ignores_unrelated_invalid_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::write(
            directory.path().join("local.env"),
            "OTHER=pa$$\nlower=x\nAPI_KEY=token$literal\n",
        )?;
        let doc = locket_core::PolicyDocument::from_toml_str(
            "schema_version=1\n[commands.dev]\nargv=[\"true\"]\nrequired_secrets=[\"API_KEY\"]",
        )?;
        let env = super::resolve_external_env_file(
            std::path::Path::new("local.env"),
            directory.path(),
            &doc.commands["dev"],
        )?;
        assert_eq!(env.len(), 1);
        assert!(env.contains_key("API_KEY"));
        Ok(())
    }

    #[test]
    fn approval_does_not_move_subtree_variables_into_global_command()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut context = crate::tests::test_context(&directory);
        crate::run_with_context(
            crate::Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
            &context,
            &mut Vec::new(),
        )?;
        let path = directory.path().join("locket.toml");
        let text = std::fs::read_to_string(&path)?;
        std::fs::write(
            &path,
            format!("{text}\n[paths.\"packages/api\"]\nrequired_secrets=[\"PACKAGE_ONLY\"]\n"),
        )?;
        std::fs::create_dir_all(directory.path().join("packages/api"))?;
        // Keep the caller's spelling noncanonical. Windows also adds a verbatim
        // prefix when resolving the project root, so raw path comparisons must
        // not accidentally widen this subtree-only authorization.
        context.cwd = directory.path().join("packages/../packages/api");
        context.confirmation_reader =
            Arc::new(Confirmations(Mutex::new(VecDeque::from(["approve dev".into()]))));
        let resolved = crate::require_project(&context)?;
        let effective = super::resolve_run_policy(
            &context,
            &mut Vec::new(),
            &mut crate::open_store(&context)?,
            &resolved,
            &crate::RunArgs {
                policy: String::new(),
                runner_args: Vec::new(),
                argv: vec!["true".into()],
                ..crate::RunArgs::default()
            },
        )?
        .effective;
        assert!(
            effective.policy.required_secrets.iter().any(|name| name.as_str() == "PACKAGE_ONLY")
        );
        let saved = crate::read_policy_document(&path)?;
        assert_eq!(saved.commands["dev"].required_secrets, [] as [locket_core::SecretName; 0]);
        Ok(())
    }

    #[test]
    fn secret_acl_rejects_working_directory_outside_project()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let document = locket_core::PolicyDocument::from_toml_str(
            "schema_version=1\n[commands.dev]\nargv=['true']\nrequired_secrets=['ROOT_ONLY']\n\
             [secrets.ROOT_ONLY]\nallow_paths=['.']\n",
        )?;
        let error = crate::enforce_secret_access_policies(
            &document,
            &document.commands["dev"],
            directory.path(),
            outside.path(),
        )
        .err()
        .ok_or("outside-project paths must not inherit root authorization")?;
        assert!(error.to_string().contains("outside project root"));
        Ok(())
    }

    #[test]
    fn previously_safe_command_requires_confirmation_after_environment_becomes_dangerous()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut context = crate::tests::test_context(&directory);
        crate::run_with_context(
            crate::Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
            &context,
            &mut Vec::new(),
        )?;
        crate::run_with_context(
            crate::Cli::try_parse_from(["locket", "policy", "add", "dev", "--", "/usr/bin/true"])?,
            &context,
            &mut Vec::new(),
        )?;
        let resolved = crate::require_project(&context)?;
        crate::open_store(&context)?.connection().execute(
            "UPDATE profiles SET dangerous=1 WHERE project_id=?1",
            [resolved.config.project_id.as_str()],
        )?;
        context.confirmation_reader =
            Arc::new(Confirmations(Mutex::new(VecDeque::from(["wrong".into()]))));
        let result = super::run_command(
            &context,
            &mut Vec::new(),
            &crate::RunArgs { policy: "dev".into(), ..crate::RunArgs::default() },
        );
        assert!(matches!(result,Err(error) if error.exit_code()==68));
        Ok(())
    }

    #[test]
    fn approved_dangerous_command_retains_confirmation_on_later_runs()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut context = crate::tests::test_context(&directory);
        crate::run_with_context(
            crate::Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
            &context,
            &mut Vec::new(),
        )?;
        let resolved = crate::require_project(&context)?;
        let store = crate::open_store(&context)?;
        store.connection().execute(
            "UPDATE profiles SET dangerous=1 WHERE project_id=?1",
            [resolved.config.project_id.as_str()],
        )?;
        context.confirmation_reader = Arc::new(Confirmations(Mutex::new(VecDeque::from([
            "approve dev".to_owned(),
            "dev".to_owned(),
        ]))));
        let effective = super::resolve_run_policy(
            &context,
            &mut Vec::new(),
            &mut crate::open_store(&context)?,
            &resolved,
            &crate::RunArgs {
                policy: String::new(),
                runner_args: Vec::new(),
                argv: vec!["/usr/bin/true".to_owned()],
                ..crate::RunArgs::default()
            },
        )?
        .effective;
        assert!(effective.policy.confirm);
        Ok(())
    }
    #[test]
    fn runner_reuses_saved_dev_authorization_and_security_gates()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let context = crate::tests::test_context(&directory);
        crate::run_with_context(
            crate::Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
            &context,
            &mut Vec::new(),
        )?;
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"scripts":{"dev":"touch must-not-run"}}"#,
        )?;
        let path = directory.path().join("locket.toml");
        let mut text = std::fs::read_to_string(&path)?;
        text.push_str("\n[commands.dev]\nargv=[\"npm\",\"run\",\"dev\"]\nrequired_secrets=[\"API_KEY\"]\nconfirm=true\nrequire_user_verification=true\nenv_mode=\"strict\"\n");
        std::fs::write(path, text)?;
        crate::tests::approve_test_policy(&context, "dev")?;
        let resolved = crate::require_project(&context)?;
        let effective = super::resolve_run_policy(
            &context,
            &mut Vec::new(),
            &mut crate::open_store(&context)?,
            &resolved,
            &crate::RunArgs {
                policy: "npm".to_owned(),
                runner_args: vec!["dev".to_owned()],
                argv: Vec::new(),
                ..crate::RunArgs::default()
            },
        )?
        .effective;
        assert_eq!(effective.policy.name, "dev");
        assert!(effective.policy.confirm);
        assert!(effective.policy.require_user_verification);
        assert_eq!(effective.policy.required_secrets[0].as_str(), "API_KEY");
        assert_eq!(effective.policy.env_mode, locket_core::EnvMode::Strict);
        assert!(!directory.path().join("must-not-run").exists());
        Ok(())
    }
}

#[cfg(test)]
mod configuration_runtime_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn configuration_contract_runtime_defaults_are_fallbacks_and_names_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let context = crate::tests::test_context(&directory);
        crate::run_with_context(
            crate::Cli::try_parse_from([
                "locket",
                "init",
                "--name",
                "fixture",
                "--profile",
                "dev",
            ])?,
            &context,
            &mut Vec::new(),
        )?;
        let path = context.cwd.join("locket.toml");
        let mut text = fs::read_to_string(&path)?;
        text.push_str(
            r"
[commands.check]
argv=['echo']
required_secrets=['PORT','API_URL']
optional_secrets=['NEXT_PUBLIC_TOKEN']
external_env_sources=[{file='.fixture-env'}]
[variables.PORT]
classification='public'
type='integer'
default='3001'
[variables.API_URL]
classification='public'
type='url'
default='http://localhost:3001/default-canary'
[variables.UNAUTHORIZED]
classification='public'
default='must-not-inject'
",
        );
        fs::write(&path, text)?;
        fs::write(
            context.cwd.join(".fixture-env"),
            "API_URL=http://localhost:4000/external-canary\n",
        )?;
        let resolved = require_project(&context)?;
        crate::tests::approve_test_policy(&context, "check")?;
        let mut store = open_store(&context)?;
        let policy = load_command_policy_or_audit_denial(&context, &mut store, &resolved, "check")?;
        let profile = default_profile(&store, &resolved.config)?;
        let mut output = Vec::new();
        let prepared = prepare_policy_execution(
            &context,
            &mut output,
            &store,
            &resolved,
            &profile,
            &policy,
            false,
        )?;
        assert_eq!(prepared.prepared.env.get("PORT").map(|value| value.as_str()), Some("3001"));
        assert_eq!(
            prepared.prepared.env.get("API_URL").map(|value| value.as_str()),
            Some("http://localhost:4000/external-canary")
        );
        assert!(!prepared.prepared.env.contains_key("UNAUTHORIZED"));
        // Execute only this synthetic assertion helper, never the fixture's app command.
        #[cfg(unix)]
        {
            let mut command = std::process::Command::new("/bin/sh");
            command.arg("-c").arg("test \"$PORT\" = 3001 && test \"$API_URL\" = http://localhost:4000/external-canary && test -z \"$UNAUTHORIZED\"").env_clear();
            for (name, value) in &prepared.prepared.env {
                command.env(name, value.as_str());
            }
            assert!(command.status()?.success());
        }

        let text = String::from_utf8(output)?;
        assert!(text.contains("browser bundles"));
        assert!(!text.contains("external-canary"));
        Ok(())
    }

    #[test]
    fn configuration_contract_final_values_validate_after_source_precedence()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let context = crate::tests::test_context(&directory);
        crate::run_with_context(
            crate::Cli::try_parse_from([
                "locket",
                "init",
                "--name",
                "fixture",
                "--profile",
                "dev",
            ])?,
            &context,
            &mut Vec::new(),
        )?;
        crate::set_secret_value(
            &context,
            &crate::tests::test_secret_write_args("PORT"),
            "secret-canary-invalid-integer",
            "manual",
            1_000,
        )?;
        let path = context.cwd.join("locket.toml");
        let mut text = fs::read_to_string(&path)?;
        text.push_str("\n[commands.keep_external]\nargv=['not-a-real-project-command']\nrequired_secrets=['PORT']\nexternal_env_sources=[{file='.synthetic-env'}]\noverride='preserve'\n[commands.use_vault]\nargv=['not-a-real-project-command']\nrequired_secrets=['PORT']\nexternal_env_sources=[{file='.synthetic-env'}]\noverride='locket'\n[variables.PORT]\ntype='integer'\n");
        fs::write(path, text)?;
        fs::write(context.cwd.join(".synthetic-env"), "PORT=4000\n")?;
        let resolved = require_project(&context)?;
        crate::tests::approve_test_policy(&context, "keep_external")?;
        crate::tests::approve_test_policy(&context, "use_vault")?;
        let mut store = open_store(&context)?;
        let profile = default_profile(&store, &resolved.config)?;
        let keep =
            load_command_policy_or_audit_denial(&context, &mut store, &resolved, "keep_external")?;
        let prepared = prepare_policy_execution(
            &context,
            &mut Vec::new(),
            &store,
            &resolved,
            &profile,
            &keep,
            false,
        )?;
        assert_eq!(prepared.prepared.env["PORT"].as_str(), "4000");
        let policy =
            load_command_policy_or_audit_denial(&context, &mut store, &resolved, "use_vault")?;
        let result = prepare_policy_execution(
            &context,
            &mut Vec::new(),
            &store,
            &resolved,
            &profile,
            &policy,
            false,
        );
        let Err(error) = result else {
            return Err("invalid selected value must fail before spawn".into());
        };
        assert!(error.to_string().contains("PORT"));
        assert!(error.to_string().contains("integer"));
        assert!(!error.to_string().contains("secret-canary"));
        Ok(())
    }
}
