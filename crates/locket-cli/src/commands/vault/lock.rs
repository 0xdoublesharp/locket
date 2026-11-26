//! Lock and unlock command implementations.

use std::io::{self, Write};
use std::str::FromStr;

use locket_core::LocketError;
use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, ProfileRecord, Store};
use serde_json::json;

use crate::commands::agent::request_status_snapshot;
use crate::commands::config::spec::{config_get_value, read_user_config};
use crate::commands::discovery::{
    GLOBAL_VAULT, SHARED_PROJECT_PREFIX, select_project, trusted_project_configs,
};
use crate::commands::exec::run::agent_invoke;
use crate::runtime::error::{
    metadata_invalid_error, profile_not_found_error, project_not_found_error, typed_cli_error,
};
use crate::runtime::prompts::prompts_disabled;
use crate::runtime::user_verification::require_user_verification;
use crate::support::handoff::shell_quote;
use crate::{
    CliError, LockArgs, MasterKeySource, ResolvedProject, RuntimeContext, UnlockArgs,
    default_profile, ensure_project_exists, load_project_key_with_source, now_unix_nanos,
    open_store, resolve_project,
};

const DIRECT_CLI_CLIENT_KIND: &str = "direct-cli";
const LOCK_COMMAND: &str = "lock";
const UNLOCK_COMMAND: &str = "unlock";
const MAX_BATCH_PROJECTS: usize = 8;

struct VaultTarget {
    profile: ProfileRecord,
    explicit: bool,
}

const fn unlock_method(source: MasterKeySource) -> &'static str {
    match source {
        MasterKeySource::OsKeyStore => "OsKeychain",
        MasterKeySource::PassphraseFallback => "Passphrase",
    }
}

pub fn lock_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &LockArgs,
) -> Result<(), CliError> {
    let current = current_project(context, &args.project)?;
    let mut store = (current.is_some() || !args.project.is_empty() || args.shared)
        .then(|| open_store(context))
        .transpose()?;
    let targets = store
        .as_ref()
        .map(|store| vault_targets(context, store, current.as_ref(), &args.project, args.shared))
        .transpose()?
        .unwrap_or_default();

    if agent_is_available(context)? {
        if targets.is_empty() {
            lock_agent(context, None)?;
        }
        run_vault_batch(output, &targets, LOCK_COMMAND, "locked", |output, profile| {
            lock_agent(context, Some(&profile.project_id))?;
            writeln!(output, "project_id: {}", profile.project_id)?;
            Ok(())
        })?;
        writeln!(output, "agent: locked")?;
        writeln!(output, "cached_keys: cleared")?;
        return Ok(());
    }

    writeln!(output, "lock: no agent-held keys to clear")?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "metadata_only: yes")?;
    if let Some(store) = &mut store {
        run_vault_batch(
            output,
            &targets,
            LOCK_COMMAND,
            "locked (metadata only)",
            |output, profile| {
                writeln!(output, "project_id: {}", profile.project_id)?;
                lock_direct(context, store, profile)
            },
        )?;
    }
    Ok(())
}

fn lock_direct(
    context: &RuntimeContext,
    store: &mut Store,
    profile: &ProfileRecord,
) -> Result<(), CliError> {
    let project_id = &profile.project_id;
    let Ok((audit_key, _)) =
        load_project_key_with_source(context, store, project_id, KeyPurpose::Audit)
    else {
        // Without an agent or an audit key, the lock remains a metadata-only no-op.
        return Ok(());
    };

    let timestamp = now_unix_nanos()?;
    let metadata = json!({
        "schema_version": 1,
        "action": "LOCK",
        "status": "SUCCESS",
        "command": LOCK_COMMAND,
        "client_kind": DIRECT_CLI_CLIENT_KIND,
        "agent_available": false,
        "cached_keys_cleared": 0,
        "live_grants_revoked": 0,
        "grant_actions": [],
        "ttl_seconds": 0,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: Some(&profile.id),
        action: "LOCK",
        status: "SUCCESS",
        secret_name: None,
        command: Some(LOCK_COMMAND),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn lock_agent(context: &RuntimeContext, project_id: Option<&str>) -> Result<(), CliError> {
    let _: serde_json::Value = agent_invoke(
        context,
        locket_agent::AgentMethod::Lock,
        &json!({ "project_id": project_id }),
        "lock vault",
    )?;
    Ok(())
}

pub fn unlock_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &UnlockArgs,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    let current = current_project(context, &args.project)?;
    let targets = vault_targets(context, &store, current.as_ref(), &args.project, args.shared)?;
    if targets.is_empty() {
        return Err(project_not_found_error());
    }
    if prompts_disabled() {
        return Err(noninteractive_unlock_error(&targets, args));
    }
    if agent_is_available(context)? {
        let ttl = unlock_ttl(context, args.ttl)?;
        return run_vault_batch(output, &targets, UNLOCK_COMMAND, "unlocked", |output, profile| {
            unlock_agent(context, profile, ttl, args.verify_user)?;
            writeln!(output, "project_id: {}", profile.project_id)?;
            writeln!(output, "active_profile: {} ({})", profile.name, profile.id)?;
            writeln!(output, "agent: unlocked")?;
            writeln!(output, "cached_keys: yes")?;
            writeln!(output, "ttl_seconds: {ttl}")?;
            Ok(())
        });
    }

    if targets.iter().any(|target| target.profile.project_id.starts_with(SHARED_PROJECT_PREFIX)) {
        return Err(typed_cli_error(
            LocketError::AgentUnavailable,
            "start the agent with `locket agent start` to unlock the Global Vault",
        ));
    }
    run_vault_batch(
        output,
        &targets,
        UNLOCK_COMMAND,
        "unlocked (metadata only)",
        |output, profile| unlock_direct(context, output, &mut store, profile, args.verify_user),
    )
}

fn noninteractive_unlock_error(targets: &[VaultTarget], args: &UnlockArgs) -> CliError {
    use std::fmt::Write as _;

    let mut command = String::from("locket unlock");
    let mut vaults = Vec::with_capacity(targets.len());
    for target in targets {
        let id = &target.profile.project_id;
        let shared = id.starts_with(SHARED_PROJECT_PREFIX);
        if target.explicit || (targets.len() > 1 && !shared) {
            let _ = write!(command, " --project {}", shell_quote(id));
        }
        if shared {
            vaults.push(format!("the Global Vault ({id})"));
        } else {
            vaults.push(format!("vault {id}"));
        }
    }
    if args.shared {
        command.push_str(" --shared");
    }
    if let Some(ttl) = args.ttl {
        let _ = write!(command, " --ttl {ttl}");
    }
    if args.verify_user {
        command.push_str(" --verify-user");
    }
    let vaults = vaults.join(", ");
    typed_cli_error(
        LocketError::UnlockRequired,
        format!(
            "unlocking {vaults} requires interactive verification (LOCKET_NO_PROMPT is set). Run `{command}` from an interactive desktop terminal or unlock in Locket Desktop"
        ),
    )
}

fn current_project(
    context: &RuntimeContext,
    selectors: &[String],
) -> Result<Option<ResolvedProject>, CliError> {
    if selectors.is_empty() { resolve_project(&context.cwd) } else { Ok(None) }
}

fn vault_targets(
    context: &RuntimeContext,
    store: &Store,
    current: Option<&ResolvedProject>,
    selectors: &[String],
    shared: bool,
) -> Result<Vec<VaultTarget>, CliError> {
    let mut targets = Vec::new();
    if let Some(current) = current {
        ensure_project_exists(store, current.config.project_id.as_str())?;
        targets.push(VaultTarget {
            profile: default_profile(store, &current.config)?,
            explicit: false,
        });
    }

    let selections = selectors.iter().map(|selector| (selector.as_str(), true));
    for (selector, explicit) in selections.chain(shared.then_some((GLOBAL_VAULT, false))) {
        let project = select_project(store, &context.cwd, selector).map_err(|error| {
            if selector == GLOBAL_VAULT
                && matches!(error, CliError::Typed { kind: LocketError::ProjectNotFound, .. })
            {
                return typed_cli_error(
                    LocketError::ProjectNotFound,
                    "Global Vault (@shared) is not initialized. Run `locket shared init` first.",
                );
            }
            error
        })?;
        if targets.iter().any(|target| target.profile.project_id == project.id) {
            continue;
        }
        if targets.len() == MAX_BATCH_PROJECTS {
            return Err(metadata_invalid_error(format!(
                "lock and unlock have an {MAX_BATCH_PROJECTS}-vault batch limit"
            )));
        }
        let profile = project_profile(store, &project.id)?;
        targets.push(VaultTarget { profile, explicit });
    }
    Ok(targets)
}

fn project_profile(store: &Store, project_id: &str) -> Result<ProfileRecord, CliError> {
    if project_id.starts_with(SHARED_PROJECT_PREFIX) {
        store
            .get_profile_by_name(project_id, "default")?
            .ok_or_else(|| profile_not_found_error("Global Vault default profile is missing"))
    } else if let Some(resolved) = trusted_project_configs(store, project_id)?.first() {
        default_profile(store, &resolved.config)
    } else {
        store
            .list_profiles(project_id)?
            .into_iter()
            .next()
            .ok_or_else(|| profile_not_found_error("project has no profile"))
    }
}

fn run_vault_batch<W: Write>(
    output: &mut W,
    targets: &[VaultTarget],
    command: &str,
    success: &str,
    mut run: impl FnMut(&mut W, &ProfileRecord) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let batch = targets.len() > 1;
    for (index, target) in targets.iter().enumerate() {
        let id = &target.profile.project_id;
        if let Err(error) = run(output, &target.profile) {
            if batch {
                let _ = writeln!(output, "vault {id}: {command} failed");
                for skipped in &targets[index + 1..] {
                    let _ =
                        writeln!(output, "vault {}: {command} skipped", skipped.profile.project_id);
                }
            }
            return Err(error);
        }
        if batch {
            writeln!(output, "vault {id}: {success}")?;
        }
    }
    Ok(())
}

fn agent_is_available(context: &RuntimeContext) -> Result<bool, CliError> {
    #[cfg(test)]
    if context.agent_data_dir.is_none() {
        return Ok(false);
    }
    match request_status_snapshot(&crate::agent_socket_path(context)) {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::Unsupported
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(typed_cli_error(
            LocketError::AgentUnavailable,
            format!("could not reach the agent: {error}"),
        )),
    }
}

fn unlock_ttl(context: &RuntimeContext, explicit: Option<u64>) -> Result<u64, CliError> {
    if let Some(seconds) = explicit {
        return Ok(seconds);
    }
    let config = read_user_config(context)?;
    let Some(value) = config_get_value(&config, "agent.unlock_ttl") else { return Ok(900) };
    value
        .as_str()
        .and_then(|value| locket_core::Duration::from_str(value).ok())
        .map(|duration| duration.as_secs())
        .filter(|seconds| (1..=86_400).contains(seconds))
        .ok_or_else(|| metadata_invalid_error("agent.unlock_ttl must be between 1s and 24h"))
}

fn unlock_agent(
    context: &RuntimeContext,
    profile: &ProfileRecord,
    ttl: u64,
    verify_user: bool,
) -> Result<(), CliError> {
    #[derive(serde::Serialize)]
    struct UnlockAudit<'a> {
        store_path: &'a std::path::Path,
        profile_id: &'a str,
    }

    #[derive(serde::Serialize)]
    struct UnlockRequest<'a> {
        project_id: &'a str,
        passphrase: Option<&'a str>,
        verify_user: bool,
        ttl_seconds: u64,
        audit: UnlockAudit<'a>,
    }

    let invoke = |passphrase: Option<&str>| {
        let payload = UnlockRequest {
            project_id: &profile.project_id,
            passphrase,
            verify_user,
            ttl_seconds: ttl,
            audit: UnlockAudit { store_path: &context.store_path, profile_id: &profile.id },
        };
        let _: serde_json::Value =
            agent_invoke(context, locket_agent::AgentMethod::Unlock, &payload, "unlock vault")?;
        Ok::<_, CliError>(())
    };
    match invoke(None) {
        Err(CliError::Typed { kind: LocketError::UnlockRequired, message })
            if message.contains("no master key in OS keychain")
                && context.passphrase_store.contains_project(&profile.project_id)? =>
        {
            let passphrase = context.passphrase_reader.existing_passphrase()?;
            invoke(Some(passphrase.as_str()))
        }
        result => result,
    }
}

fn unlock_direct(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &mut Store,
    profile: &ProfileRecord,
    verify_user: bool,
) -> Result<(), CliError> {
    let user_verification = if verify_user {
        require_user_verification(context, "vault unlock", "unlock vault")?
    } else {
        crate::runtime::user_verification::configured_user_verification(
            context,
            "user_verification_required_for.unlock",
            "vault unlock",
            "unlock vault",
        )?
    };
    let project_id = profile.project_id.as_str();
    let (audit_key, source) =
        load_project_key_with_source(context, store, project_id, KeyPurpose::Audit)?;
    let method = unlock_method(source);

    let timestamp = now_unix_nanos()?;
    let metadata = json!({
        "schema_version": 1,
        "action": "UNLOCK",
        "status": "SUCCESS",
        "command": UNLOCK_COMMAND,
        "client_kind": DIRECT_CLI_CLIENT_KIND,
        "method": method,
        "agent_available": false,
        "cached_keys": false,
        "user_verification": user_verification,
        "grant_actions": [],
        "ttl_seconds": 0,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: Some(&profile.id),
        action: "UNLOCK",
        status: "SUCCESS",
        secret_name: None,
        command: Some(UNLOCK_COMMAND),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;

    let verify_status = if user_verification.satisfied { "satisfied" } else { "not requested" };
    writeln!(output, "unlock: metadata-only direct CLI unlock succeeded")?;
    writeln!(output, "project_id: {project_id}")?;
    writeln!(output, "active_profile: {} ({})", profile.name, profile.id)?;
    writeln!(output, "unlock_method: {method}")?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "cached_keys: no")?;
    writeln!(output, "verify_user: {verify_status}")?;
    Ok(())
}
