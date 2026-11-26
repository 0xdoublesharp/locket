//! Lock and unlock command implementations.

use std::io::{self, Write};
use std::str::FromStr;

use locket_core::LocketError;
use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, ProfileRecord, Store};
use serde_json::json;

use crate::commands::agent::request_status_snapshot;
use crate::commands::config::spec::{config_get_value, read_user_config};
use crate::commands::discovery::{SHARED_PROJECT_PREFIX, select_project, trusted_project_configs};
use crate::commands::exec::run::agent_invoke;
use crate::commands::secrets::links::shared_vault_target;
use crate::runtime::error::{
    metadata_invalid_error, profile_not_found_error, project_not_found_error, typed_cli_error,
};
use crate::runtime::user_verification::require_user_verification;
use crate::{
    CliError, MasterKeySource, RuntimeContext, UnlockArgs, default_profile, ensure_project_exists,
    load_project_key_with_source, now_unix_nanos, open_store, resolve_project,
};

const DIRECT_CLI_CLIENT_KIND: &str = "direct-cli";
const LOCK_COMMAND: &str = "lock";
const UNLOCK_COMMAND: &str = "unlock";

const fn unlock_method(source: MasterKeySource) -> &'static str {
    match source {
        MasterKeySource::OsKeyStore => "OsKeychain",
        MasterKeySource::PassphraseFallback => "Passphrase",
    }
}

pub fn lock_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "lock: no agent-held keys to clear")?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "metadata_only: yes")?;

    let Some(resolved) = resolve_project(&context.cwd)? else {
        return Ok(());
    };
    let project_id = resolved.config.project_id.as_str();
    writeln!(output, "project_id: {project_id}")?;

    let mut store = open_store(context)?;
    if store.get_project(project_id)?.is_none() {
        return Ok(());
    }
    let mut profile_id_for_row: Option<String> = None;
    let audit_key =
        match load_project_key_with_source(context, &store, project_id, KeyPurpose::Audit) {
            Ok((key, _)) => {
                if let Ok(profile) = default_profile(&store, &resolved.config) {
                    profile_id_for_row = Some(profile.id);
                }
                key
            }
            Err(_) => {
                // Vault is locked or audit key cannot be unwrapped. The CLI client
                // never holds keys, so the lock action is a no-op and writing audit
                // requires the audit key we just failed to load. Stay metadata-only.
                return Ok(());
            }
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
        profile_id: profile_id_for_row.as_deref(),
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

pub fn unlock_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &UnlockArgs,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    let local = unlock_profile(context, &store, args)?;
    if agent_is_available(context)? {
        let ttl = unlock_ttl(context, args.ttl)?;
        let shared = args
            .shared
            .then(|| shared_vault_target(&store))
            .transpose()?
            .map(|(_, profile)| profile);
        let additional = shared.filter(|shared| {
            local.as_ref().is_none_or(|local| local.project_id != shared.project_id)
        });
        for profile in local.iter().chain(additional.iter()) {
            unlock_agent(context, profile, ttl, args.verify_user)?;
            writeln!(output, "project_id: {}", profile.project_id)?;
            writeln!(output, "active_profile: {} ({})", profile.name, profile.id)?;
            writeln!(output, "agent: unlocked")?;
            writeln!(output, "cached_keys: yes")?;
            writeln!(output, "ttl_seconds: {ttl}")?;
        }
        return Ok(());
    }

    let start_agent = "start the agent with `locket agent start` to unlock the Global Vault";
    let Some(profile) =
        local.filter(|profile| !profile.project_id.starts_with(SHARED_PROJECT_PREFIX))
    else {
        return Err(typed_cli_error(LocketError::AgentUnavailable, start_agent));
    };
    unlock_direct(context, output, &mut store, &profile, args.verify_user)?;
    if args.shared {
        writeln!(output, "shared: {start_agent}")?;
    }
    Ok(())
}

fn unlock_profile(
    context: &RuntimeContext,
    store: &Store,
    args: &UnlockArgs,
) -> Result<Option<ProfileRecord>, CliError> {
    if let Some(selector) = &args.project {
        let project = select_project(store, &context.cwd, selector)?;
        let profile = if project.id.starts_with(SHARED_PROJECT_PREFIX) {
            store
                .get_profile_by_name(&project.id, "default")?
                .ok_or_else(|| profile_not_found_error("Global Vault default profile is missing"))?
        } else if let Some(resolved) = trusted_project_configs(store, &project.id)?.first() {
            default_profile(store, &resolved.config)?
        } else {
            store
                .list_profiles(&project.id)?
                .into_iter()
                .next()
                .ok_or_else(|| profile_not_found_error("project has no profile"))?
        };
        Ok(Some(profile))
    } else if let Some(resolved) = resolve_project(&context.cwd)? {
        ensure_project_exists(store, resolved.config.project_id.as_str())?;
        Ok(Some(default_profile(store, &resolved.config)?))
    } else if args.shared {
        Ok(None)
    } else {
        Err(project_not_found_error())
    }
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
