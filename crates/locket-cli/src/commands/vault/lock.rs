//! Lock and unlock command implementations.

use std::io::Write;

use locket_crypto::KeyPurpose;
use locket_store::AuditWrite;
use serde_json::json;

use crate::runtime::user_verification::require_user_verification;
use crate::{
    CliError, MasterKeySource, RuntimeContext, UnlockArgs, default_profile, ensure_project_exists,
    load_project_key_with_source, now_unix_nanos, open_store, require_project, resolve_project,
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
    let resolved = require_project(context)?;
    let user_verification = if args.verify_user {
        require_user_verification(context, "vault unlock", "unlock vault")?
    } else {
        crate::runtime::user_verification::configured_user_verification(
            context,
            "user_verification_required_for.unlock",
            "vault unlock",
            "unlock vault",
        )?
    };
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let profile = default_profile(&store, &resolved.config)?;
    let (audit_key, source) =
        load_project_key_with_source(context, &store, project_id, KeyPurpose::Audit)?;
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
    writeln!(output, "active_profile: {} ({})", resolved.config.default_profile, profile.id)?;
    writeln!(output, "unlock_method: {method}")?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "cached_keys: no")?;
    writeln!(output, "verify_user: {verify_status}")?;
    Ok(())
}
