//! Passkey command implementations.

use std::io::Write;

use locket_crypto::{
    KeyPurpose, WrappedKeyMaterial, generate_key, unwrap_master_key_with_passkey_prf,
    wrap_master_key_with_passkey_prf,
};
use locket_platform::{PasskeyAssertionContext, PlatformError};
use locket_store::{AuditWrite, PasskeyCredentialRecord, PasskeyPrfWrapRecord, Store};
use serde_json::json;
use zeroize::Zeroizing;

use crate::runtime::key_access::{load_master_key, store_master_key_with_fallback};
use crate::runtime::user_verification::{UserVerificationAudit, require_user_verification};
use crate::{
    CliError, PasskeyCommand, PasskeyListArgs, PasskeyRegisterArgs, ResolvedProject,
    RuntimeContext, confirmation_failed_error, ensure_project_exists, format_hex,
    format_unix_nanos, invalid_reference_error, load_project_key, metadata_invalid_error,
    now_unix_nanos, open_store, require_project, unimplemented_in_build_error,
    user_verification_failed_error, yes_no,
};

pub fn passkey_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: PasskeyCommand,
) -> Result<(), CliError> {
    match command {
        PasskeyCommand::Register(args) => passkey_register_command(context, output, &args),
        PasskeyCommand::List(args) => passkey_list_command(context, output, &args),
        PasskeyCommand::Remove { passkey } => passkey_remove_command(context, output, &passkey),
        PasskeyCommand::Unlock { passkey } => {
            passkey_unlock_command(context, output, passkey.as_deref())
        }
    }
}

#[allow(clippy::redundant_pub_crate, clippy::too_many_lines)]
pub(crate) fn passkey_register_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &PasskeyRegisterArgs,
) -> Result<(), CliError> {
    let label = args.label.trim();
    if label.is_empty() {
        return Err(invalid_reference_error("passkey label cannot be empty"));
    }
    let relying_party_id = args.relying_party_id.trim();
    if relying_party_id.is_empty() {
        return Err(invalid_reference_error("relying_party_id cannot be empty"));
    }
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let local_device = store.get_active_local_device(project_id)?.ok_or_else(|| {
        invalid_reference_error(
            "no active local device for this project. Run `locket device init` to create one, \
             or re-run `locket init` (which now sets one up automatically by default).",
        )
    })?;
    let member_id = match store.get_team_by_project(project_id)? {
        Some(team) => store
            .get_active_team_member_by_device(&team.id, &local_device.id)?
            .map(|member| member.id),
        None => None,
    };
    if !context.passkey_registrar.supports_registration() {
        let error = PlatformError::PasskeyUnsupported;
        write_passkey_register_failure_audit(
            context,
            &mut store,
            &PasskeyRegisterFailureAudit {
                resolved: &resolved,
                label,
                relying_party_id,
                user_verification: UserVerificationAudit::not_required(),
                error: &error,
                timestamp: now_unix_nanos()?,
            },
        )
        .ok();
        return Err(map_platform_passkey_error(&error));
    }
    let user_verification = require_user_verification(
        context,
        "passkey register",
        format!("register passkey {label}"),
    )?;

    match context.passkey_registrar.register_passkey(label, relying_party_id) {
        Ok(registration) => {
            if is_legacy_keyring(&registration.transports) {
                return Err(unimplemented_in_build_error(
                    "software keyring credentials cannot be registered as WebAuthn/FIDO2 passkeys; \
                     existing legacy credentials remain available for recovery",
                ));
            }
            let timestamp = now_unix_nanos()?;
            let passkey_id = generate_passkey_id()?;
            let credential = PasskeyCredentialRecord {
                id: passkey_id,
                project_id: project_id.to_owned(),
                device_id: local_device.id,
                member_id,
                label: label.to_owned(),
                credential_id: registration.credential_id.clone(),
                public_key: registration.public_key.clone(),
                user_handle: registration.user_handle.clone(),
                transports: registration.transports.clone(),
                prf_capable: registration.prf_capable,
                webauthn_relying_party_id: relying_party_id.to_owned(),
                backup_eligible: registration.backup_eligible,
                backup_state: registration.backup_state,
                created_at: timestamp,
                last_used_at: None,
                revoked_at: None,
            };
            // Finish both authenticator ceremonies before recording enrollment.
            // A failed PRF, wrap, or audit must not leave an unusable credential.
            let prf_wrap = if credential.prf_capable {
                Some(prepare_master_key_prf_wrap(context, &credential, timestamp).inspect_err(
                    |_| {
                        // The second PIN/touch ceremony is also an authentication
                        // attempt. Record a safe denial without masking its error.
                        let _audit = write_passkey_register_failure_audit(
                            context,
                            &mut store,
                            &PasskeyRegisterFailureAudit {
                                resolved: &resolved,
                                label,
                                relying_party_id,
                                user_verification,
                                error: &PlatformError::PasskeyAuthFailed,
                                timestamp: now_unix_nanos().unwrap_or(timestamp),
                            },
                        );
                    },
                )?)
            } else {
                None
            };
            let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
            store.with_atomic_write::<_, CliError>(|store| {
                store.insert_passkey_credential(&credential)?;
                if let Some(wrap) = &prf_wrap {
                    store.upsert_passkey_prf_wrap(wrap)?;
                }
                write_passkey_register_audit(
                    audit_key.as_ref(),
                    store,
                    &resolved,
                    &credential,
                    "success",
                    user_verification,
                    timestamp,
                )
            })?;
            let prf_wrapped = prf_wrap.is_some();
            writeln!(output, "passkey: registered")?;
            writeln!(output, "passkey_id: {}", credential.id)?;
            writeln!(output, "label: {}", credential.label)?;
            writeln!(
                output,
                "credential_id_prefix: {}",
                credential_id_prefix(&credential.credential_id)
            )?;
            writeln!(output, "rp_id: {}", credential.webauthn_relying_party_id)?;
            writeln!(output, "transports: {}", render_passkey_transports(&credential.transports))?;
            writeln!(output, "prf_capable: {}", yes_no(credential.prf_capable))?;
            writeln!(
                output,
                "backup_eligible: {}",
                render_optional_bool(credential.backup_eligible)
            )?;
            writeln!(output, "backup_state: {}", render_optional_bool(credential.backup_state))?;
            writeln!(output, "registered_at: {}", format_unix_nanos(timestamp))?;
            writeln!(output, "prf_wrapped: {}", yes_no(prf_wrapped))?;
            writeln!(output, "private_key_material: never displayed")?;
            Ok(())
        }
        Err(error) => {
            let timestamp = now_unix_nanos()?;
            write_passkey_register_failure_audit(
                context,
                &mut store,
                &PasskeyRegisterFailureAudit {
                    resolved: &resolved,
                    label,
                    relying_party_id,
                    user_verification,
                    error: &error,
                    timestamp,
                },
            )
            .ok();
            Err(map_platform_passkey_error(&error))
        }
    }
}

struct PasskeyRegisterFailureAudit<'a> {
    resolved: &'a ResolvedProject,
    label: &'a str,
    relying_party_id: &'a str,
    user_verification: UserVerificationAudit,
    error: &'a PlatformError,
    timestamp: i64,
}

fn map_platform_passkey_error(error: &PlatformError) -> CliError {
    match error {
        PlatformError::PasskeyUnsupported => unimplemented_in_build_error(
            "external FIDO2 passkeys require a macOS or Linux terminal and trusted libfido2 1.17+ \
             tools (fido2-token, fido2-cred, fido2-assert); install libfido2 and run Locket from \
             a terminal. Desktop and Windows ceremonies are not supported. Existing legacy \
             software keyring credentials remain recoverable with `locket passkey unlock`",
        ),
        PlatformError::PasskeyNotFound => invalid_reference_error("passkey credential not found"),
        _ => user_verification_failed_error(
            "passkey ceremony failed; connect exactly one external FIDO2 security key with \
             hmac-secret support and a configured PIN, then retry",
        ),
    }
}

fn generate_passkey_id() -> Result<String, CliError> {
    let bytes = generate_key()?;
    Ok(format!("lk_passkey_{}", format_hex(&bytes[..16])))
}

/// Generates a fresh PRF salt and wraps the project master key under the
/// resulting verified PRF output before committing enrollment.
fn prepare_master_key_prf_wrap(
    context: &RuntimeContext,
    credential: &PasskeyCredentialRecord,
    timestamp: i64,
) -> Result<PasskeyPrfWrapRecord, CliError> {
    let prf_salt: [u8; 32] = locket_crypto::generate_passphrase_salt()?;
    let prf_output = context
        .passkey_registrar
        .evaluate_prf(assertion_context(credential), &prf_salt)
        .map_err(|error| map_platform_passkey_error(&error))?;
    let (master_key, _) = load_master_key(context, &credential.project_id)?;
    let wrapped =
        wrap_master_key_with_passkey_prf(&master_key, &prf_output, &credential.project_id)?;
    Ok(PasskeyPrfWrapRecord {
        passkey_id: credential.id.clone(),
        project_id: credential.project_id.clone(),
        prf_salt: prf_salt.to_vec(),
        wrapped_master_key: wrapped.ciphertext,
        wrap_nonce: wrapped.nonce.to_vec(),
        created_at: timestamp,
    })
}

fn assertion_context(credential: &PasskeyCredentialRecord) -> PasskeyAssertionContext<'_> {
    PasskeyAssertionContext {
        credential_id: &credential.credential_id,
        relying_party_id: &credential.webauthn_relying_party_id,
        public_key: &credential.public_key,
    }
}

pub fn passkey_unlock_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    selector: Option<&str>,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let credential = resolve_unlock_candidate(&store, project_id, selector)?;
    let wrap = store
        .get_passkey_prf_wrap(project_id, &credential.id)?
        .ok_or_else(|| invalid_reference_error("passkey is not configured for PRF-based unlock"))?;
    let timestamp = now_unix_nanos()?;
    if let Err(error) = require_user_verification(
        context,
        "passkey unlock",
        format!("recover vault access using {}", credential.label),
    ) {
        write_passkey_auth_audit(context, &mut store, &resolved, &credential, "failed", timestamp)
            .ok();
        return Err(error);
    }
    let master_key =
        recover_master_key_via_prf(context, &mut store, &resolved, &credential, &wrap, timestamp)?;
    let source = store_master_key_with_fallback(context, project_id, &master_key, timestamp)?;
    write_passkey_auth_audit(context, &mut store, &resolved, &credential, "success", timestamp)?;
    if is_legacy_keyring(&credential.transports) {
        writeln!(output, "passkey: legacy software keyring recovery")?;
    } else {
        writeln!(output, "passkey: unlocked")?;
    }
    writeln!(output, "passkey_id: {}", credential.id)?;
    writeln!(output, "credential_id_prefix: {}", credential_id_prefix(&credential.credential_id))?;
    writeln!(output, "rp_id: {}", credential.webauthn_relying_party_id)?;
    writeln!(output, "master_key_source: {}", source.as_str())?;
    writeln!(output, "private_key_material: never displayed")?;
    Ok(())
}

fn resolve_unlock_candidate(
    store: &Store,
    project_id: &str,
    selector: Option<&str>,
) -> Result<PasskeyCredentialRecord, CliError> {
    let candidates = match selector {
        Some(selector) => {
            let trimmed = selector.trim();
            if trimmed.is_empty() {
                return Err(invalid_reference_error("passkey identifier cannot be empty"));
            }
            store
                .find_passkey_credentials(project_id, trimmed)?
                .into_iter()
                .filter(|credential| credential.revoked_at.is_none())
                .collect::<Vec<_>>()
        }
        None => store
            .list_passkey_credentials(project_id, false)?
            .into_iter()
            .filter(|credential| credential.prf_capable)
            .collect::<Vec<_>>(),
    };
    match candidates.as_slice() {
        [] => Err(invalid_reference_error(
            "passkey not found or no PRF-capable credentials registered for this project",
        )),
        [credential] => Ok(credential.clone()),
        _ => Err(metadata_invalid_error(
            "passkey identifier is ambiguous; use a longer credential id prefix",
        )),
    }
}

fn recover_master_key_via_prf(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    credential: &PasskeyCredentialRecord,
    wrap: &PasskeyPrfWrapRecord,
    timestamp: i64,
) -> Result<Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let result = if is_legacy_keyring(&credential.transports) {
        context
            .passkey_registrar
            .recover_legacy_keyring_prf(&credential.credential_id, &wrap.prf_salt)
    } else {
        context.passkey_registrar.evaluate_prf(assertion_context(credential), &wrap.prf_salt)
    };
    let prf_output = match result {
        Ok(output) => output,
        Err(error) => {
            write_passkey_auth_audit(context, store, resolved, credential, "failed", timestamp)
                .ok();
            return Err(map_platform_passkey_error(&error));
        }
    };
    let wrap_nonce: [u8; locket_crypto::NONCE_LEN] =
        wrap.wrap_nonce.as_slice().try_into().map_err(|_| {
            metadata_invalid_error("stored passkey PRF wrap nonce has invalid length")
        })?;
    let wrapped_material =
        WrappedKeyMaterial { ciphertext: wrap.wrapped_master_key.clone(), nonce: wrap_nonce };
    match unwrap_master_key_with_passkey_prf(
        &wrapped_material,
        &prf_output,
        resolved.config.project_id.as_str(),
    ) {
        Ok(key) => Ok(key),
        Err(error) => {
            write_passkey_auth_audit(context, store, resolved, credential, "failed", timestamp)
                .ok();
            Err(error.into())
        }
    }
}

fn passkey_list_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &PasskeyListArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let credentials = store.list_passkey_credentials(project_id, args.all)?;
    if credentials.is_empty() {
        writeln!(output, "credentials: none")?;
    } else {
        writeln!(output, "credentials:")?;
        for credential in credentials {
            writeln!(
                output,
                "- {} id={} credential_id_prefix={} kind={} rp_id={} transports={} prf={} backup_eligible={} backup_state={} created_at={} last_used_at={} revoked_at={}",
                credential.label,
                credential.id,
                credential_id_prefix(&credential.credential_id),
                credential_kind(&credential.transports),
                credential.webauthn_relying_party_id,
                render_passkey_transports(&credential.transports),
                displayed_prf_capability(&credential),
                render_optional_bool(credential.backup_eligible),
                render_optional_bool(credential.backup_state),
                format_unix_nanos(credential.created_at),
                credential.last_used_at.map_or_else(|| "never".to_owned(), format_unix_nanos),
                credential.revoked_at.map_or_else(|| "active".to_owned(), format_unix_nanos),
            )?;
        }
    }
    writeln!(output, "include_revoked: {}", if args.all { "yes" } else { "no" })?;
    writeln!(output, "private_key_material: never displayed")?;
    Ok(())
}

fn is_legacy_keyring(transports: &[String]) -> bool {
    transports.iter().any(|transport| transport == "platform-keyring")
}

fn credential_kind(transports: &[String]) -> &'static str {
    if is_legacy_keyring(transports) { "legacy-software-keyring" } else { "webauthn" }
}

fn displayed_prf_capability(credential: &PasskeyCredentialRecord) -> &'static str {
    if is_legacy_keyring(&credential.transports) {
        "legacy-keyring-derivation"
    } else {
        yes_no(credential.prf_capable)
    }
}

fn passkey_remove_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    passkey: &str,
) -> Result<(), CliError> {
    let selector = passkey.trim();
    if selector.is_empty() {
        return Err(invalid_reference_error("passkey identifier cannot be empty"));
    }
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let matches = store.find_passkey_credentials(project_id, selector)?;
    let active_matches = matches
        .into_iter()
        .filter(|credential| credential.revoked_at.is_none())
        .collect::<Vec<_>>();
    let credential = match active_matches.as_slice() {
        [] => return Err(invalid_reference_error("passkey credential not found")),
        [credential] => credential.clone(),
        _ => {
            return Err(metadata_invalid_error(
                "passkey identifier is ambiguous; use a longer credential id prefix",
            ));
        }
    };
    let user_verification = require_user_verification(
        context,
        "passkey remove",
        format!("remove passkey {}", credential.label),
    )?;
    writeln!(output, "passkey: revoke")?;
    writeln!(output, "label: {}", credential.label)?;
    writeln!(output, "credential_id_prefix: {}", credential_id_prefix(&credential.credential_id))?;
    writeln!(output, "rp_id: {}", credential.webauthn_relying_party_id)?;
    writeln!(output, "transports: {}", render_passkey_transports(&credential.transports))?;
    writeln!(output, "credential_kind: {}", credential_kind(&credential.transports))?;
    writeln!(output, "prf: {}", displayed_prf_capability(&credential))?;
    let confirmation = context.confirmation_reader.read_confirmation("passkey remove")?;
    if confirmation.trim_end() != selector {
        return Err(confirmation_failed_error("confirmation did not match passkey identifier"));
    }
    let timestamp = now_unix_nanos()?;
    store.revoke_passkey_credential(project_id, &credential.id, timestamp)?;
    write_passkey_remove_audit_if_available(
        context,
        &mut store,
        &resolved,
        &credential,
        user_verification,
        timestamp,
    )?;
    writeln!(output, "passkey: revoked")?;
    writeln!(output, "passkey_id: {}", credential.id)?;
    writeln!(output, "revoked_at: {}", format_unix_nanos(timestamp))?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn credential_id_prefix(credential_id: &[u8]) -> String {
    format_hex(credential_id).chars().take(12).collect()
}

fn render_passkey_transports(transports: &[String]) -> String {
    if transports.is_empty() { "-".to_owned() } else { transports.join(",") }
}

fn render_optional_bool(value: Option<bool>) -> &'static str {
    value.map_or("unknown", yes_no)
}

fn write_passkey_register_audit(
    audit_key: &[u8],
    store: &mut Store,
    resolved: &ResolvedProject,
    credential: &PasskeyCredentialRecord,
    auth_result: &str,
    user_verification: UserVerificationAudit,
    timestamp: i64,
) -> Result<(), CliError> {
    let metadata = json!({
        "schema_version": 1,
        "action": "PASSKEY_REGISTER",
        "status": "SUCCESS",
        "command": "passkey register",
        "passkey_id": credential.id,
        "label": credential.label,
        "credential_id_prefix": credential_id_prefix(&credential.credential_id),
        "auth_result": auth_result,
        "webauthn_relying_party_id": credential.webauthn_relying_party_id,
        "transports": credential.transports,
        "prf_capable": credential.prf_capable,
        "credential_kind": credential_kind(&credential.transports),
        "backup_eligible": credential.backup_eligible,
        "backup_state": credential.backup_state,
        "user_verification": user_verification,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "PASSKEY_REGISTER",
        status: "SUCCESS",
        secret_name: None,
        command: Some("passkey register"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key, &audit)?;
    Ok(())
}

fn write_passkey_register_failure_audit(
    context: &RuntimeContext,
    store: &mut Store,
    request: &PasskeyRegisterFailureAudit<'_>,
) -> Result<(), CliError> {
    let audit_key = load_project_key(
        context,
        store,
        request.resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let auth_result = match request.error {
        PlatformError::PasskeyUnsupported => "unsupported",
        _ => "denied",
    };
    let metadata = json!({
        "schema_version": 1,
        "action": "PASSKEY_REGISTER",
        "status": "DENIED",
        "command": "passkey register",
        "passkey_id": serde_json::Value::Null,
        "label": request.label,
        "credential_id_prefix": serde_json::Value::Null,
        "auth_result": auth_result,
        "webauthn_relying_party_id": request.relying_party_id,
        "user_verification": request.user_verification,
        "failure_reason": request.error.to_string(),
    });
    let audit = AuditWrite {
        project_id: request.resolved.config.project_id.as_str(),
        profile_id: None,
        action: "PASSKEY_REGISTER",
        status: "DENIED",
        secret_name: None,
        command: Some("passkey register"),
        metadata_json: &metadata,
        timestamp: request.timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn write_passkey_auth_audit(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    credential: &PasskeyCredentialRecord,
    auth_result: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let audit_key =
        load_project_key(context, store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let status = if auth_result == "success" { "SUCCESS" } else { "DENIED" };
    let metadata = json!({
        "schema_version": 1,
        "action": "PASSKEY_AUTH",
        "status": status,
        "command": "passkey unlock",
        "passkey_id": credential.id,
        "label": credential.label,
        "credential_id_prefix": credential_id_prefix(&credential.credential_id),
        "auth_result": auth_result,
        "webauthn_relying_party_id": credential.webauthn_relying_party_id,
        "prf_capable": credential.prf_capable,
        "credential_kind": credential_kind(&credential.transports),
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "PASSKEY_AUTH",
        status,
        secret_name: None,
        command: Some("passkey unlock"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn write_passkey_remove_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    credential: &PasskeyCredentialRecord,
    user_verification: UserVerificationAudit,
    timestamp: i64,
) -> Result<(), CliError> {
    let audit_key =
        load_project_key(context, store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "PASSKEY_REMOVE",
        "status": "SUCCESS",
        "command": "passkey remove",
        "passkey_id": credential.id,
        "label": credential.label,
        "credential_id_prefix": credential_id_prefix(&credential.credential_id),
        "webauthn_relying_party_id": credential.webauthn_relying_party_id,
        "transports": credential.transports,
        "prf_capable": credential.prf_capable,
        "credential_kind": credential_kind(&credential.transports),
        "backup_eligible": credential.backup_eligible,
        "backup_state": credential.backup_state,
        "user_verification": user_verification,
        "auth_result": "removed",
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "PASSKEY_REMOVE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("passkey remove"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
