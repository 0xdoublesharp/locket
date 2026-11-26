use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::SigningKey;
use locket_core::{
    CommandPolicy, CommandSpec, Duration as LocketDuration, InviteId, InvitePayload, KeyId,
    LocketError, MemberId, ProjectId, SealedInvitePayloadV1, SealedInvitePlaintextCounts,
    SignedInvite, TeamId, TeamRole, decrypt_bundle_payload_with_x25519_secret,
    device_fingerprint_v1, encrypt_bundle_payload_for_age_recipients, fingerprint_hex,
};
use locket_crypto::{AAD_SCHEMA_V1, KeyPurpose, generate_key};
use locket_platform::LocalDevicePrivateKeyStorage;
use locket_store::{
    AuditContext, AuditWrite, DeviceRecord, PendingTeamInviteRecord, StoredTeamInviteRecord,
    TeamInviteRecord, TeamMemberListRecord, TeamRecord,
};
use serde_json::json;

use super::device;
use crate::runtime::key_access::{load_master_key, load_profile_key, rewrap_imported_profile_key};
use crate::runtime::user_verification::{UserVerificationAudit, configured_user_verification};
use crate::support::time::NANOS_PER_SECOND;
use crate::{
    CliError, LOCKET_TOML, ResolvedProject, RuntimeContext, TeamAcceptArgs, TeamCommand,
    TeamInitArgs, TeamInviteArgs, TeamRemoveArgs, TeamRevokeDeviceArgs, TeamRevokeInviteArgs,
    TeamRoleArg, command_type, confirmation_failed_error, ensure_project_exists,
    ensure_trusted_project_root, external_env_source_label, invalid_reference_error,
    load_project_key, metadata_invalid_error, now_unix_nanos, open_store, privacy_alias,
    privacy_redact_names_enabled, profile_not_found_error, read_policy_document, require_project,
    secret_already_exists_error, secret_not_found_error, set_user_only_file_options,
    set_user_only_file_permissions, team_role_denied_error, unix_nanos_to_rfc3339,
};

const DEFAULT_INVITE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MIN_INVITE_TTL_SECONDS: u64 = 5 * 60;
const MAX_INVITE_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct InviteSealedPlaintextV1 {
    v: u8,
    profiles: Vec<InviteSealedProfileV1>,
    profile_keys: Vec<InviteSealedProfileKeyV1>,
    command_policies: Vec<InviteSealedCommandPolicyV1>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct InviteSealedProfileV1 {
    profile_id: String,
    name: String,
    dangerous: bool,
    created_at: i64,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct InviteSealedProfileKeyV1 {
    profile_name: String,
    purpose: String,
    key_material_b64: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct InviteSealedCommandPolicyV1 {
    name: String,
    command_kind: String,
    argv: Vec<String>,
    shell: Option<String>,
    allowed_secrets: Vec<String>,
    required_secrets: Vec<String>,
    optional_secrets: Vec<String>,
    inherit_env: Vec<String>,
    env_mode: String,
    override_mode: String,
    override_explicit: bool,
    external_env_sources: Vec<String>,
    allow_remote_docker: bool,
    confirm: bool,
    require_user_verification: bool,
    ttl_seconds: u64,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Default)]
struct InviteApplyCounts {
    profile_count: usize,
    profile_key_count: usize,
    command_policy_count: usize,
}

pub fn team_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: TeamCommand,
) -> Result<(), CliError> {
    match command {
        TeamCommand::Join(args) => super::sync::join(context, output, &args),
        TeamCommand::Add(args) => super::sync::add(context, output, &args),
        TeamCommand::Publish => super::sync::publish(context, output),
        TeamCommand::Sync { command } => super::sync::sync(context, output, command),
        TeamCommand::Folder(args) => super::sync::folder(context, output, &args),
        TeamCommand::Remote { command } => super::remote::run(context, output, command),
        TeamCommand::Init(args) => team_init_command(context, output, &args),
        TeamCommand::Invite(args) => team_invite_command(context, output, &args),
        TeamCommand::RevokeInvite(args) => team_revoke_invite_command(context, output, &args),
        TeamCommand::Accept(args) => team_accept_command(context, output, &args),
        TeamCommand::Members => team_members_command(context, output),
        TeamCommand::Remove(args) => team_remove_command(context, output, &args),
        TeamCommand::RevokeDevice(args) => team_revoke_device_command(context, output, &args),
    }
}

fn team_init_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamInitArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    ensure_trusted_project_root(&store, &resolved)?;

    if let Some(existing) = store.get_team_by_project(project_id)? {
        return Err(secret_already_exists_error(format!(
            "team already initialized: {} ({})",
            existing.name, existing.id
        )));
    }

    let team_id = TeamId::generate().map_err(|_| CliError::Time)?;
    let timestamp = now_unix_nanos()?;
    let record = TeamRecord {
        id: team_id.into_string(),
        project_id: project_id.to_owned(),
        name: args.name.clone(),
        created_at: timestamp,
        updated_at: timestamp,
    };
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "TEAM_INIT",
        "status": "SUCCESS",
        "command": "team init",
        "project_id": project_id,
        "team_id": record.id,
        "team_name": record.name,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "TEAM_INIT",
        status: "SUCCESS",
        secret_name: None,
        command: Some("team init"),
        metadata_json: &metadata,
        timestamp,
    };
    store.with_atomic_write(|store| {
        store.insert_team(&record)?;
        if let Some(local_device) = store.get_active_local_device(project_id)? {
            let member_id = MemberId::generate().map_err(|_| CliError::Time)?.into_string();
            store.insert_team_member(
                &member_id,
                &record.id,
                Some(&local_device.id),
                &local_device.name,
                "owner",
                timestamp,
            )?;
        }
        store.append_audit(audit_key.as_ref(), &audit).map_err(CliError::from)
    })?;

    writeln!(output, "team initialized: {} ({})", record.name, record.id)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn team_invite_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamInviteArgs,
) -> Result<(), CliError> {
    validate_invitee_name(&args.name)?;
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;

    let issuer = load_invite_issuer(&store, project_id)?;
    let invite_role = role_from_arg(args.role);
    let role_label = role_label(args.role);
    if !can_issue_role(&issuer.member.role, args.role) {
        let InviteIssuer { team, member, .. } = issuer;
        append_team_role_denial(
            context,
            &mut store,
            project_id,
            "TEAM_INVITE",
            "team invite",
            &team.id,
            &member.id,
            "role_insufficient",
        )?;
        return Err(team_role_denied_error("team role cannot issue this invite"));
    }

    let recipient = decode_recipient_device(&args.device)?;
    if store.bundle_recipient_is_denied(project_id, &recipient.sealing_public_key)? {
        return Err(team_role_denied_error(
            "recipient device is revoked or its member was removed",
        ));
    }
    if recipient.fingerprint == issuer.local_device.fingerprint {
        return Err(metadata_invalid_error("recipient device must differ from issuer device"));
    }
    let profiles = validate_invite_profiles(&store, project_id, &args.profiles)?;
    confirm_dangerous_profiles(context, output, &store, project_id, &profiles)?;

    let created_at = now_unix_nanos()?;
    let ttl_seconds = invite_ttl_seconds(args.expires_in.as_deref())?;
    let expires_at = created_at
        .checked_add(
            i64::try_from(ttl_seconds)
                .ok()
                .and_then(|seconds| seconds.checked_mul(NANOS_PER_SECOND))
                .ok_or(CliError::Time)?,
        )
        .ok_or(CliError::Time)?;
    let sealed_payload = build_invite_sealed_payload(
        context,
        &store,
        &resolved,
        &profiles,
        &recipient.sealing_public_key,
    )?;
    let signing_key = device::load_device_signing_key(context, &issuer.local_device)?;
    let built_invite = build_signed_invite(
        &signing_key,
        project_id,
        &issuer,
        &recipient,
        &profiles,
        invite_role,
        role_label,
        expires_at,
        sealed_payload,
    )?;
    let output_path =
        args.output.clone().unwrap_or_else(|| default_invite_output_path(context, created_at));
    ensure_invite_output_available(&output_path)?;

    let invite_record = persist_invite(
        context,
        &mut store,
        project_id,
        &issuer,
        &built_invite,
        &output_path,
        created_at,
    )?;

    let redact_names = privacy_redact_names_enabled(context, false)?;
    write_invite_created_output(
        output,
        &invite_record,
        &built_invite.issuer_fingerprint,
        &output_path,
        redact_names,
    )
}

fn team_revoke_invite_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamRevokeInviteArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;

    let issuer = load_invite_issuer(&store, project_id)?;
    let invite = store.get_team_invite(&issuer.team.id, &args.invite_id)?.ok_or_else(|| {
        secret_not_found_error(format!("team invite not found: {}", args.invite_id))
    })?;
    if invite.accepted_at.is_some() || invite.revoked_at.is_some() {
        return Err(locket_store::StoreError::InviteReplayDetected {
            invite_id: invite.id.clone(),
        }
        .into());
    }
    if !can_revoke_invite(&issuer.member.role, &issuer.member.id, &invite) {
        let InviteIssuer { team, member, .. } = issuer;
        append_team_role_denial(
            context,
            &mut store,
            project_id,
            "TEAM_INVITE",
            "team revoke-invite",
            &team.id,
            &member.id,
            "role_insufficient",
        )?;
        return Err(team_role_denied_error("team role cannot revoke this invite"));
    }

    let timestamp = now_unix_nanos()?;
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "TEAM_INVITE",
        "status": "SUCCESS",
        "command": "team revoke-invite",
        "operation": "revoke",
        "project_id": project_id,
        "team_id": &issuer.team.id,
        "member_id": &invite.issuer_member_id,
        "invite_id": &invite.id,
        "issuer_member_id": &invite.issuer_member_id,
        "revoker_member_id": &issuer.member.id,
        "recipient_device_fingerprint": &invite.recipient_device_fingerprint,
        "role": &invite.role,
        "profiles": &invite.profiles,
        "created_at": invite.created_at,
        "expires_at": invite.expires_at,
        "revoked_at": timestamp,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "TEAM_INVITE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("team revoke-invite"),
        metadata_json: &metadata,
        timestamp,
    };
    store.revoke_team_invite(
        &args.invite_id,
        timestamp,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;

    let redact_names = privacy_redact_names_enabled(context, false)?;
    writeln!(output, "team_invite: revoked")?;
    writeln!(output, "invite_id: {}", invite_id_label_from_str(&args.invite_id, redact_names))?;
    writeln!(output, "role: {}", invite.role)?;
    writeln!(output, "profiles: {}", profiles_label(&invite.profiles, redact_names))?;
    writeln!(
        output,
        "recipient_fingerprint: {}",
        device_fingerprint_label(&invite.recipient_device_fingerprint, redact_names)
    )?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn team_accept_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamAcceptArgs,
) -> Result<(), CliError> {
    let invite = read_signed_invite(&args.invite)?;
    let TeamAcceptPreflight { mut store, project_id, local_device } =
        preflight_team_accept(context, &invite)?;

    write_accept_summary(output, &invite)?;
    confirm_team_accept(context, &mut store, &project_id, &invite)?;
    let user_verification = match configured_user_verification(
        context,
        "user_verification_required_for.team_accept",
        "team accept",
        "accept team invite",
    ) {
        Ok(audit) => audit,
        Err(error) => {
            append_team_accept_denial_with_user_verification(
                context,
                &mut store,
                &project_id,
                &invite,
                "user_verification_failed",
                LocketError::UserVerificationFailed,
                Some(UserVerificationAudit::failed_required()),
            )?;
            return Err(error);
        }
    };
    let applied = store.with_atomic_write(|store| {
        let applied =
            apply_invite_sealed_payload(context, store, &project_id, &local_device, &invite)?;
        accept_invite_with_audit(
            context,
            store,
            &project_id,
            &local_device,
            &invite,
            user_verification,
            applied,
        )?;
        Ok::<_, CliError>(applied)
    })?;

    writeln!(output, "team_accept: accepted")?;
    writeln!(output, "sealed_payload: applied")?;
    writeln!(output, "applied_profiles: {}", applied.profile_count)?;
    writeln!(output, "applied_profile_keys: {}", applied.profile_key_count)?;
    writeln!(output, "applied_command_policies: {}", applied.command_policy_count)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn read_signed_invite(path: &Path) -> Result<SignedInvite, CliError> {
    read_signed_invite_from_reader(path, io::stdin())
}

fn read_signed_invite_from_reader(
    path: &Path,
    mut stdin: impl Read,
) -> Result<SignedInvite, CliError> {
    let invite_text = if path == Path::new("-") {
        let mut text = String::new();
        stdin.read_to_string(&mut text)?;
        text
    } else {
        fs::read_to_string(path)?
    };
    SignedInvite::decode(invite_text.trim())
        .map_err(|error| invite_signature_invalid_error(format!("invite decode failed: {error}")))
}

#[cfg(test)]
pub fn read_signed_invite_for_tests(
    path: &Path,
    stdin: impl Read,
) -> Result<SignedInvite, CliError> {
    read_signed_invite_from_reader(path, stdin)
}

struct TeamAcceptPreflight {
    store: locket_store::Store,
    project_id: String,
    local_device: DeviceRecord,
}

fn preflight_team_accept(
    context: &RuntimeContext,
    invite: &SignedInvite,
) -> Result<TeamAcceptPreflight, CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str().to_owned();
    let project_id_str = project_id.as_str();

    ensure_project_exists(&store, project_id_str)?;
    if invite.payload.project_id.as_str() != project_id_str {
        return Err(metadata_invalid_error("invite project does not match current project"));
    }

    validate_invite_signature_and_expiry(context, &mut store, project_id_str, invite)?;
    validate_invite_fingerprint_claims_with_denial(context, &mut store, project_id_str, invite)?;
    let local_device = validate_invite_recipient(context, &mut store, project_id_str, invite)?;
    ensure_invite_pending_with_denial(context, &mut store, project_id_str, invite)?;

    Ok(TeamAcceptPreflight { store, project_id, local_device })
}

fn validate_invite_signature_and_expiry(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    invite: &SignedInvite,
) -> Result<(), CliError> {
    if let Err(error) = invite.verify() {
        let cli_error =
            invite_signature_invalid_error(format!("invite verification failed: {error}"));
        append_team_accept_denial(
            context,
            store,
            project_id,
            invite,
            "signature_invalid",
            LocketError::InviteSignatureInvalid,
        )?;
        return Err(cli_error);
    }

    let now = now_unix_nanos()?;
    if let Err(error) = invite.check_expiry(now / NANOS_PER_SECOND) {
        let cli_error = invite_expired_error(error.to_string());
        append_team_accept_denial(
            context,
            store,
            project_id,
            invite,
            "invite_expired",
            LocketError::InviteExpired,
        )?;
        return Err(cli_error);
    }
    Ok(())
}

fn validate_invite_fingerprint_claims_with_denial(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    invite: &SignedInvite,
) -> Result<(), CliError> {
    if let Err(error) = validate_invite_fingerprint_claims(invite) {
        append_team_accept_denial(
            context,
            store,
            project_id,
            invite,
            "fingerprint_mismatch",
            LocketError::DeviceDescriptorInvalid,
        )?;
        return Err(error);
    }
    Ok(())
}

fn validate_invite_recipient(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    invite: &SignedInvite,
) -> Result<DeviceRecord, CliError> {
    let local_device = store
        .get_active_local_device(project_id)?
        .ok_or_else(|| invalid_reference_error("local device is not initialized"))?;
    if local_device.fingerprint != invite.payload.recipient_device_fingerprint {
        let cli_error = invite_fingerprint_invalid_error(
            "invite recipient fingerprint does not match local device",
        );
        append_team_accept_denial(
            context,
            store,
            project_id,
            invite,
            "fingerprint_mismatch",
            LocketError::DeviceDescriptorInvalid,
        )?;
        return Err(cli_error);
    }

    let recipient_sealing_key =
        decode_invite_key(&invite.payload.recipient_sealing_public_key, "recipient sealing key")?;
    if local_device.sealing_public_key.as_slice() != recipient_sealing_key.as_slice() {
        let cli_error = invite_fingerprint_invalid_error(
            "invite recipient sealing key does not match local device",
        );
        append_team_accept_denial(
            context,
            store,
            project_id,
            invite,
            "fingerprint_mismatch",
            LocketError::DeviceDescriptorInvalid,
        )?;
        return Err(cli_error);
    }
    Ok(local_device)
}

fn ensure_invite_pending_with_denial(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    invite: &SignedInvite,
) -> Result<(), CliError> {
    if let Err(error) = ensure_invite_pending(store, project_id, invite) {
        append_team_accept_denial(
            context,
            store,
            project_id,
            invite,
            "replay_detected",
            LocketError::ReplayDetected,
        )?;
        return Err(error);
    }
    Ok(())
}

fn confirm_team_accept(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    invite: &SignedInvite,
) -> Result<(), CliError> {
    let confirmation = context.confirmation_reader.read_confirmation("team accept")?;
    if confirmation.trim_end_matches(['\r', '\n']) != invite.payload.issuer_device_fingerprint {
        append_team_accept_denial(
            context,
            store,
            project_id,
            invite,
            "confirmation_mismatch",
            LocketError::ConfirmationFailed,
        )?;
        return Err(confirmation_failed_error("confirmation did not match issuer fingerprint"));
    }
    Ok(())
}

fn apply_invite_sealed_payload(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    local_device: &DeviceRecord,
    invite: &SignedInvite,
) -> Result<InviteApplyCounts, CliError> {
    let sealed = &invite.payload.sealed_payload;
    validate_invite_sealed_payload(sealed, invite)?;
    let storage = device::build_device_private_key_storage(context, project_id)?;
    let private_key = storage.load(&local_device.id)?;
    let ciphertext = BASE64URL_NOPAD
        .decode(sealed.ciphertext_b64.as_bytes())
        .map_err(|_| metadata_invalid_error("invite sealed payload is not valid base64url"))?;
    let plaintext =
        decrypt_bundle_payload_with_x25519_secret(&ciphertext, &private_key).map_err(|error| {
            metadata_invalid_error(format!("invite sealed payload decrypt failed: {error}"))
        })?;
    let payload: InviteSealedPlaintextV1 = serde_json::from_slice(&plaintext).map_err(|error| {
        metadata_invalid_error(format!("invite sealed payload parse failed: {error}"))
    })?;
    apply_invite_plaintext_payload(context, store, project_id, &payload)
}

fn validate_invite_sealed_payload(
    sealed: &SealedInvitePayloadV1,
    invite: &SignedInvite,
) -> Result<(), CliError> {
    if sealed.v != 1 {
        return Err(metadata_invalid_error("invite sealed payload schema is unsupported"));
    }
    if sealed.aad_schema_version != AAD_SCHEMA_V1 {
        return Err(metadata_invalid_error("invite sealed payload AAD schema is unsupported"));
    }
    if sealed.recipient_sealing_public_key_b64 != invite.payload.recipient_sealing_public_key {
        return Err(metadata_invalid_error(
            "invite sealed payload recipient key does not match invite recipient",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::needless_pass_by_ref_mut)]
fn apply_invite_plaintext_payload(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    payload: &InviteSealedPlaintextV1,
) -> Result<InviteApplyCounts, CliError> {
    store.with_atomic_write(|store| {
        apply_invite_plaintext_payload_inner(context, store, project_id, payload)
    })
}

fn apply_invite_plaintext_payload_inner(
    context: &RuntimeContext,
    store: &locket_store::Store,
    project_id: &str,
    payload: &InviteSealedPlaintextV1,
) -> Result<InviteApplyCounts, CliError> {
    if payload.v != 1 {
        return Err(metadata_invalid_error("invite sealed plaintext schema is unsupported"));
    }
    let (master_key, _source) = load_master_key(context, project_id)?;
    let now = now_unix_nanos()?;
    let mut counts = InviteApplyCounts::default();

    for profile in &payload.profiles {
        if store.get_profile_by_name(project_id, &profile.name)?.is_none() {
            store
                .connection()
                .execute(
                    "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        profile.profile_id,
                        project_id,
                        profile.name,
                        profile.dangerous,
                        profile.created_at,
                    ],
                )
                .map_err(locket_store::StoreError::from)?;
            counts.profile_count = counts.profile_count.saturating_add(1);
        }
    }

    for profile_key in &payload.profile_keys {
        let Some(profile) = store.get_profile_by_name(project_id, &profile_key.profile_name)?
        else {
            return Err(metadata_invalid_error(format!(
                "invite sealed payload profile missing: {}",
                profile_key.profile_name
            )));
        };
        let purpose = parse_invite_key_purpose(&profile_key.purpose)?;
        let plaintext_bytes =
            BASE64URL_NOPAD.decode(profile_key.key_material_b64.as_bytes()).map_err(|_| {
                metadata_invalid_error("invite profile key material is not valid base64url")
            })?;
        if plaintext_bytes.len() != locket_crypto::KEY_LEN {
            return Err(metadata_invalid_error("invite profile key material has wrong length"));
        }
        let mut plaintext_array = [0_u8; locket_crypto::KEY_LEN];
        plaintext_array.copy_from_slice(&plaintext_bytes);
        let existing_key =
            store.get_key_by_scope(project_id, Some(&profile.id), purpose.as_str())?;
        if existing_key.is_some() {
            let local = load_profile_key(context, store, project_id, &profile.id, purpose)?;
            if local.as_slice() != plaintext_array.as_slice() {
                return Err(metadata_invalid_error(
                    "invite profile key conflicts with local keys; use a separate store to preserve existing secrets",
                ));
            }
            continue;
        }
        let receiver_key_id = existing_key.as_ref().map_or_else(
            || KeyId::generate().map(KeyId::into_string).map_err(|_| CliError::Time),
            |record| Ok(record.id.clone()),
        )?;
        let wrapped = rewrap_imported_profile_key(
            &master_key,
            project_id,
            &profile.id,
            &receiver_key_id,
            purpose,
            &plaintext_array,
        )?;
        if existing_key.is_some() {
            store.connection().execute(
                "UPDATE keys
                 SET wrapped_material = ?2, nonce = ?3, created_at = ?4
                 WHERE id = ?1",
                rusqlite::params![receiver_key_id, wrapped.ciphertext, wrapped.nonce, now],
            )
        } else {
            store.connection().execute(
                "INSERT INTO keys(id, project_id, profile_id, purpose, wrapped_material, nonce, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    receiver_key_id,
                    project_id,
                    profile.id,
                    purpose.as_str(),
                    wrapped.ciphertext,
                    wrapped.nonce,
                    now,
                ],
            )
        }
        .map_err(locket_store::StoreError::from)?;
        counts.profile_key_count = counts.profile_key_count.saturating_add(1);
    }

    // Invited command definitions are proposals. Only local locket.toml approval grants authority.

    Ok(counts)
}

fn parse_invite_key_purpose(value: &str) -> Result<KeyPurpose, CliError> {
    match value {
        v if v == KeyPurpose::ProfileSecret.as_str() => Ok(KeyPurpose::ProfileSecret),
        v if v == KeyPurpose::ProfileFingerprint.as_str() => Ok(KeyPurpose::ProfileFingerprint),
        other => {
            Err(metadata_invalid_error(format!("unknown invite profile key purpose: {other}")))
        }
    }
}

fn accept_invite_with_audit(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    local_device: &DeviceRecord,
    invite: &SignedInvite,
    user_verification: UserVerificationAudit,
    applied: InviteApplyCounts,
) -> Result<(), CliError> {
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    let accepted_at = now_unix_nanos()?;
    let invite_id = invite.payload.invite_id.as_str();
    let team_id =
        store.get_team_by_project(project_id)?.map_or_else(|| "unknown".to_owned(), |team| team.id);
    let mut metadata = json!({
        "schema_version": 1,
        "action": "TEAM_ACCEPT",
        "status": "SUCCESS",
        "command": "team accept",
        "project_id": project_id,
        "team_id": team_id,
        "member_id": invite.payload.issuer_member_id.as_str(),
        "invite_id": invite_id,
        "issuer_member_id": invite.payload.issuer_member_id.as_str(),
        "issuer_device_fingerprint": &invite.payload.issuer_device_fingerprint,
        "recipient_device_id": &local_device.id,
        "recipient_device_fingerprint": &local_device.fingerprint,
        "role": role_label_from_payload(invite.payload.role),
        "profiles": &invite.payload.profiles,
        "expires_at": invite.payload.expires_at,
        "accepted_at": accepted_at,
        "user_verification": user_verification,
    });
    metadata["sealed_payload_applied"] = json!(true);
    metadata["applied_profile_count"] = json!(applied.profile_count);
    metadata["applied_profile_key_count"] = json!(applied.profile_key_count);
    metadata["applied_command_policy_count"] = json!(applied.command_policy_count);
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "TEAM_ACCEPT",
        status: "SUCCESS",
        secret_name: None,
        command: Some("team accept"),
        metadata_json: &metadata,
        timestamp: accepted_at,
    };
    let accepted_member_id = MemberId::generate().map_err(|_| CliError::Time)?.into_string();
    store.accept_team_invite_with_member_scope(
        invite_id,
        accepted_at,
        &accepted_member_id,
        &local_device.id,
        &local_device.name,
        role_label_from_payload(invite.payload.role),
        &invite.payload.profiles,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    Ok(())
}

fn ensure_invite_pending(
    store: &locket_store::Store,
    project_id: &str,
    invite: &SignedInvite,
) -> Result<(), CliError> {
    let invite_id = invite.payload.invite_id.as_str();
    let Some(team) = store.get_team_by_project(project_id)? else {
        return Err(team_role_denied_error("no team initialized for this project"));
    };
    let Some(stored) = store.get_team_invite(&team.id, invite_id)? else {
        return Err(metadata_invalid_error("invite not found in local team store"));
    };
    if stored.accepted_at.is_some() || stored.revoked_at.is_some() {
        return Err(CliError::Typed {
            kind: LocketError::ReplayDetected,
            message: format!("invite {invite_id} already accepted or revoked; refusing replay"),
        });
    }
    if stored.issuer_member_id != invite.payload.issuer_member_id.as_str()
        || stored.recipient_device_fingerprint != invite.payload.recipient_device_fingerprint
        || stored.role != role_label_from_payload(invite.payload.role)
        || stored.profiles.iter().collect::<BTreeSet<_>>()
            != invite.payload.profiles.iter().collect::<BTreeSet<_>>()
        || stored.expires_at / NANOS_PER_SECOND != invite.payload.expires_at
    {
        return Err(metadata_invalid_error(
            "invite claims differ from the locally approved pending scope",
        ));
    }
    Ok(())
}

/// Append a metadata-only `DENIED` audit row for a role-insufficient team
/// operation. Used by `TEAM_INVITE`, `TEAM_ACCEPT`, and `TEAM_REMOVE` refusals.
#[allow(clippy::too_many_arguments)]
fn append_team_role_denial(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    action: &'static str,
    command: &'static str,
    team_id: &str,
    member_id: &str,
    failure_reason: &'static str,
) -> Result<(), CliError> {
    let timestamp = now_unix_nanos()?;
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": action,
        "status": "DENIED",
        "command": command,
        "project_id": project_id,
        "team_id": team_id,
        "member_id": member_id,
        "failure_reason": failure_reason,
        "exit_code": LocketError::TeamRoleDenied.exit_code(),
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action,
        status: "DENIED",
        secret_name: None,
        command: Some(command),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn append_team_accept_denial(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    invite: &SignedInvite,
    failure_reason: &'static str,
    kind: LocketError,
) -> Result<(), CliError> {
    append_team_accept_denial_with_user_verification(
        context,
        store,
        project_id,
        invite,
        failure_reason,
        kind,
        None,
    )
}

fn append_team_accept_denial_with_user_verification(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    invite: &SignedInvite,
    failure_reason: &'static str,
    kind: LocketError,
    user_verification: Option<UserVerificationAudit>,
) -> Result<(), CliError> {
    let timestamp = now_unix_nanos()?;
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    let team_id =
        store.get_team_by_project(project_id)?.map_or_else(|| "unknown".to_owned(), |team| team.id);
    let mut metadata = json!({
        "schema_version": 1,
        "action": "TEAM_ACCEPT",
        "status": "DENIED",
        "command": "team accept",
        "project_id": project_id,
        "team_id": team_id,
        "member_id": invite.payload.issuer_member_id.as_str(),
        "invite_id": invite.payload.invite_id.as_str(),
        "issuer_member_id": invite.payload.issuer_member_id.as_str(),
        "issuer_device_fingerprint": &invite.payload.issuer_device_fingerprint,
        "recipient_device_fingerprint": &invite.payload.recipient_device_fingerprint,
        "role": role_label_from_payload(invite.payload.role),
        "profiles": &invite.payload.profiles,
        "expires_at": invite.payload.expires_at,
        "failure_reason": failure_reason,
        "exit_code": kind.exit_code(),
    });
    if let Some(audit) = user_verification {
        metadata["user_verification"] = serde_json::to_value(audit).map_err(|error| {
            metadata_invalid_error(format!("user_verification encode: {error}"))
        })?;
    }
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "TEAM_ACCEPT",
        status: "DENIED",
        secret_name: None,
        command: Some("team accept"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn team_remove_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamRemoveArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;

    let Some(team) = store.get_team_by_project(project_id)? else {
        return Err(team_role_denied_error("no team initialized for this project"));
    };

    let Some(member) = store.get_team_member(&team.id, &args.member)? else {
        return Err(secret_not_found_error(format!("team member not found: {}", args.member)));
    };
    let caller = current_team_member_role(&store, project_id, &team.id)?;

    if member.removed_at.is_some() {
        return Err(secret_not_found_error(format!(
            "team member already removed: {}",
            member.display_name
        )));
    }

    if let Err(error) = authorize_team_remove(caller, &member) {
        append_team_role_denial(
            context,
            &mut store,
            project_id,
            "TEAM_REMOVE",
            "team remove",
            &team.id,
            &member.id,
            "role_insufficient",
        )?;
        return Err(error);
    }

    // Last-owner guard: cannot remove the last remaining owner.
    if member.role == "owner" {
        let owner_count = store.count_active_owners(&team.id)?;
        if owner_count <= 1 {
            append_team_role_denial(
                context,
                &mut store,
                project_id,
                "TEAM_REMOVE",
                "team remove",
                &team.id,
                &member.id,
                "last_owner_protected",
            )?;
            return Err(team_role_denied_error("cannot remove the last remaining owner"));
        }
    }

    // Show metadata summary before confirmation.
    writeln!(output, "remove member: {} ({})", member.display_name, member.role)?;
    writeln!(output, "trusted_devices: {}", member.trusted_device_count)?;
    let redact_names = privacy_redact_names_enabled(context, false)?;
    write_rotation_checklist(
        output,
        &store,
        project_id,
        rotation_scope_for_member(&member),
        redact_names,
    )?;

    // Typed confirmation: must type the display name exactly.
    let confirmation = context.confirmation_reader.read_confirmation(&member.display_name)?;
    if confirmation.trim() != member.display_name {
        return Err(confirmation_failed_error("confirmation did not match member display name"));
    }

    if locket_agent::team_sync::status(&store, project_id)
        .map_err(|e| metadata_invalid_error(e.to_string()))?
        .owner_fingerprint
        .is_some()
    {
        super::sync::remove_authenticated(context, output, &mut store, project_id, &member.id)?;
        return Ok(());
    }
    let timestamp = now_unix_nanos()?;
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "TEAM_REMOVE",
        "status": "SUCCESS",
        "command": "team remove",
        "project_id": project_id,
        "team_id": team.id,
        "member_id": member.id,
        "member_role": member.role,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "TEAM_REMOVE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("team remove"),
        metadata_json: &metadata,
        timestamp,
    };
    store.with_atomic_write(|store| {
        store.remove_team_member(&member.id, timestamp)?;
        store.append_audit(audit_key.as_ref(), &audit)
    })?;

    writeln!(output, "team_remove: success")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn team_revoke_device_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamRevokeDeviceArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;

    let Some(team) = store.get_team_by_project(project_id)? else {
        return Err(team_role_denied_error("no team initialized for this project"));
    };

    let device = store
        .find_device(project_id, &args.device)?
        .ok_or_else(|| invalid_reference_error("device not found"))?;
    let caller = current_team_member_role(&store, project_id, &team.id)?;
    let target_member = store.get_active_team_member_by_device(&team.id, &device.id)?;
    authorize_team_device_revoke(caller, target_member.as_ref())?;

    if device.revoked_at.is_some() {
        writeln!(output, "device: already revoked")?;
        writeln!(output, "device_id: {}", device.id)?;
        writeln!(output, "metadata_only: yes")?;
        return Ok(());
    }

    if locket_agent::team_sync::status(&store, project_id)
        .map_err(|e| metadata_invalid_error(e.to_string()))?
        .owner_fingerprint
        .is_some()
    {
        let member = target_member
            .ok_or_else(|| metadata_invalid_error("device has no authenticated team membership"))?;
        super::sync::remove_authenticated(context, output, &mut store, project_id, &member.id)?;
        return Ok(());
    }
    let timestamp = now_unix_nanos()?;
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "DEVICE_REVOKE",
        "status": "SUCCESS",
        "command": "team revoke-device",
        "device_id": device.id,
        "device_name": device.name,
        "fingerprint": device.fingerprint,
        "local": device.local,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "DEVICE_REVOKE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("team revoke-device"),
        metadata_json: &metadata,
        timestamp,
    };
    store.with_atomic_write(|store| {
        if store.revoke_device(project_id, &device.id, timestamp)? {
            store.append_audit(audit_key.as_ref(), &audit)?;
        }
        Ok::<_, locket_store::StoreError>(())
    })?;

    // Drop the wrapped private-key envelopes for a revoked local device.
    device::cleanup_local_device_envelope_if_local(context, project_id, &device)?;

    writeln!(output, "device: revoked")?;
    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    let redact_names = privacy_redact_names_enabled(context, false)?;
    write_rotation_checklist(
        output,
        &store,
        project_id,
        target_member.as_ref().map_or(RotationScope::LegacyUnknown, rotation_scope_for_member),
        redact_names,
    )?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn team_members_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let redact_names = privacy_redact_names_enabled(context, false)?;

    let Some(team) = store.get_team_by_project(project_id)? else {
        writeln!(output, "team: none")?;
        writeln!(output, "members: none")?;
        writeln!(output, "pending_invites: none")?;
        writeln!(output, "metadata_only: yes")?;
        return Ok(());
    };

    let members = store.list_team_members(&team.id)?;
    let pending_invites = store.list_pending_team_invites(&team.id, now_unix_nanos()?)?;

    writeln!(output, "team: {}", team_name_label(&team, redact_names))?;
    writeln!(output, "team_id: {}", team_id_label(&team, redact_names))?;
    write_members(output, &members, redact_names)?;
    write_pending_invites(output, &pending_invites, redact_names)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn write_members(
    output: &mut impl Write,
    members: &[TeamMemberListRecord],
    redact_names: bool,
) -> Result<(), CliError> {
    if members.is_empty() {
        writeln!(output, "members: none")?;
        return Ok(());
    }
    writeln!(output, "members:")?;
    for member in members {
        writeln!(
            output,
            "- id={} display={} role={} profiles={} trusted_devices={} joined_at={} removed_at={}",
            member_id_label(member, redact_names),
            member_display_label(member, redact_names),
            member.role,
            member_profiles_label(member, redact_names),
            member.trusted_device_count,
            member.joined_at,
            optional_timestamp_label(member.removed_at),
        )?;
    }
    Ok(())
}

fn write_pending_invites(
    output: &mut impl Write,
    invites: &[PendingTeamInviteRecord],
    redact_names: bool,
) -> Result<(), CliError> {
    if invites.is_empty() {
        writeln!(output, "pending_invites: none")?;
        return Ok(());
    }
    writeln!(output, "pending_invites:")?;
    for invite in invites {
        writeln!(
            output,
            "- id={} status=pending role={} profiles={} recipient_device={} created_at={} expires_at={}",
            invite_id_label(invite, redact_names),
            invite.role,
            invite_profiles_label(invite, redact_names),
            invite_recipient_label(invite, redact_names),
            invite.created_at,
            invite.expires_at,
        )?;
    }
    Ok(())
}

struct InviteIssuer {
    team: TeamRecord,
    local_device: DeviceRecord,
    member: TeamMemberListRecord,
}

struct BuiltInvite {
    id: String,
    encoded_invite: String,
    issuer_fingerprint: String,
    recipient_fingerprint: String,
    role: &'static str,
    profiles: Vec<String>,
    nonce: [u8; 24],
    expires_at: i64,
}

fn load_invite_issuer(
    store: &locket_store::Store,
    project_id: &str,
) -> Result<InviteIssuer, CliError> {
    let team = store
        .get_team_by_project(project_id)?
        .ok_or_else(|| team_role_denied_error("no team initialized for this project"))?;
    let local_device = store
        .get_active_local_device(project_id)?
        .ok_or_else(|| invalid_reference_error("local device is not initialized"))?;
    let member = store
        .get_team_member_by_device(&team.id, &local_device.id)?
        .ok_or_else(|| team_role_denied_error("local device is not a team member"))?;
    Ok(InviteIssuer { team, local_device, member })
}

fn build_invite_sealed_payload(
    context: &RuntimeContext,
    store: &locket_store::Store,
    resolved: &ResolvedProject,
    profile_names: &[String],
    recipient_sealing_public_key: &[u8; 32],
) -> Result<SealedInvitePayloadV1, CliError> {
    let project_id = resolved.config.project_id.as_str();
    let mut profiles = Vec::with_capacity(profile_names.len());
    let mut profile_keys = Vec::with_capacity(profile_names.len().saturating_mul(2));
    for profile_name in profile_names {
        let profile = store
            .get_profile_by_name(project_id, profile_name)?
            .ok_or_else(|| profile_not_found_error(format!("profile not found: {profile_name}")))?;
        profiles.push(InviteSealedProfileV1 {
            profile_id: profile.id.clone(),
            name: profile.name.clone(),
            dangerous: profile.dangerous,
            created_at: profile.created_at,
        });
        for purpose in [KeyPurpose::ProfileSecret, KeyPurpose::ProfileFingerprint] {
            let key = load_profile_key(context, store, project_id, &profile.id, purpose)?;
            profile_keys.push(InviteSealedProfileKeyV1 {
                profile_name: profile.name.clone(),
                purpose: purpose.as_str().to_owned(),
                key_material_b64: BASE64URL_NOPAD.encode(key.as_ref()),
            });
        }
    }

    let command_policies = invite_command_policies(resolved)?;
    let plaintext = InviteSealedPlaintextV1 { v: 1, profiles, profile_keys, command_policies };
    let plaintext_bytes = zeroize::Zeroizing::new(serde_json::to_vec(&plaintext)?);
    let encrypted_payload = encrypt_bundle_payload_for_age_recipients(
        &plaintext_bytes,
        &[*recipient_sealing_public_key],
    )
    .map_err(|error| {
        metadata_invalid_error(format!("invite sealed payload encrypt failed: {error}"))
    })?;
    Ok(SealedInvitePayloadV1 {
        v: 1,
        ciphertext_b64: BASE64URL_NOPAD.encode(&encrypted_payload),
        recipient_sealing_public_key_b64: BASE64URL_NOPAD.encode(recipient_sealing_public_key),
        aad_schema_version: AAD_SCHEMA_V1,
        plaintext_counts: SealedInvitePlaintextCounts {
            profile_key_count: u32::try_from(plaintext.profile_keys.len()).map_err(|_| {
                metadata_invalid_error("invite profile key count exceeds schema limit")
            })?,
            command_policy_count: u32::try_from(plaintext.command_policies.len()).map_err(
                |_| metadata_invalid_error("invite command policy count exceeds schema limit"),
            )?,
            secret_metadata_count: 0,
        },
    })
}

fn invite_command_policies(
    resolved: &ResolvedProject,
) -> Result<Vec<InviteSealedCommandPolicyV1>, CliError> {
    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    Ok(policy_document.commands.values().map(invite_command_policy).collect())
}

fn invite_command_policy(policy: &CommandPolicy) -> InviteSealedCommandPolicyV1 {
    let (argv, shell) = match &policy.command {
        CommandSpec::Argv(arguments) => (arguments.clone(), None),
        CommandSpec::Shell(script) => (Vec::new(), Some(script.clone())),
    };
    InviteSealedCommandPolicyV1 {
        name: policy.name.clone(),
        command_kind: command_type(&policy.command).to_owned(),
        argv,
        shell,
        allowed_secrets: policy
            .allowed_secrets
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
        required_secrets: policy
            .required_secrets
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
        optional_secrets: policy
            .optional_secrets
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
        inherit_env: policy.inherit_env.clone(),
        env_mode: policy.env_mode.as_str().to_owned(),
        override_mode: policy.override_behavior.as_str().to_owned(),
        override_explicit: policy.override_explicit(),
        external_env_sources: policy
            .external_env_sources
            .iter()
            .map(external_env_source_label)
            .collect(),
        allow_remote_docker: policy.allow_remote_docker,
        confirm: policy.confirm,
        require_user_verification: policy.require_user_verification,
        ttl_seconds: policy.ttl.as_secs(),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_signed_invite(
    signing_key: &SigningKey,
    project_id: &str,
    issuer: &InviteIssuer,
    recipient: &RecipientDevice,
    profiles: &[String],
    invite_role: TeamRole,
    role_label: &'static str,
    expires_at: i64,
    sealed_payload: SealedInvitePayloadV1,
) -> Result<BuiltInvite, CliError> {
    let invite_id = InviteId::generate().map_err(|_| CliError::Time)?;
    let nonce = invite_nonce()?;
    let issuer_signing_public_key = signing_key.verifying_key().to_bytes();
    let issuer_sealing_public_key = issuer
        .local_device
        .sealing_public_key
        .as_slice()
        .try_into()
        .map_err(|_| metadata_invalid_error("issuer sealing key must be 32 bytes"))?;
    let issuer_fingerprint =
        device::device_fingerprint_hex(&issuer_signing_public_key, &issuer_sealing_public_key);
    let payload = InvitePayload {
        v: 1,
        invite_id: invite_id.clone(),
        project_id: ProjectId::new(project_id.to_owned())
            .map_err(|_| metadata_invalid_error("project id is invalid"))?,
        issuer_member_id: MemberId::new(issuer.member.id.clone())
            .map_err(|_| metadata_invalid_error("issuer member id is invalid"))?,
        issuer_signing_public_key: BASE64URL_NOPAD.encode(&issuer_signing_public_key),
        issuer_sealing_public_key: BASE64URL_NOPAD.encode(&issuer_sealing_public_key),
        issuer_device_fingerprint: issuer_fingerprint.clone(),
        recipient_device_fingerprint: recipient.fingerprint.clone(),
        recipient_sealing_public_key: BASE64URL_NOPAD.encode(&recipient.sealing_public_key),
        role: invite_role,
        profiles: profiles.to_vec(),
        expires_at: expires_at / NANOS_PER_SECOND,
        nonce: BASE64URL_NOPAD.encode(&nonce),
        sealed_payload,
    };
    let signed_invite = SignedInvite::sign(signing_key, payload)
        .map_err(|error| metadata_invalid_error(format!("invite signing failed: {error}")))?;
    let encoded_invite = signed_invite
        .encode()
        .map_err(|error| metadata_invalid_error(format!("invite encoding failed: {error}")))?;
    Ok(BuiltInvite {
        id: invite_id.as_str().to_owned(),
        encoded_invite,
        issuer_fingerprint,
        recipient_fingerprint: recipient.fingerprint.clone(),
        role: role_label,
        profiles: profiles.to_vec(),
        nonce,
        expires_at,
    })
}

fn persist_invite(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    issuer: &InviteIssuer,
    invite: &BuiltInvite,
    output_path: &Path,
    created_at: i64,
) -> Result<TeamInviteRecord, CliError> {
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    write_invite_file(output_path, &invite.encoded_invite)?;
    let invite_record = TeamInviteRecord {
        id: invite.id.clone(),
        team_id: issuer.team.id.clone(),
        issuer_member_id: issuer.member.id.clone(),
        recipient_device_fingerprint: invite.recipient_fingerprint.clone(),
        role: invite.role.to_owned(),
        profiles: invite.profiles.clone(),
        nonce: invite.nonce.to_vec(),
        created_at,
        expires_at: invite.expires_at,
    };
    let metadata = json!({
        "schema_version": 1,
        "action": "TEAM_INVITE",
        "status": "SUCCESS",
        "command": "team invite",
        "project_id": project_id,
        "team_id": issuer.team.id,
        "member_id": issuer.member.id,
        "invite_id": invite_record.id,
        "issuer_member_id": issuer.member.id,
        "issuer_device_id": issuer.local_device.id,
        "issuer_device_fingerprint": invite.issuer_fingerprint,
        "recipient_device_fingerprint": invite_record.recipient_device_fingerprint,
        "role": invite_record.role,
        "profiles": invite_record.profiles,
        "expires_at": invite_record.expires_at,
        "output_path_kind": output_path_kind(output_path, context),
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "TEAM_INVITE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("team invite"),
        metadata_json: &metadata,
        timestamp: created_at,
    };
    if let Err(error) = store.insert_team_invite(
        &invite_record,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    ) {
        let _ignored = fs::remove_file(output_path);
        return Err(error.into());
    }
    Ok(invite_record)
}

fn write_invite_created_output(
    output: &mut impl Write,
    invite_record: &TeamInviteRecord,
    issuer_fingerprint: &str,
    output_path: &Path,
    redact_names: bool,
) -> Result<(), CliError> {
    writeln!(output, "team_invite: created")?;
    writeln!(output, "invite_id: {}", invite_id_label_from_str(&invite_record.id, redact_names))?;
    writeln!(
        output,
        "issuer_fingerprint: {}",
        device_fingerprint_label(issuer_fingerprint, redact_names)
    )?;
    writeln!(
        output,
        "recipient_fingerprint: {}",
        device_fingerprint_label(&invite_record.recipient_device_fingerprint, redact_names)
    )?;
    writeln!(output, "role: {}", invite_record.role)?;
    writeln!(output, "profiles: {}", profiles_label(&invite_record.profiles, redact_names))?;
    writeln!(output, "expires_at: {}", format_invite_expiry(invite_record.expires_at))?;
    writeln!(output, "output: {}", output_path.display())?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

struct RecipientDevice {
    fingerprint: String,
    sealing_public_key: [u8; 32],
}

fn decode_recipient_device(value: &str) -> Result<RecipientDevice, CliError> {
    let verified = device::decode_verified_device_descriptor(value, "recipient device descriptor")?;
    Ok(RecipientDevice {
        fingerprint: verified.fingerprint,
        sealing_public_key: verified.sealing_public_key,
    })
}

fn validate_invite_profiles(
    store: &locket_store::Store,
    project_id: &str,
    profile_names: &[String],
) -> Result<Vec<String>, CliError> {
    let mut unique = BTreeSet::new();
    for name in profile_names {
        if name.trim().is_empty() || name.chars().any(char::is_control) {
            return Err(metadata_invalid_error("invalid invite profile name"));
        }
        let Some(profile) = store.get_profile_by_name(project_id, name)? else {
            return Err(profile_not_found_error(format!("profile not found: {name}")));
        };
        unique.insert(profile.name);
    }
    Ok(unique.into_iter().collect())
}

fn validate_invite_fingerprint_claims(invite: &SignedInvite) -> Result<(), CliError> {
    let issuer_signing_key =
        decode_invite_key(&invite.payload.issuer_signing_public_key, "issuer signing key")?;
    let issuer_sealing_key =
        decode_invite_key(&invite.payload.issuer_sealing_public_key, "issuer sealing key")?;
    let fingerprint =
        fingerprint_hex(&device_fingerprint_v1(&issuer_signing_key, &issuer_sealing_key));
    if fingerprint != invite.payload.issuer_device_fingerprint {
        return Err(invite_fingerprint_invalid_error(
            "invite issuer fingerprint does not match issuer keys",
        ));
    }
    Ok(())
}

fn invite_expired_error(message: impl Into<String>) -> CliError {
    CliError::Typed { kind: LocketError::InviteExpired, message: message.into() }
}

fn invite_signature_invalid_error(message: impl Into<String>) -> CliError {
    CliError::Typed { kind: LocketError::InviteSignatureInvalid, message: message.into() }
}

fn invite_fingerprint_invalid_error(message: impl Into<String>) -> CliError {
    CliError::Typed { kind: LocketError::DeviceDescriptorInvalid, message: message.into() }
}

fn decode_invite_key(value: &str, label: &str) -> Result<[u8; 32], CliError> {
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| metadata_invalid_error(format!("invite {label} is not valid base64url")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        metadata_invalid_error(format!("invite {label} must be 32 bytes, got {}", bytes.len()))
    })
}

fn write_accept_summary(output: &mut impl Write, invite: &SignedInvite) -> Result<(), CliError> {
    let issuer_safety_words =
        device::safety_words_from_fingerprint(&invite.payload.issuer_device_fingerprint);
    writeln!(output, "team_accept: pending")?;
    writeln!(
        output,
        "command_definitions: proposed metadata only; approve separately in locket.toml"
    )?;
    writeln!(output, "invite_id: {}", invite.payload.invite_id.as_str())?;
    writeln!(output, "project_id: {}", invite.payload.project_id.as_str())?;
    writeln!(output, "issuer_member_id: {}", invite.payload.issuer_member_id.as_str())?;
    writeln!(output, "issuer_fingerprint: {}", invite.payload.issuer_device_fingerprint)?;
    writeln!(output, "issuer_safety_words: {}", issuer_safety_words.join(" "))?;
    writeln!(output, "recipient_fingerprint: {}", invite.payload.recipient_device_fingerprint)?;
    writeln!(output, "role: {}", role_label_from_payload(invite.payload.role))?;
    writeln!(output, "profiles: {}", profiles_label(&invite.payload.profiles, false))?;
    writeln!(output, "expires_at: {}", invite.payload.expires_at)?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "type '{}' to confirm team accept", invite.payload.issuer_device_fingerprint)?;
    Ok(())
}

fn confirm_dangerous_profiles(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &locket_store::Store,
    project_id: &str,
    profiles: &[String],
) -> Result<(), CliError> {
    let mut dangerous = Vec::new();
    for profile_name in profiles {
        if let Some(profile) = store.get_profile_by_name(project_id, profile_name)?
            && profile.dangerous
        {
            dangerous.push(profile.name);
        }
    }
    if dangerous.is_empty() {
        return Ok(());
    }
    let names = dangerous.join(",");
    writeln!(output, "dangerous_profiles: {names}")?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "type 'team invite {names}' to confirm dangerous profile invite")?;
    let confirmation = context.confirmation_reader.read_confirmation("team invite")?;
    if confirmation.trim_end_matches(['\r', '\n']) != format!("team invite {names}") {
        return Err(confirmation_failed_error(
            "confirmation did not match dangerous profile invite scope",
        ));
    }
    Ok(())
}

fn validate_invitee_name(name: &str) -> Result<(), CliError> {
    if name.trim().is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(metadata_invalid_error("invalid invitee name"));
    }
    Ok(())
}

fn invite_ttl_seconds(value: Option<&str>) -> Result<u64, CliError> {
    let duration = match value {
        Some(value) => LocketDuration::from_str(value)
            .map_err(|_| metadata_invalid_error("invalid invite expiry duration"))?,
        None => LocketDuration::from_secs(DEFAULT_INVITE_TTL_SECONDS),
    };
    let seconds = duration.as_secs();
    if seconds < MIN_INVITE_TTL_SECONDS {
        return Err(metadata_invalid_error("invite expiry must be at least 5m"));
    }
    if seconds > MAX_INVITE_TTL_SECONDS {
        return Err(metadata_invalid_error("invite expiry must be 30d or less"));
    }
    Ok(seconds)
}

const fn role_from_arg(role: TeamRoleArg) -> TeamRole {
    match role {
        TeamRoleArg::Owner => TeamRole::Owner,
        TeamRoleArg::Maintainer => TeamRole::Maintainer,
        TeamRoleArg::Developer => TeamRole::Developer,
        TeamRoleArg::ReadOnly => TeamRole::ReadOnly,
    }
}

const fn role_label(role: TeamRoleArg) -> &'static str {
    match role {
        TeamRoleArg::Owner => "owner",
        TeamRoleArg::Maintainer => "maintainer",
        TeamRoleArg::Developer => "developer",
        TeamRoleArg::ReadOnly => "read-only",
    }
}

const fn role_label_from_payload(role: TeamRole) -> &'static str {
    match role {
        TeamRole::Owner => "owner",
        TeamRole::Maintainer => "maintainer",
        TeamRole::Developer => "developer",
        TeamRole::ReadOnly => "read-only",
    }
}

fn can_issue_role(issuer_role: &str, invite_role: TeamRoleArg) -> bool {
    match issuer_role {
        "owner" => true,
        "maintainer" => matches!(invite_role, TeamRoleArg::Developer | TeamRoleArg::ReadOnly),
        _ => false,
    }
}

fn can_revoke_invite(
    revoker_role: &str,
    revoker_member_id: &str,
    invite: &StoredTeamInviteRecord,
) -> bool {
    match revoker_role {
        "owner" => true,
        "maintainer" => invite.issuer_member_id == revoker_member_id || invite.role != "owner",
        _ => false,
    }
}

fn invite_nonce() -> Result<[u8; 24], CliError> {
    let random = generate_key()?;
    let mut nonce = [0_u8; 24];
    nonce.copy_from_slice(&random[..24]);
    Ok(nonce)
}

fn default_invite_output_path(context: &RuntimeContext, timestamp: i64) -> PathBuf {
    let rendered = unix_nanos_to_rfc3339(timestamp)
        .map_or_else(|| timestamp.to_string(), |value| value.replace(':', "-"));
    context.cwd.join(format!("locket-invite-{rendered}.locket-invite"))
}

fn ensure_invite_output_available(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        return Err(invalid_reference_error("invite output already exists"));
    }
    Ok(())
}

fn write_invite_file(path: &Path, encoded_invite: &str) -> Result<(), CliError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    set_user_only_file_options(&mut options);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            invalid_reference_error("invite output already exists")
        } else {
            CliError::Io(error)
        }
    })?;
    file.write_all(encoded_invite.as_bytes())?;
    file.write_all(b"\n")?;
    set_user_only_file_permissions(path)?;
    Ok(())
}

fn output_path_kind(path: &Path, context: &RuntimeContext) -> &'static str {
    if path.parent().is_some_and(|parent| parent == context.cwd) {
        "current_directory"
    } else if path.is_absolute() {
        "absolute"
    } else {
        "relative"
    }
}

fn format_invite_expiry(timestamp: i64) -> String {
    unix_nanos_to_rfc3339(timestamp).unwrap_or_else(|| timestamp.to_string())
}

fn invite_id_label_from_str(invite_id: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("invite", invite_id) } else { invite_id.to_owned() }
}

fn device_fingerprint_label(fingerprint: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("device", fingerprint) } else { fingerprint.to_owned() }
}

fn profiles_label(profiles: &[String], redact_names: bool) -> String {
    if profiles.is_empty() {
        return "-".to_owned();
    }
    profiles
        .iter()
        .map(
            |profile| {
                if redact_names { privacy_alias("profile", profile) } else { profile.clone() }
            },
        )
        .collect::<Vec<_>>()
        .join(",")
}

fn team_name_label(team: &TeamRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("team", &team.name) } else { team.name.clone() }
}

fn team_id_label(team: &TeamRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("team", &team.id) } else { team.id.clone() }
}

fn member_id_label(member: &TeamMemberListRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("member", &member.id) } else { member.id.clone() }
}

fn member_display_label(member: &TeamMemberListRecord, redact_names: bool) -> String {
    if redact_names {
        privacy_alias("member", &member.display_name)
    } else {
        member.display_name.clone()
    }
}

fn member_profiles_label(member: &TeamMemberListRecord, redact_names: bool) -> String {
    if member.role == "owner" {
        return "all".to_owned();
    }
    match member.profiles.as_deref() {
        Some([]) => "all".to_owned(),
        Some(profiles) => profiles_label(profiles, redact_names),
        None => "unknown".to_owned(),
    }
}

fn invite_id_label(invite: &PendingTeamInviteRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("invite", &invite.id) } else { invite.id.clone() }
}

fn invite_recipient_label(invite: &PendingTeamInviteRecord, redact_names: bool) -> String {
    if redact_names {
        privacy_alias("device", &invite.recipient_device_fingerprint)
    } else {
        invite.recipient_device_fingerprint.clone()
    }
}

fn invite_profiles_label(invite: &PendingTeamInviteRecord, redact_names: bool) -> String {
    if invite.profiles.is_empty() {
        return "-".to_owned();
    }
    invite
        .profiles
        .iter()
        .map(
            |profile| {
                if redact_names { privacy_alias("profile", profile) } else { profile.clone() }
            },
        )
        .collect::<Vec<_>>()
        .join(",")
}

fn optional_timestamp_label(value: Option<i64>) -> String {
    value.map_or_else(|| "-".to_owned(), |timestamp| timestamp.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TeamMemberRole {
    Owner,
    Maintainer,
    Developer,
    ReadOnly,
}

impl TeamMemberRole {
    fn from_label(label: &str) -> Option<Self> {
        match label {
            "owner" => Some(Self::Owner),
            "maintainer" => Some(Self::Maintainer),
            "developer" => Some(Self::Developer),
            "read-only" => Some(Self::ReadOnly),
            _ => None,
        }
    }
}

fn current_team_member_role(
    store: &locket_store::Store,
    project_id: &str,
    team_id: &str,
) -> Result<TeamMemberRole, CliError> {
    let Some(local_device) = store.get_active_local_device(project_id)? else {
        return Err(team_role_denied_error("team action requires an active local team device"));
    };
    let Some(member) = store.get_active_team_member_by_device(team_id, &local_device.id)? else {
        return Err(team_role_denied_error("local device is not an active team member"));
    };
    TeamMemberRole::from_label(&member.role)
        .ok_or_else(|| team_role_denied_error("local team member has an unknown role"))
}

fn authorize_team_remove(
    caller: TeamMemberRole,
    target: &TeamMemberListRecord,
) -> Result<(), CliError> {
    match caller {
        TeamMemberRole::Owner => Ok(()),
        TeamMemberRole::Maintainer if matches!(target.role.as_str(), "developer" | "read-only") => {
            Ok(())
        }
        TeamMemberRole::Maintainer => Err(team_role_denied_error(
            "maintainers can remove only developer and read-only members",
        )),
        TeamMemberRole::Developer | TeamMemberRole::ReadOnly => {
            Err(team_role_denied_error("team role cannot remove members"))
        }
    }
}

fn authorize_team_device_revoke(
    caller: TeamMemberRole,
    target_member: Option<&TeamMemberListRecord>,
) -> Result<(), CliError> {
    match caller {
        TeamMemberRole::Owner => Ok(()),
        TeamMemberRole::Maintainer => {
            let Some(member) = target_member else {
                return Err(team_role_denied_error(
                    "maintainers can revoke only non-owner member devices",
                ));
            };
            if member.role == "owner" {
                return Err(team_role_denied_error(
                    "maintainers cannot revoke owner member devices",
                ));
            }
            Ok(())
        }
        TeamMemberRole::Developer | TeamMemberRole::ReadOnly => {
            Err(team_role_denied_error("team role cannot revoke team devices"))
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum RotationScope<'a> {
    AllProfiles,
    LegacyUnknown,
    Scoped(&'a [String]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RotationScopeNote {
    AllProfiles,
    LegacyUnknown,
    Scoped,
    Stale,
}

/// Emits a metadata-only rotation checklist for profiles in the member's
/// known scope, listing the count of active secrets that principal could
/// have accessed. Owners, legacy members without persisted scope, and stale
/// stored scopes fall back to every project profile.
///
/// Output shape (one block, never a value):
///
/// ```text
/// rotation_checklist:
///   profile <name>: rotate_active_secrets=N
///   ...
///   total_active_secrets=N
///   action: rotate listed secrets in each profile and `team revoke-device` any associated devices
///   scope_note: checklist covers accepted invite profile scope
/// ```
fn write_rotation_checklist(
    output: &mut impl Write,
    store: &locket_store::Store,
    project_id: &str,
    profile_scope: RotationScope<'_>,
    redact_names: bool,
) -> Result<(), CliError> {
    let mut profiles = store.list_profiles(project_id)?;
    let note = match profile_scope {
        RotationScope::AllProfiles | RotationScope::Scoped([]) => RotationScopeNote::AllProfiles,
        RotationScope::LegacyUnknown => RotationScopeNote::LegacyUnknown,
        RotationScope::Scoped(scope) => {
            let scope = scope.iter().map(String::as_str).collect::<std::collections::BTreeSet<_>>();
            if profiles.iter().all(|profile| !scope.contains(profile.name.as_str()))
                || !scope
                    .iter()
                    .all(|name| profiles.iter().any(|profile| profile.name.as_str() == *name))
            {
                RotationScopeNote::Stale
            } else {
                profiles.retain(|profile| scope.contains(profile.name.as_str()));
                RotationScopeNote::Scoped
            }
        }
    };
    writeln!(output, "rotation_checklist:")?;
    if profiles.is_empty() {
        writeln!(output, "  (no profiles)")?;
        writeln!(output, "  total_active_secrets=0")?;
        write_rotation_scope_note(output, note)?;
        return Ok(());
    }
    let mut total: usize = 0;
    for profile in &profiles {
        let secrets = store.list_active_secrets_by_profile(project_id, &profile.id)?;
        total = total.saturating_add(secrets.len());
        let label =
            if redact_names { privacy_alias("profile", &profile.id) } else { profile.name.clone() };
        writeln!(output, "  profile {label}: rotate_active_secrets={}", secrets.len())?;
    }
    writeln!(output, "  total_active_secrets={total}")?;
    writeln!(
        output,
        "  action: rotate listed secrets in each profile and `team revoke-device` any associated devices"
    )?;
    write_rotation_scope_note(output, note)?;
    Ok(())
}

fn rotation_scope_for_member(member: &TeamMemberListRecord) -> RotationScope<'_> {
    if member.role == "owner" {
        return RotationScope::AllProfiles;
    }
    member.profiles.as_deref().map_or(RotationScope::LegacyUnknown, RotationScope::Scoped)
}

fn write_rotation_scope_note(
    output: &mut impl Write,
    note: RotationScopeNote,
) -> Result<(), CliError> {
    let note = match note {
        RotationScopeNote::AllProfiles => {
            "member has all-profile scope; checklist covers all project profiles"
        }
        RotationScopeNote::LegacyUnknown => {
            "legacy member scope unknown; checklist covers all project profiles"
        }
        RotationScopeNote::Scoped => "checklist covers accepted invite profile scope",
        RotationScopeNote::Stale => {
            "stored member scope could not be resolved; checklist covers all project profiles"
        }
    };
    writeln!(output, "  scope_note: {note}")?;
    Ok(())
}

#[cfg(test)]
mod trust_safety_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn incompatible_invite_preserves_profile_key_and_rows() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let context = crate::tests::test_context(&dir);
        crate::run_with_context(
            crate::Cli::try_parse_from(["locket", "init", "--name", "app"])?,
            &context,
            &mut Vec::new(),
        )?;
        let resolved = require_project(&context)?;
        let project_id = resolved.config.project_id.as_str();
        let mut store = open_store(&context)?;
        let profile = store.get_profile_by_name(project_id, "dev")?.ok_or("dev profile missing")?;
        let args = crate::tests::test_secret_write_args("PRESERVED");
        crate::set_secret_value(&context, &args, "still-decryptable", "manual", 1000)?;
        let before =
            load_profile_key(&context, &store, project_id, &profile.id, KeyPurpose::ProfileSecret)?;
        let payload: InviteSealedPlaintextV1 = serde_json::from_value(json!({
            "v":1,"profiles":[],"profile_keys":[{"profile_name":"dev","purpose":"profile-secret","key_material_b64":BASE64URL_NOPAD.encode(&[99;32])}],"command_policies":[]
        }))?;
        assert!(
            apply_invite_plaintext_payload(&context, &mut store, project_id, &payload).is_err()
        );
        let after =
            load_profile_key(&context, &store, project_id, &profile.id, KeyPurpose::ProfileSecret)?;
        assert_eq!(*before, *after);
        let mut value = Vec::new();
        crate::run_with_context(
            crate::Cli::try_parse_from(["locket", "get", "PRESERVED", "--reveal", "--force"])?,
            &context,
            &mut value,
        )?;
        assert!(String::from_utf8(value)?.contains("still-decryptable"));
        Ok(())
    }
}
