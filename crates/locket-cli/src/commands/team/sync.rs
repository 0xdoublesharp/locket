//! Authenticated owner-published team onboarding and folder delivery.
use super::device;
use crate::runtime::key_access::load_master_key;
use crate::{
    CliError, RuntimeContext, TeamAddArgs, TeamConflictChoice, TeamFolderArgs, TeamJoinArgs,
    TeamRoleArg, TeamSyncCommand, ensure_trusted_project_root, metadata_invalid_error,
    now_unix_nanos, open_store, require_project,
};
use locket_agent::team_sync;
use locket_core::team_package::DeviceIdentity;
use locket_platform::LocalDevicePrivateKeyStorage;
use std::io::Write;

/// Consequences shared by terminal help and a completed local profile rename.
pub const PROFILE_RENAME_CONSEQUENCES: &str = "Policies, default_profile, and lk:// references using the old name will refer to the incoming team profile after retry. Review those references before using it. Directory grants remain bound to the renamed local profile ID.";

fn failure(error: impl std::fmt::Display) -> CliError {
    metadata_invalid_error(error.to_string())
}
fn now() -> Result<i64, CliError> {
    Ok(now_unix_nanos()? / 1_000_000_000)
}
fn local(
    store: &locket_store::Store,
    project: &str,
) -> Result<locket_store::DeviceRecord, CliError> {
    let local = store
        .get_active_local_device(project)?
        .ok_or_else(|| metadata_invalid_error("run `locket team join --request` first"))?;
    device::require_v2_signing(store, &local)?;
    Ok(local)
}

pub fn join(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamJoinArgs,
) -> Result<(), CliError> {
    if args.request {
        return device::join_request(context, output);
    }
    let resolved = require_project(context)?;
    let project = resolved.config.project_id.as_str();
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let local = local(&store, project)?;
    let identity = team_sync::identity(&local).map_err(failure)?;
    let pin = args
        .owner
        .as_deref()
        .filter(|p| p.len() == 64 && p.bytes().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| {
            metadata_invalid_error(
                "--owner must be the full owner fingerprint from a separate trusted channel",
            )
        })?
        .to_ascii_lowercase();
    let (master, _) = load_master_key(context, project)?;
    let sealing = device::build_device_private_key_storage(context, project)?.load(&local.id)?;
    let candidates = join_package_candidates(args)?;
    let mut chosen: Option<(u64, String, Vec<u8>)> = None;
    let mut highest_equivocation = false;
    for package in candidates {
        let Ok(bytes) = team_sync::read_package_file(&package) else {
            continue;
        };
        match team_sync::join_package_checkpoint(&bytes, &sealing, &identity, project, &pin, now()?)
        {
            Ok((epoch, digest)) => {
                if chosen
                    .as_ref()
                    .is_some_and(|(prior, hash, _)| *prior == epoch && hash != &digest)
                {
                    highest_equivocation = true;
                }
                if chosen.as_ref().is_none_or(|(prior, _, _)| epoch > *prior) {
                    chosen = Some((epoch, digest, bytes));
                    highest_equivocation = false;
                }
            }
            Err(error) if args.package.is_some() => return Err(failure(error)),
            Err(_) => {}
        }
    }
    if highest_equivocation {
        return Err(metadata_invalid_error(
            "two owner packages claim the highest join revision; contact the owner",
        ));
    }
    let (_, _, bytes) = chosen.ok_or_else(|| metadata_invalid_error("no valid package for this device and independently verified owner; ask the owner to publish, or select your package explicitly"))?;
    let mut result = team_sync::apply_package_with_consent_guarded(
        &mut store,
        &bytes,
        &master,
        &sealing,
        &identity,
        project,
        Some(&pin),
        now()?,
        args.allow_dangerous,
        None,
    )
    .map_err(failure)?;
    if result.duplicate {
        // Duplicate delivery never retries values; only its report reflects held state.
        result.pending_profiles =
            team_sync::status(&store, project).map_err(failure)?.pending_profiles.len();
    }
    writeln!(output, "team package verified: {}", serde_json::to_string(&result)?)?;
    if result.pending_profiles > 0 {
        writeln!(
            output,
            "Some profile values are held for local review. Run `locket team sync pending` for names, reasons and resolution IDs."
        )?;
    }
    if let Some(folder) = &args.folder {
        team_sync::configure_folder(
            &store,
            project,
            folder,
            &device::device_private_key_root(context)?,
            args.allow_dangerous,
        )
        .map_err(failure)?;
        writeln!(output, "Automatic signed updates enabled for this machine while unlocked.")?;
    }
    writeln!(
        output,
        "Owner fingerprint was supplied independently; imported commands remain unapproved."
    )?;
    Ok(())
}

fn join_package_candidates(args: &TeamJoinArgs) -> Result<Vec<std::path::PathBuf>, CliError> {
    let candidates = if let Some(package) = &args.package {
        vec![package.clone()]
    } else {
        let folder = args
            .folder
            .as_ref()
            .ok_or_else(|| metadata_invalid_error("provide an encrypted .lkpkg or --folder"))?;
        if std::fs::symlink_metadata(folder)?.file_type().is_symlink() {
            return Err(metadata_invalid_error("shared folder must be a regular directory"));
        }
        let mut candidates = Vec::new();
        for (count, entry) in std::fs::read_dir(folder)?.enumerate() {
            if count >= 100_000 {
                return Err(metadata_invalid_error(
                    "shared folder has too many entries; choose your .lkpkg explicitly",
                ));
            }
            let entry = entry?;
            if entry.path().extension().is_some_and(|ext| ext == "lkpkg") {
                candidates.push(entry.path());
            }
        }
        candidates.sort();
        candidates
    };
    Ok(candidates)
}

pub fn add(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamAddArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let project = resolved.config.project_id.as_str();
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let owner = local(&store, project)?;
    let descriptor = device::decode_verified_device_descriptor(&args.device, "joining device")?;
    if descriptor.descriptor.v != 2 || descriptor.fingerprint != args.confirm_device_fingerprint {
        return Err(metadata_invalid_error(
            "verify the full joining-device fingerprint through a separate trusted channel",
        ));
    }
    let recipient = DeviceIdentity::new(
        descriptor.descriptor.device_id,
        descriptor.signing_public_key,
        descriptor.sealing_public_key,
    );
    let profiles = args
        .profiles
        .iter()
        .map(|name| {
            store
                .get_profile_by_name(project, name)
                .map_err(CliError::from)?
                .ok_or_else(|| metadata_invalid_error(format!("profile not found: {name}")))
                .map(|profile| profile.id)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let role = match args.role {
        TeamRoleArg::Owner => "owner",
        TeamRoleArg::Maintainer => "maintainer",
        TeamRoleArg::Developer => "developer",
        TeamRoleArg::ReadOnly => "read-only",
    };
    confirm_dangerous_sharing(context, output, &store, project, &profiles)?;
    let _ = load_master_key(context, project)?;
    team_sync::initialize_owner(
        &mut store,
        project,
        &team_sync::identity(&owner).map_err(failure)?,
        now()?,
    )
    .map_err(failure)?;
    team_sync::add_recipient(&mut store, project, &recipient, &args.name, role, &profiles, now()?)
        .map_err(failure)?;
    writeln!(
        output,
        "Device added to the owner-published recipient list. Run `locket team publish` to send its encrypted package."
    )?;
    Ok(())
}

pub fn folder(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamFolderArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    if team_sync::status(&store, resolved.config.project_id.as_str())
        .map_err(failure)?
        .owner_fingerprint
        .is_none()
    {
        let local = local(&store, resolved.config.project_id.as_str())?;
        team_sync::initialize_owner(
            &mut store,
            resolved.config.project_id.as_str(),
            &team_sync::identity(&local).map_err(failure)?,
            now()?,
        )
        .map_err(failure)?;
    }
    team_sync::configure_folder(
        &store,
        resolved.config.project_id.as_str(),
        &args.path,
        &device::device_private_key_root(context)?,
        args.allow_dangerous,
    )
    .map_err(failure)?;
    writeln!(
        output,
        "Shared folder configured on this machine. Signed updates apply only while unlocked; last verified state is shown by `locket team sync status`."
    )?;
    Ok(())
}

pub fn publish(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let project = resolved.config.project_id.as_str();
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let local = local(&store, project)?;
    let (master, _) = load_master_key(context, project)?;
    let signer = device::load_device_signing_key(context, &store, &local)?;
    team_sync::initialize_owner(
        &mut store,
        project,
        &team_sync::identity(&local).map_err(failure)?,
        now()?,
    )
    .map_err(failure)?;
    let profiles = team_sync::shared_profile_ids(&store, project).map_err(failure)?;
    confirm_dangerous_sharing(context, output, &store, project, &profiles)?;
    let queued =
        team_sync::publish(&mut store, project, &master, &signer, now()?).map_err(failure)?;
    let written = team_sync::flush_outbox(&store, project).map_err(failure)?;
    writeln!(
        output,
        "Encrypted signed packages: queued {queued}, delivered {written}. Peers apply them when unlocked."
    )?;
    Ok(())
}

pub fn sync(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: Option<TeamSyncCommand>,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let project = resolved.config.project_id.as_str();
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    match command.unwrap_or(TeamSyncCommand::Now) {
        TeamSyncCommand::Pending => show_pending_profiles(context, output, &store, project)?,
        TeamSyncCommand::RenameLocalProfile { incoming_profile_id, local_profile_id, new_name } => {
            rename_pending_profile(
                context,
                output,
                &mut store,
                project,
                &incoming_profile_id,
                &local_profile_id,
                &new_name,
            )?;
        }
        TeamSyncCommand::KeepLocalValue { incoming_profile_id, local_secret_id } => {
            preserve_pending_value(
                context,
                output,
                &mut store,
                project,
                &incoming_profile_id,
                &local_secret_id,
            )?;
        }
        TeamSyncCommand::Resolve { secret, choice } => {
            if secret.starts_with("profile:") {
                return Err(metadata_invalid_error(
                    "A held profile requires explicit metadata review. Run `locket team sync pending`, then use `team sync rename-local-profile` for a profile-name collision or `team sync keep-local-value` for a value collision. `resolve` accepts secret conflicts only.",
                ));
            }
            let local = local(&store, project)?;
            let (master, _) = load_master_key(context, project)?;
            let sealing =
                device::build_device_private_key_storage(context, project)?.load(&local.id)?;
            team_sync::resolve_conflict(
                &mut store,
                project,
                &secret,
                matches!(choice, TeamConflictChoice::KeepLocal),
                &master,
                &sealing,
                &team_sync::identity(&local).map_err(failure)?,
                now()?,
            )
            .map_err(failure)?;
            writeln!(output, "Conflict resolved; local command approvals are unchanged.")?;
        }
        TeamSyncCommand::Disable => {
            store
                .connection()
                .execute("UPDATE team_sync_folders SET enabled=0 WHERE project_id=?1", [project])
                .map_err(locket_store::StoreError::from)?;
            writeln!(output, "Automatic updates disabled; authenticated history retained.")?;
        }
        TeamSyncCommand::Status => writeln!(
            output,
            "{}",
            serde_json::to_string_pretty(&team_sync::status(&store, project).map_err(failure)?)?
        )?,
        TeamSyncCommand::Now => {
            let (master, _) = load_master_key(context, project)?;
            writeln!(
                output,
                "{}",
                serde_json::to_string_pretty(
                    &team_sync::sync_folder(&mut store, project, &master, now()?)
                        .map_err(failure)?
                )?
            )?;
        }
    }
    Ok(())
}

fn show_pending_profiles(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &locket_store::Store,
    project: &str,
) -> Result<(), CliError> {
    let local = local(store, project)?;
    let _ = load_master_key(context, project)?;
    let sealing = device::build_device_private_key_storage(context, project)?.load(&local.id)?;
    let details = team_sync::pending_profile_details(
        store,
        project,
        &sealing,
        &team_sync::identity(&local).map_err(failure)?,
        now()?,
    )
    .map_err(failure)?;
    writeln!(output, "{}", serde_json::to_string_pretty(&details)?)?;
    if details.is_empty() {
        writeln!(output, "No profile values are waiting for local resolution.")?;
    } else {
        writeln!(
            output,
            "Names and IDs only; no values were revealed. To preserve a colliding local profile, run `locket team sync rename-local-profile INCOMING_PROFILE_ID LOCAL_PROFILE_ID NEW_NAME`. To preserve a colliding value, run `locket team sync keep-local-value INCOMING_PROFILE_ID LOCAL_SECRET_ID`."
        )?;
        if details.iter().any(|profile| profile.reason == "consent-required") {
            writeln!(
                output,
                "Dangerous profile values require local consent. After reviewing their scope, configure this machine with `locket team folder PATH --allow-dangerous`, then retry explicitly."
            )?;
        }
        write_pending_retry_guidance(output, store, project)?;
    }
    Ok(())
}

fn rename_pending_profile(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &mut locket_store::Store,
    project: &str,
    incoming_profile_id: &str,
    local_profile_id: &str,
    new_name: &str,
) -> Result<(), CliError> {
    let local = local(store, project)?;
    let (master, _) = load_master_key(context, project)?;
    let sealing = device::build_device_private_key_storage(context, project)?.load(&local.id)?;
    team_sync::rename_local_profile_for_pending(
        store,
        project,
        incoming_profile_id,
        local_profile_id,
        new_name,
        &master,
        &sealing,
        &team_sync::identity(&local).map_err(failure)?,
        now()?,
        None,
    )
    .map_err(failure)?;
    writeln!(output, "Local profile renamed with its ID, keys and values preserved.")?;
    writeln!(output, "{PROFILE_RENAME_CONSEQUENCES}")?;
    write_pending_retry_guidance(output, store, project)?;
    Ok(())
}

fn preserve_pending_value(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &mut locket_store::Store,
    project: &str,
    incoming_profile_id: &str,
    local_secret_id: &str,
) -> Result<(), CliError> {
    let local = local(store, project)?;
    let (master, _) = load_master_key(context, project)?;
    let sealing = device::build_device_private_key_storage(context, project)?.load(&local.id)?;
    team_sync::preserve_collision_as_override(
        store,
        project,
        incoming_profile_id,
        local_secret_id,
        &master,
        &sealing,
        &team_sync::identity(&local).map_err(failure)?,
        now()?,
        None,
    )
    .map_err(failure)?;
    writeln!(output, "Local value preserved as a personal override.")?;
    write_pending_retry_guidance(output, store, project)?;
    Ok(())
}

fn write_pending_retry_guidance(
    output: &mut impl Write,
    store: &locket_store::Store,
    project: &str,
) -> Result<(), CliError> {
    if team_sync::status(store, project).map_err(failure)?.folder.is_none() {
        writeln!(
            output,
            "Configure this machine's shared folder with `locket team folder PATH` before retrying delivery."
        )?;
    }
    writeln!(
        output,
        "Run `locket team sync now` to retry held profile values. No sync was started by this action; local command approvals remain unchanged."
    )?;
    Ok(())
}

/// Authenticated offboarding rotates local encryption keys before publishing revocation.
pub fn remove_authenticated(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &mut locket_store::Store,
    project: &str,
    member: &str,
) -> Result<(), CliError> {
    let local = local(store, project)?;
    let (master, _) = load_master_key(context, project)?;
    let signer = device::load_device_signing_key(context, store, &local)?;
    let rotate =
        team_sync::remove_member(store, project, member, &master, now()?).map_err(failure)?;
    writeln!(output, "Membership revoked and affected profile encryption keys rotated locally.")?;
    if !rotate.is_empty() {
        writeln!(output, "Rotate credentials at their providers: {}", rotate.join(", "))?;
    }
    // Revocation is already durable. Report delivery failure without claiming rollback.
    match team_sync::publish(store, project, &master, &signer, now()?)
        .and_then(|_| team_sync::flush_outbox(store, project))
    {
        Ok(count) => writeln!(
            output,
            "Signed revocation delivered in {count} encrypted packages. Removed devices retain old values."
        )?,
        Err(_) => writeln!(
            output,
            "Revocation is saved locally; delivery is pending. Restore the shared folder and run `locket team publish`."
        )?,
    }
    Ok(())
}

/// Shared guard for both granting and manually delivering dangerous profile scope.
fn confirm_dangerous_sharing(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &locket_store::Store,
    project: &str,
    profiles: &[String],
) -> Result<(), CliError> {
    let mut names: Vec<_> = store
        .list_profiles(project)?
        .into_iter()
        .filter(|profile| profile.dangerous && profiles.contains(&profile.id))
        .map(|profile| profile.name)
        .collect();
    names.sort();
    names.dedup();
    if names.is_empty() {
        return Ok(());
    }
    let expected = format!("team share {}", names.join(","));
    writeln!(output, "type '{expected}' to confirm sharing these dangerous profiles")?;
    output.flush()?;
    let confirmation = context.confirmation_reader.read_confirmation("team share")?;
    if confirmation.trim_end_matches(['\r', '\n']) != expected {
        return Err(crate::confirmation_failed_error(
            "confirmation did not match dangerous profile sharing scope",
        ));
    }
    Ok(())
}
