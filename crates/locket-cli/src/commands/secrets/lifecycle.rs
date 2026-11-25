//! Secret lifecycle command implementations (list, rm, rotate, copy, history, purge).

use std::io::Write;

use locket_core::SecretName;
use locket_crypto::KeyPurpose;
use locket_store::{AuditContext, AuditWrite, ProfileRecord, Store};
use serde_json::json;

use super::set::{confirm_write, select_target};
use crate::commands::discovery::GLOBAL_VAULT;
use crate::{
    CliError, CopyArgs, HistoryArgs, ListArgs, PurgeArgs, ResolvedSecret, RotateArgs,
    RuntimeContext, SourceKeyArgs, confirmation_failed_error, copy_secret_value, default_profile,
    ensure_trusted_project_root, format_optional_unix_nanos, format_unix_nanos, format_versions,
    grace_until_from_args, invalid_reference_error, invalid_secret_name_error, load_project_key,
    metadata_invalid_error, now_unix_nanos, open_store, preflight_rotate_secret_value,
    profile_not_found_error, refresh_example_for_project_if_enabled, require_project,
    resolve_secret_for_source, rotate_secret_value, secret_audit_metadata, secret_not_found_error,
    source_arg_to_str,
};

pub fn lifecycle_target(
    context: &RuntimeContext,
    selector: Option<&str>,
) -> Result<(Store, ProfileRecord), CliError> {
    if let Some(selector) = selector {
        if selector != GLOBAL_VAULT {
            return Err(invalid_reference_error("expected the Global Vault selector (@shared)"));
        }
        let store = open_store(context)?;
        let target = select_target(context, &store, Some(selector), None)?;
        return Ok((store, target.profile));
    }
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let profile = default_profile(&store, &resolved.config)?;
    Ok((store, profile))
}

pub fn rm_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &SourceKeyArgs,
) -> Result<(), CliError> {
    let (store, profile) = lifecycle_target(context, args.project.as_deref())?;
    let project_id = &profile.project_id;
    if args.project.is_some() {
        confirm_write(&profile, args.use_dangerous, "pass --use-dangerous to confirm the write")?;
    }
    let secret = if let Some(source) = args.source.source {
        let source = source_arg_to_str(source);
        store
            .get_active_secret(project_id, &profile.id, &args.key, source)?
            .ok_or_else(|| secret_not_found_error("secret not found"))?
    } else {
        let active = store
            .list_secrets_by_name(project_id, &profile.id, &args.key)?
            .into_iter()
            .filter(|secret| secret.state == "active")
            .collect::<Vec<_>>();
        match active.as_slice() {
            [] => return Err(secret_not_found_error("secret not found")),
            [secret] => secret.clone(),
            _ => {
                return Err(invalid_reference_error(
                    "multiple sources exist for this secret; pass --source",
                ));
            }
        }
    };
    let source = secret.source.as_str();
    let timestamp = now_unix_nanos()?;
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let metadata = secret_audit_metadata(
        "DELETE",
        &secret.name,
        &profile.id,
        source,
        Some(secret.current_version),
    );
    let audit = AuditWrite {
        project_id,
        profile_id: Some(&profile.id),
        action: "DELETE",
        status: "SUCCESS",
        secret_name: Some(&secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    store.tombstone_secret_with_audit(
        &secret.id,
        timestamp,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    if args.project.is_none() {
        refresh_example_for_project_if_enabled(context)?;
    }
    writeln!(output, "removed {} ({source})", args.key)?;
    Ok(())
}

pub fn rotate_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &RotateArgs,
) -> Result<(), CliError> {
    let timestamp = now_unix_nanos()?;
    let grace_until = grace_until_from_args(args.grace_ttl.as_deref(), timestamp)?;
    preflight_rotate_secret_value(context, args)?;
    let prompt = format!("rotate secret value for {}", args.key);
    let value = context.secret_value_reader.read_secret_value(&prompt)?;
    let (source, version) =
        rotate_secret_value(context, args, value.as_str(), timestamp, grace_until)?;
    if args.project.is_none() {
        refresh_example_for_project_if_enabled(context)?;
    }
    writeln!(output, "rotated {} ({source}) version={version}", args.key)?;
    Ok(())
}

pub fn copy_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &CopyArgs,
) -> Result<(), CliError> {
    let result = copy_secret_value(context, args, now_unix_nanos()?)?;
    refresh_example_for_project_if_enabled(context)?;
    writeln!(
        output,
        "copied {} from={} source={} from_version={} to={} target_source={} version={} prior_target_version={} operation={} metadata_only=yes",
        args.key,
        result.from_profile,
        result.from_source,
        result.from_version,
        result.to_profile,
        result.to_source,
        result.target_version,
        result.prior_target_version.map_or_else(|| "-".to_owned(), |v| v.to_string()),
        result.operation,
    )?;
    Ok(())
}

fn confirm_purge_scope(
    context: &RuntimeContext,
    output: &mut impl Write,
    secret: &ResolvedSecret,
    version_scope: &str,
) -> Result<(), CliError> {
    let expected = format!(
        "purge {}/{}/{}/{}",
        secret.profile.name, secret.secret.source, secret.secret.name, version_scope,
    );
    writeln!(output, "purge_profile: {}", secret.profile.name)?;
    writeln!(output, "purge_source: {}", secret.secret.source)?;
    writeln!(output, "purge_secret: {}", secret.secret.name)?;
    writeln!(output, "purge_version_scope: {version_scope}")?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "type '{expected}' to confirm purge")?;
    let confirmation = context.confirmation_reader.read_confirmation("purge")?;
    if confirmation.trim_end_matches(['\r', '\n']) != expected {
        return Err(confirmation_failed_error("confirmation did not match purge scope"));
    }
    Ok(())
}

pub fn purge_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &PurgeArgs,
) -> Result<(), CliError> {
    if args.version.is_none() && !args.all_versions {
        return Err(invalid_reference_error("purge requires --version N or --all-versions"));
    }

    let secret = resolve_secret_for_source(context, &args.key, args.source.source)?;
    let mut store = open_store(context)?;
    let versions = store.list_secret_versions(&secret.secret.id)?;
    if versions.is_empty() {
        writeln!(output, "purge: no versions")?;
        return Ok(());
    }

    let (target_versions, version_scope) = if args.all_versions {
        if secret.secret.state != "deleted" {
            return Err(metadata_invalid_error(
                "purge --all-versions requires a deleted source; run rm first",
            ));
        }
        let versions = versions.iter().map(|version| version.version).collect::<Vec<_>>();
        (versions, "all".to_owned())
    } else {
        let Some(version) = args.version else {
            return Err(invalid_reference_error("purge requires --version N"));
        };
        let Some(record) = versions.iter().find(|record| record.version == version) else {
            return Err(secret_not_found_error("secret version not found"));
        };
        if secret.secret.state == "active"
            && version == secret.secret.current_version
            && record.state == "current"
        {
            return Err(metadata_invalid_error(
                "cannot purge the current version of an active source",
            ));
        }
        (vec![version], format!("v{version}"))
    };

    let already_purged = target_versions.iter().all(|version| {
        versions.iter().any(|record| record.version == *version && record.state == "purged")
    });

    if !args.force && !already_purged {
        confirm_purge_scope(context, output, &secret, &version_scope)?;
    }

    let timestamp = now_unix_nanos()?;
    let audit_key = load_project_key(
        context,
        &store,
        secret.project.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let metadata = json!({
        "schema_version": 1,
        "action": "PURGE",
        "status": "SUCCESS",
        "secret_name": &secret.secret.name,
        "profile_id": &secret.profile.id,
        "source": &secret.secret.source,
        "versions": &target_versions,
    });
    let audit = AuditWrite {
        project_id: secret.project.config.project_id.as_str(),
        profile_id: Some(&secret.profile.id),
        action: "PURGE",
        status: "SUCCESS",
        secret_name: Some(&secret.secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    let changed = store.purge_secret_versions_with_audit(
        &secret.secret.id,
        &target_versions,
        timestamp,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    refresh_example_for_project_if_enabled(context)?;
    if changed {
        writeln!(
            output,
            "purged {} ({}) versions={}",
            secret.secret.name,
            secret.secret.source,
            format_versions(&target_versions)
        )?;
    } else {
        writeln!(
            output,
            "purge: {} ({}) already purged",
            secret.secret.name, secret.secret.source
        )?;
    }
    Ok(())
}

pub fn history_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &HistoryArgs,
) -> Result<(), CliError> {
    let name = SecretName::new(args.key.clone())
        .map_err(|err| invalid_secret_name_error(err.to_string()))?;
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let profile = if let Some(profile_name) = &args.profile {
        store
            .get_profile_by_name(resolved.config.project_id.as_str(), profile_name)?
            .ok_or_else(|| profile_not_found_error("profile not found"))?
    } else {
        default_profile(&store, &resolved.config)?
    };
    let all_secrets = store.list_secrets_by_name(
        resolved.config.project_id.as_str(),
        &profile.id,
        name.as_str(),
    )?;
    if all_secrets.is_empty() {
        return Err(secret_not_found_error("secret not found"));
    }

    let secrets = if let Some(source) = args.source {
        let target = source_arg_to_str(source);
        let filtered =
            all_secrets.into_iter().filter(|secret| secret.source == target).collect::<Vec<_>>();
        if filtered.is_empty() {
            return Err(secret_not_found_error(format!("secret {name} has no source {target}")));
        }
        filtered
    } else {
        all_secrets
    };

    writeln!(output, "history {} profile={}", name.as_str(), profile.name)?;

    let mut displayed = 0_u32;
    for secret in secrets {
        writeln!(
            output,
            "{} source={} state={} current_version={} created_at={} updated_at={} last_rotated_at={} deleted_at={}",
            secret.name,
            secret.source,
            secret.state,
            secret.current_version,
            format_unix_nanos(secret.created_at),
            format_unix_nanos(secret.updated_at),
            format_optional_unix_nanos(secret.last_rotated_at),
            format_optional_unix_nanos(secret.deleted_at)
        )?;
        let mut shown_for_source = 0_u32;
        for version in store.list_secret_versions(&secret.id)? {
            if let Some(state_filter) = args.state
                && !state_filter.matches(&version.state)
            {
                continue;
            }
            if let Some(limit) = args.limit
                && shown_for_source >= limit
            {
                break;
            }
            shown_for_source += 1;
            displayed += 1;
            writeln!(
                output,
                "  v{} state={} created_at={} deprecated_at={} grace_until={} purged_at={}",
                version.version,
                version.state,
                format_unix_nanos(version.created_at),
                format_optional_unix_nanos(version.deprecated_at),
                format_optional_unix_nanos(version.grace_until),
                format_optional_unix_nanos(version.purged_at)
            )?;
        }
    }
    if displayed == 0 {
        writeln!(output, "history: no versions")?;
    }
    Ok(())
}

pub fn list_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ListArgs,
) -> Result<(), CliError> {
    let (store, profile) = lifecycle_target(context, args.project.as_deref())?;
    let secrets = if args.all {
        store.list_secrets_by_profile(&profile.project_id, &profile.id)?
    } else {
        store.list_active_secrets_by_profile(&profile.project_id, &profile.id)?
    };
    if secrets.is_empty() {
        writeln!(output, "no secrets")?;
        return Ok(());
    }
    for secret in secrets {
        writeln!(
            output,
            "{} source={} version={} state={}",
            secret.name, secret.source, secret.current_version, secret.state
        )?;
    }
    Ok(())
}
