//! Secret metadata update command.

use std::io::Write;

use locket_crypto::KeyPurpose;
use locket_store::{AuditContext, AuditWrite, SecretMetadataUpdate};

use crate::{
    CliError, RuntimeContext, SecretMetaArgs, load_project_key, metadata_flags_have_updates,
    metadata_invalid_error, metadata_required_update, metadata_update_field_names, now_unix_nanos,
    open_store, resolve_active_secret_for_source, secret_meta_update_audit_metadata,
    secret_not_found_error, validate_secret_metadata_update,
    write_secret_meta_update_failure_audit_if_available,
};

pub fn meta_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &SecretMetaArgs,
) -> Result<(), CliError> {
    if !metadata_flags_have_updates(&args.metadata) {
        return Err(metadata_invalid_error("meta requires at least one metadata flag"));
    }

    let resolved_secret = resolve_active_secret_for_source(context, &args.key, args.source.source)?;
    let mut store = open_store(context)?;
    let required = metadata_required_update(&args.metadata);
    let tags =
        if args.metadata.tags.is_empty() { None } else { Some(args.metadata.tags.as_slice()) };
    let timestamp = now_unix_nanos()?;
    if let Err(error) =
        validate_secret_metadata_update(context, &resolved_secret, &args.metadata, timestamp)
    {
        write_secret_meta_update_failure_audit_if_available(
            context,
            &mut store,
            &resolved_secret,
            &args.metadata,
            timestamp,
        )?;
        return Err(error);
    }
    let audit_key = load_project_key(
        context,
        &store,
        resolved_secret.project.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let metadata =
        secret_meta_update_audit_metadata(&resolved_secret, &args.metadata, "SUCCESS", None);
    let audit = AuditWrite {
        project_id: resolved_secret.project.config.project_id.as_str(),
        profile_id: Some(&resolved_secret.profile.id),
        action: "SECRET_META_UPDATE",
        status: "SUCCESS",
        secret_name: Some(&resolved_secret.secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    let id = &resolved_secret.secret.id;
    let changed = if args.metadata.expires_in.is_some() || args.metadata.rotate_after_days.is_some()
    {
        // The legacy metadata update starts its own transaction. Compose the
        // metadata edit, expiry policy, and audit using the same savepoint here.
        let tags_json = tags.map(serde_json::to_string).transpose()?;
        store.with_atomic_write(|store| -> Result<bool, CliError> {
            let changed = store
                .connection()
                .execute(
                    "UPDATE secrets
                 SET description = COALESCE(?2, description), owner = COALESCE(?3, owner),
                     tags_json = COALESCE(?4, tags_json), required = COALESCE(?5, required)
                 WHERE id = ?1 AND state = 'active'",
                    rusqlite::params![
                        id,
                        args.metadata.description,
                        args.metadata.owner,
                        tags_json,
                        required
                    ],
                )
                .map_err(locket_store::StoreError::from)?;
            if changed == 0 {
                return Ok(false);
            }
            super::expiry::update_expiry_policy(store, id, &args.metadata, timestamp)?;
            store.append_audit(audit_key.as_ref(), &audit)?;
            Ok(true)
        })?
    } else {
        store.update_secret_metadata_with_options(
            id,
            SecretMetadataUpdate {
                description: args.metadata.description.as_deref(),
                owner: args.metadata.owner.as_deref(),
                tags,
                required,
                updated_at: None,
                audit: Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
            },
        )?
    };
    if !changed {
        return Err(secret_not_found_error("secret not found"));
    }

    writeln!(
        output,
        "metadata updated {} source={} version={}",
        resolved_secret.secret.name,
        resolved_secret.secret.source,
        resolved_secret.secret.current_version
    )?;
    writeln!(output, "updated_fields: {}", metadata_update_field_names(&args.metadata).join(","))?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}
