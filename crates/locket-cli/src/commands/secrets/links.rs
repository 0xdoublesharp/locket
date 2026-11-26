//! Shared secret promotion, live linking, usage inspection, and local duplicate detection.

use std::io::Write;

use clap::Args;
use locket_core::{LocketError, SecretId, SecretName};
use locket_crypto::{KeyBytes, KeyPurpose, local_dedup_tag_v1};
use locket_store::{
    AuditContext, AuditWrite, ProfileRecord, ProjectRecord, SecretLinkRecord, SecretRecord,
    SecretTransferAudit, Store,
};
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::set::{NewSecret, Rotation, SecretWriteKeys, confirm_write, create_value, rotate_value};
use crate::commands::discovery::{GLOBAL_VAULT, global_vault_project, write_json_result};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, invalid_secret_name_error, profile_not_found_error, secret_already_exists_error,
    secret_deleted_error, secret_not_found_error, typed_cli_error,
};
use crate::runtime::key_access::{load_profile_key, load_project_key};
use crate::support::project_files::refresh_example_for_project_if_enabled;
use crate::support::secret_helpers::{decrypt_secret_version, select_highest_precedence_secret};
use crate::{
    SecretMetadataFlags, SourceArg, default_profile, ensure_trusted_project_root, now_unix_nanos,
    open_store, require_project, secret_audit_metadata, source_arg_to_str,
};

#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct PromoteArgs {
    /// Local secret key name in the current project.
    pub key: String,
    /// Destination secret name in the Global Vault (@shared). Defaults to <KEY>.
    #[arg(long = "as", value_name = "SHARED_NAME")]
    pub target_name: Option<String>,
    #[command(flatten)]
    pub source: SourceArg,
    /// Keep the project-local copy instead of replacing it with a live link.
    #[arg(long)]
    pub keep_local: bool,
    /// Also replace matching duplicate user-local copies in other non-dangerous projects with links.
    #[arg(long)]
    pub consolidate_duplicates: bool,
    /// Overwrite if @shared already holds a different value under the target name.
    #[arg(long)]
    pub overwrite: bool,
    /// Confirm writes affecting a dangerous profile.
    #[arg(long)]
    pub use_dangerous: bool,
    /// Emit a metadata-only JSON result.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct LinkArgs {
    /// Environment variable name to expose in the current project.
    pub local_key: String,
    /// Target secret name in the Global Vault (with or without `@shared/` prefix).
    pub target: String,
    /// Confirm linking into a dangerous profile.
    #[arg(long)]
    pub use_dangerous: bool,
    /// Emit a metadata-only JSON result.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct UnlinkArgs {
    /// Linked environment variable name in the current project.
    pub local_key: String,
    /// Confirm unlinking in a dangerous profile.
    #[arg(long)]
    pub use_dangerous: bool,
    /// Emit a metadata-only JSON result.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DuplicatesArgs {
    /// Refresh local dedup tags across accessible projects before listing duplicates.
    #[arg(long)]
    pub reindex: bool,
    /// Emit a metadata-only JSON report.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SharedUsagesArgs {
    /// Secret name in the Global Vault (@shared).
    pub key: String,
    /// Emit a metadata-only JSON report.
    #[arg(long)]
    pub json: bool,
}

/// Metadata-only match returned when an imported value matches an existing vault secret.
#[derive(Clone, Debug, Serialize)]
pub struct CliDuplicateMatch {
    pub local_name: String,
    pub match_kind: &'static str,
    pub matched_project_id: String,
    pub matched_project_name: String,
    pub matched_profile_name: String,
    pub matched_secret_name: String,
    #[serde(skip)]
    pub matched_secret_id: String,
    pub is_shared: bool,
}

pub fn shared_vault_target(store: &Store) -> Result<(ProjectRecord, ProfileRecord), CliError> {
    let project = global_vault_project(store)?.ok_or_else(|| {
        typed_cli_error(
            LocketError::ProjectNotFound,
            "Global Vault (@shared) is not initialized; run `locket shared init` first",
        )
    })?;
    let profile = store
        .get_profile_by_name(&project.id, "default")?
        .ok_or_else(|| profile_not_found_error("Global Vault default profile is missing"))?;
    Ok((project, profile))
}

/// Loads `@shared`'s default profile fingerprint key without interactive passphrase prompts.
pub fn try_load_shared_fingerprint_key_non_interactive(
    context: &RuntimeContext,
    store: &Store,
) -> Option<Zeroizing<KeyBytes>> {
    let (project, profile) = shared_vault_target(store).ok()?;
    let master = context
        .master_key_cache
        .get(&project.id)
        .map(|(key, _)| key)
        .or_else(|| context.key_store.load_master_key(&project.id).ok())?;
    crate::runtime::key_access::load_profile_key_with_master(
        store,
        &project.id,
        &profile.id,
        KeyPurpose::ProfileFingerprint,
        &master,
    )
    .ok()
}

pub fn try_record_cli_dedup_tag(
    context: &RuntimeContext,
    store: &Store,
    secret_id: &str,
    version: u32,
    value: &str,
    timestamp: i64,
) {
    let Some(fp_key) = try_load_shared_fingerprint_key_non_interactive(context, store) else {
        return;
    };
    if let Ok(tag) = local_dedup_tag_v1(&fp_key, value) {
        let _ = store.upsert_local_value_fingerprint(secret_id, version, &tag, timestamp);
    }
}

pub fn find_duplicate_matches_for_value(
    store: &Store,
    shared_fp_key: &KeyBytes,
    project_id: &str,
    profile_id: &str,
    local_name: &str,
    value: &str,
) -> Result<Vec<CliDuplicateMatch>, CliError> {
    let tag = local_dedup_tag_v1(shared_fp_key, value)?;
    let rows = store.find_active_secrets_by_dedup_tag(&tag)?;
    Ok(rows
        .into_iter()
        .filter(|row| {
            !(row.project_id == project_id
                && row.profile_id == profile_id
                && row.name == local_name)
        })
        .map(|row| CliDuplicateMatch {
            local_name: local_name.to_owned(),
            match_kind: if row.is_shared { "shared" } else { "project" },
            matched_project_id: row.project_id,
            matched_project_name: row.project_name,
            matched_profile_name: row.profile_name,
            matched_secret_name: row.name,
            matched_secret_id: row.secret_id,
            is_shared: row.is_shared,
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
pub fn create_link_record_with_audit(
    context: &RuntimeContext,
    store: &mut Store,
    project_id: &str,
    profile_id: &str,
    local_name: &str,
    target_project_id: &str,
    target_profile_id: &str,
    target_secret: &SecretRecord,
    timestamp: i64,
) -> Result<String, CliError> {
    let link = SecretLinkRecord {
        id: format!("lk_link_{}", SecretId::generate().map_err(|_| CliError::Time)?.into_string()),
        project_id: project_id.to_owned(),
        profile_id: profile_id.to_owned(),
        local_name: local_name.to_owned(),
        target_project_id: target_project_id.to_owned(),
        target_profile_id: target_profile_id.to_owned(),
        target_secret_id: target_secret.id.clone(),
        created_at: timestamp,
        updated_at: timestamp,
    };
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "SECRET_LINK",
        "status": "SUCCESS",
        "secret_name": local_name,
        "profile_id": profile_id,
        "target_project_id": target_project_id,
        "target_profile_id": target_profile_id,
        "target_secret_id": target_secret.id,
        "target_secret_name": target_secret.name,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: Some(profile_id),
        action: "SECRET_LINK",
        status: "SUCCESS",
        secret_name: Some(local_name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    let persisted_id = store.upsert_secret_link_with_audit(
        &link,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    Ok(persisted_id)
}

pub fn link_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &LinkArgs,
) -> Result<u8, CliError> {
    let result = (|| -> Result<Value, CliError> {
        let local_name = SecretName::new(args.local_key.clone())
            .map_err(|err| invalid_secret_name_error(err.to_string()))?;
        let raw_target = args.target.strip_prefix("@shared/").unwrap_or(&args.target);
        let target_name = SecretName::new(raw_target.to_owned())
            .map_err(|err| invalid_secret_name_error(err.to_string()))?;
        let resolved = require_project(context)?;
        let mut store = open_store(context)?;
        ensure_trusted_project_root(&store, &resolved)?;
        let profile = default_profile(&store, &resolved.config)?;
        confirm_write(
            &profile,
            args.use_dangerous,
            "pass --use-dangerous to link a secret into a dangerous profile",
        )?;
        let (shared_project, shared_profile) = shared_vault_target(&store)?;
        let target_secret = store
            .get_active_secret(
                &shared_project.id,
                &shared_profile.id,
                target_name.as_str(),
                "user-local",
            )?
            .ok_or_else(|| {
                secret_not_found_error(format!(
                    "secret {} not found in {GLOBAL_VAULT}",
                    target_name.as_str()
                ))
            })?;
        let timestamp = now_unix_nanos()?;
        let link_id = create_link_record_with_audit(
            context,
            &mut store,
            resolved.config.project_id.as_str(),
            &profile.id,
            local_name.as_str(),
            &shared_project.id,
            &shared_profile.id,
            &target_secret,
            timestamp,
        )?;
        refresh_example_for_project_if_enabled(context);
        Ok(json!({
            "link_id": link_id,
            "local_name": local_name.as_str(),
            "profile": profile.name,
            "target_project_id": shared_project.id,
            "target_secret_id": target_secret.id,
            "target_secret_name": target_secret.name,
        }))
    })();
    if args.json {
        return write_json_result(output, result);
    }
    let row = result?;
    writeln!(
        output,
        "linked {} -> {GLOBAL_VAULT}/{} (profile={})",
        row["local_name"].as_str().unwrap_or_default(),
        row["target_secret_name"].as_str().unwrap_or_default(),
        row["profile"].as_str().unwrap_or_default(),
    )?;
    Ok(0)
}

pub fn unlink_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &UnlinkArgs,
) -> Result<u8, CliError> {
    let result = (|| -> Result<Value, CliError> {
        let local_name = SecretName::new(args.local_key.clone())
            .map_err(|err| invalid_secret_name_error(err.to_string()))?;
        let resolved = require_project(context)?;
        let mut store = open_store(context)?;
        ensure_trusted_project_root(&store, &resolved)?;
        let profile = default_profile(&store, &resolved.config)?;
        confirm_write(
            &profile,
            args.use_dangerous,
            "pass --use-dangerous to unlink a secret from a dangerous profile",
        )?;
        let missing_link =
            || secret_not_found_error(format!("no shared link found for {}", local_name.as_str()));
        let existing = store
            .get_secret_link(resolved.config.project_id.as_str(), &profile.id, local_name.as_str())?
            .ok_or_else(missing_link)?;
        let timestamp = now_unix_nanos()?;
        let audit_key = load_project_key(
            context,
            &store,
            resolved.config.project_id.as_str(),
            KeyPurpose::Audit,
        )?;
        let metadata = json!({
            "schema_version": 1,
            "action": "SECRET_UNLINK",
            "status": "SUCCESS",
            "secret_name": local_name.as_str(),
            "profile_id": profile.id,
            "target_project_id": existing.target_project_id,
            "target_profile_id": existing.target_profile_id,
            "target_secret_id": existing.target_secret_id,
        });
        let audit = AuditWrite {
            project_id: resolved.config.project_id.as_str(),
            profile_id: Some(&profile.id),
            action: "SECRET_UNLINK",
            status: "SUCCESS",
            secret_name: Some(local_name.as_str()),
            command: None,
            metadata_json: &metadata,
            timestamp,
        };
        store
            .delete_secret_link_with_audit(
                resolved.config.project_id.as_str(),
                &profile.id,
                local_name.as_str(),
                Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
            )?
            .ok_or_else(missing_link)?;
        refresh_example_for_project_if_enabled(context);
        Ok(json!({
            "local_name": local_name.as_str(),
            "profile": profile.name,
            "unlinked": true,
        }))
    })();
    if args.json {
        return write_json_result(output, result);
    }
    let row = result?;
    writeln!(output, "unlinked {}", row["local_name"].as_str().unwrap_or_default())?;
    Ok(0)
}

#[allow(clippy::too_many_lines)]
pub fn promote_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &PromoteArgs,
) -> Result<u8, CliError> {
    let result = (|| -> Result<Value, CliError> {
        let local_name = SecretName::new(args.key.clone())
            .map_err(|err| invalid_secret_name_error(err.to_string()))?;
        let target_name = match &args.target_name {
            Some(name) => SecretName::new(name.strip_prefix("@shared/").unwrap_or(name).to_owned())
                .map_err(|err| invalid_secret_name_error(err.to_string()))?,
            None => local_name.clone(),
        };
        let resolved = require_project(context)?;
        let mut store = open_store(context)?;
        ensure_trusted_project_root(&store, &resolved)?;
        let source_profile = default_profile(&store, &resolved.config)?;
        confirm_write(
            &source_profile,
            args.use_dangerous,
            "pass --use-dangerous to promote a secret from a dangerous profile",
        )?;
        let (shared_project, shared_profile) = shared_vault_target(&store)?;
        confirm_write(
            &shared_profile,
            args.use_dangerous,
            "pass --use-dangerous to write into a dangerous Global Vault profile",
        )?;
        let project_id = resolved.config.project_id.as_str();
        let summary = store.with_atomic_write(|store| -> Result<Value, CliError> {
            let source_secret = if let Some(source) = args.source.source {
                let source_str = source_arg_to_str(source);
                store
                    .get_active_secret(project_id, &source_profile.id, local_name.as_str(), source_str)?
                    .ok_or_else(|| secret_not_found_error("secret not found"))?
            } else {
                let rows =
                    store.list_secrets_by_name(project_id, &source_profile.id, local_name.as_str())?;
                select_highest_precedence_secret(rows.into_iter().filter(|row| row.state == "active"))
                    .ok_or_else(|| secret_not_found_error("secret not found"))?
            };
            let value = decrypt_secret_version(
                context,
                store,
                project_id,
                &source_profile.id,
                &source_secret,
                source_secret.current_version,
            )?;

            let timestamp = now_unix_nanos()?;
            let shared_keys =
                SecretWriteKeys::load(context, store, &shared_project.id, &shared_profile.id)?;
            let existing_shared = store.get_secret_by_source(
                &shared_project.id,
                &shared_profile.id,
                target_name.as_str(),
                "user-local",
            )?;
            let prior_target_version = existing_shared.as_ref().map(|secret| secret.current_version);
            let (target_secret, action) = if let Some(existing) = existing_shared {
                if existing.state == "deleted" {
                    return Err(secret_deleted_error("the Global Vault secret source is deleted"));
                }
                let same_value = decrypt_secret_version(
                    context,
                    store,
                    &shared_project.id,
                    &shared_profile.id,
                    &existing,
                    existing.current_version,
                )
                .is_ok_and(|existing_val| existing_val.as_str() == value.as_str());
                if same_value {
                    (existing, "reuse")
                } else if args.overwrite {
                    let flags = SecretMetadataFlags::default();
                    let new_ver = rotate_value(
                        store,
                        &shared_keys,
                        &existing,
                        &Rotation {
                            value: &value,
                            origin: "profile-copy",
                            timestamp,
                            grace_until: None,
                            metadata: &flags,
                            action: "ROTATE",
                        },
                    )?;
                    let mut updated = existing;
                    updated.current_version = new_ver;
                    (updated, "rotate")
                } else {
                    return Err(secret_already_exists_error(format!(
                        "{GLOBAL_VAULT}/{} already exists with a different value; pass --as <NAME> or --overwrite",
                        target_name.as_str()
                    )));
                }
            } else {
                let flags = SecretMetadataFlags::default();
                create_value(
                    store,
                    &shared_keys,
                    &NewSecret {
                        project_id: &shared_project.id,
                        profile_id: &shared_profile.id,
                        name: target_name.as_str(),
                        source: "user-local",
                        value: &value,
                        origin: "profile-copy",
                        timestamp,
                        metadata: &flags,
                        action: "SET",
                    },
                )?;
                let created = store
                    .get_active_secret(
                        &shared_project.id,
                        &shared_profile.id,
                        target_name.as_str(),
                        "user-local",
                    )?
                    .ok_or_else(|| secret_not_found_error("promoted Global Vault secret missing"))?;
                (created, "create")
            };

            let source_audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
            SecretTransferAudit {
                action: "SECRET_PROMOTE",
                operation: action,
                from_project_id: project_id,
                from_profile_id: &source_profile.id,
                from_secret: Some(&source_secret),
                target_profile: &shared_profile,
                target_name: target_name.as_str(),
                prior_target_version,
                target_version: target_secret.current_version,
                timestamp,
            }
            .append(store, source_audit_key.as_ref(), shared_keys.audit.as_ref())?;

            let dedup_tag = local_dedup_tag_v1(&shared_keys.fingerprint, &value)?;
            store.upsert_local_value_fingerprint(
                &target_secret.id,
                target_secret.current_version,
                &dedup_tag,
                timestamp,
            )?;

            let linked = if args.keep_local {
                false
            } else {
                create_link_record_with_audit(
                    context,
                    store,
                    project_id,
                    &source_profile.id,
                    local_name.as_str(),
                    &shared_project.id,
                    &shared_profile.id,
                    &target_secret,
                    timestamp,
                )?;
                if source_secret.source == "user-local" {
                    let metadata = secret_audit_metadata(
                        "DELETE",
                        &source_secret.name,
                        &source_profile.id,
                        &source_secret.source,
                        Some(source_secret.current_version),
                    );
                    let audit = AuditWrite {
                        project_id,
                        profile_id: Some(&source_profile.id),
                        action: "DELETE",
                        status: "SUCCESS",
                        secret_name: Some(&source_secret.name),
                        command: None,
                        metadata_json: &metadata,
                        timestamp,
                    };
                    store.tombstone_current_secret_with_audit(
                        &source_secret,
                        timestamp,
                        AuditContext { key: source_audit_key.as_ref(), write: &audit },
                    )?;
                }
                true
            };

            let mut consolidated = Vec::new();
            let mut skipped_projects = 0_u32;
            if args.consolidate_duplicates {
                let matches = store.find_active_secrets_by_dedup_tag(&dedup_tag)?;
                for member in matches {
                    if member.is_shared
                        || member.secret_id == source_secret.id
                        || member.secret_id == target_secret.id
                        || member.source != "user-local"
                    {
                        continue;
                    }
                    if member.profile_dangerous {
                        skipped_projects += 1;
                        continue;
                    }
                    let Some(other_record) = store.get_secret_by_id(&member.secret_id)? else {
                        continue;
                    };
                    if other_record.state != "active" {
                        continue;
                    }
                    let Ok(other_audit_key) =
                        load_project_key(context, store, &member.project_id, KeyPurpose::Audit)
                    else {
                        skipped_projects += 1;
                        continue;
                    };
                    create_link_record_with_audit(
                        context,
                        store,
                        &member.project_id,
                        &member.profile_id,
                        &member.name,
                        &shared_project.id,
                        &shared_profile.id,
                        &target_secret,
                        timestamp,
                    )?;
                    let delete_meta = secret_audit_metadata(
                        "DELETE",
                        &other_record.name,
                        &other_record.profile_id,
                        &other_record.source,
                        Some(other_record.current_version),
                    );
                    let delete_audit = AuditWrite {
                        project_id: &member.project_id,
                        profile_id: Some(&member.profile_id),
                        action: "DELETE",
                        status: "SUCCESS",
                        secret_name: Some(&other_record.name),
                        command: None,
                        metadata_json: &delete_meta,
                        timestamp,
                    };
                    store.tombstone_current_secret_with_audit(
                        &other_record,
                        timestamp,
                        AuditContext { key: other_audit_key.as_ref(), write: &delete_audit },
                    )?;
                    consolidated.push(json!({
                        "project_id": member.project_id,
                        "project_name": member.project_name,
                        "profile_name": member.profile_name,
                        "local_name": member.name,
                    }));
                }
            }

            Ok(json!({
                "local_name": local_name.as_str(),
                "target_project_id": shared_project.id,
                "target_secret_id": target_secret.id,
                "target_secret_name": target_secret.name,
                "version": target_secret.current_version,
                "action": action,
                "linked": linked,
                "consolidated_count": consolidated.len(),
                "consolidated": consolidated,
                "skipped_projects": skipped_projects,
            }))
        })?;
        refresh_example_for_project_if_enabled(context);
        Ok(summary)
    })();
    if args.json {
        return write_json_result(output, result);
    }
    let row = result?;
    let linked_note = if row["linked"].as_bool() == Some(true) {
        " and replaced local copy with live link"
    } else {
        " (kept local copy)"
    };
    writeln!(
        output,
        "promoted {} -> {GLOBAL_VAULT}/{} ({}, v{}){linked_note}",
        row["local_name"].as_str().unwrap_or_default(),
        row["target_secret_name"].as_str().unwrap_or_default(),
        row["action"].as_str().unwrap_or_default(),
        row["version"].as_u64().unwrap_or(1),
    )?;
    let consolidated_count = row["consolidated_count"].as_u64().unwrap_or(0);
    if consolidated_count > 0 {
        writeln!(output, "consolidated {consolidated_count} duplicate project copy(s) into links")?;
    }
    let skipped = row["skipped_projects"].as_u64().unwrap_or(0);
    if skipped > 0 {
        writeln!(output, "skipped {skipped} locked or dangerous duplicate project(s)")?;
    }
    Ok(0)
}

pub fn shared_usages_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &SharedUsagesArgs,
) -> Result<u8, CliError> {
    let result = (|| -> Result<Value, CliError> {
        let name = SecretName::new(args.key.clone())
            .map_err(|err| invalid_secret_name_error(err.to_string()))?;
        let store = crate::commands::discovery::require_metadata_store(context)?;
        let (shared_project, shared_profile) = shared_vault_target(&store)?;
        let secret = store
            .get_active_secret(&shared_project.id, &shared_profile.id, name.as_str(), "user-local")?
            .ok_or_else(|| {
                secret_not_found_error(format!(
                    "secret {} not found in {GLOBAL_VAULT}",
                    name.as_str()
                ))
            })?;
        let usages = store.list_shared_secret_usages(&secret.id)?;
        let rows: Vec<Value> = usages
            .iter()
            .map(|usage| {
                json!({
                    "link_id": usage.link_id,
                    "project_id": usage.project_id,
                    "project_name": usage.project_name,
                    "profile_id": usage.profile_id,
                    "profile_name": usage.profile_name,
                    "profile_dangerous": usage.profile_dangerous,
                    "local_name": usage.local_name,
                })
            })
            .collect();
        Ok(json!({
            "secret_id": secret.id,
            "secret_name": secret.name,
            "usage_count": rows.len(),
            "usages": rows,
        }))
    })();
    if args.json {
        return write_json_result(output, result);
    }
    let row = result?;
    let secret_name = row["secret_name"].as_str().unwrap_or_default();
    let usages = row["usages"].as_array().map_or(&[][..], Vec::as_slice);
    if usages.is_empty() {
        writeln!(output, "{GLOBAL_VAULT}/{secret_name}: not linked by any project")?;
        return Ok(0);
    }
    writeln!(output, "{GLOBAL_VAULT}/{secret_name} is used by {} project link(s):", usages.len())?;
    for usage in usages {
        let danger =
            if usage["profile_dangerous"].as_bool() == Some(true) { " [dangerous]" } else { "" };
        writeln!(
            output,
            "  {} ({}{}) -> {}",
            usage["project_name"].as_str().unwrap_or_default(),
            usage["profile_name"].as_str().unwrap_or_default(),
            danger,
            usage["local_name"].as_str().unwrap_or_default(),
        )?;
    }
    Ok(0)
}

#[allow(clippy::too_many_lines)]
pub fn duplicates_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DuplicatesArgs,
) -> Result<u8, CliError> {
    let result = (|| -> Result<Value, CliError> {
        let store = if args.reindex {
            open_store(context)?
        } else {
            crate::commands::discovery::require_metadata_store(context)?
        };
        let mut reindexed = 0_u32;
        if args.reindex {
            let (shared_project, shared_profile) = shared_vault_target(&store)?;
            let shared_fp_key = load_profile_key(
                context,
                &store,
                &shared_project.id,
                &shared_profile.id,
                KeyPurpose::ProfileFingerprint,
            )?;
            let timestamp = now_unix_nanos()?;
            for project in store.list_projects()? {
                for profile in store.list_profiles(&project.id)? {
                    for secret in store.list_active_secrets_by_profile(&project.id, &profile.id)? {
                        if let Ok(value) = decrypt_secret_version(
                            context,
                            &store,
                            &project.id,
                            &profile.id,
                            &secret,
                            secret.current_version,
                        ) && let Ok(tag) = local_dedup_tag_v1(&shared_fp_key, &value)
                        {
                            store.upsert_local_value_fingerprint(
                                &secret.id,
                                secret.current_version,
                                &tag,
                                timestamp,
                            )?;
                            reindexed += 1;
                        }
                    }
                }
            }
        }
        let groups = store.list_duplicate_value_groups()?;
        let rows: Vec<Value> = groups
            .into_iter()
            .enumerate()
            .map(|(index, group)| {
                let members: Vec<Value> = group
                    .members
                    .into_iter()
                    .map(|member| {
                        json!({
                            "secret_id": member.secret_id,
                            "project_id": member.project_id,
                            "project_name": member.project_name,
                            "is_shared": member.is_shared,
                            "profile_name": member.profile_name,
                            "profile_dangerous": member.profile_dangerous,
                            "name": member.name,
                            "source": member.source,
                            "version": member.current_version,
                        })
                    })
                    .collect();
                json!({
                    "group_id": format!("dup-{}", index + 1),
                    "count": members.len(),
                    "members": members,
                })
            })
            .collect();
        Ok(json!({
            "reindexed": reindexed,
            "group_count": rows.len(),
            "groups": rows,
        }))
    })();
    if args.json {
        return write_json_result(output, result);
    }
    let row = result?;
    let groups = row["groups"].as_array().map_or(&[][..], Vec::as_slice);
    if groups.is_empty() {
        writeln!(output, "no duplicate secret values detected")?;
        return Ok(0);
    }
    writeln!(output, "found {} duplicate value group(s) (metadata only):", groups.len())?;
    for group in groups {
        writeln!(
            output,
            "  {} ({} copies):",
            group["group_id"].as_str().unwrap_or_default(),
            group["count"].as_u64().unwrap_or(0),
        )?;
        if let Some(members) = group["members"].as_array() {
            for member in members {
                writeln!(
                    output,
                    "    - {} / {} / {} ({})",
                    member["project_name"].as_str().unwrap_or_default(),
                    member["profile_name"].as_str().unwrap_or_default(),
                    member["name"].as_str().unwrap_or_default(),
                    member["source"].as_str().unwrap_or_default(),
                )?;
            }
        }
    }
    writeln!(
        output,
        "tip: run `locket promote <KEY> --consolidate-duplicates` inside a project to store once in {GLOBAL_VAULT} and link everywhere."
    )?;
    Ok(0)
}
