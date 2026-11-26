//! Dotenv import and discovery for the CLI and MCP.

#[path = "env_files.rs"]
mod env_files;

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use locket_core::{LocketError, ProfileName, SecretName};
use locket_crypto::{KeyBytes, KeyPurpose, local_dedup_tag_v1};
use locket_store::{
    AuditContext, AuditWrite, ProfileRecord, SecretRecord, SecretTransferAudit, Store,
};
use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroizing;

use self::env_files::{
    Diagnostic, ParsedEnvFile, open_env_file, read_env_file, write_env_keys, write_env_scan,
    write_warnings,
};
#[allow(clippy::redundant_pub_crate, reason = "Crate-level API shared with MCP")]
pub(crate) use self::env_files::{
    InputDirectory, input_parent, inspect_open_env_file, open_scoped_file, scan_open_workspace,
};
use self::env_files::{inspect_env_file_keys, scan_workspace_env_files};
use super::links::{
    CliDuplicateMatch, create_link_record_with_audit, find_duplicate_matches_for_value,
    shared_vault_target, try_load_shared_fingerprint_key_non_interactive,
};
use super::set::{
    NewSecret, Rotation, SecretWriteKeys, WriteTarget, confirm_write, create_value, rotate_value,
    select_target,
};
use crate::commands::discovery::{
    require_metadata_store, trusted_project_configs, write_json_result,
};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, confirmation_failed_error, invalid_profile_name_error, invalid_secret_name_error,
    metadata_invalid_error, profile_not_found_error, secret_not_found_error, typed_cli_error,
};
use crate::runtime::prompts::ConfirmationReader;
use crate::support::project_files::{ensure_gitignore, refresh_example_for_project_if_enabled};
use crate::{
    EnvFileCommand, ImportArgs, ImportSelectionArgs, ResolvedProject, SecretMetadataFlags,
    SecretSourceArg, absolutize, active_profile_secret_names, ensure_trusted_project_root,
    load_project_key, now_unix_nanos, open_store, project_not_found_error, require_project,
    secret_audit_metadata, secret_deleted_error, source_arg_to_str,
};

/// Key selection and write policy for a dotenv import.
#[allow(
    clippy::redundant_pub_crate,
    clippy::struct_excessive_bools,
    reason = "Crate-level API shared with MCP"
)]
pub(crate) struct EnvImportOptions {
    pub only: Vec<String>,
    pub exclude: Vec<String>,
    pub overwrite: bool,
    pub literal: bool,
    pub dry_run: bool,
    pub link_shared: bool,
    pub promote_duplicates: bool,
    pub confirmed_profiles: Vec<String>,
    pub source: SecretSourceArg,
}

pub fn env_file_command(
    cwd: &Path,
    output: &mut impl Write,
    command: EnvFileCommand,
) -> Result<u8, CliError> {
    match command {
        EnvFileCommand::Keys { file, literal, json } => {
            let path = absolutize(cwd, &file);
            if json {
                return write_json_result(output, inspect_env_file_keys(&path, literal));
            }
            write_env_keys(output, &path, literal)?;
        }
        EnvFileCommand::Scan { path, depth, literal, json } => {
            let root = absolutize(cwd, path.as_deref().unwrap_or_else(|| Path::new(".")));
            if json {
                return write_json_result(output, scan_workspace_env_files(&root, depth, literal));
            }
            write_env_scan(output, &root, depth, literal)?;
        }
    }
    Ok(0)
}

/// Import into an already resolved target or compare keys without writing.
///
/// Reads the supplied handle and leaves the source and project files untouched.
#[allow(clippy::redundant_pub_crate, reason = "Crate-level API shared with MCP")]
pub(crate) fn import_env_to_target(
    context: &RuntimeContext,
    store: &mut Store,
    target: &WriteTarget,
    env_file: fs::File,
    options: &EnvImportOptions,
) -> Result<Value, CliError> {
    let report = run_import(context, store, target, env_file, options, |_, _| Ok(()))?;
    Ok(serde_json::to_value(report)?)
}

pub fn import_selected_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ImportArgs,
    selection: &ImportSelectionArgs,
) -> Result<u8, CliError> {
    let result = import_cli(context, output, args, selection);
    if selection.json {
        return write_json_result(output, result);
    }
    result?;
    Ok(0)
}

fn import_cli(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ImportArgs,
    selection: &ImportSelectionArgs,
) -> Result<Value, CliError> {
    let resolved = selection.project.is_none().then(|| require_project(context)).transpose()?;
    let mut store =
        if selection.dry_run { require_metadata_store(context)? } else { open_store(context)? };
    let target = if let Some(resolved) = &resolved {
        ensure_trusted_project_root(&store, resolved)?;
        let profile = import_target_profile(&store, resolved, args.profile.as_deref())?;
        let project = store
            .get_project(resolved.config.project_id.as_str())?
            .ok_or_else(project_not_found_error)?;
        WriteTarget { project, profile }
    } else {
        if let Some(profile) = &args.profile {
            ProfileName::new(profile.clone())
                .map_err(|_| invalid_profile_name_error("invalid profile name"))?;
        }
        select_target(context, &store, selection.project.as_deref(), args.profile.as_deref())?
    };
    let mut confirmed_profiles = selection.confirm_dangerous.clone();
    if args.overwrite && !selection.dry_run && target.profile.dangerous {
        if let Some(confirmation) = confirmed_profiles.first() {
            if !profile_is_confirmed(&confirmed_profiles, &target.profile) {
                validate_overwrite_confirmation(&target.profile, confirmation)?;
            }
        } else if selection.json {
            confirm_write(
                &target.profile,
                false,
                "pass --confirm-dangerous with the profile name to confirm the overwrite",
            )?;
        } else {
            confirm_dangerous_import_overwrite(
                output,
                &target.profile,
                context.confirmation_reader.as_ref(),
            )?;
            confirmed_profiles.push(target.profile.name.clone());
        }
    }
    let root = if selection.dry_run || target.project.id.starts_with("lk_proj_shared_") {
        None
    } else if let Some(resolved) = resolved {
        Some(resolved.root)
    } else {
        import_project_root(context, &store, &target, selection.project.as_deref())?
    };
    let path = absolutize(&context.cwd, Path::new(&args.file));
    let options = EnvImportOptions {
        only: selection.only.clone(),
        exclude: selection.exclude.clone(),
        overwrite: args.overwrite,
        literal: args.literal,
        dry_run: selection.dry_run,
        link_shared: selection.link_shared,
        promote_duplicates: selection.promote_duplicates,
        confirmed_profiles,
        source: args.source.unwrap_or(SecretSourceArg::UserLocal),
    };
    let file = open_env_file(&path)?;
    if selection.json {
        let report = import_env_to_target(context, &mut store, &target, file, &options)?;
        refresh_import_project_files(context, root)?;
        return Ok(report);
    }
    let report = run_import(context, &mut store, &target, file, &options, |warnings, errors| {
        write_import_diagnostics(output, warnings, errors)
    })?;
    refresh_import_project_files(context, root)?;
    write_import_report(context, output, selection, &path, &report)?;
    Ok(Value::Null)
}

fn import_project_root(
    context: &RuntimeContext,
    store: &Store,
    target: &WriteTarget,
    selector: Option<&str>,
) -> Result<Option<PathBuf>, CliError> {
    let roots = trusted_project_configs(store, &target.project.id)?;
    let selected_path = selector
        .and_then(|selector| absolutize(&context.cwd, Path::new(selector)).canonicalize().ok());
    let cwd = context.cwd.canonicalize().ok();
    let selected = roots
        .iter()
        .find(|resolved| selected_path.as_ref() == Some(&resolved.root))
        .or_else(|| {
            roots
                .iter()
                .filter(|resolved| cwd.as_ref().is_some_and(|cwd| cwd.starts_with(&resolved.root)))
                .max_by_key(|resolved| resolved.root.components().count())
        })
        .or_else(|| roots.first());
    Ok(selected.map(|resolved| resolved.root.clone()))
}

fn refresh_import_project_files(
    context: &RuntimeContext,
    root: Option<PathBuf>,
) -> Result<(), CliError> {
    if let Some(root) = root {
        let root_context = RuntimeContext { cwd: root, ..context.clone() };
        refresh_example_for_project_if_enabled(&root_context);
        ensure_gitignore(&root_context.cwd)?;
    }
    Ok(())
}

fn write_import_diagnostics(
    output: &mut impl Write,
    warnings: &[Diagnostic],
    errors: &[Diagnostic],
) -> Result<(), CliError> {
    write_warnings(output, warnings)?;
    if !errors.is_empty() {
        writeln!(output, "imported: 0")?;
        writeln!(output, "invalid: {}", errors.len())?;
        writeln!(output, "delete_env: kept")?;
        writeln!(output, "metadata_only: yes")?;
    }
    Ok(())
}

fn write_import_report(
    context: &RuntimeContext,
    output: &mut impl Write,
    selection: &ImportSelectionArgs,
    path: &Path,
    report: &ImportReport,
) -> Result<(), CliError> {
    let prefix = if selection.dry_run { "would_" } else { "" };
    let (import, overwrite, skip) = if selection.dry_run {
        ("import", "overwrite", "skip")
    } else {
        ("imported", "overwritten", "skipped")
    };
    writeln!(output, "{prefix}{import}: {}", report.imported)?;
    writeln!(output, "{prefix}{overwrite}: {}", report.overwritten)?;
    writeln!(output, "{prefix}{skip}: {}", report.skipped)?;
    if selection.link_shared || report.linked > 0 {
        let label = if selection.dry_run { "would_link" } else { "linked" };
        writeln!(output, "{label}: {}", report.linked)?;
    }
    if selection.promote_duplicates || report.promoted > 0 {
        let label = if selection.dry_run { "would_promote" } else { "promoted" };
        writeln!(output, "{label}: {}", report.promoted)?;
    }
    if !report.duplicate_matches.is_empty() {
        writeln!(output, "duplicate_matches: {}", report.duplicate_matches.len())?;
        for matched in &report.duplicate_matches {
            writeln!(
                output,
                "  match {} == {} / {} / {} ({})",
                matched.local_name,
                matched.matched_project_name,
                matched.matched_profile_name,
                matched.matched_secret_name,
                matched.match_kind,
            )?;
        }
    }
    if !selection.only.is_empty() || !selection.exclude.is_empty() {
        writeln!(output, "filtered_out: {}", report.filtered_out)?;
        writeln!(output, "filtered_out_names: {}", format_name_set(&report.filtered_out_names))?;
    }
    writeln!(output, "invalid: 0")?;
    writeln!(output, "profile: {}", report.profile)?;
    writeln!(output, "source: {}", report.source)?;
    writeln!(output, "env_names: {}", report.env_names.len())?;
    writeln!(output, "profile_names: {}", report.profile_name_count)?;
    writeln!(output, "skipped_names: {}", format_name_set(&report.skipped_names))?;
    writeln!(output, "missing_in_profile: {}", format_name_set(&report.missing_in_profile))?;
    writeln!(output, "extra_in_profile: {}", format_name_set(&report.extra_in_profile))?;
    if !selection.keep
        && !selection.dry_run
        && report.filtered_out == 0
        && report.skipped == 0
        && report.imported + report.overwritten > 0
    {
        write_env_delete_prompt(output, path, context.confirmation_reader.as_ref())?;
    } else {
        writeln!(output, "delete_env: kept")?;
    }
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

#[derive(Serialize)]
struct ImportReport {
    project_id: String,
    project_name: String,
    profile: String,
    source: &'static str,
    dry_run: bool,
    imported: usize,
    overwritten: usize,
    skipped: usize,
    #[serde(skip_serializing_if = "is_zero_usize")]
    linked: usize,
    #[serde(skip_serializing_if = "is_zero_usize")]
    promoted: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    duplicate_matches: Vec<CliDuplicateMatch>,
    filtered_out: usize,
    invalid: usize,
    env_names: BTreeSet<String>,
    imported_names: BTreeSet<String>,
    overwritten_names: BTreeSet<String>,
    skipped_names: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    linked_names: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    promoted_names: BTreeSet<String>,
    filtered_out_names: BTreeSet<String>,
    missing_in_profile: BTreeSet<String>,
    extra_in_profile: BTreeSet<String>,
    warnings: Vec<Diagnostic>,
    delete_env: &'static str,
    metadata_only: bool,
    #[serde(skip)]
    profile_name_count: usize,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}

fn run_import(
    context: &RuntimeContext,
    store: &mut Store,
    target: &WriteTarget,
    file: fs::File,
    options: &EnvImportOptions,
    diagnostics: impl FnOnce(&[Diagnostic], &[Diagnostic]) -> Result<(), CliError>,
) -> Result<ImportReport, CliError> {
    let only = import_filter(&options.only)?;
    let exclude = import_filter(&options.exclude)?;
    let ParsedEnvFile { entries, warnings, errors } = read_env_file(file, options.literal)?;
    if !errors.is_empty() {
        drop(entries);
        diagnostics(&warnings, &errors)?;
        return Err(metadata_invalid_error(
            errors
                .iter()
                .map(|error| format!("line {}: {}", error.line, error.message))
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }

    let mut filtered_out_names = BTreeSet::new();
    let mut values = Vec::new();
    for (name, value) in entries {
        if (!only.is_empty() && !only.contains(&name)) || exclude.contains(&name) {
            filtered_out_names.insert(name);
        } else {
            values.push((name, value));
        }
    }
    diagnostics(&warnings, &errors)?;

    let source = source_arg_to_str(options.source);
    let env_names: BTreeSet<String> = values.iter().map(|(name, _)| name.clone()).collect();
    // Plan from the same pre-write snapshot for both reports. Real imports keep
    // the plan and its writes in a single transaction.
    let plan_and_apply = |store: &mut Store| {
        let planner = ImportPlanner::load(context, store, target, source, options)?;
        let mut profile_names =
            active_profile_secret_names(store, &target.project.id, &target.profile.id)?;
        let plan = planner.plan(store, &values)?;
        let mut counts = ImportNames::default();
        for ((name, _), action) in values.iter().zip(&plan.actions) {
            match action {
                ImportAction::Import => &mut counts.imported,
                ImportAction::Overwrite(_) => &mut counts.overwritten,
                ImportAction::Skip => &mut counts.skipped,
                ImportAction::Link { .. } => &mut counts.linked,
                ImportAction::Promote { .. } => &mut counts.promoted,
            }
            .insert(name.clone());
        }
        profile_names
            .extend(counts.imported.iter().chain(&counts.linked).chain(&counts.promoted).cloned());
        if !options.dry_run {
            apply_import(context, store, &planner, values, plan.actions)?;
        }
        Ok::<_, CliError>((counts, plan.duplicate_matches, profile_names))
    };
    let (counts, duplicate_matches, profile_names) = if options.dry_run {
        plan_and_apply(store)?
    } else {
        store.with_atomic_write(plan_and_apply)?
    };
    let missing_in_profile = env_names.difference(&profile_names).cloned().collect();
    let extra_in_profile = profile_names.difference(&env_names).cloned().collect();
    Ok(ImportReport {
        project_id: target.project.id.clone(),
        project_name: target.project.name.clone(),
        profile: target.profile.name.clone(),
        source,
        dry_run: options.dry_run,
        imported: counts.imported.len(),
        overwritten: counts.overwritten.len(),
        skipped: counts.skipped.len(),
        linked: counts.linked.len(),
        promoted: counts.promoted.len(),
        duplicate_matches,
        filtered_out: filtered_out_names.len(),
        invalid: 0,
        env_names,
        imported_names: counts.imported,
        overwritten_names: counts.overwritten,
        skipped_names: counts.skipped,
        linked_names: counts.linked,
        promoted_names: counts.promoted,
        filtered_out_names,
        missing_in_profile,
        extra_in_profile,
        warnings,
        delete_env: "kept",
        metadata_only: true,
        profile_name_count: profile_names.len(),
    })
}

fn import_filter(values: &[String]) -> Result<BTreeSet<String>, CliError> {
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(|key| {
            SecretName::new(key.trim())
                .map(SecretName::into_string)
                .map_err(|_| invalid_secret_name_error("invalid key in import filter"))
        })
        .collect()
}

#[derive(Default)]
struct ImportNames {
    imported: BTreeSet<String>,
    overwritten: BTreeSet<String>,
    skipped: BTreeSet<String>,
    linked: BTreeSet<String>,
    promoted: BTreeSet<String>,
}

enum ImportAction {
    Import,
    Overwrite(Box<SecretRecord>),
    Skip,
    Link { target: Box<SecretRecord>, shadowing: Vec<SecretRecord> },
    Promote { shadowing: Vec<SecretRecord> },
}

struct ImportPlan {
    actions: Vec<ImportAction>,
    duplicate_matches: Vec<CliDuplicateMatch>,
}

struct ImportPlanner<'a> {
    target: &'a WriteTarget,
    source: &'static str,
    options: &'a EnvImportOptions,
    shared_profile: Option<ProfileRecord>,
    shared_fp_key: Option<Zeroizing<KeyBytes>>,
}

impl<'a> ImportPlanner<'a> {
    fn load(
        context: &RuntimeContext,
        store: &Store,
        target: &'a WriteTarget,
        source: &'static str,
        options: &'a EnvImportOptions,
    ) -> Result<Self, CliError> {
        let shared_profile = if options.link_shared || options.promote_duplicates {
            let (project, profile) = shared_vault_target(store)?;
            if target.project.id == project.id {
                return Err(metadata_invalid_error(
                    "shared deduplication requires a consuming project vault",
                ));
            }
            Some(profile)
        } else {
            None
        };
        let shared_fp_key = try_load_shared_fingerprint_key_non_interactive(context, store);
        if shared_profile.is_some() && shared_fp_key.is_none() {
            return Err(typed_cli_error(
                LocketError::UnlockRequired,
                "unlock the Global Vault with `locket unlock --shared` before importing shared secrets",
            ));
        }
        Ok(Self { target, source, options, shared_profile, shared_fp_key })
    }

    fn plan(
        &self,
        store: &Store,
        values: &[(String, Zeroizing<String>)],
    ) -> Result<ImportPlan, CliError> {
        let mut plan =
            ImportPlan { actions: Vec::with_capacity(values.len()), duplicate_matches: Vec::new() };
        for (name, value) in values {
            let project_id = &self.target.project.id;
            let profile_id = &self.target.profile.id;
            let existing = store.get_secret_by_source(project_id, profile_id, name, self.source)?;
            let mut matches = self
                .shared_fp_key
                .as_ref()
                .map(|key| {
                    find_duplicate_matches_for_value(
                        store, key, project_id, profile_id, name, value,
                    )
                })
                .transpose()?
                .unwrap_or_default();
            let action = match &self.shared_profile {
                Some(profile) => self.plan_shared(store, profile, name, &matches)?,
                None => None,
            };
            plan.actions.push(match (action, existing) {
                (Some(action), _) => action,
                (None, Some(secret)) if secret.state != "active" => {
                    return Err(secret_deleted_error("secret source is deleted"));
                }
                (None, Some(secret)) if self.options.overwrite => {
                    ImportAction::Overwrite(Box::new(secret))
                }
                (None, Some(_)) => ImportAction::Skip,
                (None, None) => ImportAction::Import,
            });
            plan.duplicate_matches.append(&mut matches);
        }
        Ok(plan)
    }

    fn plan_shared(
        &self,
        store: &Store,
        shared: &ProfileRecord,
        name: &str,
        matches: &[CliDuplicateMatch],
    ) -> Result<Option<ImportAction>, CliError> {
        let project_id = &self.target.project.id;
        let profile_id = &self.target.profile.id;
        let link = store.get_secret_link(project_id, profile_id, name)?;
        let mut matches_in_vault = matches.iter().filter(|matched| {
            matched.matched_project_id == shared.project_id
                && matched.matched_profile_name == shared.name
        });
        let target = if self.options.link_shared {
            let matching_link = link.as_ref().and_then(|link| {
                matches_in_vault
                    .clone()
                    .find(|matched| matched.matched_secret_id == link.target_secret_id)
            });
            matching_link
                .or_else(|| matches_in_vault.next())
                .map(|matched| {
                    store
                        .get_secret_by_id(&matched.matched_secret_id)?
                        .filter(|target| target.state == "active" && target.profile_id == shared.id)
                        .ok_or_else(|| {
                            secret_not_found_error(
                                "matching Global Vault secret is no longer active",
                            )
                        })
                })
                .transpose()?
        } else {
            None
        };
        let promote = target.is_none()
            && self.options.promote_duplicates
            && !matches.iter().any(|matched| matched.matched_project_id == shared.project_id)
            && matches
                .iter()
                .any(|matched| !matched.is_shared && matched.matched_project_id != *project_id)
            && store.list_secrets_by_name(&shared.project_id, &shared.id, name)?.is_empty();
        if target.is_none() && !promote {
            return Ok(None);
        }
        let shadowing = store
            .list_secrets_by_name(project_id, profile_id, name)?
            .into_iter()
            .filter(|secret| {
                secret.state == "active"
                    && matches!(secret.source.as_str(), "machine-local" | "user-local")
            })
            .collect::<Vec<_>>();
        let retargets_link = link.as_ref().is_some_and(|link| {
            target.as_ref().is_none_or(|target| link.target_secret_id != target.id)
        });
        if !self.options.overwrite && (!shadowing.is_empty() || retargets_link) {
            return Ok(Some(ImportAction::Skip));
        }
        Ok(Some(match target {
            Some(target) => ImportAction::Link { target: Box::new(target), shadowing },
            None => ImportAction::Promote { shadowing },
        }))
    }
}

fn apply_import(
    context: &RuntimeContext,
    store: &mut Store,
    planner: &ImportPlanner<'_>,
    values: Vec<(String, Zeroizing<String>)>,
    actions: Vec<ImportAction>,
) -> Result<(), CliError> {
    let profile = store
        .get_profile_by_name(&planner.target.project.id, &planner.target.profile.name)?
        .filter(|profile| profile.id == planner.target.profile.id)
        .ok_or_else(|| profile_not_found_error("target profile changed; retry the import"))?;
    if planner.options.overwrite
        || actions.iter().any(|action| {
            matches!(action, ImportAction::Link { .. } | ImportAction::Promote { .. })
        })
    {
        confirm_write(
            &profile,
            profile_is_confirmed(&planner.options.confirmed_profiles, &profile),
            "pass --confirm-dangerous with the consuming profile name",
        )?;
    }
    if let Some(shared) = &planner.shared_profile
        && actions.iter().any(|action| matches!(action, ImportAction::Promote { .. }))
    {
        confirm_write(
            shared,
            profile_is_confirmed(&planner.options.confirmed_profiles, shared),
            "pass --confirm-dangerous with the Global Vault profile name",
        )?;
    }

    let mut keys = None;
    for ((name, value), action) in values.into_iter().zip(actions) {
        match action {
            ImportAction::Skip => {}
            ImportAction::Link { target, shadowing } => {
                link_import(
                    context,
                    store,
                    &profile,
                    &name,
                    &target,
                    &shadowing,
                    now_unix_nanos()?,
                )?;
            }
            ImportAction::Promote { shadowing } => {
                promote_import(context, store, planner, &name, &value, &shadowing)?;
            }
            ImportAction::Import | ImportAction::Overwrite(_) => {
                let keys = match &keys {
                    Some(keys) => keys,
                    None => keys.insert(SecretWriteKeys::load(
                        context,
                        store,
                        &profile.project_id,
                        &profile.id,
                    )?),
                };
                write_imported_value(store, planner, keys, &name, &value, action)?;
            }
        }
    }
    Ok(())
}

fn write_imported_value(
    store: &mut Store,
    planner: &ImportPlanner<'_>,
    keys: &SecretWriteKeys,
    name: &str,
    value: &str,
    action: ImportAction,
) -> Result<(), CliError> {
    let project_id = &planner.target.project.id;
    let profile_id = &planner.target.profile.id;
    let source = planner.source;
    let timestamp = now_unix_nanos()?;
    let metadata = SecretMetadataFlags::default();
    let (id, version) = if let ImportAction::Overwrite(secret) = action {
        let version = rotate_value(
            store,
            keys,
            &secret,
            &Rotation {
                value,
                origin: "imported",
                timestamp,
                grace_until: None,
                metadata: &metadata,
                action: "ROTATE",
            },
        )?;
        (secret.id, version)
    } else {
        create_value(
            store,
            keys,
            &NewSecret {
                project_id,
                profile_id,
                name,
                source,
                value,
                origin: "imported",
                timestamp,
                metadata: &metadata,
                action: "IMPORT",
            },
        )?;
        let created = store
            .get_active_secret(project_id, profile_id, name, source)?
            .ok_or_else(|| secret_not_found_error("imported secret missing"))?;
        (created.id, created.current_version)
    };
    if let Some(fp_key) = &planner.shared_fp_key {
        let tag = local_dedup_tag_v1(fp_key, value)?;
        store.upsert_local_value_fingerprint(&id, version, &tag, timestamp)?;
    }
    Ok(())
}

fn promote_import(
    context: &RuntimeContext,
    store: &mut Store,
    planner: &ImportPlanner<'_>,
    name: &str,
    value: &str,
    shadowing: &[SecretRecord],
) -> Result<(), CliError> {
    let profile = &planner.target.profile;
    let shared = planner.shared_profile.as_ref().ok_or_else(project_not_found_error)?;
    let timestamp = now_unix_nanos()?;
    let shared_keys = SecretWriteKeys::load(context, store, &shared.project_id, &shared.id)?;
    create_value(
        store,
        &shared_keys,
        &NewSecret {
            project_id: &shared.project_id,
            profile_id: &shared.id,
            name,
            value,
            timestamp,
            source: "user-local",
            origin: "imported",
            metadata: &SecretMetadataFlags::default(),
            action: "IMPORT",
        },
    )?;
    let target = store
        .get_active_secret(&shared.project_id, &shared.id, name, "user-local")?
        .ok_or_else(|| secret_not_found_error("promoted Global Vault secret missing"))?;
    let tag = local_dedup_tag_v1(&shared_keys.fingerprint, value)?;
    store.upsert_local_value_fingerprint(&target.id, target.current_version, &tag, timestamp)?;
    let source_audit = load_project_key(context, store, &profile.project_id, KeyPurpose::Audit)?;
    SecretTransferAudit {
        action: "SECRET_PROMOTE",
        operation: "create",
        from_project_id: &profile.project_id,
        from_profile_id: &profile.id,
        from_secret: None,
        target_profile: shared,
        target_name: name,
        prior_target_version: None,
        target_version: target.current_version,
        timestamp,
    }
    .append(store, source_audit.as_ref(), shared_keys.audit.as_ref())?;
    link_import(context, store, profile, name, &target, shadowing, timestamp)
}

fn link_import(
    context: &RuntimeContext,
    store: &mut Store,
    profile: &ProfileRecord,
    name: &str,
    target: &SecretRecord,
    shadowing: &[SecretRecord],
    timestamp: i64,
) -> Result<(), CliError> {
    create_link_record_with_audit(
        context,
        store,
        &profile.project_id,
        &profile.id,
        name,
        &target.project_id,
        &target.profile_id,
        target,
        timestamp,
    )?;
    if !shadowing.is_empty() {
        let key = load_project_key(context, store, &profile.project_id, KeyPurpose::Audit)?;
        for secret in shadowing {
            let metadata = secret_audit_metadata(
                "DELETE",
                name,
                &profile.id,
                &secret.source,
                Some(secret.current_version),
            );
            let audit = AuditWrite {
                project_id: &profile.project_id,
                profile_id: Some(&profile.id),
                action: "DELETE",
                status: "SUCCESS",
                secret_name: Some(name),
                command: None,
                metadata_json: &metadata,
                timestamp,
            };
            store.tombstone_current_secret_with_audit(
                secret,
                timestamp,
                AuditContext { key: key.as_ref(), write: &audit },
            )?;
        }
    }
    Ok(())
}

fn import_target_profile(
    store: &Store,
    resolved: &ResolvedProject,
    profile_name: Option<&str>,
) -> Result<ProfileRecord, CliError> {
    let profile_name = profile_name.unwrap_or(resolved.config.default_profile.as_str());
    let profile_name = ProfileName::new(profile_name.to_owned())
        .map_err(|_| invalid_profile_name_error("invalid profile name"))?;
    store
        .get_profile_by_name(resolved.config.project_id.as_str(), profile_name.as_str())?
        .ok_or_else(|| profile_not_found_error("profile not found"))
}

fn confirm_dangerous_import_overwrite(
    output: &mut impl Write,
    profile: &ProfileRecord,
    confirmation_reader: &dyn ConfirmationReader,
) -> Result<(), CliError> {
    writeln!(output, "dangerous_profile: {}", profile.name)?;
    writeln!(output, "metadata_only: yes")?;
    let prompt = format!("type '{}' to confirm dangerous import overwrite", profile.name);
    writeln!(output, "{prompt}")?;
    let confirmation = confirmation_reader.read_confirmation(&prompt)?;
    validate_overwrite_confirmation(profile, &confirmation)
}

fn profile_is_confirmed(confirmations: &[String], profile: &ProfileRecord) -> bool {
    confirmations.iter().any(|name| name.trim_end() == profile.name)
}

fn validate_overwrite_confirmation(
    profile: &ProfileRecord,
    confirmation: &str,
) -> Result<(), CliError> {
    if confirmation.trim_end() != profile.name {
        return Err(confirmation_failed_error(format!(
            "dangerous profile import overwrite confirmation did not match '{}'",
            profile.name
        )));
    }
    Ok(())
}

fn format_name_set(names: &BTreeSet<String>) -> String {
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

fn write_env_delete_prompt(
    output: &mut impl Write,
    path: &Path,
    confirmation_reader: &dyn ConfirmationReader,
) -> Result<(), CliError> {
    if path.file_name().and_then(OsStr::to_str) != Some(".env") {
        writeln!(output, "delete_env_prompt: not_applicable")?;
        return Ok(());
    }
    writeln!(output, "delete_env_prompt: type 'delete .env' to remove the plaintext .env file")?;
    output.flush()?;
    let Ok(confirmation) = confirmation_reader
        .read_confirmation("type 'delete .env' to remove the plaintext .env file")
    else {
        writeln!(output, "delete_env_prompt: skipped_noninteractive")?;
        writeln!(output, "delete_env: kept")?;
        return Ok(());
    };
    if confirmation.trim_end() == "delete .env" {
        fs::remove_file(path)?;
        writeln!(output, "delete_env: deleted")?;
    } else {
        writeln!(output, "delete_env: kept")?;
    }
    Ok(())
}

#[cfg(test)]
pub enum EnvImportEntry {
    Secret { key: String, value: String },
    Invalid,
}

/// Legacy line-oriented regression helper. Strict commands use `parse_dotenv`.
#[cfg(test)]
pub fn parse_env_import(content: &str) -> Vec<EnvImportEntry> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            Some(parse_env_line(trimmed))
        })
        .collect()
}

#[cfg(test)]
fn parse_env_line(line: &str) -> EnvImportEntry {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let Some((key, value)) = line.split_once('=') else {
        return EnvImportEntry::Invalid;
    };
    let key = key.trim();
    if SecretName::new(key.to_owned()).is_err() {
        return EnvImportEntry::Invalid;
    }
    let raw_value = value.trim();
    if has_unmatched_env_quote(raw_value) {
        return EnvImportEntry::Invalid;
    }
    let value = unquote_env_value(raw_value);
    if value.contains('\0') {
        return EnvImportEntry::Invalid;
    }
    EnvImportEntry::Secret { key: key.to_owned(), value }
}

#[cfg(test)]
const fn has_unmatched_env_quote(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'"')) && !matches!(bytes.last(), Some(b'"'))
        || matches!(bytes.first(), Some(b'\'')) && !matches!(bytes.last(), Some(b'\''))
}

#[cfg(test)]
fn unquote_env_value(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(
            (bytes.first(), bytes.last()),
            (Some(b'"'), Some(b'"')) | (Some(b'\''), Some(b'\''))
        ) {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}
