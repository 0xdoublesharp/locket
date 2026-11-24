//! Implementation of the `locket import` command and its private helpers.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::Path;

use locket_core::ProfileName;
#[cfg(test)]
use locket_core::SecretName;
use locket_core::dotenv::{DotenvOptions, parse_dotenv};
use locket_store::{ProfileRecord, Store};
use zeroize::Zeroizing;

use super::set::{NewSecret, Rotation, SecretWriteKeys, create_value, rotate_value};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, confirmation_failed_error, invalid_profile_name_error, metadata_invalid_error,
    profile_not_found_error,
};
use crate::runtime::prompts::ConfirmationReader;
use crate::support::project_files::{ensure_gitignore, refresh_example_for_project_if_enabled};
use crate::{
    ImportArgs, ResolvedProject, SecretMetadataFlags, SecretSourceArg, absolutize,
    active_profile_secret_names, ensure_trusted_project_root, now_unix_nanos, open_store,
    require_project, secret_deleted_error, source_arg_to_str,
};

pub fn import_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ImportArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let profile = import_target_profile(&store, &resolved, args.profile.as_deref())?;
    if args.overwrite && profile.dangerous {
        confirm_dangerous_import_overwrite(output, &profile, context.confirmation_reader.as_ref())?;
    }
    let path = absolutize(&context.cwd, Path::new(&args.file));
    let env_file_text = Zeroizing::new(fs::read_to_string(&path)?);
    let source = args.source.unwrap_or(SecretSourceArg::UserLocal);
    let source_name = source_arg_to_str(source);
    let parsed = validated_import_entries(&env_file_text, args.literal, output)?;
    drop(env_file_text);
    let env_names = parsed.iter().map(|(name, _)| name.clone()).collect::<BTreeSet<_>>();
    let ImportCounts { imported, overwritten, skipped_names } = import_entries(
        context,
        &mut store,
        &resolved,
        &profile,
        source_name,
        args.overwrite,
        parsed,
    )?;
    let skipped = skipped_names.len();

    refresh_example_for_project_if_enabled(context)?;
    ensure_gitignore(&resolved.root)?;
    let profile_names =
        active_profile_secret_names(&store, resolved.config.project_id.as_str(), &profile.id)?;
    let missing_in_profile = env_names.difference(&profile_names).cloned().collect::<BTreeSet<_>>();
    let extra_in_profile = profile_names.difference(&env_names).cloned().collect::<BTreeSet<_>>();
    writeln!(output, "imported: {imported}")?;
    writeln!(output, "overwritten: {overwritten}")?;
    writeln!(output, "skipped: {skipped}")?;
    writeln!(output, "invalid: 0")?;
    writeln!(output, "profile: {}", profile.name)?;
    writeln!(output, "source: {source_name}")?;
    writeln!(output, "env_names: {}", env_names.len())?;
    writeln!(output, "profile_names: {}", profile_names.len())?;
    writeln!(output, "skipped_names: {}", format_name_set(&skipped_names))?;
    writeln!(output, "missing_in_profile: {}", format_name_set(&missing_in_profile))?;
    writeln!(output, "extra_in_profile: {}", format_name_set(&extra_in_profile))?;
    if skipped == 0 && imported + overwritten > 0 {
        write_env_delete_prompt(output, &path, context.confirmation_reader.as_ref())?;
    } else {
        writeln!(output, "delete_env: kept")?;
    }
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

struct ImportCounts {
    imported: u32,
    overwritten: u32,
    skipped_names: BTreeSet<String>,
}

fn import_entries(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    source_name: &str,
    overwrite: bool,
    parsed: Vec<(String, Zeroizing<String>)>,
) -> Result<ImportCounts, CliError> {
    let mut imported = 0_u32;
    let mut overwritten = 0_u32;
    let mut skipped_names = BTreeSet::new();

    let project_id = resolved.config.project_id.as_str();
    let metadata = SecretMetadataFlags::default();
    store.with_atomic_write(|store| -> Result<(), CliError> {
        let mut keys = None;
        for (name, value) in parsed {
            if value.contains('\0') {
                return Err(metadata_invalid_error("imported value contains NUL bytes"));
            }
            let existing =
                store.get_secret_by_source(project_id, &profile.id, &name, source_name)?;
            if let Some(secret) = &existing {
                if secret.state != "active" {
                    return Err(secret_deleted_error("secret source is deleted"));
                }
                if !overwrite {
                    skipped_names.insert(name);
                    continue;
                }
            }
            let keys = match &keys {
                Some(keys) => keys,
                None => {
                    keys.insert(SecretWriteKeys::load(context, store, project_id, &profile.id)?)
                }
            };
            let timestamp = now_unix_nanos()?;
            if let Some(secret) = existing {
                rotate_value(
                    store,
                    keys,
                    &secret,
                    &Rotation {
                        value: &value,
                        origin: "imported",
                        timestamp,
                        grace_until: None,
                        metadata: &metadata,
                        action: "ROTATE",
                    },
                )?;
                overwritten += 1;
            } else {
                create_value(
                    store,
                    keys,
                    &NewSecret {
                        project_id,
                        profile_id: &profile.id,
                        name: &name,
                        source: source_name,
                        value: &value,
                        origin: "imported",
                        timestamp,
                        metadata: &metadata,
                        action: "IMPORT",
                    },
                )?;
                imported += 1;
            }
        }
        Ok(())
    })?;

    Ok(ImportCounts { imported, overwritten, skipped_names })
}

fn validated_import_entries(
    text: &str,
    literal: bool,
    output: &mut impl Write,
) -> Result<Vec<(String, Zeroizing<String>)>, CliError> {
    let document = parse_dotenv(text, DotenvOptions { literal });
    let entries = document
        .entries
        .into_iter()
        .map(|entry| (entry.key, Zeroizing::new(entry.value)))
        .collect();
    for warning in &document.warnings {
        writeln!(output, "warning: line {}: {}", warning.line, warning.message)?;
    }
    if !document.errors.is_empty() {
        writeln!(output, "imported: 0")?;
        writeln!(output, "invalid: {}", document.errors.len())?;
        writeln!(output, "delete_env: kept")?;
        writeln!(output, "metadata_only: yes")?;
        return Err(metadata_invalid_error(
            document
                .errors
                .iter()
                .map(|error| format!("line {}: {}", error.line, error.message))
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    Ok(entries)
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
