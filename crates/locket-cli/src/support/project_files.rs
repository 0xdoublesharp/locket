//! Helpers that maintain `.env.example`, `.gitignore`, and audit metadata
//! emitted when those files are refreshed.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use locket_core::SecretName;
use locket_store::{AuditWrite, Store};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::commands::config::spec::{read_user_config, split_config_key};
use crate::{
    CliError, LOCKET_TOML, ResolvedProject, RuntimeContext, confirmation_failed_error, format_hex,
    metadata_invalid_error, now_unix_nanos, open_store, require_project,
};

pub const EXAMPLE_FILE: &str = ".env.example";
pub const GITIGNORE_FILE: &str = ".gitignore";
pub const EXAMPLE_BEGIN: &str = "# --- BEGIN LOCKET MANAGED ---";
pub const EXAMPLE_END: &str = "# --- END LOCKET MANAGED ---";

#[derive(Debug)]
pub struct ExampleWriteResult {
    pub path: PathBuf,
    pub secret_name_count: usize,
    pub replaced_unmanaged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExampleInitState {
    Created,
    UpdatedManaged,
    PreservedUnmanaged,
}

enum UnmanagedExamplePolicy<'a> {
    Preserve,
    Adopt,
    Replace(&'a RuntimeContext, &'a mut dyn Write),
}

pub fn write_example_emit_audit(
    store: &mut Store,
    resolved: &ResolvedProject,
    audit_key: &[u8],
    result: &ExampleWriteResult,
) -> Result<(), CliError> {
    let path_hash = Sha256::digest(EXAMPLE_FILE.as_bytes());
    let metadata = json!({
        "schema_version": 1,
        "action": "EXAMPLE_EMIT",
        "status": "SUCCESS",
        "command": "emit-example",
        "path_kind": "project_env_example",
        "path_hash": format_hex(&path_hash),
        "example_path_kind": "project_env_example",
        "example_path_hash": format_hex(&path_hash),
        "secret_name_count": result.secret_name_count,
        "marker_only": !result.replaced_unmanaged,
        "replaced_unmanaged": result.replaced_unmanaged,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "EXAMPLE_EMIT",
        status: "SUCCESS",
        secret_name: None,
        command: Some("emit-example"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key, &audit)?;
    Ok(())
}

pub fn ensure_gitignore(root: &Path) -> Result<(), CliError> {
    locket_platform::ensure_secret_file_ignores(root)?;
    Ok(())
}

pub fn ensure_example_file(root: &Path) -> Result<ExampleInitState, CliError> {
    let (_, state) = render_example(root, &BTreeSet::new(), UnmanagedExamplePolicy::Preserve)?;
    Ok(state)
}

pub fn refresh_example_for_project_if_enabled(context: &RuntimeContext) {
    if let Err(error) = refresh_example(context) {
        // TOML diagnostics can quote the source line. Only report metadata here.
        let reason = match error {
            CliError::Typed { message, .. } => message,
            CliError::Io(error) => error.to_string(),
            CliError::TomlDe(_) => "invalid example configuration".to_owned(),
            _ => "could not read secret metadata".to_owned(),
        };
        let _ = writeln!(
            io::stderr(),
            "locket: warning: secret saved, but .env.example was not refreshed: {reason}"
        );
    }
}

fn refresh_example(context: &RuntimeContext) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    if example_auto_refresh_enabled(context, &resolved)? {
        let store = open_store(context)?;
        let names = collect_example_secret_names(&store, &resolved)?;
        write_example_block(&resolved.root, &names)?;
    }
    Ok(())
}

fn example_auto_refresh_enabled(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
) -> Result<bool, CliError> {
    let project_config = read_config_table(&resolved.root.join(LOCKET_TOML))?;
    if let Some(value) = config_bool_value(&project_config, "example.auto_refresh")? {
        return Ok(value);
    }
    let user_config = read_user_config(context)?;
    Ok(config_bool_value(&user_config, "example.auto_refresh")?.unwrap_or(true))
}

pub fn read_config_table(path: &Path) -> Result<toml::Table, CliError> {
    let text = fs::read_to_string(path)?;
    toml::from_str::<toml::Table>(&text).map_err(CliError::from)
}

pub fn config_bool_value(config: &toml::Table, key: &str) -> Result<Option<bool>, CliError> {
    let Some((section, name)) = split_config_key(key) else {
        return Err(metadata_invalid_error("unsupported config key"));
    };
    let Some(section_value) = config.get(section) else {
        return Ok(None);
    };
    let Some(section_table) = section_value.as_table() else {
        return Err(metadata_invalid_error(format!("config section {section:?} must be a table")));
    };
    let Some(value) = section_table.get(name) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| metadata_invalid_error(format!("config key {key:?} must be boolean")))
}

pub fn collect_example_secret_names(
    store: &Store,
    resolved: &ResolvedProject,
) -> Result<BTreeSet<String>, CliError> {
    let mut names = BTreeSet::new();
    for profile in store.list_profiles(resolved.config.project_id.as_str())? {
        for secret in store.list_active_secret_metadata_by_profile(
            resolved.config.project_id.as_str(),
            &profile.id,
        )? {
            names.insert(secret.name);
        }
    }
    Ok(names)
}

pub fn write_example_block(
    root: &Path,
    names: &BTreeSet<String>,
) -> Result<ExampleWriteResult, CliError> {
    render_example(root, names, UnmanagedExamplePolicy::Preserve).map(|(result, _)| result)
}

pub fn write_example_block_for_emit(
    context: &RuntimeContext,
    root: &Path,
    names: &BTreeSet<String>,
    replace: bool,
    output: &mut impl Write,
) -> Result<ExampleWriteResult, CliError> {
    let policy = if replace {
        UnmanagedExamplePolicy::Replace(context, output)
    } else {
        UnmanagedExamplePolicy::Adopt
    };
    render_example(root, names, policy).map(|(result, _)| result)
}

pub fn example_path(root: &Path) -> Result<PathBuf, CliError> {
    let root = root.canonicalize()?;
    let path = root.join(EXAMPLE_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_symlink() => {
            let target = path.canonicalize()?;
            if !target.starts_with(root) {
                return Err(metadata_invalid_error(
                    ".env.example symlink points outside the project root",
                ));
            }
            Ok(target)
        }
        Ok(_) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
        Err(error) => Err(error.into()),
    }
}

fn render_example(
    root: &Path,
    names: &BTreeSet<String>,
    policy: UnmanagedExamplePolicy<'_>,
) -> Result<(ExampleWriteResult, ExampleInitState), CliError> {
    let path = example_path(root)?;
    let existing = match fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let mut result = ExampleWriteResult {
        path: root.join(EXAMPLE_FILE),
        secret_name_count: 0,
        replaced_unmanaged: false,
    };
    let Some(existing) = existing else {
        let mut block = managed_example_block(names, b"\n");
        block.push(b'\n');
        replace_example(&path, None, &block)?;
        result.secret_name_count = names.len();
        return Ok((result, ExampleInitState::Created));
    };

    let new = if let Some((begin, end)) = managed_range(&existing)? {
        let documented = documented_names(&existing[..begin])
            .chain(documented_names(&existing[end..]))
            .collect::<BTreeSet<_>>();
        let names = names.difference(&documented).cloned().collect::<BTreeSet<_>>();
        result.secret_name_count = names.len();
        let newline = newline_style(&existing[begin..end]);
        [&existing[..begin], &managed_example_block(&names, newline), &existing[end..]].concat()
    } else {
        let mut prefix = match policy {
            UnmanagedExamplePolicy::Preserve => {
                return Ok((result, ExampleInitState::PreservedUnmanaged));
            }
            UnmanagedExamplePolicy::Adopt => existing.clone(),
            UnmanagedExamplePolicy::Replace(context, output) => {
                confirm_replace(context, output, names.len())?;
                result.replaced_unmanaged = true;
                Vec::new()
            }
        };
        let newline = newline_style(&existing);
        let documented = documented_names(&prefix).collect::<BTreeSet<_>>();
        let names = names.difference(&documented).cloned().collect::<BTreeSet<_>>();
        result.secret_name_count = names.len();
        if !prefix.is_empty() && !prefix.ends_with(b"\n") {
            prefix.extend_from_slice(newline);
        }
        prefix.extend_from_slice(&managed_example_block(&names, newline));
        prefix.extend_from_slice(newline);
        prefix
    };
    if new != existing {
        if example_path(root)? != path {
            return Err(metadata_invalid_error(".env.example changed while preparing the update"));
        }
        replace_example(&path, Some(&existing), &new)?;
    }
    Ok((result, ExampleInitState::UpdatedManaged))
}

fn replace_example(path: &Path, original: Option<&[u8]>, updated: &[u8]) -> Result<(), CliError> {
    let directory =
        path.parent().ok_or_else(|| metadata_invalid_error("missing .env.example directory"))?;
    let mut staged = tempfile::Builder::new().prefix(".locket-example-").tempfile_in(directory)?;
    staged.write_all(updated)?;
    if let Some(original) = original {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || fs::read(path)? != original {
            return Err(metadata_invalid_error(".env.example changed while preparing the update"));
        }
        staged.as_file().set_permissions(metadata.permissions())?;
        staged.persist(path).map_err(|error| error.error)?;
    } else {
        staged.persist_noclobber(path).map_err(|error| error.error)?;
    }
    Ok(())
}

fn managed_range(bytes: &[u8]) -> Result<Option<(usize, usize)>, CliError> {
    let mut begin = None;
    let mut end = None;
    let mut offset = 0;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let content = line.strip_suffix(b"\n").unwrap_or(line);
        let content = content.strip_suffix(b"\r").unwrap_or(content);
        if content == EXAMPLE_BEGIN.as_bytes() {
            if begin.is_some() || end.is_some() {
                return Err(metadata_invalid_error(
                    ".env.example has duplicate or misplaced Locket markers",
                ));
            }
            begin = Some(offset);
        }
        if content == EXAMPLE_END.as_bytes() {
            if begin.is_none() || end.is_some() {
                return Err(metadata_invalid_error(
                    ".env.example has duplicate or misplaced Locket markers",
                ));
            }
            end = Some(offset + content.len());
        }
        offset += line.len();
    }
    match (begin, end) {
        (Some(begin), Some(end)) => Ok(Some((begin, end))),
        (None, None) => Ok(None),
        _ => Err(metadata_invalid_error(".env.example has an unterminated Locket managed block")),
    }
}

fn documented_names(bytes: &[u8]) -> impl Iterator<Item = String> + '_ {
    bytes.split(|byte| *byte == b'\n').filter_map(|line| {
        let equals = line.iter().position(|byte| *byte == b'=')?;
        let key = std::str::from_utf8(&line[..equals]).ok()?.trim();
        let key = key.strip_prefix('#').unwrap_or(key).trim_start();
        let key = key
            .strip_prefix("export")
            .filter(|rest| rest.starts_with(char::is_whitespace))
            .unwrap_or(key)
            .trim();
        SecretName::new(key).ok().map(SecretName::into_string)
    })
}

fn newline_style(bytes: &[u8]) -> &'static [u8] {
    match bytes.iter().position(|byte| *byte == b'\n') {
        Some(position) if position > 0 && bytes[position - 1] == b'\r' => b"\r\n",
        _ => b"\n",
    }
}

fn confirm_replace(
    context: &RuntimeContext,
    output: &mut dyn Write,
    name_count: usize,
) -> Result<(), CliError> {
    writeln!(output, ".env.example: unmanaged")?;
    writeln!(output, "secret_name_count: {name_count}")?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "type 'replace .env.example' to replace the unmanaged file")?;
    let confirmation = context.confirmation_reader.read_confirmation("replace .env.example")?;
    if confirmation.trim_end() != "replace .env.example" {
        return Err(confirmation_failed_error("confirmation did not match"));
    }
    Ok(())
}

fn managed_example_block(names: &BTreeSet<String>, newline: &[u8]) -> Vec<u8> {
    let mut block = EXAMPLE_BEGIN.as_bytes().to_vec();
    block.extend_from_slice(newline);
    for name in names {
        block.extend_from_slice(name.as_bytes());
        block.push(b'=');
        block.extend_from_slice(newline);
    }
    block.extend_from_slice(EXAMPLE_END.as_bytes());
    block
}
