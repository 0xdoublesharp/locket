//! Compare profiles and report plaintext drift using key names and timestamps.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;

use clap::Args;
use locket_core::dotenv::{DotenvOptions, parse_dotenv};
use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::commands::discovery::{
    require_metadata_store, select_project, trusted_project_config, write_json_result,
};
use crate::{CliError, RuntimeContext, now_unix_nanos, profile_not_found_error, require_project};

#[derive(Args, Debug)]
pub struct ParityArgs {
    /// Project id, name, or trusted root.
    #[arg(long)]
    project: Option<String>,
    /// Profile to compare. May be repeated.
    #[arg(long)]
    profile: Vec<String>,
    /// Inspect the trusted workspace root for lingering dotenv files.
    #[arg(long)]
    check_plaintext: bool,
    /// Mark active secrets older than this many days as stale.
    #[arg(long)]
    max_age_days: Option<u32>,
    /// Print JSON.
    #[arg(long)]
    json: bool,
}

pub fn parity_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ParityArgs,
) -> Result<u8, CliError> {
    let result = parity_report(context, args);
    if args.json {
        return write_json_result(output, result);
    }
    let report = result?;
    for profile in report["profiles"].as_array().into_iter().flatten() {
        let name = profile["profile"].as_str().unwrap_or_default();
        writeln!(
            output,
            "{name}: missing {} | stale {} | expired {} | expiring soon {}",
            profile["missing"], profile["stale"], profile["expired"], profile["expiring_soon"]
        )?;
    }
    for file in report["plaintext_drift"].as_array().into_iter().flatten() {
        let name = file["file"].as_str().unwrap_or_default();
        writeln!(output, "plaintext drift: {name} ({} overlapping keys)", file["overlap_count"])?;
    }
    Ok(0)
}

fn parity_report(context: &RuntimeContext, args: &ParityArgs) -> Result<Value, CliError> {
    let store = require_metadata_store(context)?;
    let (project_id, root) = if let Some(selector) = &args.project {
        let project = select_project(&store, &context.cwd, selector)?;
        let workspace = if args.check_plaintext {
            let local = crate::resolve_project(&context.cwd)?.filter(|resolved| {
                resolved.config.project_id.as_str() == project.id
                    && crate::ensure_trusted_project_root(&store, resolved).is_ok()
            });
            match local {
                Some(resolved) => Some(resolved),
                None => trusted_project_config(&store, &project.id)?,
            }
        } else {
            None
        };
        (project.id, workspace.map(|resolved| resolved.root))
    } else {
        let resolved = require_project(context)?;
        crate::ensure_trusted_project_root(&store, &resolved)?;
        (resolved.config.project_id.into_string(), args.check_plaintext.then_some(resolved.root))
    };

    let profiles = store.list_profiles(&project_id)?;
    for name in &args.profile {
        if !profiles.iter().any(|profile| &profile.name == name) {
            return Err(profile_not_found_error("requested parity profile not found"));
        }
    }
    let now = now_unix_nanos()?;
    let notices = crate::commands::secrets::expiry::expiry_notices(&store, &project_id, now)?;
    let stale_before = args
        .max_age_days
        .map(|days| now.saturating_sub(i64::from(days).saturating_mul(86_400_000_000_000)));
    let mut names = BTreeSet::new();
    let mut selected = Vec::new();
    for profile in profiles {
        if !args.profile.is_empty() && !args.profile.contains(&profile.name) {
            continue;
        }
        let records = store.list_active_secrets_by_profile(&project_id, &profile.id)?;
        let mut stale = records
            .iter()
            .filter(|secret| {
                stale_before.is_some_and(|cutoff| {
                    secret.last_rotated_at.unwrap_or(secret.created_at) < cutoff
                })
            })
            .map(|secret| secret.name.clone())
            .collect::<BTreeSet<_>>();
        let mut expired = BTreeSet::new();
        let mut expiring_soon = BTreeSet::new();
        for notice in notices.iter().filter(|notice| notice.profile_id == profile.id) {
            match notice.expiry_status {
                Some(locket_store::SecretExpiryStatus::Expired) => {
                    expired.insert(&notice.name);
                }
                Some(locket_store::SecretExpiryStatus::ExpiringSoon) => {
                    expiring_soon.insert(&notice.name);
                }
                None => {}
            }
            if notice.stale {
                stale.insert(notice.name.clone());
            }
        }
        let present = records.into_iter().map(|secret| secret.name).collect::<BTreeSet<_>>();
        names.extend(present.iter().cloned());
        selected.push((profile, present, stale, expired, expiring_soon));
    }
    let profiles = selected
        .iter()
        .map(|(profile, present, stale, expired, expiring_soon)| {
            json!({
                "profile": profile.name, "dangerous": profile.dangerous,
                "missing": names.difference(present).collect::<Vec<_>>(),
                "stale": stale,
                "expired": expired,
                "expiring_soon": expiring_soon,
            })
        })
        .collect::<Vec<_>>();
    let drift =
        root.as_deref().map(|root| plaintext_drift(root, &names)).transpose()?.unwrap_or_default();
    Ok(json!({
        "project_id": project_id, "profiles": profiles,
        "plaintext_checked": root.is_some(), "plaintext_drift": drift,
    }))
}

fn plaintext_drift(root: &Path, names: &BTreeSet<String>) -> Result<Vec<Value>, CliError> {
    let mut drift = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else { continue };
        if !(file_name == ".env" || file_name.starts_with(".env."))
            || matches!(file_name, ".env.example" | ".env.template")
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        let bytes = Zeroizing::new(fs::read(entry.path())?);
        let text = std::str::from_utf8(&bytes).unwrap_or_default();
        let mut overlapping = BTreeSet::new();
        for mut entry in parse_dotenv(text, DotenvOptions { literal: true }).entries {
            entry.value.zeroize();
            if names.contains(&entry.key) {
                overlapping.insert(entry.key);
            }
        }
        drift.push((file_name.to_owned(), overlapping.len()));
    }
    drift.sort_unstable();
    Ok(drift
        .into_iter()
        .map(|(file, count)| json!({"file": file, "overlap_count": count}))
        .collect())
}
