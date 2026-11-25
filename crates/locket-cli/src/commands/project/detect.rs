//! Detects project commands from local manifests without invoking their runners.

use std::fs;
use std::io;
use std::path::Path;

use serde::Serialize;

use crate::LOCKET_TOML;
use crate::runtime::error::{CliError, metadata_invalid_error};

const PACKAGE_TASKS: &[&str] =
    &["dev", "start", "build", "test", "lint", "typecheck", "migrate", "db:migrate"];
const MAKE_TARGETS: &[&str] = &["dev", "test", "build", "lint", "run"];

struct DetectedCommand {
    name: &'static str,
    argv: Vec<&'static str>,
    source_file: &'static str,
}

#[derive(Serialize)]
pub struct PolicyDetection {
    pub name: &'static str,
    pub argv: Vec<&'static str>,
    pub command_preview: String,
    pub source_file: &'static str,
    pub already_configured: bool,
}

pub fn detect_policy_commands(
    root: &Path,
    follow_manifest_links: bool,
) -> Result<Vec<PolicyDetection>, CliError> {
    let config = root.join(LOCKET_TOML);
    let document = manifest_is_file(&config, follow_manifest_links)
        .then(|| locket_platform::PolicyFileDocument::read(&config))
        .transpose()
        .map_err(|error| metadata_invalid_error(error.to_string()))?;
    let configured = document
        .as_ref()
        .and_then(|document| document.get("commands"))
        .and_then(toml::Value::as_table);
    Ok(detect_commands(root, follow_manifest_links)?
        .into_iter()
        .map(|command| PolicyDetection {
            name: command.name,
            command_preview: command.argv.join(" "),
            argv: command.argv,
            source_file: command.source_file,
            already_configured: configured
                .and_then(|commands| commands.get(command.name))
                .is_some_and(toml::Value::is_table),
        })
        .collect())
}

fn detect_commands(root: &Path, follow_links: bool) -> Result<Vec<DetectedCommand>, CliError> {
    let mut commands = package_commands(root, PACKAGE_TASKS, follow_links)?;
    if let Some(manifest) = read_manifest(&root.join("Cargo.toml"), follow_links)? {
        let cargo: toml::Value = toml::from_str(&manifest)
            .map_err(|_| metadata_invalid_error("could not parse Cargo.toml"))?;
        commands.push(DetectedCommand {
            name: "test",
            argv: vec!["cargo", "test"],
            source_file: "Cargo.toml",
        });
        if cargo
            .get("bin")
            .and_then(toml::Value::as_array)
            .is_some_and(|bins| bins.iter().any(toml::Value::is_table))
            || (manifest_metadata(&root.join("src"), follow_links)
                .is_ok_and(|metadata| metadata.is_dir())
                && manifest_is_file(&root.join("src/main.rs"), follow_links))
        {
            commands.push(DetectedCommand {
                name: "run",
                argv: vec!["cargo", "run"],
                source_file: "Cargo.toml",
            });
        }
    }
    commands.extend(make_commands(root, MAKE_TARGETS, follow_links)?);
    if manifest_is_file(&root.join("pyproject.toml"), follow_links) {
        let argv = if manifest_is_file(&root.join("uv.lock"), follow_links) {
            vec!["uv", "run", "pytest"]
        } else {
            vec!["pytest"]
        };
        commands.push(DetectedCommand { name: "test", argv, source_file: "pyproject.toml" });
    }
    Ok(commands)
}

pub fn detect_development_argv(root: &Path) -> Result<Option<Vec<String>>, CliError> {
    let mut command =
        package_commands(root, &["dev", "start", "develop", "serve"], true)?.into_iter().next();
    if command.is_none() {
        command = make_commands(root, &["dev"], true)?.into_iter().next();
    }
    Ok(command.map(|command| command.argv.into_iter().map(str::to_owned).collect()))
}

fn package_commands(
    root: &Path,
    names: &[&'static str],
    follow_links: bool,
) -> Result<Vec<DetectedCommand>, CliError> {
    let Some(manifest) = read_manifest(&root.join("package.json"), follow_links)? else {
        return Ok(Vec::new());
    };
    let document: serde_json::Value = serde_json::from_str(&manifest)
        .map_err(|_| metadata_invalid_error("could not parse package.json"))?;
    let Some(scripts) = document.get("scripts").and_then(serde_json::Value::as_object) else {
        return Ok(Vec::new());
    };
    let runner = if manifest_is_file(&root.join("pnpm-lock.yaml"), follow_links) {
        "pnpm"
    } else if manifest_is_file(&root.join("yarn.lock"), follow_links) {
        "yarn"
    } else if manifest_is_file(&root.join("bun.lock"), follow_links)
        || manifest_is_file(&root.join("bun.lockb"), follow_links)
    {
        "bun"
    } else {
        "npm"
    };
    Ok(names
        .iter()
        .copied()
        .filter(|name| {
            scripts
                .get(*name)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|script| !script.trim().is_empty())
        })
        .map(|name| DetectedCommand {
            name,
            argv: vec![runner, "run", name],
            source_file: "package.json",
        })
        .collect())
}

fn make_commands(
    root: &Path,
    names: &[&'static str],
    follow_links: bool,
) -> Result<Vec<DetectedCommand>, CliError> {
    let Some(makefile) = read_manifest(&root.join("Makefile"), follow_links)? else {
        return Ok(Vec::new());
    };
    let targets: std::collections::BTreeSet<_> = makefile
        .lines()
        .filter_map(|line| {
            let (name, remainder) = line.split_once(':')?;
            // A target starts in column one. Ignore immediate variable assignments.
            (!remainder.trim_start_matches(':').starts_with('=')).then_some(name)
        })
        .collect();
    Ok(names
        .iter()
        .copied()
        .filter(|name| targets.contains(name))
        .map(|name| DetectedCommand { name, argv: vec!["make", name], source_file: "Makefile" })
        .collect())
}

fn manifest_metadata(path: &Path, follow_links: bool) -> io::Result<fs::Metadata> {
    if follow_links { fs::metadata(path) } else { fs::symlink_metadata(path) }
}

fn manifest_is_file(path: &Path, follow_links: bool) -> bool {
    manifest_metadata(path, follow_links).is_ok_and(|metadata| metadata.is_file())
}

fn read_manifest(path: &Path, follow_links: bool) -> Result<Option<String>, CliError> {
    match manifest_metadata(path, follow_links) {
        Ok(metadata) if metadata.is_file() => Ok(Some(fs::read_to_string(path)?)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
