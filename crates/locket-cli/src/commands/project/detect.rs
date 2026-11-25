//! Detects project commands from local manifests without invoking their runners.

use std::fs;
use std::io;
use std::path::Path;

use serde::Serialize;

use crate::runtime::error::{CliError, metadata_invalid_error};

const PACKAGE_TASKS: &[&str] =
    &["dev", "start", "build", "test", "lint", "typecheck", "migrate", "db:migrate"];
const MAKE_TARGETS: &[&str] = &["dev", "test", "build", "lint", "run"];

#[derive(Serialize)]
pub struct DetectedCommand {
    pub name: &'static str,
    pub argv: Vec<&'static str>,
    pub source_file: &'static str,
}

pub fn detect_commands(root: &Path) -> Result<Vec<DetectedCommand>, CliError> {
    let mut commands = package_commands(root, PACKAGE_TASKS)?;
    if let Some(manifest) = read_manifest(&root.join("Cargo.toml"))? {
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
            || root.join("src/main.rs").is_file()
        {
            commands.push(DetectedCommand {
                name: "run",
                argv: vec!["cargo", "run"],
                source_file: "Cargo.toml",
            });
        }
    }
    commands.extend(make_commands(root, MAKE_TARGETS)?);
    if root.join("pyproject.toml").is_file() {
        let argv = if root.join("uv.lock").is_file() {
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
        package_commands(root, &["dev", "start", "develop", "serve"])?.into_iter().next();
    if command.is_none() {
        command = make_commands(root, &["dev"])?.into_iter().next();
    }
    Ok(command.map(|command| command.argv.into_iter().map(str::to_owned).collect()))
}

fn package_commands(root: &Path, names: &[&'static str]) -> Result<Vec<DetectedCommand>, CliError> {
    let Some(manifest) = read_manifest(&root.join("package.json"))? else {
        return Ok(Vec::new());
    };
    let document: serde_json::Value = serde_json::from_str(&manifest)
        .map_err(|_| metadata_invalid_error("could not parse package.json"))?;
    let Some(scripts) = document.get("scripts").and_then(serde_json::Value::as_object) else {
        return Ok(Vec::new());
    };
    let runner = if root.join("pnpm-lock.yaml").is_file() {
        "pnpm"
    } else if root.join("yarn.lock").is_file() {
        "yarn"
    } else if root.join("bun.lock").is_file() || root.join("bun.lockb").is_file() {
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

fn make_commands(root: &Path, names: &[&'static str]) -> Result<Vec<DetectedCommand>, CliError> {
    let Some(makefile) = read_manifest(&root.join("Makefile"))? else {
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

fn read_manifest(path: &Path) -> Result<Option<String>, CliError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(Some(fs::read_to_string(path)?)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
