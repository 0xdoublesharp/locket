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
const PACKAGE_MANAGER_MARKERS: &[(&str, &[&str])] = &[
    ("pnpm", &["pnpm-lock.yaml", "pnpm-workspace.yaml"]),
    ("yarn", &["yarn.lock"]),
    ("bun", &["bun.lock", "bun.lockb"]),
    ("npm", &["package-lock.json"]),
];
const PACKAGE_MANAGER_SEARCH_DEPTH: usize = 8;

struct DetectedCommand {
    name: String,
    argv: Vec<&'static str>,
    source_file: &'static str,
}

#[derive(Serialize)]
pub struct PolicyDetection {
    pub name: String,
    pub argv: Vec<&'static str>,
    pub command_preview: String,
    pub suggested_command: String,
    pub source_file: &'static str,
    pub already_configured: bool,
}

impl PolicyDetection {
    pub(crate) fn new(
        name: String,
        argv: Vec<&'static str>,
        source_file: &'static str,
        already_configured: bool,
    ) -> Self {
        // Detection only supplies fixed names and argv tokens that are safe to paste.
        let command_preview = argv.join(" ");
        let suggested_command = format!("locket policy add {name} -- {command_preview}");
        Self { name, argv, command_preview, suggested_command, source_file, already_configured }
    }
}

pub fn finalize_policy_detections(
    commands: Vec<(String, Vec<&'static str>, &'static str)>,
    configured: Option<&toml::Table>,
) -> Vec<PolicyDetection> {
    let mut used = std::collections::BTreeSet::new();
    let mut resolved = Vec::with_capacity(commands.len());
    for (mut name, argv, source_file) in commands {
        if !used.insert(name.clone()) {
            let prefixed = match (source_file, name.as_str()) {
                ("Cargo.toml", bare) => format!("cargo-{bare}"),
                ("Makefile", bare) => format!("make-{bare}"),
                ("pyproject.toml", "test") => "pytest".to_owned(),
                ("pyproject.toml", bare) => format!("python-{bare}"),
                ("foundry.toml", bare) => format!("forge-{bare}"),
                (_, bare) => format!("{bare}-{}", resolved.len() + 1),
            };
            name = if used.insert(prefixed.clone()) {
                prefixed
            } else {
                let fallback = format!("{prefixed}-{}", resolved.len() + 1);
                used.insert(fallback.clone());
                fallback
            };
        }
        let already_configured = configured.is_some_and(|commands| {
            commands.get(&name).is_some_and(toml::Value::is_table)
                || commands.values().any(|entry| {
                    entry.get("argv").and_then(toml::Value::as_array).is_some_and(|saved| {
                        saved.iter().map(toml::Value::as_str).eq(argv.iter().copied().map(Some))
                    })
                })
        });
        resolved.push(PolicyDetection::new(name, argv, source_file, already_configured));
    }
    resolved
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
    let commands = detect_commands(root, follow_manifest_links)?
        .into_iter()
        .map(|command| (command.name, command.argv, command.source_file))
        .collect();
    Ok(finalize_policy_detections(commands, configured))
}

fn detect_commands(root: &Path, follow_links: bool) -> Result<Vec<DetectedCommand>, CliError> {
    let mut commands = package_commands(root, PACKAGE_TASKS, follow_links)?;
    if let Some(manifest) = read_manifest(&root.join("Cargo.toml"), follow_links)? {
        let cargo: toml::Value = toml::from_str(&manifest)
            .map_err(|_| metadata_invalid_error("could not parse Cargo.toml"))?;
        commands.push(DetectedCommand {
            name: "test".to_owned(),
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
                name: "run".to_owned(),
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
        commands.push(DetectedCommand {
            name: "test".to_owned(),
            argv,
            source_file: "pyproject.toml",
        });
    }
    if manifest_is_file(&root.join("foundry.toml"), follow_links) {
        commands.extend(["build", "test"].map(|name| DetectedCommand {
            name: name.to_owned(),
            argv: vec!["forge", name],
            source_file: "foundry.toml",
        }));
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
    let runner = package_manager(root, &document, follow_links);
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
            name: name.to_owned(),
            argv: vec![runner, "run", name],
            source_file: "package.json",
        })
        .collect())
}

fn package_manager(root: &Path, document: &serde_json::Value, follow_links: bool) -> &'static str {
    if let Some(declared) = document.get("packageManager").and_then(serde_json::Value::as_str) {
        let name = declared.split_once('@').map_or(declared, |(name, _)| name);
        if let Some((runner, _)) =
            PACKAGE_MANAGER_MARKERS.iter().find(|(runner, _)| *runner == name)
        {
            return runner;
        }
    }
    let directory_count = root
        .ancestors()
        .position(|directory| {
            manifest_metadata(&directory.join(".git"), follow_links)
                .is_ok_and(|metadata| metadata.is_dir() || metadata.is_file())
        })
        .map_or(1, |depth| (depth + 1).min(PACKAGE_MANAGER_SEARCH_DEPTH));
    root.ancestors()
        .take(directory_count)
        .find_map(|directory| {
            PACKAGE_MANAGER_MARKERS.iter().find_map(|(runner, markers)| {
                markers
                    .iter()
                    .any(|marker| manifest_is_file(&directory.join(marker), follow_links))
                    .then_some(*runner)
            })
        })
        .unwrap_or("npm")
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
        .map(|name| DetectedCommand {
            name: name.to_owned(),
            argv: vec!["make", name],
            source_file: "Makefile",
        })
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
