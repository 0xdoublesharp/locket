//! Read-only command suggestions from manifest metadata in a trusted folder.

use std::{collections::BTreeSet, fs, io::Read as _, path::Path};

use serde::Serialize;
use serde_json::Value;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const PACKAGE_MANAGER_MARKERS: &[(&str, &[&str])] = &[
    ("pnpm", &["pnpm-lock.yaml", "pnpm-workspace.yaml"]),
    ("yarn", &["yarn.lock"]),
    ("bun", &["bun.lock", "bun.lockb"]),
    ("npm", &["package-lock.json"]),
];
const PACKAGE_MANAGER_SEARCH_DEPTH: usize = 8;

#[derive(Serialize)]
pub(crate) struct DetectedCommand {
    name: String,
    argv: Vec<String>,
    command_preview: String,
    source_file: &'static str,
    already_configured: bool,
}

pub(super) fn detect(root: &Path, project_id: &str) -> Result<Vec<DetectedCommand>, String> {
    let config = read_manifest(root, "locket.toml")
        .and_then(|text| text.parse::<toml::Table>().ok())
        .filter(|config| config.get("project_id").and_then(toml::Value::as_str) == Some(project_id))
        .ok_or_else(|| "Project settings changed. Reopen the trusted folder.".to_string())?;
    let configured = config.get("commands").and_then(toml::Value::as_table);
    let mut found = Vec::new();
    let mut add = |source_file, name: &str, parts: &[&str]| {
        let argv = parts.iter().map(|part| (*part).to_owned()).collect::<Vec<_>>();
        let already_configured = configured.is_some_and(|commands| {
            commands.contains_key(name)
                || commands.values().any(|command| {
                    command.get("argv").and_then(toml::Value::as_array).is_some_and(|saved| {
                        saved.iter().map(toml::Value::as_str).eq(parts.iter().copied().map(Some))
                    })
                })
        });
        // All dynamic argv elements pass the option-safe name filter.
        found.push(DetectedCommand {
            name: name.into(),
            argv,
            command_preview: parts.join(" "),
            source_file,
            already_configured,
        });
    };

    if let Some(package) = read_manifest(root, "package.json")
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
    {
        let manager = node_package_manager(root, &package);
        if let Some(scripts) = package.get("scripts").and_then(Value::as_object) {
            for (name, body) in scripts {
                if command_name(name, true)
                    && body.as_str().is_some_and(|body| !body.trim().is_empty())
                {
                    add("package.json", name, &[manager, "run", name]);
                }
            }
        }
    }

    if let Some(makefile) = read_manifest(root, "Makefile") {
        for name in make_targets(&makefile) {
            add("Makefile", name, &["make", name]);
        }
    }

    if let Some(cargo) =
        read_manifest(root, "Cargo.toml").and_then(|text| text.parse::<toml::Table>().ok())
    {
        let package = cargo.get("package").and_then(toml::Value::as_table);
        if package.is_some() || cargo.get("workspace").is_some_and(toml::Value::is_table) {
            for (name, subcommand) in
                [("cargo-build", "build"), ("cargo-check", "check"), ("cargo-test", "test")]
            {
                add("Cargo.toml", name, &["cargo", subcommand]);
            }
        }
        let auto_bin = package.is_some_and(|package| {
            package.get("autobins").and_then(toml::Value::as_bool) != Some(false)
                && regular_file(root, "src/main.rs")
        });
        if auto_bin
            || cargo.get("bin").and_then(toml::Value::as_array).is_some_and(|bins| !bins.is_empty())
        {
            add("Cargo.toml", "cargo-run", &["cargo", "run"]);
        }
    }

    if let Some(python) =
        read_manifest(root, "pyproject.toml").and_then(|text| text.parse::<toml::Table>().ok())
    {
        let project_scripts = python.get("project").and_then(|project| project.get("scripts"));
        let poetry_scripts = python
            .get("tool")
            .and_then(|tool| tool.get("poetry"))
            .and_then(|poetry| poetry.get("scripts"));
        let mut seen = BTreeSet::new();
        let modern_runner = if regular_file(root, "poetry.lock") && !regular_file(root, "uv.lock") {
            "poetry"
        } else {
            "uv"
        };
        for (runner, scripts) in [(modern_runner, project_scripts), ("poetry", poetry_scripts)] {
            if let Some(scripts) = scripts.and_then(toml::Value::as_table) {
                for (name, entry) in scripts {
                    if command_name(name, false)
                        && (entry.is_str() || entry.is_table())
                        && seen.insert(name)
                    {
                        add("pyproject.toml", name, &[runner, "run", name]);
                    }
                }
            }
        }
    }

    if regular_file(root, "foundry.toml") {
        add("foundry.toml", "forge-build", &["forge", "build"]);
        add("foundry.toml", "forge-test", &["forge", "test"]);
    }

    Ok(found)
}

fn regular_file(root: &Path, name: &str) -> bool {
    fs::symlink_metadata(root.join(name)).is_ok_and(|metadata| metadata.is_file())
}

fn read_manifest(root: &Path, name: &str) -> Option<String> {
    let path = root.join(name);
    if !regular_file(root, name) || path.canonicalize().ok()?.parent() != path.parent() {
        return None;
    }
    let file = locket_platform::open_regular_file(&path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    let mut content = String::new();
    file.take(MAX_MANIFEST_BYTES + 1).read_to_string(&mut content).ok()?;
    (u64::try_from(content.len()).ok()? <= MAX_MANIFEST_BYTES).then_some(content)
}

fn node_package_manager(root: &Path, manifest: &Value) -> &'static str {
    if let Some(declared) = manifest.get("packageManager").and_then(Value::as_str) {
        let name = declared.split_once('@').map_or(declared, |(name, _)| name);
        if let Some((manager, _)) =
            PACKAGE_MANAGER_MARKERS.iter().find(|(manager, _)| *manager == name)
        {
            return manager;
        }
    }

    let directory_count = root
        .ancestors()
        .position(|directory| {
            fs::symlink_metadata(directory.join(".git"))
                .is_ok_and(|metadata| metadata.is_dir() || metadata.is_file())
        })
        .map_or(1, |depth| (depth + 1).min(PACKAGE_MANAGER_SEARCH_DEPTH));
    root.ancestors()
        .take(directory_count)
        .find_map(|directory| {
            PACKAGE_MANAGER_MARKERS.iter().find_map(|(manager, markers)| {
                markers.iter().any(|marker| regular_file(directory, marker)).then_some(*manager)
            })
        })
        .unwrap_or("npm")
}

fn make_targets(makefile: &str) -> BTreeSet<&str> {
    let mut targets = BTreeSet::new();
    let mut continued = false;
    for line in makefile.lines() {
        let part_of_previous = continued;
        continued = line.ends_with('\\');
        if part_of_previous || line.starts_with('\t') {
            continue;
        }
        let line = line.split_once('#').map_or(line, |(prefix, _)| prefix).trim();
        let Some((names, prerequisites)) = line.split_once(':') else { continue };
        if prerequisites.starts_with('=')
            || prerequisites.starts_with(":=")
            || prerequisites.starts_with("::=")
        {
            continue;
        }
        let names = names.split_ascii_whitespace().collect::<Vec<_>>();
        if !names.is_empty() && names.iter().all(|name| command_name(name, false)) {
            targets.extend(names);
        }
    }
    targets
}

fn command_name(name: &str, allow_colon: bool) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_alphanumeric() || first == b'_')
        && bytes.all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.')
                || (allow_colon && byte == b':')
        })
}
