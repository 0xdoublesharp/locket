//! Static, metadata-only hints for files that may still consume a dotenv source.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::Read as _;
use std::iter::Peekable;
use std::path::{Component, Path, PathBuf};
use std::str::Chars;

use serde_json::Value;

use super::env_files::{InputDirectory, SKIP_DIRECTORIES};
use super::git_worktree_root;

const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_SCRIPT_BYTES: u64 = 64 * 1024;
const MAX_SCRIPTS: usize = 16;
const MAX_ANCESTORS: usize = 8;
const MAX_SUBDIR_DEPTH: usize = 3;
const MAX_SUBDIRS: usize = 64;
const MAX_SUBDIR_FILES: usize = 64;
const MAX_INTERPOLATION_KEYS: usize = 12;
const MAX_STATIC_WORD_BYTES: usize = 4096;
const MAX_SUBST_DEPTH: usize = 4;

pub(super) fn detect_archive_consumers(
    source: &Path,
    root: Option<&Path>,
    env_names: &BTreeSet<String>,
) -> Vec<String> {
    let (Some(parent), Some(name)) = (source.parent(), source.file_name()) else {
        return Vec::new();
    };
    let Ok(parent) = parent.canonicalize() else {
        return Vec::new();
    };
    let source = parent.join(name);
    let project_root = root.and_then(|root| root.canonicalize().ok());
    let in_project = project_root.as_deref().filter(|root| parent.starts_with(root));
    let git_root = in_project.and_then(|_| git_worktree_root(&parent).ok().flatten());
    let boundary = git_root.or(in_project).unwrap_or(&parent);
    let mut scan = ConsumerScan {
        source: &source,
        env_names,
        root: git_root.or(project_root.as_deref()).unwrap_or(&parent),
        git_root,
        warnings: Vec::new(),
        scripts: BTreeMap::new(),
    };
    for dir in parent.ancestors().take(MAX_ANCESTORS + 1) {
        let Ok(directory) = InputDirectory::open(dir) else { break };
        scan.directory(&directory, dir);
        if dir == boundary {
            break;
        }
    }
    if in_project.is_some() {
        let mut visited = BTreeSet::new();
        let mut dirs_budget = MAX_SUBDIRS;
        let mut files_budget = MAX_SUBDIR_FILES;
        if let Ok(directory) = InputDirectory::open(&parent) {
            scan.scan_subdirectories(
                &directory,
                &parent,
                MAX_SUBDIR_DEPTH,
                &mut visited,
                &mut dirs_budget,
                &mut files_budget,
            );
        }
        if boundary != parent
            && let Ok(directory) = InputDirectory::open(boundary)
        {
            scan.scan_subdirectories(
                &directory,
                boundary,
                1,
                &mut visited,
                &mut dirs_budget,
                &mut files_budget,
            );
        }
    }
    scan.warnings.sort_unstable();
    scan.warnings.dedup();
    scan.warnings
}

struct ConsumerScan<'a> {
    source: &'a Path,
    env_names: &'a BTreeSet<String>,
    root: &'a Path,
    git_root: Option<&'a Path>,
    warnings: Vec<String>,
    scripts: BTreeMap<PathBuf, LocalScript>,
}

struct LocalScript {
    text: Option<String>,
    recreates_in: BTreeMap<PathBuf, bool>,
}

impl ConsumerScan<'_> {
    fn directory(&mut self, directory: &InputDirectory, dir: &Path) {
        let source = self.source;
        let source_name =
            source.file_name().unwrap_or_default().to_string_lossy().escape_debug().to_string();
        let matches_source = |literal: &str| normalized_path(&dir.join(literal)) == source;
        let implicit =
            source.parent() == Some(dir) && source.file_name() == Some(OsStr::new(".env"));

        let names = directory.names().unwrap_or_default();
        let names = names.iter().filter_map(|name| name.to_str());
        for name in names.clone().filter(|name| is_compose_file(name)) {
            let Some(text) = read_config(directory, name, MAX_CONFIG_BYTES) else { continue };
            let path = relative_display(self.root, &dir.join(name));
            if compose_references(&text, matches_source) {
                self.warnings.push(format!(
                    "{path} references {source_name} in Docker Compose env_file; replace with environment: pass-through or mark required: false"
                ));
            } else if implicit
                && let Some(keys) = compose_interpolation_overlap(&text, self.env_names)
            {
                self.warnings.push(format!(
                    "{path} interpolates {keys} from {source_name} through Docker Compose; run via `locket compose run --policy <name> -- ...`"
                ));
            }
        }

        for name in names.filter(|name| matches!(*name, "Makefile" | "makefile" | "GNUmakefile")) {
            let Some(text) = read_config(directory, name, MAX_CONFIG_BYTES) else { continue };
            let path = relative_display(self.root, &dir.join(name));
            let (includes, reads, recreates) = makefile_references(&text, matches_source);
            if includes {
                self.warnings.push(format!("{path} includes {source_name} in Makefile"));
            }
            if reads {
                self.warnings.push(format!("{path} recipe may still read {source_name}"));
            }
            if recreates {
                self.warnings.push(format!("{path} recipe may recreate {source_name}"));
            }
        }
        self.package_scripts(directory, dir, &source_name, matches_source);
        self.tool_config_dotenv_loaders(directory, dir, &source_name, matches_source);
        if implicit {
            self.cargo_dotenv_dependencies(directory, dir, &source_name);
        }
    }

    fn scan_subdirectories(
        &mut self,
        directory: &InputDirectory,
        dir: &Path,
        remaining_depth: usize,
        visited: &mut BTreeSet<PathBuf>,
        dirs_budget: &mut usize,
        files_budget: &mut usize,
    ) {
        if remaining_depth == 0 || *dirs_budget == 0 || *files_budget == 0 {
            return;
        }
        let mut names = directory.names().unwrap_or_default();
        names.sort_unstable();
        let source = self.source;
        let source_name =
            source.file_name().unwrap_or_default().to_string_lossy().escape_debug().to_string();
        for entry in names {
            if *dirs_budget == 0 || *files_budget == 0 {
                break;
            }
            let Some(name) = entry.to_str() else { continue };
            if name.starts_with('.') || SKIP_DIRECTORIES.contains(&name) {
                continue;
            }
            if !directory.is_directory(&entry) {
                continue;
            }
            let child_path = dir.join(name);
            if !visited.insert(child_path.clone()) {
                continue;
            }
            *dirs_budget -= 1;
            let Ok(child_dir) = directory.child_directory(&entry) else { continue };
            let mut child_names = child_dir.names().unwrap_or_default();
            child_names.sort_unstable();
            let matches_source =
                |literal: &str| normalized_path(&child_path.join(literal)) == source;
            for file in child_names.iter().filter_map(|file| file.to_str()) {
                if *files_budget == 0 {
                    break;
                }
                if is_compose_file(file) {
                    *files_budget -= 1;
                    let Some(text) = read_config(&child_dir, file, MAX_CONFIG_BYTES) else {
                        continue;
                    };
                    if compose_references(&text, matches_source) {
                        let path = relative_display(self.root, &child_path.join(file));
                        self.warnings.push(format!(
                            "{path} references {source_name} in Docker Compose env_file; replace with environment: pass-through or mark required: false"
                        ));
                    }
                } else if matches!(file, "Makefile" | "makefile" | "GNUmakefile") {
                    *files_budget -= 1;
                    let Some(text) = read_config(&child_dir, file, MAX_CONFIG_BYTES) else {
                        continue;
                    };
                    let path = relative_display(self.root, &child_path.join(file));
                    let (includes, reads, recreates) = makefile_references(&text, matches_source);
                    if includes {
                        self.warnings.push(format!("{path} includes {source_name} in Makefile"));
                    }
                    if reads {
                        self.warnings.push(format!("{path} recipe may still read {source_name}"));
                    }
                    if recreates {
                        self.warnings.push(format!("{path} recipe may recreate {source_name}"));
                    }
                }
            }
            if *files_budget > 0 && child_dir.is_regular("package.json") {
                *files_budget -= 1;
                self.package_scripts(&child_dir, &child_path, &source_name, matches_source);
            }
            if *files_budget > 0 {
                self.tool_config_dotenv_loaders(
                    &child_dir,
                    &child_path,
                    &source_name,
                    matches_source,
                );
            }
            if *files_budget > 0
                && self.source.file_name() == Some(OsStr::new(".env"))
                && self.source.parent().is_some_and(|root| child_path.starts_with(root))
                && !child_dir.is_regular(".env")
                && child_dir.is_regular("Cargo.toml")
            {
                *files_budget -= 1;
                self.cargo_dotenv_dependencies(&child_dir, &child_path, &source_name);
            }
            self.scan_subdirectories(
                &child_dir,
                &child_path,
                remaining_depth - 1,
                visited,
                dirs_budget,
                files_budget,
            );
        }
    }

    fn tool_config_dotenv_loaders(
        &mut self,
        directory: &InputDirectory,
        dir: &Path,
        source_name: &str,
        matches_source: impl Fn(&str) -> bool,
    ) {
        const TOOL_CONFIG_FILES: &[&str] = &[
            "prisma.config.ts",
            "prisma.config.mts",
            "prisma.config.js",
            "prisma.config.mjs",
            "prisma.config.cjs",
            "drizzle.config.ts",
            "drizzle.config.mts",
            "drizzle.config.js",
            "drizzle.config.mjs",
            "drizzle.config.cjs",
            "vite.config.ts",
            "vite.config.mts",
            "vite.config.js",
            "vite.config.mjs",
            "vitest.config.ts",
            "vitest.config.mts",
            "vitest.config.js",
            "vitest.config.mjs",
            "next.config.ts",
            "next.config.mjs",
            "next.config.js",
            "playwright.config.ts",
            "playwright.config.js",
        ];
        for file in TOOL_CONFIG_FILES {
            if !directory.is_regular(file) {
                continue;
            }
            let Some(text) = read_config(directory, file, MAX_SCRIPT_BYTES) else { continue };
            if config_file_loads_env(&text, &matches_source) {
                let path = relative_display(self.root, &dir.join(file));
                self.warnings.push(format!(
                    "{path} loads {source_name}; run through `locket run <policy>` or `locket exec` once archived"
                ));
            }
        }
    }

    fn cargo_dotenv_dependencies(
        &mut self,
        directory: &InputDirectory,
        dir: &Path,
        source_name: &str,
    ) {
        let Some(text) = read_config(directory, "Cargo.toml", MAX_CONFIG_BYTES) else { return };
        let Ok(manifest) = toml::from_str::<toml::Value>(&text) else { return };
        let path = relative_display(self.root, &dir.join("Cargo.toml"));
        for dep in ["dotenvy", "dotenv"] {
            let declared =
                ["dependencies", "dev-dependencies", "build-dependencies"].iter().any(|section| {
                    manifest
                        .get(*section)
                        .and_then(toml::Value::as_table)
                        .is_some_and(|table| table.contains_key(dep))
                });
            if declared {
                self.warnings.push(format!(
                    "{path} depends on {dep}; Rust code calling `{dep}::dotenv()` requires `locket run <policy>` or `locket exec` once {source_name} is archived"
                ));
            }
        }
    }

    fn package_scripts(
        &mut self,
        directory: &InputDirectory,
        dir: &Path,
        source_name: &str,
        matches_source: impl Fn(&str) -> bool,
    ) {
        let Some(text) = read_config(directory, "package.json", MAX_CONFIG_BYTES) else { return };
        let Ok(manifest) = serde_json::from_str::<Value>(&text) else { return };
        let path = relative_display(self.root, &dir.join("package.json"));
        let may_load_root_dotenv = self.source.file_name() == Some(OsStr::new(".env"))
            && (self.source.parent() == Some(dir)
                || (self.source.parent().is_some_and(|root| dir.starts_with(root))
                    && !directory.is_regular(".env")));
        if may_load_root_dotenv {
            for dep in ["dotenv", "dotenvx", "@dotenvx/dotenvx"] {
                let declared = ["dependencies", "devDependencies", "optionalDependencies"]
                    .iter()
                    .any(|section| {
                        manifest
                            .get(*section)
                            .and_then(Value::as_object)
                            .is_some_and(|table| table.contains_key(dep))
                    });
                if declared {
                    self.warnings.push(format!(
                        "{path} depends on {dep}; code loading {source_name} (such as `import 'dotenv/config'`) requires `locket run <policy>` or `locket exec` once archived"
                    ));
                }
            }
        }
        let Some(scripts) = manifest.get("scripts").and_then(Value::as_object) else { return };
        for (name, script) in scripts {
            let Some(script) = script.as_str() else { continue };
            let mut reads = false;
            let mut recreates = false;
            shell_commands(script, None, None, |words| {
                reads |= command_references(words, &matches_source);
                recreates |= command_recreates(words, &matches_source);
                if let Some(script) = local_script_argument(words)
                    && let Some(script) = self.local_script_recreates(dir, script, &matches_source)
                {
                    self.warnings.push(format!(
                        "{script} (invoked by {path} script {name:?}) may recreate {source_name}"
                    ));
                }
                false
            });
            if reads {
                self.warnings.push(format!("{path} script {name:?} may still read {source_name}"));
            }
            if recreates {
                self.warnings.push(format!("{path} script {name:?} may recreate {source_name}"));
            }
        }
    }

    fn local_script_recreates(
        &mut self,
        cwd: &Path,
        literal: &str,
        matches_source: impl Fn(&str) -> bool,
    ) -> Option<String> {
        let root = self.git_root?;
        let path = cwd.join(literal);
        let parent = script_parent(path.parent()?, root)?;
        let name = path.file_name()?.to_str()?;
        let path = parent.join(name);
        // Cache both successes and failures so repeated references cannot multiply file reads.
        if self.scripts.len() == MAX_SCRIPTS && !self.scripts.contains_key(&path) {
            return None;
        }
        let script = self.scripts.entry(path.clone()).or_insert_with(|| LocalScript {
            text: InputDirectory::open(&parent)
                .ok()
                .and_then(|dir| read_config(&dir, name, MAX_SCRIPT_BYTES)),
            recreates_in: BTreeMap::new(),
        });
        let text = script.text.as_deref()?;
        let path_ctx = StaticPathContext { cwd, script_dir: &parent };
        if *script
            .recreates_in
            .entry(cwd.to_owned())
            .or_insert_with(|| local_script_recreates(text, path_ctx, matches_source))
        {
            Some(relative_display(root, &path))
        } else {
            None
        }
    }
}

fn config_file_loads_env(text: &str, matches_source: &impl Fn(&str) -> bool) -> bool {
    let mut chars = text.chars();
    let mut quoted_matches_source = false;
    while let Some(ch) = chars.next() {
        if matches!(ch, '"' | '\'' | '`') {
            let quote = ch;
            let mut literal = String::new();
            while let Some(inner) = chars.next() {
                if inner == '\\' {
                    let _ = chars.next();
                    continue;
                }
                if inner == quote {
                    break;
                }
                if literal.len() < 256 {
                    literal.push(inner);
                }
            }
            if literal == "dotenv/config" {
                return true;
            }
            if literal.contains(".env") && matches_source(&literal) {
                quoted_matches_source = true;
            }
        }
    }
    quoted_matches_source
}

fn script_parent(parent: &Path, root: &Path) -> Option<PathBuf> {
    let relative = parent.strip_prefix(root).ok()?;
    let mut path = root.to_path_buf();
    for component in relative.components() {
        match component {
            Component::Normal(name) => path.push(name),
            Component::CurDir => {}
            Component::ParentDir if path != root => {
                // A symlink before `..` would change which file the script names.
                InputDirectory::open(&path).ok()?;
                path.pop();
            }
            _ => return None,
        }
    }
    Some(path)
}

fn makefile_references(text: &str, matches_source: impl Fn(&str) -> bool) -> (bool, bool, bool) {
    let (mut includes, mut reads, mut recreates) = (false, false, false);
    for line in text.lines() {
        if let Some(recipe) = line.strip_prefix('\t') {
            let recipe = recipe.trim_start().trim_start_matches(['@', '-', '+']);
            shell_commands(recipe, None, None, |words| {
                reads |= command_references(words, &matches_source);
                recreates |= command_recreates(words, &matches_source);
                false
            });
        } else if let Some((directive, files)) = line.trim_start().split_once(char::is_whitespace)
            && matches!(directive, "include" | "-include" | "sinclude")
        {
            includes |= shell_commands(files, None, None, |words| {
                words.iter().flatten().any(|name| matches_source(name))
            });
        }
    }
    (includes, reads, recreates)
}

fn is_compose_file(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(stem, extension)| {
        (stem.starts_with("compose")
            || stem.starts_with("docker-compose")
            || stem.ends_with(".compose"))
            && (extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml"))
    })
}

fn read_config(directory: &InputDirectory, name: &str, limit: u64) -> Option<String> {
    if !directory.is_regular(name) {
        return None;
    }
    let mut file = directory.open_file(name.as_ref()).ok()?;
    if file.metadata().ok()?.len() > limit {
        return None;
    }
    let mut text = String::new();
    (&mut file).take(limit + 1).read_to_string(&mut text).ok()?;
    (text.len() <= usize::try_from(limit).ok()?).then_some(text)
}

fn normalized_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component),
        }
    }
    normalized
}

fn relative_display(root: &Path, path: &Path) -> String {
    for (levels, ancestor) in root.ancestors().enumerate() {
        if let Ok(relative) = path.strip_prefix(ancestor) {
            let display = std::iter::repeat_n("..", levels).collect::<PathBuf>().join(relative);
            return display
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/")
                .escape_debug()
                .to_string();
        }
    }
    // Windows paths on different volumes have no common ancestor.
    path.file_name().unwrap_or_default().to_string_lossy().escape_debug().to_string()
}

fn compose_references(text: &str, matches_source: impl Fn(&str) -> bool) -> bool {
    // Handle literal scalars and lists without expanding aliases or interpolation.
    let matches_scalar =
        |value| yaml_literal(value).is_some_and(|literal| matches_source(&literal));
    let mut env_indent = None;
    let mut item_indent = None;
    let mut block_indent = None;
    for line in text.lines() {
        let line = strip_yaml_comment(line);
        let content = line.trim_start_matches(' ');
        if content.is_empty() {
            continue;
        }
        let indent = line.len() - content.len();
        if block_indent.is_some_and(|block| indent > block) {
            continue;
        }
        block_indent = None;
        let item = content.strip_prefix("- ").map(str::trim_start);
        let block =
            content.rsplit_once(": ").map_or_else(|| item.unwrap_or(content), |(_, value)| value);
        if block.starts_with(['|', '>']) {
            block_indent = Some(indent);
        }
        if let Some(env) = env_indent {
            if indent >= env
                && let Some(item) = item
            {
                item_indent = Some(indent);
                if matches_scalar(yaml_field(item, "path").unwrap_or(item)) {
                    return true;
                }
                continue;
            }
            if let Some(item) = item_indent
                && indent > item
                && let Some(path) = yaml_field(content, "path")
                && matches_scalar(path)
            {
                return true;
            }
            if indent <= env {
                env_indent = None;
                item_indent = None;
            }
        }
        if let Some(value) = yaml_field(content, "env_file") {
            if value.is_empty() {
                env_indent = Some(indent);
                item_indent = None;
            } else if let Some(list) = value.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                if yaml_flow_entries(list).any(matches_scalar) {
                    return true;
                }
            } else if matches_scalar(value) {
                return true;
            }
        }
    }
    false
}

fn compose_interpolation_overlap(text: &str, env_names: &BTreeSet<String>) -> Option<String> {
    if env_names.is_empty() {
        return None;
    }
    let mut overlap = BTreeSet::new();
    for mut line in text.lines().map(strip_yaml_comment) {
        let trailing_bytes = line.rsplit_once('}').map_or(line.len(), |(_, after)| after.len());
        while let Some((_, after_dollar)) = line.split_once('$') {
            line = after_dollar;
            if let Some(after_escape) = line.strip_prefix('$') {
                line = after_escape;
                continue;
            }
            let expression = line.strip_prefix('{');
            let variable = expression.unwrap_or(line);
            let suffix =
                variable.trim_start_matches(|ch: char| ch.is_ascii_alphanumeric() || ch == '_');
            let name = &variable[..variable.len() - suffix.len()];
            if is_shell_variable_name(name)
                && (expression.is_none()
                    || suffix.starts_with('}')
                    || (suffix.len() > trailing_bytes
                        && suffix.strip_prefix(':').unwrap_or(suffix).starts_with(['-', '?', '+'])))
                && env_names.contains(name)
            {
                overlap.insert(name);
            }
            line = suffix;
        }
    }
    if overlap.is_empty() {
        return None;
    }
    let mut keys =
        overlap.iter().copied().take(MAX_INTERPOLATION_KEYS).collect::<Vec<_>>().join(", ");
    let extra = overlap.len().saturating_sub(MAX_INTERPOLATION_KEYS);
    if extra > 0 {
        use std::fmt::Write as _;
        let _ = write!(keys, " (+{extra} more)");
    }
    Some(keys)
}

fn yaml_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)
        .or_else(|| line.strip_prefix('\'')?.strip_prefix(key)?.strip_prefix('\''))
        .or_else(|| line.strip_prefix('"')?.strip_prefix(key)?.strip_prefix('"'))?
        .trim_start()
        .strip_prefix(':')
        .filter(|value| value.is_empty() || value.starts_with(char::is_whitespace))
        .map(str::trim)
}

fn yaml_literal(value: &str) -> Option<Cow<'_, str>> {
    let value = value.trim();
    let literal = if let Some(value) = value.strip_prefix('\'') {
        Cow::Owned(value.strip_suffix('\'')?.replace("''", "'"))
    } else if value.starts_with('"') {
        Cow::Owned(serde_json::from_str::<String>(value).ok()?)
    } else if value.starts_with(['[', '{', '&', '*', '!', '|', '>', '#', '%', '@', '\x60'])
        || value.contains(": ")
        || matches!(value, "" | "null" | "~")
    {
        return None;
    } else {
        Cow::Borrowed(value)
    };
    (!literal.is_empty() && !literal.contains(['$', '\0'])).then_some(literal)
}

fn strip_yaml_comment(line: &str) -> &str {
    for (index, ch) in unquoted_yaml_chars(line) {
        if ch == '#' && (index == 0 || line.as_bytes()[index - 1].is_ascii_whitespace()) {
            return line[..index].trim_end();
        }
    }
    line.trim_end()
}

fn yaml_flow_entries(mut list: &str) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        if list.is_empty() {
            return None;
        }
        let mut depth = 0_usize;
        let comma = unquoted_yaml_chars(list).find_map(|(index, ch)| {
            match ch {
                '[' | '{' => depth += 1,
                ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => return Some(index),
                _ => {}
            }
            None
        });
        let Some(comma) = comma else { return Some(std::mem::take(&mut list)) };
        let (entry, remainder) = list.split_at(comma);
        list = &remainder[1..];
        Some(entry)
    })
}

fn unquoted_yaml_chars(line: &str) -> impl Iterator<Item = (usize, char)> {
    let mut quote = None;
    let mut escaped = false;
    line.char_indices().filter(move |&(_, ch)| {
        if escaped {
            escaped = false;
        } else if quote == Some(ch) {
            quote = None;
        } else if quote == Some('"') && ch == '\\' {
            escaped = true;
        } else if quote.is_none() {
            if matches!(ch, '\'' | '"') {
                quote = Some(ch);
            } else {
                return true;
            }
        }
        false
    })
}

#[derive(Clone, Copy)]
struct StaticPathContext<'a> {
    cwd: &'a Path,
    script_dir: &'a Path,
}

fn shell_commands(
    script: &str,
    variables: Option<&BTreeMap<String, String>>,
    path_ctx: Option<StaticPathContext<'_>>,
    mut visit: impl FnMut(&[Option<String>]) -> bool,
) -> bool {
    let mut chars = script.chars().peekable();
    let mut words = Vec::new();
    while let Some(&ch) = chars.peek() {
        match ch {
            '\n' | ';' | '|' | '&' => {
                if visit(&words) {
                    return true;
                }
                words.clear();
                chars.next();
            }
            '#' => {
                while chars.peek().is_some_and(|ch| *ch != '\n') {
                    chars.next();
                }
            }
            ch if ch.is_ascii_whitespace() => {
                chars.next();
            }
            // A file argument before a redirection still belongs to this command.
            // Stop here so heredoc bodies and compound commands are never read as arguments.
            '<' | '>' => return visit(&words),
            '(' | ')' => return false,
            _ => {
                let Ok(word) = shell_word(&mut chars, variables, path_ctx, false, 0) else {
                    return false;
                };
                words.push(word);
            }
        }
    }
    visit(&words)
}

fn shell_word(
    chars: &mut Peekable<Chars<'_>>,
    variables: Option<&BTreeMap<String, String>>,
    path_ctx: Option<StaticPathContext<'_>>,
    allow_static_subst: bool,
    depth: usize,
) -> Result<Option<String>, ()> {
    if depth > MAX_SUBST_DEPTH {
        return Err(());
    }
    let mut word = String::new();
    let mut quote = None;
    let mut literal = true;
    while let Some(&ch) = chars.peek() {
        if quote.is_none()
            && (ch.is_ascii_whitespace() || matches!(ch, ';' | '|' | '&' | '<' | '>' | '(' | ')'))
        {
            break;
        }
        chars.next();
        match ch {
            ch if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(ch),
            '\\' if quote != Some('\'') => {
                let next = *chars.peek().ok_or(())?;
                if quote.is_none() || matches!(next, '"' | '\\' | '$' | '\x60' | '\n') {
                    chars.next();
                    if next != '\n' {
                        word.push(next);
                    }
                } else {
                    word.push(ch);
                }
            }
            '\x60' if quote != Some('\'') => return Err(()),
            '$' if quote != Some('\'') => {
                if chars.peek() == Some(&'(') {
                    if !allow_static_subst {
                        return Err(());
                    }
                    let Some(ctx) = path_ctx else { return Err(()) };
                    let inner = take_balanced_parens(chars)?;
                    let Some(resolved) =
                        eval_static_command_subst(&inner, variables, ctx, depth + 1)
                    else {
                        return Err(());
                    };
                    if word.len() + resolved.len() > MAX_STATIC_WORD_BYTES {
                        return Err(());
                    }
                    word.push_str(&resolved);
                } else if let Some(variables) = variables {
                    let expanded = expand_shell_variable(
                        chars,
                        variables,
                        path_ctx,
                        allow_static_subst,
                        depth,
                    )?;
                    if let Some(value) = expanded {
                        if word.len() + value.len() > MAX_STATIC_WORD_BYTES {
                            return Err(());
                        }
                        if quote.is_none() && value.contains(char::is_whitespace) {
                            literal = false;
                        }
                        word.push_str(&value);
                    } else {
                        literal = false;
                    }
                } else {
                    literal = false;
                    word.push(ch);
                }
            }
            '*' | '?' | '[' | '{' | '~' if quote.is_none() => {
                literal = false;
                word.push(ch);
            }
            _ => word.push(ch),
        }
    }
    if quote.is_some() { Err(()) } else { Ok(literal.then_some(word)) }
}

fn take_balanced_parens(chars: &mut Peekable<Chars<'_>>) -> Result<String, ()> {
    if chars.next() != Some('(') {
        return Err(());
    }
    let mut inner = String::new();
    let mut paren_depth = 1_usize;
    let mut quote = None;
    let mut escaped = false;
    for ch in chars.by_ref() {
        if escaped {
            escaped = false;
            inner.push(ch);
            continue;
        }
        if quote == Some('"') && ch == '\\' {
            escaped = true;
            inner.push(ch);
            continue;
        }
        if quote == Some(ch) {
            quote = None;
            inner.push(ch);
            continue;
        }
        if quote.is_none() {
            match ch {
                '\'' | '"' => quote = Some(ch),
                '(' => paren_depth += 1,
                ')' => {
                    paren_depth -= 1;
                    if paren_depth == 0 {
                        return Ok(inner);
                    }
                }
                _ => {}
            }
        }
        if inner.len() >= MAX_STATIC_WORD_BYTES {
            return Err(());
        }
        inner.push(ch);
    }
    Err(())
}

fn expand_shell_variable(
    chars: &mut Peekable<Chars<'_>>,
    variables: &BTreeMap<String, String>,
    path_ctx: Option<StaticPathContext<'_>>,
    allow_static_subst: bool,
    depth: usize,
) -> Result<Option<String>, ()> {
    if chars.peek() == Some(&'{') {
        chars.next();
        let mut expr = String::new();
        let mut brace_depth = 1_usize;
        for ch in chars.by_ref() {
            match ch {
                '{' => brace_depth += 1,
                '}' => {
                    brace_depth -= 1;
                    if brace_depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            if expr.len() >= MAX_STATIC_WORD_BYTES {
                return Err(());
            }
            expr.push(ch);
        }
        if brace_depth != 0 {
            return Err(());
        }
        if matches!(expr.as_str(), "BASH_SOURCE" | "BASH_SOURCE[0]" | "0") {
            return Ok(
                path_ctx.map(|ctx| ctx.script_dir.join("_script").to_string_lossy().into_owned())
            );
        }
        if let Some((name, default)) = expr.split_once(":-") {
            if let Some(value) = variables.get(name).filter(|value| !value.is_empty()) {
                return Ok(Some(value.clone()));
            }
            let mut default_chars = default.chars().peekable();
            let resolved = shell_word(
                &mut default_chars,
                Some(variables),
                path_ctx,
                allow_static_subst,
                depth + 1,
            )?;
            return Ok(default_chars.peek().is_none().then_some(resolved).flatten());
        }
        return Ok(variables.get(&expr).cloned());
    }
    if chars.peek() == Some(&'0') {
        chars.next();
        return Ok(
            path_ctx.map(|ctx| ctx.script_dir.join("_script").to_string_lossy().into_owned())
        );
    }
    let mut name = String::new();
    while let Some(ch) = chars.next_if(|ch| ch.is_ascii_alphanumeric() || *ch == '_') {
        name.push(ch);
    }
    if name == "BASH_SOURCE" {
        return Ok(
            path_ctx.map(|ctx| ctx.script_dir.join("_script").to_string_lossy().into_owned())
        );
    }
    Ok(variables.get(&name).cloned())
}

fn eval_static_command_subst(
    inner: &str,
    variables: Option<&BTreeMap<String, String>>,
    ctx: StaticPathContext<'_>,
    depth: usize,
) -> Option<String> {
    let trimmed = inner.trim();
    if trimmed == "pwd" {
        return Some(if ctx.cwd.as_os_str().is_empty() {
            ".".to_owned()
        } else {
            ctx.cwd.to_string_lossy().into_owned()
        });
    }
    if let Some(rest) =
        trimmed.strip_prefix("dirname").filter(|rest| rest.starts_with(char::is_whitespace))
    {
        let arg = eval_single_static_arg(rest.trim(), variables, ctx, depth)?;
        let path = normalized_path(Path::new(&arg));
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        return Some(parent.to_string_lossy().into_owned());
    }
    if let Some((before_and, after_and)) = trimmed.split_once("&&")
        && after_and.trim() == "pwd"
        && let Some(cd_rest) = before_and
            .trim()
            .strip_prefix("cd")
            .filter(|rest| rest.starts_with(char::is_whitespace))
    {
        let target_expr = strip_trailing_redirections(cd_rest.trim());
        let arg = eval_single_static_arg(target_expr, variables, ctx, depth)?;
        let resolved = if Path::new(&arg).is_absolute() || ctx.cwd.as_os_str().is_empty() {
            normalized_path(Path::new(&arg))
        } else {
            normalized_path(&ctx.cwd.join(&arg))
        };
        return Some(resolved.to_string_lossy().into_owned());
    }
    None
}

fn eval_single_static_arg(
    expr: &str,
    variables: Option<&BTreeMap<String, String>>,
    ctx: StaticPathContext<'_>,
    depth: usize,
) -> Option<String> {
    let expr = expr.strip_prefix("--").map_or(expr, str::trim_start);
    let mut chars = expr.chars().peekable();
    let value = shell_word(&mut chars, variables, Some(ctx), true, depth).ok().flatten()?;
    (chars.collect::<String>().trim().is_empty() && !value.is_empty()).then_some(value)
}

fn strip_trailing_redirections(expr: &str) -> &str {
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in expr.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && ch == '\\' {
            escaped = true;
            continue;
        }
        if quote == Some(ch) {
            quote = None;
            continue;
        }
        if quote.is_none() {
            if matches!(ch, '\'' | '"') {
                quote = Some(ch);
            } else if matches!(ch, '>' | '<') {
                let prefix = expr[..index].trim_end();
                return prefix
                    .strip_suffix('&')
                    .or_else(|| prefix.strip_suffix('2'))
                    .or_else(|| prefix.strip_suffix('1'))
                    .filter(|trimmed| {
                        trimmed.is_empty()
                            || trimmed.chars().last().is_some_and(char::is_whitespace)
                    })
                    .map_or(prefix, str::trim_end);
            }
        }
    }
    expr
}

fn local_script_argument(words: &[Option<String>]) -> Option<&str> {
    let (program, args) = words.split_first()?;
    let program = program.as_deref()?;
    if matches!(Path::new(program).file_name()?.to_str()?, "sh" | "bash") {
        let (first, rest) = args.split_first()?;
        let argument = first.as_deref()?;
        return match argument {
            "--" => rest.first()?.as_deref(),
            option if option.starts_with('-') => None,
            path => Some(path),
        };
    }
    (program.starts_with("./") || program.starts_with("../") || Path::new(program).is_absolute())
        .then_some(program)
}

fn local_script_recreates(
    script: &str,
    path_ctx: StaticPathContext<'_>,
    matches_source: impl Fn(&str) -> bool,
) -> bool {
    let mut variables = BTreeMap::new();
    for line in script.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains("<<") {
            break;
        }
        let assignment = line.strip_prefix("export ").unwrap_or(line);
        if let Some((name, value)) = assignment.split_once('=')
            && is_shell_variable_name(name)
        {
            let mut chars = value.chars().peekable();
            let value =
                shell_word(&mut chars, Some(&variables), Some(path_ctx), true, 0).ok().flatten();
            let trailing = chars.collect::<String>();
            if let Some(value) =
                value.filter(|value| !value.is_empty() && value.len() <= MAX_STATIC_WORD_BYTES)
                && (trailing.trim().is_empty() || trailing.trim_start().starts_with('#'))
            {
                variables.insert(name.to_owned(), value);
            } else {
                variables.remove(name);
            }
            continue;
        }
        let mut changes_context = false;
        if shell_commands(line, Some(&variables), Some(path_ctx), |words| {
            // The initial working directory is the package directory. Stop at commands
            // that could change it or invalidate the static assignment state.
            let program = words.first().and_then(Option::as_deref);
            changes_context |=
                matches!(program, Some("cd" | "pushd" | "popd" | "." | "source" | "eval"));
            !changes_context && command_recreates(words, &matches_source)
        }) {
            return true;
        }
        if changes_context {
            break;
        }
        if line.starts_with("unset ") {
            variables.clear();
        }
    }
    false
}

fn is_shell_variable_name(name: &str) -> bool {
    let mut chars = name.bytes();
    chars.next().is_some_and(|ch| ch.is_ascii_alphabetic() || ch == b'_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
}

fn command_recreates(words: &[Option<String>], matches_source: impl Fn(&str) -> bool) -> bool {
    let Some((Some(program), args)) = words.split_first() else { return false };
    let program = Path::new(program).file_name().and_then(OsStr::to_str);
    if !matches!(program, Some("cp" | "mv" | "install")) {
        return false;
    }
    let Some((Some(destination), inputs)) = args.split_last() else { return false };
    let mut operands = false;
    let mut options = true;
    for input in inputs {
        match input.as_deref() {
            Some("--") if options => options = false,
            Some(flag) if options && flag.starts_with("--") => {
                if flag == "--directory"
                    || flag == "--target-directory"
                    || flag.starts_with("--target-directory=")
                {
                    return false;
                }
            }
            Some(flag) if options && flag.starts_with('-') && flag != "-" => {
                if flag.contains('t') || (program == Some("install") && flag.contains('d')) {
                    return false;
                }
            }
            _ => operands = true,
        }
    }
    operands && (!options || !destination.starts_with('-')) && matches_source(destination)
}

fn command_references(words: &[Option<String>], matches_source: impl Fn(&str) -> bool) -> bool {
    let Some((program, args)) = words.split_first() else { return false };
    let Some(program) = program.as_deref().and_then(|name| Path::new(name).file_name()) else {
        return false;
    };
    let short_option = match program.to_str() {
        Some("echo" | "printf") => return false,
        Some("env-cmd") => Some("-f"),
        Some("dotenv") => Some("-e"),
        _ => None,
    };
    for (index, arg) in args.iter().enumerate() {
        let Some(arg) = arg.as_deref() else { continue };
        if arg == "--" {
            break;
        }
        if arg.strip_prefix("--env-file=").is_some_and(&matches_source)
            || (arg == "--env-file" || Some(arg) == short_option)
                && args.get(index + 1).and_then(Option::as_deref).is_some_and(&matches_source)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod monorepo_consumer_tests {
    use super::*;
    use std::fs;

    #[test]
    fn root_env_archive_warns_for_workspace_subdirectory_dotenv_and_scripts()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().canonicalize()?;
        fs::create_dir_all(root.join("apps/bot"))?;
        fs::create_dir_all(root.join("apps/web"))?;
        fs::write(root.join(".env"), "BOT_TOKEN=fixture\n")?;
        fs::write(
            root.join("apps/bot/package.json"),
            r#"{"dependencies":{"dotenv":"^16.0.0"},"scripts":{"start":"node --env-file=../../.env dist/index.js"}}"#,
        )?;
        fs::write(
            root.join("apps/bot/prisma.config.ts"),
            r#"import { config as loadDotenv } from "dotenv"; loadDotenv({ path: path.resolve(__dirname, "../../.env") });"#,
        )?;
        // Subdirectory with its own .env should not trigger the root soft-loader advisory.
        fs::write(root.join("apps/web/.env"), "WEB_KEY=fixture\n")?;
        fs::write(root.join("apps/web/package.json"), r#"{"dependencies":{"dotenv":"^16.0.0"}}"#)?;

        let names = BTreeSet::from(["BOT_TOKEN".to_owned()]);
        let warnings = detect_archive_consumers(&root.join(".env"), Some(&root), &names);
        assert!(
            warnings.iter().any(|w| w.contains("apps/bot/package.json") && w.contains("dotenv")),
            "expected apps/bot dotenv warning, got: {warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("apps/bot/package.json") && w.contains("start")),
            "expected apps/bot script warning, got: {warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("apps/bot/prisma.config.ts") && w.contains("loads .env")),
            "expected apps/bot prisma.config.ts warning, got: {warnings:?}"
        );
        assert!(
            !warnings.iter().any(|w| w.contains("apps/web/package.json")),
            "unexpected apps/web warning when it has its own .env: {warnings:?}"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;

    use super::*;

    #[test]
    fn consumer_scan_ignores_compose_without_key_overlap() -> io::Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path();
        fs::write(root.join("docker-compose.dev.yml"), "services: {app: {image: '${IMAGE}'}}\n")?;
        let names = BTreeSet::from(["TOKEN".to_owned()]);
        let warnings = detect_archive_consumers(&root.join(".env"), Some(root), &names);
        assert!(warnings.is_empty(), "{warnings:?}");
        Ok(())
    }

    #[test]
    fn consumer_scan_ignores_optional_node_env_file() -> io::Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path();
        let manifest = root.join("package.json");
        let source = root.join(".env");
        fs::write(
            &manifest,
            r#"{"scripts":{"start":"node --env-file-if-exists=.env server.js"}}"#,
        )?;
        assert_eq!(
            detect_archive_consumers(&source, Some(root), &BTreeSet::new()),
            Vec::<String>::new()
        );
        fs::write(&manifest, r#"{"scripts":{"start":"node --env-file=.env server.js"}}"#)?;
        assert_eq!(
            detect_archive_consumers(&source, Some(root), &BTreeSet::new()),
            ["package.json script \"start\" may still read .env"],
        );
        Ok(())
    }

    #[test]
    fn consumer_scan_reports_only_sorted_compose_key_overlap() -> io::Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path();
        let source = root.join(".env");
        fs::write(
            root.join("compose.production.yaml"),
            concat!(
                "services:\n  app:\n    environment:\n",
                "      REDIS: $REDIS_URL # ${COMMENTED}\n",
                "      POSTGRES: \"prefix # ${POSTGRES_PASSWORD:-dev}\"\n",
                "      ESCAPED: $$ESCAPED_VAR $${ESCAPED_VAR}\n",
                "      IMAGE: ${IMAGE}\n",
            ),
        )?;
        let names = ["REDIS_URL", "POSTGRES_PASSWORD", "ESCAPED_VAR", "COMMENTED"]
            .map(str::to_owned)
            .into_iter()
            .collect();
        assert_eq!(
            detect_archive_consumers(&source, Some(root), &names),
            [
                "compose.production.yaml interpolates POSTGRES_PASSWORD, REDIS_URL from .env through Docker Compose; run via `locket compose run --policy <name> -- ...`"
            ],
        );
        assert_eq!(
            detect_archive_consumers(&source, Some(root), &BTreeSet::new()),
            Vec::<String>::new()
        );
        Ok(())
    }

    #[test]
    fn compose_interpolation_overlap_supports_operators_and_limits_display() {
        let names = (0..14).map(|i| format!("KEY_{i:02}")).collect();
        let text = concat!(
            "${KEY_00} ${KEY_01:-dev} ${KEY_02-dev} ${KEY_03:?error} ${KEY_04?error}\n",
            "${KEY_05:+alt} ${KEY_06+alt} ${KEY_07:-${KEY_08}} $KEY_09 $KEY_10 $KEY_11 $KEY_12 $KEY_13\n",
        );
        assert_eq!(
            compose_interpolation_overlap(text, &names).as_deref(),
            Some(
                "KEY_00, KEY_01, KEY_02, KEY_03, KEY_04, KEY_05, KEY_06, KEY_07, KEY_08, KEY_09, KEY_10, KEY_11 (+2 more)"
            ),
        );
        assert!(
            compose_interpolation_overlap("${KEY_00/invalid} ${KEY_01:-unclosed", &names).is_none()
        );
    }

    #[test]
    fn templates_resolve_only_literal_or_statically_assigned_destinations() {
        let cwd = Path::new("/repo");
        let script_dir = Path::new("/repo/scripts");
        let ctx = StaticPathContext { cwd, script_dir };
        let matches = |path: &str| normalized_path(&cwd.join(path)) == Path::new("/repo/.env");
        for script in [
            r#"cp -n ".env.example" "./.env""#,
            "mv -- .env.example .env",
            "ENV_FILE=.env\ncp .env.example \"$ENV_FILE\"",
            "REPO_ROOT=\"$(pwd)\"\nENV_FILE=\"${REPO_ROOT}/.env\"\ninstall .env.example \"$ENV_FILE\"",
            concat!(
                "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n",
                "PROJECT_ROOT=\"$(dirname \"$SCRIPT_DIR\")\"\n",
                "ENV_FILE=\"${ENV_FILE:-$PROJECT_ROOT/.env}\"\n",
                "ensure_env() {\n",
                "  cp \"$PROJECT_ROOT/.env.example\" \"$ENV_FILE\"\n",
                "}\n",
            ),
            concat!(
                "ROOT=\"$(cd \"$(dirname \"$0\")/..\" >/dev/null 2>&1 && pwd)\"\n",
                "cp \"$ROOT/.env.example\" \"$ROOT/.env\"\n",
            ),
        ] {
            assert!(local_script_recreates(script, ctx, matches), "{script}");
        }
        for script in [
            "cp .env .env.example",
            "cp -t .env .env.example",
            "install -d .env",
            "echo 'cp .env.example .env'",
            "cp .env.example \"$ENV_FILE\"",
            "ENV_FILE=.env\ncp .env.example '$ENV_FILE'",
            "ENV_FILE=.env\nENV_FILE=\"$(custom)\"\ncp .env.example \"$ENV_FILE\"",
            "ENV_FILE=\"$ROOT_DIR/.env\"\ncp .env.example \"$ENV_FILE\"",
            "cat <<'EOF'\ncp .env.example .env\nEOF",
        ] {
            assert!(!local_script_recreates(script, ctx, matches), "{script}");
        }
    }

    #[test]
    fn consumer_scan_detects_subfolder_compose_manifest_loaders_and_script_dir_idiom()
    -> io::Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path();
        fs::create_dir(root.join(".git"))?;
        fs::create_dir(root.join("deploy"))?;
        fs::create_dir(root.join("scripts"))?;
        fs::create_dir(root.join("node_modules"))?;
        fs::write(root.join("deploy/compose.yaml"), "services:\n  app:\n    env_file: ../.env\n")?;
        fs::write(
            root.join("deploy/server.compose.yaml"),
            "services:\n  app:\n    env_file: ../.env\n",
        )?;
        // Skipped directory must never be scanned.
        fs::write(
            root.join("node_modules/compose.yaml"),
            "services:\n  app:\n    env_file: ../.env\n",
        )?;
        fs::write(
            root.join("scripts/dev.sh"),
            concat!(
                "#!/usr/bin/env bash\n",
                "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n",
                "PROJECT_ROOT=\"$(dirname \"$SCRIPT_DIR\")\"\n",
                "ENV_FILE=\"$PROJECT_ROOT/.env\"\n",
                "ensure_env() {\n",
                "  cp \"$PROJECT_ROOT/.env.example\" \"$ENV_FILE\"\n",
                "}\n",
            ),
        )?;
        fs::write(
            root.join("package.json"),
            serde_json::json!({
                "scripts": { "dev:docker": "./scripts/dev.sh start" },
                "dependencies": { "dotenv": "^17.4.2" }
            })
            .to_string(),
        )?;
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"demo\"\n[dependencies]\ndotenvy = \"0.15\"\n",
        )?;

        let warnings = detect_archive_consumers(&root.join(".env"), Some(root), &BTreeSet::new());
        assert!(
            warnings.iter().any(|w| w.starts_with("deploy/compose.yaml references .env")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.starts_with("deploy/server.compose.yaml references .env")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains(
                "scripts/dev.sh (invoked by package.json script \"dev:docker\") may recreate .env"
            )),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.starts_with("package.json depends on dotenv;")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.starts_with("Cargo.toml depends on dotenvy;")),
            "{warnings:?}"
        );
        assert!(!warnings.iter().any(|w| w.contains("node_modules")), "{warnings:?}");
        Ok(())
    }

    #[test]
    fn make_checks_literal_directives_and_recipe_commands() {
        let matches = |path: &str| normalized_path(Path::new(path)) == Path::new(".env");
        for directive in ["include", "-include", "sinclude"] {
            let makefile = format!("{directive} ./unrelated ./.env # comment");
            assert_eq!(makefile_references(&makefile, matches), (true, false, false));
        }
        assert_eq!(
            makefile_references(
                "start:\n\t@env-cmd -f .env node app.js\n\t+cp -n .env.example .env",
                matches
            ),
            (false, true, true)
        );
        assert_eq!(
            makefile_references(
                "# include .env\ninclude $(ENV_FILE)\nstart:\n\t@echo cp .env.example .env",
                matches
            ),
            (false, false, false)
        );
    }

    #[test]
    fn consumer_scan_stops_after_eight_ancestors() -> io::Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path();
        let deepest = "one/two/three/four/five/six/seven/eight/nine";
        fs::create_dir_all(root.join(deepest))?;
        fs::create_dir(root.join(".git"))?;
        fs::write(root.join("compose.yml"), format!("env_file: {deepest}/.env\n"))?;
        fs::write(
            root.join("one/compose.yml"),
            format!("env_file: {}/.env\n", deepest.trim_start_matches("one/")),
        )?;
        let source = root.join(deepest).join(".env");
        let warnings = detect_archive_consumers(&source, Some(root), &BTreeSet::new());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("one/compose.yml"));
        Ok(())
    }

    #[test]
    fn consumer_scan_checks_at_most_sixteen_local_scripts() -> io::Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path();
        fs::create_dir(root.join(".git"))?;
        let mut scripts = BTreeMap::new();
        for index in 0..=MAX_SCRIPTS {
            let name = format!("dev-{index:02}");
            fs::write(root.join(&name), "cp .env.example .env")?;
            scripts.insert(name.clone(), format!("sh ./{name}"));
        }
        fs::write(root.join("package.json"), serde_json::json!({"scripts": scripts}).to_string())?;
        let warnings = detect_archive_consumers(&root.join(".env"), Some(root), &BTreeSet::new());
        assert_eq!(warnings.len(), MAX_SCRIPTS);
        assert!(warnings[0].starts_with("dev-00"));
        assert!(warnings[MAX_SCRIPTS - 1].starts_with("dev-15"));
        Ok(())
    }
}
