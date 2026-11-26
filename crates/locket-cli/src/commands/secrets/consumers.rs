//! Static, metadata-only hints for files that may still consume a dotenv source.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Read as _;
use std::iter::Peekable;
use std::path::{Component, Path, PathBuf};
use std::str::Chars;

use serde_json::Value;

use super::env_files::InputDirectory;
use super::git_worktree_root;

const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_SCRIPT_BYTES: u64 = 64 * 1024;
const MAX_SCRIPTS: usize = 16;
const MAX_ANCESTORS: usize = 8;
const MAX_STATIC_WORD_BYTES: usize = 4096;

pub(super) fn detect_archive_consumers(source: &Path, root: Option<&Path>) -> Vec<String> {
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
    scan.warnings.sort_unstable();
    scan.warnings.dedup();
    scan.warnings
}

struct ConsumerScan<'a> {
    source: &'a Path,
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
            } else if implicit {
                self.warnings.push(format!(
                    "{path} may interpolate {source_name} (${{VAR}}) through Docker Compose; run via `locket compose run --policy <name> -- ...`"
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
        let Some(scripts) = manifest.get("scripts").and_then(Value::as_object) else { return };
        let path = relative_display(self.root, &dir.join("package.json"));
        for (name, script) in scripts {
            let Some(script) = script.as_str() else { continue };
            let mut reads = false;
            let mut recreates = false;
            shell_commands(script, None, |words| {
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
        if *script
            .recreates_in
            .entry(cwd.to_owned())
            .or_insert_with(|| local_script_recreates(text, matches_source))
        {
            Some(relative_display(root, &path))
        } else {
            None
        }
    }
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
            shell_commands(recipe, None, |words| {
                reads |= command_references(words, &matches_source);
                recreates |= command_recreates(words, &matches_source);
                false
            });
        } else if let Some((directive, files)) = line.trim_start().split_once(char::is_whitespace)
            && matches!(directive, "include" | "-include" | "sinclude")
        {
            includes |= shell_commands(files, None, |words| {
                words.iter().flatten().any(|name| matches_source(name))
            });
        }
    }
    (includes, reads, recreates)
}

fn is_compose_file(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(stem, extension)| {
        (stem.starts_with("compose") || stem.starts_with("docker-compose"))
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

fn shell_commands(
    script: &str,
    variables: Option<&BTreeMap<String, String>>,
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
                let Ok(word) = shell_word(&mut chars, variables, false) else { return false };
                words.push(word);
            }
        }
    }
    visit(&words)
}

fn shell_word(
    chars: &mut Peekable<Chars<'_>>,
    variables: Option<&BTreeMap<String, String>>,
    allow_pwd: bool,
) -> Result<Option<String>, ()> {
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
                    if !allow_pwd || !"(pwd)".chars().all(|ch| chars.next() == Some(ch)) {
                        return Err(());
                    }
                    word.push('.');
                } else if let Some(variables) = variables {
                    let name = shell_variable_name(chars)?;
                    if let Some(value) = variables.get(&name) {
                        if word.len() + value.len() > MAX_STATIC_WORD_BYTES {
                            return Err(());
                        }
                        if quote.is_none() && value.contains(char::is_whitespace) {
                            literal = false;
                        }
                        word.push_str(value);
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

fn shell_variable_name(chars: &mut Peekable<Chars<'_>>) -> Result<String, ()> {
    let braced = chars.peek() == Some(&'{');
    if braced {
        chars.next();
    }
    let mut name = String::new();
    while let Some(ch) = chars.next_if(|ch| ch.is_ascii_alphanumeric() || *ch == '_') {
        name.push(ch);
    }
    if braced && chars.next() != Some('}') { Err(()) } else { Ok(name) }
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

fn local_script_recreates(script: &str, matches_source: impl Fn(&str) -> bool) -> bool {
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
            let value = shell_word(&mut chars, Some(&variables), true).ok().flatten();
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
        if shell_commands(line, Some(&variables), |words| {
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
mod tests {
    use std::fs;
    use std::io;

    use super::*;

    #[test]
    fn templates_resolve_only_literal_or_statically_assigned_destinations() {
        let matches = |path: &str| normalized_path(Path::new(path)) == Path::new(".env");
        for script in [
            r#"cp -n ".env.example" "./.env""#,
            "mv -- .env.example .env",
            "ENV_FILE=.env\ncp .env.example \"$ENV_FILE\"",
            "REPO_ROOT=\"$(pwd)\"\nENV_FILE=\"${REPO_ROOT}/.env\"\ninstall .env.example \"$ENV_FILE\"",
        ] {
            assert!(local_script_recreates(script, matches), "{script}");
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
            assert!(!local_script_recreates(script, matches), "{script}");
        }
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
        let warnings = detect_archive_consumers(&source, Some(root));
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
        let warnings = detect_archive_consumers(&root.join(".env"), Some(root));
        assert_eq!(warnings.len(), MAX_SCRIPTS);
        assert!(warnings[0].starts_with("dev-00"));
        assert!(warnings[MAX_SCRIPTS - 1].starts_with("dev-15"));
        Ok(())
    }
}
