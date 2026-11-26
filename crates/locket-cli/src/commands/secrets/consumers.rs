//! Static, metadata-only hints for files that may still consume a dotenv source.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::io::Read as _;
use std::iter::Peekable;
use std::path::{Component, Path, PathBuf};
use std::str::Chars;

use serde_json::Value;

use super::env_files::InputDirectory;

const MAX_CONFIG_BYTES: u64 = 256 * 1024;

pub(super) fn detect_archive_consumers(source: &Path, root: Option<&Path>) -> Vec<String> {
    let (Some(parent), Some(name)) = (source.parent(), source.file_name()) else {
        return Vec::new();
    };
    let Some(parent) = normalize_source_parent(parent) else {
        return Vec::new();
    };
    let source = parent.join(name);
    let boundary = root.filter(|root| parent.starts_with(root)).unwrap_or(&parent);
    let display_root = root.unwrap_or(&parent);
    let mut warnings = Vec::new();
    for dir in parent.ancestors() {
        let Ok(directory) = InputDirectory::open(dir) else { break };
        scan_directory(&directory, dir, display_root, &source, &mut warnings);
        if dir == boundary || directory.has_git_boundary() {
            break;
        }
    }
    warnings.sort_unstable();
    warnings
}

fn normalize_source_parent(path: &Path) -> Option<PathBuf> {
    let mut result = PathBuf::new();
    for component in path.components() {
        if component == Component::ParentDir {
            // Check any ancestor that normalization would otherwise erase without opening it.
            InputDirectory::open(&result).ok()?;
            result.pop();
        } else {
            result.push(component);
        }
    }
    Some(result)
}

fn scan_directory(
    directory: &InputDirectory,
    dir: &Path,
    root: &Path,
    source: &Path,
    warnings: &mut Vec<String>,
) {
    let source_name = source.file_name().unwrap_or_default().to_string_lossy();
    let source_name = source_name.escape_debug();
    let matches_source = |literal: &str| normalized_path(&dir.join(literal)) == source;
    let implicit = source.parent() == Some(dir) && source.file_name() == Some(OsStr::new(".env"));

    for name in directory.names().unwrap_or_default() {
        let Some(name) = name.to_str() else { continue };
        if !is_compose_file(name) {
            continue;
        }
        if let Some(text) = read_config(directory, name)
            && (implicit || compose_references(&text, matches_source))
        {
            let path = relative_display(root, &dir.join(name));
            warnings.push(format!("{path} may still read {source_name} through Docker Compose"));
        }
    }

    if let Some(text) = read_config(directory, "package.json")
        && let Ok(manifest) = serde_json::from_str::<Value>(&text)
        && let Some(scripts) = manifest.get("scripts").and_then(Value::as_object)
    {
        let path = relative_display(root, &dir.join("package.json"));
        for (name, script) in scripts {
            if script.as_str().is_some_and(|script| script_references(script, matches_source)) {
                warnings.push(format!("{path} script {name:?} may still read {source_name}"));
            }
        }
    }
}

fn is_compose_file(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(stem, extension)| {
        (stem.starts_with("compose") || stem.starts_with("docker-compose"))
            && (extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml"))
    })
}

fn read_config(directory: &InputDirectory, name: &str) -> Option<String> {
    if !directory.is_regular(name) {
        return None;
    }
    let mut file = directory.open_file(name.as_ref()).ok()?;
    if file.metadata().ok()?.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let mut text = String::new();
    (&mut file).take(MAX_CONFIG_BYTES).read_to_string(&mut text).ok()?;
    (file.metadata().ok()?.len() <= MAX_CONFIG_BYTES).then_some(text)
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

fn script_references(script: &str, matches_source: impl Fn(&str) -> bool) -> bool {
    let mut chars = script.chars().peekable();
    let mut words = Vec::new();
    while let Some(&ch) = chars.peek() {
        match ch {
            '\n' | ';' | '|' | '&' => {
                if command_references(&words, &matches_source) {
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
            '<' | '>' => return command_references(&words, matches_source),
            '(' | ')' => return false,
            _ => {
                let Ok(word) = shell_word(&mut chars) else { return false };
                words.push(word);
            }
        }
    }
    command_references(&words, &matches_source)
}

fn shell_word(chars: &mut Peekable<Chars<'_>>) -> Result<Option<String>, ()> {
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
                    return Err(());
                }
                literal = false;
                word.push(ch);
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
