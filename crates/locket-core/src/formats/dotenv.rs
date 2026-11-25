//! Pure dotenv parsing. Diagnostics contain line numbers and fixed messages only.
#[derive(Clone, Copy, Debug, Default)]
/// Controls handling of shell expansion syntax.
pub struct DotenvOptions {
    /// Preserve dollar expressions and backticks as data. Never execute them.
    pub literal: bool,
}
#[derive(Clone, PartialEq, Eq)]
/// A validated variable. Values deliberately have no Debug implementation.
pub struct DotenvEntry {
    /// Validated variable name.
    pub key: String,
    /// Parsed value, which may be empty or contain newlines.
    pub value: String,
    /// One-based starting line.
    pub line: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
/// A diagnostic that cannot contain input values.
pub struct DotenvDiagnostic {
    /// One-based starting line.
    pub line: usize,
    /// Fixed diagnostic text without input content.
    pub message: &'static str,
}
#[derive(Default)]
/// Parsed entries plus safe diagnostics. Callers must reject errors before writing values.
pub struct DotenvDocument {
    /// Valid entries with duplicate keys resolved to the last occurrence.
    pub entries: Vec<DotenvEntry>,
    /// Metadata warnings for duplicate keys.
    pub warnings: Vec<DotenvDiagnostic>,
    /// Syntax and expansion errors, never values.
    pub errors: Vec<DotenvDiagnostic>,
}
/// Parse values without evaluating shell syntax or consulting the process environment.
#[must_use]
pub fn parse_dotenv(text: &str, options: DotenvOptions) -> DotenvDocument {
    let mut document = DotenvDocument::default();
    let mut lines = text.lines().enumerate();
    while let Some((index, line)) = lines.next() {
        let line_number = index + 1;
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export")
            .filter(|rest| rest.starts_with(char::is_whitespace))
            .map_or(line, str::trim_start);
        let Some((key, raw)) = line.split_once('=') else {
            document.errors.push(diagnostic(line_number, "expected a name and '='"));
            continue;
        };
        let key = key.trim();
        if crate::SecretName::new(key.to_owned()).is_err() {
            document.errors.push(diagnostic(line_number, "invalid variable name"));
            continue;
        }
        let leading_space = raw.starts_with(char::is_whitespace);
        let mut raw = raw.trim_start().to_owned();
        let parsed = if let Some(quote @ ('\'' | '"')) = raw.chars().next() {
            loop {
                match parse_quoted(&raw, quote) {
                    Ok(Some(value)) => break Ok(value),
                    Ok(None) => {
                        if let Some((_, next)) = lines.next() {
                            raw.push('\n');
                            raw.push_str(next);
                        } else {
                            break Err("unterminated quoted value");
                        }
                    }
                    Err(message) => break Err(message),
                }
            }
        } else {
            let comment = raw.char_indices().find_map(|(offset, ch)| {
                (ch == '#'
                    && (offset == 0 && leading_space
                        || offset > 0 && raw[..offset].ends_with(char::is_whitespace)))
                .then_some(offset)
            });
            Ok(raw[..comment.unwrap_or(raw.len())].trim_end().to_owned())
        };
        let value = match parsed {
            Ok(value) => value,
            Err(message) => {
                document.errors.push(diagnostic(line_number, message));
                continue;
            }
        };
        if value.contains('\0') {
            document.errors.push(diagnostic(line_number, "NUL bytes are not allowed"));
            continue;
        }
        if !options.literal && (value.contains('$') || value.contains('`')) {
            document
                .errors
                .push(diagnostic(line_number, "expansion syntax requires explicit literal mode"));
            continue;
        }
        if let Some(previous) = document.entries.iter().position(|entry| entry.key == key) {
            document.entries.remove(previous);
            document.warnings.push(diagnostic(line_number, "duplicate variable; last value wins"));
        }
        document.entries.push(DotenvEntry { key: key.to_owned(), value, line: line_number });
    }
    document
}

const fn diagnostic(line: usize, message: &'static str) -> DotenvDiagnostic {
    DotenvDiagnostic { line, message }
}

fn parse_quoted(raw: &str, quote: char) -> Result<Option<String>, &'static str> {
    let mut value = String::new();
    let mut chars = raw.char_indices();
    chars.next();
    while let Some((offset, ch)) = chars.next() {
        if ch == quote {
            let tail = raw[offset + ch.len_utf8()..].trim_start();
            if tail.is_empty() || tail.starts_with('#') {
                return Ok(Some(value));
            }
            return Err("unexpected text after quoted value");
        }
        if quote == '"' && ch == '\\' {
            let Some((_, escaped)) = chars.next() else {
                return Ok(None);
            };
            match escaped {
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                '\\' | '"' | '$' => value.push(escaped),
                _ => return Err("unsupported double-quote escape"),
            }
        } else {
            value.push(ch);
        }
    }
    Ok(None)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dotenv_rejects_lines_without_assignment() {
        let doc = parse_dotenv("a value without an assignment\nNEXT=ok", DotenvOptions::default());
        assert_eq!(doc.errors, [diagnostic(1, "expected a name and '='")]);
        assert_eq!(doc.entries.len(), 1);
        assert_eq!(doc.entries[0].line, 2);
    }

    #[test]
    fn dotenv_recovers_after_invalid_values_and_preserves_carriage_return_escape() {
        let doc = parse_dotenv(
            "# comment\n\nNUL=before\0after\nBAD=\"invalid\\q\"\nNEXT=\"a\\rb\"\nLAST=\"unterminated\\",
            DotenvOptions::default(),
        );
        assert_eq!(
            doc.errors,
            [
                diagnostic(3, "NUL bytes are not allowed"),
                diagnostic(4, "unsupported double-quote escape"),
                diagnostic(6, "unterminated quoted value"),
            ]
        );
        assert_eq!(doc.warnings, []);
        assert_eq!(
            doc.entries
                .iter()
                .map(|entry| (entry.key.as_str(), entry.value.as_str(), entry.line))
                .collect::<Vec<_>>(),
            [("NEXT", "a\rb", 5)]
        );
    }

    #[test]
    fn dotenv_quotes_comments_multiline_and_escapes() {
        let doc = parse_dotenv(
            "export A=one # comment\nB=hash#literal\nC='line1\nline2'\nD=\"line1\\nline2\\t\\\"\\\\\" # ok\nEMPTY=\nSINGLE=''\n",
            DotenvOptions::default(),
        );
        assert!(doc.errors.is_empty(), "{:?}", doc.errors);
        assert_eq!(
            doc.entries
                .iter()
                .map(|e| (e.key.as_str(), e.value.as_str(), e.line))
                .collect::<Vec<_>>(),
            vec![
                ("A", "one", 1),
                ("B", "hash#literal", 2),
                ("C", "line1\nline2", 3),
                ("D", "line1\nline2\t\"\\", 5),
                ("EMPTY", "", 6),
                ("SINGLE", "", 7)
            ]
        );
    }
    #[test]
    fn dotenv_duplicates_last_wins_with_safe_metadata() {
        let doc = parse_dotenv("A=first-private\nA=second-private\n", DotenvOptions::default());
        assert_eq!(doc.entries.len(), 1);
        assert_eq!(doc.entries[0].value, "second-private");
        assert_eq!(doc.warnings.len(), 1);
        assert_eq!(doc.warnings[0].line, 2);
        assert!(!format!("{:?}", doc.warnings).contains("private"));
    }
    #[test]
    fn dotenv_expansions_fail_unless_explicitly_literal() {
        for value in
            ["$HOME", "${HOME}", "$(touch secret)", "`touch secret`", "\"$HOME\"", "'$HOME'"]
        {
            let text = format!("A={value}\n");
            let doc = parse_dotenv(&text, DotenvOptions::default());
            assert_eq!(doc.errors.len(), 1, "{value}");
            assert_eq!(doc.errors[0].line, 1);
            assert!(!format!("{:?}", doc.errors).contains("HOME"));
            assert_eq!(parse_dotenv(&text, DotenvOptions { literal: true }).errors, []);
        }
    }
    #[test]
    fn dotenv_invalid_syntax_reports_line_without_values() {
        let doc = parse_dotenv(
            "A=ok\nBAD-NAME=private\nB=\"private\"garbage\nC='private",
            DotenvOptions::default(),
        );
        assert_eq!(doc.errors.iter().map(|e| e.line).collect::<Vec<_>>(), vec![2, 3, 4]);
        assert!(!format!("{:?}", doc.errors).contains("private"));
    }
    #[test]
    fn dotenv_comment_only_value_and_multiline_spaces() {
        let doc = parse_dotenv(
            "EMPTY= # comment\nHASH=#literal\nMULTI='first   \n second'\n",
            DotenvOptions::default(),
        );
        assert_eq!(doc.errors, []);
        assert_eq!(
            doc.entries.iter().map(|e| e.value.as_str()).collect::<Vec<_>>(),
            vec!["", "#literal", "first   \n second"]
        );
    }
}
