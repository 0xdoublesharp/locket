//! Inline-suppression directive parsing for `locket scan`.
//!
//! Implements the language-agnostic `locket-suppress` directive family from
//! `docs/specs/scan-redaction.md`. Three forms are supported:
//!
//! - **Line-level** `locket-suppress: <reason>` — suppresses findings on the same line.
//! - **Block-level** `locket-suppress-block-start: <reason>` ...
//!   `locket-suppress-block-end` — suppresses every finding between the markers.
//! - **File-level** `locket-suppress-file: <reason>` — when present in the first five
//!   lines of the file, suppresses every finding in the whole file.
//!
//! The directives are language-agnostic: any of the comment styles `#`, `//`, `--`,
//! `<!--`, and `;` may carry the directive. The `<reason>` is required and must be
//! between [`MIN_REASON_LENGTH`] and [`MAX_REASON_LENGTH`] characters of plain text.

use std::collections::BTreeMap;

use thiserror::Error;

/// Minimum length of a `locket-suppress*` directive `<reason>` text.
pub const MIN_REASON_LENGTH: usize = 4;

/// Maximum length of a `locket-suppress*` directive `<reason>` text.
pub const MAX_REASON_LENGTH: usize = 200;

/// Maximum line number on which a `locket-suppress-file` directive is honored.
pub const FILE_LEVEL_MAX_LINE: usize = 5;

/// Marker substring for line-level suppression directives.
pub const SUPPRESS_LINE_MARKER: &str = "locket-suppress:";

/// Marker substring that opens a block-level suppression range.
pub const SUPPRESS_BLOCK_START_MARKER: &str = "locket-suppress-block-start:";

/// Marker substring that closes a block-level suppression range.
pub const SUPPRESS_BLOCK_END_MARKER: &str = "locket-suppress-block-end";

/// Marker substring for file-level suppression directives.
pub const SUPPRESS_FILE_MARKER: &str = "locket-suppress-file:";

/// Error returned when a `locket-suppress*` directive is malformed.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum SuppressionParseError {
    /// A directive was present but its `<reason>` was empty or absent.
    #[error("locket-suppress directive on line {line} requires a reason of {min}-{max} characters")]
    MissingReason {
        /// One-based line number where the directive appeared.
        line: usize,
        /// Minimum acceptable reason length.
        min: usize,
        /// Maximum acceptable reason length.
        max: usize,
    },
    /// A directive's `<reason>` was shorter than [`MIN_REASON_LENGTH`].
    #[error("locket-suppress reason on line {line} is too short ({length} chars; minimum {min})")]
    ReasonTooShort {
        /// One-based line number where the directive appeared.
        line: usize,
        /// Length in characters of the offending reason text.
        length: usize,
        /// Minimum acceptable reason length.
        min: usize,
    },
    /// A directive's `<reason>` was longer than [`MAX_REASON_LENGTH`].
    #[error("locket-suppress reason on line {line} is too long ({length} chars; maximum {max})")]
    ReasonTooLong {
        /// One-based line number where the directive appeared.
        line: usize,
        /// Length in characters of the offending reason text.
        length: usize,
        /// Maximum acceptable reason length.
        max: usize,
    },
    /// A `locket-suppress-block-start` was never paired with a matching block-end.
    #[error("locket-suppress-block-start on line {line} is missing a matching block-end")]
    UnclosedBlock {
        /// One-based line number of the unmatched start marker.
        line: usize,
    },
    /// A `locket-suppress-block-end` had no matching block-start before it.
    #[error("locket-suppress-block-end on line {line} has no matching block-start")]
    OrphanBlockEnd {
        /// One-based line number of the orphan end marker.
        line: usize,
    },
    /// A `locket-suppress-file` directive appeared after [`FILE_LEVEL_MAX_LINE`].
    #[error("locket-suppress-file directive on line {line} must be in the first {max} lines")]
    FileDirectiveTooLate {
        /// One-based line number of the late directive.
        line: usize,
        /// Maximum line on which a file-level directive is honored.
        max: usize,
    },
}

/// Parsed inline-suppression coverage for a single file.
///
/// A `SuppressionMap` tracks the line ranges (and reasons) covered by `locket-suppress*`
/// directives. It never carries the matched value of any finding. Use
/// [`SuppressionMap::reason_for_line`] to look up whether a given line is suppressed
/// and, if so, the reason string that should be recorded in the audit row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuppressionMap {
    /// File-level reason, populated when a `locket-suppress-file` directive ran.
    file_reason: Option<String>,
    /// Block-level coverage entries: `(start_line, end_line_inclusive, reason)`.
    blocks: Vec<(usize, usize, String)>,
    /// Line-level coverage map: `line_number -> reason`.
    lines: BTreeMap<usize, String>,
}

impl SuppressionMap {
    /// Returns true if the file-level directive activated.
    #[must_use]
    pub const fn is_file_suppressed(&self) -> bool {
        self.file_reason.is_some()
    }

    /// Returns the file-level suppression reason, if any.
    #[must_use]
    pub fn file_reason(&self) -> Option<&str> {
        self.file_reason.as_deref()
    }

    /// Returns the suppression reason that covers `line` if any directive applies.
    ///
    /// File-level directives win over block-level, which win over line-level.
    #[must_use]
    pub fn reason_for_line(&self, line: usize) -> Option<&str> {
        if let Some(reason) = self.file_reason.as_deref() {
            return Some(reason);
        }
        for (start, end, reason) in &self.blocks {
            if line >= *start && line <= *end {
                return Some(reason.as_str());
            }
        }
        self.lines.get(&line).map(String::as_str)
    }

    /// Returns the line-level entries (one-based line number to reason).
    #[must_use]
    pub const fn line_entries(&self) -> &BTreeMap<usize, String> {
        &self.lines
    }

    /// Returns the block entries as `(start, end_inclusive, reason)` tuples.
    #[must_use]
    pub fn block_entries(&self) -> &[(usize, usize, String)] {
        &self.blocks
    }
}

/// Parses every `locket-suppress*` directive in `text` into a [`SuppressionMap`].
///
/// Validates that every directive (other than `block-end`, which carries no reason)
/// has a reason of [`MIN_REASON_LENGTH`]-[`MAX_REASON_LENGTH`] characters. Returns
/// [`SuppressionParseError`] when any directive is malformed.
///
/// # Errors
///
/// Returns [`SuppressionParseError`] for missing or out-of-range reasons, mismatched
/// block markers, or file-level directives placed outside the first five lines.
pub fn parse_suppression_map(text: &str) -> Result<SuppressionMap, SuppressionParseError> {
    let mut map = SuppressionMap::default();
    let mut open_block: Option<(usize, String)> = None;

    for (index, raw_line) in text.split('\n').enumerate() {
        let line_number = index + 1;
        let stripped = raw_line;

        if let Some(rest) = find_after(stripped, SUPPRESS_BLOCK_START_MARKER) {
            let reason = validate_reason(line_number, take_reason(rest))?;
            if let Some((start_line, _)) = open_block {
                return Err(SuppressionParseError::UnclosedBlock { line: start_line });
            }
            open_block = Some((line_number, reason));
            continue;
        }

        if find_after(stripped, SUPPRESS_BLOCK_END_MARKER).is_some() {
            let Some((start_line, reason)) = open_block.take() else {
                return Err(SuppressionParseError::OrphanBlockEnd { line: line_number });
            };
            map.blocks.push((start_line, line_number, reason));
            continue;
        }

        if let Some(rest) = find_after(stripped, SUPPRESS_FILE_MARKER) {
            let reason = validate_reason(line_number, take_reason(rest))?;
            if line_number > FILE_LEVEL_MAX_LINE {
                return Err(SuppressionParseError::FileDirectiveTooLate {
                    line: line_number,
                    max: FILE_LEVEL_MAX_LINE,
                });
            }
            if map.file_reason.is_none() {
                map.file_reason = Some(reason);
            }
            continue;
        }

        if let Some(rest) = find_after(stripped, SUPPRESS_LINE_MARKER) {
            let reason = validate_reason(line_number, take_reason(rest))?;
            map.lines.entry(line_number).or_insert(reason);
        }
    }

    if let Some((line, _)) = open_block {
        return Err(SuppressionParseError::UnclosedBlock { line });
    }

    Ok(map)
}

/// Returns the substring of `line` immediately after `marker`, when `marker` appears
/// preceded only by whitespace and a recognized comment-prefix sequence.
///
/// Recognized comment prefixes are `#`, `//`, `--`, `<!--`, and `;`. The directive
/// must follow the comment-prefix on the same line; matches inside arbitrary text
/// are ignored to avoid suppressing findings via embedded marker substrings.
fn find_after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let mut search_from = 0;
    while let Some(relative) = line[search_from..].find(marker) {
        let start = search_from + relative;
        let end = start + marker.len();

        if !preceded_by_comment_prefix(line, start) {
            search_from = end;
            continue;
        }

        // For block-end (no trailing reason) the next char may be EOL or whitespace;
        // for the other markers ":" is part of the marker so the next char is the
        // start of the reason. We do not need to enforce a delimiter beyond marker.
        return Some(&line[end..]);
    }
    None
}

/// Returns true when the bytes preceding `pos` form one of the recognized
/// comment prefixes (`#`, `//`, `--`, `<!--`, `;`), allowing whitespace between
/// the prefix and the marker.
fn preceded_by_comment_prefix(line: &str, pos: usize) -> bool {
    let prefix = line[..pos].trim_end();
    prefix.ends_with('#')
        || prefix.ends_with("//")
        || prefix.ends_with("--")
        || prefix.ends_with("<!--")
        || prefix.ends_with(';')
}

/// Extracts the reason text following a directive marker.
///
/// For markers ending in `:` the substring already begins at the first reason
/// character. Trailing comment terminators (`-->`) are removed so that HTML-style
/// `<!-- locket-suppress: reason -->` directives produce a clean reason.
fn take_reason(rest: &str) -> &str {
    let line_only = rest.split(['\n', '\r']).next().unwrap_or("");
    line_only.trim_end().trim_end_matches("-->").trim()
}

/// Validates that `reason` is non-empty and within the configured length bounds.
fn validate_reason(line: usize, reason: &str) -> Result<String, SuppressionParseError> {
    if reason.is_empty() {
        return Err(SuppressionParseError::MissingReason {
            line,
            min: MIN_REASON_LENGTH,
            max: MAX_REASON_LENGTH,
        });
    }
    let length = reason.chars().count();
    if length < MIN_REASON_LENGTH {
        return Err(SuppressionParseError::ReasonTooShort { line, length, min: MIN_REASON_LENGTH });
    }
    if length > MAX_REASON_LENGTH {
        return Err(SuppressionParseError::ReasonTooLong { line, length, max: MAX_REASON_LENGTH });
    }
    Ok(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{
        FILE_LEVEL_MAX_LINE, MAX_REASON_LENGTH, MIN_REASON_LENGTH, SuppressionParseError,
        parse_suppression_map,
    };

    #[test]
    fn parses_line_level_directive_in_each_comment_style() -> Result<(), Box<dyn Error>> {
        let cases = [
            "value # locket-suppress: shell hash comment fixture",
            "value // locket-suppress: c-slash comment fixture",
            "value -- locket-suppress: sql double-dash comment fixture",
            "value <!-- locket-suppress: html comment fixture -->",
            "value ; locket-suppress: ini semicolon comment fixture",
        ];
        for source in cases {
            let map = parse_suppression_map(source)?;
            let reason = map
                .reason_for_line(1)
                .ok_or_else(|| format!("expected line 1 suppression for {source:?}"))?;
            assert!(reason.contains("fixture"), "reason {reason:?} for {source:?}");
        }
        Ok(())
    }

    #[test]
    fn parses_block_directive_covering_inner_lines() -> Result<(), Box<dyn Error>> {
        let text = "first\n\
                    # locket-suppress-block-start: vendored fixtures section\n\
                    inner1\n\
                    inner2\n\
                    # locket-suppress-block-end\n\
                    outside\n";
        let map = parse_suppression_map(text)?;
        assert!(map.reason_for_line(2).is_some());
        assert_eq!(map.reason_for_line(3), Some("vendored fixtures section"));
        assert_eq!(map.reason_for_line(4), Some("vendored fixtures section"));
        assert!(map.reason_for_line(6).is_none());
        Ok(())
    }

    #[test]
    fn block_directive_supports_nested_findings_lines() -> Result<(), Box<dyn Error>> {
        let text = "// locket-suppress-block-start: external sample fixtures\n\
                    secret_one\n\
                    secret_two\n\
                    secret_three\n\
                    // locket-suppress-block-end\n";
        let map = parse_suppression_map(text)?;
        for line in 2..=4 {
            assert_eq!(map.reason_for_line(line), Some("external sample fixtures"));
        }
        Ok(())
    }

    #[test]
    fn unclosed_block_is_rejected() {
        let text = "// locket-suppress-block-start: dangling start marker\ninner\n";
        assert_eq!(
            parse_suppression_map(text).err(),
            Some(SuppressionParseError::UnclosedBlock { line: 1 })
        );
    }

    #[test]
    fn orphan_block_end_is_rejected() {
        let text = "outer\n# locket-suppress-block-end\n";
        assert_eq!(
            parse_suppression_map(text).err(),
            Some(SuppressionParseError::OrphanBlockEnd { line: 2 })
        );
    }

    #[test]
    fn file_directive_on_first_line_covers_entire_file() -> Result<(), Box<dyn Error>> {
        let text = "# locket-suppress-file: vendored fixtures repo\n\
                    line2\n\
                    line3\n";
        let map = parse_suppression_map(text)?;
        assert!(map.is_file_suppressed());
        assert_eq!(map.reason_for_line(2), Some("vendored fixtures repo"));
        assert_eq!(map.reason_for_line(99), Some("vendored fixtures repo"));
        Ok(())
    }

    #[test]
    fn file_directive_on_fifth_line_is_accepted() -> Result<(), Box<dyn Error>> {
        let text =
            "line1\nline2\nline3\nline4\n# locket-suppress-file: fifth-line fixture reason\n";
        let map = parse_suppression_map(text)?;
        assert!(map.is_file_suppressed());
        Ok(())
    }

    #[test]
    fn file_directive_on_sixth_line_is_rejected() -> Result<(), Box<dyn Error>> {
        let text =
            "line1\nline2\nline3\nline4\nline5\n# locket-suppress-file: too late for file form\n";
        let result = parse_suppression_map(text);
        let Err(error) = result else {
            return Err("must fail".into());
        };
        assert!(matches!(
            error,
            SuppressionParseError::FileDirectiveTooLate { line: 6, max: FILE_LEVEL_MAX_LINE }
        ));
        Ok(())
    }

    #[test]
    fn empty_reason_is_rejected() -> Result<(), Box<dyn Error>> {
        let result = parse_suppression_map("# locket-suppress:\n");
        let Err(error) = result else {
            return Err("must fail".into());
        };
        assert!(matches!(
            error,
            SuppressionParseError::MissingReason {
                line: 1,
                min: MIN_REASON_LENGTH,
                max: MAX_REASON_LENGTH,
            }
        ));
        Ok(())
    }

    #[test]
    fn whitespace_only_reason_is_rejected_as_missing() -> Result<(), Box<dyn Error>> {
        let result = parse_suppression_map("# locket-suppress:    \n");
        let Err(error) = result else {
            return Err("must fail".into());
        };
        assert!(matches!(error, SuppressionParseError::MissingReason { line: 1, .. }));
        Ok(())
    }

    #[test]
    fn reason_shorter_than_minimum_is_rejected() -> Result<(), Box<dyn Error>> {
        let result = parse_suppression_map("# locket-suppress: hi\n");
        let Err(error) = result else {
            return Err("must fail".into());
        };
        let SuppressionParseError::ReasonTooShort { line, length, min } = error else {
            return Err(format!("unexpected error: {error:?}").into());
        };
        assert_eq!(line, 1);
        assert_eq!(length, 2);
        assert_eq!(min, MIN_REASON_LENGTH);
        Ok(())
    }

    #[test]
    fn reason_longer_than_maximum_is_rejected() -> Result<(), Box<dyn Error>> {
        let long = "x".repeat(MAX_REASON_LENGTH + 1);
        let text = format!("# locket-suppress: {long}\n");
        let result = parse_suppression_map(&text);
        let Err(error) = result else {
            return Err("must fail".into());
        };
        let SuppressionParseError::ReasonTooLong { line, length, max } = error else {
            return Err(format!("unexpected error: {error:?}").into());
        };
        assert_eq!(line, 1);
        assert_eq!(length, MAX_REASON_LENGTH + 1);
        assert_eq!(max, MAX_REASON_LENGTH);
        Ok(())
    }

    #[test]
    fn directive_without_comment_prefix_is_ignored() -> Result<(), Box<dyn Error>> {
        let map = parse_suppression_map("data locket-suppress: not a real directive\n")?;
        assert!(map.line_entries().is_empty());
        assert_eq!(map.block_entries().len(), 0);
        Ok(())
    }

    #[test]
    fn file_directive_only_records_first_occurrence() -> Result<(), Box<dyn Error>> {
        let text = "# locket-suppress-file: first fixture reason\n\
                    # locket-suppress-file: second fixture reason\n";
        let map = parse_suppression_map(text)?;
        assert_eq!(map.file_reason(), Some("first fixture reason"));
        Ok(())
    }
}
