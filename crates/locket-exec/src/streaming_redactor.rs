//! Binary-safe redaction for child-process output.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Read, Write};
use std::process::Child;
use std::sync::Arc;
use std::thread;

use locket_scan::{FindingKind, scan_text};
use zeroize::{Zeroize, Zeroizing};

use crate::secret_encoding::Form;

const BLOCK_SIZE: usize = 8192;
const MAX_GENERIC_LINE: usize = 64 * 1024;
const DEFAULT_REPLACEMENT: &str = "[REDACTED:locket]";
const FALLBACK_MARKERS: [&str; 4] = [DEFAULT_REPLACEMENT, "[REDACTED]", "[***]", "███"];
const BINARY_REPLACEMENT_BYTE: u8 = 0xff;

/// Settings for streaming redaction. Labels are non-secret metadata.
#[derive(Clone)]
pub struct StreamingRedactorConfig {
    /// Labels and plaintext values to match.
    pub known_secrets: Vec<(String, Zeroizing<String>)>,
    /// Preferred marker emitted instead of a matching span. An empty marker or
    /// one that could recreate a known secret is replaced with a safe marker.
    pub replacement: String,
    /// Use a marker containing the primary matching label when safe.
    pub label_replacements: bool,
    /// Match percent-encoded, Base64, and JSON-escaped variants as well.
    pub include_encoded_variants: bool,
    /// Also apply provider-token detection to valid UTF-8 spans. Lines over 64 KiB
    /// are replaced wholesale when this option is enabled.
    pub redact_generic_patterns: bool,
    /// Ignore known values shorter than this many bytes. Empty values are always ignored.
    pub min_secret_len: usize,
}

impl Default for StreamingRedactorConfig {
    fn default() -> Self {
        Self {
            known_secrets: Vec::new(),
            replacement: DEFAULT_REPLACEMENT.into(),
            label_replacements: false,
            include_encoded_variants: true,
            redact_generic_patterns: false,
            min_secret_len: 4,
        }
    }
}

impl fmt::Debug for StreamingRedactorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamingRedactorConfig")
            .field("known_secret_count", &self.known_secrets.len())
            .field("label_replacements", &self.label_replacements)
            .field("include_encoded_variants", &self.include_encoded_variants)
            .field("redact_generic_patterns", &self.redact_generic_patterns)
            .field("min_secret_len", &self.min_secret_len)
            .finish_non_exhaustive()
    }
}

/// Metadata collected during redaction.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StreamingRedactionStats {
    /// Number of replacement spans, merging intersecting known-secret matches.
    pub redaction_count: u64,
    /// Configured labels whose values matched, omitting labels containing secret bytes.
    pub redacted_labels: BTreeSet<String>,
}

#[derive(Clone)]
struct Pattern {
    bytes: Zeroizing<Vec<u8>>,
    labels: BTreeSet<String>,
}

/// Compiled known-secret patterns shared across streams.
pub struct RedactionPatterns {
    by_first_byte: [Vec<Pattern>; 256],
    max_len: usize,
    replacement: Zeroizing<Vec<u8>>,
    label_replacements: bool,
    generic: bool,
}

impl RedactionPatterns {
    pub(super) fn new(config: StreamingRedactorConfig) -> Arc<Self> {
        let mut patterns = Self {
            by_first_byte: std::array::from_fn(|_| Vec::new()),
            max_len: 0,
            replacement: Zeroizing::new(config.replacement.into_bytes()),
            label_replacements: config.label_replacements,
            generic: config.redact_generic_patterns,
        };

        let forms = if config.include_encoded_variants { &Form::ALL[..] } else { &[Form::Raw] };
        for (_, secret) in &config.known_secrets {
            if secret.len() < config.min_secret_len.max(1) {
                continue;
            }
            for form in forms {
                let bytes = form.encode(secret.as_bytes());
                let bucket = &mut patterns.by_first_byte[usize::from(bytes[0])];
                if !bucket.iter().any(|pattern| pattern.bytes == bytes) {
                    patterns.max_len = patterns.max_len.max(bytes.len());
                    bucket.push(Pattern { bytes, labels: BTreeSet::new() });
                }
            }
        }

        for (label, secret) in config.known_secrets {
            if secret.len() < config.min_secret_len.max(1) || patterns.contains(label.as_bytes()) {
                continue;
            }
            for form in forms {
                let bytes = form.encode(secret.as_bytes());
                if let Some(pattern) = patterns.by_first_byte[usize::from(bytes[0])]
                    .iter_mut()
                    .find(|pattern| pattern.bytes == bytes)
                {
                    pattern.labels.insert(label.clone());
                }
            }
        }
        for bucket in &mut patterns.by_first_byte {
            bucket.sort_unstable_by_key(|pattern| std::cmp::Reverse(pattern.bytes.len()));
        }
        patterns.select_replacement();
        Arc::new(patterns)
    }

    pub(super) fn with_additional_literals(
        self: &Arc<Self>,
        literals: Vec<Zeroizing<String>>,
    ) -> Arc<Self> {
        if literals.is_empty() {
            return Arc::clone(self);
        }
        let mut patterns = Self {
            by_first_byte: self.by_first_byte.clone(),
            max_len: self.max_len,
            replacement: self.replacement.clone(),
            label_replacements: self.label_replacements,
            generic: self.generic,
        };
        for mut literal in literals {
            let bytes = Zeroizing::new(std::mem::take(&mut *literal).into_bytes());
            if let Some(first) = bytes.first() {
                patterns.max_len = patterns.max_len.max(bytes.len());
                let bucket = &mut patterns.by_first_byte[usize::from(*first)];
                bucket.push(Pattern { bytes, labels: BTreeSet::new() });
                bucket.sort_unstable_by_key(|pattern| std::cmp::Reverse(pattern.bytes.len()));
            }
        }
        patterns.select_replacement();
        Arc::new(patterns)
    }

    fn select_replacement(&mut self) {
        if self.marker_is_safe(&self.replacement) {
            return;
        }
        let marker =
            FALLBACK_MARKERS.into_iter().find(|marker| self.marker_is_safe(marker.as_bytes()));
        self.replacement = Zeroizing::new(marker.map_or_else(
            || vec![self.disjoint_marker_byte()],
            |marker| marker.as_bytes().to_vec(),
        ));
    }

    fn marker_is_safe(&self, marker: &[u8]) -> bool {
        if marker.is_empty() || self.contains(marker) {
            return false;
        }
        self.by_first_byte.iter().flatten().all(|pattern| {
            let bytes = pattern.bytes.as_slice();
            // A match can span the whole marker or cross just one boundary.
            !bytes.windows(marker.len()).any(|window| window == marker)
                && (1..marker.len().min(bytes.len())).all(|overlap| {
                    !marker.starts_with(&bytes[bytes.len() - overlap..])
                        && !marker.ends_with(&bytes[..overlap])
                })
        })
    }

    fn disjoint_marker_byte(&self) -> u8 {
        let mut used = [false; 256];
        for pattern in self.by_first_byte.iter().flatten() {
            for &byte in pattern.bytes.iter() {
                used[usize::from(byte)] = true;
            }
        }
        // Patterns come from UTF-8 strings or their encodings, so 0xff is
        // always available to this byte-oriented writer.
        (b'!'..=b'~').find(|&byte| !used[usize::from(byte)]).unwrap_or(BINARY_REPLACEMENT_BYTE)
    }

    pub(super) fn contains(&self, input: &[u8]) -> bool {
        (0..input.len()).any(|start| self.matches(&input[start..]).next().is_some())
    }

    fn matches<'a>(&'a self, input: &'a [u8]) -> impl Iterator<Item = &'a Pattern> {
        self.by_first_byte[usize::from(input[0])]
            .iter()
            .filter(|pattern| input.starts_with(&pattern.bytes))
    }
}

/// A writer that redacts known secrets across arbitrary write boundaries.
///
/// Call [`Self::flush_final`] at EOF. Ordinary flushes preserve pending matches.
pub struct StreamingRedactor<W: Write> {
    writer: W,
    patterns: Arc<RedactionPatterns>,
    pending: Zeroizing<Vec<u8>>,
    covered: usize,
    primary: Option<(usize, Option<String>)>,
    line: Zeroizing<Vec<u8>>,
    overlong_line: bool,
    stopped: bool,
    stats: StreamingRedactionStats,
}

impl<W: Write> fmt::Debug for StreamingRedactor<W> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamingRedactor")
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl<W: Write> StreamingRedactor<W> {
    /// Creates a redactor that sends scrubbed bytes to `writer`.
    #[must_use]
    pub fn new(writer: W, config: StreamingRedactorConfig) -> Self {
        Self::with_patterns(writer, RedactionPatterns::new(config))
    }

    pub(super) fn with_patterns(writer: W, patterns: Arc<RedactionPatterns>) -> Self {
        let capacity = patterns.max_len.saturating_sub(1) + BLOCK_SIZE;
        let line_capacity = if patterns.generic { MAX_GENERIC_LINE } else { 0 };
        Self {
            writer,
            patterns,
            pending: Zeroizing::new(Vec::with_capacity(capacity)),
            covered: 0,
            primary: None,
            line: Zeroizing::new(Vec::with_capacity(line_capacity)),
            overlong_line: false,
            stopped: false,
            stats: StreamingRedactionStats::default(),
        }
    }

    /// Returns redaction counts and matching labels.
    #[must_use]
    pub const fn stats(&self) -> &StreamingRedactionStats {
        &self.stats
    }

    fn process(&mut self, len: usize) -> io::Result<()> {
        let mut plain_start = 0;
        let patterns = Arc::clone(&self.patterns);
        // Keep the pending bytes out of `self` while sending slices downstream.
        let mut pending = std::mem::take(&mut self.pending);
        for start in 0..len {
            if start >= self.covered {
                self.finish_match(&patterns)?;
            }
            let mut matches = patterns.matches(&pending[start..]);
            if let Some(primary) = matches.next() {
                if start >= self.covered {
                    self.emit(&pending[plain_start..start])?;
                }
                let length = primary.bytes.len();
                self.covered = self.covered.max(start + length);
                if self.primary.as_ref().is_none_or(|(longest, _)| length > *longest) {
                    let label =
                        patterns.label_replacements.then(|| primary.labels.first()).flatten();
                    self.primary = Some((length, label.cloned()));
                }
                self.stats.redacted_labels.extend(primary.labels.iter().cloned());
                for pattern in matches {
                    self.stats.redacted_labels.extend(pattern.labels.iter().cloned());
                }
            }
            if start < self.covered {
                plain_start = start + 1;
            }
        }
        if len >= self.covered {
            self.finish_match(&patterns)?;
        }
        self.emit(&pending[plain_start..len])?;
        let remaining = pending.len() - len;
        pending.copy_within(len.., 0);
        pending[remaining..].zeroize();
        pending.truncate(remaining);
        self.pending = pending;
        self.covered = self.covered.saturating_sub(len);
        Ok(())
    }

    fn finish_match(&mut self, patterns: &RedactionPatterns) -> io::Result<()> {
        let Some((_, label)) = self.primary.take() else { return Ok(()) };
        if let Some(label) = label.filter(|label| {
            !label.is_empty()
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }) {
            let marker = Zeroizing::new(format!("[REDACTED:{label}]"));
            if patterns.marker_is_safe(marker.as_bytes()) {
                self.emit(marker.as_bytes())?;
                self.stats.redaction_count = self.stats.redaction_count.saturating_add(1);
                return Ok(());
            }
        }
        self.emit(&patterns.replacement)?;
        self.stats.redaction_count = self.stats.redaction_count.saturating_add(1);
        Ok(())
    }

    fn emit(&mut self, bytes: &[u8]) -> io::Result<()> {
        if !self.patterns.generic {
            return self.writer.write_all(bytes);
        }
        for segment in bytes.split_inclusive(|byte| *byte == b'\n') {
            let newline = segment.last() == Some(&b'\n');
            let content = &segment[..segment.len() - usize::from(newline)];
            if !self.overlong_line {
                if content.len() > MAX_GENERIC_LINE - self.line.len() {
                    self.line.as_mut_slice().zeroize();
                    self.line.clear();
                    self.overlong_line = true;
                } else {
                    self.line.extend_from_slice(content);
                }
            }
            if newline {
                self.emit_line()?;
                self.writer.write_all(b"\n")?;
            }
        }
        Ok(())
    }

    fn emit_line(&mut self) -> io::Result<()> {
        let marker = self.patterns.replacement.as_slice();
        if self.overlong_line {
            self.writer.write_all(marker)?;
            self.stats.redaction_count = self.stats.redaction_count.saturating_add(1);
            self.overlong_line = false;
            return Ok(());
        }
        let mut cursor = 0;
        let mut offset = 0;
        // Invalid bytes are token boundaries, including the binary replacement marker.
        // Keep their original bytes while scanning valid text on either side.
        for chunk in self.line.utf8_chunks() {
            let text = chunk.valid();
            let mut chars = text.char_indices();
            let mut column = 1;
            for finding in scan_text("", text) {
                if finding.kind != FindingKind::ProviderTokenPattern {
                    continue;
                }
                let Some((relative, _)) = chars.nth(finding.column - column) else { break };
                let start = offset + relative;
                column = finding.column + 1;
                self.writer.write_all(&self.line[cursor..start])?;
                self.writer.write_all(marker)?;
                cursor = start + finding.token_length;
                self.stats.redaction_count = self.stats.redaction_count.saturating_add(1);
            }
            offset += text.len() + chunk.invalid().len();
        }
        self.writer.write_all(&self.line[cursor..])?;
        self.line.as_mut_slice().zeroize();
        self.line.clear();
        Ok(())
    }

    fn clear_buffers(&mut self) {
        self.pending.zeroize();
        self.line.zeroize();
    }

    /// Redacts and writes the remaining bytes at EOF, then scrubs pending buffers.
    ///
    /// # Errors
    ///
    /// Returns downstream write or flush errors. A finalized writer rejects further input.
    pub fn flush_final(&mut self) -> io::Result<()> {
        if self.stopped {
            return Err(io::Error::other("redactor already stopped"));
        }
        self.stopped = true;
        let result = self.process(self.pending.len()).and_then(|()| {
            if self.patterns.generic {
                self.emit_line()?;
            }
            self.writer.flush()
        });
        self.clear_buffers();
        result
    }
}

impl<W: Write> Write for StreamingRedactor<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.stopped {
            return Err(io::Error::other("redactor already stopped"));
        }
        for chunk in bytes.chunks(BLOCK_SIZE) {
            self.pending.extend_from_slice(chunk);
            let ready = self.pending.len().saturating_sub(self.patterns.max_len.saturating_sub(1));
            if ready != 0
                && let Err(error) = self.process(ready)
            {
                self.stopped = true;
                self.clear_buffers();
                return Err(error);
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn copy_redacted(
    mut pipe: impl Read,
    writer: impl Write,
    patterns: Arc<RedactionPatterns>,
) -> io::Result<StreamingRedactionStats> {
    let mut redactor = StreamingRedactor::with_patterns(writer, patterns);
    let mut buffer = Zeroizing::new([0; BLOCK_SIZE]);
    loop {
        match pipe.read(&mut *buffer) {
            Ok(0) => break,
            Ok(count) => redactor.write_all(&buffer[..count])?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    redactor.flush_final()?;
    Ok(redactor.stats)
}

/// Concurrently drains both piped streams from a child through independent redactors.
///
/// Call after spawning with piped stdout and stderr. The caller owns waiting for
/// the child. Counts and labels are returned in stdout, stderr order.
///
/// # Errors
///
/// Returns an error if a pipe is absent or a reader or writer fails.
pub fn redact_child_output(
    child: &mut Child,
    stdout: impl Write + Send,
    stderr: impl Write,
    config: StreamingRedactorConfig,
) -> io::Result<(StreamingRedactionStats, StreamingRedactionStats)> {
    if child.stdout.is_none() || child.stderr.is_none() {
        return Err(io::Error::other("child output pipes are required"));
    }
    let stdout_pipe = child.stdout.take().ok_or_else(|| io::Error::other("missing stdout pipe"))?;
    let stderr_pipe = child.stderr.take().ok_or_else(|| io::Error::other("missing stderr pipe"))?;
    let patterns = RedactionPatterns::new(config);
    thread::scope(|scope| {
        let stdout_patterns = Arc::clone(&patterns);
        let stdout = thread::Builder::new()
            .spawn_scoped(scope, move || copy_redacted(stdout_pipe, stdout, stdout_patterns))?;
        let stderr = copy_redacted(stderr_pipe, stderr, patterns);
        let stdout = stdout.join().map_err(|_| io::Error::other("stdout worker failed"))??;
        Ok((stdout, stderr?))
    })
}

#[cfg(test)]
mod tests;
