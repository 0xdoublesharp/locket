use locket_crypto::KeyPurpose;
use locket_scan::{FindingKind, KnownRedaction, redact_text, redact_text_with_known_values};
use locket_store::{AuditWrite, SecretRecord};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::mpsc;
use std::thread;

use crate::runtime::error::corrupt_db_error;
use crate::support::secret_helpers::summarize_names;
use crate::{
    AI_SAFE_PARTIAL_LINE_MAX_BYTES, AI_SAFE_READ_CHUNK_BYTES, AiSafeArgs, CliError, RedactArgs,
    ResolvedProject, RuntimeContext, absolutize, decrypt_secret_version, default_profile,
    ensure_trusted_project_root, invalid_reference_error, load_project_key, now_unix_nanos,
    open_store, privacy_alias, privacy_redact_names_enabled, project_not_found_error,
    require_project, resolve_project, set_user_only_file_permissions, should_scan_known_version,
    unix_nanos_to_rfc3339, unlock_required_error,
};

pub fn redact_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &RedactArgs,
) -> Result<(), CliError> {
    let redact_names_enabled =
        privacy_redact_names_enabled(context, args.redact_names.redact_names)?;
    let project = resolve_project(&context.cwd)?;
    let coverage = collect_redaction_values_for_redact(
        context,
        project.as_ref(),
        redact_names_enabled,
        args.require_known,
        now_unix_nanos()?,
    )?;
    let (result, invalid_utf8_passthrough) = if args.stdin {
        let mut input = Vec::new();
        io::stdin().read_to_end(&mut input)?;
        let redacted = redact_stdin_bytes(&input, &coverage.redactions);
        output.write_all(&redacted.bytes)?;
        (redacted.result, redacted.invalid_utf8_passthrough)
    } else if let Some(file) = args.file.as_deref() {
        let input = fs::read_to_string(absolutize(&context.cwd, Path::new(file)))?;
        let result = redact_input(&input, &coverage.redactions);
        write!(output, "{}", result.text)?;
        (result, false)
    } else {
        return Err(invalid_reference_error("redact requires a file path or --stdin"));
    };

    if !coverage.known_coverage_active {
        let mut stderr = io::stderr();
        if let Some(message) = &coverage.skipped_message {
            let _ignored = writeln!(stderr, "locket: {message}");
        } else {
            let _ignored = writeln!(
                stderr,
                "locket: known-value redaction skipped; pattern and entropy redaction only"
            );
        }
    }
    if invalid_utf8_passthrough {
        let mut stderr = io::stderr();
        let _ignored = writeln!(
            stderr,
            "locket: redact stdin passed non-UTF-8 byte segment(s) through unchanged"
        );
    }

    write_redact_audit_if_available(
        context,
        project.as_ref(),
        args,
        &coverage,
        &result,
        invalid_utf8_passthrough,
    )?;
    Ok(())
}

pub struct RedactCoverage {
    pub redactions: Vec<KnownSecretRedaction>,
    pub known_coverage_active: bool,
    pub redact_names_enabled: bool,
    pub known_secret_names: Vec<String>,
    pub skipped_message: Option<String>,
}

pub fn collect_redaction_values_for_redact(
    context: &RuntimeContext,
    project: Option<&ResolvedProject>,
    redact_names_enabled: bool,
    require_known: bool,
    timestamp: i64,
) -> Result<RedactCoverage, CliError> {
    let Some(project) = project else {
        if require_known {
            return Err(project_not_found_error());
        }
        return Ok(RedactCoverage {
            redactions: Vec::new(),
            known_coverage_active: false,
            redact_names_enabled,
            known_secret_names: Vec::new(),
            skipped_message: Some("known-value redaction skipped: no project resolved".to_owned()),
        });
    };
    match collect_known_secret_redactions(context, project, redact_names_enabled, timestamp) {
        Ok(redactions) => {
            let known_secret_names =
                redactions.iter().filter_map(|entry| entry.secret_name.clone()).collect();
            Ok(RedactCoverage {
                redactions,
                known_coverage_active: true,
                redact_names_enabled,
                known_secret_names,
                skipped_message: None,
            })
        }
        Err(error) => {
            if require_known {
                return Err(error);
            }
            Ok(RedactCoverage {
                redactions: Vec::new(),
                known_coverage_active: false,
                redact_names_enabled,
                known_secret_names: Vec::new(),
                skipped_message: Some(format!("known-value redaction skipped: {error}")),
            })
        }
    }
}

fn write_redact_audit_if_available(
    context: &RuntimeContext,
    project: Option<&ResolvedProject>,
    args: &RedactArgs,
    coverage: &RedactCoverage,
    result: &locket_scan::RedactionResult,
    invalid_utf8_passthrough: bool,
) -> Result<(), CliError> {
    let Some(project) = project else { return Ok(()) };
    let mut store = open_store(context)?;
    if store.get_project(project.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, &store, project.config.project_id.as_str(), KeyPurpose::Audit)?;

    let counts_by_rule: serde_json::Value = result
        .counts
        .iter()
        .map(|(kind, count)| (redact_finding_kind_label(*kind).to_owned(), json!(count)))
        .collect::<serde_json::Map<_, _>>()
        .into();
    let input_kind = if args.stdin { "stdin" } else { "file" };
    let metadata = json!({
        "schema_version": 1,
        "action": "REDACT",
        "status": "SUCCESS",
        "command": "redact",
        "input_kind": input_kind,
        "require_known": args.require_known,
        "known_coverage_active": coverage.known_coverage_active,
        "redact_names_enabled": coverage.redact_names_enabled,
        "redaction_counts_by_rule": counts_by_rule,
        "known_secret_names_redacted": coverage.known_secret_names,
        "invalid_utf8_passthrough": invalid_utf8_passthrough,
        "scope": input_kind,
        "known_value_coverage": if coverage.known_coverage_active { "active" } else { "pattern_only" },
        "finding_counts": &counts_by_rule,
        "pattern_only": !coverage.known_coverage_active,
    });
    let audit = AuditWrite {
        project_id: project.config.project_id.as_str(),
        profile_id: None,
        action: "REDACT",
        status: "SUCCESS",
        secret_name: None,
        command: Some("redact"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

const fn redact_finding_kind_label(kind: locket_scan::FindingKind) -> &'static str {
    match kind {
        locket_scan::FindingKind::HighEntropy => "high_entropy",
        locket_scan::FindingKind::ProviderTokenPattern => "provider_token",
        locket_scan::FindingKind::EnvFileMarker => "env_file_marker",
        locket_scan::FindingKind::KnownSecretValue => "known_secret_value",
    }
}

fn redact_input(
    input: &str,
    known_redactions: &[KnownSecretRedaction],
) -> locket_scan::RedactionResult {
    if known_redactions.is_empty() {
        return redact_text(input);
    }
    let known_values = known_redactions
        .iter()
        .map(|entry| KnownRedaction { value: entry.value.as_str(), marker: entry.marker.as_str() })
        .collect::<Vec<_>>();
    redact_text_with_known_values(input, &known_values)
}

pub struct RedactedBytes {
    pub bytes: Vec<u8>,
    pub result: locket_scan::RedactionResult,
    pub invalid_utf8_passthrough: bool,
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn redact_stdin_bytes(
    input: &[u8],
    known_redactions: &[KnownSecretRedaction],
) -> RedactedBytes {
    let mut bytes = Vec::with_capacity(input.len());
    let mut counts = BTreeMap::<FindingKind, usize>::new();
    let mut invalid_utf8_passthrough = false;
    let mut remaining = input;
    let mut pattern_index = 1_usize;

    while !remaining.is_empty() {
        match std::str::from_utf8(remaining) {
            Ok(text) => {
                append_redacted_stdin_text(
                    text,
                    known_redactions,
                    &mut bytes,
                    &mut counts,
                    &mut pattern_index,
                );
                break;
            }
            Err(error) => {
                let valid_up_to = error.valid_up_to();
                if valid_up_to > 0 {
                    if let Ok(text) = std::str::from_utf8(&remaining[..valid_up_to]) {
                        append_redacted_stdin_text(
                            text,
                            known_redactions,
                            &mut bytes,
                            &mut counts,
                            &mut pattern_index,
                        );
                    } else {
                        bytes.extend_from_slice(&remaining[..valid_up_to]);
                    }
                }
                let invalid_len = error.error_len().unwrap_or(remaining.len() - valid_up_to);
                bytes.extend_from_slice(&remaining[valid_up_to..valid_up_to + invalid_len]);
                invalid_utf8_passthrough = true;
                remaining = &remaining[valid_up_to + invalid_len..];
            }
        }
    }

    let text = String::from_utf8_lossy(&bytes).into_owned();
    RedactedBytes {
        bytes,
        result: locket_scan::RedactionResult { text, counts },
        invalid_utf8_passthrough,
    }
}

fn append_redacted_stdin_text(
    text: &str,
    known_redactions: &[KnownSecretRedaction],
    bytes: &mut Vec<u8>,
    counts: &mut BTreeMap<FindingKind, usize>,
    pattern_index: &mut usize,
) {
    let mut result = redact_input(text, known_redactions);
    result.text = localize_pattern_markers(&result.text, pattern_index);
    bytes.extend_from_slice(result.text.as_bytes());
    for (kind, count) in result.counts {
        *counts.entry(kind).or_default() += count;
    }
}

fn localize_pattern_markers(text: &str, pattern_index: &mut usize) -> String {
    let markers = ["lk_redacted_PROVIDER_TOKEN", "lk_redacted_HIGH_ENTROPY"];
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;
    while cursor < text.len() {
        let next = markers
            .iter()
            .filter_map(|marker| {
                text[cursor..].find(marker).map(|offset| (cursor + offset, *marker))
            })
            .min_by_key(|(index, _)| *index);
        let Some((index, marker)) = next else {
            output.push_str(&text[cursor..]);
            break;
        };
        output.push_str(&text[cursor..index]);
        output.push_str("lk_redacted_PATTERN_");
        output.push_str(&pattern_index.to_string());
        *pattern_index += 1;
        cursor = index + marker.len();
    }
    output
}

pub fn ai_safe_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &AiSafeArgs,
) -> Result<(), CliError> {
    if args.command.is_empty() {
        return Err(invalid_reference_error("ai-safe requires a command after --"));
    }

    let redact_names = privacy_redact_names_enabled(context, args.redact_names.redact_names)?;
    let audit_project = if args.pattern_only {
        let mut stderr = io::stderr();
        writeln!(
            stderr,
            "locket: ai-safe running with pattern-only redaction; known values are not loaded"
        )?;
        resolve_project(&context.cwd)?
    } else {
        let project = require_project(context)?;
        Some(project)
    };
    let known_redactions = if args.pattern_only {
        Vec::new()
    } else {
        let Some(project) = audit_project.as_ref() else {
            return Err(project_not_found_error());
        };
        collect_ai_safe_known_secret_redactions(context, project, redact_names, now_unix_nanos()?)?
    };

    let mut transcript = if let Some(path) = args.output.as_deref() {
        Some(open_ai_safe_transcript(&absolutize(&context.cwd, Path::new(path)), args.force)?)
    } else {
        None
    };

    let result = run_ai_safe_child(context, output, transcript.as_mut(), args, &known_redactions)?;
    write_ai_safe_audit_if_available(
        context,
        audit_project.as_ref(),
        args,
        &result,
        !args.pattern_only,
        redact_names,
    )?;

    if result.exit_code == 0 { Ok(()) } else { Err(CliError::ChildExit(result.exit_code)) }
}

fn open_ai_safe_transcript(path: &Path, force: bool) -> Result<fs::File, CliError> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options.open(path)?;
    set_user_only_file_permissions(path)?;
    Ok(file)
}

fn collect_ai_safe_known_secret_redactions(
    context: &RuntimeContext,
    project: &ResolvedProject,
    redact_names: bool,
    timestamp: i64,
) -> Result<Vec<KnownSecretRedaction>, CliError> {
    collect_known_secret_redactions(context, project, redact_names, timestamp).map_err(|error| {
        if matches!(error, CliError::Platform(locket_platform::PlatformError::MasterKeyNotFound)) {
            crate::runtime::degraded_audit::record_locked_refusal(
                context,
                "REDACT",
                Some(project.config.project_id.as_str()),
                "scan ai-safe",
            );
            unlock_required_error(
                "UnlockRequired: ai-safe requires known-value redaction coverage; run locket unlock or pass --pattern-only",
            )
        } else {
            error
        }
    })
}

#[derive(Clone, Copy, Debug)]
pub enum AiSafeStream {
    Stdout,
    Stderr,
}

impl AiSafeStream {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

pub struct AiSafeRawChunk {
    pub stream: AiSafeStream,
    pub bytes: Vec<u8>,
}

pub struct AiSafeRedactedChunk {
    pub stream: AiSafeStream,
    pub text: String,
    pub counts: BTreeMap<FindingKind, usize>,
    pub redacted_secret_names: BTreeSet<String>,
    pub buffer_limit_reached: bool,
    pub unterminated_partial_line: bool,
}

#[derive(Default)]
pub struct AiSafeRunResult {
    pub exit_code: u8,
    pub counts: BTreeMap<FindingKind, usize>,
    pub redacted_secret_names: BTreeSet<String>,
    pub stdout_chunks: usize,
    pub stderr_chunks: usize,
    pub buffer_limit_flushes: usize,
    pub partial_line_flushes: usize,
}

struct AiSafeStreamState {
    stream: AiSafeStream,
    pending: Vec<u8>,
    discarding_line: bool,
}

impl AiSafeStreamState {
    const fn new(stream: AiSafeStream) -> Self {
        Self { stream, pending: Vec::new(), discarding_line: false }
    }
}

pub struct AiSafeStreamRedactor<'a> {
    stdout: AiSafeStreamState,
    stderr: AiSafeStreamState,
    known_redactions: &'a [KnownSecretRedaction],
}

impl<'a> AiSafeStreamRedactor<'a> {
    pub const fn new(known_redactions: &'a [KnownSecretRedaction]) -> Self {
        Self {
            stdout: AiSafeStreamState::new(AiSafeStream::Stdout),
            stderr: AiSafeStreamState::new(AiSafeStream::Stderr),
            known_redactions,
        }
    }

    pub fn push(&mut self, raw: AiSafeRawChunk) -> Vec<AiSafeRedactedChunk> {
        let stream = raw.stream;
        let bytes = raw.bytes;
        let state = match stream {
            AiSafeStream::Stdout => &mut self.stdout,
            AiSafeStream::Stderr => &mut self.stderr,
        };
        state.pending.extend(bytes);
        drain_ai_safe_pending(state, self.known_redactions, false)
    }

    pub fn finish(&mut self) -> Vec<AiSafeRedactedChunk> {
        let mut chunks = drain_ai_safe_pending(&mut self.stdout, self.known_redactions, true);
        chunks.extend(drain_ai_safe_pending(&mut self.stderr, self.known_redactions, true));
        chunks
    }
}

fn drain_ai_safe_pending(
    state: &mut AiSafeStreamState,
    known_redactions: &[KnownSecretRedaction],
    final_flush: bool,
) -> Vec<AiSafeRedactedChunk> {
    let mut chunks = Vec::new();
    loop {
        let newline_index = state.pending.iter().position(|byte| *byte == b'\n');
        if state.discarding_line {
            if let Some(newline_index) = newline_index {
                // Keep the delimiter so output framing survives the discarded line.
                state.pending.drain(..newline_index);
                state.discarding_line = false;
                continue;
            }
            state.pending.clear();
            break;
        }
        if let Some(newline_index) = newline_index
            && newline_index < AI_SAFE_PARTIAL_LINE_MAX_BYTES
        {
            let bytes = state.pending.drain(..=newline_index).collect::<Vec<_>>();
            chunks.push(redact_ai_safe_bytes(state.stream, &bytes, known_redactions, false, false));
            continue;
        }
        if state.pending.len() >= AI_SAFE_PARTIAL_LINE_MAX_BYTES {
            // A byte cut can split a known value or UTF-8 character. Retaining
            // only the longest-secret suffix still exposes crossing matches.
            // Record detections already available, but suppress the whole line.
            let mut chunk = redact_ai_safe_bytes(
                state.stream,
                &state.pending[..AI_SAFE_PARTIAL_LINE_MAX_BYTES],
                known_redactions,
                true,
                false,
            );
            "lk_redacted_BUFFER_LIMIT".clone_into(&mut chunk.text);
            chunks.push(chunk);
            state.discarding_line = true;
            continue;
        }
        break;
    }

    if final_flush && state.discarding_line {
        state.discarding_line = false;
        chunks.push(redact_ai_safe_bytes(state.stream, &[], &[], false, true));
    } else if final_flush && !state.pending.is_empty() {
        let bytes = std::mem::take(&mut state.pending);
        chunks.push(redact_ai_safe_bytes(state.stream, &bytes, known_redactions, false, true));
    }
    chunks
}

fn redact_ai_safe_bytes(
    stream: AiSafeStream,
    bytes: &[u8],
    known_redactions: &[KnownSecretRedaction],
    buffer_limit_reached: bool,
    unterminated_partial_line: bool,
) -> AiSafeRedactedChunk {
    let input = String::from_utf8_lossy(bytes);
    // Streaming flushes at newlines. Match each nonempty line of a known
    // value so a multiline credential cannot escape in separate chunks.
    // This deliberately redacts standalone occurrences of those lines too.
    let known_lines = known_redactions
        .iter()
        .flat_map(|entry| {
            entry
                .value
                .split('\n')
                .filter(|line| !line.is_empty())
                .map(|line| KnownRedaction { value: line, marker: entry.marker.as_str() })
        })
        .collect::<Vec<_>>();
    let redacted_secret_names = known_redactions
        .iter()
        .filter(|entry| {
            entry.value.split('\n').any(|line| !line.is_empty() && input.contains(line))
        })
        .filter_map(|entry| entry.secret_name.clone())
        .collect::<BTreeSet<_>>();
    let result = redact_text_with_known_values(&input, &known_lines);
    AiSafeRedactedChunk {
        stream,
        text: result.text,
        counts: result.counts,
        redacted_secret_names,
        buffer_limit_reached,
        unterminated_partial_line,
    }
}

fn run_ai_safe_child(
    context: &RuntimeContext,
    output: &mut impl Write,
    transcript: Option<&mut fs::File>,
    args: &AiSafeArgs,
    known_redactions: &[KnownSecretRedaction],
) -> Result<AiSafeRunResult, CliError> {
    let mut child = ProcessCommand::new(&args.command[0])
        .args(&args.command[1..])
        .current_dir(&context.cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout =
        child.stdout.take().ok_or_else(|| corrupt_db_error("failed to capture child stdout"))?;
    let stderr =
        child.stderr.take().ok_or_else(|| corrupt_db_error("failed to capture child stderr"))?;
    let (sender, receiver) = mpsc::channel::<Result<AiSafeRawChunk, io::Error>>();
    let stdout_reader = spawn_ai_safe_reader(AiSafeStream::Stdout, stdout, sender.clone());
    let stderr_reader = spawn_ai_safe_reader(AiSafeStream::Stderr, stderr, sender);

    let mut redactor = AiSafeStreamRedactor::new(known_redactions);
    let mut result = AiSafeRunResult::default();
    let mut stderr_output = io::stderr();
    let mut transcript = transcript;
    for message in receiver {
        let raw = message?;
        for chunk in redactor.push(raw) {
            emit_ai_safe_chunk(
                output,
                &mut stderr_output,
                transcript.as_deref_mut(),
                &mut result,
                chunk,
            )?;
        }
    }
    stdout_reader.join().map_err(|_| corrupt_db_error("ai-safe stdout reader panicked"))?;
    stderr_reader.join().map_err(|_| corrupt_db_error("ai-safe stderr reader panicked"))?;
    for chunk in redactor.finish() {
        emit_ai_safe_chunk(
            output,
            &mut stderr_output,
            transcript.as_deref_mut(),
            &mut result,
            chunk,
        )?;
    }
    let status = child.wait()?;
    result.exit_code = status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1);
    Ok(result)
}

fn spawn_ai_safe_reader<R: Read + Send + 'static>(
    stream: AiSafeStream,
    mut reader: R,
    sender: mpsc::Sender<Result<AiSafeRawChunk, io::Error>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0_u8; AI_SAFE_READ_CHUNK_BYTES];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    let chunk = AiSafeRawChunk { stream, bytes: buffer[..length].to_vec() };
                    if sender.send(Ok(chunk)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ignored = sender.send(Err(error));
                    break;
                }
            }
        }
    })
}

fn emit_ai_safe_chunk(
    output: &mut impl Write,
    stderr_output: &mut impl Write,
    transcript: Option<&mut fs::File>,
    result: &mut AiSafeRunResult,
    chunk: AiSafeRedactedChunk,
) -> Result<(), CliError> {
    if chunk.buffer_limit_reached {
        writeln!(
            stderr_output,
            "locket: ai-safe warning: {} partial-line buffer limit reached; suppressed the entire line",
            chunk.stream.as_str()
        )?;
        result.buffer_limit_flushes += 1;
    }
    if chunk.unterminated_partial_line {
        writeln!(
            stderr_output,
            "locket: ai-safe warning: {} ended with an unterminated partial line; emitted redacted buffered output",
            chunk.stream.as_str()
        )?;
        result.partial_line_flushes += 1;
    }

    match chunk.stream {
        AiSafeStream::Stdout => {
            write!(output, "{}", chunk.text)?;
            result.stdout_chunks += 1;
        }
        AiSafeStream::Stderr => {
            write!(stderr_output, "{}", chunk.text)?;
            result.stderr_chunks += 1;
        }
    }
    if let Some(file) = transcript {
        write_ai_safe_transcript_chunk(file, chunk.stream, &chunk.text)?;
    }
    merge_finding_counts(&mut result.counts, &chunk.counts);
    result.redacted_secret_names.extend(chunk.redacted_secret_names);
    Ok(())
}

fn write_ai_safe_transcript_chunk(
    file: &mut impl Write,
    stream: AiSafeStream,
    text: &str,
) -> Result<(), CliError> {
    if text.is_empty() {
        return Ok(());
    }
    let timestamp =
        unix_nanos_to_rfc3339(now_unix_nanos()?).unwrap_or_else(|| "unknown".to_owned());
    writeln!(file, "[{} timestamp={}]", stream.as_str(), timestamp)?;
    write!(file, "{text}")?;
    if !text.ends_with('\n') {
        writeln!(file)?;
    }
    Ok(())
}

fn merge_finding_counts(
    target: &mut BTreeMap<FindingKind, usize>,
    source: &BTreeMap<FindingKind, usize>,
) {
    for (kind, count) in source {
        *target.entry(*kind).or_default() += count;
    }
}

fn finding_counts_json(counts: &BTreeMap<FindingKind, usize>) -> BTreeMap<&'static str, usize> {
    counts.iter().map(|(kind, count)| (finding_kind_name(*kind), *count)).collect()
}

const fn finding_kind_name(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::HighEntropy => "high_entropy",
        FindingKind::ProviderTokenPattern => "provider_token_pattern",
        FindingKind::EnvFileMarker => "env_file_marker",
        FindingKind::KnownSecretValue => "known_secret_value",
    }
}

fn write_ai_safe_audit_if_available(
    context: &RuntimeContext,
    resolved: Option<&ResolvedProject>,
    args: &AiSafeArgs,
    result: &AiSafeRunResult,
    known_value_coverage: bool,
    redact_names: bool,
) -> Result<(), CliError> {
    let Some(resolved) = resolved else {
        return Ok(());
    };
    let mut store = open_store(context)?;
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key = match load_project_key(
        context,
        &store,
        resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    ) {
        Ok(key) => key,
        Err(CliError::Platform(locket_platform::PlatformError::MasterKeyNotFound)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let metadata = json!({
        "schema_version": 1,
        "action": "REDACT",
        "status": "SUCCESS",
        "command": "ai-safe",
        "scope": "ai-safe",
        "argv0": args.command.first().map(String::as_str).unwrap_or_default(),
        "arg_count": args.command.len().saturating_sub(1),
        "pattern_only": args.pattern_only,
        "redact_names": redact_names,
        "known_value_coverage": known_value_coverage,
        "output_destinations": {
            "stdout": true,
            "stderr": true,
            "transcript": args.output.is_some(),
        },
        "child_exit_code": result.exit_code,
        "finding_counts": finding_counts_json(&result.counts),
        "redacted_secret_names": summarize_names(&result.redacted_secret_names.iter().cloned().collect::<Vec<_>>()),
        "stdout_chunks": result.stdout_chunks,
        "stderr_chunks": result.stderr_chunks,
        "buffer_limit_flushes": result.buffer_limit_flushes,
        "partial_line_flushes": result.partial_line_flushes,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "REDACT",
        status: "SUCCESS",
        secret_name: None,
        command: Some("ai-safe"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

pub struct KnownSecretRedaction {
    pub value: zeroize::Zeroizing<String>,
    pub marker: String,
    pub secret_name: Option<String>,
}

pub fn collect_known_secret_redactions(
    context: &RuntimeContext,
    project: &ResolvedProject,
    redact_names: bool,
    timestamp: i64,
) -> Result<Vec<KnownSecretRedaction>, CliError> {
    let store = open_store(context)?;
    ensure_trusted_project_root(&store, project)?;
    let profile = default_profile(&store, &project.config)?;
    let mut values = Vec::new();
    for secret in store.list_secrets_by_profile(project.config.project_id.as_str(), &profile.id)? {
        let marker = known_secret_redaction_marker(&secret, redact_names);
        for version in store.list_secret_versions(&secret.id)? {
            if should_scan_known_version(&secret, &version, timestamp)
                && store.get_blob(&secret.id, version.version)?.is_some()
            {
                values.push(KnownSecretRedaction {
                    value: decrypt_secret_version(
                        context,
                        &store,
                        project.config.project_id.as_str(),
                        &profile.id,
                        &secret,
                        version.version,
                    )?,
                    marker: marker.clone(),
                    secret_name: Some(secret.name.clone()),
                });
            }
        }
    }
    Ok(values)
}

pub fn known_secret_redaction_marker(secret: &SecretRecord, redact_names: bool) -> String {
    let label =
        if redact_names { privacy_alias("secret", &secret.id) } else { secret.name.clone() };
    format!("lk_redacted_{label}")
}
