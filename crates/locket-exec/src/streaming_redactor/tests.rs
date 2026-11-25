use std::io::{self, Write};

use proptest::prelude::*;

use super::{StreamingRedactionStats, StreamingRedactor, StreamingRedactorConfig};
use crate::env_value;
use crate::secret_encoding::Form;

#[derive(Debug)]
enum StreamPart {
    Noise(Vec<u8>),
    Slice { secret: prop::sample::Index, start: usize, end: usize },
}

fn stream_parts() -> impl Strategy<Value = Vec<StreamPart>> {
    prop::collection::vec(
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..16).prop_map(StreamPart::Noise),
            (any::<prop::sample::Index>(), 0..32_usize, 0..32_usize)
                .prop_map(|(secret, start, end)| StreamPart::Slice { secret, start, end }),
        ],
        0..24,
    )
}

fn short_secret() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-d]{2,8}",
        prop::collection::vec(any::<char>(), 1..9).prop_map(|chars| chars.into_iter().collect()),
        prop::sample::select(vec![
            "[REDACTED]",
            "x[REDACTED]y",
            "D]",
            "[R",
            "x[",
            "]x",
            "\0a",
            "秘密"
        ])
        .prop_map(str::to_owned),
    ]
}

fn contains_secret(payload: &[u8], secret: &str) -> bool {
    payload.windows(secret.len()).any(|window| window == secret.as_bytes())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    // TLA+ NoUnredactedSecretInChildOutput and ChunkingMatchesBatch, and
    // Lean redacted_output_free_of_pattern, streaming_eq_batch and clean_stream_identity.
    #[test]
    fn known_secret_redaction_conforms_across_byte_partitions(
        mut secrets in prop::collection::btree_set(short_secret(), 0..8),
        overlap in "[a-d]{2,4}",
        parts in stream_parts(),
        cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..40),
        clean in any::<bool>(),
        labels in any::<bool>(),
        frame in ("[a-d]{0,4}", "[a-d]{0,4}"),
    ) {
        secrets.extend([format!("a{overlap}"), format!("{overlap}b")]);
        let secrets: Vec<_> = secrets.into_iter().collect();
        let mut input = Vec::new();
        for part in parts {
            match part {
                StreamPart::Noise(bytes) => input.extend(bytes),
                StreamPart::Slice { secret, start, end } => {
                    let bytes = secrets[secret.index(secrets.len())].as_bytes();
                    let (start, end) = (start % (bytes.len() + 1), end % (bytes.len() + 1));
                    input.extend_from_slice(&bytes[start.min(end)..start.max(end)]);
                }
            }
        }
        if clean {
            // 0xff cannot occur in a registered UTF-8 secret. Insert it before
            // each byte to construct clean streams with arbitrary binary data.
            input = input.into_iter().flat_map(|byte| [0xff, byte]).collect();
            // A one-byte secret still needs to be removed from the clean input.
            input.retain(|byte| !secrets.iter().any(|s| s.as_bytes() == [*byte]));
        } else {
            // Force overlapping matches and adjacent matches amid partial
            // secret bytes, with no separator to mask a replacement splice.
            input.extend_from_slice(format!("{}a{overlap}b{overlap}b{}", frame.0, frame.1).as_bytes());
            for secret in &secrets {
                input.extend_from_slice(secret.as_bytes());
            }
        }
        let config = StreamingRedactorConfig {
            known_secrets: secrets.iter().enumerate()
                .map(|(index, secret)| (format!("KEY_{index}"), env_value(secret)))
                .collect(),
            replacement: "[REDACTED]".into(),
            label_replacements: labels,
            include_encoded_variants: false,
            min_secret_len: 1,
            ..StreamingRedactorConfig::default()
        };
        let cut_points: std::collections::BTreeSet<_> = cuts.into_iter()
            .map(|cut| cut.index(input.len() + 1))
            .chain([0, input.len()])
            .collect();
        let cuts: Vec<_> = cut_points.into_iter().collect();
        let chunks: Vec<_> = cuts.windows(2).map(|ends| &input[ends[0]..ends[1]]).collect();
        let bytes: Vec<_> = input.chunks(1).collect();
        let batch = redact(&[&input], config.clone())?;
        prop_assert_eq!(&redact(&chunks, config.clone())?, &batch);
        prop_assert_eq!(&redact(&bytes, config)?, &batch);
        let (output, _) = batch;
        prop_assert!(!secrets.iter().any(|secret| contains_secret(&output, secret)));
        if clean || !secrets.iter().any(|secret| contains_secret(&input, secret)) {
            prop_assert_eq!(output, input);
        }
    }
}

fn config(secrets: &[(&str, &str)]) -> StreamingRedactorConfig {
    StreamingRedactorConfig {
        known_secrets: secrets
            .iter()
            .map(|(name, value)| ((*name).into(), env_value(*value)))
            .collect(),
        ..StreamingRedactorConfig::default()
    }
}

fn redact(
    chunks: &[&[u8]],
    config: StreamingRedactorConfig,
) -> io::Result<(Vec<u8>, StreamingRedactionStats)> {
    let mut output = Vec::new();
    let mut redactor = StreamingRedactor::new(&mut output, config);
    for chunk in chunks {
        redactor.write_all(chunk)?;
        redactor.flush()?;
    }
    redactor.flush_final()?;
    let stats = redactor.stats;
    Ok((output, stats))
}

#[test]
fn one_byte_writes_and_flushes_never_expose_a_secret() -> io::Result<()> {
    let secret = "multi-byte-秘密-a-forty-byte-test-secret";
    let mut output = Vec::new();
    let config = config(&[("TOKEN", secret)]);
    assert!(!format!("{config:?}").contains(secret));
    let mut redactor = StreamingRedactor::new(&mut output, config);
    for byte in secret.as_bytes() {
        redactor.write_all(std::slice::from_ref(byte))?;
        redactor.flush()?;
        assert!(!format!("{redactor:?}").contains(secret));
        assert_eq!(redactor.writer.as_slice(), b"");
    }
    redactor.flush_final()?;
    assert_eq!(redactor.writer, b"[REDACTED:locket]");
    assert!(redactor.pending.is_empty());
    assert_eq!(redactor.stats().redaction_count, 1);
    assert_eq!(redactor.stats().redacted_labels, ["TOKEN".to_owned()].into());
    Ok(())
}

#[test]
fn matches_across_every_chunk_boundary_in_binary_data() -> io::Result<()> {
    let input = b"\xff\xfe\0in-binary-secret\xf8\0\xff";
    for split in 0..=input.len() {
        let (output, stats) =
            redact(&[&input[..split], &input[split..]], config(&[("KEY", "in-binary-secret")]))?;
        assert_eq!(output, b"\xff\xfe\0[REDACTED:locket]\xf8\0\xff");
        assert_eq!(stats.redaction_count, 1);
    }
    let (output, stats) = redact(&[b"\xff\xfe\x80"], config(&[("KEY", "secret")]))?;
    assert_eq!(output, b"\xff\xfe\x80");
    assert_eq!(stats.redaction_count, 0);
    Ok(())
}

#[test]
fn longest_match_at_a_position_and_intersecting_suffixes_are_covered() -> io::Result<()> {
    let mut config = config(&[
        ("SHORT", "abcd"),
        ("LONG", "abcdefgh"),
        ("CROSS", "ghijklmnop"),
        ("ALIAS", "abcd"),
    ]);
    config.label_replacements = true;
    config.include_encoded_variants = false;
    let (output, stats) = redact(&[b"!abcd", b"efgh", b"ijk", b"lmnop!"], config)?;
    assert_eq!(output, b"![REDACTED:CROSS]!");
    assert_eq!(stats.redaction_count, 1);
    assert_eq!(
        stats.redacted_labels,
        ["ALIAS".into(), "CROSS".into(), "LONG".into(), "SHORT".into()].into()
    );
    Ok(())
}

#[test]
fn byte_writes_preserve_utf8_and_incomplete_prefixes_around_repeated_overlaps() -> io::Result<()> {
    let cfg = StreamingRedactorConfig {
        include_encoded_variants: false,
        ..config(&[("FIRST", "秘密-abc"), ("SECOND", "abc-終わり")])
    };
    let input = "α秘密-ab!🙂秘密-abc-終わり🌿秘密-abc-終わり秘密-a";
    let (output, stats) = redact(&input.as_bytes().chunks(1).collect::<Vec<_>>(), cfg)?;
    assert_eq!(output, "α秘密-ab!🙂[REDACTED:locket]🌿[REDACTED:locket]秘密-a".as_bytes());
    assert_eq!(stats.redaction_count, 2);
    assert_eq!(stats.redacted_labels, ["FIRST".into(), "SECOND".into()].into());
    Ok(())
}

#[test]
fn recognizes_all_encodings_even_at_eof() -> io::Result<()> {
    let secret = "x?/\u{00ff}\"\r\n";
    let defined = [
        (Form::Url, &b"x%3F%2F%C3%BF%22%0D%0A"[..]),
        (Form::UrlLower, &b"x%3f%2f%c3%bf%22%0d%0a"[..]),
        (Form::Json, r#"x?/ÿ\"\r\n"#.as_bytes()),
    ];
    for (form, expected) in defined {
        assert_eq!(form.encode(secret.as_bytes()).as_slice(), expected);
    }
    for form in Form::ALL {
        let encoded = form.encode(secret.as_bytes());
        let (output, stats) =
            redact(&encoded.chunks(1).collect::<Vec<_>>(), config(&[("KEY", secret)]))?;
        assert_eq!(output, b"[REDACTED:locket]");
        assert_eq!(stats.redaction_count, 1);
    }
    Ok(())
}

#[test]
fn configurable_markers_cannot_contain_a_secret() -> io::Result<()> {
    let mut config = config(&[("THE-secret", "secret")]);
    config.label_replacements = true;
    config.replacement = "marker:secret".into();
    let (output, stats) = redact(&[b"secret"], config)?;
    assert_eq!(output, b"[REDACTED:locket]");
    assert!(stats.redacted_labels.is_empty());
    assert_eq!(stats.redaction_count, 1);
    Ok(())
}

#[test]
fn marker_collision_cannot_splice_surrounding_bytes_into_a_secret() -> io::Result<()> {
    let cfg = StreamingRedactorConfig { min_secret_len: 1, ..config(&[("TOKEN", "locket")]) };
    let (output, stats) = redact(&[b"loc", b"locket", b"ket"], cfg)?;
    assert_eq!(output, b"loc[REDACTED]ket");
    assert_eq!(stats.redaction_count, 1);
    Ok(())
}

#[test]
fn multiple_marker_collisions_skip_each_unsafe_candidate() -> io::Result<()> {
    let cfg = StreamingRedactorConfig {
        min_secret_len: 1,
        ..config(&[("TOKEN", "locket"), ("MARKER", "[REDACTED]")])
    };
    let (output, stats) = redact(&[b"loclocketket [REDACTED]"], cfg)?;
    assert_eq!(output, b"loc[***]ket [***]");
    assert_eq!(stats.redaction_count, 2);
    Ok(())
}

#[test]
fn synthesized_marker_avoids_single_character_secrets() -> io::Result<()> {
    let covered = "[REDACTED:locket]*\u{2588}";
    let cfg = StreamingRedactorConfig {
        min_secret_len: 1,
        known_secrets: covered
            .chars()
            .map(|ch| (String::new(), env_value(ch.to_string())))
            .collect(),
        ..StreamingRedactorConfig::default()
    };
    let patterns = super::RedactionPatterns::new(cfg.clone());
    let (output, stats) = redact(&[b"l"], cfg)?;
    assert_eq!(output.len(), 1);
    assert!(
        patterns
            .by_first_byte
            .iter()
            .flatten()
            .all(|pattern| { output.iter().all(|byte| !pattern.bytes.contains(byte)) })
    );
    assert_eq!(stats.redaction_count, 1);
    Ok(())
}

#[test]
fn binary_marker_preserves_provider_scanning() -> io::Result<()> {
    let printable_ascii: String = (b'!'..=b'~').map(char::from).collect();
    let cfg = StreamingRedactorConfig {
        min_secret_len: 1,
        redact_generic_patterns: true,
        ..config(&[
            ("ASCII", &printable_ascii),
            ("BRACKET", "["),
            ("BLOCK", "█"),
            ("TOKEN", "synthetic-secret"),
        ])
    };
    let (output, stats) =
        redact(&[b"synthetic-secret ghp_abcdef1234567890ABCDEF1234567890abcd"], cfg)?;
    assert_eq!(output, b"\xff \xff");
    assert_eq!(stats.redaction_count, 2);
    Ok(())
}

#[test]
fn additional_literals_can_invalidate_the_selected_marker() -> io::Result<()> {
    let patterns = super::RedactionPatterns::new(config(&[("TOKEN", "synthetic-secret")]));
    let patterns = patterns.with_additional_literals(vec![env_value(""), env_value("REDACTED")]);
    let mut output = Vec::new();
    let mut redactor = StreamingRedactor::with_patterns(&mut output, patterns);
    redactor.write_all(b"synthetic-secret REDACTED")?;
    redactor.flush_final()?;
    assert_eq!(output, b"[***] [***]");
    Ok(())
}

#[test]
fn custom_marker_must_not_overlap_a_secret() -> io::Result<()> {
    for (secret, input, expected) in [
        ("leftx", "lefttrigger", "left[REDACTED:locket]"),
        ("yright", "triggerright", "[REDACTED:locket]right"),
        ("lefxyght", "leftriggerght", "lef[REDACTED:locket]ght"),
    ] {
        let cfg = StreamingRedactorConfig {
            replacement: "xy".into(),
            include_encoded_variants: false,
            ..config(&[("OTHER", secret), ("TOKEN", "trigger")])
        };
        let (output, stats) = redact(&[input.as_bytes()], cfg)?;
        assert_eq!(output, expected.as_bytes());
        assert_eq!(stats.redaction_count, 1);
    }
    Ok(())
}

#[test]
fn label_marker_cannot_recreate_a_secret_at_its_boundary() -> io::Result<()> {
    let cfg = StreamingRedactorConfig {
        label_replacements: true,
        ..config(&[("OTHER", "left["), ("TOKEN", "trigger")])
    };
    let (output, stats) = redact(&[b"lefttrigger"], cfg)?;
    assert_eq!(output, "left███".as_bytes());
    assert_eq!(stats.redaction_count, 1);
    Ok(())
}

#[test]
fn short_secrets_require_opt_in() -> io::Result<()> {
    let mut config = config(&[("SHORT", "ab"), ("EMPTY", "")]);
    let (output, _) = redact(&[b"ab"], config.clone())?;
    assert_eq!(output, b"ab");
    config.min_secret_len = 0;
    let (output, stats) = redact(&[b"ab"], config)?;
    assert_eq!(output, b"[REDACTED:locket]");
    assert_eq!(stats.redaction_count, 1);
    Ok(())
}

#[test]
fn provider_scanning_preserves_utf8_positions_and_binary_lines() -> io::Result<()> {
    let mut config = config(&[]);
    config.redact_generic_patterns = true;
    let (output, stats) = redact(
        &[
            "α=ghp_abcdef123456".as_bytes(),
            b"7890ABCDEF1234567890abcd;ok\naB3dE6gH9jK2mN5pQ8sT1vW4\n\xff\xfe\nend",
        ],
        config,
    )?;
    assert_eq!(
        output,
        ["α=[REDACTED:locket];ok\n".as_bytes(), b"aB3dE6gH9jK2mN5pQ8sT1vW4\n\xff\xfe\nend"]
            .concat()
    );
    assert_eq!(stats.redaction_count, 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn drains_both_child_streams_through_independent_redactors() -> io::Result<()> {
    use std::process::{Command, Stdio};

    let mut child = Command::new("/bin/sh")
        .args(["-c", "printf 'stdout:test-'; printf 'stderr:test-' >&2; printf 'secret'; printf 'secret' >&2"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let redaction = super::redact_child_output(
        &mut child,
        &mut stdout,
        &mut stderr,
        config(&[("TOKEN", "test-secret")]),
    );
    assert!(child.wait()?.success());
    let (stdout_stats, stderr_stats) = redaction?;
    assert_eq!(stdout, b"stdout:[REDACTED:locket]");
    assert_eq!(stderr, b"stderr:[REDACTED:locket]");
    assert_eq!(stdout_stats.redaction_count, 1);
    assert_eq!(stderr_stats, stdout_stats);
    Ok(())
}

#[test]
fn empty_replacement_falls_back_to_nonempty_marker() -> io::Result<()> {
    let mut cfg = config(&[("TOKEN", "SECRET")]);
    cfg.replacement = String::new();
    let (output, stats) = redact(&[b"SEC", b"SECRET", b"RET"], cfg)?;
    assert_eq!(output, b"SEC[REDACTED:locket]RET");
    assert!(!output.windows(b"SECRET".len()).any(|window| window == b"SECRET"));
    assert_eq!(stats.redaction_count, 1);
    Ok(())
}

#[test]
fn generic_redactor_collapses_overlong_lines_and_recovers_on_newline() -> io::Result<()> {
    let mut config = config(&[]);
    config.redact_generic_patterns = true;
    let limit = vec![b'a'; super::MAX_GENERIC_LINE];
    let (output, stats) = redact(
        &[&limit, b"!", b"discard this tail", b"\nnormal\n", &limit, b"!", b"discard at EOF"],
        config,
    )?;
    assert_eq!(output, b"[REDACTED:locket]\nnormal\n[REDACTED:locket]");
    assert_eq!(stats.redaction_count, 2);
    Ok(())
}

#[test]
fn finalized_redactor_rejects_additional_writes_and_finalization() -> io::Result<()> {
    let mut output = Vec::new();
    let mut writer = StreamingRedactor::new(&mut output, config(&[("KEY", "fixture-secret")]));
    writer.write_all(b"fixture-secret")?;
    writer.flush_final()?;
    assert!(writer.write_all(b"more").is_err());
    assert!(writer.flush_final().is_err());
    assert_eq!(output, b"[REDACTED:locket]");
    Ok(())
}

#[test]
fn downstream_failure_stops_streaming_redaction() {
    struct BrokenWriter;
    impl Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut writer = StreamingRedactor::new(BrokenWriter, config(&[]));
    assert_eq!(writer.write(b"data").err().map(|err| err.kind()), Some(io::ErrorKind::BrokenPipe));
    assert_eq!(writer.write(b"more").err().map(|err| err.kind()), Some(io::ErrorKind::Other));
    assert!(writer.flush_final().is_err());
}

#[test]
fn copying_redacted_output_retries_interrupted_reads_and_returns_hard_errors() {
    struct BrokenReader(bool);
    impl io::Read for BrokenReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            let first = std::mem::replace(&mut self.0, false);
            Err(if first { io::ErrorKind::Interrupted } else { io::ErrorKind::InvalidData }.into())
        }
    }
    let result = super::copy_redacted(
        BrokenReader(true),
        io::sink(),
        super::RedactionPatterns::new(config(&[])),
    );
    assert_eq!(result.err().map(|err| err.kind()), Some(io::ErrorKind::InvalidData));
}

#[cfg(unix)]
#[test]
fn child_redaction_requires_both_pipes_without_taking_the_available_pipe() -> io::Result<()> {
    use std::process::{Command, Stdio};

    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = super::redact_child_output(&mut child, io::sink(), io::sink(), config(&[]));
    assert!(child.wait()?.success());
    assert!(child.stdout.is_some());
    assert_eq!(result.err().map(|err| err.kind()), Some(io::ErrorKind::Other));
    Ok(())
}
