use std::io::{self, Write};

use super::{StreamingRedactionStats, StreamingRedactor, StreamingRedactorConfig};
use crate::env_value;
use crate::secret_encoding::Form;

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
fn recognizes_all_encodings_even_at_eof() -> io::Result<()> {
    let secret = "x?/\u{00ff}\"\n";
    let defined = [
        (Form::Url, &b"x%3F%2F%C3%BF%22%0A"[..]),
        (Form::UrlLower, &b"x%3f%2f%c3%bf%22%0a"[..]),
        (Form::Json, r#"x?/ÿ\"\n"#.as_bytes()),
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
    assert_eq!(output, b"");
    assert!(stats.redacted_labels.is_empty());
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
        &["α=ghp_abcdef123456".as_bytes(), b"7890ABCDEF1234567890abcd;ok\n\xff\xfe\nend"],
        config,
    )?;
    assert_eq!(output, ["α=[REDACTED:locket];ok\n".as_bytes(), b"\xff\xfe\nend"].concat());
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
