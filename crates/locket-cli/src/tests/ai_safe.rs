#[allow(unused_imports)]
use super::*;

#[test]
fn ai_safe_redacts_multiline_known_secrets_across_reads_and_streams() {
    let value = "quiet apple\nquiet pear";
    let redactions = vec![crate::KnownSecretRedaction {
        value: zeroize::Zeroizing::new(value.to_owned()),
        marker: "lk_redacted_TEST".to_owned(),
        secret_name: Some("TEST".to_owned()),
    }];
    for stream in [crate::AiSafeStream::Stdout, crate::AiSafeStream::Stderr] {
        for split in 0..=value.len() {
            let mut redactor = crate::AiSafeStreamRedactor::new(&redactions);
            let mut chunks = redactor
                .push(crate::AiSafeRawChunk { stream, bytes: value.as_bytes()[..split].to_vec() });
            chunks.extend(
                redactor.push(crate::AiSafeRawChunk {
                    stream,
                    bytes: value.as_bytes()[split..].to_vec(),
                }),
            );
            chunks.extend(redactor.finish());
            let text = chunks.iter().map(|chunk| chunk.text.as_str()).collect::<String>();
            assert!(!text.contains("quiet apple"));
            assert!(!text.contains("quiet pear"));
            assert!(text.contains("lk_redacted_TEST"));
            assert!(chunks.iter().any(|chunk| chunk.redacted_secret_names.contains("TEST")));
        }
    }
}

#[test]
fn ai_safe_multiline_transcript_never_contains_known_value_lines()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    fs::write(directory.path().join(".env"), "MULTILINE=\"quiet apple\nquiet pear\"\n")?;
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--output",
            "transcript.log",
            "--",
            "/bin/sh",
            "-c",
            "printf 'quiet apple\nquiet pear\n'; printf 'quiet apple\nquiet pear\n' >&2",
        ])?,
        &context,
        &mut output,
    )?;
    for text in
        [String::from_utf8(output)?, fs::read_to_string(directory.path().join("transcript.log"))?]
    {
        assert!(!text.contains("quiet apple"));
        assert!(!text.contains("quiet pear"));
        assert!(text.contains("lk_redacted_MULTILINE"));
    }
    Ok(())
}

#[test]
fn ai_safe_redacts_child_output_and_transcript() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut ai_safe_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--output",
            "transcript.log",
            "--",
            "/bin/sh",
            "-c",
            "printf 'db=postgres://localhost/app\n'; printf 'err=postgres://localhost/app\n' >&2",
        ])?,
        &context,
        &mut ai_safe_output,
    )?;

    let ai_safe_output = String::from_utf8(ai_safe_output)?;
    let transcript = std::fs::read_to_string(directory.path().join("transcript.log"))?;
    assert!(ai_safe_output.contains("lk_redacted_DATABASE_URL"));
    assert!(transcript.contains("lk_redacted_DATABASE_URL"));
    assert!(transcript.contains("[stdout timestamp="));
    assert!(transcript.contains("[stderr timestamp="));
    assert!(!ai_safe_output.contains("postgres://localhost/app"));
    assert!(!transcript.contains("postgres://localhost/app"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(directory.path().join("transcript.log"))?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REDACT'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["scope"], "ai-safe");
    assert_eq!(metadata["pattern_only"], false);
    assert_eq!(metadata["known_value_coverage"], true);
    assert_eq!(metadata["output_destinations"]["transcript"], true);
    assert_eq!(metadata["redacted_secret_names"], json!(["DATABASE_URL"]));
    assert_eq!(metadata["finding_counts"]["known_secret_value"], 2);
    assert!(!metadata.to_string().contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn ai_safe_discards_a_partial_secret_after_the_cap_until_newline() {
    let secret = "SPLIT_SECRET_VALUE";
    let redactions = vec![crate::KnownSecretRedaction {
        value: zeroize::Zeroizing::new(secret.to_owned()),
        marker: "lk_redacted_SPLIT_SECRET".to_owned(),
        secret_name: Some("SPLIT_SECRET".to_owned()),
    }];
    let mut redactor = crate::AiSafeStreamRedactor::new(&redactions);
    let prefix_len = crate::AI_SAFE_PARTIAL_LINE_MAX_BYTES - 5;
    let mut first = vec![b'a'; prefix_len];
    first.extend_from_slice(&secret.as_bytes()[..5]);

    let first_chunks =
        redactor.push(crate::AiSafeRawChunk { stream: crate::AiSafeStream::Stdout, bytes: first });
    let first_text = first_chunks.iter().map(|chunk| chunk.text.as_str()).collect::<String>();
    assert_eq!(first_text, "lk_redacted_BUFFER_LIMIT");

    let mut second = secret.as_bytes()[5..].to_vec();
    second.push(b'\n');
    let mut chunks =
        redactor.push(crate::AiSafeRawChunk { stream: crate::AiSafeStream::Stdout, bytes: second });
    chunks.extend(redactor.finish());
    let text = chunks.iter().map(|chunk| chunk.text.as_str()).collect::<String>();

    assert_eq!(text, "\n");
}

#[test]
fn ai_safe_cap_never_emits_fragments_of_a_known_secret() {
    let secret = "xyzxyz";
    let redactions = vec![crate::KnownSecretRedaction {
        value: zeroize::Zeroizing::new(secret.to_owned()),
        marker: "lk_redacted_TEST".to_owned(),
        secret_name: Some("TEST".to_owned()),
    }];
    for stream in [crate::AiSafeStream::Stdout, crate::AiSafeStream::Stderr] {
        for offset in 1..=secret.len() {
            let mut redactor = crate::AiSafeStreamRedactor::new(&redactions);
            let mut bytes =
                vec![b'a'; crate::AI_SAFE_PARTIAL_LINE_MAX_BYTES - secret.len() - offset];
            bytes.extend_from_slice(secret.as_bytes());
            bytes.extend(std::iter::repeat_n(b'a', offset));
            let mut chunks = redactor.push(crate::AiSafeRawChunk { stream, bytes });
            chunks.extend(redactor.push(crate::AiSafeRawChunk {
                stream,
                bytes: b"more secret material\nclean\n".to_vec(),
            }));
            chunks.extend(redactor.finish());
            let text = chunks.iter().map(|chunk| chunk.text.as_str()).collect::<String>();
            assert_eq!(text, "lk_redacted_BUFFER_LIMIT\nclean\n");
            assert_eq!(chunks.iter().filter(|chunk| chunk.buffer_limit_reached).count(), 1);
        }
    }
}

#[test]
fn ai_safe_cap_handles_utf8_and_secrets_larger_than_the_buffer() {
    let redactions = vec![crate::KnownSecretRedaction {
        value: zeroize::Zeroizing::new("é".repeat(crate::AI_SAFE_PARTIAL_LINE_MAX_BYTES)),
        marker: "lk_redacted_LONG".to_owned(),
        secret_name: Some("LONG".to_owned()),
    }];
    let mut redactor = crate::AiSafeStreamRedactor::new(&redactions);
    let first = redactor.push(crate::AiSafeRawChunk {
        stream: crate::AiSafeStream::Stdout,
        bytes: vec![b'x'; crate::AI_SAFE_PARTIAL_LINE_MAX_BYTES],
    });
    assert_eq!(
        first.iter().map(|chunk| chunk.text.as_str()).collect::<String>(),
        "lk_redacted_BUFFER_LIMIT"
    );
    let continuation = redactor.push(crate::AiSafeRawChunk {
        stream: crate::AiSafeStream::Stdout,
        bytes: vec![0xc3; crate::AI_SAFE_PARTIAL_LINE_MAX_BYTES],
    });
    assert!(continuation.is_empty());
    let mut chunks = redactor.push(crate::AiSafeRawChunk {
        stream: crate::AiSafeStream::Stderr,
        bytes: "other é\n".as_bytes().to_vec(),
    });
    chunks.extend(redactor.push(crate::AiSafeRawChunk {
        stream: crate::AiSafeStream::Stdout,
        bytes: "\nclean é\n".as_bytes().to_vec(),
    }));
    chunks.extend(redactor.finish());
    assert_eq!(
        chunks.iter().map(|chunk| chunk.text.as_str()).collect::<String>(),
        "other é\n\nclean é\n"
    );
}

#[test]
fn ai_safe_finish_after_suppression_emits_only_metadata_and_is_idempotent() {
    let mut redactor = crate::AiSafeStreamRedactor::new(&[]);
    let chunks = redactor.push(crate::AiSafeRawChunk {
        stream: crate::AiSafeStream::Stdout,
        bytes: vec![b'x'; crate::AI_SAFE_PARTIAL_LINE_MAX_BYTES],
    });
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].text, "lk_redacted_BUFFER_LIMIT");
    let final_chunks = redactor.finish();
    assert_eq!(final_chunks.len(), 1);
    assert_eq!(final_chunks[0].text, "");
    assert!(final_chunks[0].unterminated_partial_line);
    assert!(!final_chunks[0].buffer_limit_reached);
    assert!(redactor.finish().is_empty());
}

#[test]
fn ai_safe_partial_line_cap_emits_redacted_buffer_without_values() {
    let token = "sk_test_sampleTokenValue123";
    let mut bytes = format!("token={token} ").into_bytes();
    bytes.extend(std::iter::repeat_n(b'a', crate::AI_SAFE_PARTIAL_LINE_MAX_BYTES));

    let mut redactor = crate::AiSafeStreamRedactor::new(&[]);
    let chunks =
        redactor.push(crate::AiSafeRawChunk { stream: crate::AiSafeStream::Stdout, bytes });
    let text = chunks.iter().map(|chunk| chunk.text.as_str()).collect::<String>();

    assert!(chunks.iter().any(|chunk| chunk.buffer_limit_reached));
    assert_eq!(text, "lk_redacted_BUFFER_LIMIT");
}

#[test]
fn ai_safe_fails_closed_when_locked_unless_pattern_only() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    let (project_id, _) = test_project_id_and_master_key(&context)?;
    context.key_store.delete_master_key(&project_id)?;

    let mut default_output = Vec::new();
    let default_result = run_with_context(
        Cli::try_parse_from(["locket", "ai-safe", "--", "/bin/sh", "-c", "touch spawned-default"])?,
        &context,
        &mut default_output,
    );
    assert_error_contains(default_result, "UnlockRequired");
    assert!(!directory.path().join("spawned-default").exists());

    // The locked-vault refusal must mirror into the degraded-audit log.
    let degraded_log = directory.path().join("audit-degraded.log");
    let degraded_body = std::fs::read_to_string(&degraded_log)?;
    let degraded_lines: Vec<&str> = degraded_body.lines().collect();
    assert_eq!(degraded_lines.len(), 1, "exactly one degraded-audit row expected");
    let row: serde_json::Value = serde_json::from_str(degraded_lines[0])?;
    assert_eq!(row["action"], "REDACT");
    assert_eq!(row["status"], "DENIED_LOCKED");
    assert_eq!(row["failure_reason"], "vault_locked");
    assert_eq!(row["project_id"], project_id);

    let mut pattern_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--pattern-only",
            "--",
            "/bin/sh",
            "-c",
            "printf 'token=sk_test_sampleTokenValue123\n'; touch spawned-pattern",
        ])?,
        &context,
        &mut pattern_output,
    )?;
    let pattern_output = String::from_utf8(pattern_output)?;
    assert!(pattern_output.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(!pattern_output.contains("sk_test_sampleTokenValue123"));
    assert!(directory.path().join("spawned-pattern").exists());
    Ok(())
}

#[test]
fn ai_safe_without_project_uses_project_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    let result = run_with_context(
        Cli::try_parse_from(["locket", "ai-safe", "--", "/bin/sh", "-c", "true"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("ai-safe should fail closed outside a Locket project".into());
    };
    assert_eq!(error.exit_code(), 64);
    let crate::CliError::Typed { kind, message } = error else {
        return Err("ai-safe should return a typed project-not-found error".into());
    };
    assert_eq!(kind, locket_core::LocketError::ProjectNotFound);
    assert_eq!(message, "project not found");
    Ok(())
}

#[test]
fn ai_safe_uses_privacy_config_aliases_but_audits_exact_names()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut ai_safe_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--",
            "/bin/sh",
            "-c",
            "printf 'db=postgres://localhost/app\n'",
        ])?,
        &context,
        &mut ai_safe_output,
    )?;
    let ai_safe_output = String::from_utf8(ai_safe_output)?;
    assert!(ai_safe_output.contains("lk_redacted_secret-"));
    assert!(!ai_safe_output.contains("lk_redacted_DATABASE_URL"));
    assert!(!ai_safe_output.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REDACT'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["redact_names"], true);
    assert_eq!(metadata["redacted_secret_names"], json!(["DATABASE_URL"]));
    assert!(!metadata.to_string().contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn ai_safe_transcript_force_repairs_permissions_and_child_exit_is_forwarded()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let transcript_path = directory.path().join("transcript.log");
    std::fs::write(&transcript_path, "old\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(&transcript_path)?.permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&transcript_path, permissions)?;
    }

    let mut no_force_output = Vec::new();
    let no_force_result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--pattern-only",
            "--output",
            "transcript.log",
            "--",
            "/bin/sh",
            "-c",
            "true",
        ])?,
        &context,
        &mut no_force_output,
    );
    assert!(no_force_result.is_err());

    let mut forced_output = Vec::new();
    let forced_result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--pattern-only",
            "--force",
            "--output",
            "transcript.log",
            "--",
            "/bin/sh",
            "-c",
            "printf 'token=sk_test_sampleTokenValue123'; exit 7",
        ])?,
        &context,
        &mut forced_output,
    );
    let Err(error) = forced_result else {
        return Err("ai-safe should forward child exit status".into());
    };
    assert_eq!(error.exit_code(), 7);
    let forced_output = String::from_utf8(forced_output)?;
    let transcript = std::fs::read_to_string(&transcript_path)?;
    assert!(forced_output.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(transcript.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(!transcript.contains("sk_test_sampleTokenValue123"));
    assert!(!transcript.contains("old"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(&transcript_path)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    Ok(())
}

#[test]
fn ai_safe_redacts_non_ascii_utf8_secret_bytes_without_normalization()
-> Result<(), Box<dyn std::error::Error>> {
    let secret_value = "caf\u{e9}-secret-\u{1f511}";
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, secret_value);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("UNICODE_SECRET");
    crate::set_secret_value(&context, &args, secret_value, "manual", 1_000)?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--",
            "/bin/sh",
            "-c",
            &format!("printf 'val=%s\\n' '{secret_value}'"),
        ])?,
        &context,
        &mut output,
    )?;

    let output_str = String::from_utf8(output)?;
    assert!(
        output_str.contains("lk_redacted_UNICODE_SECRET"),
        "non-ASCII secret must be redacted: {output_str:?}"
    );
    assert!(
        !output_str.contains(secret_value),
        "plaintext must not appear in output: {output_str:?}"
    );
    Ok(())
}
