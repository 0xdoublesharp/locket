use super::{
    EntropyRule, FindingKind, KnownRedaction, RULE_ID_ENV_FILE, RULE_ID_HIGH_ENTROPY,
    RULE_ID_KNOWN_SECRET, RULE_ID_PROVIDER_TOKEN, ScanFinding, Severity,
    is_default_high_entropy_token, is_high_entropy_token, is_provider_token,
    partition_inline_suppressions, redact_text, redact_text_with_known_values, scan_text,
    scan_text_with_entropy_rule, shannon_entropy,
};

#[test]
fn entropy_is_zero_for_empty_or_repeated_tokens() {
    assert!(shannon_entropy("").abs() < f64::EPSILON);
    assert!(shannon_entropy("aaaaaaaaaaaaaaaaaaaa").abs() < f64::EPSILON);
}

#[test]
fn default_rule_rejects_short_tokens() {
    assert!(!is_default_high_entropy_token("aB3$dE5&gH7*"));
}

#[test]
fn default_rule_rejects_whitespace_and_control_characters() {
    assert!(!is_default_high_entropy_token("abcd efgh ijkl mnop qrst uvwx yz12"));
    assert!(!is_default_high_entropy_token("abcd\nefghijklmnopqrstuvwxyz123456"));
}

#[test]
fn default_rule_flags_high_entropy_tokens() {
    assert!(is_default_high_entropy_token("Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF"));
}

#[test]
fn custom_threshold_can_be_lowered() {
    assert!(is_high_entropy_token("abcabcabcabcabcabcab", 20, 1.0));
}

#[test]
fn high_entropy_rule_excludes_public_identifiers() {
    let permissive = EntropyRule { min_len: 8, threshold: 1.0 };
    assert!(!super::is_high_entropy_token_with_rule(
        "550e8400-e29b-41d4-a716-446655440000",
        permissive,
    ));
    assert!(!super::is_high_entropy_token_with_rule(
        "e3b0c44298fc1c149afbf4c8996fb924",
        permissive,
    ));
    assert!(!super::is_high_entropy_token_with_rule("lk_proj_0123456789abcdef", permissive));
}

#[test]
fn scan_text_reports_metadata_without_token_values() {
    let token = "sk_live_sampleTokenValue123";
    let findings = scan_text("config.txt", &format!("prefix\n  {token}\n"));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path_label, "config.txt");
    assert_eq!(findings[0].line, 2);
    assert_eq!(findings[0].column, 3);
    assert_eq!(findings[0].token_length, token.len());
    assert_eq!(findings[0].kind, FindingKind::ProviderTokenPattern);
    assert!(!format!("{:?}", findings[0]).contains(token));
}

#[test]
fn scan_text_flags_default_high_entropy_tokens() {
    let token = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let findings = scan_text("notes.txt", token);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 1);
    assert_eq!(findings[0].column, 1);
    assert_eq!(findings[0].token_length, token.len());
    assert_eq!(findings[0].kind, FindingKind::HighEntropy);
    assert!(!format!("{:?}", findings[0]).contains(token));
}

#[test]
fn scan_text_uses_configured_entropy_rule() {
    let token = "aB3$dE5&gH7*";
    let findings = scan_text_with_entropy_rule(
        "notes.txt",
        token,
        EntropyRule { min_len: 12, threshold: 3.0 },
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].kind, FindingKind::HighEntropy);
    assert!(!format!("{:?}", findings[0]).contains(token));
}

#[test]
fn scan_text_flags_env_file_names_without_reading_values() {
    let findings = scan_text("service/.env.local", "DATABASE_URL=postgres://user:pass@host/db");

    assert!(findings.iter().any(|finding| finding.kind == FindingKind::EnvFileMarker));
    assert!(!format!("{findings:?}").contains("postgres://user:pass@host/db"));
}

#[test]
fn redact_text_replaces_provider_and_high_entropy_tokens() {
    let provider = "github_pat_sampleTokenValue123";
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let result = redact_text(&format!("token={provider}\nrandom={entropy}\n"));

    assert!(!result.text.contains(provider));
    assert!(!result.text.contains(entropy));
    assert!(result.text.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(result.text.contains("lk_redacted_HIGH_ENTROPY"));
    assert_eq!(result.counts.get(&FindingKind::ProviderTokenPattern), Some(&1));
    assert_eq!(result.counts.get(&FindingKind::HighEntropy), Some(&1));
}

#[test]
fn redact_text_replaces_known_values_with_specific_markers() {
    let result = redact_text_with_known_values(
        "db=postgres://localhost/app token=sk_test_sampleTokenValue123\n",
        &[KnownRedaction { value: "postgres://localhost/app", marker: "lk_redacted_DATABASE_URL" }],
    );

    assert!(!result.text.contains("postgres://localhost/app"));
    assert!(result.text.contains("db=lk_redacted_DATABASE_URL"));
    assert!(result.text.contains("token=lk_redacted_PROVIDER_TOKEN"));
    assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
    assert_eq!(result.counts.get(&FindingKind::ProviderTokenPattern), Some(&1));
}

#[test]
fn known_value_redaction_wins_over_pattern_redaction() {
    let provider = "sk_test_sampleTokenValue123";
    let result = redact_text_with_known_values(
        &format!("token={provider}\n"),
        &[KnownRedaction { value: provider, marker: "lk_redacted_OPENAI_API_KEY" }],
    );

    assert_eq!(result.text, "token=lk_redacted_OPENAI_API_KEY\n");
    assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
    assert_eq!(result.counts.get(&FindingKind::ProviderTokenPattern), None);
}

#[test]
fn longer_known_value_wins_when_known_values_start_together() {
    let result = redact_text_with_known_values(
        "token=abcdef",
        &[
            KnownRedaction { value: "abc", marker: "lk_redacted_SHORT" },
            KnownRedaction { value: "abcdef", marker: "lk_redacted_LONG" },
        ],
    );

    assert_eq!(result.text, "token=lk_redacted_LONG");
    assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
}

#[test]
fn empty_known_values_are_ignored() {
    let result = redact_text_with_known_values(
        "plain text",
        &[KnownRedaction { value: "", marker: "lk_redacted_EMPTY" }],
    );

    assert_eq!(result.text, "plain text");
    assert!(result.counts.is_empty());
}

#[test]
fn overlapping_known_values_redact_the_entire_union() {
    let result = redact_text_with_known_values(
        "before abcdefgh after",
        &[
            KnownRedaction { value: "abcd", marker: "[A]" },
            KnownRedaction { value: "cdef", marker: "[B]" },
            KnownRedaction { value: "efgh", marker: "[C]" },
        ],
    );
    assert_eq!(result.text, "before [A] after");
    assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
}

#[test]
fn self_overlapping_known_values_redact_every_matched_character() {
    for (text, value) in [("ababa", "aba"), ("ééé", "éé"), ("aaaaa", "aaa")] {
        let result =
            redact_text_with_known_values(text, &[KnownRedaction { value, marker: "[X]" }]);
        assert_eq!(result.text, "[X]");
        assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
    }
}

#[test]
fn known_prefix_does_not_expose_the_rest_of_a_provider_token() {
    let result = redact_text_with_known_values(
        "key=sk_live_abc123def456!",
        &[KnownRedaction { value: "sk_live_", marker: "[KEY]" }],
    );
    assert_eq!(result.text, "key=[KEY]");
    assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
}

#[test]
fn known_value_inside_provider_token_keeps_its_marker_and_covers_both_spans() {
    let result = redact_text_with_known_values(
        "key=sk_live_abc123 trailing secret end",
        &[KnownRedaction { value: "abc123 trailing secret", marker: "[KEY]" }],
    );
    assert_eq!(result.text, "key=[KEY] end");
    assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&1));
}

#[test]
fn adjacent_known_values_remain_separate_replacements() {
    let result = redact_text_with_known_values(
        "abcdef",
        &[
            KnownRedaction { value: "abc", marker: "[A]" },
            KnownRedaction { value: "def", marker: "[B]" },
        ],
    );
    assert_eq!(result.text, "[A][B]");
    assert_eq!(result.counts.get(&FindingKind::KnownSecretValue), Some(&2));
}

#[test]
fn scan_text_reports_candidate_column_after_boundaries() {
    let token = "sk_live_sampleTokenValue123";
    let findings = scan_text("config.json", &format!("  api_key=\"{token}\""));

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 1);
    assert_eq!(findings[0].column, 12);
    assert_eq!(findings[0].token_length, token.len());
    assert_eq!(findings[0].kind, FindingKind::ProviderTokenPattern);
}

#[test]
fn scan_columns_count_unicode_characters_across_delimiters_and_controls() {
    for (text, positions) in [
        (":ghp_a,ghp_b", vec![(1, 2), (1, 8)]),
        ("éé=ghp_a;🦀:ghp_b", vec![(1, 4), (1, 12)]),
        ("x\n\tghp_a\0ghp_b", vec![(2, 2), (2, 8)]),
        ("\n{}[ghp_a]\r\n'ghp_b'", vec![(2, 4), (3, 2)]),
    ] {
        let findings = scan_text("positions.txt", text);
        assert_eq!(findings.len(), positions.len());
        for (finding, (line, column)) in findings.iter().zip(positions) {
            assert_eq!((finding.line, finding.column), (line, column), "{text:?}");
            assert_eq!(finding.token_length, 5);
            assert_eq!(finding.kind, FindingKind::ProviderTokenPattern);
        }
        let redacted = redact_text(text);
        assert_eq!(
            redacted.text,
            text.replace("ghp_a", "lk_redacted_PROVIDER_TOKEN")
                .replace("ghp_b", "lk_redacted_PROVIDER_TOKEN")
        );
    }
}

#[test]
fn dense_line_preserves_every_finding_and_redaction() {
    let record = "é=ghp_example,";
    let text = record.repeat(512);
    let findings = scan_text("dense.txt", &text);
    assert_eq!(findings.len(), 512);
    for (index, finding) in findings.iter().enumerate() {
        assert_eq!(finding.line, 1);
        assert_eq!(finding.column, index * record.chars().count() + 3);
        assert_eq!(finding.token_length, "ghp_example".len());
    }
    let redacted = redact_text(&text);
    assert_eq!(redacted.text, "é=lk_redacted_PROVIDER_TOKEN,".repeat(512));
    assert_eq!(redacted.counts.get(&FindingKind::ProviderTokenPattern), Some(&512));
}

#[test]
fn inline_suppression_removes_high_entropy_findings_on_same_line() {
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let text = format!("token={entropy} # locket-allow: known random fixture\n");
    let findings = scan_text("notes.txt", &text);

    let result = partition_inline_suppressions(&text, findings);

    assert_eq!(result.kept.len(), 0);
    assert_eq!(result.suppressed.len(), 1);
    let suppressed = &result.suppressed[0];
    assert_eq!(suppressed.kind, FindingKind::HighEntropy);
    assert_eq!(suppressed.rule_id, RULE_ID_HIGH_ENTROPY);
    assert_eq!(suppressed.path_label, "notes.txt");
    assert_eq!(suppressed.line, 1);
    assert_eq!(suppressed.reason, "known random fixture");
    assert!(!format!("{suppressed:?}").contains(entropy));
}

#[test]
fn inline_suppression_supports_next_line_marker() {
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let text = format!("// locket-allow-next-line: fixture\n{entropy}\n");
    let findings = scan_text("notes.txt", &text);

    let result = partition_inline_suppressions(&text, findings);

    assert_eq!(result.kept.len(), 0);
    assert_eq!(result.suppressed.len(), 1);
    assert_eq!(result.suppressed[0].kind, FindingKind::HighEntropy);
    assert_eq!(result.suppressed[0].line, 2);
    assert_eq!(result.suppressed[0].reason, "fixture");
}

#[test]
fn next_line_marker_skips_blank_lines_to_next_non_empty_line() {
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let text = format!("// locket-allow-next-line\n\n   \n{entropy}\n");
    let findings = scan_text("notes.txt", &text);

    let result = partition_inline_suppressions(&text, findings);

    assert_eq!(result.kept.len(), 0);
    assert_eq!(result.suppressed.len(), 1);
    assert_eq!(result.suppressed[0].line, 4);
    assert_eq!(result.suppressed[0].reason, "");
}

#[test]
fn inline_suppression_does_not_silence_known_secret_matches() {
    let path = "leak.txt";
    let suppressed_finding = ScanFinding {
        path_label: path.to_owned(),
        line: 1,
        column: 1,
        token_length: 16,
        kind: FindingKind::KnownSecretValue,
    };
    let text = "secret-value # locket-allow: hide it\n";

    let result = partition_inline_suppressions(text, vec![suppressed_finding.clone()]);

    assert_eq!(result.kept, vec![suppressed_finding]);
    assert_eq!(result.suppressed.len(), 0);
}

#[test]
fn inline_suppression_does_not_silence_provider_token_or_env_file_findings() {
    let provider_token = "sk_live_sampleTokenValue123";
    let text = format!("token={provider_token} # locket-allow: nope\n");
    let findings = scan_text(".env.local", &text);

    let result = partition_inline_suppressions(&text, findings);

    assert_eq!(result.suppressed.len(), 0);
    assert!(result.kept.iter().any(|finding| finding.kind == FindingKind::ProviderTokenPattern));
    assert!(result.kept.iter().any(|finding| finding.kind == FindingKind::EnvFileMarker));
}

#[test]
fn next_line_marker_on_last_line_is_a_noop() {
    let text = "// locket-allow-next-line: nothing follows\n";
    let findings = scan_text("notes.txt", text);

    let result = partition_inline_suppressions(text, findings);

    assert_eq!(result.kept.len(), 0);
    assert_eq!(result.suppressed.len(), 0);
}

#[test]
fn line_marker_does_not_match_next_line_marker_substring() {
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let text = format!("token={entropy} # locket-allow-next-line: previous-line note\n");
    let findings = scan_text("notes.txt", &text);

    let result = partition_inline_suppressions(&text, findings);

    assert_eq!(result.kept.len(), 1);
    assert_eq!(result.kept[0].kind, FindingKind::HighEntropy);
    assert_eq!(result.suppressed.len(), 0);
}

#[test]
fn finding_kind_rule_ids_are_stable() {
    assert_eq!(FindingKind::HighEntropy.rule_id(), RULE_ID_HIGH_ENTROPY);
    assert_eq!(FindingKind::ProviderTokenPattern.rule_id(), RULE_ID_PROVIDER_TOKEN);
    assert_eq!(FindingKind::EnvFileMarker.rule_id(), RULE_ID_ENV_FILE);
    assert_eq!(FindingKind::KnownSecretValue.rule_id(), RULE_ID_KNOWN_SECRET);
}

#[test]
fn finding_kind_default_severities_match_spec() {
    assert_eq!(FindingKind::KnownSecretValue.default_severity(), Severity::Blocking);
    assert_eq!(FindingKind::HighEntropy.default_severity(), Severity::Warning);
    assert_eq!(FindingKind::ProviderTokenPattern.default_severity(), Severity::Warning);
    assert_eq!(FindingKind::EnvFileMarker.default_severity(), Severity::Warning);
}

#[test]
fn severity_as_str_produces_stable_labels() {
    assert_eq!(Severity::Warning.as_str(), "warning");
    assert_eq!(Severity::Blocking.as_str(), "blocking");
    assert!(Severity::Warning < Severity::Blocking);
}

#[test]
fn only_high_entropy_allows_inline_suppression() {
    assert!(FindingKind::HighEntropy.allows_inline_suppression());
    assert!(!FindingKind::ProviderTokenPattern.allows_inline_suppression());
    assert!(!FindingKind::EnvFileMarker.allows_inline_suppression());
    assert!(!FindingKind::KnownSecretValue.allows_inline_suppression());
}

#[test]
fn is_provider_token_matches_all_builtin_prefixes() {
    assert!(is_provider_token("sk_live_abc123def456"));
    assert!(is_provider_token("sk_test_abc123def456"));
    assert!(is_provider_token("ghp_abc123def456"));
    assert!(is_provider_token("github_pat_abc123def456"));
    assert!(is_provider_token("xoxb-abc123def456"));
}

#[test]
fn is_provider_token_rejects_prefix_only_tokens() {
    assert!(!is_provider_token("sk_live_"));
    assert!(!is_provider_token("sk_test_"));
    assert!(!is_provider_token("ghp_"));
    assert!(!is_provider_token("xoxb-"));
}

#[test]
fn is_provider_token_rejects_non_matching_tokens() {
    assert!(!is_provider_token("AKIA1234567890ABCDEF"));
    assert!(!is_provider_token("eyJhbGciOiJIUzI1NiJ9"));
    assert!(!is_provider_token(""));
}

#[test]
fn scan_text_identifies_env_file_by_filename_not_path() {
    let findings_env = scan_text("project/.env", "plain text");
    assert!(findings_env.iter().any(|f| f.kind == FindingKind::EnvFileMarker));

    let findings_env_local = scan_text("src/.env.local", "plain text");
    assert!(findings_env_local.iter().any(|f| f.kind == FindingKind::EnvFileMarker));

    let findings_env_prod = scan_text("config/.env.production", "plain text");
    assert!(findings_env_prod.iter().any(|f| f.kind == FindingKind::EnvFileMarker));

    let findings_regular = scan_text("src/config.env", "plain text");
    assert!(!findings_regular.iter().any(|f| f.kind == FindingKind::EnvFileMarker));
}

#[test]
#[allow(clippy::panic)]
fn scan_text_with_multiple_findings_preserves_line_numbers() {
    let provider = "sk_live_sampleTokenValue123";
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let text = format!("line1\n{provider}\nline3\n{entropy}\n");
    let findings = scan_text("notes.txt", &text);

    let Some(provider_finding) =
        findings.iter().find(|f| f.kind == FindingKind::ProviderTokenPattern)
    else {
        panic!("provider token finding expected");
    };
    let Some(entropy_finding) = findings.iter().find(|f| f.kind == FindingKind::HighEntropy) else {
        panic!("high entropy finding expected");
    };
    assert_eq!(provider_finding.line, 2);
    assert_eq!(entropy_finding.line, 4);
}

#[test]
fn scan_text_returns_empty_for_clean_text() {
    let findings = scan_text("clean.rs", "let x = 42;\nlet name = \"hello world\";\n");
    assert_eq!(findings.len(), 0);
}

#[test]
fn shannon_entropy_increases_with_character_diversity() {
    let low = shannon_entropy("aaaaaaaaaaaaaaaaaaaaaa");
    let medium = shannon_entropy("ababababababababababab");
    let high = shannon_entropy("Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF");
    assert!(low < medium);
    assert!(medium < high);
}

#[test]
fn suppression_result_default_is_empty() {
    use super::SuppressionResult;
    let result = SuppressionResult::default();
    assert_eq!(result.kept.len(), 0);
    assert_eq!(result.suppressed.len(), 0);
}

#[test]
fn strict_partition_suppresses_high_entropy_finding_via_locket_suppress_directive()
-> Result<(), Box<dyn std::error::Error>> {
    use super::partition_inline_suppressions_strict;
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let text = format!("token={entropy} # locket-suppress: known random fixture\n");
    let findings = scan_text("notes.txt", &text);
    assert_eq!(findings.len(), 1, "scan must produce one high-entropy finding before suppression");

    let result = partition_inline_suppressions_strict(&text, findings)?;

    assert_eq!(result.kept.len(), 0);
    assert_eq!(result.suppressed.len(), 1);
    assert_eq!(result.suppressed[0].kind, FindingKind::HighEntropy);
    assert_eq!(result.suppressed[0].reason, "known random fixture");
    assert!(!format!("{:?}", result.suppressed[0]).contains(entropy));
    Ok(())
}

#[test]
fn strict_partition_block_directive_suppresses_inner_findings()
-> Result<(), Box<dyn std::error::Error>> {
    use super::partition_inline_suppressions_strict;
    let entropy = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    let text = format!(
        "// locket-suppress-block-start: vendored fixtures section\n\
         {entropy}\n\
         // locket-suppress-block-end\n",
    );
    let findings = scan_text("notes.txt", &text);

    let result = partition_inline_suppressions_strict(&text, findings)?;

    assert_eq!(result.kept.len(), 0);
    assert_eq!(result.suppressed.len(), 1);
    assert_eq!(result.suppressed[0].reason, "vendored fixtures section");
    Ok(())
}

#[test]
fn strict_partition_propagates_reason_validation_errors() -> Result<(), Box<dyn std::error::Error>>
{
    use super::{SuppressionParseError, partition_inline_suppressions_strict};
    let text = "value # locket-suppress: hi\n";
    let result = partition_inline_suppressions_strict(text, Vec::new());
    let Err(error) = result else {
        return Err("must fail".into());
    };
    assert!(matches!(error, SuppressionParseError::ReasonTooShort { line: 1, .. }));
    Ok(())
}

#[test]
fn streaming_scan_and_redaction_preserve_punctuation_and_overlaps() {
    let text = "🦀=[\"ghp_abcd\",'`sk_test_xyz`']\r\nkey=ghp_123";
    let findings = scan_text("quoted.txt", text);
    let positions: Vec<_> = findings
        .iter()
        .map(|finding| (finding.line, finding.column, finding.token_length, finding.kind.rule_id()))
        .collect();
    assert_eq!(
        positions,
        [
            (1, 5, 8, RULE_ID_PROVIDER_TOKEN),
            (1, 17, 11, RULE_ID_PROVIDER_TOKEN),
            (2, 5, 7, RULE_ID_PROVIDER_TOKEN)
        ]
    );
    let redacted = redact_text_with_known_values(
        text,
        &[KnownRedaction { value: "abcd\",", marker: "[KNOWN]" }],
    );
    assert_eq!(
        redacted.text,
        "🦀=[\"[KNOWN]'`lk_redacted_PROVIDER_TOKEN`']\r\nkey=lk_redacted_PROVIDER_TOKEN"
    );
    assert_eq!(redacted.counts.get(&FindingKind::KnownSecretValue), Some(&1));
    assert_eq!(redacted.counts.get(&FindingKind::ProviderTokenPattern), Some(&2));
}

#[test]
fn suppression_rejects_nested_blocks_at_the_original_opening_line() {
    let source = concat!(
        "// header\n",
        "// locket-suppress-block-start: generated fixture\n",
        "// locket-suppress-block-start: nested fixture\n",
        "// locket-suppress-block-end\n",
    );
    assert!(matches!(
        super::parse_suppression_map(source),
        Err(super::SuppressionParseError::UnclosedBlock { line: 2 })
    ));
}

#[test]
fn overlapping_known_value_takes_priority_over_entropy() {
    let token = "aB3dE6gH9jK2mN5pQ8sT1vW4";
    let known = KnownRedaction { value: "mN5", marker: "[protected]" };
    let result = redact_text_with_known_values(token, &[known]);
    assert_eq!(result.text, "[protected]");
    assert_eq!(result.counts, [(FindingKind::KnownSecretValue, 1)].into());
}
