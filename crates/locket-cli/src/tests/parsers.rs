#[allow(unused_imports)]
use super::*;
use clap::CommandFactory;

#[test]
fn env_import_parser_handles_exports_quotes_comments_and_invalid_lines() {
    let entries = crate::parse_env_import(
        "# ignored\n\
         export DATABASE_URL='postgres://localhost/app'\n\
         OPENAI_API_KEY=\"sk_test_sample\"\n\
         INVALID-NAME=value\n\
         MISSING_EQUALS\n\
         NULL_BYTE=bad\0value\n\
         MULTILINE=\"first\n\
         second\"\n",
    );

    assert_eq!(entries.len(), 7);
    let first = match &entries[0] {
        crate::EnvImportEntry::Secret { key, value } => Some((key.as_str(), value.as_str())),
        crate::EnvImportEntry::Invalid => None,
    };
    let second = match &entries[1] {
        crate::EnvImportEntry::Secret { key, value } => Some((key.as_str(), value.as_str())),
        crate::EnvImportEntry::Invalid => None,
    };
    assert_eq!(first, Some(("DATABASE_URL", "postgres://localhost/app")));
    assert_eq!(second, Some(("OPENAI_API_KEY", "sk_test_sample")));
    assert!(matches!(&entries[2], crate::EnvImportEntry::Invalid));
    assert!(matches!(&entries[3], crate::EnvImportEntry::Invalid));
    assert!(matches!(&entries[4], crate::EnvImportEntry::Invalid));
    assert!(matches!(&entries[5], crate::EnvImportEntry::Invalid));
    assert!(matches!(&entries[6], crate::EnvImportEntry::Invalid));
}

#[test]
fn root_hash_parser_accepts_prefixed_mixed_case_hex_and_rejects_bad_input()
-> Result<(), Box<dyn std::error::Error>> {
    let parsed = crate::parse_root_hash(&format!("0x{}", "Aa".repeat(32)))?;

    assert_eq!(parsed, [0xaa; 32]);
    assert_error_contains(crate::parse_root_hash("abcd").map(|_| ()), "64 hex characters");
    assert_error_contains(
        crate::parse_root_hash(&format!("{}0g", "00".repeat(31))).map(|_| ()),
        "hex encoded",
    );
    Ok(())
}

#[test]
fn grace_ttl_parser_handles_absent_values_caps_and_timestamp_overflow()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(crate::grace_until_from_args(None, 1_000)?, None);
    assert_eq!(crate::grace_until_from_args(Some("24h"), 1_000)?, Some(86_400_000_001_000),);
    for value in ["0s", "1h30m", "1.5h", "1H", " 1h", "1h "] {
        assert_error_contains(
            crate::grace_until_from_args(Some(value), 1_000).map(|_| ()),
            "invalid grace TTL duration",
        );
    }
    assert_error_contains(crate::grace_until_from_args(Some("8d"), 1_000).map(|_| ()), "7d cap");
    assert!(matches!(
        crate::grace_until_from_args(Some("1s"), i64::MAX - 10),
        Err(crate::CliError::Time)
    ));
    Ok(())
}

#[test]
fn secret_value_reader_preserves_piped_values_and_rejects_invalid_input()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        crate::read_secret_value_from_reader(b"postgres://localhost/app\n".as_slice())?.as_str(),
        "postgres://localhost/app"
    );
    assert_eq!(
        crate::read_secret_value_from_reader(b"postgres://localhost/app\r\n".as_slice())?.as_str(),
        "postgres://localhost/app"
    );

    assert_error_contains(
        crate::read_secret_value_from_reader(b"line1\nline2".as_slice()).map(|_| ()),
        "newlines",
    );
    assert_error_contains(
        crate::read_secret_value_from_reader(b"line1\nline2\n".as_slice()).map(|_| ()),
        "newlines",
    );
    assert_error_contains(
        crate::read_secret_value_from_reader(b"line1\nline2\n\n".as_slice()).map(|_| ()),
        "newlines",
    );

    assert_error_contains(
        crate::read_secret_value_from_reader(b"".as_slice()).map(|_| ()),
        "secret value cannot be empty",
    );
    assert_error_contains(
        crate::read_secret_value_from_reader(b"\n".as_slice()).map(|_| ()),
        "secret value cannot be empty",
    );
    assert_error_contains(
        crate::read_secret_value_from_reader(b"one\0two".as_slice()).map(|_| ()),
        "NUL bytes",
    );
    assert_error_contains(
        crate::read_secret_value_from_reader(&[0xff][..]).map(|_| ()),
        "valid UTF-8",
    );
    Ok(())
}

#[test]
fn parses_bare_status() {
    let cli = Cli::try_parse_from(["locket"]);
    assert!(cli.is_ok());
}

#[test]
#[allow(clippy::too_many_lines)]
fn parses_core_secret_commands() {
    for args in [
        ["locket", "init", "--name", "app"].as_slice(),
        &["locket", "init", "--recovery-code", "--name", "app"],
        &["locket", "set", "DATABASE_URL", "--source", "user-local"],
        &["locket", "import", ".env", "--source", "user-local"],
        &["locket", "get", "DATABASE_URL", "--source", "user-local"],
        &["locket", "get", "DATABASE_URL", "--copy"],
        &["locket", "get", "DATABASE_URL", "--reveal", "--force"],
        &["locket", "rm", "DATABASE_URL"],
        &["locket", "purge", "DATABASE_URL", "--all-versions"],
        &["locket", "rotate", "DATABASE_URL", "--grace-ttl", "24h"],
        &["locket", "lock"],
        &["locket", "unlock", "--verify-user"],
        &["locket", "meta", "DATABASE_URL", "--owner", "platform", "--required"],
        &["locket", "history", "DATABASE_URL"],
        &["locket", "diff", "dev", "staging"],
        &[
            "locket",
            "copy",
            "DATABASE_URL",
            "--from",
            "dev",
            "--to",
            "staging",
            "--from-source",
            "user-local",
            "--to-source",
            "machine-local",
        ],
        &["locket", "audit", "verify"],
        &["locket", "recover", "--force"],
        &["locket", "recovery", "rotate"],
        &["locket", "doctor"],
        &["locket", "debug", "bundle", "--redacted"],
        &["locket", "debug", "bundle", "--redacted", "--output", "bundle.json"],
        &["locket", "exec", "--secret", "DATABASE_URL", "--", "/bin/sh", "-c", "true"],
        &["locket", "run", "dev"],
        &["locket", "run", "npm", "dev"],
        &["locket", "run", "npm", "run", "dev", "--", "--watch"],
        &["locket", "run", "cargo", "test"],
        &["locket", "run", "make", "dev"],
        &["locket", "env", "inspect", "--policy", "dev"],
        &["locket", "env", "docker", "--policy", "dev", "--", "docker", "run", "alpine"],
        &[
            "locket",
            "compose",
            "run",
            "--policy",
            "dev",
            "--project-directory",
            ".",
            "--profile",
            "api",
            "--",
            "docker",
            "compose",
            "up",
        ],
        &["locket", "config", "list"],
        &["locket", "config", "get", "privacy.redact_names"],
        &["locket", "config", "set", "privacy.redact_names", "true"],
        &["locket", "config", "unset", "privacy.redact_names"],
        &["locket", "passkey", "register", "--label", "work-laptop"],
        &["locket", "passkey", "list", "--all"],
        &["locket", "passkey", "remove", "work-laptop"],
        &["locket", "passkey", "unlock"],
        &["locket", "passkey", "unlock", "work-laptop"],
        &["locket", "device", "init"],
        &["locket", "device", "init", "--force"],
        &["locket", "device", "pubkey"],
        &["locket", "device", "add", "work-laptop", "--device", "lkdev2_abc"],
        &["locket", "device", "list", "--all"],
        &["locket", "device", "remove", "work-laptop", "--force"],
        &["locket", "client", "create", "ci", "--action", "run-policy", "--policy", "dev"],
        &[
            "locket", "client", "add", "ci", "--pubkey", "00", "--action", "redact", "--policy",
            "dev",
        ],
        &["locket", "client", "list", "--all"],
        &["locket", "client", "revoke", "ci"],
        &[
            "locket",
            "export",
            "--sealed",
            "--recipient",
            "lkdev2_abc",
            "--profile",
            "dev",
            "--include-audit",
            "--output",
            "bundle.locket-bundle",
        ],
        &["locket", "import-bundle", "bundle.locket-bundle", "--accept-local"],
        &["locket", "bundle", "verify", "bundle.locket-bundle"],
        &["locket", "new", "--from-template", "basic"],
        &["locket", "bootstrap"],
        &["locket", "setup"],
        &["locket", "setup", "status"],
        &["locket", "setup", "agent"],
        &["locket", "setup", "share"],
        &["locket", "completion", "bash"],
    ] {
        assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
    }
}

#[test]
fn help_mentions_path_scoped_env_sets() {
    let mut command = Cli::command();
    let help = command.render_long_help().to_string();

    assert!(help.contains("[paths.\"relative/path\"]"));
    assert!(help.contains("[commands.<policy>]"));
}

#[test]
fn help_groups_workflows_and_shows_quick_start() {
    let help = Cli::command().render_long_help().to_string();
    for heading in [
        "Start & Vaults",
        "Secrets",
        "Commands & Execution",
        "AI Agents & Safety",
        "Environments, Team & Recovery",
    ] {
        assert!(help.lines().any(|line| line.trim() == heading), "missing {heading}");
    }
    let mut lines = help.lines().skip_while(|line| line.trim() != "Quick Start").skip(1);
    for command in
        ["locket shared init", "locket init", "locket status --json", "locket policy detect"]
    {
        assert!(lines.next().is_some_and(|line| line.trim().starts_with(command)), "{help}");
    }
}

#[test]
#[allow(clippy::expect_used)]
fn execution_help_mentions_path_scope_merge_points() {
    let mut command = Cli::command();
    let run_help =
        command.find_subcommand_mut("run").expect("run subcommand").render_long_help().to_string();
    assert!(run_help.contains("locket run npm dev"), "{run_help}");
    assert!(run_help.contains("runner adapter"), "{run_help}");
    assert!(run_help.contains("path scope"), "{run_help}");
    assert!(run_help.contains("Secret ACLs"), "{run_help}");

    let mut command = Cli::command();
    let env_help = command.find_subcommand_mut("env").expect("env subcommand");
    let inspect_help = env_help
        .find_subcommand_mut("inspect")
        .expect("env inspect subcommand")
        .render_long_help()
        .to_string();
    assert!(inspect_help.contains("metadata-only"), "{inspect_help}");
    assert!(inspect_help.contains("path_scope_profile"), "{inspect_help}");

    let mut command = Cli::command();
    let env_help = command.find_subcommand_mut("env").expect("env subcommand");
    let docker_help = env_help
        .find_subcommand_mut("docker")
        .expect("env docker subcommand")
        .render_long_help()
        .to_string();
    assert!(docker_help.contains("[paths.\"...\"]"), "{docker_help}");

    let mut command = Cli::command();
    let compose_help = command.find_subcommand_mut("compose").expect("compose subcommand");
    let compose_run_help = compose_help
        .find_subcommand_mut("run")
        .expect("compose run subcommand")
        .render_long_help()
        .to_string();
    assert!(compose_run_help.contains("Compose interpolation"), "{compose_run_help}");

    let mut command = Cli::command();
    let policy_help = command
        .find_subcommand_mut("policy")
        .expect("policy subcommand")
        .render_long_help()
        .to_string();
    assert!(policy_help.contains("[paths.\"relative/path\"]"), "{policy_help}");
}

#[test]
fn get_force_requires_reveal() {
    assert!(Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--force"]).is_err());
}

#[test]
fn clipboard_command_selection_uses_first_available_candidate() {
    static COMMANDS: &[crate::ClipboardCommand] = &[
        crate::ClipboardCommand { program: "missing", args: &[] },
        crate::ClipboardCommand { program: "present", args: &["--clipboard"] },
    ];

    let selected = crate::select_clipboard_command(COMMANDS, |program| program == "present");

    assert_eq!(selected.map(|command| command.program), Some("present"));
    assert_eq!(selected.map(|command| command.args), Some(["--clipboard"].as_slice()));
}

#[test]
fn clipboard_clear_limit_classifies_environment() {
    static WL_COPY: crate::ClipboardCommand =
        crate::ClipboardCommand { program: "wl-copy", args: &[] };
    static XCLIP: crate::ClipboardCommand =
        crate::ClipboardCommand { program: "xclip", args: &["-selection", "clipboard"] };
    static PBCOPY: crate::ClipboardCommand =
        crate::ClipboardCommand { program: "pbcopy", args: &[] };

    // No clipboard command at all.
    assert_eq!(crate::clipboard_clear_limit(None, None), crate::ClipboardClearLimit::DirectCli);

    // wl-copy is selected -> Wayland-limited regardless of session var.
    assert_eq!(
        crate::clipboard_clear_limit(Some(&WL_COPY), None),
        crate::ClipboardClearLimit::WaylandSourceProcessLimited
    );

    // X11 tool but XDG_SESSION_TYPE=wayland (XWayland) -> still Wayland-limited.
    assert_eq!(
        crate::clipboard_clear_limit(Some(&XCLIP), Some("wayland")),
        crate::ClipboardClearLimit::WaylandSourceProcessLimited
    );

    // XDG_SESSION_TYPE=Wayland (mixed case) is still Wayland-limited.
    assert_eq!(
        crate::clipboard_clear_limit(Some(&XCLIP), Some("Wayland")),
        crate::ClipboardClearLimit::WaylandSourceProcessLimited
    );

    // X11 tool on x11 session can read back and clear if unchanged.
    assert_eq!(
        crate::clipboard_clear_limit(Some(&XCLIP), Some("x11")),
        crate::ClipboardClearLimit::Supported
    );

    // pbcopy on macOS can read back through pbpaste and clear if unchanged.
    assert_eq!(
        crate::clipboard_clear_limit(Some(&PBCOPY), None),
        crate::ClipboardClearLimit::Supported
    );
}

#[test]
fn clipboard_clear_limit_audit_reasons_are_distinct_and_stable() {
    assert_eq!(crate::ClipboardClearLimit::Supported.audit_reason(), None);
    assert_eq!(crate::ClipboardClearLimit::Supported.warning_text(), None);
    assert_eq!(
        crate::ClipboardClearLimit::DirectCli.audit_reason(),
        Some("direct_cli_no_background_clear")
    );
    assert_eq!(
        crate::ClipboardClearLimit::WaylandSourceProcessLimited.audit_reason(),
        Some("wayland_source_process_limited")
    );
    assert_ne!(
        crate::ClipboardClearLimit::DirectCli.warning_text(),
        crate::ClipboardClearLimit::WaylandSourceProcessLimited.warning_text(),
    );
    assert!(
        crate::ClipboardClearLimit::WaylandSourceProcessLimited
            .warning_text()
            .is_some_and(|warning| warning.contains("Wayland"))
    );
}

#[test]
fn clipboard_copy_reports_unavailable_without_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    static COMMANDS: &[crate::ClipboardCommand] = &[];

    let result =
        crate::copy_secret_to_clipboard_with("postgres://localhost/app", COMMANDS, |_| false);
    let error = result.err().ok_or("expected unavailable clipboard command")?;

    assert_eq!(error, "clipboard command unavailable");
    assert!(!error.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn memory_clipboard_copies_and_clears_only_matching_value() -> Result<(), Box<dyn std::error::Error>>
{
    let mut clipboard = crate::MemoryClipboard::clearing_supported();

    crate::ClipboardBackend::copy(&mut clipboard, "postgres://localhost/app")?;
    assert_eq!(clipboard.value(), Some("postgres://localhost/app"));
    assert_eq!(
        crate::ClipboardBackend::clear_if_current(&mut clipboard, "postgres://localhost/app"),
        crate::ClipboardClearResult::Cleared
    );
    assert_eq!(clipboard.value(), None);
    Ok(())
}

#[test]
fn memory_clipboard_keeps_user_replacement_after_ttl() -> Result<(), Box<dyn std::error::Error>> {
    let mut clipboard = crate::MemoryClipboard::clearing_supported();

    crate::ClipboardBackend::copy(&mut clipboard, "postgres://localhost/app")?;
    crate::ClipboardBackend::copy(&mut clipboard, "user replacement")?;

    assert_eq!(
        crate::ClipboardBackend::clear_if_current(&mut clipboard, "postgres://localhost/app"),
        crate::ClipboardClearResult::Changed
    );
    assert_eq!(clipboard.value(), Some("user replacement"));
    Ok(())
}

#[test]
fn memory_clipboard_reports_unsupported_clear_without_dropping_value()
-> Result<(), Box<dyn std::error::Error>> {
    let mut clipboard = crate::MemoryClipboard::clearing_unsupported();

    crate::ClipboardBackend::copy(&mut clipboard, "postgres://localhost/app")?;

    assert_eq!(
        crate::ClipboardBackend::clear_if_current(&mut clipboard, "postgres://localhost/app"),
        crate::ClipboardClearResult::Unsupported
    );
    assert_eq!(clipboard.value(), Some("postgres://localhost/app"));
    Ok(())
}

#[test]
fn memory_clipboard_schedules_ttl_clear_only_for_original_value()
-> Result<(), Box<dyn std::error::Error>> {
    let mut clipboard = crate::MemoryClipboard::clearing_supported();

    crate::ClipboardBackend::copy(&mut clipboard, "postgres://localhost/app")?;
    let status = crate::ClipboardBackend::schedule_clear_after_ttl(
        &mut clipboard,
        "postgres://localhost/app",
        60,
    )?;

    assert_eq!(status, crate::ClipboardCopyStatus::clearing_scheduled());
    assert_eq!(clipboard.value(), None);
    Ok(())
}

#[test]
fn cli_handoff_helpers_quote_commands_and_avoid_heredoc_delimiter_collisions() {
    use crate::support::handoff::{heredoc_command, shell_quote, shell_words_command};

    assert_eq!(shell_quote("lkdev2_abc.DEF-123:/@%+"), "lkdev2_abc.DEF-123:/@%+");
    assert_eq!(shell_quote(""), "''");
    assert_eq!(shell_quote("Build Agent 'West'"), "'Build Agent '\\''West'\\'''");

    assert_eq!(
        shell_words_command([
            "locket",
            "agent",
            "invite",
            "create",
            "Build Agent 'West'",
            "--profile",
            "dev",
        ]),
        "locket agent invite create 'Build Agent '\\''West'\\''' --profile dev"
    );

    assert_eq!(
        heredoc_command(
            "locket agent invite accept -",
            "header\nLOCKET_INVITE\nLOCKET_INVITE_1\npayload",
            "LOCKET_INVITE",
        ),
        "cat <<'LOCKET_INVITE_2' | locket agent invite accept -\nheader\nLOCKET_INVITE\nLOCKET_INVITE_1\npayload\nLOCKET_INVITE_2"
    );
}

#[test]
fn parses_profile_project_and_agent_commands() {
    for args in [
        ["locket", "profile", "create", "dev"].as_slice(),
        &["locket", "profile", "mark-dangerous", "prod"],
        &["locket", "project", "trust-root"],
        &["locket", "project", "list-roots"],
        &["locket", "project", "untrust-root", "abc123"],
        &["locket", "shellenv"],
        &["locket", "shellenv", "--shell", "zsh"],
        &["locket", "hook"],
        &["locket", "hook", "--install"],
        &["locket", "completion", "bash"],
        &["locket", "completion", "zsh"],
        &["locket", "completion", "fish"],
        &["locket", "completion", "elvish"],
        &["locket", "completion", "powershell"],
        &["locket", "allow"],
        &["locket", "deny"],
        &["locket", "deny", "--all"],
        &["locket", "agent", "start"],
        &["locket", "agent", "status"],
        &["locket", "agent", "stop"],
        &["locket", "agent", "logs"],
        &["locket", "agent", "logs", "--lines", "10", "--since", "1700000000"],
        &["locket", "agent", "logs", "--since", "2024-01-01T00:00:00Z"],
        &["locket", "agent", "logs", "--follow"],
        &["locket", "agent", "invite", "request"],
        &[
            "locket",
            "agent",
            "invite",
            "request",
            "--device",
            "lkdev2_abc",
            "--label",
            "build-agent",
            "--profile",
            "dev",
            "--role",
            "developer",
            "--expires-in",
            "7d",
        ],
        &[
            "locket",
            "agent",
            "invite",
            "create",
            "build-agent",
            "--device",
            "lkdev2_abc",
            "--profile",
            "dev",
            "--role",
            "developer",
            "--expires-in",
            "7d",
        ],
        &["locket", "agent", "invite", "accept", "-"],
        &["locket", "doctor"],
        &["locket", "debug", "bundle", "--redacted"],
        &["locket", "policy", "add", "dev", "--", "pnpm", "dev"],
        &["locket", "policy", "allow", "dev", "DATABASE_URL"],
        &["locket", "policy", "require", "dev", "API_KEY"],
        &["locket", "policy", "edit", "dev"],
        &["locket", "policy", "delete", "dev"],
        &["locket", "policy", "doctor"],
        &["locket", "team", "revoke-invite", "lk_invite_test"],
        &["locket", "team", "accept", "invite.locket-invite"],
    ] {
        assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
    }
}

#[test]
fn parses_scan_and_redaction_commands() {
    for args in [
        ["locket", "scan", "--staged", "--require-known"].as_slice(),
        &["locket", "redact", "--stdin", "--redact-names"],
        &["locket", "context", "--redact-names"],
        &["locket", "ai-safe", "--pattern-only", "--", "npm", "test"],
        &["locket", "install-hooks"],
    ] {
        assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
    }
}
