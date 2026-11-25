//! Small ANSI presentation helpers for interactive CLI output.

#![allow(clippy::redundant_pub_crate)]

use std::env;
use std::fmt;
use std::io::{self, IsTerminal, Write};

/// Semantic color roles used by the CLI theme.
#[derive(Clone, Copy)]
pub(crate) enum Tone {
    /// Locket brand accents.
    Brand,
    /// Successful or armed state.
    Good,
    /// Warning state.
    Warn,
    /// Field labels.
    Key,
    /// Primary values.
    Value,
    /// Low-emphasis chrome.
    Muted,
    /// High-emphasis text.
    Strong,
    /// Secret or recovery-code material.
    Secret,
}

impl Tone {
    const fn code(self) -> &'static str {
        match self {
            Self::Brand => "38;5;51",
            Self::Good => "38;5;82",
            Self::Warn => "38;5;214",
            Self::Key => "38;5;117",
            Self::Value => "38;5;255",
            Self::Muted => "38;5;245",
            Self::Strong => "1;38;5;255",
            Self::Secret => "1;38;5;226",
        }
    }
}

/// Returns true when interactive output should include ANSI styling.
pub(crate) fn enabled() -> bool {
    if env_flag_set("NO_COLOR") || env_value_is("LOCKET_STYLE", &["0", "off", "plain", "never"]) {
        return false;
    }
    if env_flag_set("FORCE_COLOR")
        || env_value_is("CLICOLOR_FORCE", &["1", "true"])
        || env_value_is("LOCKET_STYLE", &["1", "ansi", "always"])
    {
        return true;
    }
    io::stdout().is_terminal()
        && env::var("TERM").map_or(true, |term| !term.eq_ignore_ascii_case("dumb"))
}

/// Paints text with the selected terminal tone when styling is enabled.
pub(crate) fn paint(tone: Tone, text: impl fmt::Display) -> String {
    if enabled() { format!("\x1b[{}m{text}\x1b[0m", tone.code()) } else { text.to_string() }
}

/// Writes a compact hacker-ish section banner in interactive terminals.
pub(crate) fn write_banner(output: &mut impl Write, title: &str, status: &str) -> io::Result<()> {
    if enabled() {
        writeln!(
            output,
            "{} {} {}",
            paint(Tone::Brand, "==[ locket ]=="),
            paint(Tone::Strong, title),
            paint(Tone::Good, format!("// {status}"))
        )
    } else {
        writeln!(output, "{title}: {status}")
    }
}

/// Writes a labeled metadata row with aligned labels in interactive output.
pub(crate) fn write_kv(
    output: &mut impl Write,
    key: &str,
    value: impl fmt::Display,
) -> io::Result<()> {
    if enabled() {
        writeln!(
            output,
            "  {} {} {}",
            paint(Tone::Key, format!("{key:<20}")),
            paint(Tone::Muted, "::"),
            paint(Tone::Value, value)
        )
    } else {
        writeln!(output, "{key}: {value}")
    }
}

fn env_flag_set(name: &str) -> bool {
    env::var_os(name).is_some_and(|value| !value.is_empty())
}

fn env_value_is(name: &str, values: &[&str]) -> bool {
    env::var(name).is_ok_and(|actual| values.iter().any(|value| actual.eq_ignore_ascii_case(value)))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn style_respects_color_opt_in_and_no_color_override() -> Result<(), Box<dyn std::error::Error>>
    {
        const MODE: &str = "LOCKET_TEST_STYLE_CHILD";
        if let Ok(mode) = std::env::var(MODE) {
            return check_init_output(mode == "ansi");
        }

        // Color settings are process-wide. Isolate both cases from the parallel harness.
        for mode in ["ansi", "plain"] {
            let mut command = std::process::Command::new(std::env::current_exe()?);
            command
                .args([
                    "--exact",
                    "support::style::tests::style_respects_color_opt_in_and_no_color_override",
                ])
                .env(MODE, mode)
                .env("LOCKET_STYLE", "ANSI")
                .env_remove("FORCE_COLOR")
                .env_remove("CLICOLOR_FORCE")
                .env_remove("NO_COLOR");
            if mode == "plain" {
                command.env("NO_COLOR", "1");
            }
            let output = command.output()?;
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
            assert!(String::from_utf8(output.stdout)?.contains("1 passed"));
        }
        Ok(())
    }

    fn check_init_output(ansi: bool) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let context = crate::tests::test_context(&directory);
        let template_directory = tempfile::tempdir()?;
        let mut output = Vec::new();
        let init =
            ["locket", "init", "--no-passkey", "--no-device", "--name", "app", "--recovery-code"];
        let template = ["locket", "new", "--from-template", "basic"];
        for (args, show_recovery) in [(&init[..], true), (&init[..], false), (&template[..], false)]
        {
            // Give the template flow its own project while using the same in-memory key store.
            let path = if args[1] == "new" {
                template_directory.path().to_path_buf()
            } else {
                directory.path().to_path_buf()
            };
            let context = crate::RuntimeContext { cwd: path, ..context.clone() };
            output.clear();
            crate::run_with_context(crate::Cli::try_parse_from(args)?, &context, &mut output)?;
            let text = std::str::from_utf8(&output)?;
            assert_eq!(text.contains("\x1b["), ansi);
            assert!(text.contains("project"));
            if ansi {
                assert!(text.contains("\x1b[38;5;51m==[ locket ]==\x1b[0m"));
                assert!(text.contains("\x1b[38;5;117mproject_id"));
            }
            let color = "\x1b[1;38;5;226m";
            let codes = text
                .lines()
                .filter(|line| {
                    let candidate = line
                        .trim()
                        .strip_prefix(color)
                        .and_then(|line| line.strip_suffix("\x1b[0m"))
                        .unwrap_or(line);
                    locket_crypto::recovery_code_decode(candidate).is_ok()
                })
                .count();
            assert_eq!(codes, usize::from(show_recovery));
        }
        let mut output = Vec::new();
        super::write_banner(&mut output, "status", "ready")?;
        super::write_kv(&mut output, "metadata_only", "yes")?;
        if !ansi {
            assert_eq!(String::from_utf8(output)?, "status: ready\nmetadata_only: yes\n");
        }
        Ok(())
    }
}
