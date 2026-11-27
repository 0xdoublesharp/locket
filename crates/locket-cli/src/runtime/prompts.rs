//! Interactive prompt readers and helpers used by the CLI runtime.

use std::io::{self, IsTerminal, Read};

use crate::runtime::error::{
    CliError, confirmation_failed_error, invalid_reference_error, metadata_invalid_error,
    tty_required_error,
};

/// Whether the caller requested a non-interactive invocation via `LOCKET_NO_PROMPT`.
pub fn prompts_disabled() -> bool {
    std::env::var("LOCKET_NO_PROMPT").is_ok_and(|value| {
        ["1", "true", "yes"].iter().any(|enabled| value.eq_ignore_ascii_case(enabled))
    })
}

fn require_prompts_enabled(reason: &str) -> Result<(), CliError> {
    if prompts_disabled() {
        return Err(tty_required_error(format!(
            "{reason} requires interactive input (LOCKET_NO_PROMPT is set)"
        )));
    }
    Ok(())
}

pub trait ConfirmationReader {
    fn read_confirmation(&self, prompt: &str) -> Result<String, CliError>;

    /// Whether this reader represents an interactive human terminal capable of immediate approval.
    fn is_interactive(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StdinConfirmationReader;

impl ConfirmationReader for StdinConfirmationReader {
    fn read_confirmation(&self, prompt: &str) -> Result<String, CliError> {
        read_stdin_confirmation(prompt, io::stdin().is_terminal())
    }

    fn is_interactive(&self) -> bool {
        !prompts_disabled() && io::stdin().is_terminal()
    }
}

/// Inner implementation of [`StdinConfirmationReader::read_confirmation`]
/// with the TTY check injected so tests can exercise the non-TTY guard
/// regardless of how `cargo test` is launched.
pub fn read_stdin_confirmation(prompt: &str, stdin_is_terminal: bool) -> Result<String, CliError> {
    require_prompts_enabled(prompt)?;
    if !stdin_is_terminal {
        return Err(tty_required_error(format!("{prompt} requires interactive confirmation")));
    }
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    Ok(confirmation)
}

pub trait PassphraseReader {
    fn existing_passphrase(&self) -> Result<zeroize::Zeroizing<String>, CliError>;

    fn new_passphrase(&self) -> Result<zeroize::Zeroizing<String>, CliError>;
}

pub trait RecoveryCodeReader {
    fn read_recovery_code(&self, prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError>;
}

#[derive(Debug, Clone, Copy)]
pub struct TtyRecoveryCodeReader;

impl RecoveryCodeReader for TtyRecoveryCodeReader {
    fn read_recovery_code(&self, prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
        read_recovery_code(prompt)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EnvOrPromptPassphraseReader;

impl PassphraseReader for EnvOrPromptPassphraseReader {
    fn existing_passphrase(&self) -> Result<zeroize::Zeroizing<String>, CliError> {
        require_interactive_passphrase("passphrase fallback unlock")?;
        read_hidden_passphrase("locket passphrase: ")
    }

    fn new_passphrase(&self) -> Result<zeroize::Zeroizing<String>, CliError> {
        require_interactive_passphrase("passphrase fallback setup")?;
        let first = read_hidden_passphrase("new locket passphrase: ")?;
        let second = read_hidden_passphrase("confirm locket passphrase: ")?;
        if *first != *second {
            return Err(confirmation_failed_error("passphrases did not match"));
        }
        Ok(first)
    }
}

pub fn require_interactive_passphrase(reason: &str) -> Result<(), CliError> {
    require_interactive_passphrase_with(
        reason,
        io::stdin().is_terminal(),
        io::stderr().is_terminal(),
    )
}

/// Inner implementation of [`require_interactive_passphrase`] with the
/// TTY checks injected so tests can drive the guard deterministically.
pub fn require_interactive_passphrase_with(
    reason: &str,
    stdin_is_terminal: bool,
    stderr_is_terminal: bool,
) -> Result<(), CliError> {
    require_prompts_enabled(reason)?;
    if stdin_is_terminal && stderr_is_terminal {
        Ok(())
    } else {
        Err(tty_required_error(format!("{reason} requires an interactive TTY")))
    }
}

pub fn read_hidden_passphrase(prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
    require_prompts_enabled("passphrase entry")?;
    let passphrase = zeroize::Zeroizing::new(rpassword::prompt_password(prompt)?);
    if passphrase.is_empty() {
        return Err(invalid_reference_error("passphrase must not be empty"));
    }
    Ok(passphrase)
}

pub trait SecretValueReader {
    fn read_secret_value(&self, prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError>;
}

#[derive(Debug, Clone, Copy)]
pub struct StdinOrPromptSecretValueReader;

impl SecretValueReader for StdinOrPromptSecretValueReader {
    fn read_secret_value(&self, prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
        if io::stdin().is_terminal() {
            read_secret_value_from_prompt(prompt)
        } else {
            read_secret_value_from_stdin()
        }
    }
}

pub fn read_secret_value_from_prompt(prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
    require_prompts_enabled(prompt)?;
    let value = rpassword::prompt_password(format!("Enter {prompt}: "))?;
    validate_secret_value(zeroize::Zeroizing::new(value))
}

pub fn read_secret_value_from_stdin() -> Result<zeroize::Zeroizing<String>, CliError> {
    read_secret_value_from_reader(io::stdin())
}

pub fn read_secret_value_from_reader(
    mut reader: impl Read,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    let mut value = String::from_utf8(bytes)
        .map_err(|_| metadata_invalid_error("secret value must be valid UTF-8"))?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    validate_secret_value(zeroize::Zeroizing::new(value))
}

pub fn validate_secret_value(
    value: zeroize::Zeroizing<String>,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    validate_secret_value_str(&value)?;
    Ok(value)
}

pub fn validate_secret_value_str(value: &str) -> Result<(), CliError> {
    if value.is_empty() {
        return Err(invalid_reference_error("secret value cannot be empty"));
    }
    if value.contains('\0') {
        return Err(metadata_invalid_error("secret value cannot contain NUL bytes"));
    }
    if value.contains('\n') || value.contains('\r') {
        return Err(metadata_invalid_error(
            "secret value cannot contain newlines; v1 has no multiline mode",
        ));
    }
    Ok(())
}

pub fn read_recovery_code(prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
    if io::stdin().is_terminal() {
        require_prompts_enabled(prompt)?;
        let value = rpassword::prompt_password(format!("Enter {prompt}: "))?;
        return Ok(zeroize::Zeroizing::new(value));
    }
    let mut value = String::new();
    io::stdin().read_to_string(&mut value)?;
    Ok(zeroize::Zeroizing::new(value))
}

#[cfg(test)]
mod secret_value_validation_tests {
    use super::validate_secret_value_str;
    use crate::runtime::error::CliError;
    use locket_core::error::LocketError;

    #[allow(clippy::panic)]
    fn assert_kind(result: &Result<(), CliError>, expected: LocketError) {
        let Err(CliError::Typed { kind, .. }) = result else {
            panic!("expected typed {expected:?}");
        };
        assert_eq!(*kind, expected);
    }

    #[test]
    fn accepts_single_line_utf8() {
        assert!(validate_secret_value_str("hunter2").is_ok());
    }

    #[test]
    fn rejects_empty_value() {
        assert_kind(&validate_secret_value_str(""), LocketError::InvalidReference);
    }

    #[test]
    fn rejects_nul_byte() {
        assert_kind(&validate_secret_value_str("foo\0bar"), LocketError::MetadataInvalid);
    }

    #[test]
    fn rejects_embedded_lf() {
        assert_kind(&validate_secret_value_str("foo\nbar"), LocketError::MetadataInvalid);
    }

    #[test]
    fn rejects_embedded_cr() {
        assert_kind(&validate_secret_value_str("foo\rbar"), LocketError::MetadataInvalid);
    }

    #[test]
    fn rejects_trailing_newline() {
        assert_kind(&validate_secret_value_str("foo\n"), LocketError::MetadataInvalid);
    }
}
