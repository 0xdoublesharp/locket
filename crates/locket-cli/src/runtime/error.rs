//! CLI error type, error conversions, and helpers for typed error construction.

use std::error::Error;
use std::fmt::{self, Display};
use std::io;

use locket_core::LocketError;
use locket_store::StoreError;

#[derive(Debug)]
pub enum CliError {
    ConfigurationValidation { code: u8, message: String },
    Typed { kind: LocketError, message: String },
    ChildExit(u8),
    Io(io::Error),
    Store(StoreError),
    Json(serde_json::Error),
    TomlDe(toml::de::Error),
    TomlSer(toml::ser::Error),
    Crypto(locket_crypto::CryptoError),
    Platform(locket_platform::PlatformError),
    Time,
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::ConfigurationValidation { code, .. } | Self::ChildExit(code) => *code,
            Self::Json(_) | Self::TomlDe(_) | Self::TomlSer(_) => {
                LocketError::InvalidReference.exit_code()
            }
            Self::Typed { kind, .. } => kind.exit_code(),
            Self::Io(_) | Self::Time => LocketError::CorruptDb.exit_code(),
            Self::Store(error) => error.locket_error().exit_code(),
            Self::Crypto(error) => crypto_error_exit_code(*error),
            Self::Platform(error) => platform_error_exit_code(error),
        }
    }
}

const fn crypto_error_exit_code(error: locket_crypto::CryptoError) -> u8 {
    match error {
        locket_crypto::CryptoError::InvalidSecretValue => LocketError::InvalidReference.exit_code(),
        _ => LocketError::CorruptDb.exit_code(),
    }
}

const fn platform_error_exit_code(error: &locket_platform::PlatformError) -> u8 {
    match error {
        locket_platform::PlatformError::MasterKeyNotFound
        | locket_platform::PlatformError::InvalidPassphrase
        | locket_platform::PlatformError::DevicePrivateKeyNotFound => {
            LocketError::UnlockRequired.exit_code()
        }
        locket_platform::PlatformError::LocalUserVerificationFailed
        | locket_platform::PlatformError::LocalUserVerificationUnavailable
        | locket_platform::PlatformError::PasskeyAuthFailed
        | locket_platform::PlatformError::PasskeyNotFound
        | locket_platform::PlatformError::PasskeyRegistrationFailed => {
            LocketError::UserVerificationFailed.exit_code()
        }
        locket_platform::PlatformError::PasskeyUnsupported => {
            LocketError::PolicyValidationIncomplete.exit_code()
        }
        locket_platform::PlatformError::ProcessStartTimeUnavailable
        | locket_platform::PlatformError::WindowsSidUnavailable(_)
        | locket_platform::PlatformError::InvalidWindowsSid => {
            LocketError::AgentUnavailable.exit_code()
        }
        locket_platform::PlatformError::RecoveryEnvelopeSchemaUnsupported(_)
        | locket_platform::PlatformError::InvalidRecoveryEnvelope(_)
        | locket_platform::PlatformError::InvalidPassphraseFallback
        | locket_platform::PlatformError::InvalidMasterKey
        | locket_platform::PlatformError::InvalidProjectId
        | locket_platform::PlatformError::Keyring(_)
        | locket_platform::PlatformError::Io(_)
        | locket_platform::PlatformError::TomlDe(_)
        | locket_platform::PlatformError::TomlSer(_)
        | locket_platform::PlatformError::Crypto(_)
        | locket_platform::PlatformError::MemoryPoisoned
        | locket_platform::PlatformError::DevicePrivateKeyIntegrityFailure(_)
        | locket_platform::PlatformError::DevicePrivateKeyPermissionsTooWide(_)
        | locket_platform::PlatformError::DegradedAuditEncoding(_) => {
            LocketError::KeychainUnavailable.exit_code()
        }
    }
}

pub fn typed_cli_error(kind: LocketError, message: impl Into<String>) -> CliError {
    CliError::Typed { kind, message: message.into() }
}

pub fn project_root_untrusted_error() -> CliError {
    typed_cli_error(
        LocketError::ProjectRootUntrusted,
        "ProjectRootNotTrusted: current project root is not trusted; run locket project trust-root",
    )
}

pub fn project_not_found_error() -> CliError {
    typed_cli_error(LocketError::ProjectNotFound, "project not found")
}

pub fn invalid_reference_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::InvalidReference, message)
}

pub fn git_worktree_required_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::GitWorktreeRequired, message)
}

pub fn corrupt_db_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::CorruptDb, message)
}

pub fn secret_deleted_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::SecretDeleted, message)
}

pub fn secret_already_exists_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::SecretAlreadyExists, message)
}

pub fn secret_not_found_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::SecretNotFound, message)
}

pub fn secret_version_overflow_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::SecretVersionOverflow, message)
}

#[cfg(test)]
pub fn secret_version_expired_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::SecretVersionExpired, message)
}

pub fn profile_not_found_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::ProfileNotFound, message)
}

pub fn policy_not_found_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::PolicyNotFound, message)
}

pub fn invalid_policy_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::InvalidPolicy, message)
}

pub fn confirmation_failed_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::ConfirmationFailed, message)
}

pub fn user_verification_failed_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::UserVerificationFailed, message)
}

pub fn tty_required_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::TtyRequired, message)
}

pub fn access_denied_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::AccessDenied, message)
}

pub fn team_role_denied_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::TeamRoleDenied, message)
}

pub fn unlock_required_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::UnlockRequired, message)
}

pub fn scan_finding_blocked_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::ScanFindingBlocked, message)
}

pub fn external_source_unavailable_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::ExternalSourceUnavailable, message)
}

pub fn ide_env_session_unavailable_error(reason: impl Into<String>) -> CliError {
    typed_cli_error(
        LocketError::IdeEnvSessionUnavailable,
        format!("IdeEnvSessionUnavailable: {}", reason.into()),
    )
}

pub fn metadata_invalid_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::MetadataInvalid, message)
}

pub fn metadata_looks_like_secret_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::MetadataLooksLikeSecret, message)
}

pub fn invalid_secret_name_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::InvalidSecretName, message)
}

pub fn invalid_profile_name_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::InvalidProfileName, message)
}

pub fn bundle_verification_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::BundleVerificationFailed, message)
}

pub fn unimplemented_in_build_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::PolicyValidationIncomplete, message)
}

pub fn exec_prepare_error(error: locket_exec::ExecError) -> CliError {
    match error {
        locket_exec::ExecError::Environment(error) => {
            typed_cli_error(LocketError::EnvironmentConflict, error.to_string())
        }
        locket_exec::ExecError::EmptyCommand => invalid_reference_error("empty command"),
    }
}

pub fn child_exit_error(status: std::process::ExitStatus) -> CliError {
    CliError::ChildExit(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1))
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Typed { message, .. } | Self::ConfigurationValidation { message, .. } => {
                formatter.write_str(message)
            }
            Self::ChildExit(code) => write!(formatter, "child process exited with code {code}"),
            Self::Io(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::Json(error) => error.fmt(formatter),
            Self::TomlDe(error) => error.fmt(formatter),
            Self::TomlSer(error) => error.fmt(formatter),
            Self::Crypto(error) => error.fmt(formatter),
            Self::Platform(error) => error.fmt(formatter),
            Self::Time => formatter.write_str("system time is before the Unix epoch"),
        }
    }
}

impl Error for CliError {}

impl From<io::Error> for CliError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StoreError> for CliError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<toml::de::Error> for CliError {
    fn from(value: toml::de::Error) -> Self {
        Self::TomlDe(value)
    }
}

impl From<toml::ser::Error> for CliError {
    fn from(value: toml::ser::Error) -> Self {
        Self::TomlSer(value)
    }
}

impl From<locket_crypto::CryptoError> for CliError {
    fn from(value: locket_crypto::CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<locket_platform::PlatformError> for CliError {
    fn from(value: locket_platform::PlatformError) -> Self {
        Self::Platform(value)
    }
}
