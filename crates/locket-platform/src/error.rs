//! Error type returned by `locket-platform`.

use locket_crypto::CryptoError;
use thiserror::Error;

/// Error returned by platform integration.
#[derive(Debug, Error)]
pub enum PlatformError {
    /// OS keyring returned an error.
    #[error(transparent)]
    Keyring(#[from] keyring_core::Error),
    /// No master key exists for the requested project.
    #[error("master key not found")]
    MasterKeyNotFound,
    /// Stored key material was malformed.
    #[error("invalid stored master key")]
    InvalidMasterKey,
    /// Passphrase authentication failed.
    #[error("invalid passphrase")]
    InvalidPassphrase,
    /// Passphrase fallback metadata was malformed or unsupported.
    #[error("invalid passphrase fallback metadata")]
    InvalidPassphraseFallback,
    /// Project id cannot be used as a local fallback-envelope filename.
    #[error("invalid project id for local path")]
    InvalidProjectId,
    /// Local user verification is not available in this build or platform.
    #[error("local user verification unavailable")]
    LocalUserVerificationUnavailable,
    /// Local user verification was rejected or failed.
    #[error("local user verification failed")]
    LocalUserVerificationFailed,
    /// The macOS pasteboard could not be opened or written.
    #[error("macOS pasteboard operation failed")]
    PasteboardUnavailable,
    /// Platform passkey/WebAuthn integration is not available in this build or platform.
    #[error("platform passkey unsupported")]
    PasskeyUnsupported,
    /// No platform passkey was registered for the requested credential id.
    #[error("platform passkey not found")]
    PasskeyNotFound,
    /// Platform passkey ceremony was rejected or failed without leaking detail.
    #[error("platform passkey authentication failed")]
    PasskeyAuthFailed,
    /// Platform passkey registration was rejected, cancelled, or failed.
    #[error("passkey registration failed")]
    PasskeyRegistrationFailed,
    /// Local filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Process start metadata could not be read for grant binding.
    #[error("process start metadata unavailable")]
    ProcessStartTimeUnavailable,
    /// Windows current-user SID could not be resolved.
    #[error("windows current-user SID unavailable (os error {0})")]
    WindowsSidUnavailable(u32),
    /// Windows SID text is not valid for a local agent pipe name.
    #[error("invalid windows SID")]
    InvalidWindowsSid,
    /// Passphrase fallback TOML decoding failed.
    #[error(transparent)]
    TomlDe(#[from] toml::de::Error),
    /// Passphrase fallback TOML encoding failed.
    #[error(transparent)]
    TomlSer(#[from] toml::ser::Error),
    /// Crypto operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// In-memory test store mutex was poisoned.
    #[error("memory key store poisoned")]
    MemoryPoisoned,
    /// Recovery envelope binary data is corrupt or uses an unsupported format.
    #[error("invalid recovery envelope: {0}")]
    InvalidRecoveryEnvelope(String),
    /// Recovery envelope uses a schema version newer than this binary supports.
    #[error("recovery envelope schema version {0} is not supported; upgrade locket")]
    RecoveryEnvelopeSchemaUnsupported(u16),
    /// No device private-key envelope exists for the requested device id.
    #[error("device private key not found")]
    DevicePrivateKeyNotFound,
    /// Device private-key envelope failed integrity checks (corrupt, wrong master key, or schema mismatch).
    #[error("device private key envelope integrity check failed: {0}")]
    DevicePrivateKeyIntegrityFailure(String),
    /// Device private-key envelope on-disk permissions are wider than 0600.
    #[error("device private key envelope permissions are too wide: {0:#o} (must be 0600)")]
    DevicePrivateKeyPermissionsTooWide(u32),
    /// Degraded-audit log JSON serialization failed.
    #[error("degraded audit log encoding failed: {0}")]
    DegradedAuditEncoding(serde_json::Error),
}
