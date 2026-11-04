//! Local user-verification request, result, and verifier traits.

use serde::{Deserialize, Serialize};

use crate::error::PlatformError;
use crate::platform_name;

/// Whether this build includes deterministic local-authentication test overrides.
///
/// This diagnostic probe never invokes a native authentication prompt.
#[doc(hidden)]
#[must_use]
pub const fn local_auth_test_overrides_enabled() -> bool {
    cfg!(test)
}

/// Request metadata for a local user-verification ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalUserVerificationRequest {
    /// Metadata-only action name, such as `unlock`, `reveal`, or `team_accept`.
    pub action: String,
    /// Metadata-only reason shown to the user by platform prompts when supported.
    pub reason: String,
}

impl LocalUserVerificationRequest {
    /// Creates a metadata-only user-verification request.
    #[must_use]
    pub fn new(action: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { action: action.into(), reason: reason.into() }
    }
}

/// Platform or fallback mechanism that satisfied a local user-verification gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalUserVerificationMethod {
    /// OS-native user-presence prompt such as Touch ID or Windows Hello.
    PlatformPrompt,
    /// Direct CTAP2/FIDO2 user-presence or user-verification ceremony.
    HardwareKey,
    /// Explicitly configured passphrase fallback.
    PassphraseFallback,
    /// In-memory test-only verifier.
    Test,
}

/// Successful local user-verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalUserVerification {
    /// Mechanism that satisfied the gate.
    pub method: LocalUserVerificationMethod,
    /// Metadata-only platform label for diagnostics.
    pub platform: String,
}

impl LocalUserVerification {
    /// Creates a verified result with metadata-only platform context.
    #[must_use]
    pub fn new(method: LocalUserVerificationMethod, platform: impl Into<String>) -> Self {
        Self { method, platform: platform.into() }
    }
}

/// Interface for local user verification used by sensitive CLI, UI, and agent gates.
pub trait LocalUserVerifier {
    /// Performs a local user-verification ceremony.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::LocalUserVerificationUnavailable`] when the
    /// current build has no platform verifier, and
    /// [`PlatformError::LocalUserVerificationFailed`] when a configured
    /// verifier rejects or cannot complete the ceremony.
    fn verify_user(
        &self,
        request: &LocalUserVerificationRequest,
    ) -> Result<LocalUserVerification, PlatformError>;
}

/// Default verifier for builds where platform presence APIs are not yet wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableLocalUserVerifier;

impl LocalUserVerifier for UnavailableLocalUserVerifier {
    fn verify_user(
        &self,
        _request: &LocalUserVerificationRequest,
    ) -> Result<LocalUserVerification, PlatformError> {
        Err(PlatformError::LocalUserVerificationUnavailable)
    }
}

/// Deterministic in-memory verifier for tests and integration harnesses.
#[derive(Debug, Clone)]
pub struct MemoryLocalUserVerifier {
    outcome: MemoryLocalUserVerificationOutcome,
}

/// Deterministic outcomes supported by [`MemoryLocalUserVerifier`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MemoryLocalUserVerificationOutcome {
    /// Verification succeeds with [`LocalUserVerificationMethod::Test`].
    Allow,
    /// Verification is rejected by the user or local policy.
    Deny,
    /// The platform/build has no verifier available.
    Unavailable,
    /// The user cancelled the ceremony before satisfying it.
    Cancelled,
}

impl MemoryLocalUserVerifier {
    /// Creates a verifier that always succeeds with a test-only method.
    #[must_use]
    pub const fn allowing() -> Self {
        Self { outcome: MemoryLocalUserVerificationOutcome::Allow }
    }

    /// Creates a verifier that always fails local user verification.
    #[must_use]
    pub const fn denying() -> Self {
        Self { outcome: MemoryLocalUserVerificationOutcome::Deny }
    }

    /// Creates a verifier that behaves like an unsupported platform.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self { outcome: MemoryLocalUserVerificationOutcome::Unavailable }
    }

    /// Creates a verifier that behaves like a user-cancelled ceremony.
    #[must_use]
    pub const fn cancelled() -> Self {
        Self { outcome: MemoryLocalUserVerificationOutcome::Cancelled }
    }

    /// Creates a verifier for the requested deterministic outcome.
    #[must_use]
    pub const fn with_outcome(outcome: MemoryLocalUserVerificationOutcome) -> Self {
        Self { outcome }
    }
}

impl LocalUserVerifier for MemoryLocalUserVerifier {
    fn verify_user(
        &self,
        _request: &LocalUserVerificationRequest,
    ) -> Result<LocalUserVerification, PlatformError> {
        match self.outcome {
            MemoryLocalUserVerificationOutcome::Allow => {
                Ok(LocalUserVerification::new(LocalUserVerificationMethod::Test, platform_name()))
            }
            MemoryLocalUserVerificationOutcome::Deny
            | MemoryLocalUserVerificationOutcome::Cancelled => {
                Err(PlatformError::LocalUserVerificationFailed)
            }
            MemoryLocalUserVerificationOutcome::Unavailable => {
                Err(PlatformError::LocalUserVerificationUnavailable)
            }
        }
    }
}
