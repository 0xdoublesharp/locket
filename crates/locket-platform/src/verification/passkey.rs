//! Platform passkey/`WebAuthn` registration and PRF evaluation traits.
//!
//! External FIDO2 credentials use a terminal-only libfido2 backend where
//! available.

use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::error::PlatformError;

/// Result of a successful platform-authenticator registration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PasskeyRegistration {
    /// Public `WebAuthn` credential id bytes. Never private key material.
    pub credential_id: Vec<u8>,
    /// Public key bytes for the credential. Never private key material.
    pub public_key: Vec<u8>,
    /// Stable random `WebAuthn` user handle for this credential.
    pub user_handle: Vec<u8>,
    /// Transport hints reported by the platform/authenticator.
    pub transports: Vec<String>,
    /// Whether the authenticator supports the `WebAuthn` PRF/hmac-secret extension.
    pub prf_capable: bool,
    /// Whether the authenticator reports backup eligibility, when known.
    pub backup_eligible: Option<bool>,
    /// Whether the authenticator reports a current backup state, when known.
    pub backup_state: Option<bool>,
}

/// Stored public bindings required to verify a fresh authenticator assertion.
#[derive(Clone, Copy, Debug)]
pub struct PasskeyAssertionContext<'a> {
    /// Credential selected during registration.
    pub credential_id: &'a [u8],
    /// Relying party used during registration; never inferred from the device.
    pub relying_party_id: &'a str,
    /// Registered public key used to verify the returned signature.
    pub public_key: &'a [u8],
}

/// Interface for registering and using platform passkeys.
///
/// Implementations must never expose passkey/biometric private key material
/// and must surface platform errors as [`PlatformError`] so the CLI can map
/// them to a generic "passkey auth failed" outcome without leaking detail.
pub trait PlatformPasskeyRegistrar {
    /// Whether this backend can register a real platform authenticator.
    ///
    /// Callers can check this before requesting local user verification.
    fn supports_registration(&self) -> bool {
        false
    }

    /// Performs a platform-authenticator registration ceremony.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::PasskeyUnsupported`] when the current build or
    /// platform has no platform-authenticator integration, and
    /// [`PlatformError::PasskeyAuthFailed`] or
    /// [`PlatformError::PasskeyRegistrationFailed`] when the platform rejects
    /// or cannot complete the ceremony.
    fn register_passkey(
        &self,
        label: &str,
        relying_party_id: &str,
    ) -> Result<PasskeyRegistration, PlatformError>;

    /// Evaluates the `WebAuthn` PRF/hmac-secret extension for a stored credential.
    /// The backend must verify the fresh challenge, relying party, signature,
    /// user presence, and user verification before returning the secret.
    ///
    /// The 32-byte PRF output is sensitive symmetric key material and must be
    /// zeroized on drop by the caller's wrapper. Implementations should not
    /// retain a copy.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::PasskeyUnsupported`] when the build or
    /// platform has no platform-authenticator integration,
    /// [`PlatformError::PasskeyNotFound`] when the credential is unknown to
    /// the platform, and [`PlatformError::PasskeyAuthFailed`] for any other
    /// platform-level failure.
    fn evaluate_prf(
        &self,
        credential: PasskeyAssertionContext<'_>,
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError>;
}

/// Default registrar for builds where platform passkey APIs are not yet wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailablePlatformPasskeyRegistrar;

impl PlatformPasskeyRegistrar for UnavailablePlatformPasskeyRegistrar {
    fn supports_registration(&self) -> bool {
        false
    }

    fn register_passkey(
        &self,
        _label: &str,
        _relying_party_id: &str,
    ) -> Result<PasskeyRegistration, PlatformError> {
        Err(PlatformError::PasskeyUnsupported)
    }

    fn evaluate_prf(
        &self,
        _credential: PasskeyAssertionContext<'_>,
        _salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        Err(PlatformError::PasskeyUnsupported)
    }
}

/// Deterministic outcomes supported by [`MemoryPlatformPasskeyRegistrar`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MemoryPlatformPasskeyOutcome {
    /// Registration succeeds with a canned [`PasskeyRegistration`].
    Allow(PasskeyRegistration),
    /// Registration fails with [`PlatformError::PasskeyUnsupported`].
    Unsupported,
    /// Registration fails with [`PlatformError::PasskeyAuthFailed`].
    AuthFailed,
}

/// In-memory test registrar with deterministic outcomes.
///
/// Stores at most one credential id and its associated PRF output so tests
/// can round-trip register -> `evaluate_prf` flows.
pub struct MemoryPlatformPasskeyRegistrar {
    outcome: MemoryPlatformPasskeyOutcome,
    prf_output: [u8; 32],
    credential_id: Mutex<Option<Vec<u8>>>,
}

impl std::fmt::Debug for MemoryPlatformPasskeyRegistrar {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("MemoryPlatformPasskeyRegistrar").finish_non_exhaustive()
    }
}

impl MemoryPlatformPasskeyRegistrar {
    /// Returns a canned successful registration with the given PRF output.
    #[must_use]
    pub const fn allowing(registration: PasskeyRegistration, prf_output: [u8; 32]) -> Self {
        Self {
            outcome: MemoryPlatformPasskeyOutcome::Allow(registration),
            prf_output,
            credential_id: Mutex::new(None),
        }
    }

    /// Returns a registrar that always reports the platform as unsupported.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            outcome: MemoryPlatformPasskeyOutcome::Unsupported,
            prf_output: [0_u8; 32],
            credential_id: Mutex::new(None),
        }
    }

    /// Returns a registrar that always reports a platform auth failure.
    #[must_use]
    pub const fn auth_failed() -> Self {
        Self {
            outcome: MemoryPlatformPasskeyOutcome::AuthFailed,
            prf_output: [0_u8; 32],
            credential_id: Mutex::new(None),
        }
    }

    /// Returns a canned PRF output matched against any credential id.
    ///
    /// Used by tests that need [`PlatformPasskeyRegistrar::evaluate_prf`]
    /// without first calling [`PlatformPasskeyRegistrar::register_passkey`].
    #[must_use]
    pub const fn with_known_credential(prf_output: [u8; 32], credential_id: Vec<u8>) -> Self {
        Self {
            outcome: MemoryPlatformPasskeyOutcome::AuthFailed,
            prf_output,
            credential_id: Mutex::new(Some(credential_id)),
        }
    }
}

impl PlatformPasskeyRegistrar for MemoryPlatformPasskeyRegistrar {
    fn supports_registration(&self) -> bool {
        !matches!(self.outcome, MemoryPlatformPasskeyOutcome::Unsupported)
    }

    fn register_passkey(
        &self,
        _label: &str,
        _relying_party_id: &str,
    ) -> Result<PasskeyRegistration, PlatformError> {
        match &self.outcome {
            MemoryPlatformPasskeyOutcome::Allow(registration) => {
                {
                    let mut guard =
                        self.credential_id.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
                    *guard = Some(registration.credential_id.clone());
                }
                Ok(registration.clone())
            }
            MemoryPlatformPasskeyOutcome::Unsupported => Err(PlatformError::PasskeyUnsupported),
            MemoryPlatformPasskeyOutcome::AuthFailed => Err(PlatformError::PasskeyAuthFailed),
        }
    }

    fn evaluate_prf(
        &self,
        credential: PasskeyAssertionContext<'_>,
        _salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        let known_credential_id = {
            let guard = self.credential_id.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
            guard.clone()
        };
        match known_credential_id {
            Some(known) if known.as_slice() == credential.credential_id => {
                Ok(Zeroizing::new(self.prf_output))
            }
            Some(_) => Err(PlatformError::PasskeyNotFound),
            None => match self.outcome {
                MemoryPlatformPasskeyOutcome::Unsupported => Err(PlatformError::PasskeyUnsupported),
                _ => Err(PlatformError::PasskeyAuthFailed),
            },
        }
    }
}

/// Default registrar: external FIDO2 ceremonies where available.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPlatformPasskeyRegistrar;

impl PlatformPasskeyRegistrar for DefaultPlatformPasskeyRegistrar {
    fn supports_registration(&self) -> bool {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            super::external_fido2::available()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            false
        }
    }

    fn register_passkey(
        &self,
        label: &str,
        relying_party_id: &str,
    ) -> Result<PasskeyRegistration, PlatformError> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            super::external_fido2::register(label, relying_party_id)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (label, relying_party_id);
            Err(PlatformError::PasskeyUnsupported)
        }
    }

    fn evaluate_prf(
        &self,
        credential: PasskeyAssertionContext<'_>,
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            super::external_fido2::evaluate(credential, salt)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (credential, salt);
            Err(PlatformError::PasskeyUnsupported)
        }
    }
}

/// Returns the default passkey registrar for this build.
#[must_use]
pub const fn default_platform_passkey_registrar() -> DefaultPlatformPasskeyRegistrar {
    DefaultPlatformPasskeyRegistrar
}
