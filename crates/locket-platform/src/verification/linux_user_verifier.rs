//! Linux implementation of [`LocalUserVerifier`] using the fail-closed
//! boundary in [`crate::linux_local_authentication`].
//!
//! This file contains zero `unsafe`. All platform interaction is
//! confined to `linux_local_authentication.rs`. See that module's
//! header comment for backend details and the FIDO2 follow-up.

use crate::error::PlatformError;
use crate::linux_local_authentication::{LocalAuthError, evaluate_local_user};
use crate::platform_name;
use crate::user_verification::{
    LocalUserVerification, LocalUserVerificationMethod, LocalUserVerificationRequest,
    LocalUserVerifier,
};

/// Linux [`LocalUserVerifier`]; unavailable without a fresh consent backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxLocalUserVerifier;

impl LinuxLocalUserVerifier {
    /// Creates a verifier ready to invoke the platform prompt.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LocalUserVerifier for LinuxLocalUserVerifier {
    fn verify_user(
        &self,
        request: &LocalUserVerificationRequest,
    ) -> Result<LocalUserVerification, PlatformError> {
        match evaluate_local_user(&request.reason) {
            Ok(true) => Ok(LocalUserVerification::new(
                LocalUserVerificationMethod::PlatformPrompt,
                platform_name(),
            )),
            Err(LocalAuthError::Unavailable(_)) => {
                Err(PlatformError::LocalUserVerificationUnavailable)
            }
            Ok(false)
            | Err(
                LocalAuthError::Rejected(_)
                | LocalAuthError::Framework(_)
                | LocalAuthError::Timeout
                | LocalAuthError::EmptyReason,
            ) => Err(PlatformError::LocalUserVerificationFailed),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::LinuxLocalUserVerifier;
    use crate::error::PlatformError;
    use crate::linux_local_authentication::with_test_override;
    use crate::user_verification::{
        LocalUserVerificationMethod, LocalUserVerificationRequest, LocalUserVerifier,
    };

    #[test]
    fn allow_maps_to_platform_prompt() {
        with_test_override(Some("allow"), || {
            let request = LocalUserVerificationRequest::new("unlock", "Unlock local vault");
            let verifier = LinuxLocalUserVerifier::new();
            let result = verifier.verify_user(&request).expect("allow override succeeds");
            assert_eq!(result.method, LocalUserVerificationMethod::PlatformPrompt);
            assert_eq!(result.platform, super::platform_name());
        });
    }

    #[test]
    fn deny_maps_to_verification_failed() {
        with_test_override(Some("deny"), || {
            let request = LocalUserVerificationRequest::new("reveal", "Reveal DATABASE_URL");
            let verifier = LinuxLocalUserVerifier::new();
            assert!(matches!(
                verifier.verify_user(&request),
                Err(PlatformError::LocalUserVerificationFailed)
            ));
        });
    }

    #[test]
    fn unavailable_maps_to_unavailable_error() {
        with_test_override(Some("unavailable"), || {
            let request = LocalUserVerificationRequest::new("unlock", "Unlock local vault");
            let verifier = LinuxLocalUserVerifier::new();
            assert!(matches!(
                verifier.verify_user(&request),
                Err(PlatformError::LocalUserVerificationUnavailable)
            ));
        });
    }
}
