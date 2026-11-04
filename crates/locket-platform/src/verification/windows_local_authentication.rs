//! Windows Hello LocalUserVerifier backend.
//!
//! Mirrors the structure of [`crate::macos_local_authentication`] but
//! uses the `Windows::Security::Credentials::UI::UserConsentVerifier`
//! binding from the `windows` crate. The implementation:
//!
//!   1. Construct a `UserConsentVerifier` request with the localized
//!      reason via `UserConsentVerifier::RequestVerificationAsync`.
//!   2. Resolve the returned `IAsyncOperation<UserConsentVerificationResult>`
//!      synchronously (using `.join()` from the WinRT runtime).
//!   3. Map `UserConsentVerificationResult::Verified` to `Ok(true)`,
//!      `DeviceBusy`/`Canceled`/`RetriesExhausted` to `Ok(false)` (user
//!      rejected), `DeviceNotPresent`/`NotConfiguredForUser`/
//!      `DisabledByPolicy` to [`LocalAuthError::Unavailable`].
//!
//! This file contains no `unsafe`. Once a real implementation lands,
//! follow the macOS pattern: a single safe `evaluate_local_user` entry
//! point, all `unsafe` confined here behind a SAFETY audit comment,
//! and no `unsafe` in
//! [`crate::windows_user_verifier`].
//!
//! Tests honor the `LOCKET_TEST_LOCAL_AUTH=allow|deny|unavailable`
//! environment variable so callers can drive the wrapper
//! deterministically without invoking Windows Hello.

use thiserror::Error;

/// Environment variable consulted by tests so they can drive the wrapper
/// deterministically without invoking Windows Hello.
#[cfg(test)]
const TEST_OVERRIDE_ENV: &str = "LOCKET_TEST_LOCAL_AUTH";

/// Errors returned by [`evaluate_local_user`].
///
/// The variants mirror [`crate::macos_local_authentication::LocalAuthError`]
/// so the outer [`LocalUserVerifier`](crate::user_verification::LocalUserVerifier)
/// implementation can treat both backends interchangeably.
#[derive(Debug, Error)]
pub enum LocalAuthError {
    /// `UserConsentVerifier` reported the policy as unavailable (no
    /// Hello enrollment, hardware missing, disabled by policy, etc.).
    #[error("Windows Hello unavailable: {0}")]
    Unavailable(String),
    /// The user dismissed, cancelled, or otherwise refused the prompt.
    #[error("Windows Hello ceremony rejected: {0}")]
    Rejected(String),
    /// `UserConsentVerifier` returned a low-level error before a reply
    /// could be observed.
    #[error("Windows Hello backend error: {0}")]
    Framework(String),
    /// The platform never delivered a reply within the configured
    /// timeout.
    #[error("Windows Hello evaluation timed out")]
    Timeout,
    /// The supplied localized reason was empty.
    #[error("Windows Hello requires a non-empty localized reason")]
    EmptyReason,
}

/// Test-only override applied before any backend call.
#[cfg(test)]
fn test_override() -> Option<Result<bool, LocalAuthError>> {
    let value = std::env::var(TEST_OVERRIDE_ENV).ok()?;
    Some(match value.as_str() {
        "allow" => Ok(true),
        "deny" => Ok(false),
        "unavailable" => Err(LocalAuthError::Unavailable("test override".to_owned())),
        "timeout" => Err(LocalAuthError::Timeout),
        other => Err(LocalAuthError::Framework(format!(
            "unrecognized {TEST_OVERRIDE_ENV} override: {other}"
        ))),
    })
}

/// Evaluate a local user-verification ceremony on Windows via Hello.
///
/// This blocks the calling thread until Windows resolves the
/// `UserConsentVerifier` availability and verification operations.
///
/// # Errors
///
/// Returns [`LocalAuthError::EmptyReason`] when `reason` is blank, and
/// [`LocalAuthError::Unavailable`] when Windows Hello is unavailable or
/// the test override selected `unavailable`.
pub fn evaluate_local_user(reason: &str) -> Result<bool, LocalAuthError> {
    if reason.trim().is_empty() {
        return Err(LocalAuthError::EmptyReason);
    }

    #[cfg(test)]
    if crate::local_auth_test_overrides_enabled()
        && let Some(outcome) = test_override()
    {
        return outcome;
    }

    evaluate_local_user_via_windows_hello(reason)
}

#[cfg(target_os = "windows")]
fn evaluate_local_user_via_windows_hello(reason: &str) -> Result<bool, LocalAuthError> {
    use windows::Security::Credentials::UI::UserConsentVerifier;
    use windows::core::HSTRING;

    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .map_err(map_windows_error)?
        .join()
        .map_err(map_windows_error)?;
    map_availability(availability)?;

    let message = HSTRING::from(reason);
    let result = UserConsentVerifier::RequestVerificationAsync(&message)
        .map_err(map_windows_error)?
        .join()
        .map_err(map_windows_error)?;
    map_verification_result(result)
}

#[cfg(not(target_os = "windows"))]
fn evaluate_local_user_via_windows_hello(_reason: &str) -> Result<bool, LocalAuthError> {
    Err(LocalAuthError::Unavailable("Windows Hello is only available on Windows".to_owned()))
}

#[cfg(target_os = "windows")]
fn map_availability(
    availability: windows::Security::Credentials::UI::UserConsentVerifierAvailability,
) -> Result<(), LocalAuthError> {
    use windows::Security::Credentials::UI::UserConsentVerifierAvailability;

    match availability {
        UserConsentVerifierAvailability::Available => Ok(()),
        UserConsentVerifierAvailability::DeviceBusy => {
            Err(LocalAuthError::Rejected("Windows Hello device is busy".to_owned()))
        }
        UserConsentVerifierAvailability::DeviceNotPresent => {
            Err(LocalAuthError::Unavailable("Windows Hello device is not present".to_owned()))
        }
        UserConsentVerifierAvailability::NotConfiguredForUser => Err(LocalAuthError::Unavailable(
            "Windows Hello is not configured for this user".to_owned(),
        )),
        UserConsentVerifierAvailability::DisabledByPolicy => {
            Err(LocalAuthError::Unavailable("Windows Hello is disabled by policy".to_owned()))
        }
        other => Err(LocalAuthError::Framework(format!(
            "unrecognized Windows Hello availability result: {}",
            other.0
        ))),
    }
}

#[cfg(target_os = "windows")]
fn map_verification_result(
    result: windows::Security::Credentials::UI::UserConsentVerificationResult,
) -> Result<bool, LocalAuthError> {
    use windows::Security::Credentials::UI::UserConsentVerificationResult;

    match result {
        UserConsentVerificationResult::Verified => Ok(true),
        UserConsentVerificationResult::DeviceBusy
        | UserConsentVerificationResult::RetriesExhausted
        | UserConsentVerificationResult::Canceled => Ok(false),
        UserConsentVerificationResult::DeviceNotPresent => {
            Err(LocalAuthError::Unavailable("Windows Hello device is not present".to_owned()))
        }
        UserConsentVerificationResult::NotConfiguredForUser => Err(LocalAuthError::Unavailable(
            "Windows Hello is not configured for this user".to_owned(),
        )),
        UserConsentVerificationResult::DisabledByPolicy => {
            Err(LocalAuthError::Unavailable("Windows Hello is disabled by policy".to_owned()))
        }
        other => Err(LocalAuthError::Framework(format!(
            "unrecognized Windows Hello verification result: {}",
            other.0
        ))),
    }
}

#[cfg(target_os = "windows")]
fn map_windows_error(error: windows::core::Error) -> LocalAuthError {
    LocalAuthError::Framework(error.to_string())
}

/// Serializes tests that mutate the shared `LOCKET_TEST_LOCAL_AUTH`
/// environment variable so they cannot race across the test binary.
///
/// Lives in this module so the entire `unsafe { env::set_var(..) }`
/// mechanic stays inside the authorized backend module, mirroring the
/// macOS layout. Callers in sibling modules
/// (`windows_user_verifier.rs`) drive their tests through
/// [`with_test_override`].
#[cfg(test)]
#[allow(unsafe_code, clippy::redundant_pub_crate, clippy::expect_used)]
pub(crate) fn with_test_override<F: FnOnce()>(value: Option<&str>, f: F) {
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    let _guard = ENV_LOCK.lock().expect("env lock poisoned");
    let previous = std::env::var(TEST_OVERRIDE_ENV).ok();
    if let Some(v) = value {
        // SAFETY: the lock above gives us exclusive access for the
        // duration of the test. `set_var` is safe when no other thread
        // is reading the environment concurrently.
        unsafe { std::env::set_var(TEST_OVERRIDE_ENV, v) };
    } else {
        // SAFETY: see above.
        unsafe { std::env::remove_var(TEST_OVERRIDE_ENV) };
    }

    f();

    if let Some(prev) = previous {
        // SAFETY: see above.
        unsafe { std::env::set_var(TEST_OVERRIDE_ENV, prev) };
    } else {
        // SAFETY: see above.
        unsafe { std::env::remove_var(TEST_OVERRIDE_ENV) };
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalAuthError, evaluate_local_user, with_test_override};

    #[test]
    fn allow_override_returns_true() {
        with_test_override(Some("allow"), || {
            assert!(matches!(evaluate_local_user("Unlock vault"), Ok(true)));
        });
    }

    #[test]
    fn deny_override_returns_false() {
        with_test_override(Some("deny"), || {
            assert!(matches!(evaluate_local_user("Unlock vault"), Ok(false)));
        });
    }

    #[test]
    fn unavailable_override_maps_to_unavailable_error() {
        with_test_override(Some("unavailable"), || {
            assert!(matches!(
                evaluate_local_user("Unlock vault"),
                Err(LocalAuthError::Unavailable(_))
            ));
        });
    }

    #[test]
    fn blank_reason_is_rejected_before_backend() {
        with_test_override(None, || {
            assert!(matches!(evaluate_local_user("   "), Err(LocalAuthError::EmptyReason)));
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "requires an enrolled Windows Hello user and an interactive desktop prompt"]
    fn real_host_windows_hello_user_consent() {
        with_test_override(None, || {
            assert!(matches!(evaluate_local_user("Validate Locket Windows Hello"), Ok(true)));
        });
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_result_mapping_covers_user_rejection_and_unavailable() {
        use windows::Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifierAvailability,
        };

        assert!(matches!(
            super::map_availability(UserConsentVerifierAvailability::Available),
            Ok(())
        ));
        assert!(matches!(
            super::map_availability(UserConsentVerifierAvailability::DisabledByPolicy),
            Err(LocalAuthError::Unavailable(_))
        ));
        assert!(matches!(
            super::map_verification_result(UserConsentVerificationResult::Verified),
            Ok(true)
        ));
        assert!(matches!(
            super::map_verification_result(UserConsentVerificationResult::Canceled),
            Ok(false)
        ));
        assert!(matches!(
            super::map_verification_result(UserConsentVerificationResult::DeviceNotPresent),
            Err(LocalAuthError::Unavailable(_))
        ));
    }
}
