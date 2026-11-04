//! Linux local user-verification boundary.
//!
//! Secret Service protects stored credentials but an unlocked collection can
//! be read without fresh user consent. It therefore cannot satisfy this gate.
//! Until a real PAM/polkit or FIDO2 ceremony is integrated, verification fails
//! closed. Ordinary keyring storage and passphrase vault unlock remain usable.

use thiserror::Error;

#[cfg(test)]
const TEST_OVERRIDE_ENV: &str = "LOCKET_TEST_LOCAL_AUTH";

/// Errors returned by [`evaluate_local_user`].
///
/// The variants mirror [`crate::macos_local_authentication::LocalAuthError`]
/// so the outer [`LocalUserVerifier`](crate::user_verification::LocalUserVerifier)
/// implementation can treat both backends interchangeably.
#[derive(Debug, Error)]
pub enum LocalAuthError {
    /// No supported fresh user-verification integration is available.
    #[error("Linux local authentication unavailable: {0}")]
    Unavailable(String),
    /// The user dismissed, cancelled, or otherwise refused the prompt.
    #[error("Linux local authentication ceremony rejected: {0}")]
    Rejected(String),
    /// The platform binding returned a low-level error before a reply
    /// could be observed.
    #[error("Linux local authentication backend error: {0}")]
    Framework(String),
    /// The platform never delivered a reply within the configured
    /// timeout.
    #[error("Linux local authentication evaluation timed out")]
    Timeout,
    /// The supplied localized reason was empty.
    #[error("Linux local authentication requires a non-empty localized reason")]
    EmptyReason,
}

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

/// Requests fresh local user verification on Linux.
///
/// # Errors
///
/// Returns [`LocalAuthError::EmptyReason`] for blank reasons and
/// [`LocalAuthError::Unavailable`] until a supported fresh-authentication
/// backend is available. Secret Service access alone is never consent.
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
    Err(LocalAuthError::Unavailable(
        "fresh local user verification is unavailable on this Linux build; \
         Secret Service access does not prove fresh consent. Ordinary vault unlock \
         with keyring or passphrase remains supported"
            .to_owned(),
    ))
}

/// Serializes tests that mutate the shared `LOCKET_TEST_LOCAL_AUTH`
/// environment variable so they cannot race across the test binary.
///
/// Lives in this module so the entire `unsafe { env::set_var(..) }`
/// mechanic stays inside the authorized backend module, mirroring the
/// macOS layout. Callers in sibling modules
/// (`linux_user_verifier.rs`) drive their tests through
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

    #[test]
    fn no_fresh_authentication_backend_fails_closed() {
        with_test_override(None, || {
            assert!(matches!(
                evaluate_local_user("Unlock vault"),
                Err(LocalAuthError::Unavailable(reason))
                    if reason.contains("fresh") && reason.contains("Secret Service")
            ));
        });
    }
}
