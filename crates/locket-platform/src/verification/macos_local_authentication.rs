//! macOS LocalAuthentication.framework wrapper.
//!
//! This module is the single concession to `unsafe` in `locket-platform`.
//! Every call into Apple's Objective-C runtime is wrapped in the safe
//! function [`evaluate_local_user`]; nothing else in the crate is allowed
//! to opt out of the workspace-level `unsafe_code = "forbid"` lint.
//
// SAFETY-AUDIT:
// ---------------------------------------------------------------------------
// Source spec:    docs/specs/crypto.md:192-218 (Local User Verification And
//                 Passkeys). macOS user-presence approval must use the
//                 platform LocalAuthentication.framework rather than a
//                 browser-style WebAuthn ceremony.
// Why `unsafe`:   The LocalAuthentication framework is exposed only as
//                 Objective-C selectors. The `objc2-local-authentication`
//                 bindings expose `LAContext::evaluatePolicy:localizedReason
//                 :reply:` and `LAContext::new` as `unsafe fn` because the
//                 caller must uphold the framework's threading and
//                 sendability contracts. Rust has no stable, safe binding
//                 to the framework, so a localized `unsafe` block is the
//                 minimum primitive needed to satisfy the spec.
// Scope:          The only `unsafe` in `locket-platform`. Restricted to
//                 this module; the workspace lint forbids `unsafe_code`
//                 elsewhere and `MacosLocalUserVerifier` (the trait impl)
//                 contains no `unsafe`.
// Invariants:
//   * The `LAContext` retains itself for the lifetime of the
//     `evaluatePolicy` reply; we keep an owned `Retained<LAContext>` until
//     we have received the reply through an `mpsc` channel, so the block
//     never observes a freed context.
//   * The `localizedReason` `NSString` is kept alive across the call
//     because `evaluatePolicy:localizedReason:reply:` is documented to
//     copy it before returning; we still hold the `Retained<NSString>`
//     for the duration of the call out of caution.
//   * The reply block is sendable: it only captures an
//     `mpsc::Sender<EvaluateOutcome>`, which is `Send`. The block converts
//     the borrowed `*mut NSError` into an owned `Option<String>` before
//     handing the result back, so no Objective-C pointer escapes the
//     block.
//   * The test-only `LOCKET_TEST_LOCAL_AUTH` short-circuit is evaluated
//     before any FFI call, so unit and integration tests never enter
//     the `unsafe` block.
// ---------------------------------------------------------------------------

#![allow(unsafe_code)]

use std::sync::mpsc;
use std::time::Duration;

use thiserror::Error;

/// Maximum time we will block waiting for a Touch ID/passcode prompt to
/// resolve before declaring the ceremony stuck. The system prompt itself
/// has its own timeout; this guard exists so a wedged framework cannot
/// deadlock the caller indefinitely.
const EVALUATE_TIMEOUT: Duration = Duration::from_secs(120);

/// Environment variable consulted by tests so they can drive the wrapper
/// deterministically without invoking Apple's framework.
#[cfg(test)]
const TEST_OVERRIDE_ENV: &str = "LOCKET_TEST_LOCAL_AUTH";

/// Errors returned by [`evaluate_local_user`].
#[derive(Debug, Error)]
pub enum LocalAuthError {
    /// LocalAuthentication.framework reported the policy is unavailable
    /// on this device (no biometrics enrolled, hardware missing, etc.).
    #[error("LocalAuthentication policy unavailable: {0}")]
    Unavailable(String),
    /// The user dismissed, cancelled, or otherwise refused the prompt.
    #[error("LocalAuthentication ceremony rejected: {0}")]
    Rejected(String),
    /// The framework failed before we could observe a reply.
    #[error("LocalAuthentication framework error: {0}")]
    Framework(String),
    /// The framework never delivered a reply within the configured
    /// timeout. Surfaces as a verification failure to the caller.
    #[error("LocalAuthentication evaluation timed out")]
    Timeout,
    /// The supplied localized reason was empty. The framework would
    /// raise `NSInvalidArgumentException`, so we reject it before the
    /// FFI call.
    #[error("LocalAuthentication requires a non-empty localized reason")]
    EmptyReason,
}

/// Test-only override applied before any FFI call.
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

/// Evaluate a local user-verification ceremony using
/// LocalAuthentication.framework.
///
/// The function blocks the calling thread until the framework delivers a
/// reply or the [`EVALUATE_TIMEOUT`] elapses. The `reason` string is shown
/// to the user inside the system-rendered prompt and must be non-empty.
///
/// # Errors
///
/// Returns [`LocalAuthError`] when the framework reports unavailability,
/// the user rejects the ceremony, the framework returns an error, or the
/// reply does not arrive within [`EVALUATE_TIMEOUT`].
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

    evaluate_local_user_via_framework(reason)
}

#[derive(Debug)]
enum EvaluateOutcome {
    Allowed,
    Rejected(String),
}

#[cfg(not(target_os = "macos"))]
fn evaluate_local_user_via_framework(_reason: &str) -> Result<bool, LocalAuthError> {
    Err(LocalAuthError::Unavailable(
        "LocalAuthentication.framework is only available on macOS".to_owned(),
    ))
}

#[cfg(target_os = "macos")]
fn evaluate_local_user_via_framework(reason: &str) -> Result<bool, LocalAuthError> {
    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    // SAFETY: `LAContext::new` allocates and retains a fresh Objective-C
    // object. The returned `Retained<LAContext>` enforces the standard
    // Objective-C reference-counting contract for us.
    let context: Retained<LAContext> = unsafe { LAContext::new() };
    let localized_reason: Retained<NSString> = NSString::from_str(reason);

    let (tx, rx) = mpsc::channel::<EvaluateOutcome>();

    // The block captures only the `Sender`, which is `Send`. The closure
    // converts the borrowed `*mut NSError` into an owned `Option<String>`
    // before forwarding the outcome, so no Objective-C pointer leaves the
    // block.
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let outcome = if success.as_bool() {
            EvaluateOutcome::Allowed
        } else if error.is_null() {
            EvaluateOutcome::Rejected("user rejected local user verification".to_owned())
        } else {
            // SAFETY: When `success` is `NO`, LocalAuthentication passes a
            // valid, autoreleased `NSError *` to the block. We immediately
            // copy the localized description into an owned `String`; the
            // pointer is not retained beyond this scope.
            let message = unsafe { describe_ns_error(error) };
            EvaluateOutcome::Rejected(message)
        };

        // The send may fail if the receiver was dropped (timeout). That
        // is fine — we simply discard the reply.
        let _ = tx.send(outcome);
    });

    // SAFETY: The framework requires that:
    //   * `policy` is one of the documented `LAPolicy` constants;
    //   * `localized_reason` is a non-nil, non-empty `NSString` (we
    //     enforced non-empty in `evaluate_local_user`);
    //   * `reply` is a sendable block with the documented signature.
    // All three are satisfied here. The block is invoked on a framework
    // thread, but it only sends through an `mpsc::Sender`, which is
    // `Send`.
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &localized_reason,
            &reply,
        );
    }

    match rx.recv_timeout(EVALUATE_TIMEOUT) {
        Ok(EvaluateOutcome::Allowed) => Ok(true),
        Ok(EvaluateOutcome::Rejected(msg)) => Err(LocalAuthError::Rejected(msg)),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // SAFETY: `invalidate` is documented as safe to call any time
            // the context is alive. We hold a `Retained` reference, so it
            // is alive here.
            unsafe { context.invalidate() };
            Err(LocalAuthError::Timeout)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(LocalAuthError::Framework(
            "LocalAuthentication reply channel closed without a value".to_owned(),
        )),
    }
}

/// Pulls the `localizedDescription` off an autoreleased `NSError`.
///
/// # Safety
///
/// `error` must point to a valid, retained-or-autoreleased `NSError`
/// instance. Caller must not use the pointer after this call returns —
/// the framework owns it.
#[cfg(target_os = "macos")]
unsafe fn describe_ns_error(error: *mut objc2_foundation::NSError) -> String {
    use objc2_foundation::NSError;

    // SAFETY: The caller guarantees `error` is a valid `NSError *`.
    let error_ref: &NSError = unsafe { &*error };
    error_ref.localizedDescription().to_string()
}

/// Serializes tests that mutate the shared `LOCKET_TEST_LOCAL_AUTH`
/// environment variable so they cannot race across the test binary.
///
/// Lives in this module rather than in callers so that the entire
/// `unsafe { env::set_var(..) }` mechanic stays inside the single
/// authorized `unsafe` module. Callers in sibling modules
/// (`macos_user_verifier.rs`) drive their tests through
/// [`with_test_override`].
#[cfg(test)]
#[allow(clippy::redundant_pub_crate, clippy::expect_used)]
pub(crate) fn with_test_override<F: FnOnce()>(value: Option<&str>, f: F) {
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    let _guard = ENV_LOCK.lock().expect("env lock poisoned");
    let previous = std::env::var(TEST_OVERRIDE_ENV).ok();
    if let Some(v) = value {
        // SAFETY: the lock above gives us exclusive access for the
        // duration of the test. `set_var` is safe when no other thread
        // is reading the environment concurrently, which is the case
        // here.
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
    fn timeout_override_maps_to_timeout_error() {
        with_test_override(Some("timeout"), || {
            assert!(matches!(evaluate_local_user("Unlock vault"), Err(LocalAuthError::Timeout)));
        });
    }

    #[test]
    fn unknown_override_value_is_framework_error() {
        with_test_override(Some("nope"), || {
            assert!(matches!(
                evaluate_local_user("Unlock vault"),
                Err(LocalAuthError::Framework(_))
            ));
        });
    }

    #[test]
    fn empty_reason_rejected_before_ffi() {
        with_test_override(Some("allow"), || {
            assert!(matches!(evaluate_local_user("   "), Err(LocalAuthError::EmptyReason)));
        });
    }
}
