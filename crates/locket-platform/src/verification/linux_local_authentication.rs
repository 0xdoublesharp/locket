//! Linux local user-verification boundary.
//!
//! Secret Service protects stored credentials but an unlocked collection can
//! be read without fresh user consent. It therefore cannot satisfy this gate.
//! Uses polkit's current-user authentication with a non-cached, packaged action.
//! Missing policy, authority, session agent, or rejected consent fails closed.
//! Secret Service access is never treated as proof of fresh consent.

use std::io::IsTerminal;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

const POLKIT_ACTION: &str = "app.locket.verify";
const POLKIT_POLICY_PATH: &str = "/usr/share/polkit-1/actions/app.locket.policy";
const POLKIT_POLICY: &[u8] = include_bytes!("../../resources/app.locket.policy");
const PKCHECK: &str = "/usr/bin/pkcheck";
const AUTH_TIMEOUT: Duration = Duration::from_secs(90);

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
/// [`LocalAuthError::Unavailable`] when the trusted polkit policy, authority,
/// or session authentication agent is missing.
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
    verify_polkit_installation()?;
    let binding = crate::current_process_binding()
        .map_err(|_| LocalAuthError::Unavailable("process identity unavailable".to_owned()))?;
    let uid = rustix::process::getuid();
    if uid.is_root() || uid != rustix::process::geteuid() {
        return Err(LocalAuthError::Unavailable(
            "fresh local verification requires an unprivileged user session".to_owned(),
        ));
    }
    let subject = format!("{},{},{}", binding.pid, binding.process_start_time, uid.as_raw());
    let mut command = Command::new(PKCHECK);
    // Do not permit inherited loader settings or a caller-selected fake system
    // bus to replace the trusted authentication helper or authority.
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/dbus/system_bus_socket");
    command.args(["--action-id", POLKIT_ACTION, "--process", &subject, "--allow-user-interaction"]);
    // The action has a fixed, metadata-only prompt. Never pass secret names or
    // caller-controlled reason text into a privileged authentication dialog.
    command.stdout(Stdio::null());
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        command.arg("--enable-internal-agent").stdin(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        command.stdin(Stdio::null()).stderr(Stdio::null());
    }
    run_polkit_check(&mut command, AUTH_TIMEOUT)
}

fn verify_polkit_installation() -> Result<(), LocalAuthError> {
    use std::os::unix::fs::MetadataExt;
    for path in [POLKIT_POLICY_PATH, PKCHECK] {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| {
            LocalAuthError::Unavailable("install Locket's polkit policy and pkcheck".to_owned())
        })?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(LocalAuthError::Unavailable("untrusted polkit installation".to_owned()));
        }
    }
    let metadata = std::fs::metadata(POLKIT_POLICY_PATH)
        .map_err(|_| LocalAuthError::Unavailable("polkit policy unavailable".to_owned()))?;
    if metadata.len() != POLKIT_POLICY.len() as u64
        || std::fs::read(POLKIT_POLICY_PATH).ok().as_deref() != Some(POLKIT_POLICY)
    {
        return Err(LocalAuthError::Unavailable(
            "Locket requires its non-cached, current-user polkit policy".to_owned(),
        ));
    }
    Ok(())
}

fn run_polkit_check(command: &mut Command, timeout: Duration) -> Result<bool, LocalAuthError> {
    let mut child = command.spawn().map_err(|_| {
        LocalAuthError::Unavailable("polkit authentication helper unavailable".to_owned())
    })?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return polkit_status(status.code()),
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20));
            }
            outcome => {
                let _kill = child.kill();
                let _wait = child.wait();
                return if outcome.is_err() {
                    Err(LocalAuthError::Framework("authentication helper failed".to_owned()))
                } else {
                    Err(LocalAuthError::Timeout)
                };
            }
        }
    }
}

fn polkit_status(code: Option<i32>) -> Result<bool, LocalAuthError> {
    match code {
        Some(0) => Ok(true),
        Some(1 | 3) => Ok(false),
        Some(2 | 127) => Err(LocalAuthError::Unavailable(
            "polkit authority, policy, or authentication agent unavailable".to_owned(),
        )),
        _ => Err(LocalAuthError::Framework("polkit authentication failed".to_owned())),
    }
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
    fn polkit_requires_fresh_current_user_authentication() {
        let policy = String::from_utf8_lossy(super::POLKIT_POLICY);
        assert!(policy.contains("<allow_active>auth_self</allow_active>"));
        assert!(policy.contains("<allow_inactive>no</allow_inactive>"));
        assert!(policy.contains("<allow_any>no</allow_any>"));
        assert!(!policy.contains("_keep"));
        assert!(!policy.contains("auth_admin"));
    }

    #[test]
    fn polkit_helper_rejection_failure_and_timeout_fail_closed() {
        use std::process::Command;
        use std::time::Duration;
        for code in [1, 3, 2, 127, 126] {
            let result = super::run_polkit_check(
                Command::new("/bin/sh").args(["-c", &format!("exit {code}")]),
                Duration::from_secs(2),
            );
            assert!(!matches!(result, Ok(true)));
        }
        let timed_out =
            super::run_polkit_check(Command::new("/bin/sleep").arg("5"), Duration::from_millis(30));
        assert!(matches!(timed_out, Err(LocalAuthError::Timeout)));
    }
}
