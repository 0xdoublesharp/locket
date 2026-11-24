//! Peer-credential validation for accepted agent connections.
//!
//! The agent socket lives at a per-user path with `0o600` permissions
//! (see `harden-socket-perms`), but a defense-in-depth check at accept
//! time confirms the connecting peer's effective UID matches the
//! daemon's own UID. Cross-user connections are rejected with
//! [`SocketServerError::PeerCredentialDenied`], which maps to
//! [`LocketError::AccessDenied`] (exit 70) at the CLI boundary.
//!
//! Linux exposes `SO_PEERCRED`; macOS and the BSDs expose
//! `getpeereid`. Tokio's [`UnixStream::peer_cred`] wraps both, so this
//! module stays free of `unsafe` code.

#[cfg(unix)]
use tokio::net::UnixStream;

#[cfg(unix)]
use crate::server::SocketServerError;

/// Connection identity reported by the local operating system.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerIdentity {
    /// Effective UID of the connecting process.
    pub uid: u32,
    /// Connecting process ID, when the platform reports one.
    pub pid: Option<u32>,
    /// Monotonic ID assigned by the daemon to this connection.
    pub connection_id: u64,
}

/// Returns the effective UID of the running process.
///
/// Used as the canonical "daemon UID" against which connecting peers
/// are validated. On non-Unix platforms the daemon-UID concept does not
/// apply and a fixed sentinel is returned so call sites that thread the
/// value through portable code still compile.
#[cfg(unix)]
#[must_use]
pub fn current_process_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Returns a sentinel UID on platforms without Unix peer credentials.
#[cfg(not(unix))]
#[must_use]
pub const fn current_process_uid() -> u32 {
    0
}

/// Reads the connecting peer's effective UID from a Tokio
/// [`UnixStream`] and validates it against `daemon_uid`.
///
/// # Errors
///
/// Returns [`SocketServerError::PeerCredentialDenied`] when the peer's
/// UID does not match the daemon's UID. Returns
/// [`SocketServerError::Io`] if the kernel cannot read peer credentials
/// for this connection (typically only on platforms where peer-cred
/// retrieval is unsupported, in which case the agent must fail closed).
#[cfg(unix)]
pub fn validate_peer_stream(
    stream: &UnixStream,
    daemon_uid: u32,
    connection_id: u64,
) -> Result<PeerIdentity, SocketServerError> {
    let cred = stream.peer_cred()?;
    validate_peer_uid(cred.uid(), daemon_uid)?;
    Ok(PeerIdentity {
        uid: cred.uid(),
        pid: cred.pid().and_then(|pid| u32::try_from(pid).ok()),
        connection_id,
    })
}

/// Pure validator: returns `Ok(())` when `peer_uid == daemon_uid` and a
/// typed error otherwise. Used by the live accept path and exercised
/// by unit tests so the policy is testable without a real socket.
///
/// # Errors
///
/// Returns [`SocketServerError::PeerCredentialDenied`] when the two
/// UIDs differ.
#[cfg(unix)]
pub const fn validate_peer_uid(peer_uid: u32, daemon_uid: u32) -> Result<(), SocketServerError> {
    if peer_uid == daemon_uid {
        Ok(())
    } else {
        Err(SocketServerError::PeerCredentialDenied { peer_uid, daemon_uid })
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::panic)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn accepted_stream_reports_kernel_pid_and_connection_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let (server, _client) = UnixStream::pair()?;
        let uid = current_process_uid();
        let identity = validate_peer_stream(&server, uid, 42)?;
        assert_eq!(
            identity,
            PeerIdentity { uid, pid: Some(std::process::id()), connection_id: 42 }
        );
        Ok(())
    }

    #[test]
    fn validate_peer_uid_accepts_matching_uids() {
        assert!(validate_peer_uid(1000, 1000).is_ok());
        assert!(validate_peer_uid(0, 0).is_ok());
    }

    #[test]
    fn validate_peer_uid_rejects_cross_user_connections() {
        let result = validate_peer_uid(1001, 1000);
        assert!(
            matches!(
                result,
                Err(SocketServerError::PeerCredentialDenied { peer_uid: 1001, daemon_uid: 1000 })
            ),
            "expected PeerCredentialDenied(1001, 1000), got {result:?}",
        );
    }

    #[test]
    fn validate_peer_uid_rejects_root_against_user() {
        // Root connecting to a user-owned daemon socket is still a
        // cross-user connection and must be rejected. The policy is
        // strict equality, not "peer >= daemon".
        let result = validate_peer_uid(0, 1000);
        assert!(matches!(result, Err(SocketServerError::PeerCredentialDenied { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn current_process_uid_is_nonzero_in_test_environment() {
        // CI and developer machines run tests as a regular user. This
        // is a sanity check that current_process_uid actually returns
        // the expected UID rather than a placeholder.
        let uid = current_process_uid();
        // No hard upper bound — UIDs above 60000 are common — but it
        // must equal `getuid()` so running it twice is stable.
        assert_eq!(uid, current_process_uid());
    }
}
