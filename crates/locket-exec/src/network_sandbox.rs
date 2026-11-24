use thiserror::Error;

use crate::PreparedExecution;

#[cfg(target_os = "macos")]
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Limits the outbound sockets that a child and its descendants may open.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct NetworkContainmentPolicy {
    /// Destination ports on loopback, such as the egress broker port.
    pub allowed_loopback_ports: Vec<u16>,
    /// Allow outbound Unix-domain socket connections. Defaults to `false`.
    /// Setting this to `true` weakens containment by allowing access to local
    /// agents, proxies, and other services that listen on Unix-domain sockets.
    pub allow_unix_sockets: bool,
}

/// Availability of kernel-enforced network containment.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NetworkContainmentSupport {
    /// The host has the named sandbox launcher.
    Supported(&'static str),
    /// The host cannot launch the network sandbox for the given reason.
    Unsupported(&'static str),
}

/// Returns the available network containment backend or the reason it is unavailable.
#[must_use]
pub fn network_containment_support() -> NetworkContainmentSupport {
    #[cfg(target_os = "macos")]
    if std::path::Path::new(SANDBOX_EXEC).is_file() {
        return NetworkContainmentSupport::Supported("macOS Seatbelt");
    }
    #[cfg(target_os = "macos")]
    let reason = "sandbox-exec is unavailable";
    #[cfg(not(target_os = "macos"))]
    let reason = "network containment requires macOS Seatbelt";
    NetworkContainmentSupport::Unsupported(reason)
}

/// Failure to prepare a kernel-contained execution.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum NetworkContainmentError {
    /// The kernel network sandbox is unavailable on this host.
    #[error("network containment is unavailable: {reason}")]
    UnsupportedPlatform {
        /// Reason the backend is unavailable.
        reason: &'static str,
    },
    /// The loopback port list contains port zero.
    #[error("network containment requires nonzero loopback ports")]
    InvalidPort,
}

/// Wraps a child command with the host's kernel network sandbox.
///
/// The caller should propagate launch errors and the sandbox launcher's exit status.
///
/// # Errors
///
/// Returns an error when no sandbox backend is available or a loopback port is zero.
pub fn wrap_command_with_network_containment(
    prepared: &PreparedExecution,
    policy: &NetworkContainmentPolicy,
) -> Result<PreparedExecution, NetworkContainmentError> {
    if let NetworkContainmentSupport::Unsupported(reason) = network_containment_support() {
        return Err(NetworkContainmentError::UnsupportedPlatform { reason });
    }

    #[cfg(target_os = "macos")]
    {
        use std::fmt::Write as _;

        if policy.allowed_loopback_ports.contains(&0) {
            return Err(NetworkContainmentError::InvalidPort);
        }
        let mut profile = String::from("(version 1)\n(allow default)\n(deny network-outbound)\n");
        for port in &policy.allowed_loopback_ports {
            // Seatbelt's IP filter accepts the localhost keyword for loopback.
            let _ = writeln!(profile, "(allow network-outbound (remote ip \"localhost:{port}\"))");
        }
        if policy.allow_unix_sockets {
            profile.push_str("(allow network-outbound (remote unix-socket))\n");
        }
        let mut args = vec!["-p".into(), profile, "--".into(), prepared.program.clone()];
        args.extend_from_slice(&prepared.args);
        Ok(PreparedExecution { program: SANDBOX_EXEC.into(), args, env: prepared.env.clone() })
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (prepared, policy);
        Err(NetworkContainmentError::UnsupportedPlatform {
            reason: "network containment requires macOS Seatbelt",
        })
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::io;
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::os::unix::net::{UnixListener, UnixStream};

    use super::*;
    use crate::{EnvMap, env_value};

    const ALLOWED: &str = "LOCKET_TEST_SEATBELT_ALLOWED";
    const DENIED: &str = "LOCKET_TEST_SEATBELT_DENIED";
    const UNIX_SOCKET: &str = "LOCKET_TEST_SEATBELT_UNIX_SOCKET";
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn probe_command(probe: &str, env: EnvMap) -> io::Result<PreparedExecution> {
        let program = std::env::current_exe()?
            .into_os_string()
            .into_string()
            .map_err(|_| io::Error::other("test executable path is not UTF-8"))?;
        Ok(PreparedExecution {
            program,
            args: ["--exact", probe, "--nocapture"].map(str::to_owned).to_vec(),
            env,
        })
    }

    fn run_probe(prepared: &PreparedExecution, policy: &NetworkContainmentPolicy) -> TestResult {
        let wrapped = wrap_command_with_network_containment(prepared, policy)?;
        let output = wrapped.command().output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&output.stderr));
        assert!(stdout.contains("1 passed"), "{stdout}");
        Ok(())
    }

    #[test]
    fn seatbelt_denies_unix_domain_connections_by_default() -> TestResult {
        let directory = tempfile::tempdir()?;
        let socket_path = directory.path().join("agent.sock");
        let _listener = UnixListener::bind(&socket_path)?;
        drop(UnixStream::connect(&socket_path)?);
        let socket_path = socket_path.to_str().ok_or("test socket path is not UTF-8")?;
        let prepared = probe_command(
            "network_sandbox::tests::seatbelt_unix_child_probe",
            EnvMap::from([(UNIX_SOCKET.into(), env_value(socket_path))]),
        )?;
        let policy = NetworkContainmentPolicy::default();
        assert!(!policy.allow_unix_sockets);
        run_probe(&prepared, &policy)
    }

    #[test]
    fn seatbelt_unix_child_probe() -> TestResult {
        let Some(socket_path) = std::env::var_os(UNIX_SOCKET) else { return Ok(()) };
        let error =
            UnixStream::connect(socket_path).err().ok_or("sandbox allowed the Unix socket")?;
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.raw_os_error(), Some(1)); // Darwin EPERM
        Ok(())
    }

    #[test]
    fn seatbelt_enforces_loopback_ports_in_the_kernel() -> TestResult {
        let allowed = TcpListener::bind("127.0.0.1:0")?;
        let denied = TcpListener::bind("127.0.0.1:0")?;
        let address = allowed.local_addr()?;
        let denied_address = denied.local_addr()?;
        let prepared = probe_command(
            "network_sandbox::tests::seatbelt_child_probe",
            [
                (ALLOWED.into(), env_value(address.to_string())),
                (DENIED.into(), env_value(denied_address.to_string())),
            ]
            .into_iter()
            .collect(),
        )?;
        for allow_unix_sockets in [true, false] {
            let policy = NetworkContainmentPolicy {
                allowed_loopback_ports: vec![address.port()],
                allow_unix_sockets,
            };
            run_probe(&prepared, &policy)?;
        }
        assert_eq!(
            wrap_command_with_network_containment(
                &prepared,
                &NetworkContainmentPolicy {
                    allowed_loopback_ports: vec![0],
                    ..NetworkContainmentPolicy::default()
                },
            ),
            Err(NetworkContainmentError::InvalidPort),
        );
        Ok(())
    }

    #[test]
    fn seatbelt_child_probe() -> TestResult {
        let Ok(allowed) = std::env::var(ALLOWED) else {
            return Ok(());
        };
        let denied = std::env::var(DENIED)?;
        TcpStream::connect(allowed)?;
        assert_eq!(
            TcpStream::connect(&denied).err().and_then(|error| error.raw_os_error()),
            Some(1)
        );
        let udp = UdpSocket::bind("127.0.0.1:0")?;
        assert_eq!(
            udp.send_to(b"probe", denied).err().and_then(|error| error.raw_os_error()),
            Some(1)
        );
        Ok(())
    }
}
