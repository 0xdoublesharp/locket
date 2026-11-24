use thiserror::Error;

use crate::PreparedExecution;

#[cfg(target_os = "macos")]
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Limits the outbound sockets that a child and its descendants may open.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkContainmentPolicy {
    /// Destination ports on loopback, such as the egress broker port.
    pub allowed_loopback_ports: Vec<u16>,
    /// Allow Unix-domain sockets for local IPC.
    pub allow_unix_sockets: bool,
}

impl Default for NetworkContainmentPolicy {
    fn default() -> Self {
        Self { allowed_loopback_ports: Vec::new(), allow_unix_sockets: true }
    }
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
    use std::net::{TcpListener, TcpStream, UdpSocket};

    use super::*;
    use crate::env_value;

    const ALLOWED: &str = "LOCKET_TEST_SEATBELT_ALLOWED";
    const DENIED: &str = "LOCKET_TEST_SEATBELT_DENIED";
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn seatbelt_enforces_loopback_ports_in_the_kernel() -> TestResult {
        let allowed = TcpListener::bind("127.0.0.1:0")?;
        let denied = TcpListener::bind("127.0.0.1:0")?;
        let address = allowed.local_addr()?;
        let denied_address = denied.local_addr()?;
        let program = std::env::current_exe()?
            .into_os_string()
            .into_string()
            .map_err(|_| std::io::Error::other("test executable path is not UTF-8"))?;
        let prepared = PreparedExecution {
            program,
            args: ["--exact", "network_sandbox::tests::seatbelt_child_probe", "--nocapture"]
                .map(str::to_owned)
                .to_vec(),
            env: [
                (ALLOWED.into(), env_value(address.to_string())),
                (DENIED.into(), env_value(denied_address.to_string())),
            ]
            .into_iter()
            .collect(),
        };
        for allow_unix_sockets in [true, false] {
            let policy = NetworkContainmentPolicy {
                allowed_loopback_ports: vec![address.port()],
                allow_unix_sockets,
            };
            let wrapped = wrap_command_with_network_containment(&prepared, &policy)?;
            let output = wrapped.command().output()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(stdout.contains("1 passed"), "{stdout}");
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
