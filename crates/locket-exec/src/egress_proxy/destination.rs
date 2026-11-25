use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::{EgressBlockReason, SOCKET_POLL};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_RESOLVERS: usize = 8;
const MAX_ADDRESSES: usize = 32;

#[derive(PartialEq, Eq)]
pub(super) struct Authority {
    pub(super) host: Zeroizing<String>,
    pub(super) port: u16,
}

impl Authority {
    pub(super) fn parse(input: &str, default_port: Option<u16>) -> Option<Self> {
        let (host, port) = split_authority(input)?;
        Some(Self { host, port: port.or(default_port)? })
    }

    pub(super) fn write_to(&self, writer: &mut impl io::Write) -> io::Result<()> {
        if self.host.contains(':') {
            write!(writer, "[{}]:{}", self.host.as_str(), self.port)
        } else {
            write!(writer, "{}:{}", self.host.as_str(), self.port)
        }
    }
}

fn split_authority(input: &str) -> Option<(Zeroizing<String>, Option<u16>)> {
    let (host, port) = if let Some(ipv6) = input.strip_prefix('[') {
        let (host, suffix) = ipv6.split_once(']')?;
        let host = host.parse::<std::net::Ipv6Addr>().ok()?;
        let port = if suffix.is_empty() { None } else { Some(suffix.strip_prefix(':')?) };
        (Zeroizing::new(host.to_string()), port)
    } else {
        let (host, port) =
            input.split_once(':').map_or((input, None), |(host, port)| (host, Some(port)));
        let host = host.strip_suffix('.').unwrap_or(host);
        if host.len() > 253 || !host.split('.').all(valid_dns_label) {
            return None;
        }
        (Zeroizing::new(host.to_ascii_lowercase()), port)
    };
    let port = if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        Some(port.parse::<std::num::NonZeroU16>().ok()?.get())
    } else {
        None
    };
    Some((host, port))
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub(super) struct HostRule {
    host: Zeroizing<String>,
    port: Option<u16>,
    subdomains: bool,
}

impl HostRule {
    pub(super) fn parse(rule: &str) -> Option<Self> {
        let (host, port) = split_authority(rule.strip_prefix("*.").unwrap_or(rule))?;
        let subdomains = rule.starts_with("*.");
        if subdomains && (!host.contains('.') || host.parse::<IpAddr>().is_ok()) {
            return None;
        }
        Some(Self { host, port, subdomains })
    }

    pub(super) fn matches(&self, target: &Authority) -> bool {
        self.port.is_none_or(|port| port == target.port)
            && if self.subdomains {
                target
                    .host
                    .strip_suffix(self.host.as_str())
                    .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
            } else {
                self.host == target.host
            }
    }

    pub(super) fn allows_loopback(&self, target: &Authority) -> bool {
        !self.subdomains && self.matches(target)
    }
}

pub(super) struct Resolver {
    in_flight: Arc<AtomicUsize>,
}

impl Resolver {
    pub(super) fn new() -> Self {
        Self { in_flight: Arc::new(AtomicUsize::new(0)) }
    }

    fn resolve(
        &self,
        target: &Authority,
        stopping: &AtomicBool,
    ) -> Result<Vec<SocketAddr>, EgressBlockReason> {
        if let Ok(ip) = target.host.parse() {
            return Ok(vec![SocketAddr::new(ip, target.port)]);
        }

        if self.in_flight.fetch_add(1, Ordering::Relaxed) >= MAX_RESOLVERS {
            self.in_flight.fetch_sub(1, Ordering::Relaxed);
            return Err(EgressBlockReason::UpstreamUnavailable);
        }
        let in_flight = Arc::clone(&self.in_flight);
        let host = Zeroizing::new(format!("{}.", target.host.as_str()));
        let port = target.port;
        let (send, receive) = mpsc::sync_channel(1);
        // The system DNS resolver can outlive a request deadline. Only its
        // address lookup runs here, with no connection or access to bindings.
        if thread::Builder::new()
            .spawn(move || {
                let result = (host.as_str(), port)
                    .to_socket_addrs()
                    .map(|addresses| addresses.take(MAX_ADDRESSES + 1).collect::<Vec<_>>());
                in_flight.fetch_sub(1, Ordering::Relaxed);
                let _ignored = send.send(result);
            })
            .is_err()
        {
            self.in_flight.fetch_sub(1, Ordering::Relaxed);
            return Err(EgressBlockReason::UpstreamUnavailable);
        }

        let deadline = Instant::now() + DNS_TIMEOUT;
        while !stopping.load(Ordering::Relaxed) && Instant::now() < deadline {
            match receive.recv_timeout(SOCKET_POLL) {
                Ok(Ok(addresses)) if addresses.len() <= MAX_ADDRESSES && !addresses.is_empty() => {
                    return Ok(addresses);
                }
                Err(RecvTimeoutError::Timeout) => {}
                _ => break,
            }
        }
        Err(EgressBlockReason::UpstreamUnavailable)
    }

    pub(super) fn pin(
        &self,
        target: &Authority,
        allow_loopback: bool,
        stopping: &AtomicBool,
    ) -> Result<Vec<SocketAddr>, EgressBlockReason> {
        let addresses = self.resolve(target, stopping)?;
        // Refuse mixed public/private DNS answers too. Connect directly to one
        // of these exact socket addresses without performing another lookup.
        if addresses.iter().any(|address| !permitted(address.ip(), allow_loopback)) {
            return Err(EgressBlockReason::PrivateDestination);
        }
        Ok(addresses)
    }

    pub(super) fn connect_pinned(
        addresses: &[SocketAddr],
        stopping: &AtomicBool,
    ) -> Result<TcpStream, EgressBlockReason> {
        let deadline = Instant::now() + DNS_TIMEOUT;
        for address in addresses {
            if stopping.load(Ordering::Relaxed) || Instant::now() >= deadline {
                break;
            }
            if let Ok(socket) = TcpStream::connect_timeout(address, CONNECT_TIMEOUT) {
                super::configure_socket(&socket)
                    .map_err(|_| EgressBlockReason::UpstreamUnavailable)?;
                return Ok(socket);
            }
        }
        Err(EgressBlockReason::UpstreamUnavailable)
    }
}

pub(super) const fn permitted(ip: IpAddr, allow_loopback: bool) -> bool {
    let ip = ip.to_canonical();
    if ip.is_loopback() {
        return allow_loopback;
    }
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || matches!(
                    ip.octets(),
                    [0 | 240..=255, ..]
                        | [100, 64..=127, ..]
                        | [192, 0, 0 | 2, _]
                        | [192, 88, 99, _]
                        | [198, 18 | 19, ..]
                        | [198, 51, 100, _]
                        | [203, 0, 113, _]
                ))
        }
        IpAddr::V6(ip) => {
            matches!(ip.segments()[0], 0x2000..=0x3fff)
                && !matches!(ip.segments(), [0x2001, 0..=0x1ff | 0xdb8, ..] | [0x2002 | 0x3fff, ..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_rejects_explicit_malformed_ports_without_using_default() {
        for address in ["example.test:", "example.test:+80", "[::1]:http", "example.test:0"] {
            assert!(Authority::parse(address, Some(80)).is_none(), "{address}");
        }
    }

    #[test]
    fn resolver_capacity_and_cancellation_fail_closed_without_connecting() -> io::Result<()> {
        let resolver = Resolver::new();
        let stopping = AtomicBool::new(false);
        let target = Authority::parse("example.test", Some(80))
            .ok_or_else(|| io::Error::other("invalid fixture authority"))?;
        resolver.in_flight.store(MAX_RESOLVERS, Ordering::Relaxed);
        assert_eq!(
            resolver.pin(&target, false, &stopping),
            Err(EgressBlockReason::UpstreamUnavailable)
        );
        assert_eq!(resolver.in_flight.load(Ordering::Relaxed), MAX_RESOLVERS);

        stopping.store(true, Ordering::Relaxed);
        let address = SocketAddr::from(([127, 0, 0, 1], 1));
        assert!(matches!(
            Resolver::connect_pinned(&[address], &stopping),
            Err(EgressBlockReason::UpstreamUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn special_use_address_boundaries_stay_out_of_public_pins()
    -> Result<(), std::net::AddrParseError> {
        for address in [
            "0.1.2.3",
            "100.64.0.0",
            "100.127.255.255",
            "240.0.0.0",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
        ] {
            assert!(!permitted(address.parse()?, true), "{address}");
        }
        for address in ["100.63.255.255", "100.128.0.0", "2001:4860::1"] {
            assert!(permitted(address.parse()?, false), "{address}");
        }
        Ok(())
    }
}
