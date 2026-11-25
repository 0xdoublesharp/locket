use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use data_encoding::BASE64;
use proptest::prelude::*;

use super::destination::{Authority, HostRule, permitted};
use super::wire::{Framing, Wire, framing, parse_head};
use super::{
    EgressBlockReason, EgressEvent, EgressProxyBroker, EgressProxyConfig, EgressProxyError,
    EgressSecretBinding,
};
use crate::env_value;
use crate::secret_encoding::Form;

fn mixed_case(host: &str, mask: u64) -> String {
    host.bytes()
        .enumerate()
        .map(|(index, byte)| {
            char::from(if mask & (1 << (index % 64)) == 0 {
                byte
            } else {
                byte.to_ascii_uppercase()
            })
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn wildcard_host_policy_respects_dns_labels_and_canonical_authority(
        label in "[a-z][a-z0-9]{0,10}",
        port in 1..u16::MAX,
        mask in any::<u64>(),
    ) {
        let raw_rule = format!("*.{}.:{port}", mixed_case("example.com", mask));
        let rule = HostRule::parse(&raw_rule).ok_or_else(|| TestCaseError::fail("invalid rule"))?;
        let plain = HostRule::parse("*.example.com")
            .ok_or_else(|| TestCaseError::fail("invalid plain rule"))?;
        for (host, expected) in [
            (format!("{label}.example.com"), true),
            (format!("deep.{label}.example.com"), true),
            ("example.com".to_owned(), false),
            (format!("{label}example.com"), false),
            (format!("{label}.notexample.com"), false),
            (format!("{label}.example.com.invalid"), false),
        ] {
            let raw = format!("{}.:{port}", mixed_case(&host, !mask));
            let normalized = Authority::parse(&raw, None)
                .ok_or_else(|| TestCaseError::fail("invalid normalized authority"))?;
            let canonical = Authority::parse(&host, Some(port))
                .ok_or_else(|| TestCaseError::fail("invalid canonical authority"))?;
            prop_assert!(normalized == canonical, "normalization changed {}", raw);
            prop_assert_eq!(rule.matches(&normalized), expected, "{}", raw);
            prop_assert_eq!(plain.matches(&canonical), expected, "{}", host);
        }
        let wrong_port = Authority::parse(&format!("{label}.example.com"), Some(port + 1))
            .ok_or_else(|| TestCaseError::fail("invalid wrong-port authority"))?;
        prop_assert!(!rule.matches(&wrong_port));
    }

    #[test]
    fn default_destination_screening_blocks_special_use_addresses(
        [a, b, c] in any::<[u8; 3]>(),
        private_second in 16..32_u8,
        port in 1..=u16::MAX,
    ) {
        let private = [
            Ipv4Addr::new(127, a, b, c),
            Ipv4Addr::new(169, 254, b, c),
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(10, a, b, c),
            Ipv4Addr::new(172, private_second, b, c),
            Ipv4Addr::new(192, 168, b, c),
        ];
        let stopping = std::sync::atomic::AtomicBool::new(false);
        let resolver = super::Resolver::new();
        for ip in private.into_iter().flat_map(|ip| [
            IpAddr::V4(ip), IpAddr::V6(ip.to_ipv6_mapped()),
        ]).chain([
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, u16::from(b), u16::from(c))),
        ]) {
            let raw = SocketAddr::new(ip, port).to_string();
            let target = Authority::parse(&raw, None)
                .ok_or_else(|| TestCaseError::fail("invalid literal authority"))?;
            prop_assert!(!permitted(ip, false), "screening allowed {}", ip);
            prop_assert_eq!(
                resolver.pin(&target, false, &stopping),
                Err(EgressBlockReason::PrivateDestination),
            );
        }
        let public = SocketAddr::new(Ipv4Addr::new(8, 8, b, c).into(), port);
        let target = Authority::parse(&public.to_string(), None)
            .ok_or_else(|| TestCaseError::fail("invalid public authority"))?;
        prop_assert_eq!(resolver.pin(&target, false, &stopping), Ok(vec![public]));
    }

    #[test]
    fn broker_rejects_non_single_line_values_and_empty_host_rules(
        before in r"[^\r\n\x00]{0,24}",
        after in r"[^\r\n\x00]{0,24}",
    ) {
        let clean = format!("fixture-{before}-{after}");
        let config = EgressProxyConfig { tls_mitm_enabled: false, ..EgressProxyConfig::default() };
        let valid = binding("API_KEY", &clean, "example.com".into());
        let broker = EgressProxyBroker::start(vec![valid], config.clone())
            .map_err(|error| TestCaseError::fail(format!("valid binding rejected: {error}")))?;
        prop_assert!(broker.shutdown().is_empty());

        let empty = EgressSecretBinding {
            env_name: "API_KEY".into(),
            secret_value: env_value(&clean),
            allowed_hosts: vec![],
        };
        let result = EgressProxyBroker::start(vec![empty], config);
        prop_assert!(matches!(result, Err(EgressProxyError::InvalidBinding)));

        for tls_mitm_enabled in [false, true] {
            let config = EgressProxyConfig { tls_mitm_enabled, ..EgressProxyConfig::default() };
            for invalid in ['\r', '\n', '\0'] {
                let raw = format!("{before}{invalid}{after}");
                let result = EgressProxyBroker::start(
                    vec![binding("API_KEY", &raw, "example.com".into())],
                    config.clone(),
                );
                prop_assert!(matches!(result, Err(EgressProxyError::InvalidBinding)));
            }
        }
    }

    // TLA+ OnlyScreenedRequestsForward and Lean host_authority_mismatch_rejected.
    #[test]
    fn mismatched_host_header_never_delivers_a_binding(
        label in "[a-z][a-z0-9]{0,10}",
        secret in "fixture-secret-[0-9a-f]{16}",
        mask in any::<u64>(),
        wrong_port in any::<bool>(),
    ) {
        let server = listener()?;
        let upstream = server.local_addr()?;
        let broker = EgressProxyBroker::start(
            vec![binding("API_KEY", &secret, upstream.to_string())],
            EgressProxyConfig { tls_mitm_enabled: false, ..allow_loopback() },
        ).map_err(|error| TestCaseError::fail(format!("broker startup failed: {error}")))?;
        let env = broker.child_env_overrides();
        let token = env.get("API_KEY")
            .ok_or_else(|| TestCaseError::fail("missing placeholder"))?.as_str();
        let auth = proxy_auth(&broker)?;
        let host = if wrong_port {
            format!("127.0.0.1.:{}", if upstream.port() == 80 { 81 } else { 80 })
        } else {
            format!("{}.:{}", mixed_case(&format!("{label}.example.com"), mask), upstream.port())
        };
        let response = request(&broker, format!(
            "GET http://{upstream}/ HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: Basic {auth}\r\nAuthorization: Bearer {token}\r\n\r\n",
        ).as_bytes())?;
        prop_assert!(response.starts_with(b"HTTP/1.1 400 "));
        prop_assert!(!response.windows(secret.len()).any(|window| window == secret.as_bytes()));
        prop_assert!(!response.windows(auth.len()).any(|window| window == auth.as_bytes()));
        prop_assert_eq!(server.accept().err().map(|error| error.kind()), Some(io::ErrorKind::WouldBlock));
        let events = broker.shutdown();
        prop_assert!(matches!(events.as_slice(), [EgressEvent::Blocked {
            env_name, reason: EgressBlockReason::InvalidRequest, ..
        }] if env_name.is_empty()), "unexpected broker events: {:?}", events);
    }
}

pub(super) const SECRET: &str = "synthetic-&echo=\"value\"";
pub(super) const WAIT: Duration = Duration::from_secs(5);
pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) fn binding(name: &str, secret: &str, host: String) -> EgressSecretBinding {
    EgressSecretBinding {
        env_name: name.into(),
        secret_value: env_value(secret),
        allowed_hosts: vec![host],
    }
}

pub(super) fn allow_loopback() -> EgressProxyConfig {
    EgressProxyConfig {
        allow_private_destinations_for_allowed_hosts: true,
        ..EgressProxyConfig::default()
    }
}

pub(super) fn proxy_auth(broker: &EgressProxyBroker) -> Result<String, io::Error> {
    let env = broker.child_env_overrides();
    let user_password = env
        .get("HTTP_PROXY")
        .and_then(|url| url.strip_prefix("http://"))
        .and_then(|url| url.split_once('@'))
        .map(|(user_password, _)| user_password)
        .ok_or_else(|| io::Error::other("proxy credential missing"))?;
    Ok(BASE64.encode(user_password.as_bytes()))
}

fn request(broker: &EgressProxyBroker, request: &[u8]) -> io::Result<Vec<u8>> {
    let mut socket = TcpStream::connect_timeout(&broker.local_addr(), WAIT)?;
    socket.set_read_timeout(Some(WAIT))?;
    socket.set_write_timeout(Some(WAIT))?;
    socket.write_all(request)?;
    socket.shutdown(Shutdown::Write)?;
    let mut response = Vec::new();
    socket.read_to_end(&mut response)?;
    Ok(response)
}

pub(super) fn listener() -> io::Result<TcpListener> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub(super) fn accept(listener: &TcpListener) -> io::Result<TcpStream> {
    let deadline = Instant::now() + WAIT;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false)?;
                socket.set_read_timeout(Some(WAIT))?;
                socket.set_write_timeout(Some(WAIT))?;
                return Ok(socket);
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn receive(upstream: impl Read) -> io::Result<(String, Vec<u8>)> {
    let stop = std::sync::atomic::AtomicBool::new(false);
    let mut input = Wire::new(upstream, &stop, Instant::now() + WAIT);
    let head = input.head()?;
    let (_, headers) = parse_head(&head).ok_or_else(super::wire::invalid)?;
    let framing = framing(&headers).ok_or_else(super::wire::invalid)?;
    let mut body = Vec::new();
    input
        .copy_body(if framing == Framing::Eof { Framing::Length(0) } else { framing }, &mut body)?;
    let head = std::str::from_utf8(&head).map_err(io::Error::other)?.to_owned();
    Ok((head, body))
}

#[test]
fn delivers_only_to_allowed_host_and_redacts_chunked_echo_and_redirect() -> TestResult {
    let server = listener()?;
    let upstream = server.local_addr()?;
    let broker = EgressProxyBroker::start(
        vec![binding("API_KEY", SECRET, upstream.to_string())],
        allow_loopback(),
    )?;
    let env = broker.child_env_overrides();
    let token = env.get("API_KEY").ok_or("missing placeholder")?.as_str();
    assert_ne!(token, SECRET);
    assert_eq!(token.len(), "lk_egress_".len() + 32);
    assert!(token.starts_with("lk_egress_"));
    assert_eq!(env["HTTP_PROXY"], env["http_proxy"]);
    assert_eq!(env["HTTPS_PROXY"], env["https_proxy"]);
    assert_eq!(env["HTTP_PROXY"], env["HTTPS_PROXY"]);
    assert_eq!(env["NO_PROXY"].as_str(), "");
    assert_eq!(env["no_proxy"].as_str(), "");
    let auth = proxy_auth(&broker)?;
    let backend = thread::spawn(move || -> io::Result<()> {
        let mut socket = accept(&server)?;
        let (head, body) = receive(&socket)?;
        assert!(head.starts_with("POST /?token=synthetic-%26echo%3D%22value%22 HTTP/1.1\r\n"));
        assert!(head.contains(&format!("Authorization: Bearer {SECRET}\r\n")));
        assert!(!head.contains("Proxy-Authorization"));
        assert!(head.contains(&format!("Content-Length: {}\r\n", SECRET.len())));
        assert_eq!(body, SECRET.as_bytes());
        write!(
            socket,
            "HTTP/1.1 302 Found\r\nLocation: /echo?key={SECRET}\r\nTransfer-Encoding: chunked\r\n\r\n"
        )?;
        let split = SECRET.len() / 2;
        for part in [&SECRET[..split], &SECRET[split..]] {
            write!(socket, "{:x}\r\n{part}\r\n", part.len())?;
        }
        write!(socket, "0\r\nX-Trailer: {SECRET}\r\n\r\n")?;
        Ok(())
    });
    let response = request(&broker, format!(
        "POST http://{upstream}/?token={token} HTTP/1.1\r\nHost: {upstream}\r\nProxy-Authorization: Basic {auth}\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{token}", token.len()
    ).as_bytes())?;
    backend.join().map_err(|_| "upstream thread failed")??;
    let response = String::from_utf8(response)?;
    assert!(response.starts_with("HTTP/1.1 302 "));
    assert!(response.contains("Location: /echo?key=[REDACTED:locket]\r\n"));
    assert!(response.ends_with("\r\n\r\n[REDACTED:locket]"));
    assert!(!response.contains(SECRET));
    assert!(
        matches!(&broker.shutdown()[..], [EgressEvent::Allowed { env_name, target_host, timestamp_unix_nanos }]
        if env_name == "API_KEY" && target_host == "127.0.0.1" && *timestamp_unix_nanos > 0)
    );
    Ok(())
}

#[test]
fn rejects_any_unapproved_placeholder_before_opening_upstream_connection() -> TestResult {
    let server = listener()?;
    let upstream = server.local_addr()?;
    let broker = EgressProxyBroker::start(
        vec![
            binding("ALLOWED", "synthetic-allowed", upstream.to_string()),
            binding("DENIED", SECRET, "example.com".into()),
        ],
        allow_loopback(),
    )?;
    let env = broker.child_env_overrides();
    let auth = proxy_auth(&broker)?;
    let token = env["DENIED"].as_str();
    let percent = Form::UrlFullLower.encode(token.as_bytes());
    let partial = format!("%6C{}", &token[1..]);
    let base64 = BASE64.encode(token.as_bytes());
    let basic = format!("Basic {}", BASE64.encode(format!("user:{token}").as_bytes()));
    let encodings = [token, std::str::from_utf8(&percent)?, &partial, &base64, &basic];
    for encoded in encodings {
        let response = request(&broker, format!(
            "GET http://{upstream}/ HTTP/1.1\r\nHost: {upstream}\r\nProxy-Authorization: Basic {auth}\r\nX-Allowed: {}\r\nAuthorization: {encoded}\r\n\r\n", env["ALLOWED"].as_str()
        ).as_bytes())?;
        assert!(response.starts_with(b"HTTP/1.1 403 "));
    }
    assert_eq!(server.accept().err().map(|error| error.kind()), Some(io::ErrorKind::WouldBlock));
    let audit = broker.shutdown();
    assert_eq!(audit.len(), encodings.len());
    assert!(audit.iter().all(|event| matches!(event, EgressEvent::Blocked {
        env_name, target_host, reason: EgressBlockReason::HostNotAllowed, ..
    } if env_name == "DENIED" && target_host == "127.0.0.1")));
    assert!(!format!("{audit:?}").contains(SECRET));
    assert!(!format!("{audit:?}").contains(token));
    Ok(())
}

#[test]
fn rejects_invalid_framing_and_authority_and_requires_authentication() -> TestResult {
    let server = listener()?;
    let upstream = server.local_addr()?;
    let broker = EgressProxyBroker::start(
        vec![binding("API_KEY", SECRET, upstream.to_string())],
        allow_loopback(),
    )?;
    let auth = proxy_auth(&broker)?;
    let get = format!("GET http://{upstream}/ HTTP/1.1\r\n");
    for invalid in [
        format!("{get}Host: wrong.example\r\n"),
        format!("GET http://user@{upstream}/ HTTP/1.1\r\nHost: {upstream}\r\n"),
        format!("{get}Host: {upstream}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n"),
        format!("{get}Host: {upstream}\r\nContent-Length: 0\r\nContent-Length: 1\r\n"),
        format!("{get}Host: {upstream}\r\n Content-Length: 0\r\n"),
    ] {
        let response = request(
            &broker,
            format!("{invalid}Proxy-Authorization: Basic {auth}\r\n\r\n").as_bytes(),
        )?;
        assert!(response.starts_with(b"HTTP/1.1 400 "));
    }
    let bad_auth = "A".repeat(auth.len());
    for header in [
        String::new(),
        format!("Proxy-Authorization: Basic {bad_auth}\r\n"),
        format!("Proxy-Authorization: Basic {auth}\r\nProxy-Authorization: Basic {auth}\r\n"),
    ] {
        let response =
            request(&broker, format!("{get}Host: {upstream}\r\n{header}\r\n").as_bytes())?;
        assert!(response.starts_with(b"HTTP/1.1 407 "));
    }
    assert_eq!(server.accept().err().map(|error| error.kind()), Some(io::ErrorKind::WouldBlock));
    let audit = broker.shutdown();
    assert_eq!(audit.len(), 8);
    Ok(())
}

#[test]
fn denies_private_destinations_and_unlisted_connect() -> TestResult {
    let broker = EgressProxyBroker::start(
        vec![
            binding("API_KEY", SECRET, "169.254.169.254".into()),
            binding("NOT_LOOPBACK", "other-secret", "127.0.0.1".into()),
        ],
        EgressProxyConfig::default(),
    )?;
    let auth = proxy_auth(&broker)?;
    for authority in ["169.254.169.254", "127.0.0.1", "[::ffff:169.254.169.254]", "[::1]"] {
        let response = request(&broker, format!(
            "GET http://{authority}/ HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        ).as_bytes())?;
        assert!(response.starts_with(b"HTTP/1.1 403 "));
    }
    let response = request(&broker, format!(
        "CONNECT blocked.example:443 HTTP/1.1\r\nHost: BLOCKED.EXAMPLE.:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    ).as_bytes())?;
    assert!(response.starts_with(b"HTTP/1.1 403 "));
    let audit = broker.shutdown();
    assert_eq!(audit.len(), 5);
    assert!(matches!(
        audit[4],
        EgressEvent::Blocked { reason: EgressBlockReason::HostNotAllowed, .. }
    ));
    Ok(())
}

#[test]
fn allowed_connect_preserves_buffered_opaque_bytes_and_half_close() -> TestResult {
    let server = listener()?;
    let upstream = server.local_addr()?;
    let broker = EgressProxyBroker::start(
        vec![binding("API_KEY", SECRET, upstream.to_string())],
        EgressProxyConfig { tls_mitm_enabled: false, ..allow_loopback() },
    )?;
    assert!(broker.ephemeral_ca_bundle_path().is_none());
    let auth = proxy_auth(&broker)?;
    let backend = thread::spawn(move || -> io::Result<()> {
        let mut stream = accept(&server)?;
        let mut received = Vec::new();
        stream.read_to_end(&mut received)?;
        assert_eq!(received, b"opaque\x00bytes");
        stream.write_all(b"upstream\xff")?;
        Ok(())
    });
    let mut query = format!("CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\nProxy-Authorization: Basic {auth}\r\n\r\n").into_bytes();
    query.extend_from_slice(b"opaque\x00bytes");
    let response = request(&broker, &query)?;
    backend.join().map_err(|_| "upstream thread failed")??;
    assert_eq!(response, b"HTTP/1.1 200 Connection Established\r\n\r\nupstream\xff");
    assert_eq!(broker.shutdown(), []);
    Ok(())
}

#[test]
fn host_rules_normalize_and_enforce_label_boundaries_and_ports() -> TestResult {
    let rule = HostRule::parse("*.Stripe.Com.:443").ok_or("invalid rule")?;
    let cases = [
        ("API.STRIPE.COM.:443", true),
        ("deep.api.stripe.com:443", true),
        ("api.stripe.com:80", false),
        ("stripe.com:443", false),
        ("badstripe.com:443", false),
        ("api.stripe.com.attacker.test:443", false),
    ];
    for (input, expected) in cases {
        let target = Authority::parse(input, None).ok_or("invalid target")?;
        assert_eq!(rule.matches(&target), expected);
    }
    for rule in ["*", "*.*.example.com", "*.127.0.0.1", "user@example.com"] {
        assert!(matches!(
            EgressProxyBroker::start(vec![binding("TEST", SECRET, rule.into())], allow_loopback()),
            Err(EgressProxyError::InvalidBinding)
        ));
    }
    let invalid = EgressSecretBinding {
        env_name: "API_KEY".into(),
        secret_value: env_value(SECRET),
        allowed_hosts: vec![],
    };
    assert!(matches!(
        EgressProxyBroker::start(vec![invalid], allow_loopback()),
        Err(EgressProxyError::InvalidBinding)
    ));
    for ip in [
        "169.254.169.254",
        "10.0.0.1",
        "172.31.0.1",
        "192.168.0.1",
        "::ffff:10.0.0.1",
        "fc00::1",
        "fe80::1",
    ] {
        assert!(!permitted(ip.parse()?, true));
    }
    assert!(permitted("127.0.0.1".parse()?, true));
    assert!(!permitted("127.0.0.1".parse()?, false));
    Ok(())
}

#[test]
fn broker_shuts_down_with_an_idle_client() -> TestResult {
    let broker = EgressProxyBroker::start(vec![], EgressProxyConfig::default())?;
    let address: SocketAddr = broker.local_addr();
    assert!(address.ip().is_loopback());
    let mut stream = TcpStream::connect_timeout(&address, WAIT)?;
    stream.set_read_timeout(Some(WAIT))?;
    assert_eq!(broker.shutdown(), []);
    let mut byte = [0; 1];
    assert!(matches!(stream.read(&mut byte), Ok(0) | Err(_)));
    assert!(TcpStream::connect_timeout(&address, WAIT).is_err());
    Ok(())
}

#[test]
fn embedded_basic_credentials_are_substituted_and_redacted_as_a_unit() -> TestResult {
    let server = listener()?;
    let upstream = server.local_addr()?;
    let broker = EgressProxyBroker::start(
        vec![binding("API_KEY", SECRET, upstream.to_string())],
        allow_loopback(),
    )?;
    let auth = proxy_auth(&broker)?;
    let env = broker.child_env_overrides();
    let token = env["API_KEY"].as_str();
    let encoded_token = BASE64.encode(format!("untrusted-user:{token}").as_bytes());
    let encoded_secret = BASE64.encode(format!("untrusted-user:{SECRET}").as_bytes());
    let echoed = encoded_secret.clone();
    let backend = thread::spawn(move || -> io::Result<()> {
        let mut socket = accept(&server)?;
        let (head, _) = receive(&socket)?;
        assert!(head.contains(&format!("Authorization: Basic {echoed}\r\n")));
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nX-Credential: Basic {echoed}\r\nContent-Length: {}\r\n\r\n{echoed}",
            echoed.len()
        )?;
        Ok(())
    });
    let response = request(&broker, format!(
        "GET http://{upstream}/ HTTP/1.1\r\nHost: {upstream}\r\nProxy-Authorization: Basic {auth}\r\nAuthorization: Basic {encoded_token}\r\n\r\n"
    ).as_bytes())?;
    backend.join().map_err(|_| "upstream thread failed")??;
    let response = String::from_utf8(response)?;
    assert!(response.contains("X-Credential: Basic [REDACTED:locket]\r\n"));
    assert!(response.ends_with("\r\n\r\n[REDACTED:locket]"));
    assert!(!response.contains(&encoded_secret));
    assert!(matches!(&broker.shutdown()[..], [EgressEvent::Allowed { .. }]));
    Ok(())
}

#[test]
fn rejects_line_breaks_and_nul_in_secret_bindings_at_startup() {
    for tls_mitm_enabled in [false, true] {
        let config = EgressProxyConfig { tls_mitm_enabled, ..EgressProxyConfig::default() };
        for secret in ["foo\rbar", "foo\nbar", "foo\0bar", "foo\r\n\r\nbar"] {
            let secret_binding = binding("API_KEY", secret, "example.com".into());
            assert!(matches!(
                EgressProxyBroker::start(vec![secret_binding], config.clone()),
                Err(EgressProxyError::InvalidBinding)
            ));
        }
    }
}

#[test]
fn proxy_credentials_and_placeholders_are_rejected_in_request_structure() -> TestResult {
    use std::collections::BTreeSet;

    use super::substitution::Field;

    let broker = EgressProxyBroker::start(
        vec![binding("API_KEY", SECRET, "example.test".into())],
        EgressProxyConfig { tls_mitm_enabled: false, ..EgressProxyConfig::default() },
    )?;
    let state = &broker.state;
    let target = Authority::parse("example.test", Some(80)).ok_or("invalid fixture host")?;
    let env = broker.child_env_overrides();
    let placeholder = env["API_KEY"].as_bytes();
    let credential = proxy_auth(&broker)?;
    assert!(!state.authorized(b"Not-Basic supplied"));
    assert!(matches!(
        state.guard_structure(credential.as_bytes(), &target),
        Err(error) if error.reason == EgressBlockReason::ProxyCredential
    ));
    assert!(matches!(
        state.guard_structure(placeholder, &target),
        Err(error) if error.reason == EgressBlockReason::InvalidRequest
    ));
    let mut used = BTreeSet::new();
    for authorization in [b"Basic not valid base64".as_slice(), b"Basic dXNlcjpwYXNz"] {
        assert!(matches!(state.rewrite_basic(authorization, &target, &mut used, 1024), Ok(None)));
    }
    assert!(used.is_empty());
    assert!(matches!(state.rewrite(b"static", Field::Header, 1024, &target, &mut used), Ok(None)));
    assert_eq!(broker.shutdown(), []);
    Ok(())
}

#[test]
fn secret_like_authorities_are_rejected_and_omitted_from_audits() -> TestResult {
    let broker = EgressProxyBroker::start(
        vec![binding("API_KEY", "synthetic-sensitive-host", "example.test".into())],
        EgressProxyConfig { tls_mitm_enabled: false, ..EgressProxyConfig::default() },
    )?;
    let target = Authority::parse("synthetic-sensitive-host.example.test", Some(80))
        .ok_or("invalid fixture host")?;
    let state = &broker.state;
    let rejection = state.guard_authority("synthetic-sensitive-host.example.test", &target);
    assert!(matches!(rejection, Err(error) if error.reason == EgressBlockReason::InvalidRequest));
    state.audit(Some(&target), None, Some(EgressBlockReason::InvalidRequest));
    state.stopping.store(true, std::sync::atomic::Ordering::Relaxed);
    state.audit(Some(&target), None, Some(EgressBlockReason::UpstreamUnavailable));
    assert!(matches!(
        &broker.shutdown()[..],
        [EgressEvent::Blocked { target_host, .. }] if target_host.is_empty()
    ));
    Ok(())
}

#[test]
fn substitution_preserves_encoded_forms_and_bounds_basic_headers() -> TestResult {
    use std::collections::BTreeSet;

    use super::substitution::Field;

    let broker = EgressProxyBroker::start(
        vec![binding("API_KEY", "fixture?", "example.test".into())],
        EgressProxyConfig { tls_mitm_enabled: false, ..EgressProxyConfig::default() },
    )?;
    let state = &broker.state;
    let target = Authority::parse("example.test", Some(80)).ok_or("invalid fixture host")?;
    let env = broker.child_env_overrides();
    let placeholder = env["API_KEY"].as_bytes();
    let encoded = BASE64.encode(placeholder);
    let first = encoded.as_bytes()[0];
    let target_bytes = format!("/path/%{first:02X}{}", &encoded[1..]);
    let mut used = BTreeSet::new();
    let malformed = format!("/path/%ZZ{}", &encoded[1..]);
    assert!(matches!(
        state.rewrite(malformed.as_bytes(), Field::Target, 1024, &target, &mut used),
        Ok(None)
    ));
    assert_eq!(used, BTreeSet::new());

    let rewritten = state
        .rewrite(target_bytes.as_bytes(), Field::Target, 1024, &target, &mut used)
        .map_err(|_| "substitution failed")?
        .ok_or("substitution missing")?;
    let expected = Form::Url.encode(BASE64.encode(b"fixture?").as_bytes());
    assert_eq!(&rewritten[b"/path/".len()..], expected.as_slice());
    assert_eq!(used, BTreeSet::from([0]));

    let authorization = format!("Basic {}", BASE64.encode(placeholder));
    assert!(matches!(
        state.rewrite_basic(authorization.as_bytes(), &target, &mut used, 12),
        Err(error) if error.reason == EgressBlockReason::InvalidRequest
    ));
    Ok(())
}
