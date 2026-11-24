use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use data_encoding::BASE64;

use super::destination::{Authority, HostRule, permitted};
use super::wire::{Framing, Wire, framing, parse_head};
use super::{
    EgressBlockReason, EgressEvent, EgressProxyBroker, EgressProxyConfig, EgressProxyError,
    EgressSecretBinding,
};
use crate::env_value;
use crate::secret_encoding::Form;

const SECRET: &str = "synthetic-&echo=\"value\"";
const WAIT: Duration = Duration::from_secs(5);
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn binding(name: &str, secret: &str, host: String) -> EgressSecretBinding {
    EgressSecretBinding {
        env_name: name.into(),
        secret_value: env_value(secret),
        allowed_hosts: vec![host],
    }
}

fn allow_loopback() -> EgressProxyConfig {
    EgressProxyConfig {
        allow_private_destinations_for_allowed_hosts: true,
        ..EgressProxyConfig::default()
    }
}

fn proxy_auth(broker: &EgressProxyBroker) -> Result<String, io::Error> {
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

fn listener() -> io::Result<TcpListener> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn accept(listener: &TcpListener) -> io::Result<TcpStream> {
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

fn receive(upstream: &TcpStream) -> io::Result<(String, Vec<u8>)> {
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
        allow_loopback(),
    )?;
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
