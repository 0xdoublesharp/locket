use std::thread;

use super::*;
use crate::egress_proxy::tests::{
    SECRET, TestResult, WAIT, accept, allow_loopback, binding, listener, proxy_auth, receive,
};
use crate::egress_proxy::{CA_BUNDLE_ENV, EgressEvent, EgressProxyBroker, EgressProxyConfig};

fn ca_pem(ca: &CertificateAuthority) -> io::Result<Vec<u8>> {
    let mut pem = Vec::new();
    write_pem(&mut pem, ca.cert.der())?;
    Ok(pem)
}

fn child_stream(
    broker: &EgressProxyBroker,
    authority: &str,
    host: &str,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn std::error::Error>> {
    const RESPONSE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    let path = broker.ephemeral_ca_bundle_path().ok_or("no child trust bundle")?;
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(path)? {
        roots.add(cert?)?;
    }
    let mut socket = TcpStream::connect_timeout(&broker.local_addr(), WAIT)?;
    socket.set_read_timeout(Some(WAIT))?;
    socket.set_write_timeout(Some(WAIT))?;
    let auth = proxy_auth(broker)?;
    let mut conn =
        ClientConnection::new(client_config(roots)?, ServerName::try_from(host.to_owned())?)?;
    let mut connect = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    ).into_bytes();
    // Coalesce ClientHello and CONNECT to exercise buffered transport handoff.
    conn.write_tls(&mut connect)?;
    socket.write_all(&connect)?;
    let mut received = [0; RESPONSE.len()];
    socket.read_exact(&mut received)?;
    assert_eq!(&received, RESPONSE);
    Ok(StreamOwned::new(conn, socket))
}

fn https_request(
    broker: &EgressProxyBroker,
    target: &str,
    host_header: &str,
    extra_headers: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let host = target.split_once(':').ok_or("missing test port")?.0;
    let mut client = child_stream(broker, target, host)?;
    let token = broker.child_env_overrides()["API_KEY"].clone();
    write!(
        client,
        "GET / HTTP/1.1\r\nHost: {host_header}\r\nAuthorization: Bearer {}\r\n{extra_headers}\r\n",
        token.as_str()
    )?;
    client.flush()?;
    let mut response = String::new();
    client.read_to_string(&mut response)?;
    Ok(response)
}

#[test]
fn https_delivers_secret_and_redacts_headers_body_and_redirects() -> TestResult {
    let server = listener()?;
    let target = format!("localhost:{}", server.local_addr()?.port());
    let ca = CertificateAuthority::new()?;
    let config = ca.server_config("localhost")?;
    let broker = EgressProxyBroker::start(
        vec![binding("API_KEY", SECRET, target.clone())],
        EgressProxyConfig { extra_upstream_root_pem: Some(ca_pem(&ca)?), ..allow_loopback() },
    )?;
    let env = broker.child_env_overrides();
    let path = broker.ephemeral_ca_bundle_path().ok_or("no child trust bundle")?.to_owned();
    for name in CA_BUNDLE_ENV {
        assert_eq!(Some(env[name].as_str()), path.to_str());
    }
    for name in ["ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"] {
        assert!(env[name].is_empty());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    }
    let bundle = std::fs::read(&path)?;
    assert!(!String::from_utf8_lossy(&bundle).contains("PRIVATE KEY"));
    let other = EgressProxyBroker::start(vec![], EgressProxyConfig::default())?;
    let other_path = other.ephemeral_ca_bundle_path().ok_or("no second child trust bundle")?;
    assert_ne!(
        CertificateDer::pem_slice_iter(&bundle).last().transpose()?,
        CertificateDer::pem_file_iter(other_path)?.last().transpose()?,
    );
    drop(other);

    let origin = target.clone();
    let backend = thread::spawn(move || -> io::Result<()> {
        let socket = accept(&server)?;
        let mut tls =
            StreamOwned::new(ServerConnection::new(config).map_err(io::Error::other)?, socket);
        let (head, _) = receive(&mut tls)?;
        assert!(head.contains(&format!("Authorization: Bearer {SECRET}\r\n")));
        assert!(!head.contains("lk_egress_"));
        assert!(!head.contains("Proxy-Authorization"));
        write!(
            tls,
            "HTTP/1.1 302 Found\r\nSet-Cookie: key={SECRET}\r\nLocation: https://example.com/bounce\r\nLocation: //example.com/bounce\r\nLocation: http://{origin}/downgrade\r\nLocation: /echo?key={SECRET}\r\nContent-Length: {}\r\n\r\n{SECRET}",
            SECRET.len()
        )?;
        tls.conn.send_close_notify();
        tls.flush()
    });
    let response = https_request(&broker, &target, &target, "")?;
    backend.join().map_err(|_| "HTTPS upstream thread failed")??;
    assert!(response.starts_with("HTTP/1.1 302 "));
    assert!(response.contains("Set-Cookie: key=[REDACTED:locket]\r\n"));
    assert!(response.contains("Location: /echo?key=[REDACTED:locket]\r\n"));
    assert_eq!(response.matches("Location:").count(), 1);
    assert!(response.ends_with("\r\n\r\n[REDACTED:locket]"));
    assert!(!response.contains(SECRET));
    assert!(matches!(&broker.shutdown()[..], [EgressEvent::Allowed { env_name, target_host, .. }]
        if env_name == "API_KEY" && target_host == "localhost"));
    assert!(!path.exists());
    Ok(())
}

#[test]
fn https_rejects_disallowed_placeholder_without_contacting_upstream() -> TestResult {
    let server = listener()?;
    let target = server.local_addr()?.to_string();
    let broker = EgressProxyBroker::start(
        vec![
            binding("API_KEY", SECRET, "example.com".into()),
            binding("OTHER_KEY", "different-secret", target.clone()),
        ],
        allow_loopback(),
    )?;
    let response = https_request(&broker, &target, &target, "")?;
    assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert_eq!(server.accept().err().map(|error| error.kind()), Some(io::ErrorKind::WouldBlock));
    assert!(matches!(&broker.shutdown()[..], [EgressEvent::Blocked {
        env_name, target_host, reason: EgressBlockReason::HostNotAllowed, ..
    }] if env_name == "API_KEY" && target_host == "127.0.0.1"));
    Ok(())
}

#[test]
fn https_rejects_host_mismatch_and_ambiguous_framing() -> TestResult {
    let server = listener()?;
    let target = server.local_addr()?.to_string();
    let broker = EgressProxyBroker::start(
        vec![binding("API_KEY", SECRET, target.clone())],
        allow_loopback(),
    )?;
    for (host, extra_headers) in [
        ("wrong.example", ""),
        (target.as_str(), "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n"),
    ] {
        assert!(https_request(&broker, &target, host, extra_headers)?.starts_with("HTTP/1.1 400 "));
    }
    assert_eq!(server.accept().err().map(|error| error.kind()), Some(io::ErrorKind::WouldBlock));
    let audit = broker.shutdown();
    assert_eq!(audit.len(), 2);
    assert!(audit.iter().all(|event| matches!(
        event,
        EgressEvent::Blocked { reason: EgressBlockReason::InvalidRequest, .. }
    )));
    Ok(())
}

#[test]
fn https_rejects_secret_with_header_line_breaks() -> TestResult {
    let server = listener()?;
    let target = server.local_addr()?.to_string();
    for secret in ["fake\rX-Injected: yes", "fake\nX-Injected: yes"] {
        let broker = EgressProxyBroker::start(
            vec![binding("API_KEY", secret, target.clone())],
            allow_loopback(),
        )?;
        assert!(https_request(&broker, &target, &target, "")?.starts_with("HTTP/1.1 400 "));
        assert!(matches!(
            &broker.shutdown()[..],
            [EgressEvent::Blocked { reason: EgressBlockReason::InvalidRequest, .. }]
        ));
    }
    assert_eq!(server.accept().err().map(|error| error.kind()), Some(io::ErrorKind::WouldBlock));
    Ok(())
}

#[test]
fn https_verifies_upstream_root_and_hostname_before_delivering_secret() -> TestResult {
    let ca = CertificateAuthority::new()?;
    let other_ca = CertificateAuthority::new()?;
    for (upstream_ca, san) in [(&other_ca, "127.0.0.1"), (&ca, "localhost")] {
        let server = listener()?;
        let target = server.local_addr()?.to_string();
        let config = upstream_ca.server_config(san)?;
        let broker = EgressProxyBroker::start(
            vec![binding("API_KEY", SECRET, target.clone())],
            EgressProxyConfig { extra_upstream_root_pem: Some(ca_pem(&ca)?), ..allow_loopback() },
        )?;
        let backend = thread::spawn(move || -> io::Result<()> {
            let socket = accept(&server)?;
            let mut tls =
                StreamOwned::new(ServerConnection::new(config).map_err(io::Error::other)?, socket);
            let mut byte = [0];
            let error = tls
                .read(&mut byte)
                .err()
                .ok_or_else(|| io::Error::other("expected the TLS handshake to fail"))?;
            assert!(matches!(
                error.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            ));
            assert!(tls.conn.is_handshaking());
            Ok(())
        });
        assert!(https_request(&broker, &target, &target, "")?.starts_with("HTTP/1.1 502 "));
        backend.join().map_err(|_| "HTTPS upstream thread failed")??;
        assert!(matches!(
            &broker.shutdown()[..],
            [EgressEvent::Blocked { reason: EgressBlockReason::UpstreamUnavailable, .. }]
        ));
    }
    Ok(())
}
