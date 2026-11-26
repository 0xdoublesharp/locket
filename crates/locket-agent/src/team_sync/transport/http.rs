use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs as _};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use zeroize::Zeroizing;

use super::{PACKAGE_LIMIT, PutOutcome, Result, reject};
use crate::team_sync::SyncError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const HEADER_LIMIT: usize = 32 * 1024;
const CHUNK_OVERHEAD_LIMIT: usize = 1024 * 1024;
const MAX_CONCURRENT_LOOKUPS: usize = 8;
const MAX_RESOLVED_ADDRESSES: usize = 32;
static ACTIVE_LOOKUPS: AtomicUsize = AtomicUsize::new(0);

/// A validated HTTP origin and canonical percent-encoded base path.
pub(super) struct Endpoint {
    tls: bool,
    host: String,
    authority: String,
    port: u16,
    pub(super) path: String,
}

impl Endpoint {
    pub(super) fn parse(raw: &str) -> Result<Self> {
        if raw.len() > 4096
            || raw.contains(['?', '#', '\\'])
            || raw.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(reject("invalid team transport URL"));
        }
        let (scheme, rest) =
            raw.split_once("://").ok_or_else(|| reject("invalid team transport URL"))?;
        let tls = match scheme {
            "https" => true,
            "http" => false,
            _ => return Err(reject("team transport URL must use HTTPS")),
        };
        let (authority, path) = rest.find('/').map_or((rest, ""), |index| rest.split_at(index));
        let (host, port) = parse_authority(authority)?;
        if !tls && !matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") {
            return Err(reject("plain HTTP team transports are limited to loopback"));
        }
        let authority = if host.contains(':') { format!("[{host}]") } else { host.clone() };
        let authority =
            port.map_or_else(|| authority.clone(), |port| format!("{authority}:{port}"));
        let path = normalize_path(path)?;
        Ok(Self { tls, host, authority, port: port.unwrap_or(if tls { 443 } else { 80 }), path })
    }

    pub(super) fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}{}", self.authority, self.path)
    }

    pub(super) fn host_header(&self) -> &str {
        &self.authority
    }

    pub(super) fn same_origin(&self, other: &Self) -> bool {
        self.tls == other.tls && self.port == other.port && self.host == other.host
    }

    pub(super) fn request(
        &self,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        cap: usize,
    ) -> Result<Response> {
        let header_bytes: usize =
            headers.iter().map(|(name, value)| name.len() + value.len() + 4).sum();
        let capacity = method.len() + target.len() + self.authority.len() + header_bytes + 100;
        let mut head = Zeroizing::new(Vec::with_capacity(capacity));
        write!(
            head,
            "{method} {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            self.authority,
            body.len()
        )
        .map_err(http_io)?;
        for (name, value) in headers {
            if value.bytes().any(|byte| !matches!(byte, b'\t' | b' '..=b'~')) {
                return Err(reject("invalid team transport request header"));
            }
            write!(head, "{name}: {value}\r\n").map_err(http_io)?;
        }
        head.extend_from_slice(b"\r\n");

        let mut socket = TimedSocket::connect(self)?;
        if self.tls {
            let name = ServerName::try_from(self.host.clone())
                .map_err(|_| reject("invalid team transport TLS server name"))?;
            let mut conn = ClientConnection::new(tls_config()?, name)
                .map_err(|_| reject("team transport TLS setup failed"))?;
            while conn.is_handshaking() {
                conn.complete_io(&mut socket).map_err(|_| {
                    reject("team transport TLS handshake or certificate validation failed")
                })?;
            }
            exchange(StreamOwned::new(conn, socket), method, &head, body, cap)
        } else {
            exchange(socket, method, &head, body, cap)
        }
    }
}

fn parse_authority(authority: &str) -> Result<(String, Option<u16>)> {
    let invalid = || reject("invalid team transport URL authority");
    if authority.contains('@') {
        return Err(reject("team transport URL must not include user information"));
    }
    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let (host, suffix) = ipv6.split_once(']').ok_or_else(invalid)?;
        let host: Ipv6Addr = host.parse().map_err(|_| invalid())?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or_else(invalid)?)
        };
        (host.to_string(), port)
    } else {
        let (host, port) =
            authority.split_once(':').map_or((authority, None), |(host, port)| (host, Some(port)));
        if host.len() > 253 || !host.split('.').all(valid_dns_label) {
            return Err(invalid());
        }
        (host.to_ascii_lowercase(), port)
    };
    let port = port
        .map(|port| {
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            port.parse::<u16>().ok().filter(|port| *port != 0).ok_or_else(invalid)
        })
        .transpose()?;
    Ok((host, port))
}

pub(super) fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub(super) fn normalize_path(path: &str) -> Result<String> {
    let mut normalized = String::new();
    for segment in path.split('/').skip(1) {
        let segment = decode(segment)?;
        if matches!(segment.as_str(), "." | "..")
            || segment.contains(['/', '\\'])
            || segment.chars().any(char::is_control)
        {
            return Err(reject("invalid team transport URL path"));
        }
        normalized.push('/');
        normalized.push_str(&encode(&segment, false));
    }
    Ok(normalized)
}

pub(super) fn encode(value: &str, keep_slash: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && byte == b'/')
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    encoded
}

pub(super) fn decode(value: &str) -> Result<String> {
    let invalid = || reject("invalid percent encoding in team transport path");
    let mut bytes = value.bytes();
    let mut decoded = Vec::with_capacity(value.len());
    while let Some(byte) = bytes.next() {
        let byte = if byte == b'%' {
            let mut hex = bytes.by_ref().take(2).map(|b| char::from(b).to_digit(16));
            let hi = hex.next().flatten().ok_or_else(invalid)?;
            let lo = hex.next().flatten().ok_or_else(invalid)?;
            u8::try_from((hi << 4) | lo).map_err(|_| invalid())?
        } else {
            byte
        };
        decoded.push(byte);
    }
    String::from_utf8(decoded).map_err(|_| invalid())
}

fn tls_config() -> Result<Arc<ClientConfig>> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(config) = CONFIG.get() {
        return Ok(Arc::clone(config));
    }
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if roots.is_empty() {
        return Err(reject("no usable native TLS root certificates"));
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| reject("team transport TLS setup failed"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::clone(CONFIG.get_or_init(|| Arc::new(config))))
}

struct LookupSlot;

impl Drop for LookupSlot {
    fn drop(&mut self) {
        ACTIVE_LOOKUPS.fetch_sub(1, Ordering::Relaxed);
    }
}

fn resolve(endpoint: &Endpoint, deadline: Instant) -> Result<Vec<SocketAddr>> {
    let port = endpoint.port;
    if let Ok(ip) = endpoint.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    // Never send cleartext credentials to an address obtained from DNS.
    if endpoint.host == "localhost" {
        return Ok(vec![
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port),
        ]);
    }
    ACTIVE_LOOKUPS
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < MAX_CONCURRENT_LOOKUPS).then_some(count + 1)
        })
        .map_err(|_| reject("too many active team transport DNS lookups"))?;

    let slot = LookupSlot;
    let host = endpoint.host.clone();
    let (send, receive) = mpsc::sync_channel(1);
    // Native DNS can block beyond the connect deadline. Keep worker count
    // bounded even when the OS resolver is slow to return.
    std::thread::Builder::new()
        .name("team-sync-dns".into())
        .spawn(move || {
            let _slot = slot;
            let result = (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.take(MAX_RESOLVED_ADDRESSES).collect());
            let _ = send.send(result);
        })
        .map_err(http_io)?;
    receive
        .recv_timeout(remaining(deadline).map_err(http_io)?)
        .map_err(|_| reject("team transport DNS lookup timed out"))?
        .map_err(|_| reject("team transport DNS lookup failed"))
}

struct TimedSocket {
    socket: TcpStream,
    write_deadline: Instant,
    read_deadline: Option<Instant>,
}

impl TimedSocket {
    fn connect(endpoint: &Endpoint) -> Result<Self> {
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        for address in resolve(endpoint, deadline)? {
            let timeout = remaining(deadline).map_err(http_io)?;
            if let Ok(socket) = TcpStream::connect_timeout(&address, timeout) {
                return Ok(Self {
                    socket,
                    write_deadline: Instant::now() + IO_TIMEOUT,
                    read_deadline: None,
                });
            }
        }
        Err(reject("team transport connection failed"))
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
}

impl Read for TimedSocket {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let deadline = *self.read_deadline.get_or_insert_with(|| Instant::now() + IO_TIMEOUT);
        self.socket.set_read_timeout(Some(remaining(deadline)?))?;
        self.socket.read(output)
    }
}

impl Write for TimedSocket {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(remaining(self.write_deadline)?))?;
        self.socket.write(input)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

pub(super) struct Response {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
}

impl Response {
    pub(super) fn require_status(self, expected: u16, operation: &str) -> Result<Vec<u8>> {
        if self.status == expected {
            Ok(self.body)
        } else {
            Err(status_error(operation, self.status))
        }
    }
}

fn exchange(
    mut stream: impl Read + Write,
    method: &str,
    headers: &[u8],
    body: &[u8],
    cap: usize,
) -> Result<Response> {
    stream
        .write_all(headers)
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(http_io)?;
    let mut stream = BufReader::new(stream);
    for _ in 0..8 {
        let (status, framing) = read_head(&mut stream)?;
        if status == 101 || (300..400).contains(&status) {
            return Err(reject("team transport HTTP redirect or protocol upgrade rejected"));
        }
        if status < 200 {
            continue;
        }
        // Skip all error bodies. Remote header values and error text are
        // untrusted and can reflect credentials.
        let body = if method == "HEAD" || status == 204 || status == 205 || status >= 400 {
            Vec::new()
        } else {
            read_body(&mut stream, framing, cap)?
        };
        return Ok(Response { status, body });
    }
    Err(invalid_response())
}

#[derive(Clone, Copy)]
enum Framing {
    Sized(usize),
    Chunked,
    Eof,
}

fn read_head(reader: &mut impl BufRead) -> Result<(u16, Framing)> {
    let mut buffer = Vec::new();
    let mut budget = HEADER_LIMIT;
    let status_line = read_line(reader, &mut buffer, &mut budget)?;
    let (version, code) = status_line.split_once(' ').ok_or_else(invalid_response)?;
    let code = code.split(' ').next().ok_or_else(invalid_response)?;
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0")
        || code.len() != 3
        || !code.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid_response());
    }
    let status = code.parse::<u16>().map_err(|_| invalid_response())?;
    if !(100..600).contains(&status) {
        return Err(invalid_response());
    }
    let mut length = None;
    let mut chunked = false;
    loop {
        let line = read_line(reader, &mut buffer, &mut budget)?;
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or_else(invalid_response)?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return Err(invalid_response());
        }
        let value = value.trim_ascii();
        if name.eq_ignore_ascii_case("Content-Length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid_response());
            }
            length = Some(value.parse().map_err(|_| invalid_response())?);
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(invalid_response());
            }
            chunked = true;
        }
    }
    let framing = match (length, chunked) {
        (Some(_), true) => return Err(invalid_response()),
        (Some(length), false) => Framing::Sized(length),
        (None, true) => Framing::Chunked,
        (None, false) => Framing::Eof,
    };
    Ok((status, framing))
}

fn read_line<'a>(
    reader: &mut impl BufRead,
    buffer: &'a mut Vec<u8>,
    budget: &mut usize,
) -> Result<&'a str> {
    buffer.clear();
    let count = reader.take(*budget as u64).read_until(b'\n', buffer).map_err(http_io)?;
    *budget -= count;
    let line = buffer.strip_suffix(b"\r\n").ok_or_else(invalid_response)?;
    std::str::from_utf8(line).map_err(|_| invalid_response())
}

fn read_body(reader: &mut impl BufRead, framing: Framing, cap: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    match framing {
        Framing::Sized(length) => append_exact(reader, &mut body, length, cap)?,
        Framing::Eof => {
            reader.take((cap + 1) as u64).read_to_end(&mut body).map_err(http_io)?;
            if body.len() > cap {
                return Err(SyncError::RemoteBodyTooLarge);
            }
        }
        Framing::Chunked => {
            let mut budget = CHUNK_OVERHEAD_LIMIT;
            let mut buffer = Vec::new();
            loop {
                let line = read_line(reader, &mut buffer, &mut budget)?;
                let size = line.split(';').next().ok_or_else(invalid_response)?;
                if size.is_empty() || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(invalid_response());
                }
                let size = usize::from_str_radix(size, 16).map_err(|_| invalid_response())?;
                if size == 0 {
                    while !read_line(reader, &mut buffer, &mut budget)?.is_empty() {}
                    break;
                }
                append_exact(reader, &mut body, size, cap)?;
                let mut delimiter = [0; 2];
                reader.read_exact(&mut delimiter).map_err(http_io)?;
                if &delimiter != b"\r\n" {
                    return Err(invalid_response());
                }
            }
        }
    }
    Ok(body)
}

fn append_exact(reader: &mut impl Read, body: &mut Vec<u8>, size: usize, cap: usize) -> Result<()> {
    if size > cap - body.len() {
        return Err(SyncError::RemoteBodyTooLarge);
    }
    let offset = body.len();
    body.resize(offset + size, 0);
    reader.read_exact(&mut body[offset..]).map_err(http_io)
}

fn http_io(error: io::Error) -> SyncError {
    let kind = error.kind();
    drop(error);
    if matches!(kind, io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
        reject("team transport HTTP operation timed out")
    } else {
        reject("team transport HTTP I/O failed")
    }
}

fn invalid_response() -> SyncError {
    reject("invalid team transport HTTP response")
}

fn status_error(operation: &str, status: u16) -> SyncError {
    reject(&format!("team transport {operation} failed with HTTP {status}"))
}

pub(super) fn put_package(
    bytes: &[u8],
    request: impl Fn(&str, &[(&str, &str)], &[u8], usize) -> Result<Response>,
) -> Result<PutOutcome> {
    if bytes.len() > PACKAGE_LIMIT {
        return Err(reject("oversized package"));
    }
    let compare = || match request("GET", &[], &[], PACKAGE_LIMIT) {
        Ok(Response { status: 200, body }) if body == bytes => Ok(PutOutcome::AlreadyPresent),
        Ok(Response { status: 200 | 404, .. }) | Err(SyncError::RemoteBodyTooLarge) => {
            Ok(PutOutcome::Conflict)
        }
        Ok(response) => Err(status_error("compare", response.status)),
        Err(error) => Err(error),
    };
    match request("HEAD", &[], &[], 0)?.status {
        200 | 204 => return compare(),
        404 | 405 | 501 => {}
        status => return Err(status_error("HEAD", status)),
    }
    let headers = [("if-none-match", "*"), ("content-type", "application/octet-stream")];
    match request("PUT", &headers, bytes, HEADER_LIMIT)?.status {
        200 | 201 | 204 => Ok(PutOutcome::Written),
        409 | 412 => compare(),
        status => Err(status_error("PUT", status)),
    }
}
