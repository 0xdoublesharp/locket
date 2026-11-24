use std::collections::BTreeSet;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Instant;

use zeroize::Zeroizing;

use super::destination::Authority;
use super::substitution::Field;
use super::wire::{self, BODY_LIMIT, Framing, HEAD_LIMIT, Header, SocketWriter, Wire};
use super::{EgressBlockReason, RESPONSE_TIMEOUT, Rejection, State};
use crate::StreamingRedactor;
use crate::streaming_redactor::RedactionPatterns;

pub(super) struct Request<'a> {
    method: &'a str,
    pub(super) authority: &'a str,
    path: &'a str,
}

impl<'a> Request<'a> {
    pub(super) fn parse_line(line: &'a str) -> Option<Self> {
        let (method, rest) = line.split_once(' ')?;
        let (target, version) = rest.split_once(' ')?;
        if version != "HTTP/1.1"
            || method.is_empty()
            || !method.bytes().all(wire::token_byte)
            || !target.bytes().all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'#' | b'\\'))
        {
            return None;
        }
        if method == "CONNECT" {
            return Some(Self { method, authority: target, path: "" });
        }
        let uri = target.get(7..)?;
        if !target.get(..7)?.eq_ignore_ascii_case("http://") {
            return None;
        }
        let (authority, path) =
            uri.find(['/', '?']).map_or((uri, ""), |position| uri.split_at(position));
        Some(Self { method, authority, path })
    }

    pub(super) fn connect(&self) -> bool {
        self.method == "CONNECT"
    }

    pub(super) fn framing(&self, headers: &[Header<'_>]) -> Option<usize> {
        if wire::named(headers, "Expect").next().is_some()
            || wire::named(headers, "Upgrade").next().is_some()
            || !is_identity(headers)
        {
            return None;
        }
        match wire::framing(headers)? {
            Framing::Eof | Framing::Length(0) => Some(0),
            Framing::Length(length) if !self.connect() && length <= BODY_LIMIT => Some(length),
            Framing::Length(_) | Framing::Chunked => None,
        }
    }
}

impl State {
    pub(super) fn check_connect(
        &self,
        request: &Request<'_>,
        headers: &[Header<'_>],
        destination: &Authority,
    ) -> Result<(), Rejection> {
        self.guard_structure(request.method.as_bytes(), destination)?;
        for header in headers {
            self.guard_structure(header.name.as_bytes(), destination)?;
            if !header.name.eq_ignore_ascii_case("Proxy-Authorization") {
                self.guard_structure(header.value, destination)?;
            }
        }
        if self.config.strict_connect_allowlist
            && !self
                .bindings
                .iter()
                .flat_map(|binding| &binding.hosts)
                .any(|rule| rule.matches(destination))
        {
            return Err(EgressBlockReason::HostNotAllowed.into());
        }
        Ok(())
    }
}

fn is_identity(headers: &[Header<'_>]) -> bool {
    wire::named(headers, "Content-Encoding")
        .all(|encoding| encoding.eq_ignore_ascii_case(b"identity"))
}

pub(super) fn forward(
    state: &State,
    request: &Request<'_>,
    headers: &[Header<'_>],
    client_input: &mut Wire<'_>,
    body_len: usize,
    destination: &Authority,
    client: &mut SocketWriter<'_>,
) -> Result<(), Rejection> {
    let mut used = BTreeSet::new();
    let mut embedded_echoes = Vec::new();
    let mut head =
        build_request_head(state, request, headers, destination, &mut used, &mut embedded_echoes)?;
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    client_input
        .copy_body(Framing::Length(body_len), &mut *body)
        .map_err(|_| EgressBlockReason::InvalidRequest)?;
    let body_rewritten = state.rewrite(&body, Field::Body, BODY_LIMIT, destination, &mut used)?;
    let final_body = body_rewritten.as_deref().map_or(body.as_slice(), Vec::as_slice);
    head.finish_request(final_body.len(), wire::named(headers, "Content-Length").next().is_some())
        .map_err(|_| EgressBlockReason::InvalidRequest)?;

    let upstream = state.connect(destination)?;
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    let mut upstream_output =
        SocketWriter { stream: &upstream, stopping: &state.stopping, deadline };
    upstream_output
        .write_all(&head.0)
        .and_then(|()| upstream_output.write_all(final_body))
        .map_err(|_| EgressBlockReason::UpstreamUnavailable)?;
    for index in used {
        state.audit(Some(destination), Some(index), None);
    }
    drop(head);
    drop(body_rewritten);
    drop(body);

    let mut input = Wire::new(&upstream, &state.stopping, deadline);
    client.deadline = deadline;
    let response = Response::read(&mut input, request.method)
        .map_err(|_| EgressBlockReason::UpstreamUnavailable)?;
    let response_patterns = state.response_patterns.with_additional_literals(embedded_echoes);
    let redacted_head = response
        .redacted_head(&response_patterns)
        .map_err(|_| EgressBlockReason::UpstreamUnavailable)?;

    // A failure once the response starts must close the socket.
    let _ignored = client.write_all(&redacted_head.0).and_then(|()| {
        let mut redactor = StreamingRedactor::with_patterns(client, response_patterns);
        input.copy_body(response.framing, &mut redactor)?;
        redactor.flush_final()
    });
    Ok(())
}

fn build_request_head(
    state: &State,
    request: &Request<'_>,
    headers: &[Header<'_>],
    destination: &Authority,
    used: &mut BTreeSet<usize>,
    embedded_echoes: &mut Vec<Zeroizing<Vec<u8>>>,
) -> Result<HeadBuffer, Rejection> {
    let invalid = EgressBlockReason::InvalidRequest;
    state.guard_structure(request.method.as_bytes(), destination)?;
    let connection = wire::connection_options(headers).ok_or(invalid)?;
    let path =
        state.rewrite(request.path.as_bytes(), Field::Target, HEAD_LIMIT, destination, used)?;
    let path = path.as_deref().map_or(request.path.as_bytes(), Vec::as_slice);
    let mut head = HeadBuffer(Zeroizing::new(Vec::with_capacity(HEAD_LIMIT)));
    let head_result = (|| -> io::Result<()> {
        write!(head, "{} ", request.method)?;
        if !path.starts_with(b"/") {
            head.write_all(b"/")?;
        }
        head.write_all(path)?;
        head.write_all(b" HTTP/1.1\r\nHost: ")?;
        destination.write_to(&mut head)?;
        head.write_all(b"\r\n")
    })();
    head_result.map_err(|_| invalid)?;

    for header in headers {
        state.guard_structure(header.name.as_bytes(), destination)?;
        if header.name.eq_ignore_ascii_case("Proxy-Authorization") {
            continue;
        }
        if wire::hop_header(header.name, &connection)
            || ["Host", "Content-Length", "Accept-Encoding", "Content-Encoding"]
                .iter()
                .any(|name| header.name.eq_ignore_ascii_case(name))
        {
            state.guard_structure(header.value, destination)?;
            continue;
        }
        let rewritten = if header.name.eq_ignore_ascii_case("Authorization") {
            state.rewrite_basic(header.value, destination, used, HEAD_LIMIT)?
        } else {
            None
        };
        let rewritten = if let Some(value) = rewritten {
            // Base64 encodes the surrounding Basic user as well as the value.
            if let Some(payload) = wire::basic_payload(&value) {
                embedded_echoes.push(Zeroizing::new(payload.to_vec()));
            }
            Some(value)
        } else {
            state.rewrite(header.value, Field::Header, HEAD_LIMIT, destination, used)?
        };
        let value = rewritten.as_deref().map_or(header.value, Vec::as_slice);
        if !wire::valid_value(value) {
            return Err(invalid.into());
        }
        write_header(&mut head, header.name.as_bytes(), value).map_err(|_| invalid)?;
    }
    Ok(head)
}

struct HeadBuffer(Zeroizing<Vec<u8>>);

impl HeadBuffer {
    fn finish_request(&mut self, body_len: usize, has_length: bool) -> io::Result<()> {
        self.write_all(b"Accept-Encoding: identity\r\n")?;
        if body_len > 0 || has_length {
            write!(self, "Content-Length: {body_len}\r\n")?;
        }
        self.write_all(b"Connection: close\r\n\r\n")
    }
}

impl Write for HeadBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > HEAD_LIMIT - self.0.len() {
            return Err(wire::invalid());
        }
        self.0.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_header(writer: &mut impl Write, name: &[u8], value: &[u8]) -> io::Result<()> {
    writer.write_all(name)?;
    writer.write_all(b": ")?;
    writer.write_all(value)?;
    writer.write_all(b"\r\n")
}

pub(super) fn empty_response(writer: &mut impl Write, status: &[u8]) -> io::Result<()> {
    writer.write_all(b"HTTP/1.1 ")?;
    writer.write_all(status)?;
    writer.write_all(b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

struct Response {
    head: Zeroizing<Vec<u8>>,
    framing: Framing,
    code: u16,
}

impl Response {
    fn read(input: &mut Wire<'_>, method: &str) -> io::Result<Self> {
        // A small number of informational responses, such as 103 Early Hints,
        // may precede the final response. They are never sent to the child.
        for _ in 0..8 {
            let head = input.head()?;
            let (line, headers) = wire::parse_head(&head).ok_or_else(wire::invalid)?;
            let code = parse_status(line).ok_or_else(wire::invalid)?;
            if code == 101 {
                return Err(wire::invalid());
            }
            if code < 200 {
                continue;
            }
            let framing = wire::framing(&headers).ok_or_else(wire::invalid)?;
            let framing = if method == "HEAD" || matches!(code, 204 | 205 | 304) {
                Framing::Length(0)
            } else if is_identity(&headers) {
                framing
            } else {
                // Do not forward a representation the redactor cannot inspect.
                return Err(wire::invalid());
            };
            wire::connection_options(&headers).ok_or_else(wire::invalid)?;
            return Ok(Self { head, framing, code });
        }
        Err(wire::invalid())
    }

    fn redacted_head(&self, patterns: &Arc<RedactionPatterns>) -> io::Result<HeadBuffer> {
        let (_, headers) = wire::parse_head(&self.head).ok_or_else(wire::invalid)?;
        let connection = wire::connection_options(&headers).ok_or_else(wire::invalid)?;
        // Generate the status line locally. Upstream reasons are arbitrary text.
        let mut head = HeadBuffer(Zeroizing::new(Vec::with_capacity(HEAD_LIMIT)));
        write!(head, "HTTP/1.1 {} \r\nConnection: close\r\n", self.code)?;
        for header in headers {
            if wire::hop_header(header.name, &connection)
                || ["Content-Length", "Content-Encoding", "Content-MD5", "Digest", "ETag"]
                    .iter()
                    .any(|name| header.name.eq_ignore_ascii_case(name))
                || patterns.contains(header.name.as_bytes())
            {
                continue;
            }
            head.write_all(header.name.as_bytes())?;
            head.write_all(b": ")?;
            let mut redactor = StreamingRedactor::with_patterns(&mut head, Arc::clone(patterns));
            redactor.write_all(header.value)?;
            redactor.flush_final()?;
            head.write_all(b"\r\n")?;
        }
        head.write_all(b"\r\n")?;
        Ok(head)
    }
}

fn parse_status(line: &str) -> Option<u16> {
    let (version, tail) = line.split_once(' ')?;
    let status = tail.split_once(' ').map_or(tail, |(status, _)| status);
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0")
        || status.len() != 3
        || !status.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let code = status.parse().ok()?;
    (100..=599).contains(&code).then_some(code)
}
