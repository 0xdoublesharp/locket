use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use zeroize::{Zeroize, Zeroizing};

pub(super) const HEAD_LIMIT: usize = 64 * 1024;
pub(super) const BODY_LIMIT: usize = 10 * 1024 * 1024;

pub(super) struct Wire<'a> {
    stream: &'a TcpStream,
    stopping: &'a AtomicBool,
    deadline: Instant,
    buffer: Zeroizing<[u8; 8192]>,
    start: usize,
    end: usize,
}

impl<'a> Wire<'a> {
    pub(super) fn new(stream: &'a TcpStream, stopping: &'a AtomicBool, deadline: Instant) -> Self {
        Self { stream, stopping, deadline, buffer: Zeroizing::new([0; 8192]), start: 0, end: 0 }
    }

    pub(super) const fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }

    fn fill(&mut self) -> io::Result<()> {
        if self.start == self.end {
            self.end = retry(self.stopping, self.deadline, || self.stream.read(&mut *self.buffer))?;
            self.start = 0;
        }
        Ok(())
    }

    pub(super) fn head(&mut self) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut head = Zeroizing::new(Vec::with_capacity(HEAD_LIMIT));
        loop {
            let start = head.len();
            self.append_line(&mut head, HEAD_LIMIT)?;
            if &head[start..] == b"\r\n" {
                return Ok(head);
            }
        }
    }

    fn append_line(&mut self, bytes: &mut Vec<u8>, limit: usize) -> io::Result<()> {
        loop {
            self.fill()?;
            let available = &self.buffer[self.start..self.end];
            if available.is_empty() {
                return Err(invalid());
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let count = newline.map_or(available.len(), |position| position + 1);
            if count > limit - bytes.len() {
                return Err(invalid());
            }
            bytes.extend_from_slice(&available[..count]);
            self.consume(count);
            if newline.is_some() {
                return Ok(());
            }
        }
    }

    pub(super) fn copy_body(
        &mut self,
        framing: Framing,
        writer: &mut impl Write,
    ) -> io::Result<()> {
        match framing {
            Framing::Length(length) => self.copy_exact(length, writer),
            Framing::Eof => self.copy_until_eof(writer),
            Framing::Chunked => self.copy_chunks(writer),
        }
    }

    fn copy_exact(&mut self, mut length: usize, writer: &mut impl Write) -> io::Result<()> {
        while length > 0 {
            self.fill()?;
            let count = length.min(self.end - self.start);
            if count == 0 {
                return Err(invalid());
            }
            writer.write_all(&self.buffer[self.start..self.start + count])?;
            self.consume(count);
            length -= count;
        }
        Ok(())
    }

    fn copy_until_eof(&mut self, writer: &mut impl Write) -> io::Result<()> {
        // Connection-close response bodies and CONNECT streams have no framing
        // size limit. The socket deadlines bound how long a worker can be held.
        loop {
            self.fill()?;
            let count = self.end - self.start;
            if count == 0 {
                return Ok(());
            }
            writer.write_all(&self.buffer[self.start..self.end])?;
            self.consume(count);
        }
    }

    fn copy_chunks(&mut self, writer: &mut impl Write) -> io::Result<()> {
        let mut line = Zeroizing::new(Vec::with_capacity(HEAD_LIMIT));
        loop {
            self.append_line(&mut line, HEAD_LIMIT)?;
            let size = chunk_size(&line).ok_or_else(invalid)?;
            line.as_mut_slice().zeroize();
            line.clear();
            if size == 0 {
                // Trailers are discarded at the proxy boundary.
                self.head()?;
                return Ok(());
            }
            self.copy_exact(size, writer)?;
            self.append_line(&mut line, 2)?;
            if line.as_slice() != b"\r\n" {
                return Err(invalid());
            }
            line.clear();
        }
    }

    fn consume(&mut self, count: usize) {
        self.buffer[self.start..self.start + count].zeroize();
        self.start += count;
    }
}

pub(super) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP message")
}

pub(super) struct SocketWriter<'a> {
    pub(super) stream: &'a TcpStream,
    pub(super) stopping: &'a AtomicBool,
    pub(super) deadline: Instant,
}

impl Write for SocketWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        retry(self.stopping, self.deadline, || self.stream.write(bytes))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn retry<T>(
    stopping: &AtomicBool,
    deadline: Instant,
    mut operation: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    while !stopping.load(Ordering::Relaxed) && Instant::now() < deadline {
        match operation() {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            result => return result,
        }
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "proxy socket deadline"))
}

fn chunk_size(line: &[u8]) -> Option<usize> {
    let line = line.strip_suffix(b"\r\n")?;
    let size = line.split(|byte| *byte == b';').next()?;
    if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    usize::from_str_radix(std::str::from_utf8(size).ok()?, 16).ok()
}

#[derive(Clone, Copy)]
pub(super) struct Header<'a> {
    pub(super) name: &'a str,
    pub(super) value: &'a [u8],
}

pub(super) fn parse_head(bytes: &[u8]) -> Option<(&str, Vec<Header<'_>>)> {
    let mut lines = bytes.strip_suffix(b"\r\n\r\n")?.split(|byte| *byte == b'\n').peekable();
    let start = parse_line(&mut lines)?;
    let start = std::str::from_utf8(start).ok()?;
    let mut headers = Vec::new();
    while lines.peek().is_some() {
        let line = parse_line(&mut lines)?;
        let colon = line.iter().position(|byte| *byte == b':')?;
        let name = &line[..colon];
        let value = &line[colon + 1..];
        if name.is_empty() || !name.iter().all(|byte| token_byte(*byte)) || !valid_value(value) {
            return None;
        }
        headers.push(Header { name: std::str::from_utf8(name).ok()?, value: trim_ows(value) });
    }
    Some((start, headers))
}

fn parse_line<'a>(
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a [u8]>>,
) -> Option<&'a [u8]> {
    let line = lines.next()?;
    if lines.peek().is_some() { line.strip_suffix(b"\r") } else { Some(line) }
}

pub(super) fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

pub(super) fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^`_|~".contains(&byte)
}

pub(super) fn valid_value(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == b'\t' || (*byte >= b' ' && *byte != 0x7f))
}

pub(super) fn named<'a, 'b>(
    headers: &'a [Header<'b>],
    name: &'a str,
) -> impl Iterator<Item = &'b [u8]> + 'a {
    headers
        .iter()
        .filter(move |header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value)
}

pub(super) fn singleton<'a>(headers: &[Header<'a>], name: &str) -> Option<&'a [u8]> {
    let mut values = named(headers, name);
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Framing {
    Length(usize),
    Chunked,
    Eof,
}

pub(super) fn framing(headers: &[Header<'_>]) -> Option<Framing> {
    let mut size = None;
    for value in named(headers, "Content-Length") {
        if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let length: usize = std::str::from_utf8(value).ok()?.parse().ok()?;
        if size.is_some_and(|previous| previous != length) {
            return None;
        }
        size = Some(length);
    }
    let mut encodings = named(headers, "Transfer-Encoding");
    if let Some(encoding) = encodings.next() {
        return (size.is_none()
            && encoding.eq_ignore_ascii_case(b"chunked")
            && encodings.next().is_none())
        .then_some(Framing::Chunked);
    }
    Some(size.map_or(Framing::Eof, Framing::Length))
}

pub(super) fn connection_options<'a>(headers: &[Header<'a>]) -> Option<Vec<&'a str>> {
    let mut options = Vec::new();
    for value in named(headers, "Connection") {
        for token in value.split(|byte| *byte == b',').map(trim_ows) {
            if token.is_empty() || !token.iter().all(|byte| token_byte(*byte)) {
                return None;
            }
            options.push(std::str::from_utf8(token).ok()?);
        }
    }
    Some(options)
}

pub(super) fn hop_header(name: &str, connection: &[&str]) -> bool {
    [
        "Connection",
        "Proxy-Connection",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "Keep-Alive",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
    ]
    .into_iter()
    .chain(connection.iter().copied())
    .any(|field| name.eq_ignore_ascii_case(field))
}

pub(super) fn basic_payload(value: &[u8]) -> Option<&[u8]> {
    let separator = value.iter().position(|byte| *byte == b' ')?;
    value[..separator].eq_ignore_ascii_case(b"basic").then(|| trim_ows(&value[separator + 1..]))
}
