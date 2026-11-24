//! Authenticated loopback broker for domain-scoped HTTP secret delivery.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use data_encoding::{BASE64, HEXLOWER};
use rand::{TryRng as _, rngs::SysRng};
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::secret_encoding::encode;
use crate::streaming_redactor::RedactionPatterns;
use crate::{EnvMap, StreamingRedactorConfig, env_value};

mod destination;
mod http;
mod substitution;
mod wire;

use destination::{Authority, HostRule, Resolver, permitted};
use http::Request;
use substitution::Placeholder;
use wire::{SocketWriter, Wire};

const SOCKET_POLL: Duration = Duration::from_millis(100);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const TUNNEL_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_CONNECTIONS: usize = 16;

const PROXY_ENV: [&str; 4] = ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"];
const NO_PROXY_ENV: [&str; 2] = ["NO_PROXY", "no_proxy"];

/// A child environment variable whose plaintext is scoped to approved HTTP destinations.
///
/// Host rules support exact DNS names and IP literals, optional ports, and DNS
/// suffixes such as `*.example.com` that exclude the apex domain.
pub struct EgressSecretBinding {
    /// Child environment variable receiving the placeholder.
    pub env_name: String,
    /// Plaintext inserted into approved requests only.
    pub secret_value: Zeroizing<String>,
    /// Nonempty set of host rules authorized to receive the plaintext.
    pub allowed_hosts: Vec<String>,
}

/// Broker settings. Defaults block private destinations and unlisted CONNECT targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressProxyConfig {
    /// Permit loopback addresses only when an exact host rule authorizes the destination.
    /// Other private and special-use addresses remain blocked.
    pub allow_private_destinations_for_allowed_hosts: bool,
    /// Require a binding's host rule to authorize each CONNECT tunnel.
    pub strict_connect_allowlist: bool,
}

impl Default for EgressProxyConfig {
    fn default() -> Self {
        Self { allow_private_destinations_for_allowed_hosts: false, strict_connect_allowlist: true }
    }
}

/// Reason a broker request was rejected or could not be forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressBlockReason {
    /// Missing, repeated, or invalid proxy authentication.
    ProxyAuthentication,
    /// Invalid or unsupported HTTP framing, syntax, or substitution.
    InvalidRequest,
    /// The destination is outside the relevant host allowlist.
    HostNotAllowed,
    /// The destination is or resolves to a disallowed address.
    PrivateDestination,
    /// The request attempted to forward a proxy credential.
    ProxyCredential,
    /// The upstream could not be resolved or reached.
    UpstreamUnavailable,
}

/// Metadata-only audit event produced by the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressEvent {
    /// A binding was delivered to an approved upstream socket.
    Allowed {
        /// Environment variable name.
        env_name: String,
        /// Canonical destination hostname.
        target_host: String,
        /// Unix timestamp in nanoseconds.
        timestamp_unix_nanos: u128,
    },
    /// A request was prevented from reaching the requested upstream.
    Blocked {
        /// Environment variable name, or empty for a request-level rejection.
        env_name: String,
        /// Canonical destination hostname, or empty when unavailable or sensitive.
        target_host: String,
        /// Reason the request was rejected.
        reason: EgressBlockReason,
        /// Unix timestamp in nanoseconds.
        timestamp_unix_nanos: u128,
    },
}

/// Broker startup failure. Error messages contain no request or binding values.
#[derive(Debug, Error)]
pub enum EgressProxyError {
    /// A binding has an invalid or reserved name, no secret, or invalid host rules.
    #[error("invalid egress binding")]
    InvalidBinding,
    /// The operating system could not provide cryptographic randomness.
    #[error("egress credential generation failed")]
    Randomness,
    /// The loopback listener or its worker could not be started.
    #[error("could not start egress proxy")]
    Start,
}

/// An authenticated, loopback-only HTTP proxy for a single execution session.
///
/// Placeholder substitution applies to plaintext HTTP requests. CONNECT relays
/// opaque bytes after checking the destination, so it cannot substitute or redact
/// encrypted HTTPS traffic. The child environment configures proxy-aware clients.
pub struct EgressProxyBroker {
    address: SocketAddr,
    env: EnvMap,
    state: Arc<State>,
    listener: Option<JoinHandle<()>>,
}

struct Binding {
    env_name: String,
    placeholder: Placeholder,
    value: Zeroizing<String>,
    hosts: Vec<HostRule>,
}

struct State {
    config: EgressProxyConfig,
    bindings: Vec<Binding>,
    auth: Zeroizing<Vec<u8>>,
    proxy_credentials: Arc<RedactionPatterns>,
    response_patterns: Arc<RedactionPatterns>,
    resolver: Resolver,
    stopping: AtomicBool,
    events: Mutex<Vec<EgressEvent>>,
}

impl EgressProxyBroker {
    /// Starts the broker on an ephemeral IPv4 loopback port.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bindings, unavailable randomness, or an
    /// operating-system failure while starting the broker.
    pub fn start(
        bindings: Vec<EgressSecretBinding>,
        config: EgressProxyConfig,
    ) -> Result<Self, EgressProxyError> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| EgressProxyError::Start)?;
        listener.set_nonblocking(true).map_err(|_| EgressProxyError::Start)?;
        let address = listener.local_addr().map_err(|_| EgressProxyError::Start)?;
        let password = random_hex()?;
        let user_password = Zeroizing::new(format!("locket:{}", password.as_str()));
        let auth = encode(&BASE64, user_password.as_bytes());
        let proxy_url = Zeroizing::new(format!("http://{}@{address}", user_password.as_str()));
        let mut env = EnvMap::new();
        for name in PROXY_ENV {
            env.insert(name.into(), proxy_url.clone());
        }
        for name in NO_PROXY_ENV {
            env.insert(name.into(), env_value(""));
        }

        let bindings = prepare_bindings(bindings, &mut env)?;
        let response_secrets =
            bindings.iter().map(|binding| (String::new(), binding.value.clone()));
        let credentials = [password, user_password].map(|value| (String::new(), value));
        let state = Arc::new(State {
            config,
            proxy_credentials: make_patterns(credentials.clone()),
            response_patterns: make_patterns(response_secrets.chain(credentials)),
            bindings,
            auth,
            resolver: Resolver::new(),
            stopping: AtomicBool::new(false),
            events: Mutex::default(),
        });
        let shared = Arc::clone(&state);
        let listener = thread::Builder::new()
            .name("locket-egress".into())
            .spawn(move || listen(&listener, &shared))
            .map_err(|_| EgressProxyError::Start)?;
        Ok(Self { address, env, state, listener: Some(listener) })
    }

    /// Returns the bound loopback address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Returns placeholder values and proxy settings for the child environment.
    #[must_use]
    pub fn child_env_overrides(&self) -> EnvMap {
        self.env.clone()
    }

    /// Stops the broker, waits for managed connections, and returns its audit events.
    #[must_use]
    pub fn shutdown(mut self) -> Vec<EgressEvent> {
        self.stop();
        std::mem::take(
            &mut *self.state.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    fn stop(&mut self) {
        self.state.stopping.store(true, Ordering::Relaxed);
        if let Some(listener) = self.listener.take() {
            listener.thread().unpark();
            let _ignored = listener.join();
        }
    }
}

impl Drop for EgressProxyBroker {
    fn drop(&mut self) {
        self.stop();
    }
}

fn make_patterns(
    secrets: impl IntoIterator<Item = (String, Zeroizing<String>)>,
) -> Arc<RedactionPatterns> {
    RedactionPatterns::new(StreamingRedactorConfig {
        known_secrets: secrets.into_iter().collect(),
        min_secret_len: 1,
        ..StreamingRedactorConfig::default()
    })
}

fn random_hex() -> Result<Zeroizing<String>, EgressProxyError> {
    Ok(Zeroizing::new(HEXLOWER.encode(&*random_bytes::<16>()?)))
}

fn random_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, EgressProxyError> {
    let mut bytes = Zeroizing::new([0; N]);
    SysRng.try_fill_bytes(&mut *bytes).map_err(|_| EgressProxyError::Randomness)?;
    Ok(bytes)
}

fn prepare_bindings(
    bindings: Vec<EgressSecretBinding>,
    env: &mut EnvMap,
) -> Result<Vec<Binding>, EgressProxyError> {
    let mut names: BTreeSet<_> = env.keys().map(|key| key.to_ascii_uppercase()).collect();
    let mut output: Vec<Binding> = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let name = &binding.env_name;
        if name.is_empty()
            || binding.secret_value.is_empty()
            || binding.allowed_hosts.is_empty()
            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || name.as_bytes()[0].is_ascii_digit()
            || !names.insert(name.to_ascii_uppercase())
        {
            return Err(EgressProxyError::InvalidBinding);
        }
        let hosts = binding
            .allowed_hosts
            .iter()
            .map(|rule| HostRule::parse(rule))
            .collect::<Option<Vec<_>>>()
            .ok_or(EgressProxyError::InvalidBinding)?;
        let token = loop {
            let random = random_hex()?;
            let token = Zeroizing::new(format!("lk_egress_{}", random.as_str()));
            if output.iter().all(|binding| binding.placeholder.raw() != token.as_bytes()) {
                break token;
            }
        };
        let placeholder = Placeholder::new(token.as_bytes());
        env.insert(binding.env_name.clone(), token);
        output.push(Binding {
            env_name: binding.env_name,
            placeholder,
            value: binding.secret_value,
            hosts,
        });
    }
    Ok(output)
}

fn configure_socket(socket: &TcpStream) -> io::Result<()> {
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(SOCKET_POLL))?;
    socket.set_write_timeout(Some(SOCKET_POLL))
}

fn listen(listener: &TcpListener, state: &Arc<State>) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !state.stopping.load(Ordering::Relaxed) {
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                let _ignored = workers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        if workers.len() < MAX_CONNECTIONS {
            match listener.accept() {
                Ok((client, _)) => {
                    let state = Arc::clone(state);
                    if let Ok(worker) = thread::Builder::new().spawn(move || serve(&client, &state))
                    {
                        workers.push(worker);
                    }
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => break,
            }
        }
        thread::park_timeout(SOCKET_POLL);
    }
    state.stopping.store(true, Ordering::Relaxed);
    for worker in workers {
        let _ignored = worker.join();
    }
}

#[derive(Clone, Copy)]
struct Rejection {
    reason: EgressBlockReason,
    binding: Option<usize>,
}

impl From<EgressBlockReason> for Rejection {
    fn from(reason: EgressBlockReason) -> Self {
        Self { reason, binding: None }
    }
}

impl State {
    fn authorized(&self, supplied: &[u8]) -> bool {
        let Some(credential) = wire::basic_payload(supplied) else {
            return false;
        };
        credential.len() == self.auth.len() && bool::from(credential.ct_eq(self.auth.as_slice()))
    }

    fn connect(&self, target: &Authority) -> Result<TcpStream, EgressBlockReason> {
        let allow_loopback = self.config.allow_private_destinations_for_allowed_hosts
            && self
                .bindings
                .iter()
                .flat_map(|binding| &binding.hosts)
                .any(|rule| rule.allows_loopback(target));
        self.resolver.connect(target, allow_loopback, &self.stopping)
    }

    fn audit(
        &self,
        target: Option<&Authority>,
        binding: Option<usize>,
        reason: Option<EgressBlockReason>,
    ) {
        let safe_metadata = |text: &str| {
            if self.response_patterns.contains(text.as_bytes())
                || self.contains_placeholder(text.as_bytes())
            {
                String::new()
            } else {
                text.to_owned()
            }
        };
        let env_name =
            binding.map_or_else(String::new, |index| safe_metadata(&self.bindings[index].env_name));
        let target_host = target.map_or_else(String::new, |target| safe_metadata(&target.host));
        let timestamp_unix_nanos =
            SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_nanos());
        let event = if let Some(reason) = reason {
            EgressEvent::Blocked { env_name, target_host, reason, timestamp_unix_nanos }
        } else {
            EgressEvent::Allowed { env_name, target_host, timestamp_unix_nanos }
        };
        self.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(event);
    }

    fn reject(&self, writer: &mut impl Write, target: Option<&Authority>, rejected: Rejection) {
        self.audit(target, rejected.binding, Some(rejected.reason));
        let status = match rejected.reason {
            EgressBlockReason::ProxyAuthentication => {
                b"407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"locket\""
                    .as_slice()
            }
            EgressBlockReason::InvalidRequest => b"400 Bad Request",
            EgressBlockReason::UpstreamUnavailable => b"502 Bad Gateway",
            EgressBlockReason::PrivateDestination
            | EgressBlockReason::ProxyCredential
            | EgressBlockReason::HostNotAllowed => b"403 Forbidden",
        };
        let _ignored = http::empty_response(writer, status);
    }
}

fn serve(client: &TcpStream, state: &State) {
    if configure_socket(client).is_err() {
        return;
    }
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    let mut input = Wire::new(client, &state.stopping, deadline);
    let mut output = SocketWriter { stream: client, stopping: &state.stopping, deadline };
    let mut target = None;
    let result = serve_request(state, &mut input, &mut output, &mut target);
    if let Err(rejected) = result {
        output.deadline = Instant::now() + SOCKET_POLL;
        state.reject(&mut output, target.as_ref(), rejected);
    }
}

fn serve_request(
    state: &State,
    input: &mut Wire<'_>,
    output: &mut SocketWriter<'_>,
    target: &mut Option<Authority>,
) -> Result<(), Rejection> {
    use EgressBlockReason::{InvalidRequest, PrivateDestination, ProxyAuthentication};

    let head = input.head().map_err(|_| InvalidRequest)?;
    let (line, headers) = wire::parse_head(&head).ok_or(InvalidRequest)?;
    let auth = wire::singleton(&headers, "Proxy-Authorization").ok_or(ProxyAuthentication)?;
    if !state.authorized(auth) {
        return Err(ProxyAuthentication.into());
    }

    let request = Request::parse_line(line).ok_or(InvalidRequest)?;
    let authority = Authority::parse(request.authority, (!request.connect()).then_some(80))
        .ok_or(InvalidRequest)?;
    let destination = target.insert(authority);
    let host = wire::singleton(&headers, "Host")
        .and_then(|host| std::str::from_utf8(host).ok())
        .and_then(|host| Authority::parse(host, Some(if request.connect() { 443 } else { 80 })));
    if host.as_ref() != Some(destination) {
        return Err(InvalidRequest.into());
    }
    let framing = request.framing(&headers).ok_or(InvalidRequest)?;

    // A hostname is never a substitution location. Do not send a secret or
    // credential in a DNS query, even if the caller put it into the authority.
    state.guard_structure(request.authority.as_bytes(), destination)?;
    if state.response_patterns.contains(request.authority.as_bytes())
        || state.response_patterns.contains(destination.host.as_bytes())
    {
        return Err(InvalidRequest.into());
    }
    if let Ok(ip) = destination.host.parse()
        && !permitted(ip, true)
    {
        return Err(PrivateDestination.into());
    }

    if request.connect() {
        state.check_connect(&request, &headers, destination)?;
        let upstream = state.connect(destination)?;
        // Once the tunnel starts, a proxy error must not enter the byte stream.
        tunnel(input, output, &upstream);
        return Ok(());
    }

    http::forward(state, &request, &headers, input, framing, destination, output)
}

fn tunnel(input: &mut Wire<'_>, output: &mut SocketWriter<'_>, upstream: &TcpStream) {
    let deadline = Instant::now() + TUNNEL_TIMEOUT;
    output.deadline = deadline;
    input.set_deadline(deadline);
    if output.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
        return;
    }
    thread::scope(|scope| {
        let mut to_upstream =
            SocketWriter { stream: upstream, stopping: output.stopping, deadline };
        if let Ok(sender) = thread::Builder::new().spawn_scoped(scope, move || {
            let result = input.copy_body(wire::Framing::Eof, &mut to_upstream);
            let half = if result.is_ok() { Shutdown::Write } else { Shutdown::Both };
            let _ignored = upstream.shutdown(half);
        }) {
            let mut from_upstream = Wire::new(upstream, output.stopping, deadline);
            let result = from_upstream.copy_body(wire::Framing::Eof, output);
            let half = if result.is_ok() { Shutdown::Write } else { Shutdown::Both };
            let _ignored = output.stream.shutdown(half);
            let _ignored = sender.join();
        }
    });
}

#[cfg(test)]
mod tests;
