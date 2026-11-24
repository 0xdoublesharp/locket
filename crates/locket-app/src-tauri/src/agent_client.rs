//! Minimal client for the locket agent's v1 framed JSON protocol.
//!
//! Uses the agent's Unix socket or SID-scoped Windows named pipe for framed
//! unary RPCs. Unix subscribes to metadata status; Windows polls the same
//! unary Status RPC because its pipe server does not support subscriptions.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use locket_agent::{
    AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, PROTOCOL_VERSION, ProtocolError, ResponseEnvelope,
    StatusEvent, StatusPayload, decode_response_frame,
};
use locket_core::{ErrorDisplayCopy, LocketError};
use locket_platform::LocketInstance;
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
type AgentStream = tokio::net::UnixStream;
#[cfg(target_os = "windows")]
type AgentStream = tokio::net::windows::named_pipe::NamedPipeClient;
use tokio::sync::{Notify, mpsc};
use zeroize::{Zeroize, Zeroizing};

const FRAME_PREFIX_LEN: usize = size_of::<u32>();
const FRAME_READ_CHUNK_SIZE: usize = 16 * 1024;

/// Socket file name inside the instance's agent directory.
const DEFAULT_SOCKET_FILE: &str = "agent.sock";

/// Environment variable that overrides the agent socket path.
const SOCKET_PATH_ENV: &str = "LOCKET_AGENT_SOCKET";

/// Connect timeout for the agent socket.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Round-trip request timeout once a connection is established.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Windows exposes unary RPCs, so poll for metadata invalidation once a second.
#[cfg(target_os = "windows")]
const WINDOWS_STATUS_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Initial reconnect backoff after the status stream drops.
pub const RECONNECT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Maximum reconnect backoff between attempts. The desktop spec caps
/// the wait at 30 seconds so a long-stopped agent still surfaces a
/// reconnect within a UX-acceptable window once it comes back.
pub const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Pure mapping from a previous attempt delay to the next delay. The
/// schedule doubles starting at [`RECONNECT_INITIAL_BACKOFF`] until it
/// hits [`RECONNECT_MAX_BACKOFF`]. Exposed as a `pub` helper so tests
/// and the Tauri reconnect loop share the same source of truth.
#[must_use]
pub fn next_reconnect_delay(previous: Option<Duration>) -> Duration {
    let Some(previous) = previous else {
        return RECONNECT_INITIAL_BACKOFF;
    };
    let doubled = previous.saturating_mul(2);
    if doubled >= RECONNECT_MAX_BACKOFF { RECONNECT_MAX_BACKOFF } else { doubled }
}

/// Cancellation token shared between the desktop shell and the
/// streaming client task.
///
/// The Tauri layer flips this on app shutdown so the long-lived
/// `SubscribeStatus` reader exits cleanly without leaving a half-open
/// socket behind.
#[derive(Clone, Debug, Default)]
pub struct CancelToken {
    notify: Arc<Notify>,
    flag: Arc<std::sync::atomic::AtomicBool>,
}

impl CancelToken {
    /// Creates a fresh, unflagged cancel token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the token as cancelled and wakes every waiter.
    pub fn cancel(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Reports whether the token has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Future resolves the moment [`CancelToken::cancel`] is called.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

/// Typed errors surfaced by the desktop agent client.
///
/// Variants distinguish the daemon being absent (the common case the
/// `AgentUnavailable` banner is for) from wire-protocol faults so the
/// UI can keep them separate per the spec.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AgentClientError {
    /// The agent daemon is not running or its socket is missing.
    #[error("agent unavailable: {reason}")]
    Unavailable {
        /// Short reason — daemon offline, socket missing, refused, timed-out.
        reason: String,
        /// Shared typed-error reason shown across UI surfaces.
        display_reason: String,
        /// Shared typed-error recovery action shown across UI surfaces.
        next_action: String,
        /// Path that was attempted, for diagnostics.
        socket_path: String,
    },
    /// The wire protocol failed: framing, JSON, version, or unknown method.
    #[error("agent protocol error: {reason}")]
    Protocol {
        /// Human-readable summary of the protocol failure.
        reason: String,
    },
    /// The agent answered with an error envelope.
    #[error("agent rejected request: {code}")]
    Rejected {
        /// Stable typed-error code from the agent.
        code: String,
        /// Redacted safe message.
        message: String,
        /// Shared typed-error reason when the code maps to `LocketError`.
        display_reason: String,
        /// Shared typed-error recovery action when the code maps to `LocketError`.
        next_action: String,
        /// Whether the client may retry the request unchanged.
        retryable: bool,
    },
}

impl AgentClientError {
    fn unavailable(reason: impl Into<String>, socket_path: &Path) -> Self {
        let copy = LocketError::AgentUnavailable.display_copy();
        Self::Unavailable {
            reason: reason.into(),
            display_reason: copy.reason.to_owned(),
            next_action: copy.next_action.to_owned(),
            socket_path: socket_path.display().to_string(),
        }
    }
}

impl From<ProtocolError> for AgentClientError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol { reason: value.to_string() }
    }
}

/// Resolve the local agent endpoint, preserving `LOCKET_AGENT_SOCKET` overrides.
///
/// Uses the CLI's macOS Application Support path, Linux XDG runtime path or
/// home fallback, and the current user's SID-scoped Windows pipe. If Windows
/// SID resolution fails, returns an empty endpoint that connect rejects.
#[must_use]
pub fn resolve_socket_path() -> PathBuf {
    let explicit = std::env::var_os(SOCKET_PATH_ENV);
    let home = directories::BaseDirs::new()
        .map_or_else(|| PathBuf::from("."), |directories| directories.home_dir().to_path_buf());
    #[cfg(target_os = "windows")]
    let windows_pipe = locket_platform::default_agent_pipe_name().ok().map(PathBuf::from);
    #[cfg(not(target_os = "windows"))]
    let windows_pipe: Option<PathBuf> = None;
    endpoint_from_inputs(
        LocketInstance::current(),
        std::env::consts::OS,
        explicit.as_deref(),
        &home,
        std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        windows_pipe.as_deref(),
    )
}

/// Issue a single `Status` request to the agent.
///
/// Returns the metadata-only payload on success. Maps every failure
/// mode (no socket, refused connection, framing fault, error envelope)
/// onto [`AgentClientError`] without ever surfacing raw I/O errors to
/// the UI.
///
/// # Errors
///
/// Returns [`AgentClientError`] when the socket can't be reached, the
/// request times out, the wire protocol fails, or the agent replies
/// with an error envelope.
pub async fn fetch_status(socket_path: &Path) -> Result<StatusPayload, AgentClientError> {
    invoke_method::<(), StatusPayload>(socket_path, AgentMethod::Status, &()).await
}

/// Invoke any agent RPC end-to-end.
///
/// Serializes `payload` to JSON, exchanges a single request frame, and
/// deserializes the success payload as `R`. Error envelopes flow back
/// as [`AgentClientError::Rejected`].
///
/// # Errors
///
/// Returns [`AgentClientError`] for unreachable sockets, timeouts,
/// framing/JSON faults, and agent-side rejections.
pub async fn invoke_method<P: Serialize, R: DeserializeOwned>(
    socket_path: &Path,
    method: AgentMethod,
    payload: &P,
) -> Result<R, AgentClientError> {
    let frame = encode_request(&new_request_id(), method, payload)?;
    let stream = connect(socket_path).await?;
    let response = round_trip(stream, method, frame).await?;
    decode_payload(response)
}

/// Subscribe to metadata-only agent status events.
///
/// Unix opens a dedicated `SubscribeStatus` connection and forwards decoded
/// [`StatusEvent`] values until the socket closes or the receiver is dropped.
/// Windows polls unary Status and emits equivalent metadata snapshots and
/// unchanged-status heartbeats. It never sends unsupported SubscribeStatus.
///
/// # Errors
///
/// Returns [`AgentClientError`] when the socket can't be reached, the
/// initial request can't be written, the wire protocol fails, or the
/// agent replies with an error envelope.
pub async fn stream_status_events(
    socket_path: &Path,
    sender: mpsc::Sender<StatusEvent>,
) -> Result<(), AgentClientError> {
    stream_status_events_with_cancel(socket_path, sender, &CancelToken::new()).await
}

/// Cancellable variant of [`stream_status_events`].
///
/// Cancellation stops an in-flight request or a blocked event send on Windows.
/// Unix sends a best-effort `CancelSubscription` envelope before closing its
/// dedicated stream. App shutdown can therefore stop both transport variants.
///
/// # Errors
///
/// Returns [`AgentClientError`] for unreachable sockets, write/flush
/// failures, framing/JSON faults, and agent-side error envelopes.
pub async fn stream_status_events_with_cancel(
    socket_path: &Path,
    sender: mpsc::Sender<StatusEvent>,
    cancel: &CancelToken,
) -> Result<(), AgentClientError> {
    #[cfg(unix)]
    {
        stream_unix_status_events_with_cancel(socket_path, sender, cancel).await
    }
    #[cfg(target_os = "windows")]
    {
        poll_status_events_with(
            || fetch_status(socket_path),
            sender,
            cancel,
            WINDOWS_STATUS_POLL_INTERVAL,
            Duration::from_secs(locket_agent::STATUS_HEARTBEAT_INTERVAL_SECS),
        )
        .await
    }
}

#[cfg(unix)]
async fn stream_unix_status_events_with_cancel(
    socket_path: &Path,
    sender: mpsc::Sender<StatusEvent>,
    cancel: &CancelToken,
) -> Result<(), AgentClientError> {
    let mut stream = connect(socket_path).await?;
    let subscribe_id = new_request_id();
    let frame = encode_request(&subscribe_id, AgentMethod::SubscribeStatus, &())?;
    stream
        .write_all(&frame)
        .await
        .map_err(|error| AgentClientError::Protocol { reason: format!("write failed: {error}") })?;
    drop(frame);
    stream
        .flush()
        .await
        .map_err(|error| AgentClientError::Protocol { reason: format!("flush failed: {error}") })?;
    let result = read_status_stream(&mut stream, sender, cancel).await;
    if cancel.is_cancelled() {
        // Best-effort `CancelSubscription` so the agent doesn't have to
        // observe the close to free the subscriber. The cancellation
        // path returns `Ok(())` regardless of whether the agent saw the
        // envelope before the socket closed.
        if let Ok(frame) = encode_request(
            &new_request_id(),
            AgentMethod::CancelSubscription,
            &serde_json::json!({ "subscription_id": subscribe_id }),
        ) {
            let _ = stream.write_all(&frame).await;
            let _ = stream.flush().await;
        }
        return Ok(());
    }
    result
}

#[cfg(unix)]
async fn connect(socket_path: &Path) -> Result<AgentStream, AgentClientError> {
    if !socket_path.exists() {
        return Err(AgentClientError::unavailable("agent socket not found", socket_path));
    }
    match tokio::time::timeout(CONNECT_TIMEOUT, AgentStream::connect(socket_path)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => {
            Err(AgentClientError::unavailable(format!("connect failed: {error}"), socket_path))
        }
        Err(_) => Err(AgentClientError::unavailable("connect timed out", socket_path)),
    }
}

#[cfg(target_os = "windows")]
async fn connect(socket_path: &Path) -> Result<AgentStream, AgentClientError> {
    if socket_path.as_os_str().is_empty() {
        return Err(AgentClientError::unavailable(
            "could not resolve the current user's agent pipe",
            socket_path,
        ));
    }
    // Named pipes do not have filesystem entries. The shared connector retries
    // busy instances; this outer deadline bounds both retrying and initial open.
    match tokio::time::timeout(
        CONNECT_TIMEOUT,
        locket_agent::connect_named_pipe_client(socket_path),
    )
    .await
    {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => {
            Err(AgentClientError::unavailable(format!("connect failed: {error}"), socket_path))
        }
        Err(_) => Err(AgentClientError::unavailable("connect timed out", socket_path)),
    }
}

async fn round_trip(
    mut stream: AgentStream,
    method: AgentMethod,
    frame: Zeroizing<Vec<u8>>,
) -> Result<ResponseEnvelope, AgentClientError> {
    let mutation = matches!(
        method,
        AgentMethod::ImportDotenv | AgentMethod::ApplyPolicy | AgentMethod::SetSecret
    );
    let timeout = if mutation { Duration::from_secs(30) } else { REQUEST_TIMEOUT };
    let result = tokio::time::timeout(timeout, exchange_frame(&mut stream, frame)).await;
    match result {
        Ok(Ok(envelope)) => Ok(envelope),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(AgentClientError::Protocol {
            reason: if mutation {
                "request timed out; outcome is unknown. Refresh before retrying".to_owned()
            } else {
                "request timed out".to_owned()
            },
        }),
    }
}

async fn exchange_frame(
    stream: &mut AgentStream,
    frame: Zeroizing<Vec<u8>>,
) -> Result<ResponseEnvelope, AgentClientError> {
    stream
        .write_all(&frame)
        .await
        .map_err(|error| AgentClientError::Protocol { reason: format!("write failed: {error}") })?;
    drop(frame);
    stream
        .flush()
        .await
        .map_err(|error| AgentClientError::Protocol { reason: format!("flush failed: {error}") })?;
    let mut buffer = Zeroizing::new(Vec::with_capacity(FRAME_READ_CHUNK_SIZE));
    read_response_frame(stream, &mut buffer).await?.ok_or_else(|| AgentClientError::Protocol {
        reason: "agent closed connection before response".to_owned(),
    })
}

#[derive(Serialize)]
struct Request<'a, P> {
    v: u16,
    id: &'a str,
    kind: &'static str,
    payload: &'a P,
}

fn encode_request<P: Serialize>(
    id: &str,
    method: AgentMethod,
    payload: &P,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut frame = RequestFrame(Zeroizing::new(Vec::with_capacity(128)));
    frame.0.extend_from_slice(&[0; FRAME_PREFIX_LEN]);
    serde_json::to_writer(
        &mut frame,
        &Request { v: PROTOCOL_VERSION, id, kind: method.as_str(), payload },
    )?;
    let mut bytes = frame.0;
    let length = bytes.len() - FRAME_PREFIX_LEN;
    if length > DEFAULT_MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge { length, maximum: DEFAULT_MAX_MESSAGE_SIZE });
    }
    let length = u32::try_from(length).map_err(|_| ProtocolError::LengthPrefixOverflow)?;
    bytes[..FRAME_PREFIX_LEN].copy_from_slice(&length.to_le_bytes());
    Ok(bytes)
}

struct RequestFrame(Zeroizing<Vec<u8>>);

impl std::io::Write for RequestFrame {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let needed = self.0.len() + bytes.len();
        let capacity = self.0.capacity();
        if needed > capacity {
            grow_buffer(&mut self.0, needed.max(capacity * 2));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn grow_buffer(buffer: &mut Zeroizing<Vec<u8>>, capacity: usize) {
    // Replacing the wrapper wipes the old allocation before it is freed.
    let mut replacement = Zeroizing::new(Vec::with_capacity(capacity));
    replacement.extend_from_slice(buffer);
    *buffer = replacement;
}

async fn read_response_frame(
    stream: &mut AgentStream,
    buffer: &mut Zeroizing<Vec<u8>>,
) -> Result<Option<ResponseEnvelope>, AgentClientError> {
    loop {
        match decode_response_frame(buffer, DEFAULT_MAX_MESSAGE_SIZE) {
            Ok((envelope, consumed)) => {
                let remaining = buffer.len() - consumed;
                buffer.copy_within(consumed.., 0);
                buffer[remaining..].zeroize();
                buffer.truncate(remaining);
                return Ok(Some(envelope));
            }
            Err(ProtocolError::IncompleteFrame) => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(prefix) = buffer.first_chunk::<FRAME_PREFIX_LEN>() {
            // The decoder already checked this length against the protocol maximum.
            let needed = FRAME_PREFIX_LEN + u32::from_le_bytes(*prefix) as usize;
            if needed > buffer.capacity() {
                grow_buffer(buffer, needed);
            }
        }
        let read = stream.read_buf(&mut **buffer).await.map_err(|error| {
            AgentClientError::Protocol { reason: format!("read failed: {error}") }
        })?;
        if read == 0 {
            return Ok(None);
        }
    }
}

#[cfg(unix)]
async fn read_status_stream(
    stream: &mut AgentStream,
    sender: mpsc::Sender<StatusEvent>,
    cancel: &CancelToken,
) -> Result<(), AgentClientError> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(FRAME_READ_CHUNK_SIZE));
    loop {
        let response = tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            result = read_response_frame(stream, &mut buffer) => result?,
        };
        let Some(response) = response else {
            return Err(AgentClientError::Protocol {
                reason: "agent closed status stream".to_owned(),
            });
        };
        let event = decode_payload::<StatusEvent>(response)?;
        if sender.send(event).await.is_err() {
            return Ok(());
        }
    }
}

fn decode_payload<R: DeserializeOwned>(response: ResponseEnvelope) -> Result<R, AgentClientError> {
    match response {
        ResponseEnvelope::Success(success) => {
            serde_json::from_value::<R>(success.payload).map_err(|error| {
                AgentClientError::Protocol {
                    reason: format!("malformed response payload: {error}"),
                }
            })
        }
        ResponseEnvelope::Error(error) => {
            let copy = display_copy_for_agent_code(&error.error).unwrap_or(ErrorDisplayCopy {
                reason: "The agent rejected the request.",
                next_action: "See the agent logs for details.",
            });
            Err(AgentClientError::Rejected {
                code: error.error,
                message: error.message,
                display_reason: copy.reason.to_owned(),
                next_action: copy.next_action.to_owned(),
                retryable: error.retryable,
            })
        }
    }
}

fn display_copy_for_agent_code(code: &str) -> Option<ErrorDisplayCopy> {
    LocketError::from_code_name(code).map(|error| error.display_copy())
}

fn new_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let next = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("desktop-{next}")
}

// Platform-testable endpoint resolver.
fn endpoint_from_inputs(
    instance: LocketInstance,
    platform: &str,
    explicit: Option<&std::ffi::OsStr>,
    home: &Path,
    runtime: Option<&std::ffi::OsStr>,
    windows_pipe: Option<&Path>,
) -> PathBuf {
    if let Some(explicit) = explicit.filter(|value| !value.is_empty()) {
        return explicit.into();
    }
    if platform == "windows" {
        return windows_pipe.map_or_else(PathBuf::new, Path::to_path_buf);
    }
    instance.agent_data_dir(platform, home, runtime).join(DEFAULT_SOCKET_FILE)
}

// Windows status polling core, also tested without a real endpoint.
#[cfg(any(target_os = "windows", test))]
async fn poll_status_events_with<F, Fut>(
    mut fetch: F,
    sender: mpsc::Sender<StatusEvent>,
    cancel: &CancelToken,
    interval: Duration,
    heartbeat_interval: Duration,
) -> Result<(), AgentClientError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<StatusPayload, AgentClientError>>,
{
    let mut previous: Option<StatusPayload> = None;
    let mut sequence = 0_u64;
    let mut heartbeat_deadline = tokio::time::Instant::now();
    loop {
        let status = tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            () = sender.closed() => return Ok(()),
            result = fetch() => result?,
        };
        let meaningful_change = previous.as_ref().is_none_or(|previous| {
            // Countdown-only samples do not invalidate project metadata. A
            // renewed or newly available TTL must still notify immediately.
            let ttl_renewed_or_unavailable =
                match (previous.unlock_ttl_seconds, status.unlock_ttl_seconds) {
                    (Some(previous), Some(current)) => current > previous,
                    (None, None) => false,
                    _ => true,
                };
            let mut without_countdown = previous.clone();
            without_countdown.unlock_ttl_seconds = status.unlock_ttl_seconds;
            without_countdown != status || ttl_renewed_or_unavailable
        });
        // Compare renewals against the latest sample, not the last emitted TTL.
        previous = Some(status.clone());
        if meaningful_change || tokio::time::Instant::now() >= heartbeat_deadline {
            sequence = sequence.saturating_add(1);
            let event = if meaningful_change {
                StatusEvent::status(sequence, status)
            } else {
                StatusEvent::heartbeat(sequence, status)
            };
            tokio::select! {
                biased;
                () = cancel.cancelled() => return Ok(()),
                result = sender.send(event) => if result.is_err() { return Ok(()); },
            }
            heartbeat_deadline = tokio::time::Instant::now() + heartbeat_interval;
        }
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            () = sender.closed() => return Ok(()),
            () = tokio::time::sleep(interval) => {},
        }
    }
}

// Endpoint defaults are tested through injected platform/environment inputs.
// Separate Unix socket and Windows named-pipe integration tests exercise
// actual framed unary requests and the supported status transport.

#[cfg(test)]
mod tests {
    use super::{
        AgentMethod, CancelToken, DEFAULT_MAX_MESSAGE_SIZE, RECONNECT_INITIAL_BACKOFF,
        RECONNECT_MAX_BACKOFF, display_copy_for_agent_code, encode_request, next_reconnect_delay,
    };
    use std::time::Duration;

    #[test]
    fn encoded_request_matches_agent_framing() -> Result<(), Box<dyn std::error::Error>> {
        let value = "test input\n".repeat(2_000);
        let frame =
            encode_request("test", AgentMethod::Unlock, &serde_json::json!({"passphrase": value}))?;
        let (request, consumed) =
            locket_agent::decode_request_frame(&frame, DEFAULT_MAX_MESSAGE_SIZE)?;
        assert_eq!(consumed, frame.len());
        assert_eq!(request.id, "test");
        assert_eq!(request.method()?, AgentMethod::Unlock);
        assert_eq!(request.payload["passphrase"], value);
        Ok(())
    }

    #[test]
    fn agent_error_codes_use_shared_locket_error_copy() -> Result<(), Box<dyn std::error::Error>> {
        let copy = display_copy_for_agent_code("UnlockRequired").ok_or("known typed error")?;
        assert_eq!(copy.reason, "The vault is locked.");
        assert_eq!(copy.next_action, "Run locket unlock or approve an agent unlock prompt.");
        assert!(display_copy_for_agent_code("ProtocolError").is_none());
        Ok(())
    }

    #[test]
    fn reconnect_schedule_doubles_until_capped_at_30_seconds() {
        // Spec: start at 1 second, double on each failure, cap at 30
        // seconds. The schedule must always start from
        // `RECONNECT_INITIAL_BACKOFF` and never exceed
        // `RECONNECT_MAX_BACKOFF`.
        let mut delays = Vec::new();
        let mut current: Option<Duration> = None;
        for _ in 0..10 {
            let next = next_reconnect_delay(current);
            delays.push(next);
            current = Some(next);
        }

        assert_eq!(delays[0], RECONNECT_INITIAL_BACKOFF);
        assert_eq!(delays[0], Duration::from_secs(1));
        assert_eq!(delays[1], Duration::from_secs(2));
        assert_eq!(delays[2], Duration::from_secs(4));
        assert_eq!(delays[3], Duration::from_secs(8));
        assert_eq!(delays[4], Duration::from_secs(16));
        for delay in &delays[5..] {
            assert_eq!(*delay, RECONNECT_MAX_BACKOFF);
            assert_eq!(*delay, Duration::from_secs(30));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::expect_used)]
    async fn cancel_token_wakes_waiters_once_cancelled() {
        let token = CancelToken::new();
        assert!(!token.is_cancelled());
        let waiter = {
            let token = token.clone();
            tokio::spawn(async move { token.cancelled().await })
        };
        token.cancel();
        waiter.await.expect("waiter must complete");
        assert!(token.is_cancelled());
        // Subsequent waits resolve immediately.
        token.cancelled().await;
    }
}

#[cfg(test)]
#[path = "agent_client_platform_tests.rs"]
mod platform_tests;
