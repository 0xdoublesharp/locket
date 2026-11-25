//! Desktop clipboard helpers backing the `copy_secret` Tauri command.
//!
//! Splits the clear-after-TTL flow into:
//!
//! - A pure decision function (`decide_clear`) so unit tests can pin
//!   the contract without bringing up an OS clipboard.
//! - A platform probe (`clipboard_platform`) that flags Wayland sessions
//!   as `unsupported_reason = "wayland-session"` because the X11/Wayland
//!   selection model means our value never reaches a generic clipboard
//!   peer in the first place.
//! - A worker that owns one clipboard session from the successful write
//!   through expiry. Linux needs that owner alive to serve paste requests;
//!   creating and dropping a clipboard for each operation loses the selection.

use std::time::Duration;

use thiserror::Error;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// Decision returned by [`decide_clear`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardCopyDecision {
    /// The TTL elapsed and the clipboard still holds the value we
    /// wrote — the caller should clear it.
    Clear,
    /// The clipboard changed since we wrote the value — leave it
    /// alone.
    Keep,
}

/// Outcome of the user-facing `copy_secret` flow surfaced to the UI.
///
/// Mirrors the wire shape returned by the Tauri command but kept in
/// the lib so unit tests can pattern-match without re-exporting the
/// command's private response struct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClipboardCopyOutcome {
    /// The agent value reached the OS clipboard.
    Copied {
        /// TTL after which the clipboard is re-checked.
        ttl_seconds: u32,
    },
    /// The desktop did not write anything.
    Unsupported {
        /// Stable reason code surfaced to the UI.
        unsupported_reason: String,
    },
}

/// Platforms where the `copy_secret` flow has different behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardPlatform {
    /// macOS, Windows, or X11 — full TTL-bound clear path is wired.
    Standard,
    /// Wayland session — the desktop returns an `unsupported_reason`
    /// and skips the timer.
    Wayland,
}

/// Errors raised by the thin clipboard helpers.
#[derive(Debug, Error)]
pub enum ClipboardError {
    /// Underlying platform refused or could not service the request.
    #[error("clipboard backend error: {0}")]
    Backend(String),
}

/// Probe the platform once. Wayland is detected via `XDG_SESSION_TYPE`
/// or the `WAYLAND_DISPLAY` env var, matching the convention used by
/// the rest of the workspace.
#[must_use]
pub fn clipboard_platform() -> ClipboardPlatform {
    #[cfg(target_os = "linux")]
    {
        linux_clipboard_platform(
            &std::env::var("XDG_SESSION_TYPE").unwrap_or_default(),
            &std::env::var("WAYLAND_DISPLAY").unwrap_or_default(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        ClipboardPlatform::Standard
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_clipboard_platform(session: &str, wayland_display: &str) -> ClipboardPlatform {
    if session.eq_ignore_ascii_case("wayland") || !wayland_display.is_empty() {
        ClipboardPlatform::Wayland
    } else {
        ClipboardPlatform::Standard
    }
}

/// Pure mapping from "what the clipboard now holds" to the clear
/// decision. Treats a missing/None read as "leave it alone" — if we
/// can't be sure, we never wipe a clipboard we don't own.
#[must_use]
pub fn decide_clear(current: Option<&str>, expected: &str) -> ClipboardCopyDecision {
    match current {
        Some(value) if value == expected => ClipboardCopyDecision::Clear,
        _ => ClipboardCopyDecision::Keep,
    }
}

/// Clipboard factory used only on the worker that retains its returned owner.
/// `arboard::Clipboard` need not be `Send`: it never leaves that thread.
pub struct ClipboardSession;

impl ClipboardSession {
    /// Open a clipboard session.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardError::Backend`] if the OS clipboard cannot
    /// be initialized.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Result<arboard::Clipboard, ClipboardError> {
        arboard::Clipboard::new().map_err(|error| ClipboardError::Backend(error.to_string()))
    }
}

#[cfg(any(not(target_os = "macos"), test))]
trait ClipboardBackend {
    fn write(&mut self, value: &str) -> Result<(), ClipboardError>;
    fn read(&mut self) -> Result<String, ClipboardError>;
    fn clear(&mut self) -> Result<(), ClipboardError>;
}

#[cfg(not(target_os = "macos"))]
impl ClipboardBackend for arboard::Clipboard {
    fn write(&mut self, value: &str) -> Result<(), ClipboardError> {
        self.set_text(value.to_owned()).map_err(|error| ClipboardError::Backend(error.to_string()))
    }

    fn read(&mut self) -> Result<String, ClipboardError> {
        self.get_text().map_err(|error| ClipboardError::Backend(error.to_string()))
    }

    fn clear(&mut self) -> Result<(), ClipboardError> {
        arboard::Clipboard::clear(self).map_err(|error| ClipboardError::Backend(error.to_string()))
    }
}

/// Copy on a native worker and acknowledge only after the write succeeds.
/// At expiry, macOS checks pasteboard ownership. Elsewhere the worker retains
/// the selection and checks whether it still holds the value.
pub(crate) async fn copy_with_ttl(value: String, ttl: Duration) -> Result<(), ClipboardError> {
    copy_with_worker(value, ttl, |value, ttl, ready| {
        #[cfg(target_os = "macos")]
        copy_concealed_on_worker(
            value,
            ttl,
            ready,
            locket_platform::write_concealed_secret,
            locket_platform::clear_if_unchanged,
            std::thread::sleep,
        );
        #[cfg(not(target_os = "macos"))]
        copy_on_worker(value, ttl, ready, ClipboardSession::new, std::thread::sleep);
    })
    .await
}

async fn copy_with_worker(
    value: String,
    ttl: Duration,
    worker: impl FnOnce(Zeroizing<String>, Duration, oneshot::Sender<Result<(), ClipboardError>>)
    + Send
    + 'static,
) -> Result<(), ClipboardError> {
    let value = Zeroizing::new(value);
    let (ready, written) = oneshot::channel();
    std::thread::Builder::new()
        .name("locket-clipboard".into())
        .spawn(move || worker(value, ttl, ready))
        .map_err(|error| ClipboardError::Backend(error.to_string()))?;
    written.await.map_err(|_| ClipboardError::Backend("clipboard worker stopped".into()))?
}

#[cfg(any(target_os = "macos", test))]
fn copy_concealed_on_worker(
    value: Zeroizing<String>,
    ttl: Duration,
    ready: oneshot::Sender<Result<(), ClipboardError>>,
    write: impl FnOnce(&str) -> Result<i64, locket_platform::PlatformError>,
    clear: impl FnOnce(i64) -> Result<bool, locket_platform::PlatformError>,
    wait: impl FnOnce(Duration),
) {
    let change_count = write(&value);
    drop(value);
    match change_count {
        Ok(change_count) => {
            if ready.send(Ok(())).is_ok() {
                wait(ttl);
            }
            let _ = clear(change_count);
        }
        Err(error) => {
            let _ = ready.send(Err(ClipboardError::Backend(error.to_string())));
        }
    }
}

pub(crate) fn copy_plain_text(text: String) -> Result<(), ClipboardError> {
    #[cfg(target_os = "macos")]
    {
        locket_platform::write_plain_text(&text)
            .map_err(|error| ClipboardError::Backend(error.to_string()))
    }
    #[cfg(target_os = "linux")]
    {
        // The X11 selection remains available while this process has an owner.
        static CLIPBOARD: std::sync::Mutex<Option<arboard::Clipboard>> =
            std::sync::Mutex::new(None);
        let mut clipboard =
            CLIPBOARD.lock().map_err(|error| ClipboardError::Backend(error.to_string()))?;
        let clipboard = match clipboard.as_mut() {
            Some(owner) => owner,
            None => clipboard.insert(ClipboardSession::new()?),
        };
        clipboard.set_text(text).map_err(|error| ClipboardError::Backend(error.to_string()))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        ClipboardSession::new()?
            .set_text(text)
            .map_err(|error| ClipboardError::Backend(error.to_string()))
    }
}

#[cfg(any(not(target_os = "macos"), test))]
fn copy_on_worker<B: ClipboardBackend>(
    value: Zeroizing<String>,
    ttl: Duration,
    ready: oneshot::Sender<Result<(), ClipboardError>>,
    open: impl FnOnce() -> Result<B, ClipboardError>,
    wait: impl FnOnce(Duration),
) {
    let mut clipboard = match open() {
        Ok(clipboard) => clipboard,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    if let Err(error) = clipboard.write(&value) {
        let _ = ready.send(Err(error));
        return;
    }
    // If the caller disappeared before acknowledgement, expire immediately.
    if ready.send(Ok(())).is_ok() {
        wait(ttl);
    }
    let current = clipboard.read().ok().map(Zeroizing::new);
    if decide_clear(current.as_deref().map(String::as_str), &value) == ClipboardCopyDecision::Clear
    {
        let _ = clipboard.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::time::Duration;
    use zeroize::Zeroizing;

    #[cfg(target_os = "linux")]
    use super::clipboard_platform;
    use super::{
        ClipboardBackend, ClipboardCopyDecision, ClipboardError, ClipboardPlatform,
        copy_concealed_on_worker, copy_on_worker, copy_with_worker, decide_clear,
        linux_clipboard_platform,
    };

    struct OwnedClipboard {
        alive: Rc<Cell<bool>>,
        contents: Rc<RefCell<Option<String>>>,
        reject_write: bool,
    }

    impl Drop for OwnedClipboard {
        fn drop(&mut self) {
            self.alive.set(false);
        }
    }

    impl ClipboardBackend for OwnedClipboard {
        fn write(&mut self, value: &str) -> Result<(), ClipboardError> {
            if self.reject_write {
                return Err(ClipboardError::Backend("write refused".into()));
            }
            *self.contents.borrow_mut() = Some(value.into());
            Ok(())
        }

        fn read(&mut self) -> Result<String, ClipboardError> {
            self.contents.borrow().clone().ok_or_else(|| ClipboardError::Backend("no text".into()))
        }

        fn clear(&mut self) -> Result<(), ClipboardError> {
            *self.contents.borrow_mut() = None;
            Ok(())
        }
    }

    #[test]
    fn clipboard_owner_survives_acknowledgement_until_expiry() {
        let alive = Rc::new(Cell::new(true));
        let contents = Rc::new(RefCell::new(None));
        let clipboard = OwnedClipboard {
            alive: Rc::clone(&alive),
            contents: Rc::clone(&contents),
            reject_write: false,
        };
        let (ready, mut written) = tokio::sync::oneshot::channel();
        copy_on_worker(
            Zeroizing::new("clipboard-lifetime-test".into()),
            Duration::from_secs(30),
            ready,
            || Ok(clipboard),
            |ttl| {
                assert_eq!(ttl, Duration::from_secs(30));
                assert!(matches!(written.try_recv(), Ok(Ok(()))));
                assert!(alive.get(), "the selection owner must still serve paste requests");
                assert_eq!(contents.borrow().as_deref(), Some("clipboard-lifetime-test"));
            },
        );
        assert!(!alive.get());
        assert_eq!(*contents.borrow(), None, "our value is cleared before dropping the owner");
    }

    #[test]
    fn clipboard_expiry_preserves_a_replacement_value() {
        let alive = Rc::new(Cell::new(true));
        let contents = Rc::new(RefCell::new(None));
        let clipboard = OwnedClipboard {
            alive: Rc::clone(&alive),
            contents: Rc::clone(&contents),
            reject_write: false,
        };
        let (ready, _written) = tokio::sync::oneshot::channel();
        copy_on_worker(
            Zeroizing::new("initial".into()),
            Duration::from_secs(30),
            ready,
            || Ok(clipboard),
            |_| *contents.borrow_mut() = Some("replacement".into()),
        );
        assert!(!alive.get());
        assert_eq!(contents.borrow().as_deref(), Some("replacement"));
    }

    #[test]
    fn clipboard_write_failure_never_acknowledges_success_or_waits() {
        let alive = Rc::new(Cell::new(true));
        let contents = Rc::new(RefCell::new(None));
        let clipboard = OwnedClipboard {
            alive: Rc::clone(&alive),
            contents: Rc::clone(&contents),
            reject_write: true,
        };
        let (ready, mut written) = tokio::sync::oneshot::channel();
        let waited = Cell::new(false);
        copy_on_worker(
            Zeroizing::new("initial".into()),
            Duration::from_secs(30),
            ready,
            || Ok(clipboard),
            |_| waited.set(true),
        );
        assert!(matches!(written.try_recv(), Ok(Err(_))));
        assert!(!waited.get());
        assert!(!alive.get());
        assert_eq!(*contents.borrow(), None);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires an X11 desktop without a clipboard manager; writes the OS clipboard"]
    async fn x11_copy_remains_available_to_another_clipboard_client() -> Result<(), ClipboardError>
    {
        assert_eq!(clipboard_platform(), ClipboardPlatform::Standard);
        assert!(std::env::var_os("DISPLAY").is_some());
        let value = "locket-x11-clipboard-lifetime-check";
        super::copy_with_ttl(value.into(), Duration::from_millis(500)).await?;
        // Open the reader after the copy has returned, so it cannot keep a
        // prematurely dropped writer alive through arboard's shared state.
        let mut reader = super::ClipboardSession::new()?;
        assert_eq!(ClipboardBackend::read(&mut reader)?, value);
        tokio::time::sleep(Duration::from_millis(750)).await;
        assert_ne!(ClipboardBackend::read(&mut reader).ok().as_deref(), Some(value));
        Ok(())
    }

    #[test]
    fn decide_clear_clears_when_clipboard_still_holds_the_secret() {
        assert_eq!(
            decide_clear(Some("super-secret-value"), "super-secret-value"),
            ClipboardCopyDecision::Clear,
        );
    }

    #[test]
    fn decide_clear_keeps_when_user_overwrote_the_clipboard() {
        assert_eq!(
            decide_clear(Some("user typed something else"), "super-secret-value"),
            ClipboardCopyDecision::Keep,
        );
    }

    #[test]
    fn decide_clear_keeps_when_clipboard_is_unreadable() {
        // We can't tell what the clipboard holds, so treat as "leave
        // it alone".
        assert_eq!(decide_clear(None, "super-secret-value"), ClipboardCopyDecision::Keep);
    }

    #[test]
    fn wayland_is_detected_from_either_linux_session_hint() {
        for (session, display) in [("WaYLaNd", ""), ("x11", "wayland-test"), ("", "wayland-test")] {
            assert_eq!(linux_clipboard_platform(session, display), ClipboardPlatform::Wayland);
        }
        assert_eq!(linux_clipboard_platform("x11", ""), ClipboardPlatform::Standard);
        assert_eq!(linux_clipboard_platform("", ""), ClipboardPlatform::Standard);
    }

    #[test]
    fn concealed_copy_acknowledges_before_waiting_and_clears_only_the_original_change_count() {
        let (ready, mut written) = tokio::sync::oneshot::channel();
        let count = Cell::new(0);
        let cleared = Cell::new(false);
        copy_concealed_on_worker(
            Zeroizing::new("test secret".into()),
            Duration::from_secs(5),
            ready,
            |value| {
                assert_eq!(value, "test secret");
                count.set(41);
                Ok(41)
            },
            |expected| {
                assert_eq!(expected, 41);
                cleared.set(count.get() == expected);
                Ok(cleared.get())
            },
            |ttl| {
                assert_eq!(ttl, Duration::from_secs(5));
                assert!(matches!(written.try_recv(), Ok(Ok(()))));
                count.set(42);
            },
        );
        assert_eq!(count.get(), 42);
        assert!(!cleared.get());
    }

    #[tokio::test]
    async fn concealed_write_failure_reaches_the_caller_without_starting_an_expiry_timer() {
        let result = copy_with_worker(
            "fixture secret".into(),
            Duration::from_secs(30),
            |value, ttl, ready| {
                copy_concealed_on_worker(
                    value,
                    ttl,
                    ready,
                    |_| Err(locket_platform::PlatformError::MasterKeyNotFound),
                    |_| unreachable!("failed writes must not clear the existing clipboard"),
                    |_| unreachable!("failed writes must not start the expiry timer"),
                );
            },
        )
        .await;
        assert!(matches!(result, Err(ClipboardError::Backend(message))
            if message == locket_platform::PlatformError::MasterKeyNotFound.to_string()));
    }
}
