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

use std::env;
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
    if cfg!(target_os = "linux") {
        let session = env::var("XDG_SESSION_TYPE").unwrap_or_default();
        let wayland_display = env::var("WAYLAND_DISPLAY").unwrap_or_default();
        if session.eq_ignore_ascii_case("wayland") || !wayland_display.is_empty() {
            return ClipboardPlatform::Wayland;
        }
    }
    ClipboardPlatform::Standard
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

trait ClipboardBackend {
    fn write(&mut self, value: &str) -> Result<(), ClipboardError>;
    fn read(&mut self) -> Result<String, ClipboardError>;
    fn clear(&mut self) -> Result<(), ClipboardError>;
}

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
/// The worker retains selection ownership until the TTL expires, then clears
/// only if the clipboard still contains this value.
pub(crate) async fn copy_with_ttl(value: String, ttl: Duration) -> Result<(), ClipboardError> {
    let value = Zeroizing::new(value);
    let (ready, written) = oneshot::channel();
    std::thread::Builder::new()
        .name("locket-clipboard".into())
        .spawn(move || {
            copy_on_worker(value, ttl, ready, ClipboardSession::new, std::thread::sleep);
        })
        .map_err(|error| ClipboardError::Backend(error.to_string()))?;
    written.await.map_err(|_| ClipboardError::Backend("clipboard worker stopped".into()))?
}

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

    use super::{
        ClipboardBackend, ClipboardCopyDecision, ClipboardCopyOutcome, ClipboardError,
        ClipboardPlatform, clipboard_platform, copy_on_worker, decide_clear,
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
    fn clipboard_platform_returns_a_known_variant() {
        // The function is platform-dependent so we just assert the
        // probe terminates and returns one of the documented variants.
        match clipboard_platform() {
            ClipboardPlatform::Standard | ClipboardPlatform::Wayland => {}
        }
    }

    #[test]
    fn unsupported_outcome_surfaces_a_stable_wayland_reason_code() {
        let outcome =
            ClipboardCopyOutcome::Unsupported { unsupported_reason: "wayland-session".to_owned() };
        assert!(matches!(&outcome, ClipboardCopyOutcome::Unsupported { .. }));
        if let ClipboardCopyOutcome::Unsupported { unsupported_reason } = outcome {
            assert_eq!(unsupported_reason, "wayland-session");
        }
    }
}
