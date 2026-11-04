//! Native session notifications. Observers carry metadata, never keys.

use std::io;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "linux", target_os = "windows", test))]
mod portable;
#[cfg(target_os = "windows")]
mod windows;

/// A native transition that invalidates cached unlocks and live grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSessionEvent {
    /// The system is about to suspend.
    SystemSleep,
    /// The system resumed; require fresh authorization for the new session.
    SystemWake,
    /// The user's screen locked.
    ScreenLock,
    /// The user's screen unlocked; pre-lock grants remain revoked.
    ScreenUnlock,
}

/// One native event and its opaque acknowledgement identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeSessionNotification {
    /// The transition to apply to the agent's authorization state.
    pub event: NativeSessionEvent,
    sleep_token: Option<u64>,
}

impl NativeSessionNotification {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
    const fn new(event: NativeSessionEvent, sleep_token: Option<u64>) -> Self {
        Self { event, sleep_token }
    }
}

/// Run work with the OS's required native session event loop.
///
/// On macOS's main thread this runs `work` on a worker while servicing native
/// callbacks on the main thread. Other callers run directly; macOS observers
/// explicitly report unavailable when no main-thread driver exists.
///
/// # Errors
/// Returns a native loop initialization error or worker panic.
pub fn run_with_native_session_loop<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> io::Result<T> {
    #[cfg(target_os = "macos")]
    {
        macos::run(work)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(work())
    }
}

/// An owned native notification subscription, stopped when dropped.
pub struct SessionObserver {
    // Stop and join native delivery before dropping its receiver. Otherwise a
    // callback racing normal destruction could mistake it for monitor loss.
    #[cfg(target_os = "macos")]
    guard: macos::ObserverGuard,
    #[cfg(target_os = "linux")]
    guard: linux::ObserverGuard,
    #[cfg(target_os = "windows")]
    guard: windows::ObserverGuard,
    receiver: mpsc::Receiver<NativeSessionNotification>,
    backend_name: &'static str,
}

impl SessionObserver {
    /// Subscribe to native transitions and verify real notification delivery.
    ///
    /// `sleep_lock_failed` must fail closed if key erasure is not acknowledged
    /// before the OS's suspend deadline or if the bounded event queue overflows.
    /// Native transitions must never be silently dropped.
    ///
    /// # Errors
    /// Returns an explicit error when native monitoring or delivery is unavailable.
    pub async fn start(sleep_lock_failed: impl Fn() + Send + Sync + 'static) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        {
            macos::start(std::sync::Arc::new(sleep_lock_failed)).await
        }
        #[cfg(target_os = "linux")]
        {
            linux::start(std::sync::Arc::new(sleep_lock_failed)).await
        }
        #[cfg(target_os = "windows")]
        {
            windows::start(std::sync::Arc::new(sleep_lock_failed)).await
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _unused = sleep_lock_failed;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native sleep/screen-lock monitoring is not implemented on this platform; use locket lock or short unlock TTLs",
            ))
        }
    }

    /// Wait for a native transition; `None` means monitoring stopped.
    ///
    /// Transitions are ordered and never coalesced. Queue overflow invokes the
    /// failure callback so the daemon cannot silently miss a lock transition.
    pub async fn next_event(&mut self) -> Option<NativeSessionNotification> {
        self.receiver.recv().await
    }

    /// Drain an already queued transition before accepting authorizations.
    ///
    /// # Errors
    /// Returns an error when the native monitor has stopped. `None` means
    /// all currently queued events have been consumed.
    pub fn try_next_event(&mut self) -> io::Result<Option<NativeSessionNotification>> {
        match self.receiver.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(io::Error::other("native session monitor stopped"))
            }
        }
    }

    /// Native backend that established this observer's registrations.
    #[must_use]
    pub const fn backend_name(&self) -> &'static str {
        self.backend_name
    }

    /// Acknowledge this event after key erasure and grant revocation.
    /// Call this even if writing the audit record fails after erasure.
    /// An older or unrelated event cannot acknowledge a newly pending sleep.
    pub fn acknowledge_event(&self, event: NativeSessionNotification) {
        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        self.guard.acknowledge(event.sleep_token);
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        let _unused = event;
    }
}
