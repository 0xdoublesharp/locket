//! Real main-thread delivery and teardown without locking or sleeping the host.
#![allow(unused_crate_dependencies)]

#[cfg(target_os = "macos")]
fn main() -> std::io::Result<()> {
    locket_platform::run_with_native_session_loop(|| {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async {
            // Startup waits for a private, unique distributed notification
            // through the actual OS center, not an injected callback.
            let observer = locket_platform::SessionObserver::start(|| {}).await?;
            drop(observer);
            // A second observer verifies teardown did not stop the driver or
            // leave a subscription owning the previous callback context.
            let observer = locket_platform::SessionObserver::start(|| {}).await?;
            drop(observer);
            Ok(())
        })
    })?
}

#[cfg(target_os = "windows")]
#[allow(clippy::print_stderr)]
fn main() -> std::io::Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        for _ in 0..2 {
            let failed = Arc::new(AtomicBool::new(false));
            let called = Arc::clone(&failed);
            let mut observer = match locket_platform::SessionObserver::start(move || {
                called.store(true, Ordering::SeqCst);
            })
            .await
            {
                Ok(observer) => observer,
                Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
                    // Windows service/session-0 runners cannot establish an
                    // interactive-session observer. Exercise truthful startup
                    // failure without claiming native event delivery there.
                    eprintln!("native Windows session observer unavailable on this host: {error}");
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let initial = observer.try_next_event()?.ok_or_else(|| {
                std::io::Error::other("native Windows observer omitted initial lock state")
            })?;
            assert!(matches!(
                initial.event,
                locket_platform::NativeSessionEvent::ScreenLock
                    | locket_platform::NativeSessionEvent::ScreenUnlock
            ));
            drop(observer);
            assert!(!failed.load(Ordering::SeqCst));
        }
        Ok(())
    })
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn main() {}
