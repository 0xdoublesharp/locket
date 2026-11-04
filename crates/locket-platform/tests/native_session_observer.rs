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

#[cfg(not(target_os = "macos"))]
fn main() {}
