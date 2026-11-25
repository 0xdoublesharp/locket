pub mod core_dumps;
pub mod memory_lock;

#[cfg(all(test, target_os = "macos"))]
fn with_isolated_process(
    qualified_test_name: &str,
    check: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    const CHILD: &str = "LOCKET_TEST_HARDENING_CHILD";
    if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new(qualified_test_name)) {
        return check();
    }

    // The unit-test harness lists local module paths without the crate name.
    let (_, test) = qualified_test_name
        .split_once("::")
        .ok_or_else(|| std::io::Error::other("missing crate in hardening test name"))?;
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", test])
        .env(CHILD, qualified_test_name)
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{}: {stdout}", output.status);
    assert!(stdout.contains("1 passed"), "{stdout}");
    Ok(())
}
