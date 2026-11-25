//! Core-dump suppression for processes that hold key material.
//!
//! Per `docs/specs/agent.md`:
//!
//! - Linux agents must call `prctl(PR_SET_DUMPABLE, 0)` and set
//!   `RLIMIT_CORE = 0` where available.
//! - macOS and Windows agents must use the closest platform-supported
//!   core-dump suppression and process hardening available to a
//!   user-space app.
//!
//! On Linux this lowers `RLIMIT_CORE` to zero (so the kernel writes no
//! core file even if the user's shell raised the limit) and clears
//! `PR_SET_DUMPABLE` (so `/proc/<pid>/mem` and `ptrace` from same-uid
//! debuggers don't yield key material). On macOS `RLIMIT_CORE = 0`
//! suppresses core dumps and the release agent separately calls
//! `ptrace(PT_DENY_ATTACH, 0, 0, 0)` to deny debugger attachment.
//! On Windows the supported mitigation is `SetErrorMode(SEM_NOGPFAULTERRORBOX |
//! SEM_FAILCRITICALERRORS)`, which suppresses Windows Error Reporting
//! crash dumps and the system "this program has stopped responding"
//! dialog. The Windows path is implemented through
//! [`windows-sys`](https://crates.io/crates/windows-sys), gated behind
//! `cfg(target_os = "windows")`.

use std::fmt::{self, Display};

/// Outcome of a [`disable_core_dumps`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreDumpHardening {
    /// All available mitigations succeeded on this platform.
    Active,
    /// Core dumps are suppressed without a verified debugger-attach
    /// mitigation. On macOS this means `RLIMIT_CORE = 0` and no
    /// `PT_DENY_ATTACH` call. On Windows, this indicates best-effort
    /// suppression via `SetErrorMode`.
    Suppressed,
    /// The platform has no implementation in this build. Diagnostics
    /// should surface this so users know the fall-back state.
    Unsupported,
    /// At least one mitigation failed; key material may still be
    /// observable. The caller should fail closed where the spec
    /// demands it and otherwise surface `Degraded` to diagnostics.
    Degraded,
}

impl Display for CoreDumpHardening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Active => "active",
            Self::Suppressed => "suppressed",
            Self::Unsupported => "unsupported",
            Self::Degraded => "degraded",
        })
    }
}

/// Disables core-dump generation for the current process.
///
/// Dispatches to the platform-specific implementation:
///
/// - **Linux:** [`unix::disable_linux_core_dumps`] —
///   `prctl(PR_SET_DUMPABLE, 0)` plus `setrlimit(RLIMIT_CORE, 0, 0)`.
/// - **macOS / other BSD Unixes:** `setrlimit(RLIMIT_CORE, 0, 0)`.
///   macOS release agents also call `disable_debugger_attach()`
///   at their daemon entry point.
/// - **Windows:** [`windows_impl::disable_windows_core_dumps`] —
///   `SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS)`
///   to suppress Windows Error Reporting crash dumps.
///
/// The call is idempotent and safe to invoke from any process.
#[must_use]
pub fn disable_core_dumps() -> CoreDumpHardening {
    #[cfg(target_os = "linux")]
    {
        unix::disable_linux_core_dumps()
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        unix::disable_unix_core_dumps()
    }
    #[cfg(target_os = "windows")]
    {
        windows_impl::disable_windows_core_dumps()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        CoreDumpHardening::Unsupported
    }
}

/// Returns the current core-dump hardening state without changing it.
///
/// This is what `locket doctor` reports — `disable_core_dumps()` is
/// already called once at process startup, so this inspects
/// `RLIMIT_CORE` and either `PR_GET_DUMPABLE` on Linux or the recorded
/// `PT_DENY_ATTACH` result on macOS. On Windows the call queries the current
/// process error-mode bits via `GetErrorMode` and returns
/// `Suppressed` when both `SEM_NOGPFAULTERRORBOX` and
/// `SEM_FAILCRITICALERRORS` are set.
#[must_use]
pub fn core_dump_hardening_state() -> CoreDumpHardening {
    #[cfg(unix)]
    {
        unix::core_dump_hardening_state()
    }
    #[cfg(target_os = "windows")]
    {
        windows_impl::core_dump_hardening_state()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        CoreDumpHardening::Unsupported
    }
}

#[cfg(target_os = "macos")]
static DEBUGGER_ATTACH_DENIED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Denies debugger attachment to the calling macOS release agent.
///
/// Call this at daemon startup after disabling core dumps. macOS
/// terminates the process if a debugger is already attached. Debug
/// and unit-test builds skip the `ptrace` call.
#[cfg(target_os = "macos")]
#[must_use]
pub fn disable_debugger_attach() -> CoreDumpHardening {
    #[cfg(all(target_os = "macos", not(debug_assertions), not(test)))]
    DEBUGGER_ATTACH_DENIED.get_or_init(macos_ptrace::deny_attach);
    core_dump_hardening_state()
}

#[cfg(target_os = "macos")]
const fn macos_status(
    core_zeroed: bool,
    debugger_attach_denied: Option<bool>,
) -> CoreDumpHardening {
    match (core_zeroed, debugger_attach_denied) {
        (true, Some(true)) => CoreDumpHardening::Active,
        (true, None) => CoreDumpHardening::Suppressed,
        _ => CoreDumpHardening::Degraded,
    }
}

#[cfg(all(target_os = "macos", any(test, not(debug_assertions))))]
#[allow(unsafe_code)]
mod macos_ptrace {
    use std::ffi::{c_char, c_int};

    const PT_DENY_ATTACH: c_int = 31;

    #[link(name = "System")]
    unsafe extern "C" {
        fn ptrace(request: c_int, pid: c_int, addr: *mut c_char, data: c_int) -> c_int;
    }

    pub(super) fn deny_attach() -> bool {
        // SAFETY: PT_DENY_ATTACH ignores pid, addr, and data. The
        // kernel receives no Rust memory to read or write.
        unsafe { ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) == 0 }
    }
}

#[cfg(unix)]
mod unix {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    use super::CoreDumpHardening;

    /// Linux-specific entry point: `prctl(PR_SET_DUMPABLE, 0)` plus
    /// `setrlimit(RLIMIT_CORE, 0, 0)`. Both calls in one place so the
    /// agent boot path and tests can target the Linux contract
    /// directly. Equivalent to:
    ///
    /// ```text
    /// libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    /// libc::setrlimit(libc::RLIMIT_CORE, &rlim { rlim_cur: 0, rlim_max: 0 });
    /// ```
    ///
    /// Routed through `rustix` so the call is `unsafe`-free and shares
    /// the typed `DumpableBehavior` enum with the doctor read path.
    #[cfg(target_os = "linux")]
    pub fn disable_linux_core_dumps() -> CoreDumpHardening {
        let core_ok = set_core_rlimit_zero();
        let dumpable_ok = clear_dumpable_flag();
        if core_ok && dumpable_ok { CoreDumpHardening::Active } else { CoreDumpHardening::Degraded }
    }

    /// macOS / BSD entry point: `setrlimit(RLIMIT_CORE, 0, 0)`.
    #[cfg(not(target_os = "linux"))]
    pub fn disable_unix_core_dumps() -> CoreDumpHardening {
        core_dump_status(set_core_rlimit_zero())
    }

    pub fn core_dump_hardening_state() -> CoreDumpHardening {
        let core_zeroed =
            matches!(getrlimit(Resource::Core), Rlimit { current: Some(0), maximum: Some(0) });
        core_dump_status(core_zeroed)
    }

    #[cfg(target_os = "linux")]
    fn core_dump_status(core_zeroed: bool) -> CoreDumpHardening {
        if core_zeroed && dumpable_flag_cleared() {
            CoreDumpHardening::Active
        } else {
            CoreDumpHardening::Degraded
        }
    }

    #[cfg(target_os = "macos")]
    fn core_dump_status(core_zeroed: bool) -> CoreDumpHardening {
        super::macos_status(core_zeroed, super::DEBUGGER_ATTACH_DENIED.get().copied())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const fn core_dump_status(core_zeroed: bool) -> CoreDumpHardening {
        if core_zeroed { CoreDumpHardening::Active } else { CoreDumpHardening::Degraded }
    }

    fn set_core_rlimit_zero() -> bool {
        setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) }).is_ok()
    }

    /// `prctl(PR_SET_DUMPABLE, 0)` via rustix's typed wrapper.
    #[cfg(target_os = "linux")]
    fn clear_dumpable_flag() -> bool {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .is_ok()
    }

    /// `prctl(PR_GET_DUMPABLE)` via rustix's typed wrapper.
    #[cfg(target_os = "linux")]
    fn dumpable_flag_cleared() -> bool {
        matches!(
            rustix::process::dumpable_behavior(),
            Ok(rustix::process::DumpableBehavior::NotDumpable)
        )
    }
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod windows_impl {
    // SAFETY-AUDIT: this module is the second `unsafe` concession in
    // `locket-platform`. It calls `SetErrorMode` and `GetErrorMode`
    // from `windows-sys`, which are exposed as `unsafe extern "system"`
    // because they are direct FFI into Win32. Both calls are safe in
    // practice — the arguments are plain `u32` flag bitmasks and
    // neither function takes pointers — but Rust's type system cannot
    // express that, so the calls live in narrowly scoped `unsafe`
    // blocks. The wider workspace lint is `unsafe_code = "deny"`,
    // which the parent `Cargo.toml` already downgrades from `forbid`
    // for the macOS LocalAuthentication backend; this module reuses
    // that opt-out with a per-module `#![allow(unsafe_code)]`.
    //
    // `SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS)`
    // suppresses Windows Error Reporting crash dialogs and the
    // "critical error" dialog the kernel raises on disk faults. It
    // returns the previous mask, which we deliberately discard:
    // `disable_core_dumps` is the single startup-time hardening call
    // and is intentionally one-way for the lifetime of the process.
    //
    // Spec ref: `docs/specs/agent.md` (process hardening), and
    // <https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode>.

    use windows_sys::Win32::System::Diagnostics::Debug::{
        GetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
    };

    use super::CoreDumpHardening;

    /// Mask of the bits this module sets / inspects.
    const SUPPRESSION_MASK: u32 = SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS;

    /// Windows entry point: `SetErrorMode(SEM_NOGPFAULTERRORBOX |
    /// SEM_FAILCRITICALERRORS)`. The previous mode bits are merged in
    /// to avoid clobbering other suppressions a host process might
    /// have applied.
    #[must_use]
    pub fn disable_windows_core_dumps() -> CoreDumpHardening {
        // SAFETY: `GetErrorMode` and `SetErrorMode` take and return a
        // process-wide `u32` flag mask. They have no pointer arguments
        // and document no error semantics other than the returned mask.
        let merged = unsafe {
            let previous = GetErrorMode();
            let merged = previous | SUPPRESSION_MASK;
            // `SetErrorMode` returns the previous mode but cannot fail.
            let _ = SetErrorMode(merged);
            merged
        };
        if merged & SUPPRESSION_MASK == SUPPRESSION_MASK {
            CoreDumpHardening::Suppressed
        } else {
            CoreDumpHardening::Degraded
        }
    }

    /// Inspects the live error-mode mask without changing it.
    #[must_use]
    pub fn core_dump_hardening_state() -> CoreDumpHardening {
        // SAFETY: `GetErrorMode` returns the current process-wide
        // `u32` mask. No pointers, no error semantics.
        let current = unsafe { GetErrorMode() };
        if current & SUPPRESSION_MASK == SUPPRESSION_MASK {
            CoreDumpHardening::Suppressed
        } else {
            CoreDumpHardening::Degraded
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CoreDumpHardening, core_dump_hardening_state, disable_core_dumps};

    #[cfg(unix)]
    const CORE_DUMPS_DISABLED: CoreDumpHardening = if cfg!(target_os = "macos") {
        CoreDumpHardening::Suppressed
    } else {
        CoreDumpHardening::Active
    };

    #[test]
    fn hardening_outcomes_render_as_doctor_labels() {
        assert_eq!(CoreDumpHardening::Active.to_string(), "active");
        assert_eq!(CoreDumpHardening::Suppressed.to_string(), "suppressed");
        assert_eq!(CoreDumpHardening::Unsupported.to_string(), "unsupported");
        assert_eq!(CoreDumpHardening::Degraded.to_string(), "degraded");
    }

    /// Cross-platform dispatcher smoke check: must not panic and must
    /// return a value the doctor can render.
    #[test]
    fn dispatcher_returns_a_well_formed_outcome() {
        let outcome = disable_core_dumps();
        assert!(matches!(
            outcome,
            CoreDumpHardening::Active
                | CoreDumpHardening::Suppressed
                | CoreDumpHardening::Degraded
                | CoreDumpHardening::Unsupported
        ));
        let _ = core_dump_hardening_state().to_string();
    }

    #[cfg(unix)]
    #[test]
    fn disable_core_dumps_lowers_rlimit_core_to_zero() {
        use rustix::process::{Resource, getrlimit};

        let outcome = disable_core_dumps();
        assert_eq!(outcome, CORE_DUMPS_DISABLED);

        let limit = getrlimit(Resource::Core);
        assert_eq!(limit.current, Some(0));
        assert_eq!(limit.maximum, Some(0));
    }

    #[cfg(unix)]
    #[test]
    fn disable_core_dumps_is_idempotent() {
        let first = disable_core_dumps();
        let second = disable_core_dumps();
        assert_eq!(first, CORE_DUMPS_DISABLED);
        assert_eq!(second, CORE_DUMPS_DISABLED);
    }

    /// Subtask 1: explicit Linux entry-point smoke test — confirms
    /// `disable_linux_core_dumps` returns `Active` on Linux hosts.
    #[cfg(target_os = "linux")]
    #[test]
    fn disable_linux_core_dumps_returns_ok() {
        assert_eq!(super::unix::disable_linux_core_dumps(), CoreDumpHardening::Active);
    }

    /// Subtask 1: confirm `prctl(PR_GET_DUMPABLE)` returns 0 after
    /// `disable_linux_core_dumps()` runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn disable_linux_core_dumps_clears_pr_get_dumpable() {
        use rustix::process::{DumpableBehavior, dumpable_behavior};

        let outcome = super::unix::disable_linux_core_dumps();
        assert_eq!(outcome, CoreDumpHardening::Active);
        assert!(matches!(dumpable_behavior(), Ok(DumpableBehavior::NotDumpable)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_test_build_suppresses_core_dumps_without_denying_attach() {
        assert_eq!(disable_core_dumps(), CoreDumpHardening::Suppressed);
        assert_eq!(super::disable_debugger_attach(), CoreDumpHardening::Suppressed);
        assert_eq!(core_dump_hardening_state(), CoreDumpHardening::Suppressed);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_status_distinguishes_skipped_and_failed_debugger_protection() {
        use super::macos_status;

        assert_eq!(macos_status(true, Some(true)), CoreDumpHardening::Active);
        assert_eq!(macos_status(true, None), CoreDumpHardening::Suppressed);
        assert_eq!(macos_status(true, Some(false)), CoreDumpHardening::Degraded);
        assert_eq!(macos_status(false, Some(true)), CoreDumpHardening::Degraded);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_ptrace_succeeds_in_isolated_process() -> std::io::Result<()> {
        crate::hardening::with_isolated_process(
            concat!(module_path!(), "::macos_ptrace_succeeds_in_isolated_process"),
            || {
                assert!(super::macos_ptrace::deny_attach());
                Ok(())
            },
        )
    }

    /// Windows entry-point compile + behaviour test: `SetErrorMode`
    /// resolves and the call returns `Suppressed` once both
    /// `SEM_NOGPFAULTERRORBOX` and `SEM_FAILCRITICALERRORS` are set.
    /// Compile coverage is the primary value here — most CI runs are
    /// unix and never observe this assertion.
    #[cfg(target_os = "windows")]
    #[test]
    fn disable_windows_core_dumps_reports_suppressed() {
        assert_eq!(
            super::windows_impl::disable_windows_core_dumps(),
            CoreDumpHardening::Suppressed
        );
        assert_eq!(super::windows_impl::core_dump_hardening_state(), CoreDumpHardening::Suppressed);
    }

    /// Windows idempotency: a second call must not flip the result
    /// back to `Degraded` (the merge-with-previous-mode logic must
    /// preserve the suppression bits).
    #[cfg(target_os = "windows")]
    #[test]
    fn disable_windows_core_dumps_is_idempotent() {
        let first = super::windows_impl::disable_windows_core_dumps();
        let second = super::windows_impl::disable_windows_core_dumps();
        assert_eq!(first, CoreDumpHardening::Suppressed);
        assert_eq!(second, CoreDumpHardening::Suppressed);
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    #[test]
    fn disable_core_dumps_reports_unsupported_on_other_targets() {
        assert_eq!(disable_core_dumps(), CoreDumpHardening::Unsupported);
    }
}
