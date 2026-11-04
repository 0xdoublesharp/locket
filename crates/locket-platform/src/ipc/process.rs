//! Process identity helpers used for live grant binding.

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::PlatformError;

/// Process identity captured when a live grant is issued.
///
/// The start-time token is intentionally opaque. Callers compare it for exact
/// equality instead of interpreting platform-specific clock or tick units.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessBinding {
    /// Operating-system process id.
    pub pid: u32,
    /// Platform-specific process start metadata.
    pub process_start_time: String,
}

impl ProcessBinding {
    /// Creates a process binding from already captured metadata.
    #[must_use]
    pub fn new(pid: u32, process_start_time: impl Into<String>) -> Self {
        Self { pid, process_start_time: process_start_time.into() }
    }
}

/// Capture a binding for the current process.
///
/// # Errors
///
/// Returns [`PlatformError::ProcessStartTimeUnavailable`] when the platform
/// cannot report stable start metadata for the process.
pub fn current_process_binding() -> Result<ProcessBinding, PlatformError> {
    process_binding_for_pid(std::process::id())
}

/// Capture a binding for an arbitrary process id.
///
/// # Errors
///
/// Returns [`PlatformError::ProcessStartTimeUnavailable`] if the process is not
/// live or if the platform metadata source is unavailable.
pub fn process_binding_for_pid(pid: u32) -> Result<ProcessBinding, PlatformError> {
    Ok(ProcessBinding::new(pid, process_start_time_for_pid(pid)?))
}

/// Validate that the binding still refers to the same live process.
///
/// This returns `Ok(false)` when the PID is gone or its start-time token no
/// longer matches. I/O and parser failures from a live metadata source are
/// surfaced so callers can fail closed instead of trusting the PID alone.
///
/// # Errors
///
/// Returns platform I/O errors other than "not found", plus
/// [`PlatformError::ProcessStartTimeUnavailable`] for malformed metadata.
pub fn process_binding_matches_live_process(
    binding: &ProcessBinding,
) -> Result<bool, PlatformError> {
    match process_start_time_for_pid(binding.pid) {
        Ok(current) => Ok(current == binding.process_start_time),
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(PlatformError::ProcessStartTimeUnavailable) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Returns whether a Windows process id currently refers to a live process.
#[cfg(target_os = "windows")]
#[must_use]
pub fn windows_process_is_live(pid: u32) -> bool {
    windows_process_impl::process_is_live(pid)
}

/// Terminates a Windows process by id.
///
/// # Errors
///
/// Returns the OS error from opening or terminating the process.
#[cfg(target_os = "windows")]
pub fn terminate_windows_process(pid: u32) -> Result<(), PlatformError> {
    windows_process_impl::terminate_process(pid).map_err(PlatformError::Io)
}

#[cfg(target_os = "linux")]
fn process_start_time_for_pid(pid: u32) -> Result<String, PlatformError> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let after_name = stat.rsplit_once(") ").ok_or(PlatformError::ProcessStartTimeUnavailable)?.1;
    let fields = after_name.split_whitespace().collect::<Vec<_>>();
    let start_time = fields.get(19).ok_or(PlatformError::ProcessStartTimeUnavailable)?;
    if start_time.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok((*start_time).to_owned())
    } else {
        Err(PlatformError::ProcessStartTimeUnavailable)
    }
}

#[cfg(target_os = "macos")]
fn process_start_time_for_pid(pid: u32) -> Result<String, PlatformError> {
    let output = Command::new("ps")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .output()
        .map_err(PlatformError::Io)?;
    if !output.status.success() {
        return Err(PlatformError::ProcessStartTimeUnavailable);
    }
    let text =
        String::from_utf8(output.stdout).map_err(|_| PlatformError::ProcessStartTimeUnavailable)?;
    let rendered = text.trim();
    if rendered.is_empty() {
        return Err(PlatformError::ProcessStartTimeUnavailable);
    }
    parse_macos_lstart(rendered)?;
    Ok(rendered.to_owned())
}

#[cfg(target_os = "macos")]
fn parse_macos_lstart(value: &str) -> Result<(), PlatformError> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    let [weekday, month, day, time, year] = fields.as_slice() else {
        return Err(PlatformError::ProcessStartTimeUnavailable);
    };
    let known_weekday = matches!(*weekday, "Mon" | "Tue" | "Wed" | "Thu" | "Fri" | "Sat" | "Sun");
    let known_month = matches!(
        *month,
        "Jan"
            | "Feb"
            | "Mar"
            | "Apr"
            | "May"
            | "Jun"
            | "Jul"
            | "Aug"
            | "Sep"
            | "Oct"
            | "Nov"
            | "Dec"
    );
    let day_ok = day.parse::<u8>().is_ok_and(|value| (1..=31).contains(&value));
    let year_ok = year.parse::<u16>().is_ok_and(|value| value >= 1970);
    let time_fields = time.split(':').collect::<Vec<_>>();
    let clock_ok = match time_fields.as_slice() {
        [hour, minute, second] => {
            hour.parse::<u8>().is_ok_and(|value| value <= 23)
                && minute.parse::<u8>().is_ok_and(|value| value <= 59)
                && second.parse::<u8>().is_ok_and(|value| value <= 60)
        }
        _ => false,
    };
    if known_weekday && known_month && day_ok && clock_ok && year_ok {
        Ok(())
    } else {
        Err(PlatformError::ProcessStartTimeUnavailable)
    }
}

#[cfg(target_os = "windows")]
fn process_start_time_for_pid(pid: u32) -> Result<String, PlatformError> {
    windows_process_impl::start_time_for_pid(pid)
}

#[cfg(target_os = "windows")]
mod windows_process_impl {
    #![allow(unsafe_code)]

    use std::io;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, WAIT_FAILED, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
    };

    use crate::PlatformError;

    struct ProcessHandle(HANDLE);

    impl ProcessHandle {
        fn open_query(pid: u32) -> Result<Self, PlatformError> {
            // SAFETY: request only query/synchronize rights for the supplied PID.
            let handle = unsafe {
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid)
            };
            if handle.is_null() {
                let error = io::Error::last_os_error();
                if error
                    .raw_os_error()
                    .is_some_and(|code| u32::try_from(code) == Ok(ERROR_INVALID_PARAMETER))
                {
                    return Err(PlatformError::ProcessStartTimeUnavailable);
                }
                return Err(PlatformError::Io(error));
            }
            Ok(Self(handle))
        }

        fn require_live(&self) -> Result<(), PlatformError> {
            // SAFETY: this owned process handle has SYNCHRONIZE access. A zero
            // timeout probes liveness without waiting or relying on exit codes.
            match unsafe { WaitForSingleObject(self.0, 0) } {
                WAIT_TIMEOUT => Ok(()),
                WAIT_FAILED => Err(PlatformError::Io(io::Error::last_os_error())),
                _ => Err(PlatformError::ProcessStartTimeUnavailable),
            }
        }
    }

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            // SAFETY: this handle came from OpenProcess and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    pub(super) fn start_time_for_pid(pid: u32) -> Result<String, PlatformError> {
        // Keep the same kernel process object alive through both liveness
        // probes and the creation-time query so PID reuse cannot mix identities.
        let process = ProcessHandle::open_query(pid)?;
        process.require_live()?;
        let mut created = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut exited = created;
        let mut kernel = created;
        let mut user = created;
        // SAFETY: the handle has QUERY_LIMITED_INFORMATION rights, stays alive,
        // and all four FILETIME outputs are distinct writable local values.
        if unsafe {
            GetProcessTimes(
                process.0,
                &raw mut created,
                &raw mut exited,
                &raw mut kernel,
                &raw mut user,
            )
        } == 0
        {
            return Err(PlatformError::Io(io::Error::last_os_error()));
        }
        process.require_live()?;
        let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        if ticks == 0 {
            return Err(PlatformError::ProcessStartTimeUnavailable);
        }
        Ok(ticks.to_string())
    }

    pub(super) fn process_is_live(pid: u32) -> bool {
        // SAFETY: `OpenProcess` is called with query/synchronize
        // access for a PID read from the user-scoped pid file. A null
        // handle means not live.
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE, 0, pid) };
        if handle.is_null() {
            return false;
        }
        // SAFETY: `handle` is valid until closed below.
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        // SAFETY: `handle` was opened by `OpenProcess`.
        unsafe {
            CloseHandle(handle);
        }
        wait == WAIT_TIMEOUT
    }

    pub(super) fn terminate_process(pid: u32) -> io::Result<()> {
        // SAFETY: `OpenProcess` is called with terminate access for a
        // PID supplied by the caller.
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is a process handle opened with
        // PROCESS_TERMINATE.
        let terminated = unsafe { TerminateProcess(handle, 0) };
        let terminate_error = if terminated == 0 { Some(io::Error::last_os_error()) } else { None };
        // SAFETY: `handle` was opened by `OpenProcess`.
        unsafe {
            CloseHandle(handle);
        }
        if let Some(error) = terminate_error {
            return Err(error);
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            ProcessBinding, current_process_binding, process_binding_for_pid,
            process_binding_matches_live_process,
        };

        struct ChildGuard(std::process::Child);

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _kill = self.0.kill();
                let _wait = self.0.wait();
            }
        }

        #[test]
        fn windows_process_creation_token_is_stable_and_rejects_stale_bindings()
        -> Result<(), PlatformError> {
            let first = current_process_binding()?;
            let second = current_process_binding()?;
            assert_eq!(first, second);
            assert!(first.process_start_time.parse::<u64>().is_ok_and(|ticks| ticks > 0));
            assert!(process_binding_matches_live_process(&first)?);
            let stale =
                ProcessBinding::new(first.pid, format!("{}-stale", first.process_start_time));
            assert!(!process_binding_matches_live_process(&stale)?);
            assert!(!process_binding_matches_live_process(&ProcessBinding::new(u32::MAX, "0"))?);
            Ok(())
        }

        #[test]
        fn windows_process_binding_rejects_terminated_child()
        -> Result<(), Box<dyn std::error::Error>> {
            use std::io::Read;
            use std::process::{Command, Stdio};

            const CHILD: &str = "LOCKET_PROCESS_BINDING_CHILD";
            if std::env::var_os(CHILD).is_some() {
                let mut byte = [0];
                let _read = io::stdin().read(&mut byte)?;
                return Ok(());
            }
            let mut child = ChildGuard(
                Command::new(std::env::current_exe()?)
                    .args([
                        "--exact",
                        "ipc::process::windows_process_impl::tests::windows_process_binding_rejects_terminated_child",
                    ])
                    .env(CHILD, "1")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()?,
            );
            let binding = process_binding_for_pid(child.0.id())?;
            let held_process = ProcessHandle::open_query(binding.pid)?;
            assert!(process_binding_matches_live_process(&binding)?);
            child.0.kill()?;
            child.0.wait()?;

            // Keep a kernel handle alive after exit: creation metadata remains
            // queryable, but it must never make this dead process valid again.
            assert!(matches!(
                held_process.require_live(),
                Err(PlatformError::ProcessStartTimeUnavailable)
            ));
            assert!(!process_binding_matches_live_process(&binding)?);
            assert!(matches!(
                start_time_for_pid(binding.pid),
                Err(PlatformError::ProcessStartTimeUnavailable)
            ));
            Ok(())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn process_start_time_for_pid(_pid: u32) -> Result<String, PlatformError> {
    Err(PlatformError::ProcessStartTimeUnavailable)
}
