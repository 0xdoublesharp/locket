//! Windows named-pipe path and ACL helpers for the local agent.
//!
//! The Windows request loop is owned by `locket-agent`, but the path,
//! security descriptor rules, and raw security-attribute pipe creation
//! live here so CLI, desktop, and tests can share one contract while
//! platform-specific unsafe code stays in the platform crate.

use std::borrow::Cow;

use crate::PlatformError;

/// Windows named-pipe prefix for the local agent endpoint.
pub const AGENT_PIPE_PREFIX: &str = r"\\.\pipe\locket-agent-";

/// Returns the spec-mandated Windows named-pipe path for a user SID.
///
/// # Errors
///
/// Returns [`PlatformError::InvalidWindowsSid`] when `sid` is empty,
/// malformed, or would produce an overlong pipe path.
pub fn agent_pipe_name_for_sid(sid: &str) -> Result<String, PlatformError> {
    let sid = validate_sid_fragment(sid)?;
    let pipe_name = format!("{AGENT_PIPE_PREFIX}{sid}");
    if pipe_name.len() > 256 {
        return Err(PlatformError::InvalidWindowsSid);
    }
    Ok(pipe_name)
}

/// Returns the protected DACL SDDL used when creating the agent pipe.
///
/// The descriptor sets the owner and grants generic-all to the current user's SID and
/// marks the DACL protected (`D:P`) so inherited ACEs are not added by
/// the object manager.
///
/// # Errors
///
/// Returns [`PlatformError::InvalidWindowsSid`] when `sid` is empty or malformed.
pub fn agent_pipe_dacl_sddl_for_sid(sid: &str) -> Result<String, PlatformError> {
    let sid = validate_sid_fragment(sid)?;
    Ok(format!("O:{sid}D:P(A;;GA;;;{sid})"))
}

fn validate_sid_fragment(sid: &str) -> Result<Cow<'_, str>, PlatformError> {
    let sid = sid.trim();
    if !sid.starts_with("S-") {
        return Err(PlatformError::InvalidWindowsSid);
    }
    if !sid.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
        return Err(PlatformError::InvalidWindowsSid);
    }
    Ok(Cow::Borrowed(sid))
}

/// Resolves the current user's SID as a string.
///
/// # Errors
///
/// Returns [`PlatformError::WindowsSidUnavailable`] when Windows token
/// APIs fail or return malformed data.
#[cfg(target_os = "windows")]
pub fn current_user_sid_string() -> Result<String, PlatformError> {
    windows_impl::current_user_sid_string()
}

/// Resolves the current user's default agent pipe path.
///
/// # Errors
///
/// Returns [`PlatformError::WindowsSidUnavailable`] when the current
/// user's SID cannot be read.
#[cfg(target_os = "windows")]
pub fn default_agent_pipe_name() -> Result<String, PlatformError> {
    agent_pipe_name_for_sid(&current_user_sid_string()?)
}

/// Creates a Windows named-pipe server with a protected DACL SDDL.
///
/// `locket-agent` owns the request loop, but this helper keeps the
/// reviewed `SECURITY_ATTRIBUTES` FFI boundary in `locket-platform`.
///
/// # Errors
///
/// Returns any SDDL conversion or named-pipe creation OS error.
#[cfg(target_os = "windows")]
pub fn create_agent_pipe_server_with_sddl(
    options: &tokio::net::windows::named_pipe::ServerOptions,
    pipe_name: &std::ffi::OsStr,
    sddl: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    windows_impl::create_agent_pipe_server_with_sddl(options, pipe_name, sddl)
}

/// Opens a local pipe only after verifying its object owner and server user.
///
/// The connected handle is checked before any protocol data is sent. The pipe
/// object's owner binds the check even if its original server PID was recycled.
/// The client permits identification only, never server impersonation.
///
/// # Errors
/// Rejects non-local endpoints, identity mismatches and unavailable identity data.
#[cfg(target_os = "windows")]
pub fn open_verified_agent_pipe_client(
    pipe_name: &std::ffi::OsStr,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    windows_impl::open_verified_agent_pipe_client(pipe_name)
}

#[cfg(target_os = "windows")]
mod windows_impl {
    #![allow(unsafe_code)]

    use std::ffi::{OsStr, c_void};
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::{NonNull, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::core::PWSTR;

    use crate::PlatformError;

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is a live owned process or token handle.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    pub(super) fn current_user_sid_string() -> Result<String, PlatformError> {
        // SAFETY: GetCurrentProcess returns the current process pseudo-handle.
        process_user_sid_string(unsafe { GetCurrentProcess() })
    }

    fn process_user_sid_string(process: HANDLE) -> Result<String, PlatformError> {
        let mut token: HANDLE = null_mut();
        // SAFETY: callers supply a live process handle; token is writable.
        let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) };
        if opened == 0 {
            return Err(PlatformError::WindowsSidUnavailable(last_os_error_code()));
        }
        let token = Handle(token);

        let mut needed = 0_u32;
        // SAFETY: The first call intentionally passes a null buffer to
        // query the required size per `GetTokenInformation` contract.
        unsafe {
            GetTokenInformation(token.0, TokenUser, null_mut(), 0, &raw mut needed);
        }
        if needed == 0 {
            return Err(PlatformError::WindowsSidUnavailable(last_os_error_code()));
        }

        // TOKEN_USER contains a pointer, so byte-aligned storage is insufficient.
        let mut buffer = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
        // SAFETY: `buffer` has at least the size Windows just requested, with
        // pointer alignment suitable for TOKEN_USER and its embedded SID, and
        // `needed` points to writable storage for the returned size.
        let read = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &raw mut needed,
            )
        };
        if read == 0 {
            return Err(PlatformError::WindowsSidUnavailable(last_os_error_code()));
        }

        // SAFETY: `buffer` contains a TOKEN_USER structure written by
        // `GetTokenInformation(TokenUser, ...)`.
        let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        sid_string(token_user.User.Sid)
    }

    fn sid_string(sid: *mut c_void) -> Result<String, PlatformError> {
        let mut sid_text: PWSTR = null_mut();
        // SAFETY: callers supply an OS-owned SID alive for this call.
        let converted = unsafe { ConvertSidToStringSidW(sid, &raw mut sid_text) };
        if converted == 0 || sid_text.is_null() {
            return Err(PlatformError::WindowsSidUnavailable(last_os_error_code()));
        }

        let text = wide_ptr_to_string(sid_text);
        // SAFETY: `sid_text` was allocated by `ConvertSidToStringSidW`
        // and must be released with `LocalFree`.
        unsafe {
            LocalFree(sid_text.cast::<core::ffi::c_void>() as HLOCAL);
        }
        text
    }

    pub(super) fn open_verified_agent_pipe_client(
        pipe_name: &OsStr,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        validate_local_pipe_name(pipe_name)?;
        let expected_sid = current_user_sid_string().map_err(io::Error::other)?;
        let client = tokio::net::windows::named_pipe::ClientOptions::new()
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(pipe_name)?;
        verify_pipe_server_identity(&client, &expected_sid)?;
        Ok(client)
    }

    fn validate_local_pipe_name(name: &OsStr) -> io::Result<()> {
        const PREFIX: &str = r"\\.\pipe\";
        let Some(name) = name.to_str() else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid local pipe name"));
        };
        if !name.get(..PREFIX.len()).is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
            || name.len() == PREFIX.len()
            || name[PREFIX.len()..].contains(['\\', '/', '\0'])
        {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected a local named pipe"));
        }
        Ok(())
    }

    fn verify_pipe_server_identity(
        client: &tokio::net::windows::named_pipe::NamedPipeClient,
        expected_sid: &str,
    ) -> io::Result<()> {
        let pipe = client.as_raw_handle();
        let owner_sid = pipe_owner_sid(pipe)?;
        if owner_sid != expected_sid {
            return Err(identity_denied());
        }
        let mut pid = 0;
        // SAFETY: the connected client owns a live pipe handle; pid is writable.
        if unsafe { GetNamedPipeServerProcessId(pipe, &raw mut pid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the kernel provided this PID; request only token-query access.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let process = Handle(process);
        require_process_user(process.0, expected_sid)
    }

    fn require_process_user(process: HANDLE, expected_sid: &str) -> io::Result<()> {
        let server_sid = process_user_sid_string(process).map_err(io::Error::other)?;
        if server_sid != expected_sid {
            return Err(identity_denied());
        }
        Ok(())
    }

    fn pipe_owner_sid(pipe: HANDLE) -> io::Result<String> {
        let mut owner = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: pipe is a connected live handle with GENERIC_READ/READ_CONTROL.
        // Returned owner borrows the LocalAlloc descriptor until it is freed.
        let status = unsafe {
            GetSecurityInfo(
                pipe,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &raw mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &raw mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX)));
        }
        let result = if owner.is_null() || descriptor.is_null() {
            Err(identity_denied())
        } else {
            sid_string(owner).map_err(io::Error::other)
        };
        // SAFETY: GetSecurityInfo returns a LocalAlloc descriptor (or null).
        unsafe { LocalFree(descriptor) };
        result
    }

    fn identity_denied() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "agent pipe server is not owned by this user",
        )
    }

    fn wide_ptr_to_string(ptr: *const u16) -> Result<String, PlatformError> {
        if ptr.is_null() {
            return Err(PlatformError::WindowsSidUnavailable(0));
        }
        let mut len = 0_usize;
        // SAFETY: `ptr` is a NUL-terminated UTF-16 string allocated by
        // Windows. The loop stops at the first terminator.
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            String::from_utf16(std::slice::from_raw_parts(ptr, len))
                .map_err(|_| PlatformError::WindowsSidUnavailable(0))
        }
    }

    fn last_os_error_code() -> u32 {
        // SAFETY: `GetLastError` has no preconditions.
        unsafe { GetLastError() }
    }

    pub(super) fn create_agent_pipe_server_with_sddl(
        options: &tokio::net::windows::named_pipe::ServerOptions,
        pipe_name: &OsStr,
        sddl: &str,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        let mut attributes = SecurityAttributes::from_sddl(sddl)?;
        // SAFETY: `attributes.as_mut_ptr()` points at a live
        // SECURITY_ATTRIBUTES whose security descriptor remains owned
        // by `attributes` for the duration of this synchronous create call.
        unsafe { options.create_with_security_attributes_raw(pipe_name, attributes.as_mut_ptr()) }
    }

    struct SecurityAttributes {
        descriptor: NonNull<c_void>,
        attributes: SECURITY_ATTRIBUTES,
    }

    impl SecurityAttributes {
        fn from_sddl(sddl: &str) -> io::Result<Self> {
            let wide = sddl.encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>();
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            // SAFETY: `wide` is NUL-terminated UTF-16, `descriptor`
            // points to writable storage for the allocated descriptor,
            // and Windows owns the allocation until released with
            // `LocalFree`.
            let converted = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &raw mut descriptor,
                    null_mut(),
                )
            };
            if converted == 0 {
                return Err(io::Error::last_os_error());
            }
            let descriptor =
                NonNull::new(descriptor.cast::<c_void>()).ok_or_else(io::Error::last_os_error)?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                    .unwrap_or(u32::MAX),
                lpSecurityDescriptor: descriptor.as_ptr(),
                bInheritHandle: 0,
            };
            Ok(Self { descriptor, attributes })
        }

        const fn as_mut_ptr(&mut self) -> *mut c_void {
            (&raw mut self.attributes).cast::<c_void>()
        }
    }

    impl Drop for SecurityAttributes {
        fn drop(&mut self) {
            // SAFETY: `descriptor` was allocated by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
            unsafe {
                LocalFree(self.descriptor.as_ptr() as HLOCAL);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn pipe_client_rejects_remote_and_non_pipe_paths_before_opening() {
            for path in [
                r"\\remote\pipe\locket-agent",
                r"\\localhost\pipe\locket-agent",
                r"\\?\pipe\locket-agent",
                r"C:\locket-agent",
                r"\\.\pipe\",
                r"\\.\pipe\nested\locket-agent",
                "\\\\.\\pipe\\locket\0ignored",
            ] {
                assert!(
                    open_verified_agent_pipe_client(OsStr::new(path))
                        .is_err_and(|error| error.kind() == io::ErrorKind::InvalidInput)
                );
            }
        }

        #[tokio::test]
        async fn pipe_client_checks_real_object_owner_and_server_token()
        -> Result<(), Box<dyn std::error::Error>> {
            use std::sync::atomic::{AtomicU64, Ordering};

            static NEXT_PIPE: AtomicU64 = AtomicU64::new(0);
            let name = format!(
                r"\\.\pipe\locket-owner-test-{}-{}",
                std::process::id(),
                NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
            );
            let sid = current_user_sid_string()?;
            let sddl = crate::agent_pipe_dacl_sddl_for_sid(&sid)?;
            let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
            options.first_pipe_instance(true).reject_remote_clients(true);
            let server = create_agent_pipe_server_with_sddl(&options, OsStr::new(&name), &sddl)?;
            let client = open_verified_agent_pipe_client(OsStr::new(&name))?;
            server.connect().await?;
            assert_eq!(pipe_owner_sid(client.as_raw_handle())?, sid);
            assert!(
                verify_pipe_server_identity(&client, "S-1-0-0")
                    .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
            );
            // Check the process-token branch independently of the owner branch.
            // SAFETY: the current-process pseudo-handle is valid and not owned.
            let process = unsafe { GetCurrentProcess() };
            assert!(
                require_process_user(process, "S-1-0-0")
                    .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
            );
            assert!(
                server
                    .try_read(&mut [0; 1])
                    .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{agent_pipe_dacl_sddl_for_sid, agent_pipe_name_for_sid};

    #[test]
    fn agent_pipe_name_uses_sid_suffix() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            agent_pipe_name_for_sid("S-1-5-21-1000")?,
            r"\\.\pipe\locket-agent-S-1-5-21-1000"
        );
        Ok(())
    }

    #[test]
    fn agent_pipe_dacl_sddl_is_current_user_only_and_protected()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            agent_pipe_dacl_sddl_for_sid("S-1-5-21-1000")?,
            "O:S-1-5-21-1000D:P(A;;GA;;;S-1-5-21-1000)"
        );
        Ok(())
    }

    #[test]
    fn agent_pipe_helpers_reject_malformed_sid_text() {
        assert!(agent_pipe_name_for_sid("").is_err());
        assert!(agent_pipe_name_for_sid("user name").is_err());
        assert!(agent_pipe_dacl_sddl_for_sid("S-1-5-21/1000").is_err());
    }
}
