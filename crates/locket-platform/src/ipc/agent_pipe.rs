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
/// The descriptor grants generic-all to the current user's SID and
/// marks the DACL protected (`D:P`) so inherited ACEs are not added by
/// the object manager.
///
/// # Errors
///
/// Returns [`PlatformError::InvalidWindowsSid`] when `sid` is empty or malformed.
pub fn agent_pipe_dacl_sddl_for_sid(sid: &str) -> Result<String, PlatformError> {
    let sid = validate_sid_fragment(sid)?;
    Ok(format!("D:P(A;;GA;;;{sid})"))
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

#[cfg(target_os = "windows")]
mod windows_impl {
    #![allow(unsafe_code)]

    use std::ffi::{OsStr, c_void};
    use std::io;
    use std::ptr::{NonNull, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::core::PWSTR;

    use crate::PlatformError;

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is a live handle returned by `OpenProcessToken`.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    pub(super) fn current_user_sid_string() -> Result<String, PlatformError> {
        let mut token: HANDLE = null_mut();
        // SAFETY: `GetCurrentProcess` is a pseudo-handle and `token`
        // points to writable storage for the opened token handle.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) };
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
        let mut sid_text: PWSTR = null_mut();
        // SAFETY: `token_user.User.Sid` is owned by the token-info
        // buffer and valid for this call; Windows allocates `sid_text`.
        let converted = unsafe { ConvertSidToStringSidW(token_user.User.Sid, &raw mut sid_text) };
        if converted == 0 || sid_text.is_null() {
            return Err(PlatformError::WindowsSidUnavailable(last_os_error_code()));
        }

        let text = wide_ptr_to_string(sid_text)?;
        // SAFETY: `sid_text` was allocated by `ConvertSidToStringSidW`
        // and must be released with `LocalFree`.
        unsafe {
            LocalFree(sid_text.cast::<core::ffi::c_void>() as HLOCAL);
        }
        Ok(text)
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
        assert_eq!(agent_pipe_dacl_sddl_for_sid("S-1-5-21-1000")?, "D:P(A;;GA;;;S-1-5-21-1000)");
        Ok(())
    }

    #[test]
    fn agent_pipe_helpers_reject_malformed_sid_text() {
        assert!(agent_pipe_name_for_sid("").is_err());
        assert!(agent_pipe_name_for_sid("user name").is_err());
        assert!(agent_pipe_dacl_sddl_for_sid("S-1-5-21/1000").is_err());
    }
}
