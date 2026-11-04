//! Atomic private-directory creation on Windows.
//!
//! SAFETY-AUDIT: descriptors are allocated by Windows, kept alive across each
//! synchronous API call, and released with `LocalFree`. Returned ACL pointers
//! borrow their owning descriptor. No plaintext is created before verification.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::mem::{MaybeUninit, offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path};
use std::ptr::{self, NonNull};

use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_WRITE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    EqualSid, GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorOwner, INHERIT_ONLY_ACE,
    IsWellKnownSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC,
    WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};

struct Descriptor(NonNull<c_void>);

impl Descriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut raw = ptr::null_mut();
        // SAFETY: the string is terminated; Windows initializes and owns `raw`.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        NonNull::new(raw).map(Self).ok_or_else(io::Error::last_os_error)
    }

    fn owner(&self) -> io::Result<*mut c_void> {
        let mut owner = ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: descriptor stays alive; both outputs are writable locals.
        if unsafe {
            GetSecurityDescriptorOwner(self.0.as_ptr(), &raw mut owner, &raw mut defaulted)
        } == 0
            || owner.is_null()
        {
            return Err(io::Error::other("directory security descriptor has no owner"));
        }
        Ok(owner)
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: both descriptor-producing APIs allocate with LocalAlloc.
        unsafe {
            LocalFree(self.0.as_ptr());
        }
    }
}

/// Creates a new directory with a protected, inheritable current-user-only ACL.
///
/// Existing paths are rejected. The resulting owner and ACL are read back
/// before returning, so filesystems that cannot enforce the ACL fail closed.
/// The absolute parent path must have no reparse points or untrusted accounts
/// able to replace its components. The current user, SYSTEM, and administrators
/// are trusted; callers should use their canonical per-user temporary directory.
///
/// # Errors
/// Returns an OS or permission error if private creation cannot be established.
pub fn create_user_only_windows_directory(path: &Path) -> io::Result<()> {
    let sid = crate::current_user_sid_string().map_err(io::Error::other)?;
    let descriptor = Descriptor::from_sddl(&format!("O:{sid}D:P(A;OICI;FA;;;{sid})"))?;
    let owner = descriptor.owner()?;
    verify_parent_chain(path, owner)?;
    let wide = wide_path(path)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(io::Error::other)?,
        lpSecurityDescriptor: descriptor.0.as_ptr(),
        bInheritHandle: 0,
    };
    // SAFETY: path and descriptor live through synchronous atomic creation.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = verify_directory_acl(&wide, owner);
    if result.is_err() {
        // No file has been written yet. Never remove an existing caller path.
        let _cleanup = std::fs::remove_dir(path);
    }
    result
}

fn read_security(path: &[u16]) -> io::Result<(Descriptor, *mut c_void, *mut ACL)> {
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut raw = ptr::null_mut();
    // SAFETY: path is terminated; Windows initializes pointers into `raw`.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            &raw mut dacl,
            ptr::null_mut(),
            &raw mut raw,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(i32::try_from(status).unwrap_or(i32::MAX)));
    }
    let descriptor = Descriptor(NonNull::new(raw).ok_or_else(invalid_acl)?);
    if owner.is_null() || dacl.is_null() {
        return Err(invalid_acl());
    }
    Ok((descriptor, owner, dacl))
}

fn verify_directory_acl(path: &[u16], expected_owner: *mut c_void) -> io::Result<()> {
    let (descriptor, owner, dacl) = read_security(path)?;
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: the OS returned this descriptor and initialized its pointers.
    if unsafe {
        EqualSid(owner, expected_owner) == 0
            || GetSecurityDescriptorControl(
                descriptor.0.as_ptr(),
                &raw mut control,
                &raw mut revision,
            ) == 0
            || (*dacl).AceCount != 1
    } || control & SE_DACL_PROTECTED == 0
    {
        return Err(invalid_acl());
    }
    let Some((ace, sid)) = read_allow_ace(dacl, 0)? else {
        return Err(invalid_acl());
    };
    // SAFETY: both SIDs borrow validated descriptors alive in this scope.
    let sid_matches = unsafe { EqualSid(sid, expected_owner) != 0 };
    if u32::from(ace.Header.AceFlags) != OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        || ace.Mask != FILE_ALL_ACCESS
        || !sid_matches
    {
        return Err(invalid_acl());
    }
    Ok(())
}

// Returned SID borrows the caller's OS-owned descriptor, which must stay alive.
fn read_allow_ace(
    dacl: *const ACL,
    index: u32,
) -> io::Result<Option<(ACCESS_ALLOWED_ACE, *mut c_void)>> {
    let mut raw_ace = ptr::null_mut();
    // SAFETY: callers supply an OS-owned ACL and an index below its ACE count.
    if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
        return Err(invalid_acl());
    }
    let mut header = MaybeUninit::<ACE_HEADER>::uninit();
    // SAFETY: every OS-owned ACE contains this fixed header.
    let header = unsafe {
        ptr::copy_nonoverlapping(
            raw_ace.cast::<u8>(),
            header.as_mut_ptr().cast::<u8>(),
            size_of::<ACE_HEADER>(),
        );
        header.assume_init()
    };
    if u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE
        || u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
    {
        return Ok(None);
    }
    // A SID has an eight-byte fixed header following this ACE's access mask.
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || usize::from(header.AceSize) < offset_of!(ACCESS_ALLOWED_ACE, SidStart) + 8
    {
        return Err(invalid_acl());
    }
    let mut ace = MaybeUninit::<ACCESS_ALLOWED_ACE>::uninit();
    // SAFETY: the OS-owned ACE is valid. Copy into aligned storage instead of
    // assuming an alignment stronger than the API's void-pointer type.
    let ace = unsafe {
        ptr::copy_nonoverlapping(
            raw_ace.cast::<u8>(),
            ace.as_mut_ptr().cast::<u8>(),
            size_of::<ACCESS_ALLOWED_ACE>(),
        );
        ace.assume_init()
    };
    // SAFETY: ACCESS_ALLOWED_ACE stores its valid SID at SidStart.
    let sid = unsafe { raw_ace.cast::<u8>().add(offset_of!(ACCESS_ALLOWED_ACE, SidStart)).cast() };
    Ok(Some((ace, sid)))
}

fn verify_parent_chain(path: &Path, current_user: *mut c_void) -> io::Result<()> {
    if !path.is_absolute()
        || path.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private directory requires an absolute normalized path",
        ));
    }
    let parent = path.parent().ok_or_else(invalid_acl)?;
    for (depth, ancestor) in parent.ancestors().enumerate() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid_acl());
        }
        let (_descriptor, owner, dacl) = read_security(&wide_path(ancestor)?)?;
        if !trusted_sid(owner, current_user) {
            return Err(invalid_acl());
        }
        // Adding a new sibling under an ancestor cannot replace an existing
        // component. Delete-child, ACL/owner changes and attribute writes can.
        let mut unsafe_rights = DELETE
            | FILE_DELETE_CHILD
            | WRITE_DAC
            | WRITE_OWNER
            | FILE_WRITE_ATTRIBUTES
            | FILE_WRITE_EA
            | GENERIC_ALL
            | GENERIC_WRITE;
        if depth == 0 {
            unsafe_rights |= FILE_WRITE_DATA | FILE_APPEND_DATA;
        }
        // SAFETY: read_security returned a valid ACL owned by _descriptor.
        let count = unsafe { (*dacl).AceCount };
        for index in 0..u32::from(count) {
            if let Some((ace, sid)) = read_allow_ace(dacl, index)?
                && ace.Mask & unsafe_rights != 0
                && !trusted_sid(sid, current_user)
            {
                return Err(invalid_acl());
            }
        }
    }
    Ok(())
}

fn trusted_sid(sid: *mut c_void, current_user: *mut c_void) -> bool {
    // SAFETY: both pointers borrow validated, live OS security descriptors.
    unsafe {
        EqualSid(sid, current_user) != 0
            || IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
    }
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<_> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "directory path contains NUL"));
    }
    wide.push(0);
    Ok(wide)
}

fn invalid_acl() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "filesystem did not enforce a private owner-only directory ACL",
    )
}
