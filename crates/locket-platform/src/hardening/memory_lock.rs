//! Memory locking for processes that hold key material.
//!
//! Locking pages with `mlockall` keeps unwrapped key material out of
//! the swap file even if the operating system would otherwise page
//! the process. The CLI and the agent both call this at startup. On
//! Linux, success requires `RLIMIT_MEMLOCK` to permit at least the
//! process's working set; otherwise the call falls back to
//! `Degraded` and `locket doctor` surfaces the gap.
//!
//! `LockedBytes` locks individual buffers independently of process-wide
//! locking, including on macOS and Windows.

use std::fmt::{self, Debug, Display};

use zeroize::Zeroizing;

/// Owns secret bytes in a stable allocation and wipes them on drop.
///
/// On Unix and Windows, each buffer gets its own virtual memory pages.
/// Page locks are not reference-counted by the OS, so sharing a page
/// could let one buffer's drop unlock a second buffer that is still live.
/// Locking is best-effort. If the OS rejects it, the bytes remain usable
/// and are still wiped on drop.
pub struct LockedBytes {
    storage: Storage,
}

enum Storage {
    #[cfg(any(unix, windows))]
    Mapping(mapping::Mapping),
    Heap(Zeroizing<Box<[u8]>>),
}

impl LockedBytes {
    /// Copies bytes into a buffer, attempting to lock its pages before copying.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        #[cfg(any(unix, windows))]
        if let Some(mut mapping) = mapping::Mapping::new(bytes.len()) {
            mapping.as_mut_slice().copy_from_slice(bytes);
            return Self { storage: Storage::Mapping(mapping) };
        }
        Self { storage: Storage::Heap(Zeroizing::new(Box::from(bytes))) }
    }

    /// Borrows the secret bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match &self.storage {
            #[cfg(any(unix, windows))]
            Storage::Mapping(mapping) => mapping.as_slice(),
            Storage::Heap(bytes) => bytes,
        }
    }

    /// Reports whether the OS successfully locked this buffer's pages.
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        match &self.storage {
            #[cfg(any(unix, windows))]
            Storage::Mapping(mapping) => mapping.is_locked(),
            Storage::Heap(_) => false,
        }
    }
}

impl Debug for LockedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LockedBytes([REDACTED])")
    }
}

#[cfg(any(unix, windows))]
#[allow(unsafe_code)]
mod mapping {
    use std::{ptr::NonNull, slice};

    use zeroize::Zeroize;

    pub(super) struct Mapping {
        ptr: NonNull<u8>,
        len: usize,
        locked: bool,
    }

    // SAFETY: The mapping is owned exclusively, has no thread affinity,
    // and can only be written or released through an exclusive borrow.
    unsafe impl Send for Mapping {}
    // SAFETY: Shared access exposes only immutable bytes.
    unsafe impl Sync for Mapping {}

    impl Mapping {
        pub(super) fn new(len: usize) -> Option<Self> {
            if len == 0 || len > isize::MAX as usize {
                return None;
            }
            let ptr = allocate(len)?;
            let locked = lock(ptr, len);
            Some(Self { ptr, len, locked })
        }

        pub(super) const fn as_slice(&self) -> &[u8] {
            // SAFETY: The live mapping holds len initialized bytes, and
            // we only expose a shared borrow tied to its lifetime.
            unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
        }

        pub(super) const fn as_mut_slice(&mut self) -> &mut [u8] {
            // SAFETY: The live mapping holds len initialized bytes, and
            // the exclusive borrow prevents overlapping Rust references.
            unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
        }

        pub(super) const fn is_locked(&self) -> bool {
            self.locked
        }

        fn wipe_and_unlock(&mut self, unlock_pages: impl FnOnce(NonNull<u8>, usize)) {
            self.as_mut_slice().zeroize();
            if self.locked {
                unlock_pages(self.ptr, self.len);
                self.locked = false;
            }
        }
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            self.wipe_and_unlock(unlock);
            release(self.ptr, self.len);
        }
    }

    #[cfg(unix)]
    fn allocate(len: usize) -> Option<NonNull<u8>> {
        use rustix::mm::{MapFlags, ProtFlags, mmap_anonymous};

        // SAFETY: No fixed address is requested. The OS supplies a fresh,
        // private, zero-filled mapping and owns the page-size rounding.
        let ptr = unsafe {
            mmap_anonymous(
                std::ptr::null_mut(),
                len,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE,
            )
        }
        .ok()?;
        NonNull::new(ptr.cast())
    }

    #[cfg(unix)]
    fn lock(ptr: NonNull<u8>, len: usize) -> bool {
        // SAFETY: ptr starts an exclusively owned mapping covering len
        // bytes and the full pages the OS rounds the range to.
        unsafe { rustix::mm::mlock(ptr.as_ptr().cast(), len) }.is_ok()
    }

    #[cfg(unix)]
    fn unlock(ptr: NonNull<u8>, len: usize) {
        // SAFETY: The wiped mapping is still live and owns the whole
        // page-rounded range. Its lock succeeded before we got here.
        let _ = unsafe { rustix::mm::munlock(ptr.as_ptr().cast(), len) };
    }

    #[cfg(unix)]
    fn release(ptr: NonNull<u8>, len: usize) {
        // SAFETY: ptr and len describe the original mapping. The slice
        // borrows have ended, and no other owner can release this range.
        let _ = unsafe { rustix::mm::munmap(ptr.as_ptr().cast(), len) };
    }

    #[cfg(windows)]
    fn allocate(len: usize) -> Option<NonNull<u8>> {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc,
        };

        // SAFETY: A null address asks the OS for a new, zero-filled
        // region with read/write access covering at least len bytes.
        let ptr = unsafe {
            VirtualAlloc(std::ptr::null(), len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        };
        NonNull::new(ptr.cast())
    }

    #[cfg(windows)]
    fn lock(ptr: NonNull<u8>, len: usize) -> bool {
        // SAFETY: The OS committed this entire range in allocate().
        unsafe { windows_sys::Win32::System::Memory::VirtualLock(ptr.as_ptr().cast(), len) != 0 }
    }

    #[cfg(windows)]
    fn unlock(ptr: NonNull<u8>, len: usize) {
        // SAFETY: The wiped range remains committed and was locked by
        // this buffer. No other buffer shares these pages.
        let _ =
            unsafe { windows_sys::Win32::System::Memory::VirtualUnlock(ptr.as_ptr().cast(), len) };
    }

    #[cfg(windows)]
    fn release(ptr: NonNull<u8>, _len: usize) {
        use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};

        // SAFETY: ptr is the base from VirtualAlloc. MEM_RELEASE takes
        // length zero and no Rust borrow of the region remains live.
        let _ = unsafe { VirtualFree(ptr.as_ptr().cast(), 0, MEM_RELEASE) };
    }

    #[cfg(test)]
    mod tests {
        use super::{Mapping, unlock};

        #[test]
        fn bytes_are_zero_by_the_time_pages_unlock() -> Result<(), &'static str> {
            let mut mapping = Mapping::new(32).ok_or("could not allocate a page")?;
            mapping.as_mut_slice().fill(0x42);
            let was_locked = mapping.is_locked();
            let mut unlocked = false;
            mapping.wipe_and_unlock(|ptr, len| {
                // SAFETY: The mapping outlives the callback and is
                // initialized and exclusively held by the test.
                let bytes = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) };
                assert_eq!(bytes, [0; 32]);
                unlock(ptr, len);
                unlocked = true;
            });
            assert_eq!(unlocked, was_locked);
            assert_eq!(mapping.as_slice(), [0; 32]);
            assert!(!mapping.is_locked());
            Ok(())
        }
    }
}

/// Outcome of a [`lock_process_memory`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryLockHardening {
    /// `mlockall(MCL_CURRENT | MCL_FUTURE)` succeeded.
    Active,
    /// The platform has no implementation in this build (currently
    /// Windows). Diagnostics should surface this so users know the
    /// fall-back state.
    Unsupported,
    /// The lock attempt failed (most often `RLIMIT_MEMLOCK` is too
    /// small for the working set). Individual buffers can still try
    /// to lock their pages through [`LockedBytes`].
    Degraded,
}

impl Display for MemoryLockHardening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Active => "active",
            Self::Unsupported => "unsupported",
            Self::Degraded => "degraded",
        })
    }
}

/// Locks the calling process's current and future memory pages.
///
/// Idempotent: calling it again after a successful lock is a no-op
/// from the process's perspective.
// `const fn` would require all return paths to be const-evaluable, but
// the Linux path calls into rustix which is not. The macOS/Windows
// path is const-friendly on its own, but the function as a whole
// can't be const.
#[allow(clippy::missing_const_for_fn)]
#[must_use]
pub fn lock_process_memory() -> MemoryLockHardening {
    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    {
        mlockall_supported::lock_process_memory()
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    {
        // This status describes process-wide locking. Per-buffer
        // locking is available on macOS and Windows via LockedBytes.
        MemoryLockHardening::Unsupported
    }
}

/// Returns the current memory-lock hardening state without changing it.
///
/// `mlockall` doesn't expose a queryable "is the process locked" bit
/// the way `RLIMIT_CORE` does, so this helper just calls
/// [`lock_process_memory`] again — it's idempotent and the kernel
/// returns success when the requested flags are already in effect.
#[must_use]
pub fn memory_lock_hardening_state() -> MemoryLockHardening {
    lock_process_memory()
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
mod mlockall_supported {
    use rustix::mm::{MlockAllFlags, mlockall};

    use super::MemoryLockHardening;

    pub fn lock_process_memory() -> MemoryLockHardening {
        let flags = MlockAllFlags::CURRENT | MlockAllFlags::FUTURE;
        if mlockall(flags).is_ok() {
            MemoryLockHardening::Active
        } else {
            MemoryLockHardening::Degraded
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LockedBytes, MemoryLockHardening, lock_process_memory, memory_lock_hardening_state,
    };

    #[test]
    fn locked_bytes_preserve_contents_but_redact_debug() {
        let source = b"secret vault key";
        let bytes = LockedBytes::new(source);
        assert_eq!(bytes.as_slice(), source);
        assert_eq!(format!("{bytes:?}"), "LockedBytes([REDACTED])");
    }

    #[test]
    fn empty_buffer_reports_unlocked() {
        let bytes = LockedBytes::new(&[]);
        assert_eq!(bytes.as_slice(), b"");
        assert!(!bytes.is_locked());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn small_key_buffer_locks_on_macos() {
        let first = LockedBytes::new(&[1; 32]);
        let second = LockedBytes::new(&[2; 32]);
        assert!(first.is_locked());
        assert!(second.is_locked());
        assert_eq!(first.as_slice(), [1; 32]);
        drop(first);
        assert_eq!(second.as_slice(), [2; 32]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lock_denial_preserves_bytes_and_drop_releases_lock_quota() -> std::io::Result<()> {
        use rustix::process::{Resource, Rlimit, setrlimit};

        crate::hardening::with_isolated_process(
            concat!(module_path!(), "::lock_denial_preserves_bytes_and_drop_releases_lock_quota"),
            || {
                const LIMIT: usize = 1024 * 1024;
                let limit = Some(LIMIT as u64);
                setrlimit(Resource::Memlock, Rlimit { current: limit, maximum: limit })?;
                let reservation = LockedBytes::new(&vec![0x42; LIMIT]);
                assert!(reservation.is_locked());

                let key = [42; 32];
                let buffer = LockedBytes::new(&key);
                assert!(!buffer.is_locked());
                assert_eq!(buffer.as_slice(), key);
                drop(reservation);
                assert!(LockedBytes::new(&key).is_locked());
                Ok(())
            },
        )
    }

    #[test]
    fn hardening_outcomes_render_as_doctor_labels() {
        assert_eq!(MemoryLockHardening::Active.to_string(), "active");
        assert_eq!(MemoryLockHardening::Unsupported.to_string(), "unsupported");
        assert_eq!(MemoryLockHardening::Degraded.to_string(), "degraded");
    }

    #[test]
    fn lock_process_memory_outcome_matches_platform() {
        let outcome = lock_process_memory();
        if cfg!(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
        )) {
            // The success path requires RLIMIT_MEMLOCK to be high
            // enough for the test process; some sandboxes don't allow
            // it, so accept either Active or Degraded and let the
            // doctor surface the difference.
            assert!(matches!(outcome, MemoryLockHardening::Active | MemoryLockHardening::Degraded));
        } else {
            // macOS lacks `mlockall`; Windows lacks any equivalent.
            assert_eq!(outcome, MemoryLockHardening::Unsupported);
        }
    }

    #[test]
    fn state_query_matches_lock_outcome() {
        // `memory_lock_hardening_state` is just `lock_process_memory`
        // again, so the result should be one of the same variants.
        let first = lock_process_memory();
        let second = memory_lock_hardening_state();
        assert_eq!(first, second);
    }
}
