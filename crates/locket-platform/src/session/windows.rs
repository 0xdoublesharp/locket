//! Session/power notification ownership on a dedicated Windows message thread.
//!
//! SAFETY-AUDIT: the hidden window, WTS registration, callback state, and their
//! destruction stay on one thread. The boxed context outlives `DestroyWindow`;
//! its pointer lives in thread-local storage, not message-controlled window
//! data. Only `PostThreadMessage` crosses
//! threads, using an OS thread id. WTS-allocated buffers are size checked and
//! released with `WTSFreeMemory`. Native callbacks carry metadata, never keys.

#![allow(unsafe_code)]

use std::cell::Cell;
use std::io;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::sync::oneshot;
use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE,
    WTS_SESSIONSTATE_UNLOCK, WTSActive, WTSFreeMemory, WTSINFOEXW, WTSQuerySessionInformationW,
    WTSRegisterSessionNotification, WTSSessionInfoEx, WTSUnRegisterSessionNotification,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, MSG,
    PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMECRITICAL, PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
    PostThreadMessageW, RegisterClassW, UnregisterClassW, WM_NCDESTROY, WM_POWERBROADCAST, WM_QUIT,
    WM_WTSSESSION_CHANGE, WNDCLASSW, WTS_CONSOLE_CONNECT, WTS_CONSOLE_DISCONNECT,
    WTS_REMOTE_CONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK, WTS_SESSION_LOGOFF,
    WTS_SESSION_UNLOCK,
};

use super::portable::{Acknowledgement, EventSink, FailureCallback, event_stream};
use super::{NativeSessionEvent, SessionObserver};

static NEXT_WINDOW: AtomicU64 = AtomicU64::new(1);
// Windows permits approximately two seconds for PBT_APMSUSPEND handling.
const SUSPEND_ACK_TIMEOUT: Duration = Duration::from_secs(1);

thread_local! {
    // Only WindowObserver's owner may install or clear the callback context.
    static CALLBACK_STATE: Cell<*const CallbackState> = const { Cell::new(ptr::null()) };
}

pub(super) struct ObserverGuard {
    acknowledgement: Arc<Acknowledgement>,
    thread_id: Arc<AtomicU32>,
    worker: Option<JoinHandle<()>>,
}

impl ObserverGuard {
    pub(super) fn acknowledge(&self, token: Option<u64>) {
        self.acknowledgement.acknowledge(token);
    }
}

impl Drop for ObserverGuard {
    fn drop(&mut self) {
        self.acknowledgement.stop();
        let thread_id = self.thread_id.load(Ordering::Acquire);
        if thread_id != 0 {
            // SAFETY: WM_QUIT contains no borrowed pointers. A startup worker
            // without a queue also checks stopping before entering its loop.
            unsafe {
                PostThreadMessageW(thread_id, WM_QUIT, 0, 0);
            }
        }
        if let Some(worker) = self.worker.take() {
            let _joined = worker.join();
        }
    }
}

pub(super) async fn start(failed: FailureCallback) -> io::Result<SessionObserver> {
    let (sink, receiver) = event_stream(failed);
    let acknowledgement = Arc::clone(&sink.acknowledgement);
    let thread_id = Arc::new(AtomicU32::new(0));
    let worker_id = Arc::clone(&thread_id);
    let (ready_tx, ready_rx) = oneshot::channel();
    let worker =
        std::thread::Builder::new().name("locket-session".to_owned()).spawn(move || {
            // SAFETY: GetCurrentThreadId has no pointer parameters.
            worker_id.store(unsafe { GetCurrentThreadId() }, Ordering::Release);
            match WindowObserver::new(sink) {
                Ok(observer) => {
                    if ready_tx.send(Ok(())).is_ok() {
                        observer.run();
                    }
                }
                Err(error) => {
                    let _sent = ready_tx.send(Err(error));
                }
            }
        })?;
    let guard = ObserverGuard { acknowledgement, thread_id, worker: Some(worker) };
    ready_rx.await.map_err(|_| io::Error::other("Windows session observer startup stopped"))??;
    Ok(SessionObserver { receiver, guard, backend_name: "Windows WTS/power session notifications" })
}

struct CallbackState {
    sink: EventSink,
    session_id: u32,
}

struct WindowObserver {
    // Fields drop after Drop destroys the native window and registration.
    state: Box<CallbackState>,
    window: HWND,
    instance: HINSTANCE,
    class_name: Vec<u16>,
    registered: bool,
}

impl WindowObserver {
    fn new(sink: EventSink) -> io::Result<Self> {
        let mut session_id = 0;
        // SAFETY: the output is a valid exclusive u32 and the PID is ours.
        if unsafe { ProcessIdToSessionId(std::process::id(), &raw mut session_id) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if session_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "session monitoring requires an interactive Windows session",
            ));
        }
        // SAFETY: null requests this executable's loaded module handle.
        let instance = unsafe { GetModuleHandleW(ptr::null()) };
        if instance.is_null() {
            return Err(io::Error::last_os_error());
        }
        let class_name: Vec<u16> = format!(
            "LocketSession-{}-{}",
            std::process::id(),
            NEXT_WINDOW.fetch_add(1, Ordering::Relaxed)
        )
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class_name.as_ptr(),
            ..WNDCLASSW::default()
        };
        // SAFETY: class name remains alive until UnregisterClassW.
        if unsafe { RegisterClassW(&raw const class) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut observer = Self {
            state: Box::new(CallbackState { sink, session_id }),
            window: ptr::null_mut(),
            instance,
            class_name,
            registered: false,
        };
        CALLBACK_STATE.set(ptr::from_ref(&*observer.state));
        // SAFETY: the boxed context is stable and outlives destruction. This is
        // a hidden top-level window: message-only windows miss power broadcasts.
        observer.window = unsafe {
            CreateWindowExW(
                0,
                observer.class_name.as_ptr(),
                observer.class_name.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                instance,
                ptr::null(),
            )
        };
        if observer.window.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: window belongs to this thread and remains alive through unregister.
        if unsafe { WTSRegisterSessionNotification(observer.window, NOTIFY_FOR_THIS_SESSION) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        observer.registered = true;
        let locked = session_locked(session_id)?;
        if !observer.state.sink.emit(screen_event(locked)) {
            return Err(io::Error::other("Windows session notification startup failed"));
        }
        Ok(observer)
    }

    fn run(&self) {
        let mut message = MSG::default();
        while !self.state.sink.acknowledgement.stopping() {
            // SAFETY: this thread owns its message queue and valid output buffer.
            let result = unsafe { GetMessageW(&raw mut message, ptr::null_mut(), 0, 0) };
            if result <= 0 {
                self.state.sink.fail();
                break;
            }
            // SAFETY: GetMessageW filled a valid MSG for this thread.
            unsafe {
                DispatchMessageW(&raw const message);
            }
        }
    }
}

impl Drop for WindowObserver {
    fn drop(&mut self) {
        self.state.sink.acknowledgement.stop();
        // SAFETY: all native registration ownership remains on this thread.
        unsafe {
            if self.registered {
                WTSUnRegisterSessionNotification(self.window);
            }
            if !self.window.is_null() {
                DestroyWindow(self.window);
            }
            UnregisterClassW(self.class_name.as_ptr(), self.instance);
        }
        CALLBACK_STATE.set(ptr::null());
    }
}

fn session_locked(session_id: u32) -> io::Result<bool> {
    let mut buffer = ptr::null_mut();
    let mut bytes = 0;
    // SAFETY: Windows initializes both output parameters; successful allocation
    // must be released by WTSFreeMemory even if its shape is unexpected.
    if unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            WTSSessionInfoEx,
            &raw mut buffer,
            &raw mut bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let result = if !buffer.is_null() && bytes as usize >= size_of::<WTSINFOEXW>() {
        let mut info = std::mem::MaybeUninit::<WTSINFOEXW>::uninit();
        // SAFETY: allocation size checked above; WTS returns WTSINFOEXW for
        // this query. Copy bytes into aligned local storage rather than
        // assuming alignment from the API's UTF-16 output pointer type.
        let info = unsafe {
            ptr::copy_nonoverlapping(
                buffer.cast::<u8>(),
                info.as_mut_ptr().cast::<u8>(),
                size_of::<WTSINFOEXW>(),
            );
            info.assume_init()
        };
        if info.Level == 1 {
            // SAFETY: Level selects WTSInfoExLevel1 in this union.
            let state = unsafe { info.Data.WTSInfoExLevel1 };
            Ok(state.SessionId != session_id
                || state.SessionState != WTSActive
                || u32::try_from(state.SessionFlags).ok() != Some(WTS_SESSIONSTATE_UNLOCK))
        } else {
            Err(io::Error::other("unsupported Windows session information version"))
        }
    } else {
        Err(io::Error::other("invalid Windows session information buffer"))
    };
    // SAFETY: this is precisely the allocation returned by WTS above.
    unsafe {
        WTSFreeMemory(buffer.cast());
    }
    result
}

const fn screen_event(locked: bool) -> NativeSessionEvent {
    if locked { NativeSessionEvent::ScreenLock } else { NativeSessionEvent::ScreenUnlock }
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let state = CALLBACK_STATE.get();
    if !state.is_null() {
        // SAFETY: the owning boxed state outlives the window's destruction.
        let state = unsafe { &*state };
        if message == WM_NCDESTROY {
            state.sink.fail();
        }
        if message == WM_WTSSESSION_CHANGE && u32::try_from(lparam).ok() == Some(state.session_id) {
            match u32::try_from(wparam).ok() {
                Some(
                    WTS_SESSION_LOCK
                    | WTS_SESSION_LOGOFF
                    | WTS_CONSOLE_DISCONNECT
                    | WTS_REMOTE_DISCONNECT,
                ) => {
                    state.sink.emit(NativeSessionEvent::ScreenLock);
                }
                Some(WTS_SESSION_UNLOCK | WTS_CONSOLE_CONNECT | WTS_REMOTE_CONNECT) => {
                    // A window message cannot itself prove an unlocked session.
                    match session_locked(state.session_id) {
                        Ok(locked) => {
                            state.sink.emit(screen_event(locked));
                        }
                        Err(_) => state.sink.fail(),
                    }
                }
                _ => {}
            }
        } else if message == WM_POWERBROADCAST {
            match u32::try_from(wparam).ok() {
                Some(PBT_APMSUSPEND) => {
                    state.sink.suspend(SUSPEND_ACK_TIMEOUT);
                }
                Some(PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND | PBT_APMRESUMECRITICAL) => {
                    match session_locked(state.session_id) {
                        Ok(locked) => {
                            state.sink.emit(screen_event(locked));
                            state.sink.emit(NativeSessionEvent::SystemWake);
                        }
                        Err(_) => state.sink.fail(),
                    }
                }
                _ => {}
            }
        }
    }
    // SAFETY: unhandled/default processing receives the original Windows parameters.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}
