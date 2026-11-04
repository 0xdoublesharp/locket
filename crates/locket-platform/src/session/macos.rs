//! Main-thread Core Foundation observer ownership and `IOKit` sleep handling.
//!
//! SAFETY-AUDIT: native registrations, callback contexts and their destruction
//! stay on the main run loop. A task queue crosses threads using Rust-owned
//! messages. Only CFRunLoopSourceSignal/CFRunLoopWakeUp cross the FFI boundary
//! from a worker. Callbacks carry metadata and never borrow agent key material.

#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::io;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

use objc2_core_foundation::{
    CFDictionary, CFNotificationCenter, CFNotificationName, CFNotificationSuspensionBehavior,
    CFRetained, CFRunLoop, CFRunLoopSource, CFRunLoopSourceContext, CFString,
    kCFRunLoopDefaultMode,
};
use objc2_io_kit::{
    IOAllowPowerChange, IODeregisterForSystemPower, IONotificationPort, IONotificationPortRef,
    IORegisterForSystemPower, IOServiceClose, io_connect_t, io_object_t, io_service_t,
    kIOMessageCanSystemSleep, kIOMessageSystemHasPoweredOn, kIOMessageSystemWillSleep,
};
use tokio::sync::{mpsc as event_mpsc, oneshot};

use super::{NativeSessionEvent, NativeSessionNotification, SessionObserver};

type FailureCallback = Arc<dyn Fn() + Send + Sync>;
const EVENT_QUEUE_CAPACITY: usize = 32;

#[derive(Clone)]
struct EventSender {
    sender: event_mpsc::Sender<NativeSessionNotification>,
    failed: FailureCallback,
}

impl EventSender {
    fn send(&self, event: NativeSessionNotification) {
        if matches!(self.sender.try_send(event), Err(event_mpsc::error::TrySendError::Full(_))) {
            // Dropping either side of a lock/wake pair would corrupt the
            // daemon's persistent gate. The CLI callback terminates it safely.
            (self.failed)();
        }
        // A closed receiver means its owner has already stopped monitoring.
    }
}

fn event_stream(
    failed: FailureCallback,
) -> (EventSender, event_mpsc::Receiver<NativeSessionNotification>) {
    let (sender, receiver) = event_mpsc::channel(EVENT_QUEUE_CAPACITY);
    (EventSender { sender, failed }, receiver)
}

static DRIVER: Mutex<Option<Arc<DispatchHandle>>> = Mutex::new(None);
static NEXT_OBSERVER: AtomicU64 = AtomicU64::new(1);

struct DispatchHandle {
    sender: mpsc::Sender<MainTask>,
    run_loop: CFRetained<CFRunLoop>,
    source: CFRetained<CFRunLoopSource>,
}

// SAFETY: this type exposes only Core Foundation's documented cross-thread
// source-signal/run-loop-wakeup operations. Registration and running never
// leave the main thread. Retained handles outlive every queued task.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for DispatchHandle {}
// SAFETY: the only shared operations are the thread-safe signal/wakeup calls
// and Rust's multi-producer channel. No mutable native object is exposed.
unsafe impl Sync for DispatchHandle {}

impl DispatchHandle {
    fn send(&self, task: MainTask) -> io::Result<()> {
        self.sender.send(task).map_err(|_| io::Error::other("native session loop stopped"))?;
        self.source.signal();
        self.run_loop.wake_up();
        Ok(())
    }
}

enum MainTask {
    Start {
        id: u64,
        sender: EventSender,
        acknowledgement: Arc<SleepAcknowledgement>,
        failed: FailureCallback,
        ready: oneshot::Sender<io::Result<()>>,
    },
    Remove {
        id: u64,
        done: mpsc::SyncSender<()>,
    },
    Stop,
}

struct MainState {
    receiver: mpsc::Receiver<MainTask>,
    observers: BTreeMap<u64, NativeObserver>,
}

struct SourceLifetime(CFRetained<CFRunLoopSource>);

impl Drop for SourceLifetime {
    fn drop(&mut self) {
        self.0.invalidate();
    }
}

/// Run the daemon on a worker while servicing native callbacks on real main.
/// Off-main callers (including unit harnesses) run without a native driver.
pub(super) fn run<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> io::Result<T> {
    if objc2::MainThreadMarker::new().is_none() {
        return Ok(work());
    }
    let run_loop = CFRunLoop::current().ok_or_else(|| io::Error::other("no main run loop"))?;
    let (sender, receiver) = mpsc::channel();
    let mut state = Box::new(MainState { receiver, observers: BTreeMap::new() });
    let mut context = CFRunLoopSourceContext {
        version: 0,
        info: ptr::from_mut(&mut *state).cast(),
        retain: None,
        release: None,
        copyDescription: None,
        equal: None,
        hash: None,
        schedule: None,
        cancel: None,
        perform: Some(dispatch_tasks),
    };
    // SAFETY: the initialized context is copied; its stable boxed state lives
    // until the source is invalidated after the worker and run loop stop.
    let source = unsafe { CFRunLoopSource::new(None, 0, &raw mut context) }
        .ok_or_else(|| io::Error::other("cannot create native session dispatcher"))?;
    let _source_lifetime = SourceLifetime(source.clone());
    // SAFETY: the default mode is an immortal framework constant.
    run_loop.add_source(Some(&source), unsafe { kCFRunLoopDefaultMode });
    let handle = Arc::new(DispatchHandle { sender, run_loop, source: source.clone() });
    {
        let mut driver =
            DRIVER.lock().map_err(|_| io::Error::other("native dispatcher poisoned"))?;
        if driver.is_some() {
            source.invalidate();
            return Err(io::Error::other("native session loop already running"));
        }
        *driver = Some(Arc::clone(&handle));
    }
    let worker_handle = Arc::clone(&handle);
    let worker = std::thread::Builder::new().name("locket-daemon".to_owned()).spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
        let _sent = worker_handle.send(MainTask::Stop);
        result
    });
    let result = match worker {
        Ok(worker) => {
            CFRunLoop::run();
            worker.join().map_or_else(
                |_| Err(io::Error::other("daemon worker panicked")),
                |result| result.map_err(|_| io::Error::other("daemon worker panicked")),
            )
        }
        Err(error) => Err(error),
    };
    if let Ok(mut driver) = DRIVER.lock() {
        *driver = None;
    }
    source.invalidate();
    // Native observer destruction stays on main, before callback state drops.
    state.observers.clear();
    result
}

unsafe extern "C-unwind" fn dispatch_tasks(info: *mut c_void) {
    // SAFETY: only this source callback touches the boxed state, on main.
    let state = unsafe { &mut *info.cast::<MainState>() };
    while let Ok(task) = state.receiver.try_recv() {
        match task {
            MainTask::Start { id, sender, acknowledgement, failed, ready } => {
                match NativeObserver::new(id, sender, acknowledgement, failed, ready) {
                    Ok(observer) => {
                        state.observers.insert(id, observer);
                    }
                    Err((error, ready)) => {
                        let _sent = ready.send(Err(error));
                    }
                }
            }
            MainTask::Remove { id, done } => {
                state.observers.remove(&id);
                let _sent = done.send(());
            }
            MainTask::Stop => {
                if let Some(run_loop) = CFRunLoop::current() {
                    run_loop.stop();
                }
                break;
            }
        }
    }
}

pub(super) struct ObserverGuard {
    id: u64,
    driver: Arc<DispatchHandle>,
    acknowledgement: Arc<SleepAcknowledgement>,
}

impl ObserverGuard {
    pub(super) fn acknowledge(&self, token: Option<u64>) {
        if let Some(token) = token {
            self.acknowledgement.acknowledge(token);
        }
    }
}

impl Drop for ObserverGuard {
    fn drop(&mut self) {
        self.acknowledgement.close();
        let (done, removed) = mpsc::sync_channel(1);
        if self.driver.send(MainTask::Remove { id: self.id, done }).is_ok()
            && objc2::MainThreadMarker::new().is_none()
        {
            // The native loop remains running until its daemon worker exits.
            // Waiting ensures no callback context outlives the guard.
            let _removed = removed.recv();
        }
    }
}

pub(super) async fn start(failed: FailureCallback) -> io::Result<SessionObserver> {
    let driver = DRIVER
        .lock()
        .map_err(|_| io::Error::other("native dispatcher poisoned"))?
        .clone()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "macOS native notifications require the daemon's main run-loop driver",
            )
        })?;
    let id = NEXT_OBSERVER.fetch_add(1, Ordering::Relaxed);
    let acknowledgement = Arc::new(SleepAcknowledgement::default());
    let guard = ObserverGuard { id, driver, acknowledgement: Arc::clone(&acknowledgement) };
    let (sender, receiver) = event_stream(Arc::clone(&failed));
    let (ready, started) = oneshot::channel();
    guard.driver.send(MainTask::Start { id, sender, acknowledgement, failed, ready })?;
    // The private probe exercises the same real OS delivery path as screen
    // locks. Never claim native coverage merely because registration returned.
    tokio::time::timeout(Duration::from_secs(3), started)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "macOS native notification delivery probe timed out",
            )
        })?
        .map_err(|_| io::Error::other("native observer stopped during startup"))??;
    Ok(SessionObserver { receiver, guard })
}

#[derive(Default)]
struct SleepState {
    generation: u64,
    pending: Option<u64>,
    closed: bool,
}
#[derive(Default)]
struct SleepAcknowledgement {
    state: Mutex<SleepState>,
    changed: Condvar,
}
#[derive(Debug, PartialEq, Eq)]
enum SleepResult {
    Acknowledged,
    Closed,
    TimedOut,
}

impl SleepAcknowledgement {
    fn arm(&self) -> Option<u64> {
        let mut state = self.state.lock().ok()?;
        if state.closed {
            return None;
        }
        state.generation = state.generation.checked_add(1)?;
        let token = state.generation;
        state.pending = Some(token);
        drop(state);
        Some(token)
    }
    fn wait(&self, token: u64, timeout: Duration) -> SleepResult {
        let Ok(state) = self.state.lock() else {
            return SleepResult::TimedOut;
        };
        let Ok((state, _)) = self.changed.wait_timeout_while(state, timeout, |state| {
            state.pending == Some(token) && !state.closed
        }) else {
            return SleepResult::TimedOut;
        };
        if state.closed {
            SleepResult::Closed
        } else if state.pending == Some(token) {
            SleepResult::TimedOut
        } else {
            SleepResult::Acknowledged
        }
    }
    fn acknowledge(&self, token: u64) {
        if let Ok(mut state) = self.state.lock()
            && state.pending == Some(token)
        {
            state.pending = None;
            self.changed.notify_all();
        }
    }
    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            self.changed.notify_all();
        }
    }
}

struct PowerContext {
    sender: EventSender,
    connection: io_connect_t,
    acknowledgement: Arc<SleepAcknowledgement>,
    failed: FailureCallback,
    timeout: Duration,
}
struct PowerObserver {
    context: Box<PowerContext>,
    port: IONotificationPortRef,
    notifier: io_object_t,
}

impl PowerObserver {
    fn new(
        sender: EventSender,
        acknowledgement: Arc<SleepAcknowledgement>,
        failed: FailureCallback,
    ) -> io::Result<Self> {
        let mut observer = Self {
            context: Box::new(PowerContext {
                sender,
                connection: 0,
                acknowledgement,
                failed,
                timeout: Duration::from_secs(5),
            }),
            port: ptr::null_mut(),
            notifier: 0,
        };
        // SAFETY: the stable boxed context survives until deregistration;
        // initialized output pointers are valid and callbacks run on main.
        observer.context.connection = unsafe {
            IORegisterForSystemPower(
                ptr::from_mut(&mut *observer.context).cast(),
                &raw mut observer.port,
                Some(power_notification),
                &raw mut observer.notifier,
            )
        };
        if observer.context.connection == 0 || observer.port.is_null() {
            return Err(io::Error::other("macOS system power notifications unavailable"));
        }
        // SAFETY: successful registration owns a valid notification port.
        let source = unsafe { IONotificationPort::run_loop_source(observer.port) }
            .ok_or_else(|| io::Error::other("macOS power source unavailable"))?;
        let run_loop = CFRunLoop::current().ok_or_else(|| io::Error::other("no main run loop"))?;
        // SAFETY: the default mode is an immortal framework constant.
        run_loop.add_source(Some(&source), unsafe { kCFRunLoopDefaultMode });
        Ok(observer)
    }
}
impl Drop for PowerObserver {
    fn drop(&mut self) {
        // SAFETY: cleanup is serialized on the same main loop as callbacks,
        // and unregisters before releasing their boxed context.
        unsafe {
            if self.notifier != 0 {
                let _result = IODeregisterForSystemPower(&raw mut self.notifier);
            }
            if self.context.connection != 0 {
                let _result = IOServiceClose(self.context.connection);
            }
            if !self.port.is_null() {
                IONotificationPort::destroy(self.port);
            }
        }
    }
}

struct ScreenContext {
    sender: EventSender,
    ready: Mutex<Option<oneshot::Sender<io::Result<()>>>>,
}
struct NativeObserver {
    center: CFRetained<CFNotificationCenter>,
    screen: Box<ScreenContext>,
    _power: PowerObserver,
}
impl NativeObserver {
    fn new(
        id: u64,
        sender: EventSender,
        acknowledgement: Arc<SleepAcknowledgement>,
        failed: FailureCallback,
        ready: oneshot::Sender<io::Result<()>>,
    ) -> Result<Self, (io::Error, oneshot::Sender<io::Result<()>>)> {
        let Some(center) = CFNotificationCenter::distributed_center() else {
            return Err((io::Error::other("macOS distributed notifications unavailable"), ready));
        };
        let power = match PowerObserver::new(sender.clone(), acknowledgement, failed) {
            Ok(power) => power,
            Err(error) => return Err((error, ready)),
        };
        let observer = Self {
            center,
            screen: Box::new(ScreenContext { sender, ready: Mutex::new(Some(ready)) }),
            _power: power,
        };
        let context = ptr::from_ref(&*observer.screen).cast();
        let lock = CFString::from_str("com.apple.screenIsLocked");
        let unlock = CFString::from_str("com.apple.screenIsUnlocked");
        let probe =
            CFString::from_str(&format!("com.locket.session-probe.{}.{id}", std::process::id()));
        // SAFETY: context is a stable box owned until these registrations are
        // removed on main; no untrusted notification payload is dereferenced.
        unsafe {
            for (name, callback) in [
                (&lock, screen_lock as unsafe extern "C-unwind" fn(_, _, _, _, _)),
                (&unlock, screen_unlock),
                (&probe, probe_delivered),
            ] {
                observer.center.add_observer(
                    context,
                    Some(callback),
                    Some(name),
                    ptr::null(),
                    CFNotificationSuspensionBehavior::DeliverImmediately,
                );
            }
            observer.center.post_notification(Some(&probe), ptr::null(), None, true);
        }
        Ok(observer)
    }
}
impl Drop for NativeObserver {
    fn drop(&mut self) {
        // SAFETY: removal runs on the main loop, serialized with callbacks,
        // before the boxed context or IOKit observer is released.
        unsafe {
            self.center.remove_every_observer(ptr::from_ref(&*self.screen).cast());
        }
    }
}

unsafe extern "C-unwind" fn screen_lock(
    _: *mut CFNotificationCenter,
    observer: *mut c_void,
    _: *const CFNotificationName,
    _: *const c_void,
    _: *const CFDictionary,
) {
    // SAFETY: registration owns this context until main-thread removal.
    let context = unsafe { &*observer.cast::<ScreenContext>() };
    context.sender.send(NativeSessionNotification::new(NativeSessionEvent::ScreenLock, None));
}
unsafe extern "C-unwind" fn screen_unlock(
    _: *mut CFNotificationCenter,
    observer: *mut c_void,
    _: *const CFNotificationName,
    _: *const c_void,
    _: *const CFDictionary,
) {
    // SAFETY: registration owns this context until main-thread removal.
    let context = unsafe { &*observer.cast::<ScreenContext>() };
    context.sender.send(NativeSessionNotification::new(NativeSessionEvent::ScreenUnlock, None));
}
unsafe extern "C-unwind" fn probe_delivered(
    _: *mut CFNotificationCenter,
    observer: *mut c_void,
    _: *const CFNotificationName,
    _: *const c_void,
    _: *const CFDictionary,
) {
    // SAFETY: registration owns this context until main-thread removal.
    let context = unsafe { &*observer.cast::<ScreenContext>() };
    if let Ok(mut ready) = context.ready.lock()
        && let Some(ready) = ready.take()
    {
        let _sent = ready.send(Ok(()));
    }
}

unsafe extern "C-unwind" fn power_notification(
    context: *mut c_void,
    _: io_service_t,
    message: u32,
    argument: *mut c_void,
) {
    // SAFETY: IOKit holds this context until main-thread deregistration.
    let context = unsafe { &*context.cast::<PowerContext>() };
    handle_power_notification(context, message, argument as isize, |connection, notification| {
        let _result = IOAllowPowerChange(connection, notification);
    });
}
fn handle_power_notification(
    context: &PowerContext,
    message: u32,
    notification: isize,
    allow: impl FnOnce(io_connect_t, isize),
) {
    if message == kIOMessageCanSystemSleep {
        allow(context.connection, notification);
        return;
    }
    if message == kIOMessageSystemHasPoweredOn {
        context.sender.send(NativeSessionNotification::new(NativeSessionEvent::SystemWake, None));
    }
    if message != kIOMessageSystemWillSleep {
        return;
    }
    let Some(token) = context.acknowledgement.arm() else {
        return;
    };
    context
        .sender
        .send(NativeSessionNotification::new(NativeSessionEvent::SystemSleep, Some(token)));
    // The native callback waits for this exact event to finish key erasure.
    match context.acknowledgement.wait(token, context.timeout) {
        SleepResult::Acknowledged => allow(context.connection, notification),
        SleepResult::Closed => {}
        SleepResult::TimedOut => (context.failed)(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn native_session_observer_preserves_distinct_transitions() -> io::Result<()> {
        let (sender, mut receiver) = event_stream(Arc::new(|| {}));
        sender.send(NativeSessionNotification::new(NativeSessionEvent::SystemWake, None));
        sender.send(NativeSessionNotification::new(NativeSessionEvent::ScreenUnlock, None));
        let first = receiver.try_recv().map_err(io::Error::other)?;
        assert_eq!(first.event, NativeSessionEvent::SystemWake);
        assert_eq!(
            receiver.try_recv().map_err(io::Error::other)?.event,
            NativeSessionEvent::ScreenUnlock
        );
        Ok(())
    }

    #[test]
    fn native_session_observer_queue_overflow_fails_closed() {
        let failed = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&failed);
        let (sender, _receiver) = event_stream(Arc::new(move || {
            marker.store(true, Ordering::SeqCst);
        }));
        for _ in 0..EVENT_QUEUE_CAPACITY {
            sender.send(NativeSessionNotification::new(NativeSessionEvent::ScreenLock, None));
        }
        assert!(!failed.load(Ordering::SeqCst));
        sender.send(NativeSessionNotification::new(NativeSessionEvent::ScreenUnlock, None));
        assert!(failed.load(Ordering::SeqCst));
    }

    #[test]
    fn native_session_observer_acknowledgement_is_bound_to_sleep_generation() -> io::Result<()> {
        let ack = SleepAcknowledgement::default();
        let first = ack.arm().ok_or_else(|| io::Error::other("closed"))?;
        ack.acknowledge(first);
        let second = ack.arm().ok_or_else(|| io::Error::other("closed"))?;
        ack.acknowledge(first);
        assert_eq!(ack.wait(second, Duration::ZERO), SleepResult::TimedOut);
        ack.acknowledge(second);
        assert_eq!(ack.wait(second, Duration::ZERO), SleepResult::Acknowledged);
        Ok(())
    }
    #[tokio::test]
    async fn native_session_observer_sleep_waits_for_matching_erasure() -> io::Result<()> {
        let (sender, mut receiver) = event_stream(Arc::new(|| {}));
        let ack = Arc::new(SleepAcknowledgement::default());
        let allowed = Arc::new(AtomicBool::new(false));
        let worker_allowed = Arc::clone(&allowed);
        let context = PowerContext {
            sender,
            connection: 11,
            acknowledgement: Arc::clone(&ack),
            failed: Arc::new(|| {}),
            timeout: Duration::from_secs(3),
        };
        let worker = std::thread::spawn(move || {
            handle_power_notification(&context, kIOMessageSystemWillSleep, 42, |connection, id| {
                assert_eq!((connection, id), (11, 42));
                worker_allowed.store(true, Ordering::SeqCst);
            });
        });
        let event = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await?
            .ok_or_else(|| io::Error::other("missing event"))?;
        assert_eq!(event.event, NativeSessionEvent::SystemSleep);
        assert!(!allowed.load(Ordering::SeqCst));
        ack.acknowledge(event.sleep_token.ok_or_else(|| io::Error::other("missing sleep token"))?);
        worker.join().map_err(|_| io::Error::other("callback panicked"))?;
        assert!(allowed.load(Ordering::SeqCst));
        Ok(())
    }
    #[test]
    fn native_session_observer_sleep_timeout_fails_closed() {
        let failed = Arc::new(AtomicBool::new(false));
        let callback_failed = Arc::clone(&failed);
        let (sender, _receiver) = event_stream(Arc::new(|| {}));
        let context = PowerContext {
            sender,
            connection: 11,
            acknowledgement: Arc::new(SleepAcknowledgement::default()),
            failed: Arc::new(move || {
                callback_failed.store(true, Ordering::SeqCst);
            }),
            timeout: Duration::ZERO,
        };
        let allowed = std::cell::Cell::new(false);
        handle_power_notification(&context, kIOMessageSystemWillSleep, 42, |_, _| {
            allowed.set(true);
        });
        assert!(failed.load(Ordering::SeqCst));
        assert!(!allowed.get());
    }
    #[test]
    fn native_session_observer_shutdown_wakes_pending_sleep() -> io::Result<()> {
        let ack = SleepAcknowledgement::default();
        let token = ack.arm().ok_or_else(|| io::Error::other("closed"))?;
        ack.close();
        assert_eq!(ack.wait(token, Duration::from_secs(5)), SleepResult::Closed);
        Ok(())
    }
    #[test]
    fn native_session_observer_maps_idle_sleep_and_resume() {
        let (sender, mut receiver) = event_stream(Arc::new(|| {}));
        let context = PowerContext {
            sender,
            connection: 11,
            acknowledgement: Arc::new(SleepAcknowledgement::default()),
            failed: Arc::new(|| {}),
            timeout: Duration::ZERO,
        };
        let allowed = std::cell::Cell::new(false);
        handle_power_notification(&context, kIOMessageCanSystemSleep, 42, |_, _| allowed.set(true));
        assert!(allowed.get());
        assert!(receiver.try_recv().is_err());
        handle_power_notification(&context, kIOMessageSystemHasPoweredOn, 0, |_, _| {
            allowed.set(false);
        });
        assert!(allowed.get());
        assert_eq!(
            receiver.try_recv().ok().map(|event| event.event),
            Some(NativeSessionEvent::SystemWake)
        );
    }
}
