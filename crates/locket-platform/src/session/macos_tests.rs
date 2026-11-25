use super::*;

#[tokio::test]
async fn observer_reports_missing_main_thread_driver() {
    assert!(matches!(
        SessionObserver::start(|| {}).await,
        Err(error) if error.kind() == io::ErrorKind::Unsupported
    ));
}

#[tokio::test]
async fn screen_callbacks_publish_ordered_events_and_answer_probe_once() -> io::Result<()> {
    let (sender, receiver) = event_stream(Arc::new(|| {}));
    let (ready, started) = oneshot::channel();
    let mut screen = ScreenContext { sender, ready: Mutex::new(Some(ready)) };

    let (driver, disconnected) = test_dispatch()?;
    drop(disconnected);
    let acknowledgement = Arc::new(SleepAcknowledgement::default());
    let guard = ObserverGuard { id: 1, driver, acknowledgement: Arc::clone(&acknowledgement) };
    let mut observer = SessionObserver { guard, receiver, backend_name: "synthetic callbacks" };
    assert_eq!(observer.backend_name(), "synthetic callbacks");
    assert!(observer.try_next_event()?.is_none());

    let context = ptr::from_mut(&mut screen).cast();
    // SAFETY: the callbacks read only the live context here. All other
    // arguments are unused. No system notifications are posted.
    unsafe {
        screen_lock(ptr::null_mut(), context, ptr::null(), ptr::null(), ptr::null());
        screen_unlock(ptr::null_mut(), context, ptr::null(), ptr::null(), ptr::null());
        probe_delivered(ptr::null_mut(), context, ptr::null(), ptr::null(), ptr::null());
        probe_delivered(ptr::null_mut(), context, ptr::null(), ptr::null(), ptr::null());
    }
    started.await.map_err(io::Error::other)??;
    assert!(screen.ready.lock().map_err(|_| io::Error::other("probe lock"))?.is_none());
    let token = acknowledgement.arm().ok_or_else(|| io::Error::other("closed"))?;
    let lock = observer.try_next_event()?.ok_or_else(|| io::Error::other("missing lock"))?;
    assert_eq!(lock.event, NativeSessionEvent::ScreenLock);
    observer.acknowledge_event(lock);
    assert_eq!(acknowledgement.wait(token, Duration::ZERO), SleepResult::TimedOut);
    let unlock = observer.next_event().await.ok_or_else(|| io::Error::other("missing unlock"))?;
    assert_eq!(unlock.event, NativeSessionEvent::ScreenUnlock);
    screen
        .sender
        .send(NativeSessionNotification::new(NativeSessionEvent::SystemSleep, Some(token)));
    let sleep = observer.try_next_event()?.ok_or_else(|| io::Error::other("missing sleep"))?;
    observer.acknowledge_event(sleep);
    assert_eq!(acknowledgement.wait(token, Duration::ZERO), SleepResult::Acknowledged);

    drop(screen);
    assert_eq!(
        observer.try_next_event().err().map(|error| error.kind()),
        Some(io::ErrorKind::Other)
    );
    assert!(observer.next_event().await.is_none());
    drop(observer);
    assert!(acknowledgement.arm().is_none());
    Ok(())
}

fn test_dispatch() -> io::Result<(Arc<DispatchHandle>, mpsc::Receiver<MainTask>)> {
    let loop_ = CFRunLoop::current().ok_or_else(|| io::Error::other("no test run loop"))?;
    let mut context = CFRunLoopSourceContext {
        version: 0,
        info: ptr::null_mut(),
        retain: None,
        release: None,
        copyDescription: None,
        equal: None,
        hash: None,
        schedule: None,
        cancel: None,
        perform: Some(noop),
    };
    // SAFETY: the source copies a valid context. It is never registered or run.
    let source = unsafe { CFRunLoopSource::new(None, 0, &raw mut context) }
        .ok_or_else(|| io::Error::other("no test source"))?;
    let (dispatch, disconnected) = mpsc::channel();
    Ok((Arc::new(DispatchHandle { sender: dispatch, run_loop: loop_, source }), disconnected))
}

unsafe extern "C-unwind" fn noop(_: *mut c_void) {}

#[test]
fn closed_sleep_acknowledgement_never_allows_system_sleep() -> io::Result<()> {
    let (sender, mut receiver) = event_stream(Arc::new(|| {}));
    let acknowledgement = Arc::new(SleepAcknowledgement::default());
    let context = PowerContext {
        sender,
        connection: 0,
        acknowledgement: Arc::clone(&acknowledgement),
        failed: Arc::new(|| {}),
        timeout: Duration::from_secs(3),
    };
    let allowed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_allowed = Arc::clone(&allowed);
    let worker = std::thread::spawn(move || {
        handle_power_notification(&context, kIOMessageSystemWillSleep, 42, |_, _| {
            worker_allowed.store(true, Ordering::Relaxed);
        });
        handle_power_notification(&context, kIOMessageSystemWillSleep, 43, |_, _| {
            worker_allowed.store(true, Ordering::Relaxed);
        });
    });
    let event = receiver.blocking_recv().ok_or_else(|| io::Error::other("missing sleep"))?;
    assert_eq!(event.event, NativeSessionEvent::SystemSleep);
    acknowledgement.close();
    worker.join().map_err(|_| io::Error::other("power handler panicked"))?;
    assert!(!allowed.load(Ordering::Relaxed));
    assert!(receiver.try_recv().is_err());
    Ok(())
}

#[tokio::test]
async fn startup_probe_failure_removes_the_observer_and_closes_sleep_acknowledgements()
-> io::Result<()> {
    enum Probe {
        Reject,
        Disconnect,
        Timeout,
    }
    for probe in [Probe::Reject, Probe::Disconnect, Probe::Timeout] {
        let (driver, tasks) = test_dispatch()?;
        let deadline = Duration::from_secs(5);
        let (timeout, expected) = match probe {
            Probe::Reject => (deadline, io::ErrorKind::PermissionDenied),
            Probe::Disconnect => (deadline, io::ErrorKind::Other),
            Probe::Timeout => (Duration::ZERO, io::ErrorKind::TimedOut),
        };

        let responder = std::thread::spawn(move || -> io::Result<()> {
            let MainTask::Start { id, ready, acknowledgement, .. } =
                tasks.recv_timeout(deadline).map_err(io::Error::other)?
            else {
                return Err(io::Error::other("missing start request"));
            };
            let pending = match probe {
                Probe::Reject => {
                    ready
                        .send(Err(io::Error::from(io::ErrorKind::PermissionDenied)))
                        .map_err(|_| io::Error::other("startup receiver dropped"))?;
                    None
                }
                Probe::Disconnect => {
                    drop(ready);
                    None
                }
                Probe::Timeout => Some(ready),
            };
            let MainTask::Remove { id: removed, done } =
                tasks.recv_timeout(deadline).map_err(io::Error::other)?
            else {
                return Err(io::Error::other("missing removal request"));
            };
            assert_eq!(removed, id);
            assert!(acknowledgement.arm().is_none());
            done.send(()).map_err(io::Error::other)?;
            drop(pending);
            Ok(())
        });
        let result = start_with_driver(driver, Arc::new(|| {}), timeout).await;
        responder.join().map_err(|_| io::Error::other("probe responder panicked"))??;
        assert!(matches!(result, Err(error) if error.kind() == expected));
    }
    Ok(())
}

#[test]
fn power_callback_routes_resume_without_accessing_a_power_connection() -> io::Result<()> {
    let (sender, mut receiver) = event_stream(Arc::new(|| {}));
    let mut context = PowerContext {
        sender,
        connection: 0,
        acknowledgement: Arc::new(SleepAcknowledgement::default()),
        failed: Arc::new(|| {}),
        timeout: Duration::ZERO,
    };
    // SAFETY: the callback receives a valid context. A wake notification
    // never calls IOKit and therefore does not require a live connection.
    unsafe {
        power_notification(
            ptr::from_mut(&mut context).cast(),
            0,
            kIOMessageSystemHasPoweredOn,
            ptr::null_mut(),
        );
    }
    let event = receiver.try_recv().map_err(io::Error::other)?;
    assert_eq!(event.event, NativeSessionEvent::SystemWake);
    assert!(event.sleep_token.is_none());
    Ok(())
}

#[test]
fn off_main_loop_invocation_runs_on_its_calling_thread() -> io::Result<()> {
    let thread = std::thread::current().id();
    assert_eq!(super::run(|| std::thread::current().id())?, thread);
    Ok(())
}
