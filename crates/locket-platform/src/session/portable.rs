//! Bounded delivery and generation-specific suspend acknowledgements.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

use super::{NativeSessionEvent, NativeSessionNotification};

pub(super) type FailureCallback = Arc<dyn Fn() + Send + Sync>;
const EVENT_CAPACITY: usize = 32;

#[derive(Default)]
struct AckState {
    next: u64,
    pending: Option<u64>,
    acknowledged: u64,
    stopping: bool,
}

#[derive(Default)]
pub(super) struct Acknowledgement {
    state: Mutex<AckState>,
    changed: Condvar,
}

impl Acknowledgement {
    pub(super) fn acknowledge(&self, token: Option<u64>) {
        if let Some(token) = token
            && let Ok(mut state) = self.state.lock()
            && state.pending == Some(token)
        {
            state.pending = None;
            state.acknowledged = token;
            self.changed.notify_all();
        }
    }

    pub(super) fn stop(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.stopping = true;
            self.changed.notify_all();
        }
    }

    pub(super) fn stopping(&self) -> bool {
        self.state.lock().map_or(true, |state| state.stopping)
    }

    fn begin(&self) -> Option<u64> {
        let mut state = self.state.lock().ok()?;
        if state.stopping || state.pending.is_some() {
            return None;
        }
        state.next = state.next.checked_add(1)?;
        state.pending = Some(state.next);
        Some(state.next)
    }

    fn wait(&self, token: u64, timeout: Duration) -> bool {
        let Ok(state) = self.state.lock() else { return false };
        let result = self.changed.wait_timeout_while(state, timeout, |state| {
            state.acknowledged != token && !state.stopping
        });
        result.is_ok_and(|(state, _)| state.acknowledged == token || state.stopping)
    }
}

pub(super) struct EventSink {
    sender: mpsc::Sender<NativeSessionNotification>,
    pub(super) acknowledgement: Arc<Acknowledgement>,
    failed: FailureCallback,
}

impl EventSink {
    pub(super) fn emit(&self, event: NativeSessionEvent) -> bool {
        self.send(NativeSessionNotification::new(event, None))
    }

    fn send(&self, event: NativeSessionNotification) -> bool {
        if self.acknowledgement.stopping() {
            return false;
        }
        if self.sender.try_send(event).is_err() {
            self.fail();
            return false;
        }
        true
    }

    pub(super) fn suspend(&self, timeout: Duration) -> bool {
        let Some(token) = self.acknowledgement.begin() else {
            self.fail();
            return false;
        };
        if !self.send(NativeSessionNotification::new(NativeSessionEvent::SystemSleep, Some(token)))
        {
            return false;
        }
        if !self.acknowledgement.wait(token, timeout) {
            self.fail();
            return false;
        }
        true
    }

    pub(super) fn fail(&self) {
        if !self.acknowledgement.stopping() {
            (self.failed)();
        }
    }
}

pub(super) fn event_stream(
    failed: FailureCallback,
) -> (EventSink, mpsc::Receiver<NativeSessionNotification>) {
    let (sender, receiver) = mpsc::channel(EVENT_CAPACITY);
    (EventSink { sender, acknowledgement: Arc::default(), failed }, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn stream() -> (EventSink, mpsc::Receiver<NativeSessionNotification>, Arc<AtomicUsize>) {
        let failed = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&failed);
        let (sink, receiver) = event_stream(Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
        }));
        (sink, receiver, failed)
    }

    #[test]
    fn portable_session_queue_preserves_transitions_and_fails_on_overflow() {
        let (sink, mut receiver, failures) = stream();
        for _ in 0..EVENT_CAPACITY / 2 {
            assert!(sink.emit(NativeSessionEvent::ScreenLock));
            assert!(sink.emit(NativeSessionEvent::ScreenUnlock));
        }
        assert!(!sink.emit(NativeSessionEvent::ScreenLock));
        assert_eq!(failures.load(Ordering::SeqCst), 1);
        assert_eq!(
            receiver.try_recv().map(|event| event.event),
            Ok(NativeSessionEvent::ScreenLock)
        );
        assert_eq!(
            receiver.try_recv().map(|event| event.event),
            Ok(NativeSessionEvent::ScreenUnlock)
        );
    }

    #[test]
    fn portable_session_acknowledgement_is_generation_bound() {
        let ack = Acknowledgement::default();
        let first = ack.begin();
        ack.acknowledge(first);
        let second = ack.begin();
        assert_ne!(first, second);
        ack.acknowledge(first);
        assert!(!ack.wait(second.unwrap_or(0), Duration::ZERO));
        ack.acknowledge(second);
        assert!(ack.wait(second.unwrap_or(0), Duration::ZERO));
    }

    #[test]
    fn portable_session_suspend_timeout_fails_closed() {
        let (sink, _receiver, failures) = stream();
        assert!(!sink.suspend(Duration::ZERO));
        assert_eq!(failures.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn portable_session_suspend_waits_for_matching_erasure()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sink, mut receiver, failures) = stream();
        let ack = Arc::clone(&sink.acknowledgement);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let acknowledged = sink.suspend(Duration::from_secs(1));
            let _sent = done_tx.send(acknowledged);
        });
        let event = receiver.blocking_recv().ok_or("missing suspend notification")?;
        assert_eq!(event.event, NativeSessionEvent::SystemSleep);
        assert_eq!(
            done_rx.recv_timeout(Duration::from_millis(10)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        );
        ack.acknowledge(event.sleep_token);
        assert!(done_rx.recv_timeout(Duration::from_secs(1))?);
        assert!(worker.join().is_ok());
        assert_eq!(failures.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn portable_session_shutdown_releases_wait_and_closes_stream() {
        let (sink, mut receiver, failures) = stream();
        let ack = Arc::clone(&sink.acknowledgement);
        assert!(ack.begin().is_some());
        ack.stop();
        assert!(ack.wait(1, Duration::ZERO));
        assert!(!sink.emit(NativeSessionEvent::ScreenLock));
        drop(sink);
        assert_eq!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Disconnected));
        assert_eq!(failures.load(Ordering::SeqCst), 0);
    }
}
