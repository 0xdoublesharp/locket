//! Server-side fan-out of metadata-only status events.
//!
//! [`StatusHub`] owns the current [`StatusPayload`], broadcasts every
//! [`StatusHub::publish`] to live subscribers via
//! `tokio::sync::broadcast`, and tracks a per-subscriber
//! [`StatusEventSequence`] so each stream sees its own monotonic
//! sequence numbers (the spec ties `sequence` to the connection, not
//! the agent).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, broadcast};
use tokio::time::Instant;

use crate::status::{
    STATUS_HEARTBEAT_INTERVAL_SECS, StatusEvent, StatusEventSequence, StatusPayload,
};

const BROADCAST_CAPACITY: usize = 64;

/// Server-side fan-out hub for metadata-only status events.
#[derive(Clone)]
pub struct StatusHub {
    inner: Arc<HubInner>,
}

struct HubInner {
    current: Mutex<StatusPayload>,
    sender: broadcast::Sender<StatusPayload>,
}

impl StatusHub {
    /// Creates a hub initialized with the given snapshot.
    #[must_use]
    pub fn new(initial: StatusPayload) -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self { inner: Arc::new(HubInner { current: Mutex::new(initial), sender }) }
    }

    /// Replaces the current snapshot and broadcasts it.
    pub async fn publish(&self, payload: StatusPayload) {
        let mut current = self.inner.current.lock().await;
        *current = payload.clone();
        let _ = self.inner.sender.send(payload);
        drop(current);
    }

    /// Subscribes a new client. The first
    /// [`StatusSubscriber::next_event`] call yields a snapshot of the
    /// current status; subsequent calls yield broadcasted updates or
    /// heartbeats per the configured interval.
    pub async fn subscribe(&self) -> StatusSubscriber {
        // Snapshot and subscription must see the same position in the stream.
        let current = self.inner.current.lock().await;
        let snapshot = current.clone();
        let receiver = self.inner.sender.subscribe();
        drop(current);
        let heartbeat_interval = Duration::from_secs(STATUS_HEARTBEAT_INTERVAL_SECS);
        StatusSubscriber {
            sequence: StatusEventSequence::new(),
            receiver,
            initial: Some(snapshot.clone()),
            last_seen: snapshot,
            heartbeat_interval,
            next_heartbeat: Instant::now() + heartbeat_interval,
        }
    }
}

/// A connected `SubscribeStatus` stream.
pub struct StatusSubscriber {
    sequence: StatusEventSequence,
    receiver: broadcast::Receiver<StatusPayload>,
    initial: Option<StatusPayload>,
    last_seen: StatusPayload,
    heartbeat_interval: Duration,
    next_heartbeat: Instant,
}

impl StatusSubscriber {
    /// Returns the next event in the stream using the configured
    /// heartbeat interval. Returns `None` only if the hub was dropped.
    pub async fn next_event(&mut self) -> Option<StatusEvent> {
        let interval = self.heartbeat_interval;
        self.next_event_with_heartbeat(interval).await
    }

    /// Like [`StatusSubscriber::next_event`], but the heartbeat tick is
    /// overridable so tests can run with millisecond cadence.
    pub async fn next_event_with_heartbeat(&mut self, heartbeat: Duration) -> Option<StatusEvent> {
        if let Some(initial) = self.initial.take() {
            self.last_seen = initial.clone();
            self.next_heartbeat = Instant::now() + heartbeat;
            return Some(self.sequence.status(initial));
        }
        let sleep = tokio::time::sleep_until(self.next_heartbeat);
        tokio::select! {
            received = self.receiver.recv() => match received {
                Ok(payload) => {
                    self.last_seen = payload.clone();
                    self.next_heartbeat = Instant::now() + heartbeat;
                    Some(self.sequence.status(payload))
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    self.next_heartbeat = Instant::now() + heartbeat;
                    Some(self.sequence.heartbeat(self.last_seen.clone()))
                }
                Err(broadcast::error::RecvError::Closed) => None,
            },
            () = sleep => {
                self.next_heartbeat = Instant::now() + heartbeat;
                Some(self.sequence.heartbeat(self.last_seen.clone()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{StatusHub, StatusPayload};
    use crate::status::LockState;
    use std::time::Duration;

    #[tokio::test]
    async fn subscription_does_not_replay_updates_older_than_its_initial_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let locked = StatusPayload::locked("v");
        let hub = StatusHub::new(locked.clone());
        let mut subscriber = {
            let current = hub.inner.current.lock().await;
            let mut unlocked = locked.clone();
            unlocked.lock_state = LockState::Unlocked;
            let mut publish_unlock = std::pin::pin!(hub.publish(unlocked));
            let mut publish_lock = std::pin::pin!(hub.publish(locked.clone()));
            let mut subscribe = std::pin::pin!(hub.subscribe());
            tokio::select! {
                biased;
                () = &mut publish_unlock => return Err("unlock skipped the snapshot lock".into()),
                () = &mut publish_lock => return Err("lock skipped the snapshot lock".into()),
                _ = &mut subscribe => return Err("subscription skipped the snapshot lock".into()),
                () = async {} => {}
            }
            drop(current);
            publish_unlock.await;
            publish_lock.await;
            subscribe.await
        };
        let first = subscriber.next_event().await.ok_or("initial snapshot missing")?;
        assert_eq!(first.status, locked);
        tokio::select! {
            biased;
            update = subscriber.next_event() => return Err(format!("unexpected queued update: {update:?}").into()),
            () = async {} => {}
        }
        drop(hub);
        assert!(subscriber.next_event().await.is_none());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn subscriber_receives_initial_status_then_heartbeat() {
        let hub = StatusHub::new(StatusPayload::locked("test-version"));
        let mut subscriber = hub.subscribe().await;

        let Some(initial) = subscriber.next_event_with_heartbeat(Duration::from_millis(20)).await
        else {
            unreachable!("initial event must be available");
        };
        assert!(initial.is_state_change());
        assert_eq!(initial.status.lock_state, LockState::Locked);

        let Some(beat) = subscriber.next_event_with_heartbeat(Duration::from_millis(20)).await
        else {
            unreachable!("heartbeat must fire when no publish arrives");
        };
        assert!(beat.is_heartbeat());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn publish_sends_status_change_to_subscribers() {
        let hub = StatusHub::new(StatusPayload::locked("v"));
        let mut a = hub.subscribe().await;
        let mut b = hub.subscribe().await;

        let _initial_a = a.next_event().await;
        let _initial_b = b.next_event().await;

        let mut updated = StatusPayload::locked("v");
        updated.lock_state = LockState::Unlocked;
        hub.publish(updated.clone()).await;

        let Some(from_a) = a.next_event().await else {
            unreachable!("a must observe published status");
        };
        assert_eq!(from_a.status.lock_state, LockState::Unlocked);
        let Some(from_b) = b.next_event().await else {
            unreachable!("b must observe published status");
        };
        assert_eq!(from_b.status.lock_state, LockState::Unlocked);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn subscriber_interleaves_state_changes_and_heartbeats() {
        let hub = StatusHub::new(StatusPayload::locked("v"));
        let mut subscriber = hub.subscribe().await;

        let Some(initial) = subscriber.next_event_with_heartbeat(Duration::from_millis(20)).await
        else {
            unreachable!("initial status event must arrive");
        };
        assert_eq!(initial.sequence, 1);
        assert!(initial.is_state_change());
        assert_eq!(initial.status.lock_state, LockState::Locked);

        let Some(first_heartbeat) =
            subscriber.next_event_with_heartbeat(Duration::from_millis(20)).await
        else {
            unreachable!("heartbeat event must arrive");
        };
        assert_eq!(first_heartbeat.sequence, 2);
        assert!(first_heartbeat.is_heartbeat());
        assert_eq!(first_heartbeat.status.lock_state, LockState::Locked);

        let mut unlocked = StatusPayload::locked("v");
        unlocked.lock_state = LockState::Unlocked;
        hub.publish(unlocked).await;

        let Some(changed) = subscriber.next_event_with_heartbeat(Duration::from_millis(20)).await
        else {
            unreachable!("published state-change event must arrive");
        };
        assert_eq!(changed.sequence, 3);
        assert!(changed.is_state_change());
        assert_eq!(changed.status.lock_state, LockState::Unlocked);

        let Some(second_heartbeat) =
            subscriber.next_event_with_heartbeat(Duration::from_millis(20)).await
        else {
            unreachable!("heartbeat after state change must arrive");
        };
        assert_eq!(second_heartbeat.sequence, 4);
        assert!(second_heartbeat.is_heartbeat());
        assert_eq!(second_heartbeat.status.lock_state, LockState::Unlocked);
    }
}
