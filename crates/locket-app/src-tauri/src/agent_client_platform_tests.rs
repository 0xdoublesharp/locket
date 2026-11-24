//! Deterministic endpoint and polling regressions, without environment mutation.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use super::{AgentClientError, CancelToken, endpoint_from_inputs, poll_status_events_with};
use locket_agent::{LockState, StatusEvent, StatusPayload};
use locket_platform::LocketInstance::{Dev, Installed};
use tokio::sync::{Notify, mpsc};

#[test]
fn macos_default_endpoint_matches_cli_application_support_directory() {
    assert_eq!(
        endpoint_from_inputs(
            Installed,
            "macos",
            None,
            Path::new("/Users/fixture"),
            Some(OsStr::new("/ignored-runtime")),
            None
        ),
        PathBuf::from("/Users/fixture/Library/Application Support/locket/agent.sock")
    );
}

#[test]
fn linux_endpoint_uses_xdg_runtime_then_home_fallback() {
    let home = Path::new("/home/fixture");
    assert_eq!(
        endpoint_from_inputs(
            Installed,
            "linux",
            None,
            home,
            Some(OsStr::new("/run/user/1000")),
            None
        ),
        PathBuf::from("/run/user/1000/locket/agent.sock")
    );
    for runtime in [None, Some(OsStr::new(""))] {
        assert_eq!(
            endpoint_from_inputs(Installed, "linux", None, home, runtime, None),
            home.join(".locket/agent.sock")
        );
    }
}

#[test]
fn explicit_endpoint_override_wins_on_every_platform_and_empty_override_is_ignored() {
    for platform in ["macos", "linux", "windows"] {
        assert_eq!(
            endpoint_from_inputs(
                Installed,
                platform,
                Some(OsStr::new("explicit-agent-endpoint")),
                Path::new("home"),
                None,
                None
            ),
            PathBuf::from("explicit-agent-endpoint")
        );
    }
    assert_eq!(
        endpoint_from_inputs(
            Installed,
            "macos",
            Some(OsStr::new("")),
            Path::new("home"),
            None,
            None
        ),
        PathBuf::from("home/Library/Application Support/locket/agent.sock")
    );
}

#[test]
fn dev_endpoint_never_matches_the_installed_endpoint() {
    let home = Path::new("/Users/fixture");
    assert_eq!(
        endpoint_from_inputs(Dev, "macos", None, home, None, None),
        PathBuf::from("/Users/fixture/Library/Application Support/locket-dev/agent.sock")
    );
    assert_eq!(
        endpoint_from_inputs(Dev, "linux", None, home, Some(OsStr::new("/run/user/1000")), None),
        PathBuf::from("/run/user/1000/locket-dev/agent.sock")
    );
    assert_eq!(
        endpoint_from_inputs(Dev, "linux", None, home, None, None),
        home.join(".locket-dev/agent.sock")
    );
}

#[test]
fn windows_endpoint_uses_resolved_user_pipe_and_fails_closed_without_sid() {
    let pipe = Path::new(r"\\.\pipe\locket-agent-S-1-5-21-1000");
    assert_eq!(
        endpoint_from_inputs(Installed, "windows", None, Path::new("home"), None, Some(pipe)),
        pipe
    );
    assert!(
        endpoint_from_inputs(Installed, "windows", None, Path::new("home"), None, None)
            .as_os_str()
            .is_empty()
    );
}

#[tokio::test]
async fn status_polling_emits_real_snapshot_heartbeat_and_changed_status()
-> Result<(), Box<dyn std::error::Error>> {
    let mut locked = StatusPayload::locked("synthetic");
    locked.project_id = Some("project-fixture".into());
    let mut unlocked = locked.clone();
    unlocked.lock_state = LockState::Unlocked;
    unlocked.unlock_ttl_seconds = Some(37);
    let expected = unlocked.clone();
    let mut statuses = std::collections::VecDeque::from([locked.clone(), locked, unlocked]);
    let (sender, mut receiver) = mpsc::channel::<StatusEvent>(4);
    let cancel = CancelToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        poll_status_events_with(
            move || {
                std::future::ready(statuses.pop_front().ok_or_else(|| AgentClientError::Protocol {
                    reason: "fixture exhausted".into(),
                }))
            },
            sender,
            &task_cancel,
            Duration::from_millis(5),
            Duration::from_millis(5),
        )
        .await
    });
    let first = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("initial status missing")?;
    let second = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("heartbeat missing")?;
    let third = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("changed status missing")?;
    cancel.cancel();
    task.await??;
    assert!(first.is_state_change());
    assert!(second.is_heartbeat());
    assert!(third.is_state_change());
    assert_eq!(third.status, expected);
    assert!(first.sequence < second.sequence && second.sequence < third.sequence);
    Ok(())
}

#[tokio::test]
async fn polling_cancellation_interrupts_pending_rpc() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, _receiver) = mpsc::channel(1);
    let cancel = CancelToken::new();
    let task_cancel = cancel.clone();
    let entered = Arc::new(Notify::new());
    let task_entered = Arc::clone(&entered);
    let task = tokio::spawn(async move {
        poll_status_events_with(
            move || {
                task_entered.notify_one();
                std::future::pending::<Result<StatusPayload, AgentClientError>>()
            },
            sender,
            &task_cancel,
            Duration::from_secs(30),
            Duration::from_secs(30),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified()).await?;
    cancel.cancel();
    tokio::time::timeout(Duration::from_millis(100), task).await???;
    Ok(())
}

#[tokio::test]
async fn polling_cancellation_interrupts_full_event_queue() -> Result<(), Box<dyn std::error::Error>>
{
    let (sender, mut receiver) = mpsc::channel(1);
    let cancel = CancelToken::new();
    let task_cancel = cancel.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let task_calls = Arc::clone(&calls);
    let blocked = Arc::new(Notify::new());
    let task_blocked = Arc::clone(&blocked);
    let task = tokio::spawn(async move {
        poll_status_events_with(
            move || {
                let call = task_calls.fetch_add(1, Ordering::SeqCst);
                if call == 1 {
                    task_blocked.notify_one();
                }
                std::future::ready(Ok(StatusPayload::locked(format!("synthetic-{call}"))))
            },
            sender,
            &task_cancel,
            Duration::from_millis(1),
            Duration::from_secs(30),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), blocked.notified()).await?;
    cancel.cancel();
    tokio::time::timeout(Duration::from_millis(100), task).await???;
    assert!(receiver.recv().await.is_some());
    assert!(receiver.recv().await.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn polling_propagates_rpc_failure_without_inventing_freshness() {
    let (sender, mut receiver) = mpsc::channel(1);
    let result = poll_status_events_with(
        || {
            std::future::ready(Err(AgentClientError::Protocol {
                reason: "synthetic failure".into(),
            }))
        },
        sender,
        &CancelToken::new(),
        Duration::from_millis(1),
        Duration::from_secs(30),
    )
    .await;
    assert!(
        matches!(result, Err(AgentClientError::Protocol { reason }) if reason == "synthetic failure")
    );
    assert!(receiver.recv().await.is_none());
}

#[tokio::test]
async fn countdown_only_polls_wait_for_heartbeat_and_publish_latest_ttl()
-> Result<(), Box<dyn std::error::Error>> {
    let (sender, mut receiver) = mpsc::channel(4);
    let cancel = CancelToken::new();
    let task_cancel = cancel.clone();
    let mut first = true;
    let task = tokio::spawn(async move {
        poll_status_events_with(
            move || {
                let mut status = StatusPayload::locked("synthetic");
                status.lock_state = LockState::Unlocked;
                status.unlock_ttl_seconds = Some(if std::mem::take(&mut first) { 60 } else { 55 });
                std::future::ready(Ok(status))
            },
            sender,
            &task_cancel,
            Duration::from_millis(1),
            Duration::from_millis(20),
        )
        .await
    });
    let initial = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("initial event")?;
    let heartbeat = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("heartbeat event")?;
    cancel.cancel();
    task.await??;
    assert!(initial.is_state_change());
    assert_eq!(initial.status.unlock_ttl_seconds, Some(60));
    assert!(heartbeat.is_heartbeat());
    assert_eq!(heartbeat.status.unlock_ttl_seconds, Some(55));
    assert_eq!(heartbeat.sequence, initial.sequence + 1);
    Ok(())
}

#[tokio::test]
async fn ttl_renewal_after_countdown_is_meaningful_below_last_published_ttl()
-> Result<(), Box<dyn std::error::Error>> {
    let mut statuses = [60, 55, 58]
        .map(|ttl| {
            let mut status = StatusPayload::locked("synthetic");
            status.lock_state = LockState::Unlocked;
            status.unlock_ttl_seconds = Some(ttl);
            status
        })
        .into_iter();
    let (sender, mut receiver) = mpsc::channel(4);
    let cancel = CancelToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        poll_status_events_with(
            move || {
                let status = statuses.next();
                async move {
                    match status {
                        Some(status) => Ok(status),
                        None => std::future::pending().await,
                    }
                }
            },
            sender,
            &task_cancel,
            Duration::from_millis(1),
            Duration::from_secs(30),
        )
        .await
    });
    let initial = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("initial event")?;
    let renewed = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("renewal event")?;
    cancel.cancel();
    task.await??;
    assert_eq!(initial.status.unlock_ttl_seconds, Some(60));
    assert!(renewed.is_state_change());
    assert_eq!(renewed.status.unlock_ttl_seconds, Some(58));
    assert_eq!(renewed.sequence, initial.sequence + 1);
    Ok(())
}

#[tokio::test]
async fn non_ttl_metadata_change_is_emitted_during_heartbeat_quiet_period()
-> Result<(), Box<dyn std::error::Error>> {
    let mut initial = StatusPayload::locked("first");
    initial.lock_state = LockState::Unlocked;
    initial.unlock_ttl_seconds = Some(60);
    let mut countdown = initial.clone();
    countdown.unlock_ttl_seconds = Some(55);
    let mut changed = countdown.clone();
    changed.agent_version = "changed".into();
    changed.unlock_ttl_seconds = Some(54);
    let mut statuses = std::collections::VecDeque::from([initial, countdown, changed]);
    let (sender, mut receiver) = mpsc::channel(4);
    let cancel = CancelToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        poll_status_events_with(
            move || {
                let status = statuses.pop_front();
                async move {
                    match status {
                        Some(status) => Ok(status),
                        None => std::future::pending().await,
                    }
                }
            },
            sender,
            &task_cancel,
            Duration::from_millis(1),
            Duration::from_secs(30),
        )
        .await
    });
    let first = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("initial event")?;
    let second = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("metadata event")?;
    cancel.cancel();
    task.await??;
    assert!(second.is_state_change());
    assert_eq!(second.status.agent_version, "changed");
    assert_eq!(second.status.unlock_ttl_seconds, Some(54));
    assert_eq!(second.sequence, first.sequence + 1);
    Ok(())
}

#[tokio::test]
async fn meaningful_change_resets_heartbeat_deadline() -> Result<(), Box<dyn std::error::Error>> {
    let timestamps = Arc::new(std::sync::Mutex::new(Vec::new()));
    let task_timestamps = Arc::clone(&timestamps);
    let (sender, mut receiver) = mpsc::channel(4);
    let cancel = CancelToken::new();
    let task_cancel = cancel.clone();
    let heartbeat_interval = Duration::from_millis(50);
    let mut sample = 0_u64;
    let task = tokio::spawn(async move {
        poll_status_events_with(
            move || {
                let index = sample;
                sample += 1;
                let timestamps = Arc::clone(&task_timestamps);
                async move {
                    if index > 0 {
                        tokio::time::sleep(Duration::from_millis(30)).await;
                    }
                    timestamps
                        .lock()
                        .map_err(|_| AgentClientError::Protocol { reason: "fixture lock".into() })?
                        .push(tokio::time::Instant::now());
                    let mut status =
                        StatusPayload::locked(if index == 0 { "initial" } else { "changed" });
                    status.lock_state = LockState::Unlocked;
                    status.unlock_ttl_seconds = Some(60_u64.saturating_sub(index));
                    Ok(status)
                }
            },
            sender,
            &task_cancel,
            Duration::from_millis(1),
            heartbeat_interval,
        )
        .await
    });
    let initial = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("initial event")?;
    let changed = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("meaningful event")?;
    let heartbeat = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("heartbeat event")?;
    cancel.cancel();
    task.await??;
    assert!(initial.is_state_change() && changed.is_state_change() && heartbeat.is_heartbeat());
    let timestamps = timestamps.lock().map_err(|_| "fixture lock")?;
    let changed_index =
        usize::try_from(60 - changed.status.unlock_ttl_seconds.ok_or("change ttl")?)?;
    let heartbeat_index =
        usize::try_from(60 - heartbeat.status.unlock_ttl_seconds.ok_or("heartbeat ttl")?)?;
    assert!(
        timestamps[heartbeat_index].duration_since(timestamps[changed_index]) >= heartbeat_interval
    );
    Ok(())
}
