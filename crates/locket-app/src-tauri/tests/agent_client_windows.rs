//! Windows desktop client checks against a separate current-user pipe and
//! synthetic in-memory agent state. No vault, keychain, or default pipe is used.
// These crates are consumed by this integration target on its supported platform.
use arboard as _;
use base64 as _;
use directories as _;
use locket_agent as _;
use locket_app as _;
use locket_core as _;
use locket_desktop_lib as _;
use locket_platform as _;
use locket_store as _;
use serde as _;
use serde_json as _;
use sha2 as _;
use tauri as _;
use tempfile as _;
use thiserror as _;
use tokio as _;
use toml as _;
use zeroize as _;

#[cfg(target_os = "windows")]
mod windows {
    use locket_agent::{
        AgentMethod, AgentPipeConfig, AgentSocketState, LockState, StatusEvent, StatusPayload,
        UnlockEntry, UnlockMethod, bind_named_pipe_instance, bind_named_pipe_listener,
        handle_named_pipe_connection,
    };
    use locket_desktop_lib::{
        AgentClientError, CancelToken, fetch_status, invoke_method,
        stream_status_events_with_cancel,
    };
    use std::{
        error::Error,
        io,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tokio::sync::mpsc;

    const VERSION: &str = "desktop-pipe-test";

    #[tokio::test]
    async fn unary_status_uses_secured_pipe_without_filesystem_existence_check()
    -> Result<(), Box<dyn Error>> {
        let state = AgentSocketState::locked(VERSION);
        let server = TestPipeServer::start(state.clone())?;
        // The fixture supplies only a pipe endpoint, never a socket file.
        let locked = fetch_status(&server.path).await?;
        assert_eq!(locked.agent_version, VERSION);
        assert_eq!(locked.lock_state, LockState::Locked);
        insert_synthetic_unlock(&state).await?;
        let scoped: StatusPayload = invoke_method(
            &server.path,
            AgentMethod::Status,
            &serde_json::json!({"project_id":"synthetic-project"}),
        )
        .await?;
        assert_eq!(scoped.project_id.as_deref(), Some("synthetic-project"));
        assert_eq!(scoped.lock_state, LockState::Unlocked);
        assert!(scoped.unlock_ttl_seconds.is_some_and(|ttl| ttl > 0 && ttl <= 60));
        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn windows_status_fallback_polls_unary_rpc_and_observes_state_changes()
    -> Result<(), Box<dyn Error>> {
        let state = AgentSocketState::locked(VERSION);
        let server = TestPipeServer::start(state.clone())?;
        let path = server.path.clone();
        let (sender, mut receiver) = mpsc::channel::<StatusEvent>(4);
        let cancel = CancelToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            stream_status_events_with_cancel(&path, sender, &task_cancel).await
        });
        let first = next_event(&mut receiver).await?;
        assert_eq!(first.status.lock_state, LockState::Locked);
        assert!(first.is_state_change());
        insert_synthetic_unlock(&state).await?;
        let unlocked = next_event(&mut receiver).await?;
        assert!(unlocked.is_state_change());
        assert_eq!(unlocked.status.lock_state, LockState::Unlocked);
        assert!(unlocked.status.unlock_ttl_seconds.is_some_and(|ttl| ttl > 0));
        assert!(first.sequence < unlocked.sequence);
        // A countdown-only poll must not trigger another desktop refresh. This
        // spans a full one-second poll, without waiting for the 30-second heartbeat.
        assert!(tokio::time::timeout(Duration::from_millis(1500), receiver.recv()).await.is_err());
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), task).await???;
        server.stop().await?;
        Ok(())
    }

    #[tokio::test]
    async fn missing_test_pipe_reports_unavailable() {
        let result = fetch_status(&unique_pipe_path()).await;
        assert!(matches!(result, Err(AgentClientError::Unavailable { .. })));
    }

    async fn next_event(
        receiver: &mut mpsc::Receiver<StatusEvent>,
    ) -> Result<StatusEvent, Box<dyn Error>> {
        tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await?
            .ok_or_else(|| "status polling ended before its next event".into())
    }

    async fn insert_synthetic_unlock(state: &AgentSocketState) -> Result<(), Box<dyn Error>> {
        let now = i128::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
        state.unlock_cache.lock().await.insert(
            "synthetic-project".into(),
            UnlockEntry::new(
                vec![0x31; 32],
                now,
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        Ok(())
    }

    fn unique_pipe_path() -> PathBuf {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        PathBuf::from(format!(
            r"\\.\pipe\locket-desktop-test-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    struct TestPipeServer {
        path: PathBuf,
        cancel: CancelToken,
        task: Option<tokio::task::JoinHandle<io::Result<()>>>,
    }

    impl TestPipeServer {
        fn start(state: AgentSocketState) -> Result<Self, Box<dyn Error>> {
            let path = unique_pipe_path();
            let config = AgentPipeConfig::current_user(path.clone())?;
            let mut listener = bind_named_pipe_listener(&config)?;
            let cancel = CancelToken::new();
            let task_cancel = cancel.clone();
            let task = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        biased;
                        () = task_cancel.cancelled() => break,
                        connected = listener.connect() => {
                            connected?;
                            let next = bind_named_pipe_instance(&config)?;
                            let connected = std::mem::replace(&mut listener, next);
                            connections.spawn(handle_named_pipe_connection(connected, state.clone()));
                        }
                        _ = connections.join_next(), if !connections.is_empty() => {}
                    }
                }
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                Ok(())
            });
            Ok(Self { path, cancel, task: Some(task) })
        }

        async fn stop(mut self) -> Result<(), Box<dyn Error>> {
            self.cancel.cancel();
            if let Some(task) = self.task.take() {
                task.await??;
            }
            Ok(())
        }
    }

    impl Drop for TestPipeServer {
        fn drop(&mut self) {
            self.cancel.cancel();
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }
}
