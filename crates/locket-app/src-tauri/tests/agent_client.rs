//! End-to-end tests for the desktop agent client.
//!
//! Spins up the locket-agent socket server in-process and drives the
//! desktop client against it. Covers the daemon-offline failure path,
//! a successful round-trip, and reconnection after the daemon drops.
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

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

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use locket_agent::{
        AgentMethod, AgentSocketConfig, AgentSocketState, DEFAULT_MAX_MESSAGE_SIZE,
        ListRuntimeSessionsRequest, LockState, ResponseEnvelope, StatusEvent, StatusPayload,
        SuccessEnvelope, bind_socket_listener, decode_request_frame, encode_frame,
        handle_connection,
    };
    use locket_desktop_lib::{
        AgentClientError, CancelToken, RECONNECT_INITIAL_BACKOFF, RECONNECT_MAX_BACKOFF,
        fetch_status, invoke_method, next_reconnect_delay, resolve_socket_path,
        stream_status_events, stream_status_events_with_cancel,
    };
    use locket_store::{AuditWrite, Store};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::sync::Notify;

    const AGENT_VERSION: &str = "0.0.0-test";

    #[tokio::test]
    async fn fetch_status_returns_unavailable_when_socket_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("never-bound.sock");

        let result = fetch_status(&socket_path).await;
        let err = result.expect_err("missing socket must fail");
        match err {
            AgentClientError::Unavailable {
                reason,
                display_reason,
                next_action,
                socket_path: returned,
            } => {
                assert!(reason.contains("not found"), "reason was {reason}");
                assert_eq!(display_reason, "The local agent is unavailable.");
                assert_eq!(next_action, "Run locket agent start, then retry.");
                assert_eq!(returned, socket_path.display().to_string());
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_status_round_trips_against_a_live_agent() {
        let dir = tempdir_user_only();
        let socket_path = dir.path().join("agent.sock");

        let server = TestServer::start_at(&socket_path).await;
        let payload = fetch_status(&server.socket_path).await.expect("status round-trip");
        assert_eq!(payload.agent_version, AGENT_VERSION);
        server.stop().await;
    }

    #[tokio::test]
    async fn fetch_status_recovers_after_daemon_restart() {
        let dir = tempdir_user_only();
        let socket_path = dir.path().join("agent.sock");

        let first = TestServer::start_at(&socket_path).await;
        let payload = fetch_status(&first.socket_path).await.expect("first round-trip");
        assert_eq!(payload.agent_version, AGENT_VERSION);
        first.stop().await;

        // After the daemon stops the path may linger or vanish depending on
        // OS cleanup; both states must surface as Unavailable, not as a
        // protocol error.
        let result = fetch_status(&socket_path).await;
        match result {
            Err(AgentClientError::Unavailable { .. }) => {}
            other => panic!("expected Unavailable after stop, got {other:?}"),
        }

        let second = TestServer::start_at(&socket_path).await;
        let payload = fetch_status(&second.socket_path).await.expect("second round-trip");
        assert_eq!(payload.agent_version, AGENT_VERSION);
        second.stop().await;
    }

    #[tokio::test]
    async fn list_runtime_sessions_round_trips_against_a_live_agent() {
        let dir = tempdir_user_only();
        let socket_path = dir.path().join("agent.sock");

        let server = TestServer::start_at(&socket_path).await;
        let request = ListRuntimeSessionsRequest {
            project_id: "project-main".to_owned(),
            profile_id: "profile-prod".to_owned(),
            privacy_redact_names: true,
        };
        let response: locket_agent::ListRuntimeSessionsResponse =
            invoke_method(&server.socket_path, AgentMethod::ListRuntimeSessions, &request)
                .await
                .expect("runtime sessions round-trip");
        assert!(response.rows.is_empty());
        server.stop().await;
    }

    #[tokio::test]
    async fn stream_status_events_decodes_subscribe_status_frames() {
        let dir = tempdir_user_only();
        let socket_path = dir.path().join("status-stream.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind stream listener");

        let server = tokio::spawn(async move {
            let (mut stream, _addr) = listener.accept().await.expect("accept status client");
            let mut buffer = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let read = stream.read(&mut chunk).await.expect("read subscribe request");
                assert_ne!(read, 0, "client closed before SubscribeStatus");
                buffer.extend_from_slice(&chunk[..read]);
                if let Ok((request, _consumed)) =
                    decode_request_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE)
                {
                    assert_eq!(request.method().ok(), Some(AgentMethod::SubscribeStatus));
                    break;
                }
            }

            let locked = StatusEvent::status(1, StatusPayload::locked(AGENT_VERSION));
            write_status_event(&mut stream, &locked).await;
            let mut unlocked = StatusPayload::locked(AGENT_VERSION);
            unlocked.lock_state = LockState::Unlocked;
            write_status_event(&mut stream, &StatusEvent::status(2, unlocked)).await;
        });

        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let client_path = socket_path.clone();
        let client = tokio::spawn(async move { stream_status_events(&client_path, sender).await });

        let first = receiver.recv().await.expect("initial status event");
        assert!(first.is_state_change());
        assert_eq!(first.sequence, 1);
        assert_eq!(first.status.lock_state, LockState::Locked);

        let second = receiver.recv().await.expect("updated status event");
        assert!(second.is_state_change());
        assert_eq!(second.sequence, 2);
        assert_eq!(second.status.lock_state, LockState::Unlocked);

        let result = client.await.expect("client task");
        assert!(matches!(result, Err(AgentClientError::Protocol { .. })));
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn config_settings_round_trip_and_locked_write_rejection() {
        let dir = tempdir_user_only();
        let socket_path = dir.path().join("agent.sock");
        let config_path = dir.path().join("config.toml");
        let store_path = dir.path().join("store.db");

        let server = TestServer::start_at(&socket_path).await;
        let read_request = locket_agent::ReadConfigRequest {
            config_path: config_path.clone(),
            store_path: None,
            project_id: None,
            profile_name: None,
        };
        let response: locket_agent::AgentConfigSettings =
            invoke_method(&server.socket_path, AgentMethod::ReadConfig, &read_request)
                .await
                .expect("read config round-trip");
        assert!(!response.privacy_redact_names);
        assert_eq!(response.agent_unlock_ttl, None);

        let write_request = locket_agent::WriteConfigRequest {
            config_path,
            store_path,
            project_id: "project-main".to_owned(),
            profile_name: None,
            changes: locket_agent::WriteConfigChanges {
                privacy_redact_names: Some(true),
                ..locket_agent::WriteConfigChanges::default()
            },
        };
        let result: Result<locket_agent::WriteConfigResponse, AgentClientError> =
            invoke_method(&server.socket_path, AgentMethod::WriteConfig, &write_request).await;
        let err = result.expect_err("locked config writes require unlock");
        match err {
            AgentClientError::Rejected { code, .. } => assert_eq!(code, "UnlockRequired"),
            other => panic!("expected UnlockRequired rejection, got {other:?}"),
        }
        server.stop().await;
    }

    #[tokio::test]
    async fn list_audit_round_trips_against_a_live_agent_while_locked()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir_user_only();
        let store_path = dir.path().join("store.db");
        let mut store = Store::open(&store_path)?;
        store.initialize_schema()?;
        store.connection().execute(
            "INSERT INTO projects(id, name, created_at) VALUES ('project-main', 'main', 1)",
            [],
        )?;
        store.connection().execute(
            "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('profile-prod', 'project-main', 'prod', 0, 1)",
            [],
        )?;
        store.append_audit(
            &[9; 32],
            &AuditWrite {
                project_id: "project-main",
                profile_id: Some("profile-prod"),
                action: "COPY",
                status: "SUCCESS",
                secret_name: Some("DATABASE_URL"),
                command: Some("deploy"),
                metadata_json: &json!({
                    "schema_version": 1,
                    "action": "COPY",
                    "status": "SUCCESS",
                    "profile_id": "profile-prod",
                    "secret_name": "DATABASE_URL",
                    "source": "user-local",
                    "access_mode": "clipboard",
                    "command": "deploy"
                }),
                timestamp: 100,
            },
        )?;

        let socket_path = dir.path().join("agent.sock");
        let server = TestServer::start_at(&socket_path).await;
        let request = locket_agent::ListAuditRequest {
            store_path,
            project_id: "project-main".to_owned(),
            profile_id: None,
            action: None,
            status: None,
            since_unix_nanos: None,
            until_unix_nanos: None,
            limit: Some(5),
            redact_names: true,
        };
        let response: locket_agent::ListAuditResponse =
            invoke_method(&server.socket_path, AgentMethod::ListAudit, &request).await?;

        assert_eq!(response.rows.len(), 1);
        assert_eq!(response.rows[0].action, "COPY");
        assert_ne!(response.rows[0].profile_id.as_deref(), Some("profile-prod"));
        assert_ne!(response.rows[0].secret_name.as_deref(), Some("DATABASE_URL"));
        assert!(response.chain_status.locked);
        assert_eq!(response.chain_status.hmac_ok, None);
        server.stop().await;
        Ok(())
    }

    #[test]
    fn resolve_socket_path_returns_a_value() {
        // Sanity check: the helper must produce a path even when no env
        // override is set. The integration tests above exercise the live
        // socket directly without depending on this helper.
        let path = resolve_socket_path();
        assert!(!path.as_os_str().is_empty());
    }

    #[tokio::test]
    async fn reconnect_schedule_is_exponential_capped_at_thirty_seconds() {
        // Pins the desktop-spec backoff: 1s → 2s → 4s → 8s → 16s → 30s …
        let mut current: Option<Duration> = None;
        let mut observed = Vec::new();
        for _ in 0..8 {
            let next = next_reconnect_delay(current);
            observed.push(next);
            current = Some(next);
        }
        assert_eq!(observed[0], RECONNECT_INITIAL_BACKOFF);
        assert_eq!(observed[0], Duration::from_secs(1));
        assert_eq!(observed[1], Duration::from_secs(2));
        assert_eq!(observed[2], Duration::from_secs(4));
        assert_eq!(observed[3], Duration::from_secs(8));
        assert_eq!(observed[4], Duration::from_secs(16));
        for value in &observed[5..] {
            assert_eq!(*value, RECONNECT_MAX_BACKOFF);
        }
    }

    #[tokio::test]
    async fn stream_status_events_reports_close_then_reconnects_against_fresh_listener() {
        // Mock-agent path: bind a Unix listener, write two status frames,
        // close the socket, and assert the client surfaced both frames and
        // returned a Protocol error for the close. Then bind a second
        // listener at the same path and assert the client re-subscribes
        // and observes another status frame — which is the loop's
        // contract on close.
        let dir = tempdir_user_only();
        let socket_path = dir.path().join("reconnect.sock");

        // First listener: send two frames then drop the connection.
        let first_listener = UnixListener::bind(&socket_path).expect("bind first listener");
        let first_server = tokio::spawn(async move {
            let (mut stream, _addr) = first_listener.accept().await.expect("accept first client");
            wait_for_subscribe(&mut stream).await;
            let locked = StatusEvent::status(1, StatusPayload::locked(AGENT_VERSION));
            write_status_event(&mut stream, &locked).await;
            let mut unlocked = StatusPayload::locked(AGENT_VERSION);
            unlocked.lock_state = LockState::Unlocked;
            write_status_event(&mut stream, &StatusEvent::status(2, unlocked)).await;
            // Close: drops `stream` which triggers EOF on the client side.
        });

        let cancel = CancelToken::new();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        let first_client = {
            let cancel = cancel.clone();
            let path = socket_path.clone();
            tokio::spawn(
                async move { stream_status_events_with_cancel(&path, sender, &cancel).await },
            )
        };

        let first = receiver.recv().await.expect("first status");
        assert_eq!(first.sequence, 1);
        assert_eq!(first.status.lock_state, LockState::Locked);
        let second = receiver.recv().await.expect("second status");
        assert_eq!(second.sequence, 2);
        assert_eq!(second.status.lock_state, LockState::Unlocked);

        let first_result = first_client.await.expect("first client task");
        assert!(
            matches!(first_result, Err(AgentClientError::Protocol { .. })),
            "expected close to surface as Protocol error, got {first_result:?}",
        );
        first_server.await.expect("first server task");

        // Replicate what the desktop reconnect loop does: drop the closed
        // socket file, rebind a fresh listener, retry the subscribe call.
        let _ = std::fs::remove_file(&socket_path);
        let second_listener = UnixListener::bind(&socket_path).expect("bind second listener");
        let second_server = tokio::spawn(async move {
            let (mut stream, _addr) = second_listener.accept().await.expect("accept second client");
            wait_for_subscribe(&mut stream).await;
            let event = StatusEvent::status(7, StatusPayload::locked(AGENT_VERSION));
            write_status_event(&mut stream, &event).await;
        });

        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        let second_client = {
            let cancel = cancel.clone();
            let path = socket_path.clone();
            tokio::spawn(
                async move { stream_status_events_with_cancel(&path, sender, &cancel).await },
            )
        };

        let frame = receiver.recv().await.expect("post-reconnect status");
        assert_eq!(frame.sequence, 7);
        assert_eq!(frame.status.lock_state, LockState::Locked);

        let second_result = second_client.await.expect("second client task");
        assert!(
            matches!(second_result, Err(AgentClientError::Protocol { .. })),
            "expected second close to surface as Protocol error, got {second_result:?}",
        );
        second_server.await.expect("second server task");
    }

    #[tokio::test]
    async fn cancel_token_aborts_status_stream_without_protocol_error() {
        // The Tauri shell flips the cancel token on app shutdown so the
        // long-lived reader exits cleanly — the cancellation path must
        // resolve to `Ok(())`, not surface a "stream closed" error.
        let dir = tempdir_user_only();
        let socket_path = dir.path().join("cancel.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind listener");
        let server = tokio::spawn(async move {
            let (mut stream, _addr) = listener.accept().await.expect("accept");
            wait_for_subscribe(&mut stream).await;
            let event = StatusEvent::status(1, StatusPayload::locked(AGENT_VERSION));
            write_status_event(&mut stream, &event).await;
            // Hold the connection open until the client drops it via cancel.
            let mut sink = [0_u8; 256];
            let _ = stream.read(&mut sink).await;
        });

        let cancel = CancelToken::new();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let client = {
            let cancel = cancel.clone();
            let path = socket_path.clone();
            tokio::spawn(
                async move { stream_status_events_with_cancel(&path, sender, &cancel).await },
            )
        };

        let event = receiver.recv().await.expect("first status");
        assert_eq!(event.sequence, 1);

        cancel.cancel();
        drop(receiver);

        let result = tokio::time::timeout(Duration::from_secs(2), client)
            .await
            .expect("client joins promptly");
        let outcome = result.expect("client task");
        assert!(matches!(outcome, Ok(())), "cancel must yield Ok(()), got {outcome:?}");
        server.await.expect("server task");
    }

    async fn wait_for_subscribe(stream: &mut tokio::net::UnixStream) {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.expect("read subscribe request");
            assert_ne!(read, 0, "client closed before SubscribeStatus");
            buffer.extend_from_slice(&chunk[..read]);
            if let Ok((request, _consumed)) =
                decode_request_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE)
            {
                assert_eq!(request.method().ok(), Some(AgentMethod::SubscribeStatus));
                break;
            }
        }
    }

    async fn write_status_event(stream: &mut tokio::net::UnixStream, event: &StatusEvent) {
        let payload = serde_json::to_value(event).expect("status event JSON");
        let response = ResponseEnvelope::Success(SuccessEnvelope::new("desktop-test", payload));
        let frame = encode_frame(&response, DEFAULT_MAX_MESSAGE_SIZE).expect("status frame");
        stream.write_all(&frame).await.expect("write status frame");
        stream.flush().await.expect("flush status frame");
    }

    struct TestServer {
        socket_path: PathBuf,
        shutdown: Arc<Notify>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl TestServer {
        async fn start_at(path: &Path) -> Self {
            let config = AgentSocketConfig::new(path.to_path_buf(), AGENT_VERSION.to_owned());
            let listener = bind_socket_listener(&config).expect("bind listener");
            let state = AgentSocketState::locked(AGENT_VERSION);
            let shutdown = Arc::new(Notify::new());

            let socket_path = path.to_path_buf();
            let shutdown_signal = shutdown.clone();
            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        () = shutdown_signal.notified() => return,
                        accept = listener.accept() => {
                            let Ok((stream, _addr)) = accept else { return };
                            let connection_state = state.clone();
                            tokio::spawn(async move {
                                let _outcome = handle_connection(stream, connection_state).await;
                            });
                        }
                    }
                }
            });

            // Give the spawn a moment to enter accept().
            tokio::time::sleep(Duration::from_millis(20)).await;
            Self { socket_path, shutdown, handle }
        }

        async fn stop(self) {
            self.shutdown.notify_waiters();
            let _ = self.handle.await;
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }

    /// Returns a tempdir with mode 0o700 so `bind_socket_listener` accepts it.
    fn tempdir_user_only() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir.path(), perms).expect("chmod tempdir");
        dir
    }
}
