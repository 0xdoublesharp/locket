//! Focused regression test for the agent process supervisor.
//!
//! `agent_start_command` execs `current_exe()` to spawn the daemon. In
//! `cargo test` the test harness binary is `current_exe()`, so a true
//! end-to-end test of the parent-spawns-child dance is not possible
//! from inside the test crate. Instead, we exercise the daemon entry
//! point (`run_internal_agent_serve`) directly: bind a socket on a
//! background thread, drive a `Status` request through the same Unix
//! socket the CLI would use, then signal the thread to exit via
//! SIGTERM and verify that the socket and pid file are cleaned up.

#[allow(unused_imports)]
use super::*;

#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
fn serve_status_requests(
    socket_path: PathBuf,
    count: usize,
) -> std::thread::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>> {
    std::thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use locket_agent::{
            AgentSocketConfig, AgentSocketState, bind_socket_listener, handle_connection,
        };

        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        runtime.block_on(async move {
            let listener =
                bind_socket_listener(&AgentSocketConfig::new(socket_path, "test-version"))?;
            let state = AgentSocketState::locked("test-version");
            for _ in 0..count {
                let (stream, _) = listener.accept().await?;
                let _outcome = handle_connection(stream, state.clone()).await;
            }
            Ok(())
        })
    })
}

#[cfg(unix)]
fn read_status_snapshot(
    socket_path: &Path,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    use locket_agent::{
        AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, RequestEnvelope, ResponseEnvelope,
        decode_response_frame, encode_frame,
    };
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)?;
    let request = RequestEnvelope::new("status-test", AgentMethod::Status, serde_json::Value::Null);
    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
    stream.write_all(&frame)?;
    stream.flush()?;

    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        if let Ok((response, _)) = decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
            return match response {
                ResponseEnvelope::Success(success) => Ok(success.payload),
                ResponseEnvelope::Error(error) => {
                    Err(format!("agent returned error: {} ({})", error.error, error.message).into())
                }
            };
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err("agent closed connection without a response".into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(unix)]
#[test]
fn agent_start_preserves_live_socket_without_pid_file()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir_in("/tmp")?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let context = test_context(&directory);
    let socket_path = crate::agent_socket_path(&context);
    let pid_path = crate::agent_pid_path(&context);

    let serve_thread = serve_status_requests(socket_path.clone(), 2);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if socket_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(socket_path.exists(), "test agent did not bind socket within deadline");
    assert!(!pid_path.exists(), "test setup should not create a pid file");

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "agent", "start"])?, &context, &mut output)?;
    let output = String::from_utf8(output)?;

    assert!(output.contains("agent: already running"), "{output}");
    assert!(output.contains("running: yes"), "{output}");
    assert!(output.contains("pid: -"), "{output}");
    assert!(!pid_path.exists(), "agent start should not write a pid file for the socket owner");
    assert!(socket_path.exists(), "agent start should preserve the live socket");

    let snapshot = read_status_snapshot(&socket_path)?;
    assert_eq!(snapshot.get("lock_state").and_then(|value| value.as_str()), Some("locked"));
    assert_eq!(
        snapshot.get("agent_version").and_then(|value| value.as_str()),
        Some("test-version")
    );
    serve_thread.join().map_err(|_| "serve thread panicked")??;
    Ok(())
}

#[cfg(unix)]
#[test]
fn run_internal_agent_serve_listens_and_cleans_up_on_sigterm()
-> Result<(), Box<dyn std::error::Error>> {
    use locket_agent::{
        AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, RequestEnvelope, ResponseEnvelope,
        decode_response_frame, encode_frame,
    };
    use std::os::unix::net::UnixStream;

    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir()?;
    // Use a short directory name to keep the AF_UNIX path under sun_path
    // limits on macOS (~104 bytes).
    let agent_dir = directory.path().join("a");
    fs::create_dir_all(&agent_dir)?;
    // bind_socket_listener refuses parent dirs with mode beyond 0o700,
    // so tighten the permissions before the daemon thread starts.
    fs::set_permissions(&agent_dir, fs::Permissions::from_mode(0o700))?;
    let socket_path = agent_dir.join("agent.sock");
    let pid_path = agent_dir.join("agent.pid");

    let serve_socket = socket_path.clone();
    let serve_pid = pid_path.clone();
    let serve_thread = std::thread::spawn(move || -> Result<(), crate::CliError> {
        let args = crate::InternalAgentServeArgs {
            socket: serve_socket,
            pid_file: serve_pid,
            require_session_monitoring: false,
        };
        crate::commands::agent::run_internal_agent_serve(&args)
    });

    // Wait for the daemon to bind its socket (up to ~3s).
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if socket_path.exists() && pid_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(socket_path.exists(), "agent did not bind socket within deadline");
    assert!(pid_path.exists(), "agent did not write pid file within deadline");

    // The pid file should record this process's pid (the daemon shares
    // the test process when invoked directly).
    let pid_text = fs::read_to_string(&pid_path)?;
    let recorded_pid: u32 = pid_text.trim().parse()?;
    assert_eq!(recorded_pid, std::process::id(), "pid file should record current process");

    // Drive a Status request through the socket using a blocking client
    // so we don't have to spin up another tokio runtime in the test.
    let mut stream = UnixStream::connect(&socket_path)?;
    let request = RequestEnvelope::new("status-test", AgentMethod::Status, serde_json::Value::Null);
    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
    stream.write_all(&frame)?;
    stream.flush()?;

    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        if let Ok((response, _)) = decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
            match response {
                ResponseEnvelope::Success(success) => {
                    let snapshot = success.payload;
                    let lock_state =
                        snapshot.get("lock_state").and_then(|v| v.as_str()).unwrap_or("");
                    assert_eq!(lock_state, "locked", "expected locked state, got {snapshot}");
                    assert!(snapshot.get("agent_version").is_some(), "missing agent_version");
                    break;
                }
                ResponseEnvelope::Error(error) => {
                    return Err(format!(
                        "agent returned error: {} ({})",
                        error.error, error.message
                    )
                    .into());
                }
            }
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err("agent closed connection without a response".into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    drop(stream);

    // Send SIGTERM to ourselves; the daemon's signal handler will pick
    // it up because the test process is the daemon process.
    let our_pid =
        rustix::process::Pid::from_raw(i32::try_from(std::process::id())?).ok_or("invalid pid")?;
    rustix::process::kill_process(our_pid, rustix::process::Signal::TERM)?;

    // Wait for the serve thread to drain.
    let join_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < join_deadline {
        if serve_thread.is_finished() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(serve_thread.is_finished(), "serve thread did not exit after SIGTERM");
    serve_thread.join().map_err(|_| "serve thread panicked")??;

    assert!(!socket_path.exists(), "socket should be removed on shutdown");
    assert!(!pid_path.exists(), "pid file should be removed on shutdown");
    Ok(())
}
