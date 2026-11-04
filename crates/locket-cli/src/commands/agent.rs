//! Agent command implementation (start/status/stop/logs).

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration as StdDuration, Instant};

use clap::ValueEnum;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::commands::team::{device, members};
use crate::runtime::error::typed_cli_error;
use crate::support::handoff::{heredoc_command, shell_words_command};
use crate::{
    AGENT_LOG_FOLLOW_SLEEP_MS, AgentCommand, AgentInviteCommand, AgentInviteCreateArgs,
    AgentInviteRequestArgs, AgentLogsArgs, CliError, InternalAgentServeArgs, NANOS_PER_SECOND,
    RuntimeContext, TeamAcceptArgs, TeamCommand, TeamInviteArgs, agent_data_dir, agent_log_path,
    agent_log_paths_oldest_first, agent_pid_path, agent_socket_path, append_agent_log,
    metadata_invalid_error, now_unix_nanos, prepare_agent_log_dir, read_agent_pid, require_project,
    resolve_project, sanitize_agent_log_line, set_user_only_file_permissions,
    unix_nanos_to_rfc3339, write_agent_paths,
};

pub fn agent_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: AgentCommand,
) -> Result<(), CliError> {
    match command {
        AgentCommand::Start(args) => agent_start_command(context, output, &args),
        AgentCommand::Status => agent_status_command(context, output),
        AgentCommand::Stop => agent_stop_command(context, output),
        AgentCommand::Logs(args) => agent_logs_command(context, output, &args),
        AgentCommand::Invite { command } => agent_invite_command(context, output, command),
    }
}

/// Maximum time `agent start` waits for the spawned daemon to bind its socket.
const AGENT_START_SOCKET_WAIT: StdDuration = StdDuration::from_secs(2);
/// Polling interval while `agent start` waits for the spawned daemon's socket.
const AGENT_START_POLL_INTERVAL: StdDuration = StdDuration::from_millis(25);
/// Maximum time `agent stop` waits for the daemon to exit after SIGTERM.
const AGENT_STOP_WAIT: StdDuration = StdDuration::from_secs(5);
/// Polling interval while `agent stop` waits for the daemon to exit.
const AGENT_STOP_POLL_INTERVAL: StdDuration = StdDuration::from_millis(50);
const AGENT_INVITE_HEREDOC: &str = "LOCKET_INVITE";

fn agent_invite_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: AgentInviteCommand,
) -> Result<(), CliError> {
    match command {
        AgentInviteCommand::Request(args) => agent_invite_request_command(context, output, &args),
        AgentInviteCommand::Create(args) => agent_invite_create_command(context, output, &args),
        AgentInviteCommand::Accept(args) => agent_invite_accept_command(context, output, &args),
    }
}

fn agent_invite_request_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &AgentInviteRequestArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let request_device = resolve_agent_invite_request_device(context, args.device.as_deref())?;
    let label = args.label.as_deref().unwrap_or(request_device.label.as_str()).trim();
    let label = if label.is_empty() { "agent" } else { label };
    let profiles = if args.profiles.is_empty() {
        vec![resolved.config.default_profile.to_string()]
    } else {
        args.profiles.clone()
    };
    let command =
        build_agent_invite_create_command(label, &request_device.descriptor, &profiles, args);

    writeln!(output, "agent_invite_request: ready")?;
    writeln!(output, "recipient_label: {label}")?;
    writeln!(output, "device_id: {}", request_device.device_id)?;
    writeln!(output, "fingerprint: {}", request_device.fingerprint)?;
    writeln!(output, "safety_words: {}", request_device.safety_words.join(" "))?;
    writeln!(output, "descriptor: {}", request_device.descriptor)?;
    writeln!(output, "paste_for_inviter:")?;
    writeln!(output, "{command}")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

struct AgentInviteRequestDevice {
    device_id: String,
    label: String,
    fingerprint: String,
    safety_words: Vec<String>,
    descriptor: String,
}

fn resolve_agent_invite_request_device(
    context: &RuntimeContext,
    descriptor: Option<&str>,
) -> Result<AgentInviteRequestDevice, CliError> {
    if let Some(descriptor) = descriptor {
        let verified = device::decode_verified_device_descriptor(descriptor, "device descriptor")?;
        return Ok(AgentInviteRequestDevice {
            device_id: verified.descriptor.device_id,
            label: verified.descriptor.label,
            fingerprint: verified.fingerprint,
            safety_words: verified.descriptor.safety_words,
            descriptor: descriptor.trim().to_owned(),
        });
    }

    let (device, descriptor, _) = device::active_local_device_descriptor(context)?;
    Ok(AgentInviteRequestDevice {
        device_id: device.id,
        label: device.name,
        fingerprint: device.fingerprint,
        safety_words: device.safety_words,
        descriptor,
    })
}

fn agent_invite_create_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &AgentInviteCreateArgs,
) -> Result<(), CliError> {
    let output_path = match args.output.clone() {
        Some(path) => path,
        None => default_agent_invite_output_path(context)?,
    };
    let team_args = TeamInviteArgs {
        name: args.name.clone(),
        device: args.device.clone(),
        profiles: args.profiles.clone(),
        role: args.role,
        expires_in: args.expires_in.clone(),
        output: Some(output_path.clone()),
    };

    members::team_command(context, output, TeamCommand::Invite(team_args))?;
    let invite_text = fs::read_to_string(&output_path)?;
    write_agent_invite_accept_handoff(output, invite_text.trim())?;
    Ok(())
}

fn agent_invite_accept_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamAcceptArgs,
) -> Result<(), CliError> {
    members::team_command(context, output, TeamCommand::Accept(args.clone()))
}

fn default_agent_invite_output_path(
    context: &RuntimeContext,
) -> Result<std::path::PathBuf, CliError> {
    let timestamp = now_unix_nanos()?;
    let rendered = unix_nanos_to_rfc3339(timestamp)
        .map_or_else(|| timestamp.to_string(), |value| value.replace(':', "-"));
    Ok(context.cwd.join(format!("locket-agent-invite-{rendered}.locket-invite")))
}

fn write_agent_invite_accept_handoff(
    output: &mut impl Write,
    invite_text: &str,
) -> Result<(), CliError> {
    writeln!(output, "agent_invite_handoff: paste_to_recipient")?;
    writeln!(output, "paste_for_recipient:")?;
    writeln!(
        output,
        "{}",
        heredoc_command("locket agent invite accept -", invite_text, AGENT_INVITE_HEREDOC,)
    )?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn build_agent_invite_create_command(
    label: &str,
    descriptor: &str,
    profiles: &[String],
    args: &AgentInviteRequestArgs,
) -> String {
    let mut parts = vec![
        "locket".to_owned(),
        "agent".to_owned(),
        "invite".to_owned(),
        "create".to_owned(),
        label.to_owned(),
        "--device".to_owned(),
        descriptor.to_owned(),
    ];
    for profile in profiles {
        parts.push("--profile".to_owned());
        parts.push(profile.clone());
    }
    parts.push("--role".to_owned());
    parts.push(
        args.role
            .to_possible_value()
            .map_or_else(|| "developer".to_owned(), |value| value.get_name().to_owned()),
    );
    if let Some(expires_in) = args.expires_in.as_deref() {
        parts.push("--expires-in".to_owned());
        parts.push(expires_in.to_owned());
    }
    shell_words_command(parts)
}

fn agent_start_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &crate::AgentStartArgs,
) -> Result<(), CliError> {
    let launcher =
        ProcessAgentDaemonLauncher { require_session_monitoring: args.require_session_monitoring };
    let report = ensure_agent_running_with_launcher(context, &launcher)?;
    if args.require_session_monitoring {
        require_active_session_monitoring(&report)?;
    }
    if report.started {
        append_agent_log(context, "start", "running", "daemon started")?;
        writeln!(output, "agent: running")?;
    } else {
        writeln!(output, "agent: already running")?;
    }
    writeln!(output, "running: yes")?;
    match report.pid {
        Some(pid) => writeln!(output, "pid: {pid}")?,
        None => writeln!(output, "pid: -")?,
    }
    write_agent_paths(context, output)?;
    write_session_monitoring_status(output, report.session_monitoring.as_deref())?;
    Ok(())
}

#[cfg(not(test))]
pub fn ensure_agent_running_for_execution(context: &RuntimeContext) -> Result<(), CliError> {
    let report =
        ensure_agent_running_with_launcher(context, &ProcessAgentDaemonLauncher::default())?;
    if report.started
        && !report.session_monitoring.as_deref().is_some_and(|status| status.starts_with("active:"))
    {
        write_session_monitoring_status(&mut io::stderr(), report.session_monitoring.as_deref())?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
pub fn ensure_agent_running_for_execution(_context: &RuntimeContext) -> Result<(), CliError> {
    // `cargo test` runs the libtest harness as `current_exe()`, so the
    // production spawn path cannot exec `internal-agent-serve`. The startup
    // state machine itself is covered below with an injectable launcher.
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentStartupReport {
    started: bool,
    pid: Option<u32>,
    session_monitoring: Option<String>,
}

trait AgentDaemonLauncher {
    fn spawn(&self, socket: &Path, pid_file: &Path) -> Result<(), CliError>;
    fn status_snapshot(&self, socket: &Path) -> Result<Value, io::Error>;
}

#[derive(Default)]
struct ProcessAgentDaemonLauncher {
    require_session_monitoring: bool,
}

impl AgentDaemonLauncher for ProcessAgentDaemonLauncher {
    fn spawn(&self, socket: &Path, pid_file: &Path) -> Result<(), CliError> {
        spawn_agent_daemon(socket, pid_file, self.require_session_monitoring)
    }

    fn status_snapshot(&self, socket: &Path) -> Result<Value, io::Error> {
        request_status_snapshot(socket)
    }
}

fn ensure_agent_running_with_launcher(
    context: &RuntimeContext,
    launcher: &dyn AgentDaemonLauncher,
) -> Result<AgentStartupReport, CliError> {
    fs::create_dir_all(agent_data_dir(context))?;

    let pid_path = agent_pid_path(context);
    let socket_path = agent_socket_path(context);

    // Idempotency: if a live PID owns the pid file and responds on the
    // socket, execution can proceed without spawning a second daemon.
    if let Some(pid) = read_running_pid(context)? {
        if let Ok(snapshot) = launcher.status_snapshot(&socket_path) {
            return Ok(AgentStartupReport {
                started: false,
                pid: Some(pid),
                session_monitoring: session_monitoring_from_snapshot(&snapshot),
            });
        }
        let _ignored = fs::remove_file(&pid_path);
        let _ignored = fs::remove_file(&socket_path);
    }

    // If the pid file is missing or stale but the socket owner still
    // answers trusted status requests, preserve the live daemon and
    // keep start idempotent instead of unlinking its socket.
    #[cfg(unix)]
    if socket_path.exists()
        && let Ok(snapshot) = launcher.status_snapshot(&socket_path)
    {
        return Ok(AgentStartupReport {
            started: false,
            pid: None,
            session_monitoring: session_monitoring_from_snapshot(&snapshot),
        });
    }
    #[cfg(target_os = "windows")]
    if let Ok(snapshot) = launcher.status_snapshot(&socket_path) {
        return Ok(AgentStartupReport {
            started: false,
            pid: None,
            session_monitoring: session_monitoring_from_snapshot(&snapshot),
        });
    }

    // Best-effort cleanup of stale pid/socket files. The daemon may have
    // crashed and left them behind; bind_socket_listener will refuse if
    // a live owner is still present.
    let _ignored = fs::remove_file(&pid_path);
    let _ignored = fs::remove_file(&socket_path);

    launcher.spawn(&socket_path, &pid_path)?;

    // Poll for the endpoint so the caller's first
    // `agent status`/connect attempt does not race the child.
    wait_for_agent_endpoint(
        launcher,
        &socket_path,
        AGENT_START_SOCKET_WAIT,
        AGENT_START_POLL_INTERVAL,
    );

    let pid = read_running_pid(context)?;
    let snapshot = launcher.status_snapshot(&socket_path).map_err(|error| {
        typed_cli_error(
            locket_core::LocketError::AgentUnavailable,
            format!("agent did not become reachable after on-demand startup: {error}"),
        )
    })?;
    Ok(AgentStartupReport {
        started: true,
        pid,
        session_monitoring: session_monitoring_from_snapshot(&snapshot),
    })
}

fn require_active_session_monitoring(report: &AgentStartupReport) -> Result<(), CliError> {
    if report.session_monitoring.as_deref().is_some_and(|value| value.starts_with("active:")) {
        Ok(())
    } else {
        Err(typed_cli_error(
            locket_core::LocketError::AgentUnavailable,
            "native session monitoring is required; stop the existing agent and start it with --require-session-monitoring on a supported desktop session",
        ))
    }
}

fn session_monitoring_from_snapshot(snapshot: &Value) -> Option<String> {
    snapshot.get("session_monitoring").and_then(Value::as_str).map(str::to_owned)
}

fn agent_status_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let pid_path = agent_pid_path(context);
    let socket_path = agent_socket_path(context);

    let live_pid = read_running_pid(context)?;
    let Some(pid) = live_pid else {
        let last_known = read_agent_pid(context)?;
        writeln!(output, "agent: stopped")?;
        writeln!(output, "running: no")?;
        match last_known {
            Some(pid) => writeln!(output, "last_known_pid: {pid}")?,
            None => writeln!(output, "last_known_pid: -")?,
        }
        write_agent_paths(context, output)?;
        if let Some(project) = resolve_project(&context.cwd)? {
            writeln!(output, "active_project_id: {}", project.config.project_id)?;
            writeln!(output, "active_profile: {}", project.config.default_profile)?;
        }
        return Ok(());
    };

    match request_status_snapshot(&socket_path) {
        Ok(snapshot) => {
            writeln!(output, "agent: running")?;
            writeln!(output, "running: yes")?;
            writeln!(output, "pid: {pid}")?;
            write_agent_paths(context, output)?;
            write_agent_status_snapshot(output, &snapshot)?;
            if let Some(project) = resolve_project(&context.cwd)? {
                writeln!(output, "active_project_id: {}", project.config.project_id)?;
                writeln!(output, "active_profile: {}", project.config.default_profile)?;
            }
        }
        Err(_error) => {
            // The pid file says the daemon is alive but we cannot reach
            // it on the socket. Treat as stopped + stale and clean up
            // the pid file so the next `agent start` is unblocked.
            let _ignored = fs::remove_file(&pid_path);
            writeln!(output, "agent: stopped")?;
            writeln!(output, "running: no")?;
            writeln!(output, "last_known_pid: {pid}")?;
            write_agent_paths(context, output)?;
            writeln!(output, "lock_state: unknown")?;
            writeln!(output, "live_grants: 0")?;
            if let Some(project) = resolve_project(&context.cwd)? {
                writeln!(output, "active_project_id: {}", project.config.project_id)?;
                writeln!(output, "active_profile: {}", project.config.default_profile)?;
            }
        }
    }
    Ok(())
}

#[cfg(all(any(unix, target_os = "windows"), not(test)))]
pub(super) fn request_agent_once(
    context: &RuntimeContext,
    method: locket_agent::AgentMethod,
    payload: Value,
) -> Result<Value, CliError> {
    request_agent_endpoint(&agent_socket_path(context), method, payload).map_err(|error| {
        typed_cli_error(
            locket_core::LocketError::AgentUnavailable,
            format!("agent request {} failed: {error}", method.as_str()),
        )
    })
}

#[cfg(all(not(any(unix, target_os = "windows")), not(test)))]
pub(super) fn request_agent_once(
    _context: &RuntimeContext,
    _method: (),
    _payload: Value,
) -> Result<Value, CliError> {
    Err(typed_cli_error(
        locket_core::LocketError::AgentUnavailable,
        "agent daemon is only supported on Unix targets",
    ))
}

fn agent_stop_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let pid_path = agent_pid_path(context);
    let socket_path = agent_socket_path(context);

    let last_known = read_agent_pid(context)?;
    let Some(raw_pid) = last_known else {
        append_agent_log(context, "stop", "stopped", "no daemon was running")?;
        writeln!(output, "agent: stopped")?;
        writeln!(output, "running: no")?;
        writeln!(output, "removed_stale_pid: no")?;
        write_agent_paths(context, output)?;
        return Ok(());
    };

    let Some(pid) = parse_pid(&raw_pid) else {
        let _ignored = fs::remove_file(&pid_path);
        append_agent_log(context, "stop", "stopped", "removed unparseable pid file")?;
        writeln!(output, "agent: stopped")?;
        writeln!(output, "running: no")?;
        writeln!(output, "removed_stale_pid: yes")?;
        write_agent_paths(context, output)?;
        return Ok(());
    };

    if !process_is_live(pid) {
        let _ignored = fs::remove_file(&pid_path);
        let _ignored = fs::remove_file(&socket_path);
        append_agent_log(context, "stop", "stopped", "removed stale pid file")?;
        writeln!(output, "agent: stopped")?;
        writeln!(output, "running: no")?;
        writeln!(output, "removed_stale_pid: yes")?;
        write_agent_paths(context, output)?;
        return Ok(());
    }

    request_agent_shutdown_or_signal(&socket_path, pid)?;

    let deadline = Instant::now() + AGENT_STOP_WAIT;
    while Instant::now() < deadline {
        #[cfg(target_os = "windows")]
        if !process_is_live(pid) {
            break;
        }
        if !process_is_live(pid) && !pid_path.exists() {
            break;
        }
        std::thread::sleep(AGENT_STOP_POLL_INTERVAL);
    }

    if process_is_live(pid) {
        return Err(typed_cli_error(
            locket_core::LocketError::AgentUnavailable,
            format!("agent (pid {pid}) did not exit within {} seconds", AGENT_STOP_WAIT.as_secs()),
        ));
    }

    let _ignored = fs::remove_file(&pid_path);
    let _ignored = fs::remove_file(&socket_path);
    append_agent_log(context, "stop", "stopped", "daemon stopped")?;
    writeln!(output, "agent: stopped")?;
    writeln!(output, "running: no")?;
    write_agent_paths(context, output)?;
    Ok(())
}

/// Spawns the daemon child via `current_exe internal-agent-serve`.
#[cfg(unix)]
fn spawn_agent_daemon(
    socket: &Path,
    pid_file: &Path,
    require_session_monitoring: bool,
) -> Result<(), CliError> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command as StdCommand, Stdio};

    let exe = std::env::current_exe()?;
    let mut command = StdCommand::new(&exe);
    command
        .arg("internal-agent-serve")
        .arg("--socket")
        .arg(socket)
        .arg("--pid-file")
        .arg(pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Place the child in a fresh process group so terminal signals
        // delivered to the parent (SIGINT/SIGHUP from a foreground
        // shell) are not forwarded to the daemon. This is the
        // unsafe-free counterpart of the `setsid` call recommended by
        // the agent-daemon plan; combined with the null stdio streams
        // it is sufficient to detach the daemon from a controlling
        // terminal for both interactive and CI invocations.
        .process_group(0);
    if require_session_monitoring {
        command.arg("--require-session-monitoring");
    }
    let _child = command.spawn()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn spawn_agent_daemon(
    socket: &Path,
    pid_file: &Path,
    require_session_monitoring: bool,
) -> Result<(), CliError> {
    use std::process::{Command as StdCommand, Stdio};

    let exe = std::env::current_exe()?;
    let mut command = StdCommand::new(&exe);
    command
        .arg("internal-agent-serve")
        .arg("--socket")
        .arg(socket)
        .arg("--pid-file")
        .arg(pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if require_session_monitoring {
        command.arg("--require-session-monitoring");
    }
    let _child = command.spawn()?;
    Ok(())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn spawn_agent_daemon(
    _socket: &Path,
    _pid_file: &Path,
    _require_session_monitoring: bool,
) -> Result<(), CliError> {
    Err(typed_cli_error(
        locket_core::LocketError::AgentUnavailable,
        "agent daemon is only supported on Unix targets",
    ))
}

fn wait_for_agent_endpoint(
    launcher: &dyn AgentDaemonLauncher,
    endpoint: &Path,
    timeout: StdDuration,
    interval: StdDuration,
) {
    #[cfg(not(target_os = "windows"))]
    let _ = launcher;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        #[cfg(unix)]
        if endpoint.exists() {
            return;
        }
        #[cfg(target_os = "windows")]
        if launcher.status_snapshot(endpoint).is_ok() {
            return;
        }
        std::thread::sleep(interval);
    }
}

/// Returns the live PID owning the pid file, if any. A pid file with a
/// dead PID is treated as stale and ignored (but is not deleted here —
/// the caller decides when to remove it).
fn read_running_pid(context: &RuntimeContext) -> Result<Option<u32>, CliError> {
    let Some(raw) = read_agent_pid(context)? else {
        return Ok(None);
    };
    let Some(pid) = parse_pid(&raw) else {
        return Ok(None);
    };
    Ok(if process_is_live(pid) { Some(pid) } else { None })
}

fn write_agent_status_snapshot(output: &mut impl Write, snapshot: &Value) -> Result<(), io::Error> {
    let lock_state = snapshot.get("lock_state").and_then(Value::as_str).unwrap_or("unknown");
    writeln!(output, "lock_state: {lock_state}")?;
    if let Some(ttl) = snapshot.get("unlock_ttl_seconds").and_then(Value::as_u64) {
        writeln!(output, "unlock_ttl_seconds: {ttl}")?;
    }
    let live_grants = snapshot.get("live_grant_count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(output, "live_grants: {live_grants}")?;
    let version = snapshot.get("agent_version").and_then(Value::as_str).unwrap_or("unknown");
    writeln!(output, "agent_version: {version}")?;
    write_session_monitoring_status(
        output,
        snapshot.get("session_monitoring").and_then(Value::as_str),
    )?;
    Ok(())
}

fn write_session_monitoring_status(
    output: &mut impl Write,
    status: Option<&str>,
) -> io::Result<()> {
    let status =
        status.unwrap_or("unavailable: this agent does not report native session monitoring");
    writeln!(output, "session_monitoring: {status}")?;
    if !status.starts_with("active:") {
        writeln!(
            output,
            "warning: automatic locking on sleep or screen lock is unavailable; use locket lock or short unlock TTLs"
        )?;
    }
    Ok(())
}

fn parse_pid(value: &str) -> Option<u32> {
    value.trim().parse::<u32>().ok()
}

#[cfg(unix)]
fn process_is_live(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    let Some(rust_pid) = rustix::process::Pid::from_raw(raw) else {
        return false;
    };
    rustix::process::test_kill_process(rust_pid).is_ok()
}

#[cfg(not(any(unix, target_os = "windows")))]
const fn process_is_live(_pid: u32) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn process_is_live(pid: u32) -> bool {
    locket_platform::windows_process_is_live(pid)
}

#[cfg(unix)]
fn send_sigterm(pid: u32) -> Result<(), CliError> {
    let raw = i32::try_from(pid)
        .map_err(|_| typed_cli_error(locket_core::LocketError::AgentUnavailable, "invalid pid"))?;
    let rust_pid = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
        typed_cli_error(locket_core::LocketError::AgentUnavailable, "invalid pid")
    })?;
    rustix::process::kill_process(rust_pid, rustix::process::Signal::TERM)
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn request_agent_shutdown_or_signal(socket_path: &Path, pid: u32) -> Result<(), CliError> {
    request_agent_endpoint(
        socket_path,
        locket_agent::AgentMethod::Shutdown,
        serde_json::json!({ "source": "process_exit" }),
    )
    .map(|_| ())
    .or_else(|_| terminate_windows_agent(pid))
}

#[cfg(unix)]
fn request_agent_shutdown_or_signal(_socket_path: &Path, pid: u32) -> Result<(), CliError> {
    send_sigterm(pid)
}

#[cfg(target_os = "windows")]
fn terminate_windows_agent(pid: u32) -> Result<(), CliError> {
    // Compatibility fallback for older daemons that predate the
    // in-band Shutdown RPC.
    locket_platform::terminate_windows_process(pid).map_err(CliError::from)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn send_sigterm(_pid: u32) -> Result<(), CliError> {
    Err(typed_cli_error(
        locket_core::LocketError::AgentUnavailable,
        "agent daemon is only supported on Unix targets",
    ))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn request_agent_shutdown_or_signal(_socket_path: &Path, pid: u32) -> Result<(), CliError> {
    send_sigterm(pid)
}

/// Connects to the local endpoint, sends a `Status` request, and parses the
/// response payload.
#[cfg(any(unix, target_os = "windows"))]
pub fn request_status_snapshot(endpoint: &Path) -> Result<Value, io::Error> {
    request_agent_endpoint(endpoint, locket_agent::AgentMethod::Status, serde_json::Value::Null)
}

/// Probes only the selected project's unlock state without starting the daemon.
pub fn request_project_status_snapshot(
    endpoint: &Path,
    project_id: &str,
) -> Result<Value, io::Error> {
    #[cfg(any(unix, target_os = "windows"))]
    {
        request_agent_endpoint(
            endpoint,
            locket_agent::AgentMethod::Status,
            serde_json::json!({"project_id": project_id}),
        )
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (endpoint, project_id);
        Err(io::Error::other("agent transport is unavailable"))
    }
}

#[cfg(any(unix, target_os = "windows"))]
/// Decodes a response, waiting only for an incomplete frame. Parser diagnostics
/// may contain peer-supplied plaintext, so permanent failures use a fixed message.
pub fn decode_agent_frame(
    buffer: &[u8],
) -> Result<Option<locket_agent::ResponseEnvelope>, io::Error> {
    use locket_agent::{DEFAULT_MAX_MESSAGE_SIZE, ProtocolError, decode_response_frame};

    match decode_response_frame(buffer, DEFAULT_MAX_MESSAGE_SIZE) {
        Ok((response, _)) => Ok(Some(response)),
        Err(ProtocolError::IncompleteFrame) => Ok(None),
        Err(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid agent response frame")),
    }
}

#[cfg(any(unix, target_os = "windows"))]
fn decode_agent_response(buffer: &[u8]) -> Option<Result<Value, io::Error>> {
    use locket_agent::ResponseEnvelope;

    let response = match decode_agent_frame(buffer) {
        Ok(Some(response)) => response,
        Ok(None) => return None,
        Err(error) => return Some(Err(error)),
    };
    Some(match response {
        ResponseEnvelope::Success(success) => Ok(success.payload),
        ResponseEnvelope::Error(error) => {
            Err(io::Error::other(format!("agent error: {} ({})", error.error, error.message)))
        }
    })
}

#[cfg(unix)]
fn request_agent_endpoint(
    endpoint: &Path,
    method: locket_agent::AgentMethod,
    payload: Value,
) -> Result<Value, io::Error> {
    use locket_agent::{DEFAULT_MAX_MESSAGE_SIZE, RequestEnvelope, encode_frame};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async move {
        tokio::time::timeout(std::time::Duration::from_secs(2), async move {
            let mut stream = UnixStream::connect(endpoint).await?;
            let request = RequestEnvelope::new("cli-request-1", method, payload);
            let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)
                .map_err(|error| io::Error::other(error.to_string()))?;
            stream.write_all(&frame).await?;
            stream.flush().await?;

            let mut buffer = Vec::with_capacity(1024);
            loop {
                if let Some(response) = decode_agent_response(&buffer) {
                    return response;
                }
                let mut chunk = [0_u8; 1024];
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "agent closed connection without a response",
                    ));
                }
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() > DEFAULT_MAX_MESSAGE_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "agent response exceeds message limit",
                    ));
                }
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "agent response timed out"))?
    })
}

#[cfg(target_os = "windows")]
fn request_agent_endpoint(
    endpoint: &Path,
    method: locket_agent::AgentMethod,
    payload: Value,
) -> Result<Value, io::Error> {
    use locket_agent::{DEFAULT_MAX_MESSAGE_SIZE, RequestEnvelope, encode_frame};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async move {
        tokio::time::timeout(std::time::Duration::from_secs(2), async move {
            let mut stream = locket_agent::connect_named_pipe_client(endpoint).await?;
            let request = RequestEnvelope::new("cli-request-1", method, payload);
            let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)
                .map_err(|error| io::Error::other(error.to_string()))?;
            stream.write_all(&frame).await?;
            stream.flush().await?;

            let mut buffer = Vec::with_capacity(1024);
            loop {
                if let Some(response) = decode_agent_response(&buffer) {
                    return response;
                }
                let mut chunk = [0_u8; 1024];
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "agent closed connection without a response",
                    ));
                }
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() > DEFAULT_MAX_MESSAGE_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "agent response exceeds message limit",
                    ));
                }
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "agent response timed out"))?
    })
}

#[cfg(not(any(unix, target_os = "windows")))]
pub fn request_status_snapshot(_socket_path: &Path) -> Result<Value, io::Error> {
    Err(io::Error::other("agent daemon is only supported on Unix targets"))
}

/// Daemon entry point spawned by `agent_start_command`.
///
/// Owns the Unix socket and `agent.pid` file for the duration of its
/// lifetime, accepts connections on a current-thread Tokio runtime, and
/// shuts down on `SIGTERM`/`SIGINT`. On exit it removes both the pid
/// file and the socket so the next `agent start` is unblocked.
#[cfg(unix)]
pub fn run_internal_agent_serve(args: &InternalAgentServeArgs) -> Result<(), CliError> {
    let args = InternalAgentServeArgs {
        socket: args.socket.clone(),
        pid_file: args.pid_file.clone(),
        require_session_monitoring: args.require_session_monitoring,
    };
    locket_platform::run_with_native_session_loop(move || run_internal_agent_worker(&args))?
}

#[cfg(unix)]
fn run_internal_agent_worker(args: &InternalAgentServeArgs) -> Result<(), CliError> {
    // Daemon-startup ordering invariant:
    //
    // `agent_lifecycle::run_internal_agent_serve_listens_and_cleans_up_on_sigterm`
    // signals the test process with SIGTERM after observing the pid file on
    // disk. Tokio's `signal::unix::signal(SignalKind::terminate())` only
    // masks the default-terminate disposition once it has been registered,
    // so the pid file MUST NOT be written until both `term` and `intr`
    // signal handlers are installed below. Reordering the write to run
    // before the handler registration would re-introduce a race against
    // any parallel test that emits SIGTERM, allowing the test process to
    // exit instead of the daemon.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        let (listener, state) = bind_and_record(args)?;
        let sync_task = locket_agent::team_sync::spawn_team_sync_poll(state.clone());
        let expiry_task = state.spawn_unlock_expiry();
        let result =
            serve_until_signal(listener, state, &args.pid_file, args.require_session_monitoring)
                .await
                .map_err(CliError::Io);
        sync_task.abort();
        expiry_task.abort();
        result
    });

    let _ignored = fs::remove_file(&args.socket);
    let _ignored = fs::remove_file(&args.pid_file);
    result
}

#[cfg(unix)]
fn bind_and_record(
    args: &InternalAgentServeArgs,
) -> Result<(tokio::net::UnixListener, locket_agent::AgentSocketState), CliError> {
    use locket_agent::{AgentSocketConfig, AgentSocketState, bind_socket_listener};

    // bind_socket_listener creates a tokio UnixListener and so must run
    // inside a runtime; the caller invokes us from within `block_on` so
    // a runtime is already on the current thread.
    let listener = bind_socket_listener(&AgentSocketConfig::new(
        args.socket.clone(),
        env!("CARGO_PKG_VERSION"),
    ))
    .map_err(socket_error_to_cli)?;
    let state = AgentSocketState::locked(env!("CARGO_PKG_VERSION"));
    Ok((listener, state))
}

#[cfg(unix)]
async fn serve_until_signal(
    listener: tokio::net::UnixListener,
    state: locket_agent::AgentSocketState,
    pid_file: &Path,
    require_session_monitoring: bool,
) -> io::Result<()> {
    use locket_agent::{SessionLockSource, handle_connection};
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate())?;
    let mut intr = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    let mut observer = start_session_observer(&state, require_session_monitoring).await?;
    write_pid_file(pid_file).map_err(|error| io::Error::other(error.to_string()))?;
    let result: io::Result<()> = async {
    loop {
        tokio::select! {
            biased;
            event = next_native_session_event(&mut observer) => {
                let result = handle_native_session_event(&state, event.map(|event| event.event)).await;
                if let (Some(observer), Some(event)) = (&observer, event) { observer.acknowledge_event(event); }
                result?;
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let connection_state = state.clone();
                tokio::spawn(async move {
                    let _outcome = handle_connection(stream, connection_state).await;
                });
            }
            _ = hup.recv() => {
                state.lock_for_session_event(
                    SessionLockSource::UserSessionSwitch,
                    agent_signal_unix_nanos(),
                ).await.map_err(|error| {
                    io::Error::other(format!("failed to append LOCK audit row: {error}"))
                })?;
            }
            _ = term.recv() => {
                state.lock_for_session_event(
                    SessionLockSource::ProcessExit,
                    agent_signal_unix_nanos(),
                ).await.map_err(|error| {
                    io::Error::other(format!("failed to append LOCK audit row: {error}"))
                })?;
                break;
            }
            _ = intr.recv() => {
                state.lock_for_session_event(
                    SessionLockSource::ProcessExit,
                    agent_signal_unix_nanos(),
                ).await.map_err(|error| {
                    io::Error::other(format!("failed to append LOCK audit row: {error}"))
                })?;
                break;
            }
        }
    }
    Ok(())
    }.await;
    // Clear keys and prevent in-flight requests from unlocking again before
    // the observer drops and releases any outstanding suspend acknowledgement.
    let cleanup = lock_before_observer_shutdown(&state).await;
    drop(observer);
    result.and(cleanup)
}

#[cfg(any(unix, target_os = "windows"))]
async fn lock_before_observer_shutdown(state: &locket_agent::AgentSocketState) -> io::Result<()> {
    state
        .lock_for_native_session_event(
            locket_agent::SessionLockSource::ProcessExit,
            true,
            agent_signal_unix_nanos(),
        )
        .await
        .map(|_| ())
        .map_err(|error| io::Error::other(error.to_string()))
}

#[cfg(any(unix, target_os = "windows"))]
fn agent_signal_unix_nanos() -> i128 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| {
        let max = u128::from(u64::try_from(i64::MAX).unwrap_or(0));
        let clamped = duration.as_nanos().min(max);
        i128::from(i64::try_from(clamped).unwrap_or(0))
    })
}

#[cfg(any(unix, target_os = "windows"))]
async fn handle_native_session_event(
    state: &locket_agent::AgentSocketState,
    event: Option<locket_platform::NativeSessionEvent>,
) -> io::Result<()> {
    use locket_agent::SessionLockSource;
    use locket_platform::NativeSessionEvent;
    let (source, blocked) = match event {
        Some(NativeSessionEvent::SystemSleep) => (SessionLockSource::SystemSleep, true),
        Some(NativeSessionEvent::SystemWake) => (SessionLockSource::SystemSleep, false),
        Some(NativeSessionEvent::ScreenLock) => (SessionLockSource::ScreenLock, true),
        Some(NativeSessionEvent::ScreenUnlock) => (SessionLockSource::ScreenLock, false),
        None => (SessionLockSource::UserSessionSwitch, true),
    };
    state
        .lock_for_native_session_event(source, blocked, agent_signal_unix_nanos())
        .await
        .map_err(|error| io::Error::other(format!("failed to append LOCK audit row: {error}")))?;
    if event.is_none() {
        return Err(io::Error::other("native session observer stopped; agent locked and stopped"));
    }
    Ok(())
}

#[cfg(any(unix, target_os = "windows"))]
async fn start_session_observer(
    state: &locket_agent::AgentSocketState,
    required: bool,
) -> io::Result<Option<locket_platform::SessionObserver>> {
    match locket_platform::SessionObserver::start(|| std::process::exit(1)).await {
        Ok(mut observer) => {
            // Apply the current lock/sleep state before accepting any client.
            while let Some(event) = observer.try_next_event()? {
                handle_native_session_event(state, Some(event.event)).await?;
                observer.acknowledge_event(event);
            }
            state
                .set_session_monitoring_status(format!("active: {}", observer.backend_name()))
                .await;
            Ok(Some(observer))
        }
        Err(error) => {
            state.set_session_monitoring_status(format!("unavailable: {error}")).await;
            if required { Err(error) } else { Ok(None) }
        }
    }
}

#[cfg(any(unix, target_os = "windows"))]
async fn next_native_session_event(
    observer: &mut Option<locket_platform::SessionObserver>,
) -> Option<locket_platform::NativeSessionNotification> {
    match observer {
        Some(observer) => observer.next_event().await,
        None => std::future::pending().await,
    }
}

#[cfg(target_os = "windows")]
pub fn run_internal_agent_serve(args: &InternalAgentServeArgs) -> Result<(), CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        let config = locket_agent::AgentPipeConfig::current_user(args.socket.clone())
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut listener = locket_agent::bind_named_pipe_listener(&config)?;
        let state = locket_agent::AgentSocketState::locked(env!("CARGO_PKG_VERSION"));
        let mut observer = start_session_observer(&state, args.require_session_monitoring).await?;
        write_pid_file(&args.pid_file).map_err(|error| io::Error::other(error.to_string()))?;
        let sync_task = locket_agent::team_sync::spawn_team_sync_poll(state.clone());
        let expiry_task = state.spawn_unlock_expiry();
        let serving: io::Result<()> = async {
        loop {
            tokio::select! {
                biased;
                event = next_native_session_event(&mut observer) => {
                    let result = handle_native_session_event(&state, event.map(|event| event.event)).await;
                    if let (Some(observer), Some(event)) = (&observer, event) { observer.acknowledge_event(event); }
                    result?;
                }
                connected = listener.connect() => {
                    connected?;
                    let stream = listener;
                    listener = locket_agent::bind_named_pipe_instance(&config)?;
                    let connection_state = state.clone();
                    tokio::spawn(async move {
                        let _ignored =
                            locket_agent::handle_named_pipe_connection(stream, connection_state)
                                .await;
                    });
                }
                () = state.shutdown.notified() => break,
            }
        }
        Ok(())
        }.await;
        sync_task.abort();
        expiry_task.abort();
        let cleanup = lock_before_observer_shutdown(&state).await;
        drop(observer);
        serving.and(cleanup)
    });
    let _ignored = fs::remove_file(&args.pid_file);
    result.map_err(CliError::Io)
}

#[cfg(not(any(unix, target_os = "windows")))]
pub fn run_internal_agent_serve(_args: &InternalAgentServeArgs) -> Result<(), CliError> {
    Err(typed_cli_error(
        locket_core::LocketError::AgentUnavailable,
        "agent daemon is only supported on Unix targets",
    ))
}

#[cfg(any(unix, target_os = "windows"))]
fn write_pid_file(path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", std::process::id()))?;
    set_user_only_file_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn socket_error_to_cli(error: locket_agent::SocketServerError) -> CliError {
    use locket_agent::SocketServerError;
    use locket_core::LocketError;

    match error {
        SocketServerError::AgentSocketInUse { path } => typed_cli_error(
            LocketError::AgentSocketInUse,
            format!("agent socket already bound: {}", path.display()),
        ),
        SocketServerError::PeerCredentialDenied { peer_uid, daemon_uid } => typed_cli_error(
            LocketError::AccessDenied,
            format!(
                "peer uid {peer_uid} does not match daemon uid {daemon_uid}; refusing cross-user connection"
            ),
        ),
        // This is a permissions failure rather than a bound-socket
        // conflict. Reuse the closest existing typed error while keeping
        // the formatted message specific enough to identify the path and
        // mode that need repair.
        SocketServerError::SocketPathTooWide { path, mode, expected } => typed_cli_error(
            LocketError::AgentSocketInUse,
            format!(
                "agent socket path {} has mode {mode:#o}; expected at most {expected:#o}",
                path.display()
            ),
        ),
        SocketServerError::Io(error) => CliError::Io(error),
    }
}

fn agent_logs_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &AgentLogsArgs,
) -> Result<(), CliError> {
    if args.lines > 10_000 {
        return Err(metadata_invalid_error("agent logs --lines is capped at 10000"));
    }
    let since = args.since.as_deref().map(parse_agent_log_since).transpose()?;
    let lines = read_agent_log_lines(context, since)?;
    if lines.is_empty() {
        if !args.follow {
            writeln!(output, "no agent logs")?;
        }
    } else {
        for line in lines.iter().skip(lines.len().saturating_sub(args.lines)) {
            writeln!(output, "{}", sanitize_agent_log_line(line))?;
        }
    }
    if args.follow {
        follow_agent_logs(context, output, since)?;
    }
    Ok(())
}

fn parse_agent_log_since(value: &str) -> Result<i64, CliError> {
    if let Ok(timestamp) = value.parse::<i64>() {
        return Ok(normalize_log_since(timestamp));
    }
    let timestamp = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        metadata_invalid_error("agent logs --since must be RFC3339 UTC or Unix seconds")
    })?;
    timestamp.unix_timestamp_nanos().try_into().map_err(|_| CliError::Time)
}

const fn normalize_log_since(value: i64) -> i64 {
    if value.abs() < 10_000_000_000 { value.saturating_mul(NANOS_PER_SECOND) } else { value }
}

fn read_agent_log_lines(
    context: &RuntimeContext,
    since: Option<i64>,
) -> Result<Vec<String>, CliError> {
    let mut lines = Vec::new();
    for path in agent_log_paths_oldest_first(context) {
        let log_text = match fs::read_to_string(&path) {
            Ok(log_text) => log_text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        lines.extend(
            log_text.lines().filter(|line| agent_log_line_is_since(line, since)).map(str::to_owned),
        );
    }
    Ok(lines)
}

fn agent_log_line_is_since(line: &str, since: Option<i64>) -> bool {
    let Some(since) = since else {
        return true;
    };
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|value| agent_log_timestamp_nanos(value.get("timestamp")?))
        .is_some_and(|timestamp| timestamp >= since)
}

fn agent_log_timestamp_nanos(value: &Value) -> Option<i64> {
    if let Some(timestamp) = value.as_i64() {
        return Some(normalize_log_since(timestamp));
    }
    let timestamp = OffsetDateTime::parse(value.as_str()?, &Rfc3339).ok()?;
    timestamp.unix_timestamp_nanos().try_into().ok()
}

fn follow_agent_logs(
    context: &RuntimeContext,
    output: &mut impl Write,
    since: Option<i64>,
) -> Result<(), CliError> {
    prepare_agent_log_dir(context)?;
    let log_path = agent_log_path(context);
    let mut file = fs::OpenOptions::new().read(true).create(true).append(true).open(&log_path)?;
    set_user_only_file_permissions(&log_path)?;
    file.seek(SeekFrom::End(0))?;
    let mut pending = String::new();
    loop {
        let mut chunk = String::new();
        file.read_to_string(&mut chunk)?;
        if !chunk.is_empty() {
            pending.push_str(&chunk);
            while let Some(newline) = pending.find('\n') {
                let line = pending[..newline].to_owned();
                pending.drain(..=newline);
                if agent_log_line_is_since(&line, since) {
                    writeln!(output, "{}", sanitize_agent_log_line(&line))?;
                }
            }
        }
        std::thread::sleep(StdDuration::from_millis(AGENT_LOG_FOLLOW_SLEEP_MS));
    }
}

#[cfg(all(test, unix))]
#[path = "agent_framing_tests.rs"]
pub(crate) mod framing_tests;

#[cfg(test)]
mod tests {
    #[test]
    fn required_session_monitoring_rejects_unavailable_or_legacy_daemons() {
        for status in [None, Some("unavailable: no desktop"), Some("inactive")] {
            let report = super::AgentStartupReport {
                started: false,
                pid: None,
                session_monitoring: status.map(str::to_owned),
            };
            assert!(super::require_active_session_monitoring(&report).is_err());
        }
        let report = super::AgentStartupReport {
            started: false,
            pid: None,
            session_monitoring: Some("active: native session notifications".to_owned()),
        };
        assert!(super::require_active_session_monitoring(&report).is_ok());
    }

    use std::cell::Cell;
    use std::sync::Arc;

    use locket_platform::{
        KeyringAutomationClientKeyStore, KeyringMasterKeyStore, PassphraseFallbackMasterKeyStore,
        UnavailableLocalUserVerifier, UnavailablePlatformPasskeyRegistrar,
    };
    use serde_json::json;
    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::runtime::prompts::{
        EnvOrPromptPassphraseReader, StdinConfirmationReader, StdinOrPromptSecretValueReader,
        TtyRecoveryCodeReader,
    };

    #[cfg(any(unix, target_os = "windows"))]
    #[tokio::test]
    async fn native_session_events_clear_keys_and_revoke_grants() -> io::Result<()> {
        use locket_agent::{
            AgentSocketState, GrantAction, GrantBinding, GrantRecord, UnlockEntry, UnlockMethod,
        };
        use locket_platform::NativeSessionEvent;

        for event in [
            Some(NativeSessionEvent::SystemSleep),
            Some(NativeSessionEvent::ScreenLock),
            Some(NativeSessionEvent::SystemWake),
            Some(NativeSessionEvent::ScreenUnlock),
            None,
        ] {
            let state = AgentSocketState::locked("test");
            state.unlock_cache.lock().await.insert(
                "project".to_owned(),
                UnlockEntry::new(
                    vec![7; 32],
                    0,
                    StdDuration::from_secs(30),
                    UnlockMethod::OsKeychain,
                ),
            );
            state.grants.lock().await.insert(GrantRecord {
                grant_id: "before-sleep".to_owned(),
                project_id: "project".to_owned(),
                profile_id: "profile".to_owned(),
                action: GrantAction::RunPolicy,
                binding: GrantBinding::new(std::process::id(), "test"),
                issued_at_unix_nanos: 0,
                ttl_seconds: 30,
                expires_at_unix_nanos: i128::MAX,
            });
            let result = handle_native_session_event(&state, event).await;
            assert!(state.unlock_cache.lock().await.is_empty(), "{event:?} retained keys");
            assert!(state.grants.lock().await.is_empty(), "{event:?} retained a pre-event grant");
            assert_eq!(result.is_err(), event.is_none(), "observer failure must stop serving");
        }
        Ok(())
    }

    struct FakeLauncher {
        spawn_calls: Cell<usize>,
        status_ok: Cell<bool>,
        spawn_ok: bool,
    }

    impl FakeLauncher {
        const fn succeeding() -> Self {
            Self { spawn_calls: Cell::new(0), status_ok: Cell::new(true), spawn_ok: true }
        }

        const fn status_failing() -> Self {
            Self { spawn_calls: Cell::new(0), status_ok: Cell::new(false), spawn_ok: true }
        }

        fn spawn_calls(&self) -> usize {
            self.spawn_calls.get()
        }
    }

    impl AgentDaemonLauncher for FakeLauncher {
        fn spawn(&self, socket: &Path, pid_file: &Path) -> Result<(), CliError> {
            self.spawn_calls.set(self.spawn_calls.get() + 1);
            if !self.spawn_ok {
                return Err(typed_cli_error(locket_core::LocketError::AgentUnavailable, "spawn"));
            }
            if let Some(parent) = pid_file.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(pid_file, format!("{}\n", std::process::id()))?;
            fs::write(socket, b"")?;
            Ok(())
        }

        fn status_snapshot(&self, _socket: &Path) -> Result<Value, io::Error> {
            if self.status_ok.get() {
                Ok(json!({ "lock_state": "locked", "agent_version": "test" }))
            } else {
                Err(io::Error::other("unreachable"))
            }
        }
    }

    fn temp_context(directory: &TempDir) -> RuntimeContext {
        RuntimeContext {
            cwd: directory.path().to_path_buf(),
            store_path: directory.path().join("store.db"),
            config_path: directory.path().join("config.toml"),
            template_dir: directory.path().join(".locket").join("templates"),
            agent_data_dir: None,
            key_store: Arc::new(KeyringMasterKeyStore),
            automation_client_key_store: Arc::new(KeyringAutomationClientKeyStore),
            passphrase_store: PassphraseFallbackMasterKeyStore::new(
                directory.path().join("passphrase-fallback"),
            ),
            passphrase_reader: Arc::new(EnvOrPromptPassphraseReader),
            recovery_code_reader: Arc::new(TtyRecoveryCodeReader),
            confirmation_reader: Arc::new(StdinConfirmationReader),
            secret_value_reader: Arc::new(StdinOrPromptSecretValueReader),
            user_verifier: Arc::new(UnavailableLocalUserVerifier),
            passkey_registrar: Arc::new(UnavailablePlatformPasskeyRegistrar),
            master_key_cache: crate::runtime::context::MasterKeyCache::new(),
        }
    }

    #[test]
    fn on_demand_startup_spawns_once_then_reuses_running_agent()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let context = temp_context(&directory);
        let launcher = FakeLauncher::succeeding();

        let first = ensure_agent_running_with_launcher(&context, &launcher)?;
        assert_eq!(
            first,
            AgentStartupReport {
                started: true,
                pid: Some(std::process::id()),
                session_monitoring: None
            }
        );
        assert_eq!(launcher.spawn_calls(), 1);

        let second = ensure_agent_running_with_launcher(&context, &launcher)?;
        assert_eq!(
            second,
            AgentStartupReport {
                started: false,
                pid: Some(std::process::id()),
                session_monitoring: None
            }
        );
        assert_eq!(launcher.spawn_calls(), 1);
        Ok(())
    }

    #[test]
    fn on_demand_startup_fails_closed_when_spawned_agent_is_unreachable()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let context = temp_context(&directory);
        let launcher = FakeLauncher::status_failing();

        let Err(error) = ensure_agent_running_with_launcher(&context, &launcher) else {
            return Err("unreachable agent must fail closed".into());
        };
        assert_eq!(launcher.spawn_calls(), 1);
        let CliError::Typed { kind, message } = error else {
            return Err("expected typed AgentUnavailable".into());
        };
        assert_eq!(kind, locket_core::LocketError::AgentUnavailable);
        assert!(message.contains("on-demand startup"));
        Ok(())
    }
}
