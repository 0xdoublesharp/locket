use super::*;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::time::Duration;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

struct Fixture {
    directory: tempfile::TempDir,
    root: PathBuf,
    store: PathBuf,
    id: String,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("project ' $(nope)");
        fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let id = locket_core::ProjectId::generate()?.to_string();
        fs::write(
            root.join("locket.toml"),
            format!(
                "schema_version = 1\nproject_id = '{id}'\nname = 'Fixture'\ndefault_profile = 'dev'\n[commands.test]\nargv = ['echo', 'test']\n"
            ),
        )?;
        let store = directory.path().join("store.db");
        let mut db = locket_store::Store::open(&store)?;
        db.initialize_schema()?;
        db.insert_project_if_absent(&id, "Stored Fixture", 1)?;
        db.insert_profile_if_absent("lk_prof_fixture", &id, "dev", false, 1)?;
        db.trust_project_root(
            &id,
            &Sha256::digest(root.to_string_lossy().as_bytes()).into(),
            root.to_str(),
            1,
        )?;
        Ok(Self { directory, root, store, id })
    }
}

#[test]
fn trusted_context_reads_actual_profile_and_lists_registered_roots() -> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    let opened = open_project_at(&f.store, &f.root.join("locket.toml"))?;
    assert_eq!(opened.project_id, f.id);
    assert_eq!(opened.project_name, "Stored Fixture");
    assert_eq!(opened.profile_id, "lk_prof_fixture");
    assert_eq!(opened.profile_name, "dev");
    assert_eq!(list_projects_at(&f.store)?, vec![opened]);
    Ok(())
}

#[test]
fn copied_or_changed_project_config_cannot_claim_trusted_root() -> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    let copy = f.directory.path().join("copy");
    fs::create_dir(&copy)?;
    fs::copy(f.root.join("locket.toml"), copy.join("locket.toml"))?;
    assert!(open_project_at(&f.store, &copy).is_err());
    fs::write(
        f.root.join("locket.toml"),
        "schema_version = 1\nproject_id='bad'\nSECRET='do-not-display'\n",
    )?;
    let error = open_project_at(&f.store, &f.root).err().ok_or("expected invalid config")?;
    assert!(!error.contains("do-not-display"));
    Ok(())
}

#[test]
fn init_and_start_have_only_scoped_fixed_arguments() -> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    assert_eq!(initialize_plan(&f.root)?.args, ["init", "--no-passkey"]);
    let start = start_plan(&f.store, Some(&f.id))?;
    assert_eq!(start.cwd, f.root);
    assert_eq!(start.args, ["agent", "start"]);
    Ok(())
}

#[test]
fn unknown_policy_and_unknown_project_are_rejected() -> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    assert!(policy_context(&f.store, &f.id, "missing").is_err());
    assert!(policy_context(&f.store, "unknown", "test").is_err());
    assert!(policy_context(&f.store, &f.id, "test").is_ok());
    Ok(())
}

#[test]
fn scan_launch_uses_registered_root_fixed_argv_and_returns_only_launch_metadata()
-> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    let cli = f.directory.path().join("trusted-locket");
    let called = std::cell::Cell::new(false);
    let response = scan_project_with(
        &f.store,
        &f.id,
        || Ok(cli.clone()),
        |executable, root, args| {
            called.set(true);
            assert_eq!(executable, cli);
            assert_eq!(root, f.root);
            assert_eq!(args, ["scan", "--require-known"]);
            Ok(())
        },
    )?;
    assert!(called.get());
    assert_eq!(
        serde_json::to_value(response)?,
        serde_json::json!({"launched": true, "command": "locket scan --require-known"})
    );
    Ok(())
}

#[test]
fn scan_launch_rejects_unknown_untrusted_or_changed_projects_before_resolving_cli()
-> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    let resolved = std::cell::Cell::new(false);
    let launched = std::cell::Cell::new(false);
    for state in ["unknown", "untrusted", "changed"] {
        if state == "untrusted" {
            Store::open(&f.store)?.untrust_project_root(&f.id, &root_hash(&f.root))?;
        } else if state == "changed" {
            Store::open(&f.store)?.trust_project_root(
                &f.id,
                &root_hash(&f.root),
                f.root.to_str(),
                2,
            )?;
            fs::write(f.root.join("locket.toml"), "schema_version = 1\nproject_id = 'changed'\n")?;
        }
        let result = scan_project_with(
            &f.store,
            if state == "unknown" { "unknown" } else { &f.id },
            || {
                resolved.set(true);
                Ok(f.root.join("unused-cli"))
            },
            |_, _, _| {
                launched.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!resolved.get());
        assert!(!launched.get());
    }
    Ok(())
}

#[test]
fn scan_launch_failures_never_return_success() -> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    let launched = std::cell::Cell::new(false);
    let missing_cli = scan_project_with(
        &f.store,
        &f.id,
        || Err("CLI unavailable".into()),
        |_, _, _| {
            launched.set(true);
            Ok(())
        },
    );
    assert_eq!(missing_cli.err().as_deref(), Some("CLI unavailable"));
    assert!(!launched.get());
    let failed_terminal = scan_project_with(
        &f.store,
        &f.id,
        || Ok(f.root.join("unused-cli")),
        |_, _, _| Err("Terminal refused to open".into()),
    );
    assert_eq!(failed_terminal.err().as_deref(), Some("Terminal refused to open"));
    Ok(())
}

#[cfg(unix)]
fn executable(directory: &Path, body: &str) -> Result<PathBuf, Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    let file = directory.join("fake-locket");
    fs::write(&file, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o700))?;
    Ok(file)
}

#[test]
#[cfg(unix)]
fn fake_cli_receives_argv_cwd_and_json_stdin_without_returning_secret_output()
-> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    let cli = executable(
        &f.root,
        "pwd > cwd; printf '%s\\n' \"$@\" > args; cat > input; echo 'SECRET=private'; echo 'SECRET=private' >&2",
    )?;
    let plan = CliPlan {
        cwd: f.root.clone(),
        args: vec!["policy".into(), "apply".into()],
        input: Some(b"{\"safe\":true}".to_vec()),
    };
    execute_cli(&cli, &plan, Duration::from_secs(2))?;
    assert_eq!(fs::read_to_string(f.root.join("args"))?, "policy\napply\n");
    assert_eq!(fs::read_to_string(f.root.join("input"))?, "{\"safe\":true}");
    assert_eq!(fs::read_to_string(f.root.join("cwd"))?.trim(), f.root.to_str().ok_or("utf8")?);
    Ok(())
}

#[test]
#[cfg(unix)]
fn runner_rejects_exit_failure_and_kills_timed_out_child() -> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    let plan = CliPlan { cwd: f.root.clone(), args: vec!["import".into()], input: None };
    let cli = executable(&f.root, "echo 'private-value' >&2; exit 7")?;
    let error = execute_cli(&cli, &plan, Duration::from_secs(2)).err().ok_or("expected failure")?;
    assert!(error.contains("7"));
    assert!(!error.contains("private-value"));
    assert!(error.contains("matching CLI release"));
    let cli = executable(&f.root, "exec sleep 5")?;
    let started = std::time::Instant::now();
    assert!(execute_cli(&cli, &plan, Duration::from_millis(50)).is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[test]
fn cli_lookup_requires_executable_and_prefers_bundled_candidate() -> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    let invalid = f.root.join("invalid");
    fs::write(&invalid, "invalid")?;
    assert!(find_cli_from(std::slice::from_ref(&invalid), None).is_err());
    #[cfg(unix)]
    {
        let valid = executable(&f.root, "exit 0")?;
        assert_eq!(find_cli_from(&[invalid, valid.clone()], None)?, valid);
    }
    Ok(())
}

#[test]
fn absent_store_listing_does_not_create_store() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("missing.db");
    assert!(list_projects_at(&path)?.is_empty());
    assert!(!path.exists());
    Ok(())
}
#[test]
fn terminal_script_quotes_adversarial_paths_and_policy() {
    let script = terminal_script(
        Path::new("/bin/locket '$(touch nope)'"),
        Path::new("/project/a'b\n$(oops)"),
        &["run", "test' ; touch nope"],
    );
    assert!(script.contains("'/project/a'\\''b\n$(oops)'"));
    assert!(script.contains("'test'\\'' ; touch nope'"));
    assert!(script.contains("rm -- \"$0\""));
}

#[test]
fn scoped_status_preserves_agent_lock_state_and_only_enriches_verified_context()
-> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    let context = open_project_at(&f.store, &f.root)?;
    let mut status = locket_agent::StatusPayload::locked("test");
    status.project_id = Some(f.id.clone());
    let status = scoped_status(status, &context)?;
    assert_eq!(status.profile_name.as_deref(), Some("dev"));
    assert_eq!(status.lock_state, locket_agent::LockState::Locked);
    assert!(status.unlock_ttl_seconds.is_none());
    let other = locket_agent::StatusPayload::locked("test");
    assert!(scoped_status(other, &context).is_err());
    Ok(())
}

#[test]
fn windows_terminal_receives_only_encoded_untrusted_content() -> Result<(), Box<dyn Error>> {
    let args = windows_terminal_args(
        Path::new("C:\\cli'; write-host nope\\locket.exe"),
        Path::new("C:\\root; ' $(oops)"),
        &["run", "task'; write-host nope"],
    );
    assert!(args.iter().any(|arg| arg == "-EncodedCommand"));
    assert!(!args.iter().any(|arg| arg.contains("write-host") || arg.contains("oops")));
    let encoded = args.last().ok_or("encoded command")?;
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let units: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let command = String::from_utf16(&units)?;
    assert!(command.contains("Set-Location -LiteralPath 'C:\\root; '' $(oops)'"));
    assert!(command.contains("'task''; write-host nope'"));
    Ok(())
}

#[test]
#[cfg(unix)]
fn terminal_script_reaches_only_fake_cli_with_literal_arguments() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new()?;
    let cli = executable(&f.root, "printf '%s\\n' \"$@\" > terminal-args; pwd > terminal-cwd")?;
    let policy = "test' ; $(touch unintended)";
    let launcher = write_terminal_launcher(&cli, &f.root, &["run", policy])?;
    assert_eq!(fs::metadata(launcher.path())?.permissions().mode() & 0o777, 0o700);
    let result = Command::new("/bin/sh").arg(launcher.path()).status()?;
    assert!(result.success());
    assert!(!launcher.path().exists());
    assert_eq!(fs::read_to_string(f.root.join("terminal-args"))?, format!("run\n{policy}\n"));
    assert!(!f.root.join("unintended").exists());
    Ok(())
}

#[test]
fn scan_terminal_script_quotes_hostile_paths_and_keeps_fixed_arguments() {
    let script = terminal_script(
        Path::new("/bin/locket '$(touch nope)'"),
        Path::new("/project/a'b\n$(oops); `oops`"),
        &["scan", "--require-known"],
    );
    assert!(script.starts_with(
        "#!/bin/sh\n/bin/rm -- \"$0\"\ncd -- '/project/a'\\''b\n$(oops); `oops`' && '/bin/locket '\\''$(touch nope)'\\''' 'scan' '--require-known'\n"
    ));
}

#[test]
#[cfg(unix)]
fn scan_terminal_launcher_passes_only_fixed_argv_in_hostile_cwd() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new()?;
    let root = f.root.join("scan' $(touch unintended); `touch injected`\n");
    fs::create_dir(&root)?;
    let cli = executable(&root, "printf '%s\\n' \"$@\" > scan-args; pwd -P > scan-cwd")?;
    let launcher = write_terminal_launcher(&cli, &root, &["scan", "--require-known"])?;
    assert_eq!(fs::metadata(launcher.path())?.permissions().mode() & 0o777, 0o700);
    let result = Command::new("/bin/sh")
        .arg(launcher.path())
        .current_dir(&f.root)
        .stdin(Stdio::null())
        .status()?;
    assert!(result.success());
    assert!(!launcher.path().exists());
    assert_eq!(fs::read_to_string(root.join("scan-args"))?, "scan\n--require-known\n");
    assert_eq!(fs::read_to_string(root.join("scan-cwd"))?, format!("{}\n", root.display()));
    for directory in [&f.root, &root] {
        assert!(!directory.join("unintended").exists());
        assert!(!directory.join("injected").exists());
    }
    Ok(())
}

#[test]
#[cfg(unix)]
fn scan_terminal_keeps_results_until_dismissed_and_preserves_exit_status()
-> Result<(), Box<dyn Error>> {
    use std::io::{BufRead, BufReader};
    for (exit_code, linux) in [(0, false), (69, false), (0, true), (69, true)] {
        let f = Fixture::new()?;
        let cli =
            executable(&f.root, &format!("printf 'scan fixture result\\n'; exit {exit_code}"))?;
        let launcher = write_terminal_launcher(&cli, &f.root, &["scan", "--require-known"])?;
        let argv = if linux {
            posix_terminal_command(&cli, &f.root, &["scan", "--require-known"])
        } else {
            vec!["/bin/sh".into(), launcher.path().as_os_str().to_owned()]
        };
        let mut child = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut output = BufReader::new(child.stdout.take().ok_or("child output")?);
        let mut line = String::new();
        output.read_line(&mut line)?;
        assert_eq!(line, "scan fixture result\n");
        line.clear();
        output.read_line(&mut line)?;
        if line == "\n" {
            line.clear();
            output.read_line(&mut line)?;
        }
        assert!(line.contains("Press Enter to close"), "scan exited without a dismissal prompt");
        assert!(child.try_wait()?.is_none(), "results window must remain open");
        child.stdin.take().ok_or("child input")?.write_all(b"\n")?;
        assert_eq!(child.wait()?.code(), Some(exit_code));
    }
    Ok(())
}

#[test]
fn scan_windows_terminal_encodes_paths_and_fixed_argv() -> Result<(), Box<dyn Error>> {
    use base64::Engine as _;
    let args = windows_terminal_args(
        Path::new("C:\\cli'; write-host nope\\locket.exe"),
        Path::new("C:\\root; ' $(oops)\n`oops`"),
        &["scan", "--require-known"],
    );
    assert_eq!(
        &args[..args.len() - 1],
        ["-w", "new", "new-tab", "powershell.exe", "-NoProfile", "-NoExit", "-EncodedCommand"]
    );
    let bytes =
        base64::engine::general_purpose::STANDARD.decode(args.last().ok_or("encoded command")?)?;
    let units: Vec<_> =
        bytes.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    assert_eq!(
        String::from_utf16(&units)?,
        "Set-Location -LiteralPath 'C:\\root; '' $(oops)\n`oops`' -ErrorAction Stop; & 'C:\\cli''; write-host nope\\locket.exe' 'scan' '--require-known'; $scanExit = $LASTEXITCODE; Read-Host \"Scan finished (exit $scanExit). Press Enter to close\" | Out-Null; exit $scanExit"
    );
    Ok(())
}

#[test]
fn duplicate_trusted_roots_require_selection_and_respect_selected_clone()
-> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    let other = f.directory.path().join("another clone");
    fs::create_dir(&other)?;
    let other = other.canonicalize()?;
    fs::copy(f.root.join("locket.toml"), other.join("locket.toml"))?;
    let store = Store::open(&f.store)?;
    store.trust_project_root(&f.id, &root_hash(&other), other.to_str(), 2)?;
    assert!(project_context_with_selection(&f.store, &f.id, None).is_err());
    let selected = open_project_at(&f.store, &f.root)?;
    assert_eq!(
        project_context_with_selection(&f.store, &f.id, Some(&selected))?.root,
        selected.root
    );
    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn status_bridge_sends_selected_project_to_fake_agent_and_preserves_real_ttl()
-> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = Fixture::new()?;
    let context = open_project_at(&f.store, &f.root)?;
    let socket = f.directory.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let id = f.id.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let length = stream.read_u32_le().await?;
        let mut bytes = vec![0; length as usize];
        stream.read_exact(&mut bytes).await?;
        let request: locket_agent::RequestEnvelope = serde_json::from_slice(&bytes)?;
        assert_eq!(request.payload["project_id"], id);
        let mut status = locket_agent::StatusPayload::locked("fake");
        status.project_id = Some(id);
        status.lock_state = locket_agent::LockState::Unlocked;
        status.unlock_ttl_seconds = Some(37);
        let response = locket_agent::ResponseEnvelope::Success(locket_agent::SuccessEnvelope::new(
            request.id,
            serde_json::to_value(status)?,
        ));
        let frame = locket_agent::encode_frame(&response, locket_agent::DEFAULT_MAX_MESSAGE_SIZE)?;
        stream.write_all(&frame).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let result = fetch_context_status(&socket, &context).await;
    server.await?.map_err(|error| error.to_string())?;
    let status = result?;
    assert_eq!(status.profile_name.as_deref(), Some("dev"));
    assert_eq!(status.project_id.as_deref(), Some(f.id.as_str()));
    assert_eq!(status.unlock_ttl_seconds, Some(37));
    assert_eq!(status.lock_state, locket_agent::LockState::Unlocked);
    Ok(())
}

#[test]
fn selected_context_refresh_reads_actual_default_profile_after_switch() -> Result<(), Box<dyn Error>>
{
    let f = Fixture::new()?;
    let selected = open_project_at(&f.store, &f.root)?;
    let store = Store::open(&f.store)?;
    store.insert_profile_if_absent("lk_prof_other", &f.id, "prod", true, 2)?;
    let config = f.root.join("locket.toml");
    let source =
        fs::read_to_string(&config)?.replace("default_profile = 'dev'", "default_profile = 'prod'");
    fs::write(config, source)?;
    let refreshed = project_context_with_selection(&f.store, &f.id, Some(&selected))?;
    assert_eq!(refreshed.profile_name, "prod");
    assert_eq!(refreshed.profile_id, "lk_prof_other");
    Ok(())
}

#[test]
fn init_rejects_child_of_existing_or_partial_project_before_cli_invocation()
-> Result<(), Box<dyn Error>> {
    let f = Fixture::new()?;
    let child = f.root.join("child");
    fs::create_dir(&child)?;
    let error = initialize_plan(&child).err().ok_or("expected ancestor rejection")?;
    assert!(error.contains("parent"));
    fs::write(f.root.join("locket.toml"), "partial malformed config")?;
    assert!(initialize_plan(&child).is_err());
    Ok(())
}

#[test]
fn cli_failures_do_not_redirect_agent_mutations_to_a_terminal() {
    let error = cli_failure_guidance("init", "exit status: 7");
    assert!(error.contains("matching CLI release"));
    assert!(!error.contains("locket import"));
    assert!(!error.contains("policy apply"));
    assert!(!error.contains("passphrase"));
}

#[cfg(unix)]
#[test]
fn bundled_cli_version_is_checked_and_bounded() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new()?;
    let cli = fixture.root.join("version-cli");
    for (output, valid) in [
        (format!("locket {}", env!("CARGO_PKG_VERSION")), true),
        ("locket 99.0.0".into(), false),
        ("untrusted output".into(), false),
    ] {
        fs::write(&cli, format!("#!/bin/sh\nprintf '%s\\n' '{}'\n", output))?;
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o700))?;
        assert_eq!(verify_cli_version(&cli, Duration::from_secs(1)).is_ok(), valid);
    }
    fs::write(&cli, "#!/bin/sh\nexec sleep 10\n")?;
    assert!(verify_cli_version(&cli, Duration::from_millis(20)).is_err());
    Ok(())
}

#[test]
fn readiness_uses_only_contract_and_inventory_metadata() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let path = fixture.root.join("locket.toml");
    let text = fs::read_to_string(&path)?.replace(
        "argv = ['echo', 'test']",
        "argv = ['echo', 'test']\nrequired_secrets=['TOKEN','PUBLIC_URL']",
    );
    fs::write(
        &path,
        format!(
            "{text}\n[variables.TOKEN]\ndescription='service token'\nsetup_hint='Get a development token'\n[variables.PUBLIC_URL]\nclassification='public'\ndefault='https://canary-do-not-return.invalid'\n"
        ),
    )?;
    let request = DesktopReadinessRequest {
        project_id: fixture.id.clone(),
        policy_name: Some("test".into()),
    };
    let result = variable_readiness_at(&fixture.store, &request)?;
    let serialized = serde_json::to_value(result)?;
    assert_eq!(serialized["profile_id"], "lk_prof_fixture");
    let rows = serialized["policies"][0]["rows"].as_array().ok_or("rows")?;
    assert_eq!(rows.iter().find(|row| row["name"] == "TOKEN").ok_or("TOKEN")?["state"], "missing");
    assert!(!serialized.to_string().contains("canary-do-not-return"));
    assert!(!serialized.to_string().contains("https://"));
    assert!(serialized.to_string().contains("public-default"));
    Ok(())
}

#[tokio::test]
async fn native_grant_rejects_profile_name_before_connecting() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let result: Result<serde_json::Value, _> = invoke_granted(
        locket_agent::AgentMethod::SetSecret,
        locket_agent::GrantAction::SetSecret,
        serde_json::json!({}),
        &fixture.store,
        &fixture.id,
        "dev",
    )
    .await;
    assert!(matches!(result, Err(super::super::AgentClientError::Protocol { .. })));
    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn native_action_grants_use_actual_process_and_are_revoked() -> Result<(), Box<dyn Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fixture = Fixture::new()?;
    let context = open_project_at(&fixture.store, &fixture.root)?;
    let socket = fixture.directory.path().join("grant.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let expected = native_binding()?;
    let id = fixture.id.clone();
    let server = tokio::spawn(async move {
        for kind in ["RequestGrant", "SetSecret", "RevokeGrant"] {
            let (mut stream, _) = listener.accept().await?;
            let length = stream.read_u32_le().await?;
            let mut bytes = vec![0; length as usize];
            stream.read_exact(&mut bytes).await?;
            let request: locket_agent::RequestEnvelope = serde_json::from_slice(&bytes)?;
            assert_eq!(request.kind, kind);
            if kind != "RevokeGrant" {
                assert_eq!(request.payload["project_id"], id);
                assert_eq!(request.payload["profile_id"], "lk_prof_fixture");
                assert_eq!(request.payload["binding"], serde_json::to_value(&expected)?);
            }
            if kind == "RequestGrant" {
                assert_eq!(request.payload["action"], "SetSecret");
            } else {
                assert_eq!(request.payload["grant_id"], "native-grant");
            }
            let value = if kind == "RequestGrant" {
                serde_json::json!({"grant_id":"native-grant"})
            } else {
                serde_json::json!({"metadata_only":true})
            };
            let response = locket_agent::ResponseEnvelope::Success(
                locket_agent::SuccessEnvelope::new(request.id, value),
            );
            stream
                .write_all(&locket_agent::encode_frame(
                    &response,
                    locket_agent::DEFAULT_MAX_MESSAGE_SIZE,
                )?)
                .await?;
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });
    let result:serde_json::Value=invoke_granted_at(&socket,locket_agent::AgentMethod::SetSecret,locket_agent::GrantAction::SetSecret,serde_json::json!({"project_id":fixture.id,"profile_id":"lk_prof_fixture","binding":{"pid":0},"grant_id":"forged"}),&fixture.store,&context).await?;
    assert_eq!(result["metadata_only"], true);
    server.await?.map_err(|error| error.to_string())?;
    Ok(())
}

#[test]
fn denied_policy_readiness_does_not_hide_an_available_policy() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    fs::write(
        fixture.root.join("locket.toml"),
        format!(
            "schema_version=1\nproject_id='{}'\nname='fixture'\ndefault_profile='dev'\n[commands.allowed]\nargv=['echo']\nrequired_secrets=['CONFIG']\n[commands.denied]\nargv=['echo']\nrequired_secrets=['CONFIG']\n[variables.CONFIG]\nclassification='public'\ndefault='canary-public-default'\n[secrets.CONFIG]\nallow_commands=['allowed']\nallow_paths=['.']\n",
            fixture.id
        ),
    )?;
    let request = DesktopReadinessRequest { project_id: fixture.id.clone(), policy_name: None };
    let result = serde_json::to_value(variable_readiness_at(&fixture.store, &request)?)?;
    let policies = result["policies"].as_array().ok_or("policies")?;
    let denied =
        policies.iter().find(|policy| policy["policy_name"] == "denied").ok_or("denied")?;
    assert_eq!(denied["rows"], serde_json::json!([]));
    assert!(denied["error"].is_string());
    let allowed =
        policies.iter().find(|policy| policy["policy_name"] == "allowed").ok_or("allowed")?;
    assert!(allowed.get("error").is_none_or(serde_json::Value::is_null));
    assert_eq!(allowed["rows"][0]["state"], "ready");
    assert!(!result.to_string().contains("canary-public-default"));
    Ok(())
}

#[test]
fn readiness_scope_and_acl_use_verified_command_directory() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let cwd = fixture.root.join("services/api");
    fs::create_dir_all(&cwd)?;
    Store::open(&fixture.store)?.insert_profile_if_absent(
        "lk_prof_scoped",
        &fixture.id,
        "scoped",
        false,
        1,
    )?;
    let path = fixture.root.join("locket.toml");
    let text = fs::read_to_string(&path)?;
    fs::write(
        &path,
        format!(
            "{text}\n[paths.services]\nprofile='scoped'\nrequired_secrets=['NESTED']\n[secrets.NESTED]\nallow_commands=['test']\nallow_paths=['services/**']\n"
        ),
    )?;
    let context = open_project_at(&fixture.store, &fixture.root)?;
    let request = DesktopReadinessRequest {
        project_id: fixture.id.clone(),
        policy_name: Some("test".into()),
    };
    let nested = serde_json::to_value(variable_readiness_for_context(
        &fixture.store,
        &request,
        &context,
        &cwd,
    )?)?;
    assert_eq!(nested["policies"][0]["profile_id"], "lk_prof_scoped");
    assert_eq!(nested["policies"][0]["rows"][0]["name"], "NESTED");
    assert!(nested["policies"][0].get("error").is_none());
    let root = serde_json::to_value(variable_readiness_at(&fixture.store, &request)?)?;
    assert_eq!(root["policies"][0]["profile_id"], "lk_prof_fixture");
    assert_eq!(root["policies"][0]["rows"], serde_json::json!([]));
    let outside = fixture.directory.path().join("outside");
    fs::create_dir(&outside)?;
    assert!(variable_readiness_for_context(&fixture.store, &request, &context, &outside).is_err());
    Ok(())
}

#[test]
fn pending_profile_payload_pins_native_scope_and_rejects_webview_authority_fields()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let context = open_project_at(&fixture.store, &fixture.root)?;
    let payload = pending_reconcile_payload(
        &context,
        &fixture.store,
        "incoming-profile".into(),
        locket_agent::TeamSyncAction::RenameProfile {
            local_profile_id: "local-profile".into(),
            new_name: "preserved-local".into(),
        },
    )?;
    assert_eq!(payload["project_id"], fixture.id);
    assert_eq!(payload["profile_id"], "lk_prof_fixture");
    assert_eq!(payload["store_path"], serde_json::to_value(&fixture.store)?);
    assert_eq!(payload["incoming_profile_id"], "incoming-profile");
    assert_eq!(
        payload["action"],
        serde_json::json!({"kind":"rename_profile","local_profile_id":"local-profile","new_name":"preserved-local"})
    );
    assert!(payload["grant_id"].is_null());
    assert!(payload["binding"].is_null());
    assert!(serde_json::from_value::<DesktopRenameProfileRequest>(serde_json::json!({"project_id":fixture.id,"incoming_profile_id":"incoming","local_profile_id":"local","new_name":"name","store_path":"forged"})).is_err());
    assert!(serde_json::from_value::<DesktopPreserveOverrideRequest>(serde_json::json!({"project_id":fixture.id,"incoming_profile_id":"incoming","local_secret_id":"local","value":"not-accepted"})).is_err());
    Ok(())
}

#[tokio::test]
#[cfg(unix)]
async fn pending_profile_actions_use_team_sync_grants_and_return_status_metadata()
-> Result<(), Box<dyn Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fixture = Fixture::new()?;
    let context = open_project_at(&fixture.store, &fixture.root)?;
    let socket = fixture.directory.path().join("pending-grant.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let expected = native_binding()?;
    let id = fixture.id.clone();
    let server = tokio::spawn(async move {
        for kind in ["RequestGrant", "TeamSyncReconcile", "RevokeGrant"] {
            let (mut stream, _) = listener.accept().await?;
            let length = stream.read_u32_le().await?;
            let mut bytes = vec![0; length as usize];
            stream.read_exact(&mut bytes).await?;
            let request: locket_agent::RequestEnvelope = serde_json::from_slice(&bytes)?;
            assert_eq!(request.kind, kind);
            if kind != "RevokeGrant" {
                assert_eq!(request.payload["project_id"], id);
                assert_eq!(request.payload["profile_id"], "lk_prof_fixture");
                assert_eq!(request.payload["binding"], serde_json::to_value(&expected)?);
            }
            let value = if kind == "RequestGrant" {
                assert_eq!(request.payload["action"], "TeamSync");
                serde_json::json!({"grant_id":"pending-grant"})
            } else {
                assert_eq!(request.payload["grant_id"], "pending-grant");
                if kind == "TeamSyncReconcile" {
                    assert_eq!(request.payload["incoming_profile_id"], "incoming-profile");
                    assert_eq!(
                        request.payload["action"],
                        serde_json::json!({"kind":"preserve_override","local_secret_id":"local-secret"})
                    );
                    assert!(request.payload.get("value").is_none());
                }
                serde_json::to_value(locket_agent::team_sync::SyncStatus::default())?
            };
            let response = locket_agent::ResponseEnvelope::Success(
                locket_agent::SuccessEnvelope::new(request.id, value),
            );
            stream
                .write_all(&locket_agent::encode_frame(
                    &response,
                    locket_agent::DEFAULT_MAX_MESSAGE_SIZE,
                )?)
                .await?;
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });
    let payload = pending_reconcile_payload(
        &context,
        &fixture.store,
        "incoming-profile".into(),
        locket_agent::TeamSyncAction::PreserveOverride { local_secret_id: "local-secret".into() },
    )?;
    let result: locket_agent::team_sync::SyncStatus = invoke_granted_at(
        &socket,
        locket_agent::AgentMethod::TeamSyncReconcile,
        locket_agent::GrantAction::TeamSync,
        payload,
        &fixture.store,
        &context,
    )
    .await?;
    assert_eq!(result.applied, 0);
    assert!(serde_json::to_value(result)?.get("value").is_none());
    server.await?.map_err(|error| error.to_string())?;
    Ok(())
}
