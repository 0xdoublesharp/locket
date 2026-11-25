//! Exercise runtime validation and typed failures through the CLI process.
#![allow(unused_crate_dependencies, clippy::multiple_crate_versions)]

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_mutation_killers {
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    use std::path::Path;
    use std::process::{Child, Command, Output, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use locket_agent::{
        AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, ErrorEnvelope, RequestEnvelope, ResponseEnvelope,
        SuccessEnvelope, encode_frame,
    };
    use locket_platform::LocketInstance;
    use locket_store::Store;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    const PROJECT: &str = "lk_proj_mutation";
    const PROFILE: &str = "lk_prof_dev";
    const SHARED_PROJECT: &str = "lk_proj_shared_fixture";
    const GRANT_ID: &str = "lk_grant_0123456789abcdef0123456789abcdef";
    const AGENT_FIXTURE_MODE: &str = "LOCKET_MUTATION_FIXTURE_AGENT";

    #[test]
    fn last_external_source_is_validated_before_the_child_can_start()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let project_path = project.path();
        let store = initialize_project_store(project_path)?;
        fs::write(project_path.join("locket.toml"), POLICY)?;
        fs::write(project_path.join(".settings"), "PORT=synthetic-invalid-port\n")?;
        let _agent = start_agent(project_path)?;
        let output = command(project_path).args(["run", "serve"]).env("PORT", "9000").output()?;
        let stderr = String::from_utf8(output.stderr)?;
        let stdout = String::from_utf8(output.stdout)?;
        assert_eq!(output.status.code(), Some(65), "stdout={stdout:?}, stderr={stderr:?}");
        assert!(stderr.contains("PORT"), "{stderr}");
        assert!(stderr.contains("expected a signed 64-bit integer"), "{stderr}");
        assert!(!stderr.contains("synthetic-invalid-port"));
        assert!(!stdout.contains("synthetic-invalid-port"));
        assert!(!stdout.contains("child-started"), "{stdout}");
        assert_no_runtime_sessions(&store)?;
        Ok(())
    }

    #[test]
    fn egress_bindings_require_injected_names_and_exclusive_delivery()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let store = initialize_project_store(root)?;
        let _agent = start_agent(root)?;
        let duplicate = "egress-fixture-value";
        for (value, sibling_value, argument) in [
            ("/bin/echo", "separate", "child-started"),
            (duplicate, "separate", duplicate),
            (duplicate, duplicate, "child-started"),
        ] {
            let policy = format!(
                r#"
schema_version = 1
project_id = "lk_proj_mutation"
name = "mutation"
default_profile = "dev"

[commands.serve]
argv = ["/bin/echo", "{argument}"]
required_secrets = ["SERVICE_TOKEN"]
optional_secrets = ["SIBLING_TOKEN"]
external_env_sources = [{{ file = ".settings" }}]
env_mode = "strict"
"#,
            );
            fs::write(root.join("locket.toml"), policy)?;
            fs::write(
                root.join(".settings"),
                format!("SERVICE_TOKEN={value}\nSIBLING_TOKEN={sibling_value}\n"),
            )?;
            let stderr = denied_egress(root, "SERVICE_TOKEN=example.test")?;
            assert!(
                stderr.contains("egress-bound secret would also be delivered outside its binding"),
                "{stderr}"
            );
            assert!(!stderr.contains(value), "{stderr}");
        }

        for invalid in
            ["SERVICE_TOKEN=example.test=other", "SERVICE_TOKEN=", "bad-name=example.test"]
        {
            let stderr = denied_egress(root, invalid)?;
            assert!(stderr.contains("--egress-host requires SECRET_NAME=HOST_PATTERN"), "{stderr}");
        }
        fs::write(root.join("locket.toml"), POLICY)?;
        fs::write(root.join(".settings"), "")?;
        let stderr = denied_egress(root, "PORT=example.test")?;
        assert!(stderr.contains("--egress-host must name a secret injected by the run policy"));
        assert_no_runtime_sessions(&store)?;
        Ok(())
    }

    #[test]
    fn egress_tls_option_controls_child_trust_environment() -> Result<(), Box<dyn std::error::Error>>
    {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let mut store = initialize_project_store(root)?;
        let policy = format!(
            r#"
schema_version = 1
project_id = "{PROJECT}"
name = "mutation"
default_profile = "dev"

[commands.serve]
shell = '''if [ -n "$SSL_CERT_FILE" ]; then printf 'tls=on\n'; else printf 'tls=off\n'; fi'''
required_secrets = ["SERVICE_TOKEN"]
external_env_sources = [{{file = ".settings"}}]
env_mode = "strict"
require_agent = true
"#,
        );
        cache_policy(&mut store, root, &policy)?;
        fs::write(root.join(".settings"), "SERVICE_TOKEN=egress-tls-fixture\n")?;
        let _fixture = start_fixture_agent(root)?;
        for (flags, expected) in
            [(&[][..], "tls=on\n"), (&["--no-egress-tls-mitm"][..], "tls=off\n")]
        {
            let output = command(root)
                .args([
                    "run",
                    "--egress-host",
                    "SERVICE_TOKEN=example.test",
                    "--allow-uncontained-egress",
                ])
                .args(flags)
                .arg("serve")
                .output()?;
            let stdout = String::from_utf8(output.stdout)?;
            let stderr = String::from_utf8(output.stderr)?;
            assert!(stdout.contains(expected), "stdout={stdout:?}, stderr={stderr:?}");
            assert!(!stderr.contains("Locket blocked 0 egress request"), "{stderr}");
        }
        assert_eq!(
            fs::read_to_string(root.join(".fixture-grant-actions"))?,
            "RunPolicy\nRunPolicy\n"
        );
        Ok(())
    }

    #[test]
    fn egress_connect_allowlist_is_required_by_default() -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let mut store = initialize_project_store(root)?;
        let executable = std::env::current_exe()?;
        let program =
            serde_json::to_string(executable.to_str().ok_or("fixture path is not UTF-8")?)?;
        let policy = format!(
            r#"
schema_version = 1
project_id = "{PROJECT}"
name = "mutation"
default_profile = "dev"

[commands.serve]
argv = [{program}, "--exact", "unix_mutation_killers::egress_connect_probe", "--nocapture"]
required_secrets = ["SERVICE_TOKEN"]
external_env_sources = [{{file = ".settings"}}]
env_mode = "strict"
require_agent = true
"#,
        );
        cache_policy(&mut store, root, &policy)?;
        fs::write(root.join(".settings"), "SERVICE_TOKEN=egress-connect-fixture\n")?;
        fs::write(root.join(".fixture-egress-connect"), "")?;
        let _agent = start_fixture_agent(root)?;
        for (flags, expected) in [
            (&[][..], "403 Forbidden"),
            (&["--egress-allow-unlisted-connect"][..], "502 Bad Gateway"),
        ] {
            let output = command(root)
                .args([
                    "run",
                    "--egress-host",
                    "SERVICE_TOKEN=example.test",
                    "--allow-uncontained-egress",
                ])
                .args(flags)
                .arg("serve")
                .output()?;
            let stdout = String::from_utf8(output.stdout)?;
            let stderr = String::from_utf8(output.stderr)?;
            assert!(
                stdout.contains(&format!("broker status: HTTP/1.1 {expected}")),
                "{stdout} {stderr}"
            );
            assert!(stderr.contains("Locket blocked 1 egress request"), "{stderr}");
        }
        Ok(())
    }

    #[test]
    fn egress_connect_probe() -> Result<(), Box<dyn std::error::Error>> {
        if !Path::new(".fixture-egress-connect").exists() {
            return Ok(());
        }
        let proxy = std::env::var("HTTPS_PROXY")?;
        let (credentials, address) = proxy
            .strip_prefix("http://")
            .and_then(|url| url.split_once('@'))
            .ok_or("missing loopback broker configuration")?;
        let address: std::net::SocketAddr = address.parse()?;
        assert!(address.ip().is_loopback());
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(8)))?;
        let auth = data_encoding::BASE64.encode(credentials.as_bytes());
        // This uses a reserved name and only reads the broker status. No TLS or
        // application data is exchanged beyond the loopback proxy.
        write!(
            stream,
            "CONNECT locket-mutation.invalid:443 HTTP/1.1\r\nHost: locket-mutation.invalid:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        )?;
        let mut status = String::new();
        BufReader::new(stream).read_line(&mut status)?;
        writeln!(std::io::stdout().lock(), "broker status: {}", status.trim_end())?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn egress_requires_kernel_containment_unless_explicitly_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let mut store = initialize_project_store(root)?;
        let listener = UnixListener::bind(root.join("fixture.sock"))?;
        let policy = format!(
            r#"
schema_version = 1
project_id = "{PROJECT}"
name = "mutation"
default_profile = "dev"

[commands.serve]
shell = '''
if /usr/bin/nc -w 1 -U fixture.sock </dev/null 2>/dev/null; then
  printf 'socket available\n'
else
  printf 'socket denied\n'
fi
'''
required_secrets = ["SERVICE_TOKEN"]
external_env_sources = [{{file = ".settings"}}]
env_mode = "strict"
require_agent = true
"#,
        );
        cache_policy(&mut store, root, &policy)?;
        fs::write(root.join(".settings"), "SERVICE_TOKEN=egress-containment-fixture\n")?;
        let _agent = start_fixture_agent(root)?;
        for (flags, expected) in
            [(&[][..], "socket denied"), (&["--allow-uncontained-egress"][..], "socket available")]
        {
            let mut run = command(root);
            run.args(["run", "--egress-host", "SERVICE_TOKEN=example.test"])
                .args(flags)
                .arg("serve");
            let output = output_with_deadline(&mut run)?;
            let stdout = String::from_utf8(output.stdout)?;
            assert!(stdout.lines().any(|line| line == expected), "{stdout}");
        }
        let completed: u32 = store.connection().query_row(
            "SELECT COUNT(*) FROM runtime_sessions WHERE ended_at IS NOT NULL AND exit_status = 0",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(completed, 2);
        listener.set_nonblocking(true)?;
        let _connection = listener.accept()?;
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        Ok(())
    }

    #[test]
    fn invalid_policy_grant_responses_fail_before_launch() -> Result<(), Box<dyn std::error::Error>>
    {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let mut store = initialize_project_store(root)?;
        cache_policy(&mut store, root, POLICY)?;
        fs::write(root.join(".settings"), "PORT=9000\n")?;
        let _fixture = start_fixture_agent(root)?;
        for fault in ["binding", "project", "profile", "action", "id", "stale", "expiry", "ttl"] {
            fs::write(root.join(".fixture-grant-fault"), fault)?;
            let output = command(root).args(["run", "serve"]).output()?;
            let stdout = String::from_utf8(output.stdout)?;
            let stderr = String::from_utf8(output.stderr)?;
            assert_eq!(output.status.code(), Some(73), "{fault}: {stdout:?} {stderr:?}");
            assert!(stderr.contains("agent returned an invalid policy grant"), "{fault}: {stderr}");
            assert!(!stdout.contains("child-started"), "{fault}: {stdout}");
            assert_no_runtime_sessions(&store)?;
            let revoked = fs::read_to_string(root.join(".fixture-last-revoke"))?;
            assert_eq!(revoked, if fault == "id" { "invalid-fixture-id" } else { GRANT_ID });
            fs::remove_file(root.join(".fixture-last-revoke"))?;
        }
        Ok(())
    }

    #[test]
    fn redaction_covers_a_preserved_short_value_and_provider_tokens()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let mut store = initialize_project_store(root)?;
        let short_value = "g8v";
        let provider_token = "ghp_abcdef1234567890ABCDEF1234567890abcd";
        let config_dir = if cfg!(target_os = "macos") {
            vault_dir(root)?
        } else {
            let dirs = LocketInstance::Dev.project_dirs().ok_or("missing application directory")?;
            root.join("config").join(dirs.project_path())
        };
        fs::create_dir_all(&config_dir)?;
        fs::write(
            config_dir.join("config.toml"),
            "[runtime]\nsession_secret_name_retention = 'off'\n",
        )?;
        let script = format!(
            r#"printf 'selected=%s\n' "$SERVICE_TOKEN"; printf 'provider=%s\n' '{provider_token}'"#
        );
        let argv = serde_json::to_string(&["/bin/sh", "-c", &script])?;
        let policy = format!(
            r#"
schema_version = 1
project_id = "{PROJECT}"
name = "mutation"
default_profile = "dev"

[commands.serve]
argv = {argv}
required_secrets = ["SERVICE_TOKEN"]
require_agent = true
inherit_env = ["SERVICE_TOKEN"]
override = "preserve"

[commands.dev]
argv = ["/bin/echo", "unrelated-command"]
"#,
        );
        cache_policy(&mut store, root, &policy)?;
        store.connection().execute(
            "INSERT INTO secrets(
            id, project_id, profile_id, name, source, origin, required, current_version,
            state, created_at, updated_at
         ) VALUES ('fixture-secret', ?1, ?2, 'SERVICE_TOKEN', 'user-local',
                   'manual', 0, 1, 'active', 1, 1)",
            [PROJECT, PROFILE],
        )?;
        let _fixture = start_fixture_agent(root)?;
        let output = command(root)
            .args(["run", "--redact-output", "--", "/bin/sh", "-c", &script])
            .env("SERVICE_TOKEN", short_value)
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            stdout.contains("selected=[REDACTED:locket]"),
            "stdout={stdout:?}, stderr={stderr:?}"
        );
        assert!(stdout.contains("provider="), "{stdout}");
        assert!(!stdout.contains(short_value), "{stdout}");
        assert!(!stdout.contains(provider_token), "{stdout}");
        assert!(!stderr.contains(short_value));
        let session = store.connection().query_row(
            "SELECT policy_name, exit_status, secret_names_json FROM runtime_sessions",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        assert_eq!(session, ("serve".to_owned(), Some(0), "[]".to_owned()));
        assert_eq!(fs::read_to_string(root.join(".fixture-last-revoke"))?, GRANT_ID);
        Ok(())
    }

    #[test]
    fn new_command_names_are_unique_and_subtree_optional_names_still_require_permission()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let store = initialize_project_store(root)?;
        let work_dir = root.join("apps");
        fs::create_dir(&work_dir)?;
        for (allowed_command, expected_status) in [("dev_3", 68), ("other", 65)] {
            let policy = format!(
                r#"
schema_version = 1
project_id = "{PROJECT}"
name = "mutation"
default_profile = "dev"

[commands.dev]
argv = ["/bin/echo", "first"]
[commands.dev_2]
argv = ["/bin/echo", "second"]
[paths.apps]
optional_secrets = ["SCOPED_VALUE"]
[secrets.SCOPED_VALUE]
allow_commands = ["{allowed_command}"]
"#,
            );
            fs::write(root.join("locket.toml"), &policy)?;
            let mut run = command(root);
            run.current_dir(&work_dir).env("HOME", root).args([
                "run",
                "--",
                "/bin/echo",
                "child-started",
            ]);
            let output = output_with_deadline(&mut run)?;
            let stdout = String::from_utf8(output.stdout)?;
            let stderr = String::from_utf8(output.stderr)?;
            assert_eq!(output.status.code(), Some(expected_status), "{stdout:?} {stderr:?}");
            if allowed_command == "dev_3" {
                assert!(stdout.contains("proposed_command: dev_3"), "{stdout}");
            } else {
                assert!(stderr.contains("secret ACL denied command dev_3"), "{stderr}");
                assert!(!stdout.contains("proposed_command"));
            }
            assert!(!stdout.contains("child-started\n"));
            assert_eq!(fs::read_to_string(root.join("locket.toml"))?, policy);
        }
        assert_no_runtime_sessions(&store)?;
        Ok(())
    }

    #[test]
    fn setup_distinguishes_missing_optional_defaulted_and_deferred_configuration()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let store = initialize_project_store(root)?;
        let header = format!(
            r#"
schema_version = 1
project_id = "{PROJECT}"
name = "mutation"
default_profile = "dev"
[commands.serve]
argv = ["/bin/echo", "child-started"]
env_mode = "strict"
"#,
        );
        for (fields, next_action) in [
            (
                "required_secrets=['NEEDED']\n[variables.NEEDED]\ndescription='Get a local value'",
                "locket set NEEDED",
            ),
            (
                "required_secrets=['NEEDED']\n[variables.NEEDED]\nclassification='public'\ndefault='hint'",
                "locket run serve",
            ),
            ("optional_secrets=['OPTIONAL_SETTING']", "locket run serve"),
            (
                "required_secrets=['NEEDED']\nexternal_env_sources=['ide']",
                "locket env inspect serve",
            ),
            ("shared_secrets=['SHARED_SETTING']", "locket set SHARED_SETTING --project @shared"),
        ] {
            fs::write(root.join("locket.toml"), format!("{header}{fields}\n"))?;
            let output = command(root).args(["setup", "status"]).output()?;
            let stdout = String::from_utf8(output.stdout)?;
            assert!(output.status.success(), "{stdout:?} {:?}", output.stderr);
            assert!(
                stdout.lines().any(|line| line.strip_prefix("next_action: ") == Some(next_action)),
                "{stdout}"
            );
        }
        let _agent = StopAgent(root);
        let output = command(root).args(["run", "serve"]).output()?;
        assert_eq!(output.status.code(), Some(65), "{output:?}");
        assert!(String::from_utf8(output.stderr)?.contains("missing from @shared: SHARED_SETTING"));
        assert_no_runtime_sessions(&store)?;
        Ok(())
    }

    #[test]
    fn shared_policy_requires_live_unlock_status_from_both_vaults()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let store = initialize_project_store(root)?;
        store.insert_project_if_absent(SHARED_PROJECT, "@shared", 1)?;
        store.insert_profile_if_absent("lk_prof_shared", SHARED_PROJECT, "default", false, 1)?;
        store.connection().execute(
            "INSERT INTO secrets(
            id, project_id, profile_id, name, source, origin, required, current_version,
            state, created_at, updated_at
         ) VALUES ('shared-fixture', ?1, 'lk_prof_shared', 'SHARED_SETTING', 'user-local',
                   'manual', 0, 1, 'active', 1, 1)",
            [SHARED_PROJECT],
        )?;
        let policy = format!(
            r#"
schema_version = 1
project_id = "{PROJECT}"
name = "mutation"
default_profile = "dev"
[commands.serve]
argv = ["/bin/echo", "child-started"]
shared_secrets = ["SHARED_SETTING"]
"#,
        );
        fs::write(root.join("locket.toml"), policy)?;
        let _fixture = start_fixture_agent(root)?;
        for (fault, denied_vault) in [
            ("shared-locked", "the Global Vault"),
            ("project-locked", "the policy's project vault"),
            ("shared-wrong-project", "the Global Vault"),
        ] {
            fs::write(root.join(".fixture-status-fault"), fault)?;
            let output = command(root).args(["run", "serve"]).output()?;
            let stderr = String::from_utf8(output.stderr)?;
            assert_eq!(output.status.code(), Some(72), "{fault}: {stderr}");
            assert!(
                stderr.contains(&format!("unlock {denied_vault} before executing")),
                "{fault}: {stderr}"
            );
            assert!(!String::from_utf8(output.stdout)?.contains("child-started"));
        }
        assert_no_runtime_sessions(&store)?;
        Ok(())
    }

    #[test]
    fn ide_session_delivers_only_names_authorized_by_the_run_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let mut store = initialize_project_store(root)?;
        let policy = format!(
            r#"
schema_version = 1
project_id = "{PROJECT}"
name = "mutation"
default_profile = "dev"
[commands.serve]
shell = '''test "$SERVICE_TOKEN" = 'stored-fixture-value' && test -z "$OTHER_TOKEN" && printf 'ide-ready\n' '''
required_secrets = ["SERVICE_TOKEN"]
external_env_sources = ["ide"]
env_mode = "strict"
"#,
        );
        cache_policy(&mut store, root, &policy)?;
        let _fixture = start_fixture_agent(root)?;
        let empty =
            command(root).args(["run", "serve"]).env("LOCKET_IDE_ENV_SESSION", "").output()?;
        assert_eq!(empty.status.code(), Some(80), "{empty:?}");
        assert!(String::from_utf8(empty.stderr)?.contains("LOCKET_IDE_ENV_SESSION not set"));
        assert_no_runtime_sessions(&store)?;

        let output = command(root)
            .args(["run", "serve"])
            .env("LOCKET_IDE_ENV_SESSION", "fixture-session")
            .env("OTHER_TOKEN", "unexpected-parent-value")
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        assert!(
            stdout.contains("ide-ready\n"),
            "stdout={stdout:?}, stderr={:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!stdout.contains("stored-fixture-value"));
        assert!(!stdout.contains("unexpected-parent-value"));
        assert_eq!(
            fs::read_to_string(root.join(".fixture-resolutions"))?,
            "lk://dev/SERVICE_TOKEN\n"
        );
        Ok(())
    }

    fn output_with_deadline(command: &mut Command) -> Result<Output, Box<dyn std::error::Error>> {
        let mut child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        let start = Instant::now();
        while child.try_wait()?.is_none() {
            if start.elapsed() >= Duration::from_secs(10) {
                child.kill()?;
                child.wait()?;
                return Err("CLI did not finish before its test deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(child.wait_with_output()?)
    }

    #[cfg(target_os = "macos")]
    const FIXTURE_PASSPHRASE: &str = "fixture-only-passphrase";

    #[cfg(target_os = "macos")]
    #[test]
    fn interactive_setup_saves_the_explicitly_approved_command_without_running_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let _stop_daemon = StopAgent(root);
        let store = initialize_project_store(root)?;
        seed_fixture_audit_key(&store, root)?;
        fs::write(
            root.join("locket.toml"),
            format!(
                "schema_version=1\nproject_id='{PROJECT}'\nname='mutation'\ndefault_profile='dev'\n"
            ),
        )?;
        fs::write(root.join("package.json"), r#"{"scripts":{"dev":"touch should-not-run"}}"#)?;
        fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n")?;
        let transcript = run_in_fixture_terminal(
            root,
            Path::new("."),
            &["setup"],
            &[("type 'approve dev'", "approve dev"), ("locket passphrase:", FIXTURE_PASSPHRASE)],
        )?;
        let saved = locket_core::PolicyDocument::from_toml_str(&fs::read_to_string(
            root.join("locket.toml"),
        )?)?;
        let command = saved.commands.get("dev").ok_or(transcript)?;
        let locket_core::CommandSpec::Argv(argv) = &command.command else {
            return Err("detected command was saved as a shell script".into());
        };
        assert_eq!(argv, &["pnpm", "run", "dev"]);
        assert!(!root.join("should-not-run").exists());
        assert_no_runtime_sessions(&store)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn approved_subtree_optional_names_stay_out_of_the_saved_root_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let _stop_daemon = StopAgent(root);
        let store = initialize_project_store(root)?;
        seed_fixture_audit_key(&store, root)?;
        fs::create_dir(root.join("apps"))?;
        fs::write(
            root.join("locket.toml"),
            format!(
                "schema_version=1\nproject_id='{PROJECT}'\nname='mutation'\ndefault_profile='dev'\n[paths.apps]\noptional_secrets=['SUBTREE_OPTIONAL']\n"
            ),
        )?;
        let _fixture = start_fixture_agent(root)?;
        let transcript = run_in_fixture_terminal(
            root,
            Path::new("apps"),
            &["run", "--", "/bin/echo", "child-started"],
            &[("type 'approve dev'", "approve dev"), ("locket passphrase:", FIXTURE_PASSPHRASE)],
        )?;
        let saved = locket_core::PolicyDocument::from_toml_str(&fs::read_to_string(
            root.join("locket.toml"),
        )?)?;
        let command = saved.commands.get("dev").ok_or(transcript)?;
        assert_eq!(command.optional_secrets, [] as [locket_core::SecretName; 0]);
        assert_eq!(saved.path_scopes["apps"].optional_secrets[0].as_str(), "SUBTREE_OPTIONAL");
        let audit_count: u32 = store.connection().query_row(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'POLICY_UPDATE' AND status = 'SUCCESS'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(audit_count, 1);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn runtime_denials_keep_distinct_metadata_only_audit_reasons()
    -> Result<(), Box<dyn std::error::Error>> {
        let project = tempfile::tempdir()?;
        let root = project.path();
        let _stop_daemon = StopAgent(root);
        let mut store = initialize_project_store(root)?;
        seed_fixture_audit_key(&store, root)?;
        let _fixture = start_fixture_agent(root)?;
        let fixture_dialog = &[("locket passphrase:", FIXTURE_PASSPHRASE)];
        let file_policy = POLICY.replace("PORT", "SERVICE_TOKEN").replace(
        "[variables.SERVICE_TOKEN]\nclassification = \"public\"\ntype = \"integer\"\ndefault = \"8000\"",
        "",
    );
        fs::write(root.join("locket.toml"), &file_policy)?;
        fs::write(root.join(".settings"), "SERVICE_TOKEN=\"unterminated\n")?;
        run_in_fixture_terminal(root, Path::new("."), &["run", "serve"], fixture_dialog)?;

        let docker = root.join("docker");
        fs::write(&docker, "#!/bin/sh\nexit 7\n")?;
        fs::set_permissions(&docker, fs::Permissions::from_mode(0o700))?;
        let compose_policy =
            file_policy.replace("[\"parent\", { file = \".settings\" }]", "[\"compose\"]");
        fs::write(root.join("locket.toml"), &compose_policy)?;
        run_in_fixture_terminal(root, Path::new("."), &["run", "serve"], fixture_dialog)?;

        let ide_policy = file_policy.replace("[\"parent\", { file = \".settings\" }]", "[\"ide\"]");
        cache_policy(&mut store, root, &ide_policy)?;
        for error in ["AgentUnavailable", "GrantRequired"] {
            fs::write(root.join(".fixture-reference-fault"), error)?;
            run_in_fixture_terminal(root, Path::new("."), &["run", "serve"], fixture_dialog)?;
        }
        store.connection().execute(
            "INSERT INTO secrets(
            id, project_id, profile_id, name, source, origin, required, current_version,
            state, created_at, updated_at, expires_at
         ) VALUES ('expired-fixture', ?1, ?2, 'SERVICE_TOKEN', 'user-local',
                   'manual', 0, 1, 'active', 1, 1, 2)",
            [PROJECT, PROFILE],
        )?;
        fs::write(root.join("locket.toml"), &file_policy)?;
        run_in_fixture_terminal(root, Path::new("."), &["run", "serve"], fixture_dialog)?;

        let reasons = store
            .connection()
            .prepare(
                "SELECT json_extract(metadata_json, '$.failure_reason') FROM audit_log
              WHERE action = 'RUN_POLICY' AND status = 'DENIED' ORDER BY sequence",
            )?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            reasons,
            [
                "external_source_metadata_invalid",
                "external_source_unavailable",
                "agent_unavailable",
                "grant_required",
                "secret_expired"
            ]
        );
        assert_no_runtime_sessions(&store)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn seed_fixture_audit_key(
        store: &Store,
        root: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use locket_crypto::{
            HkdfWrapInfo, KeyPurpose, KeyWrapAad, derive_wrapping_key_v1, key_wrap_aad_v1,
            wrap_key_material_v1,
        };
        use locket_platform::PassphraseFallbackMasterKeyStore;

        let master = [7; 32];
        let fallback =
            PassphraseFallbackMasterKeyStore::new(vault_dir(root)?.join("passphrase-fallback"));
        fallback.store_master_key(PROJECT, &master, FIXTURE_PASSPHRASE.as_bytes(), 1)?;
        let id = "lk_key_mutation_audit";
        let purpose = KeyPurpose::Audit;
        let wrapping = derive_wrapping_key_v1(&master, &HkdfWrapInfo::new(PROJECT, None, purpose))?;
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(PROJECT, id, None, 0, purpose.into()))?;
        let wrapped = wrap_key_material_v1(&wrapping, &[11; 32], &aad)?;
        store.insert_key(&locket_store::KeyRecord {
            id: id.to_owned(),
            project_id: PROJECT.to_owned(),
            profile_id: None,
            purpose: purpose.as_str().to_owned(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: 1,
        })?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn run_in_fixture_terminal(
        root: &Path,
        relative_cwd: &Path,
        args: &[&str],
        dialog: &[(&str, &str)],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let home = if relative_cwd == Path::new(".") { "." } else { ".." };
        let mut paths = vec![root.to_path_buf()];
        if let Some(existing) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&existing));
        }
        let child = Command::new("/usr/bin/script")
            .current_dir(root.join(relative_cwd))
            .args(["-q", "/dev/null", env!("CARGO_BIN_EXE_locket")])
            .args(args)
            .env("HOME", home)
            .env("PATH", std::env::join_paths(paths)?)
            .env("LOCKET_INSTANCE", "dev")
            .env("LOCKET_IDE_ENV_SESSION", "fixture-session")
            .stdin(Stdio::piped())
            .stderr(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut child = FixtureAgent(child);
        let mut input = child.0.stdin.take().ok_or("missing terminal input")?;
        let mut output = child.0.stdout.take().ok_or("missing terminal output")?;
        let (sender, receiver) = std::sync::mpsc::channel();
        let _reader = std::thread::spawn(move || {
            let mut buffer = [0; 2048];
            while let Ok(count @ 1..) = output.read(&mut buffer) {
                if sender.send(buffer[..count].to_vec()).is_err() {
                    break;
                }
            }
        });
        let mut transcript = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(25);
        for (prompt, response) in dialog {
            while !String::from_utf8_lossy(&transcript).contains(prompt) {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let chunk = receiver.recv_timeout(remaining).map_err(|error| {
                    format!(
                        "fixture terminal did not show {prompt:?}: {error}: {}",
                        String::from_utf8_lossy(&transcript)
                    )
                })?;
                transcript.extend(chunk);
            }
            writeln!(input, "{response}")?;
            input.flush()?;
        }
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match receiver.recv_timeout(remaining) {
                Ok(chunk) => transcript.extend(chunk),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(error) => return Err(error.into()),
            }
        }
        child.0.wait()?;
        Ok(String::from_utf8_lossy(&transcript).into_owned())
    }

    fn cache_policy(
        store: &mut Store,
        root: &Path,
        policy: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let source_path = root.canonicalize()?.join("locket.toml");
        fs::write(&source_path, policy)?;
        let raw: toml::Value = toml::from_str(policy)?;
        let digest = locket_core::policy::policy_source_digest(&raw, "serve")?;
        store.upsert_command_policy_index(
            PROJECT,
            "serve",
            &serde_json::to_value(&raw["commands"]["serve"])?,
            &json!({"source_path": source_path, "source_digest": digest}),
            1,
            None,
        )?;
        Ok(())
    }

    fn start_fixture_agent(root: &Path) -> Result<FixtureAgent, Box<dyn std::error::Error>> {
        let child = Command::new(std::env::current_exe()?)
            .current_dir(root)
            .args(["--exact", "unix_mutation_killers::fixture_agent_process"])
            .env(AGENT_FIXTURE_MODE, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()?;
        let mut fixture = FixtureAgent(child);
        let start = Instant::now();
        while !root.join(".fixture-agent-ready").is_file() {
            if fixture.0.try_wait()?.is_some() || start.elapsed() >= Duration::from_secs(10) {
                return Err("fixture agent did not open its socket".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(fixture)
    }

    struct FixtureAgent(Child);

    impl Drop for FixtureAgent {
        fn drop(&mut self) {
            let _ignored = self.0.kill();
            let _ignored = self.0.wait();
        }
    }

    #[test]
    fn fixture_agent_process() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(AGENT_FIXTURE_MODE).is_none() {
            return Ok(());
        }
        let local = Path::new(".");
        let dir = LocketInstance::Dev.agent_data_dir(
            std::env::consts::OS,
            local,
            Some(local.as_os_str()),
        );
        let socket = dir.join("agent.sock");
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        fs::write(".fixture-agent-ready", [])?;
        for stream in listener.incoming() {
            let mut stream = stream?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut length = [0; 4];
            stream.read_exact(&mut length)?;
            let length = u32::from_le_bytes(length) as usize;
            if length > DEFAULT_MAX_MESSAGE_SIZE {
                return Err("fixture received an oversized agent frame".into());
            }
            let mut body = vec![0; length];
            stream.read_exact(&mut body)?;
            let request: RequestEnvelope = serde_json::from_slice(&body)?;
            let response = fixture_agent_response(&request)?;
            stream.write_all(&encode_frame(&response, DEFAULT_MAX_MESSAGE_SIZE)?)?;
        }
        Ok(())
    }

    fn fixture_agent_response(
        request: &RequestEnvelope,
    ) -> Result<ResponseEnvelope, Box<dyn std::error::Error>> {
        let payload = match request.method()? {
            AgentMethod::Status => Ok(fixture_status(&request.payload)),
            AgentMethod::Unlock => Ok(Value::Null),
            AgentMethod::IdeEnvSession
                if request.payload["session_id"] == "fixture-session"
                    && request.payload["project_id"] == PROJECT =>
            {
                Ok(json!({"env_names":["OTHER_TOKEN","SERVICE_TOKEN"],"ttl_seconds_remaining":60}))
            }
            AgentMethod::ResolveReference
                if request.payload["reference"] == "lk://dev/SERVICE_TOKEN" =>
            {
                if let Ok(error) = fs::read_to_string(".fixture-reference-fault") {
                    return Ok(ResponseEnvelope::Error(ErrorEnvelope::new(
                        request.id.clone(),
                        error,
                        "fixture reference failure",
                        false,
                    )));
                }
                let mut observations = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(".fixture-resolutions")?;
                writeln!(observations, "lk://dev/SERVICE_TOKEN")?;
                Ok(json!({"value": "stored-fixture-value", "version": 1, "profile_id": PROFILE}))
            }
            AgentMethod::RequestGrant => fixture_grant_response(&request.payload),
            AgentMethod::RevokeGrant => {
                let id =
                    request.payload["grant_id"].as_str().ok_or("revocation needs a grant id")?;
                fs::write(".fixture-last-revoke", id)?;
                Ok(Value::Null)
            }
            other => return Err(format!("unexpected fixture request {other:?}").into()),
        }?;
        Ok(ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), payload)))
    }

    fn fixture_status(payload: &Value) -> Value {
        let requested = payload["project_id"].as_str();
        let fault = fs::read_to_string(".fixture-status-fault").unwrap_or_default();
        let (project, lock_state) = match (fault.as_str(), requested) {
            ("shared-locked", Some(SHARED_PROJECT)) => (SHARED_PROJECT, "locked"),
            ("project-locked", Some(PROJECT)) => (PROJECT, "locked"),
            ("shared-wrong-project", Some(SHARED_PROJECT)) => (PROJECT, "unlocked"),
            (_, project) => (project.unwrap_or(PROJECT), "unlocked"),
        };
        json!({"project_id": project, "lock_state": lock_state})
    }

    fn fixture_grant_response(payload: &Value) -> Result<Value, Box<dyn std::error::Error>> {
        let action = payload["action"].as_str().ok_or("grant request must include an action")?;
        let mut observations =
            fs::OpenOptions::new().create(true).append(true).open(".fixture-grant-actions")?;
        writeln!(observations, "{action}")?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let mut reply = json!({
            "grant_id": GRANT_ID,
            "project_id": payload["project_id"],
            "profile_id": payload["profile_id"],
            "action": payload["action"],
            "binding": payload["binding"],
            "ttl_seconds": payload["ttl_seconds"],
            "expires_at_unix_nanos": (now + 60_000_000_000).to_string(),
        });
        let fault = fs::read_to_string(".fixture-grant-fault").unwrap_or_default();
        match fault.as_str() {
            "binding" => reply["binding"]["process_start_time"] = json!("different-start"),
            "project" => reply["project_id"] = json!("separate-project"),
            "profile" => reply["profile_id"] = json!("separate-profile"),
            "action" => reply["action"] = json!("ResolveReference"),
            "id" => reply["grant_id"] = json!("invalid-fixture-id"),
            "stale" => reply["expires_at_unix_nanos"] = json!(now.to_string()),
            "expiry" => reply["expires_at_unix_nanos"] = json!("invalid-timestamp"),
            "ttl" => reply["ttl_seconds"] = json!(3601),
            "" => {}
            _ => return Err("unknown fixture grant fault".into()),
        }
        Ok(reply)
    }

    fn denied_egress(root: &Path, binding: &str) -> Result<String, Box<dyn std::error::Error>> {
        let output = command(root)
            .args(["run", "--egress-host", binding, "--no-egress-tls-mitm", "serve"])
            .env_remove("PORT")
            .output()?;
        let stderr = String::from_utf8(output.stderr)?;
        assert_eq!(output.status.code(), Some(64), "{stderr}");
        assert!(!String::from_utf8(output.stdout)?.contains("child-started"));
        Ok(stderr)
    }

    fn vault_dir(root: &Path) -> Result<std::path::PathBuf, &'static str> {
        let data = LocketInstance::Dev.project_dirs().ok_or("missing application directory")?;
        Ok(if cfg!(target_os = "macos") {
            root.join("Library/Application Support").join(data.project_path())
        } else {
            root.join("data").join(data.project_path())
        })
    }

    fn initialize_project_store(root: &Path) -> Result<Store, Box<dyn std::error::Error>> {
        let vault_dir = vault_dir(root)?;
        fs::create_dir_all(&vault_dir)?;
        let mut store = Store::open(vault_dir.join("store.db"))?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT, "mutation", 1)?;
        store.insert_profile_if_absent(PROFILE, PROJECT, "dev", false, 1)?;
        let root_hash = Sha256::digest(root.canonicalize()?.to_string_lossy().as_bytes()).into();
        store.trust_project_root(PROJECT, &root_hash, None, 1)?;
        Ok(store)
    }

    fn assert_no_runtime_sessions(store: &Store) -> Result<(), rusqlite::Error> {
        let count =
            store.connection().query_row("SELECT COUNT(*) FROM runtime_sessions", [], |row| {
                row.get::<_, u32>(0)
            })?;
        assert_eq!(count, 0);
        Ok(())
    }

    fn start_agent(project: &Path) -> Result<StopAgent<'_>, std::io::Error> {
        let cleanup = StopAgent(project);
        let started = command(project).args(["agent", "start"]).output()?;
        assert!(started.status.success(), "{}", String::from_utf8_lossy(&started.stderr));
        Ok(cleanup)
    }

    struct StopAgent<'a>(&'a Path);

    impl Drop for StopAgent<'_> {
        fn drop(&mut self) {
            let _ignored = command(self.0).args(["agent", "stop"]).output();
        }
    }

    fn command(project: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_locket"));
        // Relative socket paths stay within sockaddr_un's limit under long TMPDIRs.
        command
            .current_dir(project)
            .env("HOME", ".")
            .env("XDG_CONFIG_HOME", project.join("config"))
            .env("XDG_DATA_HOME", project.join("data"))
            .env("XDG_RUNTIME_DIR", ".")
            .env("LOCKET_INSTANCE", "dev")
            .stdin(Stdio::null());
        command
    }

    const POLICY: &str = r#"
schema_version = 1
project_id = "lk_proj_mutation"
name = "mutation"
default_profile = "dev"

[commands.serve]
argv = ["/bin/echo", "child-started"]
required_secrets = ["PORT"]
external_env_sources = ["parent", { file = ".settings" }]

[variables.PORT]
classification = "public"
type = "integer"
default = "8000"
"#;
}
