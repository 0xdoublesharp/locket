//! Exercise process exit codes and stdio through the installed binary entry point.
#![allow(unused_crate_dependencies, clippy::multiple_crate_versions)]

#[cfg(unix)]
mod unix_tests {
    use std::fs;
    use std::path::Path;
    use std::process::{Command, Output, Stdio};

    use locket_core::LocketError;
    use serde_json::{Value, json};

    fn command(home: &Path, cwd: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_locket"));
        command
            .current_dir(cwd)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_RUNTIME_DIR", home)
            .env("LOCKET_INSTANCE", "dev")
            .stdin(Stdio::null());
        command
    }

    fn locket(home: &Path, cwd: &Path, args: &[&str]) -> Result<Output, std::io::Error> {
        command(home, cwd).args(args).output()
    }

    fn locket_with_input(
        home: &Path,
        cwd: &Path,
        args: &[&str],
        input: &[u8],
    ) -> Result<Output, Box<dyn std::error::Error>> {
        use std::io::Write;

        let mut child = command(home, cwd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().ok_or("missing child stdin")?.write_all(input)?;
        Ok(child.wait_with_output()?)
    }

    #[test]
    fn standalone_commands_leave_local_vault_directories_untouched()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = tempfile::tempdir()?;
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        let canary = "dotenv-synthetic-value-12679";
        fs::create_dir(root.join("frontend"))?;
        fs::create_dir(root.join("frontend/.git"))?;
        fs::write(root.join("frontend/.env.production.local"), format!("API_TOKEN={canary}\n"))?;
        fs::write(root.join(".env.test"), [0xff, 0xfe])?;
        fs::write(root.join(".env.template"), "TEMPLATE_ONLY=skipped\n")?;
        fs::write(root.join(".env"), format!("API_TOKEN={canary}\nOPENAI_API_KEY={canary}\n"))?;

        let completion = locket(home.path(), root, &["completion", "bash"])?;
        assert!(completion.status.success());
        assert!(String::from_utf8(completion.stdout)?.contains("_locket"));
        assert_eq!(completion.stderr, b"");

        let keys = locket(home.path(), root, &["env", "keys", ".env"])?;
        assert!(keys.status.success());
        assert_eq!(
            String::from_utf8(keys.stdout)?,
            "API_TOKEN\nOPENAI_API_KEY\ninvalid: 0\nmetadata_only: yes\n"
        );
        assert_eq!(keys.stderr, b"");

        let scan = locket(home.path(), root, &["env", "scan"])?;
        assert!(scan.status.success());
        let report = String::from_utf8(scan.stdout)?;
        for line in [
            "total_files: 3",
            "profile=prod",
            "profile=test",
            "dotenv input must be UTF-8",
            "shared_candidates: 2",
            "metadata_only: yes",
        ] {
            assert!(report.contains(line), "missing {line:?} in {report}");
        }
        assert!(!report.contains(canary));
        assert!(!report.contains(".env.template"));
        assert_eq!(scan.stderr, b"");

        let invalid = locket(home.path(), root, &["env", "keys", ".env.test", "--json"])?;
        assert_eq!(
            invalid.status.code(),
            Some(i32::from(LocketError::MetadataInvalid.exit_code()))
        );
        assert_eq!(invalid.stderr, b"");
        let report: Value = serde_json::from_slice(&invalid.stdout)?;
        assert_eq!(report["error"]["code"], "MetadataInvalid");
        assert_eq!(report["error"]["message"], "dotenv input must be UTF-8");

        let symlink = root.join(".env.link");
        std::os::unix::fs::symlink(root.join(".env"), &symlink)?;
        let rejected = locket(home.path(), root, &["env", "keys", ".env.link"])?;
        assert_eq!(
            rejected.status.code(),
            Some(i32::from(LocketError::MetadataInvalid.exit_code()))
        );
        assert_eq!(rejected.stdout, b"");
        assert_eq!(
            String::from_utf8(rejected.stderr)?,
            "locket: dotenv input must be a regular file\n"
        );
        assert_eq!(fs::read_dir(home.path())?.count(), 0);
        Ok(())
    }

    #[test]
    fn fresh_machine_reports_no_project_and_machine_readable_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = tempfile::tempdir()?;
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        let default = locket(home.path(), root, &[])?;
        assert!(default.status.success());
        assert!(String::from_utf8(default.stdout)?.contains("not initialized"));
        assert_eq!(default.stderr, b"");

        let status = locket(home.path(), root, &["status", "--json", "--scan"])?;
        assert!(status.status.success());
        let report: Value = serde_json::from_slice(&status.stdout)?;
        assert_eq!(report["has_locket_config"], false);
        assert_eq!(report["agent_running"], false);
        assert_eq!(status.stderr, b"");

        let list = locket(home.path(), root, &["project", "list", "--json"])?;
        assert!(list.status.success());
        assert_eq!(serde_json::from_slice::<Value>(&list.stdout)?, json!([]));
        assert_eq!(list.stderr, b"");

        let selector = "missing-project";
        let missing = locket(home.path(), root, &["discover", "--json", "--project", selector])?;
        let exit = LocketError::ProjectNotFound.exit_code();
        assert_eq!(missing.status.code(), Some(i32::from(exit)));
        assert_eq!(
            serde_json::from_slice::<Value>(&missing.stdout)?,
            json!({"error": {"code": "ProjectNotFound", "message": "project not found", "exit_code": exit}}),
        );
        assert_eq!(missing.stderr, b"");
        let human = locket(home.path(), root, &["discover", "--project", selector])?;
        assert_eq!(human.status.code(), Some(i32::from(exit)));
        assert_eq!(human.stdout, b"");
        assert_eq!(String::from_utf8(human.stderr)?, "locket: project not found\n");
        assert_eq!(fs::read_dir(root)?.count(), 0);
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn clipboard_helper_clears_only_a_matching_value() -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir()?;
        let tools = tempfile::tempdir()?;
        let clipboard = home.path().join("clipboard");
        let canary = "clipboard-synthetic-value-18426";

        let write_tool = |name: &str, script: &str| -> Result<(), std::io::Error> {
            let path = tools.path().join(name);
            fs::write(&path, format!("#!/bin/sh\n{script}\n"))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        };
        if cfg!(target_os = "macos") {
            write_tool("pbcopy", r#"/bin/cat > "$TEST_CLIPBOARD""#)?;
            write_tool("pbpaste", r#"/bin/cat "$TEST_CLIPBOARD""#)?;
        } else {
            write_tool(
                "xclip",
                r#"if [ "$3" = "-o" ]; then /bin/cat "$TEST_CLIPBOARD"; else /bin/cat > "$TEST_CLIPBOARD"; fi"#,
            )?;
        }

        for (prior, expected) in [
            (b"newer selection".as_slice(), b"newer selection".as_slice()),
            (&[0xff], &[0xff]),
            (canary.as_bytes(), &[]),
        ] {
            fs::write(&clipboard, prior)?;
            let mut child = command(home.path(), home.path())
                .args(["internal-clipboard-clear", "--ttl-seconds", "0"])
                .env("PATH", tools.path())
                .env("TEST_CLIPBOARD", &clipboard)
                .env("XDG_SESSION_TYPE", "x11")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            child
                .stdin
                .take()
                .ok_or("clipboard helper stdin missing")?
                .write_all(canary.as_bytes())?;
            let output = child.wait_with_output()?;
            assert!(output.status.success());
            assert_eq!(output.stdout, b"");
            assert_eq!(output.stderr, b"");
            assert!(fs::read(&clipboard)? == expected, "unexpected clipboard state");
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn agent_binary_starts_reports_locked_and_shuts_down_its_daemon()
    -> Result<(), Box<dyn std::error::Error>> {
        struct StopAgent<'a>(&'a Path);

        impl Drop for StopAgent<'_> {
            fn drop(&mut self) {
                let _ = command(Path::new("."), self.0).args(["agent", "stop"]).output();
            }
        }

        let home = tempfile::tempdir()?;
        let path = home.path();
        // Install cleanup before spawning so subsequent assertion failures still stop the daemon.
        let _cleanup = StopAgent(path);
        // Resolve the macOS socket relative to this isolated home to stay
        // within sockaddr_un's limit even when the harness uses a long TMPDIR.
        let run = |args: &[&str]| command(Path::new("."), path).args(args).output();
        let start = run(&["agent", "start"])?;
        assert!(start.status.success(), "{}", String::from_utf8_lossy(&start.stderr));
        let start = String::from_utf8(start.stdout)?;
        assert!(start.contains("agent: running\n"));
        let pid = start
            .lines()
            .find_map(|line| line.strip_prefix("pid: "))
            .ok_or("missing daemon PID")?
            .parse::<u32>()?;
        assert_ne!(pid, std::process::id());

        let status = run(&["agent", "status"])?;
        assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
        let status = String::from_utf8(status.stdout)?;
        for line in ["agent: running", "lock_state: locked", "live_grants: 0"] {
            assert!(status.lines().any(|actual| actual == line), "{status}");
        }
        assert!(status.contains(&format!("pid: {pid}\n")));

        let stop = run(&["agent", "stop"])?;
        assert!(stop.status.success(), "{}", String::from_utf8_lossy(&stop.stderr));
        assert!(String::from_utf8(stop.stdout)?.contains("agent: stopped\n"));
        let status = run(&["status", "--json"])?;
        assert!(status.status.success());
        assert_eq!(serde_json::from_slice::<Value>(&status.stdout)?["agent_running"], false);
        let agent_files = path.join("Library/Application Support/locket-dev");
        assert!(!agent_files.join("agent.pid").exists());
        assert!(!agent_files.join("agent.sock").exists());
        Ok(())
    }

    #[test]
    fn piped_input_errors_return_redacted_json_and_persist_no_values()
    -> Result<(), Box<dyn std::error::Error>> {
        const PROJECT: &str = "lk_proj_piped_fixture";
        let home = tempfile::tempdir()?;
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        fs::write(
            root.join("locket.toml"),
            format!(
                "schema_version=1\nproject_id='{PROJECT}'\nname='fixture'\ndefault_profile='dev'\n"
            ),
        )?;
        let status = locket(home.path(), root, &["status"])?;
        assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
        let paths: Vec<_> = ignore::WalkBuilder::new(home.path())
            .standard_filters(false)
            .build()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() == "store.db")
            .map(ignore::DirEntry::into_path)
            .collect();
        assert_eq!(paths.len(), 1, "expected exactly one isolated store");
        let store = locket_store::Store::open(&paths[0])?;
        store.insert_project_if_absent(PROJECT, "fixture", 1)?;
        store.insert_profile_if_absent("lk_profile_piped_fixture", PROJECT, "dev", false, 1)?;

        for (input, code, expected) in [
            (b"".as_slice(), "InvalidReference", "secret value cannot be empty"),
            (
                b"stdin-synthetic-canary\0suffix",
                "MetadataInvalid",
                "secret value cannot contain NUL bytes",
            ),
            (
                b"stdin-synthetic-canary\nsuffix\n",
                "MetadataInvalid",
                "secret value cannot contain newlines",
            ),
            (b"stdin-synthetic-canary\xff", "MetadataInvalid", "secret value must be valid UTF-8"),
        ] {
            let output = locket_with_input(
                home.path(),
                root,
                &["set", "SERVICE_KEY", "--project", PROJECT, "--profile", "dev", "--json"],
                input,
            )?;
            assert_eq!(output.status.code(), Some(64));
            assert_eq!(output.stderr, b"");
            let text = std::str::from_utf8(&output.stdout)?;
            assert!(!text.contains("stdin-synthetic-canary"));
            let json: Value = serde_json::from_str(text)?;
            assert_eq!(json["error"]["code"], code);
            assert!(
                json["error"]["message"]
                    .as_str()
                    .is_some_and(|message| message.starts_with(expected))
            );
        }

        let request = locket_with_input(
            home.path(),
            root,
            &["policy", "apply"],
            b"{\"stdin-synthetic-canary\":",
        )?;
        assert_eq!(request.status.code(), Some(64));
        assert_eq!(request.stdout, b"");
        assert_eq!(String::from_utf8(request.stderr)?, "locket: invalid policy editor request\n");
        assert_eq!(store.list_secrets_by_profile(PROJECT, "lk_profile_piped_fixture")?, Vec::new());
        Ok(())
    }

    #[test]
    fn status_scan_reports_only_counts_in_a_fresh_checkout()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = tempfile::tempdir()?;
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        let config = root.join("locket.toml");
        let canary = "ghp_123456789012345678901234567890123456";
        let valid = "schema_version=1\nproject_id='lk_proj_status_fixture'\nname='fixture'\ndefault_profile='dev'\n";
        fs::write(&config, valid)?;
        fs::write(root.join("fixture.txt"), format!("GITHUB_TOKEN={canary}\n"))?;
        let scanned = locket(home.path(), root, &["status", "--json", "--scan"])?;
        assert!(scanned.status.success(), "{}", String::from_utf8_lossy(&scanned.stderr));
        assert_eq!(scanned.stderr, b"");
        let text = String::from_utf8(scanned.stdout)?;
        assert!(!text.contains(canary));
        let report: Value = serde_json::from_str(&text)?;
        assert_eq!(report["scan_warnings"], 1);
        assert_eq!(report["has_locket_config"], true);
        assert_eq!(report["secret_count"], 0);
        assert_eq!(report["vault_unlocked"], Value::Null);

        fs::write(&config, format!("{valid}\n[commands.dev]\nargv='{canary}'\n"))?;
        let invalid = locket(home.path(), root, &["status", "--json"])?;
        assert_eq!(invalid.status.code(), Some(i32::from(LocketError::InvalidPolicy.exit_code())));
        assert_eq!(invalid.stderr, b"");
        let text = String::from_utf8(invalid.stdout)?;
        assert!(!text.contains(canary));
        let report: Value = serde_json::from_str(&text)?;
        assert_eq!(report["error"]["code"], "InvalidPolicy");
        assert_eq!(report["error"]["message"], "could not read project policy metadata");
        assert!(
            ignore::Walk::new(home.path())
                .filter_map(Result::ok)
                .all(|entry| entry.file_name() != "store.db"),
            "status --json must not create a vault store"
        );
        Ok(())
    }

    #[test]
    fn stdin_redaction_preserves_non_utf8_bytes_and_refuses_missing_known_coverage()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = tempfile::tempdir()?;
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        let canary = "ghp_123456789012345678901234567890123456";
        let mut input = format!("token={canary}\n").into_bytes();
        input.extend_from_slice(b"opaque=\xff\n");
        let redacted = locket_with_input(home.path(), root, &["redact", "--stdin"], &input)?;
        assert!(redacted.status.success());
        assert!(String::from_utf8_lossy(&redacted.stdout).contains("token=lk_redacted_PATTERN_1"));
        assert!(redacted.stdout.ends_with(b"opaque=\xff\n"));
        assert!(!String::from_utf8_lossy(&redacted.stdout).contains(canary));
        let diagnostic = String::from_utf8(redacted.stderr)?;
        assert!(diagnostic.contains("known-value redaction skipped: no project resolved"));
        assert!(diagnostic.contains("passed non-UTF-8 byte segment(s) through unchanged"));
        assert!(!diagnostic.contains(canary));

        let denied = locket_with_input(
            home.path(),
            root,
            &["redact", "--stdin", "--require-known"],
            &input,
        )?;
        assert_eq!(denied.status.code(), Some(i32::from(LocketError::ProjectNotFound.exit_code())));
        assert_eq!(denied.stdout, b"");
        assert_eq!(String::from_utf8(denied.stderr)?, "locket: project not found\n");
        Ok(())
    }

    #[test]
    fn mcp_stdio_validates_frame_bounds_and_never_echoes_invalid_request_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = tempfile::tempdir()?;
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        let input = concat!(
            "invalid-rpc-synthetic-canary\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":[],\"method\":\"ping\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\"}}\n",
        );
        let responses = locket_with_input(home.path(), root, &["mcp"], input.as_bytes())?;
        assert!(responses.status.success());
        assert_eq!(responses.stderr, b"");
        let text = String::from_utf8(responses.stdout)?;
        assert!(!text.contains("invalid-rpc-synthetic-canary"));
        let responses =
            text.lines().map(serde_json::from_str::<Value>).collect::<Result<Vec<_>, _>>()?;
        assert_eq!(responses.len(), 4);
        assert_eq!(responses[0]["error"]["code"], -32700);
        assert_eq!(responses[1]["error"]["code"], -32600);
        assert_eq!(responses[2]["error"]["code"], -32602);
        assert_eq!(responses[3]["result"]["protocolVersion"], "2025-11-25");

        let oversized = vec![b'x'; 1_048_577];
        let rejected = locket_with_input(home.path(), root, &["mcp"], &oversized)?;
        assert!(rejected.status.success());
        assert_eq!(rejected.stderr, b"");
        assert_eq!(
            serde_json::from_slice::<Value>(&rejected.stdout)?,
            json!({
                "jsonrpc": "2.0", "id": null,
                "error": {"code": -32600, "message": "request exceeds size limit"},
            }),
        );
        Ok(())
    }

    #[test]
    fn policy_edit_rejects_unsafe_editor_environment_before_writing_any_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let home = tempfile::tempdir()?;
        let workspace = tempfile::tempdir()?;
        let root = workspace.path();
        let config = "schema_version=1\nproject_id='lk_proj_editor_fixture'\nname='fixture'\ndefault_profile='dev'\n[commands.dev]\nargv=['true']\n";
        fs::write(root.join("locket.toml"), config)?;

        for (visual, editor, message) in [
            (None, None, "policy edit requires editor.default, VISUAL, or EDITOR"),
            (
                Some("vim --unsafe"),
                Some("true"),
                "policy editor must be a command name or absolute path without arguments",
            ),
            (None, Some("$EDITOR_CANARY"), "policy editor must not use shell expansion"),
        ] {
            let mut process = command(home.path(), root);
            process.args(["policy", "edit", "dev"]);
            for (key, value) in [("VISUAL", visual), ("EDITOR", editor)] {
                if let Some(value) = value {
                    process.env(key, value);
                } else {
                    process.env_remove(key);
                }
            }
            let result = process.output()?;
            assert_eq!(
                result.status.code(),
                Some(i32::from(LocketError::MetadataInvalid.exit_code()))
            );
            assert_eq!(result.stdout, b"");
            assert_eq!(String::from_utf8(result.stderr)?, format!("locket: {message}\n"));
            assert_eq!(fs::read_to_string(root.join("locket.toml"))?, config);
            assert_eq!(fs::read_dir(root)?.count(), 1);
        }
        Ok(())
    }
}
