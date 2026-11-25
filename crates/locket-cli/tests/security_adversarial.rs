//! Black-box regressions for the child environment and metadata-only MCP surface.
#![allow(unused_crate_dependencies, clippy::multiple_crate_versions)]

#[cfg(unix)]
mod unix {
    use std::error::Error;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::process::{Command, Stdio};

    use locket_exec::{ExecutionRequest, env_value, prepare_execution};
    use locket_store::Store;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    #[test]
    fn child_path_drops_relative_entries_and_preserves_explicit_symlinked_tools()
    -> Result<(), Box<dyn Error>> {
        let workspace = tempfile::tempdir()?;
        let tools = tempfile::tempdir()?;
        let helper = "locket-fixture-echo";
        symlink("/bin/false", workspace.path().join(helper))?;
        symlink("/bin/echo", tools.path().join(helper))?;
        let mut request = ExecutionRequest::strict(vec![helper.into(), "ready".into()]);
        request.inherit_env = vec!["PATH".into()];
        request.parent_env.insert(
            "PATH".into(),
            env_value(format!(":.:relative/bin:{}:/bin:", tools.path().display())),
        );
        request.locket_env.insert("APP_TOKEN".into(), env_value("synthetic-fixture"));

        let prepared = prepare_execution(&request)?;
        let path = prepared.env.get("PATH").ok_or("missing child PATH")?;
        assert_eq!(
            std::env::split_paths(path.as_str()).collect::<Vec<_>>(),
            [tools.path(), Path::new("/bin")]
        );
        let output = prepared.command().current_dir(workspace.path()).output()?;
        assert!(output.status.success());
        assert_eq!(output.stdout, b"ready\n");
        Ok(())
    }

    fn locket(home: &Path, cwd: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_locket"));
        command
            .current_dir(cwd)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_RUNTIME_DIR", home)
            .env("LOCKET_INSTANCE", "dev");
        command
    }

    fn mcp(home: &Path, cwd: &Path, input: &[u8]) -> Result<Vec<Value>, Box<dyn Error>> {
        let mut child = locket(home, cwd)
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().ok_or("MCP stdin missing")?.write_all(input)?;
        let output = child.wait_with_output()?;
        assert!(output.status.success());
        assert_eq!(output.stderr, b"");
        Ok(String::from_utf8(output.stdout)?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?)
    }

    fn call(id: u32, name: &str, arguments: &Value) -> Value {
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name": name, "arguments": arguments}})
    }

    fn tool_text(reply: &Value) -> Result<Value, Box<dyn Error>> {
        let text =
            reply["result"]["content"][0]["text"].as_str().ok_or("missing MCP tool result")?;
        Ok(serde_json::from_str(text)?)
    }

    #[test]
    fn mcp_denies_invalid_requests_and_value_tools_without_echoing_input()
    -> Result<(), Box<dyn Error>> {
        let home = tempfile::tempdir()?;
        let workspace = tempfile::tempdir()?;
        let canary = "mcp-synthetic-input-marker";
        let requests = [
            json!({"jsonrpc":"2.0","id":{},"method":"ping"}),
            call(1, "locket_list_projects", &json!([canary])),
            call(2, "locket_reveal_secret", &json!({"name": canary})),
            call(3, "locket_get_secret_metadata", &json!({"value": canary})),
            json!({"jsonrpc":"2.0","id":4,"method":"ping"}),
        ];
        let mut input = format!("{canary}\n").into_bytes();
        for request in requests {
            writeln!(input, "{request}")?;
        }
        let replies = mcp(home.path(), workspace.path(), &input)?;
        assert_eq!(replies.len(), 6);
        assert!(!serde_json::to_string(&replies)?.contains(canary));
        assert_eq!(replies[0]["error"]["code"], -32700);
        assert_eq!(replies[1]["error"]["code"], -32600);
        for reply in &replies[2..5] {
            assert_eq!(reply["result"]["isError"], true);
            assert_eq!(tool_text(reply)?["error"]["code"], "MetadataInvalid");
        }
        assert_eq!(replies[5]["result"], json!({}));

        let mut oversized = serde_json::to_vec(&call(
            5,
            "locket_list_projects",
            &json!({"redact_names": "x".repeat(1_048_576)}),
        ))?;
        oversized.push(b'\n');
        let replies = mcp(home.path(), workspace.path(), &oversized)?;
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0]["error"]["code"], -32600);
        assert_eq!(replies[0]["error"]["message"], "request exceeds size limit");
        Ok(())
    }

    #[test]
    fn mcp_keeps_dotenv_and_command_detection_inside_the_workspace() -> Result<(), Box<dyn Error>> {
        let home = tempfile::tempdir()?;
        let workspace = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let root = workspace.path();
        let canary = "outside-synthetic-dotenv-marker";
        fs::write(outside.path().join(".env"), format!("OUTSIDE_TOKEN={canary}\n"))?;
        fs::write(outside.path().join("locket.toml"), "[commands.dev]\nargv=['true']\n")?;
        fs::write(root.join("package.json"), r#"{"scripts":{"dev":"true"}}"#)?;
        symlink(outside.path().join(".env"), root.join(".env"))?;
        symlink(outside.path().join("locket.toml"), root.join("locket.toml"))?;
        symlink(outside.path(), root.join("other-project"))?;

        let mut input = Vec::new();
        for request in [
            call(1, "locket_inspect_env_keys", &json!({"path": ".env"})),
            call(2, "locket_inspect_env_keys", &json!({"path": "other-project/.env"})),
            call(3, "locket_detect_commands", &json!({})),
        ] {
            writeln!(input, "{request}")?;
        }
        let replies = mcp(home.path(), root, &input)?;
        assert_eq!(replies.len(), 3);
        assert!(!serde_json::to_string(&replies)?.contains(canary));
        assert_eq!(tool_text(&replies[0])?["error"]["code"], "MetadataInvalid");
        assert_eq!(tool_text(&replies[1])?["error"]["code"], "AccessDenied");
        assert_eq!(replies[2]["result"]["isError"], false);
        let commands = tool_text(&replies[2])?;
        assert_eq!(commands["commands"][0]["name"], "dev");
        assert_eq!(commands["commands"][0]["already_configured"], false);
        Ok(())
    }

    #[test]
    fn mcp_import_requires_the_named_projects_root_and_profile() -> Result<(), Box<dyn Error>> {
        let home = tempfile::tempdir()?;
        let workspace = tempfile::tempdir()?;
        let root_a = workspace.path().join("project-a");
        let root_b = workspace.path().join("project-b");
        let projects = [
            (&root_a, "lk_proj_security_a", "lk_profile_security_a", "dev"),
            (&root_b, "lk_proj_security_b", "lk_profile_security_b", "test"),
        ];
        for (root, project, _, profile) in projects {
            fs::create_dir(root)?;
            fs::write(
                root.join("locket.toml"),
                format!(
                    "schema_version=1\nproject_id='{project}'\nname='{project}'\ndefault_profile='{profile}'\n"
                ),
            )?;
            fs::write(root.join(".env"), "FIXTURE_TOKEN=synthetic-mcp-secret\n")?;
        }
        let output = locket(home.path(), &root_a).arg("status").output()?;
        assert!(output.status.success());
        let vault = ignore::WalkBuilder::new(home.path())
            .standard_filters(false)
            .build()
            .filter_map(Result::ok)
            .find(|entry| entry.file_name() == "store.db")
            .ok_or("missing isolated vault")?;
        let store = Store::open(vault.path())?;
        for (root, project, profile_id, profile) in projects {
            store.insert_project_if_absent(project, project, 1)?;
            store.insert_profile_if_absent(profile_id, project, profile, false, 1)?;
            let canonical = root.canonicalize()?;
            let display = canonical.to_str().ok_or("invalid fixture path")?;
            store.trust_project_root(
                project,
                &Sha256::digest(display.as_bytes()).into(),
                Some(display),
                1,
            )?;
        }
        drop(store);

        let import = |id, profile, path: &str| {
            call(
                id,
                "locket_import_env",
                &json!({
                    "project":"lk_proj_security_a", "profile":profile, "path":path, "dry_run":true,
                }),
            )
        };
        let mut input = Vec::new();
        for request in [
            import(1, "dev", ".env"),
            import(2, "dev", "../project-b/.env"),
            import(3, "test", ".env"),
            call(
                4,
                "locket_get_secret_metadata",
                &json!({
                    "project":"lk_proj_security_a", "profile":"dev", "name":"lk://test/FIXTURE_TOKEN",
                }),
            ),
        ] {
            writeln!(input, "{request}")?;
        }
        let replies = mcp(home.path(), &root_a, &input)?;
        assert_eq!(replies.len(), 4);
        assert_eq!(replies[0]["result"]["isError"], false);
        for (reply, code) in
            replies[1..].iter().zip(["AccessDenied", "ProfileNotFound", "InvalidSecretName"])
        {
            assert_eq!(reply["result"]["isError"], true);
            assert_eq!(tool_text(reply)?["error"]["code"], code);
        }
        assert!(!serde_json::to_string(&replies)?.contains("synthetic-mcp-secret"));
        Ok(())
    }
}
