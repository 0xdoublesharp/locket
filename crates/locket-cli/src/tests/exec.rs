#![allow(clippy::literal_string_with_formatting_args)]
#[allow(unused_imports)]
use super::*;

#[test]
fn exec_enforces_secret_acl_before_spawning() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey", "--name", "app"])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(
        &context,
        &test_secret_write_args("DATABASE_URL"),
        "local-test",
        "manual",
        1000,
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(b"\n[secrets.DATABASE_URL]\nallow_commands=['dev']\n")?;
    let result = run_with_context(
        Cli::try_parse_from(["locket", "exec", "--secret", "DATABASE_URL", "--", test_true()])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "secret ACL denied command exec");
    Ok(())
}

#[test]
fn exec_all_force_injects_active_profile_secrets_and_writes_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let db = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db, "postgres://localhost/app", "manual", 1_000)?;
    let api = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &api, "tok-v1", "manual", 2_000)?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--all",
            "--force",
            "--",
            test_shell(),
            "-c",
            "test \"$DATABASE_URL\" = \"postgres://localhost/app\" \
             && test \"$API_KEY\" = \"tok-v1\"",
        ])?,
        &context,
        &mut output,
    )?;
    assert_eq!(String::from_utf8(output)?, "");

    let store = crate::open_store(&context)?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'EXEC'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"EXEC\""));
    assert!(metadata.contains("\"all_mode\":true"));
    assert_eq!(serde_json::from_str::<serde_json::Value>(&metadata)?["argv_program"], test_shell());
    assert!(metadata.contains("\"arg_count\":3"));
    assert!(metadata.contains("\"API_KEY\""));
    assert!(metadata.contains("\"DATABASE_URL\""));
    assert!(!metadata.contains("postgres://localhost/app"));
    assert!(!metadata.contains("tok-v1"));
    Ok(())
}

#[test]
fn exec_all_requires_typed_confirmation_when_not_forced() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let setup = test_context_with_key_store(&directory, Arc::clone(&key_store));
    let db = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&setup, &db, "postgres://localhost/app", "manual", 1_000)?;

    let bad_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "wrong\n");
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "exec", "--all", "--", test_shell(), "-c", "true"])?,
        &bad_context,
        &mut output,
    );
    assert_error_contains(result, "confirmation did not match exec --all scope");
    let output = String::from_utf8(output)?;
    assert!(output.contains("exec_profile: dev"));
    assert!(output.contains(&format!("exec_argv_program: {}", test_shell())));
    assert!(output.contains("exec_secret_count: 1"));
    assert!(output.contains("exec_secret_names: DATABASE_URL"));
    assert!(output.contains("metadata_only: yes"));

    let good_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "exec --all dev\n",
    );
    let mut good_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "exec", "--all", "--", test_shell(), "-c", "true"])?,
        &good_context,
        &mut good_output,
    )?;
    Ok(())
}

#[test]
fn exec_without_secrets_or_all_errors() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "exec", "--", test_shell(), "-c", "true"])?,
        &context,
        &mut output,
    );
    assert_error_contains(result, "exec requires --all or at least one --secret");
    Ok(())
}

#[test]
fn exec_all_and_secret_flags_are_mutually_exclusive() {
    let result = Cli::try_parse_from([
        "locket",
        "exec",
        "--all",
        "--secret",
        "DATABASE_URL",
        "--",
        test_shell(),
        "-c",
        "true",
    ]);
    assert!(result.is_err(), "clap should reject combining --all and --secret");
}

#[test]
fn exec_injects_secret_into_child_scope() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let user_args =
        test_secret_write_args_for_source("DATABASE_URL", crate::SecretSourceArg::UserLocal);
    crate::set_secret_value(&context, &user_args, "user-db-value", "manual", 1_000)?;
    let machine_args =
        test_secret_write_args_for_source("DATABASE_URL", crate::SecretSourceArg::MachineLocal);
    crate::set_secret_value(&context, &machine_args, "machine-db-value", "manual", 2_000)?;

    let mut exec_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--secret",
            "DATABASE_URL",
            "--",
            test_shell(),
            "-c",
            "test \"$DATABASE_URL\" = \"machine-db-value\"",
        ])?,
        &context,
        &mut exec_output,
    )?;

    assert_eq!(String::from_utf8(exec_output)?, "");
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let session = store.connection().query_row(
        "SELECT policy_name, ended_at IS NOT NULL, exit_status, secret_names_json
         FROM runtime_sessions",
        [],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, Option<i32>>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    assert_eq!(session.0, None);
    assert!(session.1);
    assert_eq!(session.2, Some(0));
    assert_eq!(session.3, "[\"DATABASE_URL\"]");
    assert!(!session.3.contains("machine-db-value"));
    assert!(!session.3.contains("user-db-value"));

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'EXEC'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["action"], "EXEC");
    assert_eq!(metadata["status"], "SUCCESS");
    assert_eq!(metadata["all_mode"], false);
    assert_eq!(metadata["secret_names"], json!(["DATABASE_URL"]));
    assert_eq!(metadata["secret_sources"]["DATABASE_URL"], "machine-local");
    assert_eq!(metadata["argv_program"], test_shell());
    assert_eq!(metadata["arg_count"], 3);
    assert_eq!(metadata["command"], "exec");
    assert!(!metadata.to_string().contains("machine-db-value"));
    assert!(!metadata.to_string().contains("user-db-value"));
    Ok(())
}

#[test]
fn exec_secret_requires_unlocked_vault_before_spawn() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    let (project_id, _) = test_project_id_and_master_key(&context)?;
    context.key_store.delete_master_key(&project_id)?;

    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--secret",
            "DATABASE_URL",
            "--",
            test_shell(),
            "-c",
            "touch spawned-locked",
        ])?,
        &context,
        &mut output,
    );
    let Err(error) = result else {
        return Err("locked exec --secret must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UnlockRequired.exit_code());
    assert_eq!(String::from_utf8(output)?, "");
    assert!(!directory.path().join("spawned-locked").exists());
    Ok(())
}

#[test]
fn run_policy_injects_required_and_optional_secrets_without_printing_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    let api_args = test_secret_write_args("OPENAI_API_KEY");
    crate::set_secret_value(&context, &api_args, "sk_test_policy_value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "printf 'DATABASE_URL=%s\nOPENAI_API_KEY=%s\n' \"${DATABASE_URL:+present}\" \"${OPENAI_API_KEY:+present}\" > env-presence.txt"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["OPENAI_API_KEY"]
env_mode = "strict"
inherit_env = ["PATH"]
"#.replace("/bin/sh", test_shell()).replace("/usr/bin/true", test_true())).as_bytes(),
        )?;

    let mut inspect_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "env", "inspect", "--policy", "env_check"])?,
        &context,
        &mut inspect_output,
    )?;
    let inspect_output = String::from_utf8(inspect_output)?;
    assert!(inspect_output.contains("secret DATABASE_URL kind=required sources=user-local"));
    assert!(inspect_output.contains("secret OPENAI_API_KEY kind=optional sources=user-local"));
    assert!(inspect_output.contains("decision=inject"));
    assert!(!inspect_output.contains("postgres://localhost/app"));
    assert!(!inspect_output.contains("sk_test_policy_value"));

    let mut run_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "run", "env_check"])?,
        &context,
        &mut run_output,
    )?;
    assert_eq!(String::from_utf8(run_output)?, "");
    let presence = std::fs::read_to_string(directory.path().join("env-presence.txt"))?;
    assert_eq!(presence, "DATABASE_URL=present\nOPENAI_API_KEY=present\n");
    assert!(!presence.contains("postgres://localhost/app"));
    assert!(!presence.contains("sk_test_policy_value"));
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let session = store.connection().query_row(
        "SELECT policy_name, ended_at IS NOT NULL, exit_status, secret_names_json
         FROM runtime_sessions",
        [],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, Option<i32>>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    assert_eq!(session.0.as_deref(), Some("env_check"));
    assert!(session.1);
    assert_eq!(session.2, Some(0));
    assert_eq!(session.3, "[\"DATABASE_URL\",\"OPENAI_API_KEY\"]");
    Ok(())
}

#[test]
fn run_policy_audit_records_selected_source_by_precedence_without_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let user_args =
        test_secret_write_args_for_source("DATABASE_URL", crate::SecretSourceArg::UserLocal);
    crate::set_secret_value(&context, &user_args, "user-precedence-value", "manual", 1_000)?;
    let machine_args =
        test_secret_write_args_for_source("DATABASE_URL", crate::SecretSourceArg::MachineLocal);
    crate::set_secret_value(&context, &machine_args, "machine-precedence-value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "test \"$DATABASE_URL\" = \"machine-precedence-value\""]
required_secrets = ["DATABASE_URL"]
env_mode = "strict"
inherit_env = ["PATH"]
ttl = "30s"
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "env_check"])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["command"], "run");
    assert_eq!(metadata_json["secret_names"], json!(["DATABASE_URL"]));
    assert_eq!(metadata_json["allowed_secret_names"], json!(["DATABASE_URL"]));
    assert_eq!(metadata_json["required_secret_names"], json!(["DATABASE_URL"]));
    assert_eq!(metadata_json["policy_id"], "env_check");
    assert_eq!(metadata_json["external_sources"], json!([]));
    assert_eq!(metadata_json["confirmation_source"], json!(null));
    assert_eq!(metadata_json["child_exit"], json!(0));
    assert_eq!(metadata_json["override_explicit"], json!(false));
    assert_eq!(metadata_json["grant_actions"], json!(["RunPolicy"]));
    assert_eq!(metadata_json["ttl_seconds"], json!(30));
    assert!(metadata_json["process_id"].as_u64().is_some_and(|pid| pid > 0));
    assert!(metadata_json["process_start_time"].as_str().is_some_and(|start| !start.is_empty()));
    assert_eq!(
        metadata_json["secrets"],
        json!([{
            "name": "DATABASE_URL",
            "required": true,
            "selected_source": "machine-local",
            "selected_version": 1,
            "sources": ["machine-local", "user-local"]
        }])
    );
    assert!(!metadata.contains("machine-precedence-value"));
    assert!(!metadata.contains("user-precedence-value"));
    Ok(())
}

#[test]
fn run_warns_when_implicit_locket_override_replaces_parent_name_without_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    // Use a native child on Windows so this exact-value fixture does not depend
    // on Git's POSIX environment translation.
    #[cfg(windows)]
    let (name, argv) = (
        "USERNAME",
        vec![
            std::env::var("COMSPEC")?,
            "/D".to_owned(),
            "/C".to_owned(),
            "if %USERNAME%==locket-value (exit /b 0) else (exit /b 1)".to_owned(),
        ],
    );
    #[cfg(not(windows))]
    let (name, argv) = (
        "HOME",
        vec![
            test_shell().to_owned(),
            "-c".to_owned(),
            "test \"$HOME\" = \"locket-value\"".to_owned(),
        ],
    );
    assert!(std::env::var_os(name).is_some(), "fixture requires a parent {name}");
    let secret = test_secret_write_args(name);
    crate::set_secret_value(&context, &secret, "locket-value", "manual", 1_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            format!(
                r#"
[commands.env_check]
argv = {argv}
required_secrets = ["{name}"]
inherit_env = ["{name}"]
env_mode = "minimal"
"#,
                argv = serde_json::to_string(&argv)?
            )
            .as_bytes(),
        )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "run", "env_check"])?, &context, &mut output)?;
    let output = String::from_utf8(output)?;
    assert!(output.contains(&format!(
        "warning: implicit override=locket will replace existing env name(s): {name}"
    )));
    assert!(!output.contains("locket-value"));
    Ok(())
}

#[test]
fn run_policy_audit_records_child_exit_code_on_failure() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.fail_command]
argv = ["/bin/sh", "-c", "exit 17"]
env_mode = "strict"
inherit_env = ["PATH"]
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "run", "fail_command"])?,
        &context,
        &mut output,
    );
    let Err(error) = result else {
        return Err("policy with `exit 17` should propagate child exit".into());
    };
    assert_eq!(error.exit_code(), 17);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "FAILED");
    assert_eq!(metadata_json["child_exit"], json!(17));
    Ok(())
}

#[test]
fn parent_external_env_source_reinjects_only_allowed_names()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        &(r#"
schema_version = 1

[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["PARENT_ALLOWED"]
optional_secrets = ["PARENT_OPTIONAL"]
external_env_sources = ["parent"]
env_mode = "strict"
"#
        .replace("/bin/sh", test_shell())
        .replace("/usr/bin/true", test_true())),
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let parent_env = [
        ("PARENT_ALLOWED".to_owned(), locket_exec::env_value("from-parent")),
        ("PARENT_OPTIONAL".to_owned(), locket_exec::env_value("also-parent")),
        ("PARENT_DENIED".to_owned(), locket_exec::env_value("must-not-leak")),
    ]
    .into_iter()
    .collect::<locket_exec::EnvMap>();

    let project_root = tempdir()?;
    let external_env =
        crate::resolve_policy_external_env(policy, &parent_env, project_root.path())?;
    assert_eq!(external_env.len(), 2);
    assert_eq!(external_env.get("PARENT_ALLOWED").map(|value| value.as_str()), Some("from-parent"));
    assert_eq!(
        external_env.get("PARENT_OPTIONAL").map(|value| value.as_str()),
        Some("also-parent")
    );
    assert!(!external_env.contains_key("PARENT_DENIED"));

    let request = locket_exec::ExecutionRequest {
        argv: vec![test_shell().to_owned(), "-c".to_owned(), "true".to_owned()],
        parent_env,
        inherit_env: policy.inherit_env.clone(),
        external_env,
        locket_env: locket_exec::EnvMap::new(),
        env_mode: policy.env_mode,
        override_mode: policy.override_behavior,
    };
    let prepared = locket_exec::prepare_execution(&request)?;
    assert_eq!(prepared.env.get("PARENT_ALLOWED").map(|value| value.as_str()), Some("from-parent"));
    assert_eq!(
        prepared.env.get("PARENT_OPTIONAL").map(|value| value.as_str()),
        Some("also-parent")
    );
    assert!(!prepared.env.contains_key("PARENT_DENIED"));
    Ok(())
}

#[test]
fn file_external_env_source_loads_only_policy_allowed_names()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        &(r#"
schema_version = 1

[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["LOG_LEVEL"]
external_env_sources = [{ file = ".env.local" }]
env_mode = "strict"
"#
        .replace("/bin/sh", test_shell())
        .replace("/usr/bin/true", test_true())),
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;
    std::fs::write(
        project_root.path().join(".env.local"),
        "DATABASE_URL=postgres://localhost/app\nLOG_LEVEL=debug\nNOT_ALLOWED=denied\n",
    )?;
    let parent_env = locket_exec::EnvMap::new();

    let external_env =
        crate::resolve_policy_external_env(policy, &parent_env, project_root.path())?;
    assert_eq!(external_env.len(), 2);
    assert_eq!(
        external_env.get("DATABASE_URL").map(|value| value.as_str()),
        Some("postgres://localhost/app")
    );
    assert_eq!(external_env.get("LOG_LEVEL").map(|value| value.as_str()), Some("debug"));
    assert!(!external_env.contains_key("NOT_ALLOWED"));
    Ok(())
}

#[test]
fn env_inspect_reports_external_layers_without_values() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::write(
        directory.path().join(".env.local"),
        "DATABASE_URL=fixture-dsn\nLOG_LEVEL=debug\nNOT_ALLOWED=hidden\n",
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["LOG_LEVEL"]
external_env_sources = [{ file = ".env.local" }]
env_mode = "strict"
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "env", "inspect", "--policy", "env_check"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("external_layers names=DATABASE_URL,LOG_LEVEL"));
    assert!(output.contains("external_source file:.env.local decision=resolved"));
    assert!(output.contains("secret DATABASE_URL kind=required sources=none selected=none"));
    assert!(output.contains("conflicts=external-source decision=external-source"));
    assert!(output.contains("secret LOG_LEVEL kind=optional sources=none selected=none"));
    assert!(!output.contains("fixture-dsn"));
    assert!(!output.contains("debug"));
    assert!(!output.contains("hidden"));
    assert!(!output.contains("NOT_ALLOWED"));
    Ok(())
}

#[test]
fn path_scoped_env_sets_extend_policy_from_matching_subdirectory()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey", "--name", "app"])?,
        &context,
        &mut Vec::new(),
    )?;
    let api_dir = directory.path().join("apps").join("api").join("src");
    std::fs::create_dir_all(&api_dir)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.dev]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["BASE_URL"]
optional_secrets = ["BASE_OPT"]

[paths."apps/api"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["STRIPE_SECRET_KEY"]
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let api_context = RuntimeContext { cwd: api_dir, ..context.clone() };
    let mut api_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "env", "inspect", "--policy", "dev"])?,
        &api_context,
        &mut api_output,
    )?;
    let api_output = String::from_utf8(api_output)?;
    let scope_line = format!("path_scope={}", Path::new("apps").join("api").display());
    assert!(api_output.contains(&scope_line), "{api_output}");
    assert!(api_output.contains("secret BASE_URL kind=required"), "{api_output}");
    assert!(api_output.contains("secret DATABASE_URL kind=required"), "{api_output}");
    assert!(api_output.contains("secret STRIPE_SECRET_KEY kind=optional"), "{api_output}");

    let mut root_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "env", "inspect", "--policy", "dev"])?,
        &context,
        &mut root_output,
    )?;
    let root_output = String::from_utf8(root_output)?;
    assert!(!root_output.contains(&scope_line), "{root_output}");
    assert!(!root_output.contains("DATABASE_URL"), "{root_output}");
    Ok(())
}

#[test]
fn run_runner_adapters_expand_common_dev_commands() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    std::fs::write(
        directory.path().join("package.json"),
        r#"{"scripts":{"dev":"vite","test":"vitest"}}"#,
    )?;

    let dev = crate::expand_runner_command_for_tests("npm", &["dev".to_owned()], directory.path())?;
    assert_eq!(dev, ["npm", "run", "dev"]);

    let explicit = crate::expand_runner_command_for_tests(
        "npm",
        &["run".to_owned(), "test".to_owned(), "--".to_owned(), "--watch".to_owned()],
        directory.path(),
    )?;
    assert_eq!(explicit, ["npm", "run", "test", "--", "--watch"]);

    let cargo =
        crate::expand_runner_command_for_tests("cargo", &["test".to_owned()], directory.path())?;
    assert_eq!(cargo, ["cargo", "test"]);

    let uv = crate::expand_runner_command_for_tests(
        "uv",
        &["pytest".to_owned(), "-q".to_owned()],
        directory.path(),
    )?;
    assert_eq!(uv, ["uv", "run", "pytest", "-q"]);

    Ok(())
}

#[test]
fn run_runner_adapter_rejects_missing_package_script() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    std::fs::write(directory.path().join("package.json"), r#"{"scripts":{"dev":"vite"}}"#)?;

    let result =
        crate::expand_runner_command_for_tests("npm", &["build".to_owned()], directory.path());
    let Err(error) = result else {
        return Err("missing package script must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidPolicy.exit_code());
    assert!(error.to_string().contains("npm script not found"));
    Ok(())
}

#[test]
fn path_scoped_env_sets_extend_runner_policy_from_matching_subdirectory()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey", "--name", "app"])?,
        &context,
        &mut Vec::new(),
    )?;
    let api_dir = directory.path().join("apps").join("api");
    std::fs::create_dir_all(&api_dir)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[paths."apps/api"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["STRIPE_SECRET_KEY"]
"#,
        )?;

    let api_context = RuntimeContext { cwd: api_dir, ..context };
    let resolved = crate::require_project(&api_context)?;
    let effective = crate::load_effective_command_policy_for_argv(
        &resolved,
        crate::runner_policy_name_for_tests("cargo", &["test".to_owned()]),
        vec!["cargo".to_owned(), "test".to_owned()],
        &api_context.cwd,
    )?;
    assert_eq!(effective.policy.name, "cargo:test");
    assert_eq!(
        effective.policy.command,
        locket_core::CommandSpec::Argv(vec!["cargo".to_owned(), "test".to_owned(),])
    );
    assert_eq!(effective.path_scope_path.as_deref(), Some(std::path::Path::new("apps/api")));
    assert!(effective.policy.required_secrets.iter().any(|name| name.as_str() == "DATABASE_URL"));
    assert!(
        effective.policy.optional_secrets.iter().any(|name| name.as_str() == "STRIPE_SECRET_KEY")
    );
    Ok(())
}

#[test]
fn secret_acls_allow_named_policy_and_deny_other_commands() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey", "--name", "app"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.dev]
argv = ["npm", "run", "dev"]
required_secrets = ["DATABASE_URL"]

[commands.build]
argv = ["npm", "run", "build"]
required_secrets = ["DATABASE_URL"]

[secrets.DATABASE_URL]
allow_commands = ["dev"]
"#,
        )?;

    let resolved = crate::require_project(&context)?;
    let dev = crate::load_effective_command_policy(&resolved, "dev", &context.cwd)?;
    assert_eq!(dev.policy.name, "dev");

    let result = crate::load_effective_command_policy(&resolved, "build", &context.cwd);
    let Err(error) = result else {
        return Err("build policy must be denied by secret ACL".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidPolicy.exit_code());
    assert!(error.to_string().contains("secret ACL denied command build"));
    Ok(())
}

#[test]
fn secret_acls_apply_to_runner_identity_argv_and_path_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey", "--name", "app"])?,
        &context,
        &mut Vec::new(),
    )?;
    let api_dir = directory.path().join("apps").join("api");
    std::fs::create_dir_all(&api_dir)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[paths."apps/api"]
required_secrets = ["DATABASE_URL"]

[secrets.DATABASE_URL]
allow_commands = ["npm:dev"]
allow_argv = [["npm", "run", "dev"]]
allow_paths = ["apps/api/**"]
"#,
        )?;

    let api_context = RuntimeContext { cwd: api_dir, ..context };
    let resolved = crate::require_project(&api_context)?;
    let allowed = crate::load_effective_command_policy_for_argv(
        &resolved,
        "npm:dev",
        vec!["npm".to_owned(), "run".to_owned(), "dev".to_owned()],
        &api_context.cwd,
    )?;
    assert_eq!(allowed.policy.name, "npm:dev");

    let denied = crate::load_effective_command_policy_for_argv(
        &resolved,
        "npm:build",
        vec!["npm".to_owned(), "run".to_owned(), "build".to_owned()],
        &api_context.cwd,
    );
    let Err(error) = denied else {
        return Err("npm:build must be denied by secret ACL".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidPolicy.exit_code());
    assert!(error.to_string().contains("DATABASE_URL"));
    Ok(())
}

#[test]
fn file_external_env_source_rejects_absolute_path() -> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        &(r#"
schema_version = 1

[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = [{ file = "/etc/passwd" }]
env_mode = "strict"
"#
        .replace("/bin/sh", test_shell())
        .replace("/usr/bin/true", test_true())),
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;

    let result = crate::resolve_policy_external_env(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
    );
    let Err(error) = result else {
        return Err("absolute external env file paths must be rejected".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidPolicy.exit_code());
    Ok(())
}

#[test]
fn file_external_env_source_rejects_paths_outside_project_root()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        &(r#"
schema_version = 1

[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = [{ file = "../escape.env" }]
env_mode = "strict"
"#
        .replace("/bin/sh", test_shell())
        .replace("/usr/bin/true", test_true())),
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let outside = tempdir()?;
    std::fs::write(outside.path().join("escape.env"), "DATABASE_URL=postgres://escape\n")?;
    let project_root = tempdir_in(outside.path())?;

    let result = crate::resolve_policy_external_env(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
    );
    let Err(error) = result else {
        return Err("external env paths outside the project root must be rejected".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidPolicy.exit_code());
    Ok(())
}

/// runtime.md:117 requires that symlinks resolving outside the project root are
/// rejected. The `canonicalize()` + `starts_with()` check covers this; this
/// test pins the behaviour explicitly so future refactors can't regress.
#[cfg(unix)]
#[test]
fn file_external_env_source_rejects_symlink_resolving_outside_root()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        &(r#"
schema_version = 1

[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = [{ file = "linked.env" }]
env_mode = "strict"
"#
        .replace("/bin/sh", test_shell())
        .replace("/usr/bin/true", test_true())),
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;

    let outside = tempdir()?;
    let target = outside.path().join("real.env");
    std::fs::write(&target, "DATABASE_URL=postgres://escape\n")?;
    let project_root = tempdir_in(outside.path())?;
    // Create symlink inside the project root that points outside it.
    if std::os::unix::fs::symlink(&target, project_root.path().join("linked.env")).is_err() {
        // Skip on platforms/CI where symlink creation is not permitted.
        return Ok(());
    }

    let result = crate::resolve_policy_external_env(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
    );
    let Err(error) = result else {
        return Err("symlink resolving outside the project root must be rejected".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidPolicy.exit_code());
    Ok(())
}

/// Companion test to the above: a symlink that lives inside the project root
/// AND points to another file inside the project root must be accepted.
#[cfg(unix)]
#[test]
fn file_external_env_source_accepts_symlink_resolving_inside_root()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        &(r#"
schema_version = 1

[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = [{ file = "linked.env" }]
env_mode = "strict"
"#
        .replace("/bin/sh", test_shell())
        .replace("/usr/bin/true", test_true())),
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;

    let project_root = tempdir()?;
    let target = project_root.path().join("real.env");
    std::fs::write(&target, "DATABASE_URL=postgres://inside\n")?;
    // Create symlink inside project root pointing to a file inside project root.
    if std::os::unix::fs::symlink(&target, project_root.path().join("linked.env")).is_err() {
        return Ok(());
    }

    let env = crate::resolve_policy_external_env(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
    )?;
    // The required secret should be resolved from the symlinked file.
    assert!(env.contains_key("DATABASE_URL"));
    Ok(())
}

#[test]
fn compose_external_env_source_uses_process_stub_without_docker()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        &(r#"
schema_version = 1

[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["API_KEY", "LOG_LEVEL", "PORT"]
external_env_sources = ["compose"]
env_mode = "strict"
"#
        .replace("/bin/sh", test_shell())
        .replace("/usr/bin/true", test_true())),
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;
    let args = [
        "-c",
        r#"printf '%s' '{"environment":{"LOG_LEVEL":"debug","PORT":5432,"NOT_ALLOWED":"denied"},"services":{"web":{"environment":{"DATABASE_URL":"from-compose"}},"worker":{"environment":["API_KEY=from-compose-array","IGNORED=denied"]}}}'"#,
    ];
    let command = crate::ComposeConfigCommand::new(Path::new(test_shell()), &args);

    let external_env = crate::resolve_policy_external_env_with_compose_config_command(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
        &command,
        None,
    )?;

    assert_eq!(external_env.len(), 4);
    assert_eq!(external_env.get("DATABASE_URL").map(|value| value.as_str()), Some("from-compose"));
    assert_eq!(external_env.get("API_KEY").map(|value| value.as_str()), Some("from-compose-array"));
    assert_eq!(external_env.get("LOG_LEVEL").map(|value| value.as_str()), Some("debug"));
    assert_eq!(external_env.get("PORT").map(|value| value.as_str()), Some("5432"));
    assert!(!external_env.contains_key("NOT_ALLOWED"));
    assert!(!external_env.contains_key("IGNORED"));
    Ok(())
}

#[test]
fn compose_external_env_source_reports_command_failure_without_values()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        &(r#"
schema_version = 1

[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = ["compose"]
env_mode = "strict"
"#
        .replace("/bin/sh", test_shell())
        .replace("/usr/bin/true", test_true())),
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;
    let args = ["-c", "printf '%s' 'from-compose' >&2; exit 19"];
    let command = crate::ComposeConfigCommand::new(Path::new(test_shell()), &args);

    let result = crate::resolve_policy_external_env_with_compose_config_command(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
        &command,
        None,
    );

    let Err(error) = result else {
        return Err("failing docker compose config stub must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::ExternalSourceUnavailable.exit_code());
    let message = error.to_string();
    assert!(message.contains("docker compose config failed"));
    assert!(!message.contains("from-compose"));
    Ok(())
}

#[test]
fn compose_external_env_source_reports_missing_command_with_typed_error()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        &(r#"
schema_version = 1

[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = ["compose"]
env_mode = "strict"
"#
        .replace("/bin/sh", test_shell())
        .replace("/usr/bin/true", test_true())),
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;
    let missing = project_root.path().join("missing-docker");
    let command = crate::ComposeConfigCommand::new(&missing, &["compose", "config"]);

    let result = crate::resolve_policy_external_env_with_compose_config_command(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
        &command,
        None,
    );

    let Err(error) = result else {
        return Err("missing compose config command must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::ExternalSourceUnavailable.exit_code());
    assert!(error.to_string().contains("could not be started"));
    Ok(())
}

#[test]
fn compose_external_env_source_rejects_invalid_json() -> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        &(r#"
schema_version = 1

[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = ["compose"]
env_mode = "strict"
"#
        .replace("/bin/sh", test_shell())
        .replace("/usr/bin/true", test_true())),
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;
    let args = ["-c", "printf '%s' 'not json'"];
    let command = crate::ComposeConfigCommand::new(Path::new(test_shell()), &args);

    let result = crate::resolve_policy_external_env_with_compose_config_command(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
        &command,
        None,
    );

    let Err(error) = result else {
        return Err("invalid docker compose config JSON must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::ExternalSourceUnavailable.exit_code());
    assert!(error.to_string().contains("invalid JSON"));
    Ok(())
}

#[test]
fn ide_external_env_source_without_agent_context_returns_typed_error()
-> Result<(), Box<dyn std::error::Error>> {
    // The `env` and `env inspect` paths call resolve_policy_external_env
    // without bringing an agent socket; they must still surface a typed
    // IdeEnvSessionUnavailable so the operator is told to switch to
    // `locket run`.
    let document = locket_core::PolicyDocument::from_toml_str(
        &(r#"
schema_version = 1

[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = ["ide"]
env_mode = "strict"
"#
        .replace("/bin/sh", test_shell())
        .replace("/usr/bin/true", test_true())),
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;

    let result = crate::resolve_policy_external_env(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
    );

    let Err(error) = result else {
        return Err("ide external env source must fail without agent context".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::IdeEnvSessionUnavailable.exit_code());
    assert_eq!(error.exit_code(), 80);
    let message = error.to_string();
    assert!(message.contains("IdeEnvSessionUnavailable"), "error must be typed, got: {message}");
    assert!(
        message.contains("requires `locket run`") || message.contains("LOCKET_IDE_ENV_SESSION"),
        "error must carry an actionable reason, got: {message}"
    );
    Ok(())
}

fn docker_test_env(directory: &tempfile::TempDir) -> locket_exec::EnvMap {
    locket_exec::EnvMap::from([
        ("PATH".into(), locket_exec::env_value("/bin")),
        (
            "DOCKER_CONFIG".into(),
            locket_exec::env_value(directory.path().join("docker-config").to_string_lossy()),
        ),
    ])
}

fn init_docker_test_project(
    context: &RuntimeContext,
    secret: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(context, &test_secret_write_args("API_KEY"), secret, "manual", 1_000)?;
    Ok(())
}

struct DockerNonInteractiveConfirmation;

impl crate::ConfirmationReader for DockerNonInteractiveConfirmation {
    fn read_confirmation(&self, prompt: &str) -> Result<String, crate::CliError> {
        crate::runtime::prompts::read_stdin_confirmation(prompt, false)
    }
}

#[test]
fn docker_policy_plan_and_audit_are_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    let api_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &api_args, "sk_test_docker_value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.docker_app]
argv = ["docker", "run", "app"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["API_KEY"]
env_mode = "strict"
inherit_env = ["PATH", "DOCKER_CONFIG", "DOCKER_HOST"]
"#,
        )?;

    let parsed = Cli::try_parse_from([
        "locket",
        "env",
        "docker",
        "--policy",
        "docker_app",
        "--",
        "docker",
        "run",
        "alpine",
    ])?;
    assert!(matches!(
        parsed.command,
        Some(crate::Command::Env { command: crate::EnvCommand::Docker(_) })
    ));

    let parent_env = docker_test_env(&directory);
    let docker_argv = vec!["docker".to_owned(), "run".to_owned(), "alpine".to_owned()];
    let mut prepared =
        crate::prepare_docker_policy_execution(&context, "docker_app", &docker_argv, parent_env)?;
    assert_eq!(prepared.execution.program, "docker");
    assert!(prepared.plan.argv.windows(2).any(|pair| pair == ["--env", "API_KEY"]));
    assert!(prepared.plan.argv.windows(2).any(|pair| pair == ["--env", "DATABASE_URL"]));
    let argv_text = prepared.plan.argv.join(" ");
    assert!(!argv_text.contains("postgres://localhost/app"));
    assert!(!argv_text.contains("sk_test_docker_value"));

    let metadata = crate::docker_policy_audit_metadata(&prepared, "SUCCESS");
    let metadata_text = metadata.to_string();
    assert!(metadata_text.contains("DATABASE_URL"));
    assert!(metadata_text.contains("API_KEY"));
    assert!(metadata_text.contains("environment_names"));
    assert!(metadata_text.contains("\"argv_program\":\"docker\""));
    assert!(!metadata_text.contains("postgres://localhost/app"));
    assert!(!metadata_text.contains("sk_test_docker_value"));

    crate::write_docker_policy_audit_if_available(&context, &mut prepared, "SUCCESS")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("DATABASE_URL"));
    assert!(audit_metadata.contains("API_KEY"));
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    assert!(!audit_metadata.contains("sk_test_docker_value"));
    Ok(())
}

#[test]
fn compose_policy_plan_supports_options_and_denies_remote_by_default()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let api_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &api_args, "sk_test_compose_value", "manual", 1_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.compose_app]
argv = ["docker", "compose", "up"]
required_secrets = ["API_KEY"]
env_mode = "strict"
inherit_env = ["PATH", "DOCKER_CONFIG", "DOCKER_HOST"]
"#,
        )?;

    let parsed = Cli::try_parse_from([
        "locket",
        "compose",
        "run",
        "--policy",
        "compose_app",
        "--project-directory",
        ".",
        "--profile",
        "web",
        "--",
        "docker",
        "compose",
        "up",
    ])?;
    assert!(matches!(
        parsed.command,
        Some(crate::Command::Compose { command: crate::ComposeCommand::Run(_) })
    ));

    let argv = crate::compose_argv_with_options(
        vec!["docker".to_owned(), "compose".to_owned(), "up".to_owned()],
        Some(Path::new(".")),
        &["web".to_owned()],
    )?;
    assert_eq!(argv, ["docker", "compose", "--project-directory", ".", "--profile", "web", "up"]);
    let parent_env = docker_test_env(&directory);
    let prepared =
        crate::prepare_compose_policy_execution(&context, "compose_app", &argv, parent_env)?;
    assert_eq!(
        prepared.plan.argv,
        prepared.execution.args.iter().fold(
            vec![prepared.execution.program.clone()],
            |mut values, arg| {
                values.push(arg.clone());
                values
            }
        )
    );
    assert_eq!(prepared.plan.injected_names, ["API_KEY"]);
    assert!(!prepared.plan.argv.join(" ").contains("sk_test_compose_value"));
    assert_eq!(
        prepared.execution.env.get("API_KEY").map(|value| value.as_str()),
        Some("sk_test_compose_value")
    );

    let remote_env =
        std::iter::once(("DOCKER_HOST".to_owned(), locket_exec::env_value("ssh://builder")))
            .collect();
    let remote_argv = vec!["docker".to_owned(), "compose".to_owned(), "up".to_owned()];
    let Err(error) =
        crate::prepare_compose_policy_execution(&context, "compose_app", &remote_argv, remote_env)
    else {
        return Err("remote Docker context should be denied".into());
    };
    let message = error.to_string();
    assert!(message.contains("remote Docker context is denied by default"));
    assert!(!message.contains("sk_test_compose_value"));
    Ok(())
}

#[test]
fn context_reports_metadata_only_summaries_without_values() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    let api_args = test_secret_write_args("OPENAI_API_KEY");
    crate::set_secret_value(&context, &api_args, "sk_test_context_value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["MISSING_ONLY", "OPENAI_API_KEY"]
confirm = true
require_user_verification = true
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let locked_context = test_context_with_key_store(
        &directory,
        std::sync::Arc::new(MemoryMasterKeyStore::default()),
    );
    let mut context_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "context"])?,
        &locked_context,
        &mut context_output,
    )?;

    let context_output = String::from_utf8(context_output)?;
    assert!(context_output.contains("Project: app"));
    assert!(context_output.contains("Profile: dev"));
    assert!(context_output.contains("- dev active=yes dangerous=no secrets=2"));
    assert!(context_output.contains(
        "- DATABASE_URL profiles=dev,policy:env_check sources=policy-required,user-local"
    ));
    assert!(context_output.contains(
        "- OPENAI_API_KEY profiles=dev,policy:env_check sources=policy-optional,user-local"
    ));
    assert!(
        context_output.contains("- MISSING_ONLY profiles=policy:env_check sources=policy-optional")
    );
    assert!(context_output.contains("- env_check type=argv"));
    assert!(context_output.contains("required=DATABASE_URL"));
    assert!(context_output.contains("optional=MISSING_ONLY,OPENAI_API_KEY"));
    assert!(context_output.contains("confirm=yes verify_user=yes"));
    assert!(context_output.contains("No secret values included."));
    assert!(context_output.contains("metadata_only: yes"));
    assert!(!context_output.contains("postgres://localhost/app"));
    assert!(!context_output.contains("sk_test_context_value"));
    Ok(())
}

#[test]
fn context_redacts_names_from_flag_or_privacy_config() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let mut flag_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "context", "--redact-names"])?,
        &context,
        &mut flag_output,
    )?;
    let flag_output = String::from_utf8(flag_output)?;
    assert!(flag_output.contains("Project: project-"));
    assert!(flag_output.contains("Profile: profile-"));
    assert!(flag_output.contains("secret-"));
    assert!(flag_output.contains("policy-"));
    assert!(!flag_output.contains("Project: app"));
    assert!(!flag_output.contains("Profile: dev"));
    assert!(!flag_output.contains("DATABASE_URL"));
    assert!(!flag_output.contains("env_check"));
    assert!(!flag_output.contains("postgres://localhost/app"));

    let mut config_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut config_output,
    )?;
    let mut configured_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "context"])?,
        &context,
        &mut configured_output,
    )?;
    let configured_output = String::from_utf8(configured_output)?;
    assert!(configured_output.contains("Project: project-"));
    assert!(!configured_output.contains("DATABASE_URL"));
    assert!(!configured_output.contains("env_check"));
    Ok(())
}

#[test]
fn run_policy_confirm_gate_rejects_wrong_confirmation() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.deploy]
argv = ["/bin/sh", "-c", "true"]
confirm = true
env_mode = "strict"
inherit_env = ["PATH"]
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let bad_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "wrong\n");
    let result = run_with_context(
        Cli::try_parse_from(["locket", "run", "deploy"])?,
        &bad_context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("policy with confirm=true must reject wrong confirmation".into());
    };
    assert_eq!(error.exit_code(), 68);
    assert!(error.to_string().contains("confirmation did not match run scope"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'RUN_POLICY'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0, "rejected run must not write a RUN_POLICY audit row");
    Ok(())
}

#[test]
fn run_policy_confirm_gate_accepts_typed_confirmation() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.deploy]
argv = ["/bin/sh", "-c", "true"]
confirm = true
env_mode = "strict"
inherit_env = ["PATH"]
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let good_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "run deploy\n",
    );
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "run", "deploy"])?,
        &good_context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("type 'run deploy' to confirm run"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "SUCCESS");
    assert_eq!(metadata_json["confirmation_source"], json!("interactive"));
    assert_eq!(metadata_json["policy"], "deploy");
    Ok(())
}

#[test]
fn run_policy_user_verification_gate_rejects_when_unsatisfied()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.sensitive]
argv = ["/bin/sh", "-c", "true"]
require_user_verification = true
env_mode = "strict"
inherit_env = ["PATH"]
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    let cases: [(&str, Arc<dyn LocalUserVerifier + Send + Sync>); 3] = [
        ("denied", Arc::new(MemoryLocalUserVerifier::denying())),
        ("cancelled", Arc::new(MemoryLocalUserVerifier::cancelled())),
        ("unavailable", Arc::new(MemoryLocalUserVerifier::unavailable())),
    ];
    for (label, verifier) in cases {
        let rejecting_context = context_with_user_verifier(&context, verifier);
        let result = run_with_context(
            Cli::try_parse_from(["locket", "run", "sensitive"])?,
            &rejecting_context,
            &mut Vec::new(),
        );
        let Err(error) = result else {
            return Err(format!("policy must reject {label} user verification").into());
        };
        assert_eq!(error.exit_code(), 74);
        assert!(error.to_string().contains("local user verification"));
    }

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'RUN_POLICY'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0, "rejected verification must not write a RUN_POLICY audit row");
    Ok(())
}

#[test]
fn run_policy_user_verification_gate_records_method_on_success()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.sensitive]
argv = ["/bin/sh", "-c", "true"]
require_user_verification = true
env_mode = "strict"
inherit_env = ["PATH"]
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "sensitive"])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "SUCCESS");
    assert_eq!(metadata_json["user_verification"]["required"], json!(true));
    assert_eq!(metadata_json["user_verification"]["satisfied"], json!(true));
    assert_eq!(metadata_json["user_verification"]["method"], json!("test"));
    Ok(())
}

#[test]
fn run_policy_user_verification_metadata_is_unsatisfied_when_not_required()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.unprotected]
argv = ["/bin/sh", "-c", "true"]
env_mode = "strict"
inherit_env = ["PATH"]
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "unprotected"])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["user_verification"]["required"], json!(false));
    assert_eq!(metadata_json["user_verification"]["satisfied"], json!(false));
    assert_eq!(metadata_json["user_verification"]["method"], json!(null));
    Ok(())
}

#[test]
#[cfg(unix)]
fn run_shell_policy_executes_via_sh_and_audits_shape_shell()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let marker_path = directory.path().join("shell-marker.txt");
    let marker_str = marker_path.display().to_string();
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            format!(
                r#"
[commands.shell_check]
shell = "echo shell-mode-marker > {marker_str}"
env_mode = "strict"
inherit_env = ["PATH"]
"#,
            )
            .as_bytes(),
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "shell_check"])?,
        &context,
        &mut Vec::new(),
    )?;

    let marker_contents = std::fs::read_to_string(&marker_path)?;
    assert!(
        marker_contents.contains("shell-mode-marker"),
        "shell-mode policy must invoke /bin/sh -c so shell features run; got {marker_contents:?}"
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "SUCCESS");
    assert_eq!(metadata_json["command_type"], "shell");
    assert_eq!(metadata_json["policy"], "shell_check");
    Ok(())
}

#[test]
fn run_argv_policy_audit_records_command_type_argv() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            (r#"
[commands.argv_check]
argv = ["/bin/sh", "-c", "true"]
env_mode = "strict"
inherit_env = ["PATH"]
"#
            .replace("/bin/sh", test_shell())
            .replace("/usr/bin/true", test_true()))
            .as_bytes(),
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "argv_check"])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["command_type"], "argv");
    Ok(())
}

#[test]
#[cfg(unix)]
fn run_shell_policy_injects_locket_secrets_into_shell_environment()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let db = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db, "postgres://shell-mode-secret", "manual", 1_000)?;

    let marker_path = directory.path().join("shell-secret-check.txt");
    let marker_str = marker_path.display().to_string();
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            format!(
                r#"
[commands.shell_secret]
shell = "printf '%s' \"$DATABASE_URL\" > {marker_str}"
required_secrets = ["DATABASE_URL"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
            )
            .as_bytes(),
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "shell_secret"])?,
        &context,
        &mut Vec::new(),
    )?;

    let value = std::fs::read_to_string(&marker_path)?;
    assert_eq!(value, "postgres://shell-mode-secret");
    Ok(())
}

#[test]
fn exec_preserves_non_ascii_utf8_secret_bytes_through_injection()
-> Result<(), Box<dyn std::error::Error>> {
    let secret_value = "caf\u{e9}-tok\u{e9}n-\u{1f511}";
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, secret_value);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("UNICODE_SECRET");
    crate::set_secret_value(&context, &args, secret_value, "manual", 1_000)?;

    let out_path = directory.path().join("secret_bytes.bin");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--force",
            "--secret",
            "UNICODE_SECRET",
            "--",
            test_shell(),
            "-c",
            "printf '%s' \"$UNICODE_SECRET\" > secret_bytes.bin",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    let written = std::fs::read(&out_path)?;
    assert_eq!(
        written,
        secret_value.as_bytes(),
        "exec must pass non-ASCII UTF-8 bytes through unchanged"
    );
    Ok(())
}

#[test]
fn run_preserves_non_ascii_utf8_secret_bytes_through_injection()
-> Result<(), Box<dyn std::error::Error>> {
    let secret_value = "r\u{e9}sum\u{e9}-value";
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, secret_value);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("UNICODE_SECRET");
    crate::set_secret_value(&context, &args, secret_value, "manual", 1_000)?;

    let out_path = directory.path().join("secret_bytes.bin");
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            format!(
                "\n[commands.check_unicode]\nargv = [\"{shell}\", \"-c\", \"printf '%s' \\\"$UNICODE_SECRET\\\" > secret_bytes.bin\"]\nrequired_secrets = [\"UNICODE_SECRET\"]\n",
                shell = test_shell()
            )
            .as_bytes(),
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "check_unicode"])?,
        &context,
        &mut Vec::new(),
    )?;

    let written = std::fs::read(&out_path)?;
    assert_eq!(
        written,
        secret_value.as_bytes(),
        "run must pass non-ASCII UTF-8 bytes through unchanged"
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn e2e_docker_compose_policy_run_writes_names_only_audit_and_refuses_remote()
-> Result<(), Box<dyn std::error::Error>> {
    // End-to-end harness for the e2e-docker-compose subtask: drives both
    // `prepare_docker_policy_execution` and `prepare_compose_policy_execution`
    // through a single project, verifies the names-only RUN audit row
    // shape, and confirms remote DOCKER_HOST refusal for both helpers
    // when `allow_remote_docker = false`.
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/e2e", "manual", 1_000)?;
    let api_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &api_args, "sk_test_e2e_value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.docker_app]
argv = ["docker", "run", "app"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["API_KEY"]
env_mode = "strict"
inherit_env = ["PATH", "DOCKER_CONFIG", "DOCKER_HOST"]

[commands.compose_app]
argv = ["docker", "compose", "up"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["API_KEY"]
env_mode = "strict"
inherit_env = ["PATH", "DOCKER_CONFIG", "DOCKER_HOST"]
"#,
        )?;

    let parent_env = docker_test_env(&directory);

    // docker run path: prepare, write audit row, assert metadata-only.
    let docker_argv = vec!["docker".to_owned(), "run".to_owned(), "alpine".to_owned()];
    let mut docker_prepared =
        crate::prepare_docker_policy_execution(&context, "docker_app", &docker_argv, parent_env)?;
    assert_eq!(docker_prepared.execution.program, "docker");
    assert!(docker_prepared.plan.argv.windows(2).any(|pair| pair == ["--env", "DATABASE_URL"]));
    let docker_argv_text = docker_prepared.plan.argv.join(" ");
    assert!(!docker_argv_text.contains("postgres://localhost/e2e"));
    assert!(!docker_argv_text.contains("sk_test_e2e_value"));
    crate::write_docker_policy_audit_if_available(&context, &mut docker_prepared, "SUCCESS")?;

    // compose path: prepare with `--project-directory .`, audit, assert names-only.
    let compose_argv = crate::compose_argv_with_options(
        vec!["docker".to_owned(), "compose".to_owned(), "up".to_owned()],
        Some(Path::new(".")),
        &[],
    )?;
    let compose_parent_env = docker_test_env(&directory);
    let mut compose_prepared = crate::prepare_compose_policy_execution(
        &context,
        "compose_app",
        &compose_argv,
        compose_parent_env,
    )?;
    let compose_argv_text = compose_prepared.plan.argv.join(" ");
    assert!(!compose_argv_text.contains("postgres://localhost/e2e"));
    assert!(!compose_argv_text.contains("sk_test_e2e_value"));
    crate::write_docker_policy_audit_if_available(&context, &mut compose_prepared, "SUCCESS")?;

    // Both runs should have produced metadata-only RUN rows naming both
    // secrets but never a value.
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let mut statement = store.connection().prepare(
        "SELECT command, metadata_json FROM audit_log WHERE action = 'RUN' ORDER BY sequence",
    )?;
    let rows: Vec<(String, String)> = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 2, "expected one RUN row per helper");
    let mut commands: Vec<&str> = rows.iter().map(|(command, _)| command.as_str()).collect();
    commands.sort_unstable();
    let mut expected_commands = vec!["compose run", "env docker"];
    expected_commands.sort_unstable();
    assert_eq!(commands, expected_commands);
    for (_, metadata) in &rows {
        assert!(metadata.contains("\"action\":\"RUN\""));
        assert!(metadata.contains("\"status\":\"SUCCESS\""));
        assert!(metadata.contains("DATABASE_URL"));
        assert!(metadata.contains("API_KEY"));
        assert!(!metadata.contains("postgres://localhost/e2e"));
        assert!(!metadata.contains("sk_test_e2e_value"));
    }

    // Remote DOCKER_HOST refusal — both helpers must reject when
    // `allow_remote_docker = false` (default).
    let remote_env =
        std::iter::once(("DOCKER_HOST".to_owned(), locket_exec::env_value("ssh://builder")))
            .collect();
    let remote_docker_argv = vec!["docker".to_owned(), "run".to_owned(), "alpine".to_owned()];
    let docker_remote = crate::prepare_docker_policy_execution(
        &context,
        "docker_app",
        &remote_docker_argv,
        remote_env,
    );
    let Err(docker_err) = docker_remote else {
        return Err("remote docker context must be denied".into());
    };
    assert!(docker_err.to_string().contains("remote Docker context is denied by default"));

    let remote_env =
        std::iter::once(("DOCKER_HOST".to_owned(), locket_exec::env_value("tcp://host:2376")))
            .collect();
    let remote_compose_argv = vec!["docker".to_owned(), "compose".to_owned(), "up".to_owned()];
    let compose_remote = crate::prepare_compose_policy_execution(
        &context,
        "compose_app",
        &remote_compose_argv,
        remote_env,
    );
    let Err(compose_err) = compose_remote else {
        return Err("remote compose context must be denied".into());
    };
    assert!(compose_err.to_string().contains("remote Docker context is denied by default"));

    Ok(())
}

#[test]
fn docker_helpers_enforce_secret_acls_against_actual_arguments()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(
        &context,
        &test_secret_write_args("API_KEY"),
        "fixture-value",
        "manual",
        1_000,
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.docker_app]
argv = ["docker", "run", "approved-image"]
required_secrets = ["API_KEY"]
inherit_env = ["DOCKER_CONFIG"]
[commands.compose_app]
argv = ["docker", "compose", "up", "approved-service"]
required_secrets = ["API_KEY"]
inherit_env = ["DOCKER_CONFIG"]
[secrets.API_KEY]
allow_argv = [["docker", "run", "approved-image"], ["docker", "compose", "up", "approved-service"]]
"#,
        )?;

    for (policy, approved, denied) in [
        (
            "docker_app",
            vec!["docker", "run", "approved-image"],
            vec!["docker", "run", "other-image"],
        ),
        (
            "compose_app",
            vec!["docker", "compose", "up", "approved-service"],
            vec!["docker", "compose", "up", "other-service"],
        ),
    ] {
        let prepare = if policy == "docker_app" {
            crate::prepare_docker_policy_execution
        } else {
            crate::prepare_compose_policy_execution
        };
        let approved = approved.into_iter().map(str::to_owned).collect::<Vec<_>>();
        let denied = denied.into_iter().map(str::to_owned).collect::<Vec<_>>();
        let allowed = prepare(&context, policy, &approved, docker_test_env(&directory))?;
        assert_eq!(
            allowed.execution.env.get("API_KEY").map(|value| value.as_str()),
            Some("fixture-value")
        );
        let unavailable =
            test_context_with_key_store(&directory, Arc::new(UnavailableMasterKeyStore));
        let Err(error) = prepare(&unavailable, policy, &denied, docker_test_env(&directory)) else {
            return Err("Docker helper delivered a secret to arguments denied by its ACL".into());
        };
        assert_eq!(error.exit_code(), locket_core::LocketError::InvalidPolicy.exit_code());
        assert!(error.to_string().contains("secret ACL denied"));
    }
    Ok(())
}

#[test]
fn docker_helpers_deny_remote_saved_and_environment_contexts()
-> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    let directory = tempdir()?;
    let context = test_context(&directory);
    init_docker_test_project(&context, "fixture-value")?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.docker_app]
argv = ["docker", "run", "app"]
required_secrets = ["API_KEY"]
env_mode = "strict"
inherit_env = ["DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST"]
[commands.compose_app]
argv = ["docker", "compose", "up"]
required_secrets = ["API_KEY"]
env_mode = "strict"
inherit_env = ["DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_HOST"]
"#,
        )?;
    let config = directory.path().join("docker-config");
    let metadata_dir = config
        .join("contexts/meta")
        .join(data_encoding::HEXLOWER.encode(&Sha256::digest(b"fixture-context")));
    std::fs::create_dir_all(&metadata_dir)?;
    std::fs::write(config.join("config.json"), r#"{"currentContext":"fixture-context"}"#)?;
    let metadata = metadata_dir.join("meta.json");
    std::fs::write(
        &metadata,
        r#"{"Name":"fixture-context","Endpoints":{"docker":{"Host":"ssh://remote-builder"}}}"#,
    )?;
    for (policy, argv) in [
        ("docker_app", vec!["docker", "run", "app"]),
        ("compose_app", vec!["docker", "compose", "up"]),
    ] {
        let prepare = if policy == "docker_app" {
            crate::prepare_docker_policy_execution
        } else {
            crate::prepare_compose_policy_execution
        };
        let argv = argv.into_iter().map(str::to_owned).collect::<Vec<_>>();
        for explicit_context in [false, true] {
            let mut env = locket_exec::EnvMap::from([(
                "DOCKER_CONFIG".into(),
                locket_exec::env_value(config.to_string_lossy()),
            )]);
            if explicit_context {
                env.insert("DOCKER_CONTEXT".into(), locket_exec::env_value("fixture-context"));
            }
            let Err(error) = prepare(&context, policy, &argv, env) else {
                return Err("remote Docker context received local secrets".into());
            };
            assert!(error.to_string().contains("remote Docker context"));
            assert!(!error.to_string().contains("fixture-value"));
        }
    }
    for (policy, subcommand, command) in
        [("docker_app", "run", "app"), ("compose_app", "compose", "up")]
    {
        std::fs::write(
            &metadata,
            r#"{"Name":"fixture-context","Endpoints":{"docker":{"Host":"unix:///fixture/docker.sock"}}}"#,
        )?;
        let env = locket_exec::EnvMap::from([
            ("DOCKER_CONFIG".into(), locket_exec::env_value(config.to_string_lossy())),
            ("DOCKER_CONTEXT".into(), locket_exec::env_value("fixture-context")),
            ("DOCKER_HOST".into(), locket_exec::env_value("ssh://overridden-host")),
        ]);
        let argv = ["docker", subcommand, command].map(str::to_owned);
        let prepare = if subcommand == "run" {
            crate::prepare_docker_policy_execution
        } else {
            crate::prepare_compose_policy_execution
        };
        let prepared = prepare(&context, policy, &argv, env)?;
        // A subsequent context change cannot redirect the pinned local plan.
        std::fs::write(
            &metadata,
            r#"{"Name":"fixture-context","Endpoints":{"docker":{"Host":"ssh://changed-after-check"}}}"#,
        )?;
        assert_eq!(prepared.plan.context_class, locket_docker::DockerContextClass::Local);
        assert_eq!(
            &prepared.plan.argv[..4],
            &["docker", "--host", "unix:///fixture/docker.sock", subcommand]
        );
        assert_eq!(prepared.execution.args, prepared.plan.argv[1..]);
        assert!(!prepared.execution.env.contains_key("DOCKER_CONTEXT"));
        assert_eq!(
            prepared.execution.env.get("API_KEY").map(|value| value.as_str()),
            Some("fixture-value")
        );
        assert!(!prepared.plan.argv.join(" ").contains("fixture-value"));
    }
    Ok(())
}

#[test]
fn docker_helpers_reject_routing_secrets_before_decryption()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut policy_file =
        std::fs::OpenOptions::new().append(true).open(directory.path().join("locket.toml"))?;
    let names = [
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "HOME",
        "USERPROFILE",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    ];
    for name in names {
        crate::set_secret_value(
            &context,
            &test_secret_write_args(name),
            "routing-secret-canary",
            "manual",
            1_000,
        )?;
        for subcommand in ["run", "compose"] {
            writeln!(
                policy_file,
                "\n[commands.{subcommand}_{name}]\nargv = [\"docker\", \"{subcommand}\", \"app\"]\nrequired_secrets = [\"{name}\"]\nenv_mode = \"strict\"\ninherit_env = [\"DOCKER_CONFIG\"]"
            )?;
        }
    }
    // A routing-policy error must win over unavailable decryption keys.
    let unavailable = test_context_with_key_store(&directory, Arc::new(UnavailableMasterKeyStore));
    for name in names {
        for subcommand in ["run", "compose"] {
            let prepare = if subcommand == "run" {
                crate::prepare_docker_policy_execution
            } else {
                crate::prepare_compose_policy_execution
            };
            let argv = ["docker".into(), subcommand.into(), "app".into()];
            let env = locket_exec::EnvMap::from([(
                "DOCKER_CONFIG".into(),
                locket_exec::env_value(directory.path().join("docker-config").to_string_lossy()),
            )]);
            let Err(error) = prepare(&unavailable, &format!("{subcommand}_{name}"), &argv, env)
            else {
                return Err(format!("routing secret {name} was accepted").into());
            };
            assert!(error.to_string().contains("cannot be injected"), "{name}: {error}");
            assert!(!error.to_string().contains("routing-secret-canary"));
        }
    }
    Ok(())
}

#[test]
fn docker_helpers_remote_allow_requires_exact_policy_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    let directory = tempdir()?;
    let context = test_context(&directory);
    init_docker_test_project(&context, "remote-secret-canary")?;
    let mut policy_file =
        std::fs::OpenOptions::new().append(true).open(directory.path().join("locket.toml"))?;
    for subcommand in ["run", "compose"] {
        let command = if subcommand == "run" { "app" } else { "up" };
        writeln!(
            policy_file,
            "\n[commands.{subcommand}_remote]\nargv = [\"docker\", \"{subcommand}\", \"{command}\"]\nrequired_secrets = [\"API_KEY\"]\nenv_mode = \"strict\"\ninherit_env = [\"DOCKER_CONFIG\", \"DOCKER_HOST\", \"DOCKER_CONTEXT\"]\nallow_remote_docker = true"
        )?;
    }
    let config = directory.path().join("docker-config");
    let metadata = config
        .join("contexts/meta")
        .join(data_encoding::HEXLOWER.encode(&Sha256::digest(b"remote-context")));
    std::fs::create_dir_all(&metadata)?;
    std::fs::write(config.join("config.json"), r#"{"currentContext":"remote-context"}"#)?;
    std::fs::write(
        metadata.join("meta.json"),
        r#"{"Name":"remote-context","Endpoints":{"docker":{"Host":"ssh://builder"}}}"#,
    )?;
    for subcommand in ["run", "compose"] {
        let prepare = if subcommand == "run" {
            crate::prepare_docker_policy_execution
        } else {
            crate::prepare_compose_policy_execution
        };
        let policy = format!("{subcommand}_remote");
        let command = if subcommand == "run" { "app" } else { "up" };
        let argv = ["docker".into(), subcommand.into(), command.into()];
        for (variable, value) in [
            ("DOCKER_HOST", "ssh://builder"),
            ("DOCKER_HOST", "tcp://builder:2376"),
            ("DOCKER_HOST", "npipe:////server/pipe/docker_engine"),
            ("DOCKER_CONTEXT", "remote-context"),
            ("DOCKER_CONTEXT", ""), // Falls back to the saved currentContext.
        ] {
            let mut env = docker_test_env(&directory);
            env.insert(variable.into(), locket_exec::env_value(value));
            let mut non_interactive = context.clone();
            non_interactive.confirmation_reader = Arc::new(DockerNonInteractiveConfirmation);
            let Err(error) = prepare(&non_interactive, &policy, &argv, env.clone()) else {
                return Err("non-interactive remote injection bypassed confirmation".into());
            };
            assert!(error.to_string().contains("requires interactive confirmation"), "{error}");
            for answer in [
                String::new(),
                "yes".into(),
                "remote wrong-policy".into(),
                format!("remote {policy} "),
            ] {
                let mut denied_context = context.clone();
                denied_context.confirmation_reader =
                    Arc::new(StaticConfirmationReader::new(&answer));
                let Err(error) = prepare(&denied_context, &policy, &argv, env.clone()) else {
                    return Err(format!("remote injection accepted confirmation {answer:?}").into());
                };
                assert!(
                    error.to_string().contains("confirmation did not match remote Docker scope"),
                    "{error}"
                );
                assert!(!error.to_string().contains("remote-secret-canary"));
            }
            let mut confirmed_context = context.clone();
            confirmed_context.confirmation_reader =
                Arc::new(StaticConfirmationReader::new(&format!("remote {policy}\r\n")));
            let prepared = prepare(&confirmed_context, &policy, &argv, env)?;
            assert_eq!(prepared.plan.context_class, locket_docker::DockerContextClass::Remote);
            assert_eq!(
                prepared.execution.env.get("API_KEY").map(|value| value.as_str()),
                Some("remote-secret-canary")
            );
            assert!(!prepared.plan.argv.join(" ").contains("remote-secret-canary"));
            assert!(
                !crate::docker_policy_audit_metadata(&prepared, "SUCCESS")
                    .to_string()
                    .contains("remote-secret-canary")
            );
        }
        let mut confirmed_context = context.clone();
        confirmed_context.confirmation_reader =
            Arc::new(StaticConfirmationReader::new(&format!("remote {policy}")));
        for host in ["fd://3", "unknown-endpoint", "unix://", "tcp://host:invalid"] {
            let mut env = docker_test_env(&directory);
            env.insert("DOCKER_HOST".into(), locket_exec::env_value(host));
            let Err(error) = prepare(&confirmed_context, &policy, &argv, env) else {
                return Err(format!("unclassifiable host {host} accepted").into());
            };
            assert!(error.to_string().contains("unknown or malformed"), "{error}");
            assert!(!error.to_string().contains("remote-secret-canary"));
        }
    }
    Ok(())
}

#[test]
fn docker_helpers_ignore_stripped_routing_environment_and_preserve_pass_through()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(
        &context,
        &test_secret_write_args("API_KEY"),
        "local-secret-canary",
        "manual",
        1_000,
    )?;
    let mut policy_file =
        std::fs::OpenOptions::new().append(true).open(directory.path().join("locket.toml"))?;
    for subcommand in ["run", "compose"] {
        writeln!(
            policy_file,
            "\n[commands.{subcommand}_local]\nargv = [\"docker\", \"{subcommand}\", \"saved-app\"]\nrequired_secrets = [\"API_KEY\"]\nenv_mode = \"strict\"\ninherit_env = [\"DOCKER_CONFIG\"]"
        )?;
    }
    for subcommand in ["run", "compose"] {
        let prepare = if subcommand == "run" {
            crate::prepare_docker_policy_execution
        } else {
            crate::prepare_compose_policy_execution
        };
        let mut argv = vec![
            "docker",
            subcommand,
            "app",
            "tool",
            "--host=container-option",
            "--context",
            "container-option",
            "--config=app.json",
            "-Hheader",
        ];
        if subcommand == "compose" {
            argv.insert(2, "run");
        }
        let argv = argv.into_iter().map(str::to_owned).collect::<Vec<_>>();
        let env = locket_exec::EnvMap::from([
            (
                "DOCKER_CONFIG".into(),
                locket_exec::env_value(directory.path().join("docker-config").to_string_lossy()),
            ),
            ("DOCKER_HOST".into(), locket_exec::env_value("ssh://ignored-parent-host")),
            ("DOCKER_CONTEXT".into(), locket_exec::env_value("ignored-parent-context")),
            ("DOCKER_TLS".into(), locket_exec::env_value("1")),
        ]);
        let prepared = prepare(&context, &format!("{subcommand}_local"), &argv, env)?;
        assert_eq!(prepared.plan.context_class, locket_docker::DockerContextClass::Local);
        let default_host = if cfg!(windows) {
            "npipe:////./pipe/docker_engine"
        } else {
            "unix:///var/run/docker.sock"
        };
        assert_eq!(&prepared.plan.argv[..4], &["docker", "--host", default_host, subcommand]);
        assert!(prepared.plan.argv.ends_with(&argv[2..]));
        assert_eq!(prepared.policy.command, locket_core::CommandSpec::Argv(argv.clone()));
        for name in ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS"] {
            assert!(!prepared.execution.env.contains_key(name));
        }
        assert_eq!(prepared.execution.args, prepared.plan.argv[1..]);
        assert!(!prepared.plan.argv.join(" ").contains("local-secret-canary"));
        let unavailable =
            test_context_with_key_store(&directory, Arc::new(UnavailableMasterKeyStore));
        for flag in [
            "--host=ssh://remote",
            "--context=remote",
            "--config=elsewhere",
            "-Hssh://remote",
            "-cremote",
            "-DHssh://remote",
        ] {
            let mut global_argv = argv.clone();
            global_argv.insert(1, flag.to_owned());
            let Err(error) = prepare(
                &unavailable,
                &format!("{subcommand}_local"),
                &global_argv,
                docker_test_env(&directory),
            ) else {
                return Err(format!("global routing flag {flag} was accepted").into());
            };
            assert!(
                error.to_string().contains("Global Docker destination flags are not supported"),
                "{error}"
            );
        }
    }
    Ok(())
}

#[test]
fn generic_run_reuses_saved_exact_argv_and_policy_authorization()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(
        &context,
        &test_secret_write_args("API_KEY"),
        "fixture-value",
        "manual",
        1000,
    )?;
    let config = directory.path().join("locket.toml");
    let mut text = std::fs::read_to_string(&config)?;
    text.push_str("\n[commands.dev]\nargv = [\"");
    text.push_str(test_shell());
    text.push_str("\", \"-c\", \"test \\\"$API_KEY\\\" = fixture-value\"]\nrequired_secrets = [\"API_KEY\"]\n");
    std::fs::write(&config, text)?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "run",
            "--",
            test_shell(),
            "-c",
            "test \"$API_KEY\" = fixture-value",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let store = crate::open_store(&context)?;
    let resolved = crate::require_project(&context)?;
    let sessions = store.list_incomplete_runtime_sessions(resolved.config.project_id.as_str())?;
    assert_eq!(sessions, [] as [locket_store::RuntimeSessionRecord; 0]);
    let policy: String = store.connection().query_row(
        "SELECT policy_name FROM runtime_sessions ORDER BY started_at DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(policy, "dev");
    Ok(())
}

#[test]
fn generic_run_new_argv_requires_approval_and_persists_only_chosen_profile_names()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "no");
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(
        &context,
        &test_secret_write_args("API_KEY"),
        "fixture-value",
        "manual",
        1000,
    )?;
    let before = std::fs::read_to_string(directory.path().join("locket.toml"))?;
    let error = run_with_context(
        Cli::try_parse_from(["locket", "run", "--", test_true()])?,
        &context,
        &mut Vec::new(),
    )
    .err()
    .ok_or("new command must be approved")?;
    assert!(error.to_string().contains("confirmation"));
    assert_eq!(std::fs::read_to_string(directory.path().join("locket.toml"))?, before);
    let approved =
        test_context_with_key_store_and_confirmation(&directory, key_store, "approve dev");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "run", "--", test_true()])?,
        &approved,
        &mut output,
    )?;
    let resolved = crate::require_project(&approved)?;
    let document = crate::read_policy_document(&directory.path().join("locket.toml"))?;
    assert_eq!(
        document.commands["dev"]
            .required_secrets
            .iter()
            .map(locket_core::SecretName::as_str)
            .collect::<Vec<_>>(),
        vec!["API_KEY"]
    );
    assert_eq!(
        document.commands["dev"].command,
        locket_core::CommandSpec::Argv(vec![test_true().to_owned()])
    );
    let store = crate::open_store(&approved)?;
    assert!(store.get_command_policy_index(resolved.config.project_id.as_str(), "dev")?.is_some());
    Ok(())
}
