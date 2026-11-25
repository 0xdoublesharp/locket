#[allow(unused_imports)]
use super::*;

#[test]
fn expiry_metadata_round_trips_and_get_and_run_refuse_expired_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "canary-expired-value");
    let cli = |args: &[&str], output: &mut Vec<u8>| {
        run_with_context(Cli::try_parse_from(args)?, &context, output)
            .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
    };
    cli(&["locket", "init", "--no-device", "--no-passkey"], &mut Vec::new())?;
    cli(
        &["locket", "set", "TOKEN", "--expires-in", "24h", "--rotate-after-days", "3"],
        &mut Vec::new(),
    )?;
    let store = locket_store::Store::open(&context.store_path)?;
    let resolved = crate::require_project(&context)?;
    let project = resolved.config.project_id.as_str();
    let profile = crate::default_profile(&store, &resolved.config)?;
    let token = store
        .list_secrets_by_name(project, &profile.id, "TOKEN")?
        .into_iter()
        .next()
        .ok_or("missing token metadata")?;
    let initial = store.get_secret_expiry_policy(&token.id)?.ok_or("missing expiry policy")?;
    assert!(initial.expires_at.is_some());
    assert_eq!(initial.rotate_after_days, Some(3));
    cli(&["locket", "rotate", "TOKEN", "--expires-in", "30d"], &mut Vec::new())?;
    let rotated =
        store.get_secret_expiry_policy(&token.id)?.ok_or("missing rotate expiry policy")?;
    assert!(rotated.expires_at > initial.expires_at);
    assert_eq!(rotated.rotate_after_days, Some(3));
    cli(
        &[
            "locket",
            "secret",
            "meta",
            "TOKEN",
            "--rotate-after-days",
            "2",
            "--description",
            "API credential",
        ],
        &mut Vec::new(),
    )?;
    let edited =
        store.get_secret_expiry_policy(&token.id)?.ok_or("missing edited expiry policy")?;
    assert_eq!(edited.expires_at, rotated.expires_at);
    assert_eq!(edited.rotate_after_days, Some(2));
    cli(&["locket", "generate", "GENERATED", "--expires-in", "90d"], &mut Vec::new())?;
    let generated = store
        .list_secrets_by_name(project, &profile.id, "GENERATED")?
        .into_iter()
        .next()
        .ok_or("missing generated secret metadata")?;
    let generated_expiry =
        store.get_secret_expiry_policy(&generated.id)?.ok_or("missing generated expiry policy")?;
    assert!(generated_expiry.expires_at > edited.expires_at);
    cli(&["locket", "secret", "meta", "GENERATED", "--expires-in", "24h"], &mut Vec::new())?;

    let now = crate::now_unix_nanos()?;
    store.set_secret_expiry_policy(
        &token.id,
        locket_store::SecretExpiryPolicy { expires_at: Some(now), ..edited },
        now,
    )?;
    store
        .connection()
        .execute("UPDATE secrets SET last_rotated_at = 0 WHERE id = ?1", [&token.id])?;
    let mut output = Vec::new();
    let err = cli(&["locket", "get", "TOKEN", "--reveal", "--force"], &mut output)
        .err()
        .ok_or("expired value was revealed")?;
    assert!(err.to_string().contains("secret has expired"));
    assert_eq!(output, [] as [u8; 0]);
    cli(&["locket", "policy", "add", "deploy", "--", test_true()], &mut Vec::new())?;
    cli(&["locket", "policy", "require", "deploy", "TOKEN"], &mut Vec::new())?;
    let err =
        cli(&["locket", "run", "deploy"], &mut output).err().ok_or("expired value was injected")?;
    assert!(err.to_string().contains("secret has expired"));
    let sessions: u32 =
        store
            .connection()
            .query_row("SELECT count(*) FROM runtime_sessions", [], |row| row.get(0))?;
    assert_eq!(sessions, 0);

    let mut output = Vec::new();
    cli(&["locket", "parity", "--json"], &mut output)?;
    let parity: serde_json::Value = serde_json::from_slice(&output)?;
    let profile = &parity["profiles"][0];
    assert_eq!(profile["expired"], serde_json::json!(["TOKEN"]));
    assert_eq!(profile["stale"], serde_json::json!(["TOKEN"]));
    assert_eq!(profile["expiring_soon"], serde_json::json!(["GENERATED"]));
    output.clear();
    cli(&["locket", "discover", "--json"], &mut output)?;
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&output)?;
    assert!(rows.iter().any(|row| row["name"] == "TOKEN"
        && row["expiry_status"] == "expired"
        && row["stale"] == true));
    assert!(
        rows.iter()
            .any(|row| row["name"] == "GENERATED" && row["expiry_status"] == "expiring_soon")
    );
    assert!(!String::from_utf8(output)?.contains("canary-expired-value"));
    Ok(())
}

#[test]
fn reveal_rejects_unsupported_stored_blob_schema() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "schema-test", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let canary = "stored-schema-test-canary";
    crate::set_secret_value(&context, &test_secret_write_args("API_KEY"), canary, "manual", 1_000)?;
    let reveal = || Cli::try_parse_from(["locket", "get", "API_KEY", "--reveal", "--force"]);
    let mut output = Vec::new();
    run_with_context(reveal()?, &context, &mut output)?;
    assert_eq!(String::from_utf8(output)?, format!("{canary}\n"));
    let store = crate::open_store(&context)?;
    assert_eq!(store.connection().execute("UPDATE blobs SET aad_schema_version = 2", [])?, 1);
    let success_count = || {
        store.connection().query_row(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'REVEAL' AND status = 'SUCCESS'",
            [],
            |row| row.get::<_, i64>(0),
        )
    };
    let before = success_count()?;
    assert_eq!(before, 1);
    let mut output = Vec::new();
    let result = run_with_context(reveal()?, &context, &mut output);
    assert!(matches!(
        result,
        Err(crate::CliError::Crypto(locket_crypto::CryptoError::DecryptionFailed))
    ));
    assert_eq!(output, [] as [u8; 0]);
    assert_eq!(success_count()?, before);
    Ok(())
}

#[test]
fn set_command_reads_secure_secret_value_without_leaking_it()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "postgres://localhost/prompt");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let mut set_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL"])?,
        &context,
        &mut set_output,
    )?;
    let set_output = String::from_utf8(set_output)?;
    assert!(set_output.contains("set DATABASE_URL"));
    assert!(!set_output.contains("postgres://localhost/prompt"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SET'",
        [],
        |row| row.get(0),
    )?;
    assert!(!metadata.contains("postgres://localhost/prompt"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/prompt\n");
    Ok(())
}

#[test]
fn set_command_rejects_empty_secure_secret_before_writing() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "secret value cannot be empty");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let set_count: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'SET'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(set_count, 0);
    Ok(())
}

#[test]
fn set_command_preflights_source_conflicts_before_reading_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_failing_secret_reader(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args =
        test_secret_write_args_for_source("DATABASE_URL", crate::SecretSourceArg::MachineLocal);
    crate::set_secret_value(&context, &args, "postgres://localhost/machine", "manual", 1_000)?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "pass --source");
    Ok(())
}

#[test]
fn set_command_preflights_deleted_source_as_typed_error_before_reading_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/deleted", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "rm", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    )?;

    let failing_context = test_context_with_failing_secret_reader(&directory);
    let result = run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL", "--source", "user-local"])?,
        &failing_context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("deleted source should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::SecretDeleted.exit_code());
    assert!(error.to_string().contains("secret source is deleted"), "{error}");
    Ok(())
}

#[test]
fn rotate_command_reads_secure_secret_value_without_leaking_it()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "postgres://localhost/new");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/old", "manual", 1_000)?;

    let mut rotate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "rotate", "DATABASE_URL"])?,
        &context,
        &mut rotate_output,
    )?;
    let rotate_output = String::from_utf8(rotate_output)?;
    assert!(rotate_output.contains("rotated DATABASE_URL"));
    assert!(rotate_output.contains("version=2"));
    assert!(!rotate_output.contains("postgres://localhost/new"));
    assert!(!rotate_output.contains("postgres://localhost/old"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'ROTATE'",
        [],
        |row| row.get(0),
    )?;
    assert!(!metadata.contains("postgres://localhost/new"));
    assert!(!metadata.contains("postgres://localhost/old"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/new\n");
    Ok(())
}

#[test]
fn rotate_command_preflights_source_ambiguity_before_reading_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_failing_secret_reader(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let user_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &user_args, "postgres://localhost/user", "manual", 1_000)?;
    let machine_args =
        test_secret_write_args_for_source("DATABASE_URL", crate::SecretSourceArg::MachineLocal);
    crate::set_secret_value(
        &context,
        &machine_args,
        "postgres://localhost/machine",
        "manual",
        2_000,
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "rotate", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "multiple sources");
    Ok(())
}

#[test]
fn set_list_get_and_rm_secret_value() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let args = crate::SecretWriteArgs {
        target: crate::commands::secrets::set::WriteTargetArgs::default(),
        key: "DATABASE_URL".to_owned(),
        source: crate::SourceArg { source: Some(crate::SecretSourceArg::UserLocal) },
        metadata: crate::SecretMetadataFlags::default(),
    };
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut list_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "list"])?, &context, &mut list_output)?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("DATABASE_URL"));
    assert!(!list_output.contains("postgres://localhost/app"));

    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL"])?,
        &context,
        &mut get_output,
    )?;
    let get_output = String::from_utf8(get_output)?;
    assert!(get_output.contains("version=1"));
    assert!(!get_output.contains("postgres://localhost/app"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/app\n");

    let mut rm_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "rm", "DATABASE_URL"])?,
        &context,
        &mut rm_output,
    )?;
    let mut list_after_rm = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "list"])?, &context, &mut list_after_rm)?;
    assert!(String::from_utf8(list_after_rm)?.contains("no secrets"));
    Ok(())
}

#[test]
fn get_copy_writes_metadata_only_audit_without_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let copy_args = crate::GetArgs {
        project: None,
        profile: None,
        key: "DATABASE_URL".to_owned(),
        source: crate::SourceArg { source: None },
        reveal: false,
        force: false,
        copy: true,
        verify_user: false,
        use_dangerous: false,
    };
    let mut copy_output = Vec::new();
    let mut copy_stderr = Vec::new();
    let mut clipboard = crate::MemoryClipboard::clearing_supported();
    crate::get_command_with_clipboard_status_and_limit(
        &context,
        &mut copy_output,
        &mut copy_stderr,
        &copy_args,
        |value, ttl_seconds, limit| {
            assert_eq!(ttl_seconds, 60);
            assert_eq!(limit, crate::ClipboardClearLimit::Supported);
            crate::ClipboardBackend::copy(&mut clipboard, value)?;
            crate::ClipboardBackend::schedule_clear_after_ttl(&mut clipboard, value, ttl_seconds)
        },
        crate::ClipboardClearLimit::Supported,
    )?;
    assert_eq!(clipboard.value(), None);
    let copy_output = String::from_utf8(copy_output)?;
    let copy_stderr = String::from_utf8(copy_stderr)?;
    assert!(copy_output.contains("metadata_only=yes"));
    assert!(copy_output.contains("clipboard_clear_supported=yes"));
    assert!(!copy_output.contains("postgres://localhost/app"));
    assert_eq!(copy_stderr, "");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"access_mode\":\"clipboard\""));
    assert!(metadata.contains("\"ttl_seconds\":60"));
    assert!(metadata.contains("\"clipboard_clear_supported\":true"));
    assert!(metadata.contains("\"secret_name\":\"DATABASE_URL\""));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn get_copy_wayland_limit_emits_targeted_warning_and_audit_reason()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let copy_args = crate::GetArgs {
        project: None,
        profile: None,
        key: "DATABASE_URL".to_owned(),
        source: crate::SourceArg { source: None },
        reveal: false,
        force: false,
        copy: true,
        verify_user: false,
        use_dangerous: false,
    };
    let mut copy_output = Vec::new();
    let mut copy_stderr = Vec::new();
    crate::get_command_with_clipboard_and_limit(
        &context,
        &mut copy_output,
        &mut copy_stderr,
        &copy_args,
        |value| {
            assert_eq!(value, "postgres://localhost/app");
            Ok(())
        },
        crate::ClipboardClearLimit::WaylandSourceProcessLimited,
    )?;
    let copy_stderr = String::from_utf8(copy_stderr)?;
    assert!(copy_stderr.contains("Wayland"));
    assert!(copy_stderr.contains("source process"));
    assert!(!copy_stderr.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"unsupported_reason\":\"wayland_source_process_limited\""));
    assert!(metadata.contains("\"clipboard_clear_supported\":false"));
    assert!(metadata.contains("\"clipboard_supported\":true"));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn get_copy_direct_cli_limit_records_audit_reason() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let copy_args = crate::GetArgs {
        project: None,
        profile: None,
        key: "DATABASE_URL".to_owned(),
        source: crate::SourceArg { source: None },
        reveal: false,
        force: false,
        copy: true,
        verify_user: false,
        use_dangerous: false,
    };
    let mut copy_output = Vec::new();
    let mut copy_stderr = Vec::new();
    crate::get_command_with_clipboard_and_limit(
        &context,
        &mut copy_output,
        &mut copy_stderr,
        &copy_args,
        |_| Ok(()),
        crate::ClipboardClearLimit::DirectCli,
    )?;
    let copy_stderr = String::from_utf8(copy_stderr)?;
    assert!(copy_stderr.contains("clipboard TTL clearing is unsupported"));
    assert!(!copy_stderr.contains("Wayland"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"unsupported_reason\":\"direct_cli_no_background_clear\""));
    Ok(())
}

#[test]
fn get_copy_unavailable_audits_unsupported_state_without_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let copy_args = crate::GetArgs {
        project: None,
        profile: None,
        key: "DATABASE_URL".to_owned(),
        source: crate::SourceArg { source: None },
        reveal: false,
        force: false,
        copy: true,
        verify_user: false,
        use_dangerous: false,
    };
    let mut copy_output = Vec::new();
    let mut copy_stderr = Vec::new();
    let result = crate::get_command_with_clipboard_and_limit(
        &context,
        &mut copy_output,
        &mut copy_stderr,
        &copy_args,
        |_value| Err("clipboard command unavailable".to_owned()),
        crate::ClipboardClearLimit::DirectCli,
    );
    let Err(error) = result else {
        return Err("clipboard failure must return an error".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::ExternalSourceUnavailable.exit_code());
    let crate::CliError::Typed { kind, message } = error else {
        return Err("clipboard failure should return a typed error".into());
    };
    assert_eq!(kind, locket_core::LocketError::ExternalSourceUnavailable);
    assert_eq!(message, "clipboard command unavailable");
    let copy_output = String::from_utf8(copy_output)?;
    let copy_stderr = String::from_utf8(copy_stderr)?;
    assert!(copy_stderr.contains("clipboard TTL clearing is unsupported"));
    assert!(!copy_output.contains("clipboard TTL clearing is unsupported"));
    assert!(!copy_output.contains("postgres://localhost/app"));
    assert!(!copy_stderr.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"status\":\"FAILED\""));
    assert!(metadata.contains("\"clipboard_supported\":false"));
    assert!(metadata.contains("\"unsupported_reason\":\"clipboard command unavailable\""));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn get_copy_verify_user_denial_audits_without_decrypting_or_copying()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let context =
        context_with_user_verifier(&context, Arc::new(MemoryLocalUserVerifier::denying()));
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let copy_args = crate::GetArgs {
        project: None,
        profile: None,
        key: "DATABASE_URL".to_owned(),
        source: crate::SourceArg { source: None },
        reveal: false,
        force: false,
        copy: true,
        verify_user: true,
        use_dangerous: false,
    };
    let mut copy_output = Vec::new();
    let mut copy_stderr = Vec::new();
    let result = crate::get_command_with_clipboard(
        &context,
        &mut copy_output,
        &mut copy_stderr,
        &copy_args,
        |_value| Ok(()),
    );
    let Err(error) = result else {
        return Err("verification denial must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UserVerificationFailed.exit_code());
    assert_eq!(String::from_utf8(copy_output)?, "");
    assert!(!String::from_utf8(copy_stderr)?.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'COPY'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["status"], "DENIED");
    assert_eq!(metadata["denial_reason"], "user_verification_failed");
    assert_eq!(metadata["user_verification"]["required"], true);
    assert_eq!(metadata["user_verification"]["satisfied"], false);
    assert!(metadata["user_verification"].get("method").is_none());
    assert!(!metadata.to_string().contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn reveal_requires_force_for_noninteractive_stdout_and_audits_force()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut reveal_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal"])?,
        &context,
        &mut reveal_output,
    );
    assert_error_contains(result.map(|_| ()), "requires an interactive terminal");

    let mut forced_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut forced_output,
    )?;
    assert_eq!(String::from_utf8(forced_output)?, "postgres://localhost/app\n");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let mut statement = store.connection().prepare(
        "SELECT command, status, metadata_json FROM audit_log WHERE action = 'REVEAL' ORDER BY sequence",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 2);
    let (denied_command, denied_status, denied_metadata) = &rows[0];
    assert_eq!(denied_command, "get");
    assert_eq!(denied_status, "DENIED");
    assert!(denied_metadata.contains("\"command\":\"get\""));
    assert!(denied_metadata.contains("\"denial_reason\":\"noninteractive_terminal\""));
    assert!(denied_metadata.contains("\"force\":false"));
    assert!(!denied_metadata.contains("postgres://localhost/app"));
    let (success_command, success_status, success_metadata) = &rows[1];
    assert_eq!(success_command, "get");
    assert_eq!(success_status, "SUCCESS");
    assert!(success_metadata.contains("\"command\":\"get\""));
    assert!(success_metadata.contains("\"force\":true"));
    assert!(success_metadata.contains("\"access_mode\":\"stdout\""));
    assert!(!success_metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn reveal_verify_user_success_audits_method_without_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "get",
            "DATABASE_URL",
            "--reveal",
            "--force",
            "--verify-user",
        ])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/app\n");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REVEAL'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["status"], "SUCCESS");
    assert_eq!(metadata["user_verification"]["required"], true);
    assert_eq!(metadata["user_verification"]["satisfied"], true);
    assert_eq!(metadata["user_verification"]["method"], "test");
    assert!(!metadata.to_string().contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn reveal_verify_user_still_requires_unlocked_vault() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    let (project_id, _) = test_project_id_and_master_key(&context)?;
    context.key_store.delete_master_key(&project_id)?;

    let mut reveal_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "get",
            "DATABASE_URL",
            "--reveal",
            "--force",
            "--verify-user",
        ])?,
        &context,
        &mut reveal_output,
    );
    let Err(error) = result else {
        return Err("locked vault must fail before reveal".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UnlockRequired.exit_code());
    assert_eq!(String::from_utf8(reveal_output)?, "");

    // The CLI must mirror the locked-vault refusal into the degraded-audit
    // log under ${LOCKET_HOME}/audit-degraded.log. Names only - never
    // values, never secret_name.
    let degraded_log = directory.path().join("audit-degraded.log");
    let degraded_body = std::fs::read_to_string(&degraded_log)?;
    let degraded_lines: Vec<&str> = degraded_body.lines().collect();
    assert_eq!(degraded_lines.len(), 1, "exactly one degraded-audit row expected");
    let row: serde_json::Value = serde_json::from_str(degraded_lines[0])?;
    assert_eq!(row["action"], "REVEAL");
    assert_eq!(row["status"], "DENIED_LOCKED");
    assert_eq!(row["failure_reason"], "vault_locked");
    assert_eq!(row["command"], "get --reveal");
    assert_eq!(row["project_id"], project_id);
    assert!(row.get("secret_name").is_none(), "must never include secret_name");
    assert!(!degraded_body.contains("DATABASE_URL"));
    assert!(!degraded_body.contains("postgres://"));
    Ok(())
}

#[test]
fn meta_updates_secret_metadata_without_printing_values() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut meta_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--description",
            "primary database",
            "--owner",
            "platform",
            "--tag",
            "database",
            "--tag",
            "prod",
            "--required",
        ])?,
        &context,
        &mut meta_output,
    )?;
    let meta_output = String::from_utf8(meta_output)?;
    assert!(meta_output.contains("metadata updated DATABASE_URL"));
    assert!(meta_output.contains("updated_fields: description,owner,tags,required"));
    assert!(meta_output.contains("metadata_only: yes"));
    assert!(!meta_output.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let row = store.connection().query_row(
        "SELECT description, owner, tags_json, required, updated_at
         FROM secrets
         WHERE name = 'DATABASE_URL'",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, i64>(4)?,
            ))
        },
    )?;
    assert_eq!(row.0, "primary database");
    assert_eq!(row.1, "platform");
    assert_eq!(row.2, "[\"database\",\"prod\"]");
    assert!(row.3);
    assert_eq!(row.4, 1_000);

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SECRET_META_UPDATE'",
        [],
        |row| row.get(0),
    )?;
    assert!(
        audit_metadata
            .contains("\"updated_fields\":[\"description\",\"owner\",\"tags\",\"required\"]")
    );
    assert!(audit_metadata.contains("\"updated_field_count\":4"));
    assert!(audit_metadata.contains("\"tag_update_count\":2"));
    assert!(audit_metadata.contains("\"required_update\":true"));
    assert!(!audit_metadata.contains("primary database"));
    assert!(!audit_metadata.contains("platform"));
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn meta_rejects_secret_like_metadata_without_storing_value()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let provider = "sk_test_sampleTokenValue123";
    let result = run_with_context(
        Cli::try_parse_from(["locket", "meta", "DATABASE_URL", "--description", provider])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("secret-like metadata should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::MetadataLooksLikeSecret.exit_code());
    assert!(error.to_string().contains("metadata field description looks like a secret"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let row = store.connection().query_row(
        "SELECT description, updated_at FROM secrets WHERE name = 'DATABASE_URL'",
        [],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    assert_eq!(row, (None, 1_000));

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE action = 'SECRET_META_UPDATE' AND status = 'FAILED'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("\"failure_reason\":\"metadata_privacy_validation\""));
    assert!(!audit_metadata.contains(provider));
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn meta_rejects_known_secret_value_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--owner",
            "postgres://localhost/app",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("known-secret metadata should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::MetadataLooksLikeSecret.exit_code());
    assert!(error.to_string().contains("metadata field owner matches an existing secret value"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let owner: Option<String> = store.connection().query_row(
        "SELECT owner FROM secrets WHERE name = 'DATABASE_URL'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(owner, None);

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE action = 'SECRET_META_UPDATE' AND status = 'FAILED'",
        [],
        |row| row.get(0),
    )?;
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn meta_rejects_control_character_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "meta", "DATABASE_URL", "--tag", "prod\u{1b}[31m"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("control-character metadata should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::MetadataInvalid.exit_code());
    assert!(error.to_string().contains("metadata field tag contains control characters"));
    Ok(())
}

#[test]
fn meta_requires_source_for_multiple_active_sources_and_updates_explicit_source()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let user_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &user_args, "postgres://localhost/user", "manual", 1_000)?;
    let machine_args = crate::SecretWriteArgs {
        target: crate::commands::secrets::set::WriteTargetArgs::default(),
        key: "DATABASE_URL".to_owned(),
        source: crate::SourceArg { source: Some(crate::SecretSourceArg::MachineLocal) },
        metadata: crate::SecretMetadataFlags::default(),
    };
    crate::set_secret_value(
        &context,
        &machine_args,
        "postgres://localhost/machine",
        "manual",
        2_000,
    )?;

    let ambiguous = run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--description",
            "ambiguous database",
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(ambiguous, "multiple sources exist for this secret");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let versions_before: i64 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM secret_versions", [], |row| row.get(0))?;

    let mut meta_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--source",
            "machine-local",
            "--description",
            "machine database",
        ])?,
        &context,
        &mut meta_output,
    )?;
    let meta_output = String::from_utf8(meta_output)?;
    assert!(meta_output.contains("source=machine-local"));
    assert!(!meta_output.contains("postgres://localhost"));

    let descriptions = store.connection().query_row(
        "SELECT
            MAX(CASE WHEN source = 'user-local' THEN description END),
            MAX(CASE WHEN source = 'machine-local' THEN description END)
         FROM secrets
         WHERE name = 'DATABASE_URL'",
        [],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<String>>(1)?)),
    )?;
    assert_eq!(descriptions.0, None);
    assert_eq!(descriptions.1.as_deref(), Some("machine database"));
    let versions_after: i64 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM secret_versions", [], |row| row.get(0))?;
    assert_eq!(versions_after, versions_before);

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE action = 'SECRET_META_UPDATE' AND status = 'SUCCESS'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("\"source\":\"machine-local\""));
    assert!(!audit_metadata.contains("machine database"));
    assert!(!audit_metadata.contains("postgres://localhost"));
    Ok(())
}

#[test]
fn generate_alphanumeric_stores_requested_entropy_without_printing_the_value()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut output = Vec::new();
    let code = run_with_context(
        Cli::try_parse_from([
            "locket",
            "generate",
            "SERVICE_TOKEN",
            "--format",
            "alphanumeric",
            "--bytes",
            "16",
            "--json",
        ])?,
        &context,
        &mut output,
    )?;
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(report["name"], "SERVICE_TOKEN");
    assert_eq!(report["version"], 1);
    assert_eq!(report["origin_detail"], "generated");
    let project = crate::require_project(&context)?;
    let project_id = project.config.project_id.as_str();
    let store = crate::open_store(&context)?;
    let profile = crate::default_profile(&store, &project.config)?;
    let secret = store
        .get_secret_by_source(project_id, &profile.id, "SERVICE_TOKEN", "user-local")?
        .ok_or("generated secret missing")?;
    let value = crate::decrypt_secret_version(
        &context,
        &store,
        project_id,
        &profile.id,
        &secret,
        secret.current_version,
    )?;
    assert_eq!(value.len(), 32);
    assert!(value.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert!(!std::str::from_utf8(&output)?.contains(value.as_str()));

    for (format, bytes) in [("alphanumeric", "15"), ("base64url", "257"), ("uuid", "17")] {
        output.clear();
        let code = run_with_context(
            Cli::try_parse_from([
                "locket",
                "generate",
                "REJECTED_TOKEN",
                "--format",
                format,
                "--bytes",
                bytes,
                "--json",
            ])?,
            &context,
            &mut output,
        )?;
        assert_eq!(code, locket_core::LocketError::MetadataInvalid.exit_code());
        let error: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(error["error"]["code"], "MetadataInvalid");
        assert!(
            store
                .get_secret_by_source(project_id, &profile.id, "REJECTED_TOKEN", "user-local")?
                .is_none()
        );
    }
    Ok(())
}
