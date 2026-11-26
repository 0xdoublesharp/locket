#[allow(unused_imports)]
use super::*;

#[test]
fn rotate_history_and_purge_keep_values_hidden() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut output,
    )?;

    let set_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &set_args, "postgres://localhost/old", "manual", 1_000)?;

    let rotate_args = test_rotate_args("DATABASE_URL", Some("24h"));
    let grace_until = crate::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    let crate::RotationResult { version, .. } = crate::rotate_secret_value(
        &context,
        &rotate_args,
        "postgres://localhost/new",
        2_000,
        grace_until,
    )?;
    assert_eq!(version, 2);

    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL"])?,
        &context,
        &mut get_output,
    )?;
    let get_output = String::from_utf8(get_output)?;
    assert!(get_output.contains("version=2"));
    assert!(!get_output.contains("postgres://localhost/new"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/new\n");

    let mut history_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL"])?,
        &context,
        &mut history_output,
    )?;
    let history_output = String::from_utf8(history_output)?;
    assert!(history_output.contains("v1 state=deprecated"));
    assert!(history_output.contains("v2 state=current"));
    assert!(history_output.contains("grace_until="));
    assert!(!history_output.contains("postgres://localhost/old"));
    assert!(!history_output.contains("postgres://localhost/new"));

    let purge_args = ["locket", "purge", "DATABASE_URL", "--version", "1", "--force"];
    let mut purge_output = Vec::new();
    run_with_context(Cli::try_parse_from(purge_args)?, &context, &mut purge_output)?;
    assert!(String::from_utf8(purge_output)?.contains("versions=1"));

    let mut history_after_purge = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL"])?,
        &context,
        &mut history_after_purge,
    )?;
    let history_after_purge = String::from_utf8(history_after_purge)?;
    assert!(history_after_purge.contains("v1 state=purged"));
    assert!(history_after_purge.contains("v2 state=current"));

    let invalid_purge_args = ["locket", "purge", "DATABASE_URL", "--version", "2", "--force"];
    let mut invalid_purge_output = Vec::new();
    let invalid_purge = run_with_context(
        Cli::try_parse_from(invalid_purge_args)?,
        &context,
        &mut invalid_purge_output,
    );
    assert!(invalid_purge.is_err());

    let mut rm_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "rm", "DATABASE_URL"])?,
        &context,
        &mut rm_output,
    )?;
    let purge_all_args = ["locket", "purge", "DATABASE_URL", "--all-versions", "--force"];
    let mut purge_all_output = Vec::new();
    run_with_context(Cli::try_parse_from(purge_all_args)?, &context, &mut purge_all_output)?;
    assert!(String::from_utf8(purge_all_output)?.contains("versions=1,2"));

    let mut audit_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "audit", "verify"])?,
        &context,
        &mut audit_output,
    )?;
    assert!(String::from_utf8(audit_output)?.contains("verified 7 row(s)"));

    assert_lifecycle_audit_log(&directory)?;
    Ok(())
}

#[test]
fn purge_requires_typed_confirmation_of_full_scope() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let setup_context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    let set_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(
        &setup_context,
        &set_args,
        "postgres://localhost/old",
        "manual",
        1_000,
    )?;
    let rotate_args = test_rotate_args("DATABASE_URL", Some("24h"));
    let grace_until = crate::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    crate::rotate_secret_value(
        &setup_context,
        &rotate_args,
        "postgres://localhost/new",
        2_000,
        grace_until,
    )?;

    let bad_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "purge dev/user-local/DATABASE_URL/v2\n",
    );
    let mut bad_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "purge", "DATABASE_URL", "--version", "1"])?,
        &bad_context,
        &mut bad_output,
    );
    assert_error_contains(result, "confirmation did not match");
    let bad_output = String::from_utf8(bad_output)?;
    assert!(bad_output.contains("purge_profile: dev"));
    assert!(bad_output.contains("purge_source: user-local"));
    assert!(bad_output.contains("purge_secret: DATABASE_URL"));
    assert!(bad_output.contains("purge_version_scope: v1"));
    assert!(bad_output.contains("metadata_only: yes"));

    let good_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "purge dev/user-local/DATABASE_URL/v1\n",
    );
    let mut good_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "purge", "DATABASE_URL", "--version", "1"])?,
        &good_context,
        &mut good_output,
    )?;
    let good_output = String::from_utf8(good_output)?;
    assert!(good_output.contains("purged DATABASE_URL"));
    assert!(good_output.contains("versions=1"));

    Ok(())
}

#[test]
fn purge_force_skips_confirmation_prompt() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let set_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &set_args, "tok-v1", "manual", 1_000)?;
    let rotate_args = test_rotate_args("API_KEY", Some("24h"));
    let grace = crate::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    crate::rotate_secret_value(&context, &rotate_args, "tok-v2", 2_000, grace)?;

    let mut force_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "purge", "API_KEY", "--version", "1", "--force"])?,
        &context,
        &mut force_output,
    )?;
    let force_output = String::from_utf8(force_output)?;
    assert!(force_output.contains("purged API_KEY"));
    assert!(!force_output.contains("type 'purge"));
    Ok(())
}

#[test]
fn purge_already_purged_skips_confirmation_and_writes_no_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let set_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &set_args, "tok-v1", "manual", 1_000)?;
    let rotate_args = test_rotate_args("API_KEY", Some("24h"));
    let grace = crate::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    crate::rotate_secret_value(&context, &rotate_args, "tok-v2", 2_000, grace)?;

    run_with_context(
        Cli::try_parse_from(["locket", "purge", "API_KEY", "--version", "1", "--force"])?,
        &context,
        &mut Vec::new(),
    )?;
    let store_pre = crate::open_store(&context)?;
    let count_before: i64 = store_pre.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PURGE'",
        [],
        |row| row.get(0),
    )?;
    drop(store_pre);

    let no_confirm_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "should-not-be-read\n",
    );
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "purge", "API_KEY", "--version", "1"])?,
        &no_confirm_context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("already purged"));
    let store_post = crate::open_store(&no_confirm_context)?;
    let count_after: i64 = store_post.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PURGE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count_before, count_after, "no-op purge must not write audit");
    Ok(())
}

#[test]
fn history_filters_by_source_state_limit_and_renders_iso_timestamps()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut output,
    )?;

    let user_local = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &user_local, "postgres://localhost/u-v1", "manual", 1_000)?;
    let rotate_user = test_rotate_args("DATABASE_URL", Some("24h"));
    let grace_user = crate::grace_until_from_args(rotate_user.grace_ttl.as_deref(), 2_000)?;
    crate::rotate_secret_value(
        &context,
        &rotate_user,
        "postgres://localhost/u-v2",
        2_000,
        grace_user,
    )?;

    let mut machine_local = test_secret_write_args("DATABASE_URL");
    machine_local.source = crate::SourceArg { source: Some(crate::SecretSourceArg::MachineLocal) };
    crate::set_secret_value(
        &context,
        &machine_local,
        "postgres://localhost/m-v1",
        "manual",
        3_000,
    )?;

    let mut all_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL"])?,
        &context,
        &mut all_output,
    )?;
    let all_output = String::from_utf8(all_output)?;
    assert!(all_output.contains("history DATABASE_URL profile=dev"));
    assert!(all_output.contains("source=user-local"));
    assert!(all_output.contains("source=machine-local"));
    assert!(all_output.contains("v1 state=deprecated"));
    assert!(all_output.contains("v2 state=current"));
    assert!(all_output.contains("created_at=1000(1970-01-01T00:00:00.000001000Z)"));
    assert!(!all_output.contains("postgres://"));

    let mut user_only = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL", "--source", "user-local"])?,
        &context,
        &mut user_only,
    )?;
    let user_only = String::from_utf8(user_only)?;
    assert!(user_only.contains("source=user-local"));
    assert!(!user_only.contains("source=machine-local"));

    let mut current_only = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "history",
            "DATABASE_URL",
            "--source",
            "user-local",
            "--state",
            "current",
        ])?,
        &context,
        &mut current_only,
    )?;
    let current_only = String::from_utf8(current_only)?;
    assert!(current_only.contains("v2 state=current"));
    assert!(!current_only.contains("v1 state=deprecated"));

    let mut limit_one = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "history",
            "DATABASE_URL",
            "--source",
            "user-local",
            "--limit",
            "1",
        ])?,
        &context,
        &mut limit_one,
    )?;
    let limit_one = String::from_utf8(limit_one)?;
    let version_lines = limit_one.matches("\n  v").count();
    assert_eq!(version_lines, 1, "limit=1 should print exactly one version line");

    Ok(())
}

#[test]
fn history_state_filter_prints_no_versions_notice_and_exits_ok()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("API_TOKEN");
    crate::set_secret_value(&context, &args, "tok-v1", "manual", 1_000)?;

    let mut history_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "API_TOKEN", "--state", "purged"])?,
        &context,
        &mut history_output,
    )?;
    let history_output = String::from_utf8(history_output)?;
    assert!(history_output.contains("history: no versions"));
    assert!(!history_output.contains("v1"));
    Ok(())
}

#[test]
fn history_unknown_source_fails_without_listing_other_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("API_TOKEN");
    crate::set_secret_value(&context, &args, "tok-v1", "manual", 1_000)?;

    let mut history_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "history", "API_TOKEN", "--source", "team-managed"])?,
        &context,
        &mut history_output,
    );
    assert!(result.is_err(), "missing source should error");
    assert_eq!(history_output.len(), 0);
    Ok(())
}

#[test]
fn history_missing_key_errors_with_secret_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut output,
    )?;
    let mut history_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "history", "NOPE_TOKEN"])?,
        &context,
        &mut history_output,
    );
    assert_error_contains(result, "secret not found");
    Ok(())
}

#[test]
fn unix_nanos_to_rfc3339_renders_known_timestamps() {
    assert_eq!(crate::unix_nanos_to_rfc3339(0), Some("1970-01-01T00:00:00.000000000Z".to_owned()));
    assert_eq!(
        crate::unix_nanos_to_rfc3339(1_700_000_000_000_000_000),
        Some("2023-11-14T22:13:20.000000000Z".to_owned())
    );
    assert_eq!(crate::unix_nanos_to_rfc3339(-1), None);
}

#[test]
fn optional_formatters_use_dash_for_absent_values() {
    assert_eq!(crate::optional_i64(None), "-");
    assert_eq!(crate::format_optional_unix_nanos(None), "-");
    assert_eq!(crate::format_optional_str(None), "-");
    assert_eq!(crate::format_optional_str(Some("run")), "run");
}

#[test]
fn import_env_encrypts_values_and_refreshes_example() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut output,
    )?;
    std::fs::write(
        directory.path().join(".env"),
        "DATABASE_URL=postgres://localhost/app\nINVALID-NAME=value\nOPENAI_API_KEY='sk_test_sample'\n",
    )?;

    let mut import_output = Vec::new();
    let error = run_with_context(
        Cli::try_parse_from(["locket", "import", ".env"])?,
        &context,
        &mut import_output,
    )
    .err()
    .ok_or("invalid dotenv must fail before writes")?;
    assert!(error.to_string().contains("line 2"));
    assert!(!error.to_string().contains("value"));
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("imported: 0"));
    assert!(import_output.contains("invalid: 1"));
    let store = crate::open_store(&context)?;
    let resolved = crate::require_project(&context)?;
    let profile = crate::default_profile(&store, &resolved.config)?;
    assert_eq!(
        store.list_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?,
        [] as [locket_store::SecretRecord; 0]
    );
    assert!(directory.path().join(".env").exists());
    assert!(!import_output.contains("postgres://localhost/app"));
    std::fs::write(
        directory.path().join(".env"),
        "DATABASE_URL=postgres://localhost/app\nOPENAI_API_KEY='sk_test_sample'\n",
    )?;
    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env"])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("imported: 2"));
    assert!(import_output.contains("profile: dev"));
    assert!(import_output.contains("source: user-local"));
    assert!(import_output.contains("missing_in_profile: none"));
    assert!(import_output.contains("delete_env: kept"));
    assert!(import_output.contains("metadata_only: yes"));
    assert!(!import_output.contains("postgres://localhost/app"));

    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains("DATABASE_URL="));
    assert!(example.contains("OPENAI_API_KEY="));
    assert!(!example.contains("postgres://localhost/app"));

    std::fs::write(directory.path().join(".env"), "DATABASE_URL=postgres://localhost/new\n")?;
    let mut duplicate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env"])?,
        &context,
        &mut duplicate_output,
    )?;
    let duplicate_output = String::from_utf8(duplicate_output)?;
    assert!(duplicate_output.contains("imported: 0"));
    assert!(duplicate_output.contains("skipped: 1"));
    assert!(duplicate_output.contains("skipped_names: DATABASE_URL"));
    assert!(!duplicate_output.contains("postgres://localhost/new"));

    let mut overwrite_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--overwrite"])?,
        &context,
        &mut overwrite_output,
    )?;
    let overwrite_output = String::from_utf8(overwrite_output)?;
    assert!(overwrite_output.contains("overwritten: 1"));
    assert!(!overwrite_output.contains("postgres://localhost/new"));

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
fn import_env_targets_named_profile_and_reports_parity() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::write(directory.path().join(".env"), "API_KEY=sk_test_stagingImport123\n")?;

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--profile", "staging"])?,
        &context,
        &mut import_output,
    )?;

    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("imported: 1"));
    assert!(import_output.contains("profile: staging"));
    assert!(import_output.contains("env_names: 1"));
    assert!(import_output.contains("profile_names: 1"));
    assert!(import_output.contains("missing_in_profile: none"));
    assert!(import_output.contains("extra_in_profile: none"));
    assert!(import_output.contains("delete_env: kept"));
    assert!(!import_output.contains("sk_test_stagingImport123"));

    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let staging = store
        .get_profile_by_name(resolved.config.project_id.as_str(), "staging")?
        .ok_or("staging profile should exist")?;
    let secret = store
        .get_secret_by_source(
            resolved.config.project_id.as_str(),
            &staging.id,
            "API_KEY",
            "user-local",
        )?
        .ok_or("imported secret should exist")?;
    assert_eq!(secret.origin, "imported");
    assert_eq!(secret.current_version, 1);
    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'IMPORT'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("\"secret_name\":\"API_KEY\""));
    assert!(audit_metadata.contains(&staging.id));
    assert!(!audit_metadata.contains("sk_test_stagingImport123"));
    Ok(())
}

#[test]
fn import_overwrite_to_dangerous_profile_requires_confirmation_before_rotation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "prod"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mark_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "prod\n");
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "prod"])?,
        &mark_context,
        &mut Vec::new(),
    )?;
    std::fs::write(directory.path().join(".env"), "API_KEY=sk_test_prodOriginal123\n")?;
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--profile", "prod"])?,
        &context,
        &mut Vec::new(),
    )?;

    std::fs::write(directory.path().join(".env"), "API_KEY=sk_test_prodRotated123\n")?;
    let mut overwrite_output = Vec::new();
    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "import", ".env", "--profile", "prod", "--overwrite"])?,
            &context,
            &mut overwrite_output,
        ),
        "dangerous profile",
    );
    let overwrite_output = String::from_utf8(overwrite_output)?;
    assert!(overwrite_output.contains("dangerous_profile: prod"));
    assert!(!overwrite_output.contains("sk_test_prodRotated123"));

    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let prod = store
        .get_profile_by_name(resolved.config.project_id.as_str(), "prod")?
        .ok_or("prod profile should exist")?;
    let secret = store
        .get_secret_by_source(
            resolved.config.project_id.as_str(),
            &prod.id,
            "API_KEY",
            "user-local",
        )?
        .ok_or("prod import should exist")?;
    assert_eq!(secret.current_version, 1);
    Ok(())
}

#[test]
fn import_with_delete_confirmation_removes_env_and_emits_example()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let secret_value = "postgres://user:secret@db.example.local/myapp";
    std::fs::write(
        directory.path().join(".env"),
        format!("DATABASE_URL={secret_value}\nAPI_TOKEN=tok_test_abc123\n"),
    )?;

    let confirm_context = context_with_confirmation(&context, "delete .env\n");
    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env"])?,
        &confirm_context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("imported: 2"), "output: {import_output}");
    assert!(import_output.contains("delete_env: deleted"), "output: {import_output}");
    assert!(!import_output.contains(secret_value), "secret value must not appear in output");
    assert!(!import_output.contains("tok_test_abc123"), "secret value must not appear in output");

    assert!(!directory.path().join(".env").exists(), ".env should be deleted after confirmation");

    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains("DATABASE_URL="), ".env.example should list DATABASE_URL");
    assert!(example.contains("API_TOKEN="), ".env.example should list API_TOKEN");
    assert!(!example.contains(secret_value), "secret value must not appear in .env.example");
    assert!(!example.contains("tok_test_abc123"), "secret value must not appear in .env.example");

    Ok(())
}

#[test]
fn import_multiline_empty_and_literal_values_roundtrip_without_expansion()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::write(
        directory.path().join(".env"),
        "MULTILINE='first\nsecond'\nEMPTY=''\nLITERAL='${HOME}'\n",
    )?;
    let error = run_with_context(
        Cli::try_parse_from(["locket", "import", ".env"])?,
        &context,
        &mut Vec::new(),
    )
    .err()
    .ok_or("expansion must fail by default")?;
    assert!(error.to_string().contains("line 4"));
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--literal"])?,
        &context,
        &mut Vec::new(),
    )?;
    for (name, expected) in
        [("MULTILINE", "first\nsecond\n"), ("EMPTY", "\n"), ("LITERAL", "${HOME}\n")]
    {
        let mut output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "get", name, "--reveal", "--force"])?,
            &context,
            &mut output,
        )?;
        assert_eq!(String::from_utf8(output)?, expected);
    }
    Ok(())
}

#[test]
fn import_rolls_back_all_values_when_a_later_write_fails() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    let store = crate::open_store(&context)?;
    store.connection().execute_batch("CREATE TRIGGER reject_second_import BEFORE INSERT ON secrets WHEN NEW.name = 'SECOND' BEGIN SELECT RAISE(ABORT, 'fixture rejection'); END;")?;
    std::fs::write(directory.path().join(".env"), "FIRST=one\nSECOND=two\n")?;
    assert!(
        run_with_context(
            Cli::try_parse_from(["locket", "import", ".env"])?,
            &context,
            &mut Vec::new()
        )
        .is_err()
    );
    let resolved = crate::require_project(&context)?;
    let profile = crate::default_profile(&store, &resolved.config)?;
    assert_eq!(
        store.list_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?,
        [] as [locket_store::SecretRecord; 0]
    );
    let rows: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action='IMPORT'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(rows, 0);
    assert!(directory.path().join(".env").exists());
    Ok(())
}

#[test]
fn import_never_deletes_skipped_plaintext_values() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let context =
        test_context_with_key_store_and_confirmation(&directory, key_store, "delete .env");
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(&context, &test_secret_write_args("EXISTS"), "old", "manual", 1000)?;
    std::fs::write(directory.path().join(".env"), "EXISTS=new\n")?;
    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "import", ".env"])?, &context, &mut output)?;
    assert!(directory.path().join(".env").exists());
    assert!(String::from_utf8(output)?.contains("delete_env: kept"));
    Ok(())
}

fn run_env_json(
    context: &RuntimeContext,
    args: &[&str],
    canaries: &[&str],
) -> Result<(u8, serde_json::Value), Box<dyn std::error::Error>> {
    let (code, output) = run_env_command(context, args, canaries)?;
    Ok((code, serde_json::from_str(&output)?))
}

fn run_env_command(
    context: &RuntimeContext,
    args: &[&str],
    canaries: &[&str],
) -> Result<(u8, String), Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(std::iter::once("locket").chain(args.iter().copied()))?,
        context,
        &mut output,
    );
    let output = String::from_utf8(output)?;
    for canary in canaries {
        assert!(!output.contains(canary));
        assert!(!result.as_ref().is_err_and(|error| error.to_string().contains(canary)));
    }
    Ok((result?, output))
}

#[test]
fn import_archive_preserves_bytes_and_creates_distinct_private_backups()
-> Result<(), Box<dyn std::error::Error>> {
    let project = tempdir()?;
    let context = test_context(&project);
    let outside = tempdir()?;
    let archive = outside.path().join("backups");
    let archive_arg = archive.to_str().ok_or("archive path must be UTF-8")?;
    let source = project.path().join(".env");
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;

    for value in ["first-archive-fixture", "second-archive-fixture"] {
        let contents = format!("# preserve comments and line endings\r\nTOKEN='{value}'\r\n");
        fs::write(&source, &contents)?;
        let (code, report) = run_env_json(
            &context,
            &["import", ".env", "--archive", archive_arg, "--overwrite", "--json"],
            &[value],
        )?;
        assert_eq!(code, 0);
        assert_eq!(report["delete_env"], "archived");
        let archived = Path::new(report["archived_to"].as_str().ok_or("missing archive path")?);
        assert_eq!(archived.parent(), Some(archive.canonicalize()?.as_path()));
        assert_eq!(fs::read(archived)?, contents.as_bytes());
        assert!(!source.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(fs::metadata(archived)?.permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&archive)?.permissions().mode() & 0o777, 0o700);
        }
    }
    let backups = fs::read_dir(&archive)?
        .map(|entry| fs::read_to_string(entry?.path()))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(backups.len(), 2);
    assert!(backups.iter().any(|contents| contents.contains("first-archive-fixture")));
    Ok(())
}

#[test]
fn import_archive_dry_run_leaves_source_and_destination_untouched()
-> Result<(), Box<dyn std::error::Error>> {
    let project = tempdir()?;
    let context = test_context(&project);
    let source = project.path().join(".env");
    let contents = "TOKEN=dry-run-archive-fixture\n";
    fs::write(&source, contents)?;
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = ["import", ".env", "--archive", "new/backups", "--dry-run"];
    let mut output = Vec::new();
    assert_eq!(
        run_with_context(
            Cli::try_parse_from(std::iter::once("locket").chain(args))?,
            &context,
            &mut output
        )?,
        0
    );
    let output = String::from_utf8(output)?;
    assert!(output.contains("delete_env: would-archive"));
    assert!(!output.contains("dry-run-archive-fixture"));

    let mut json_args = args.to_vec();
    json_args.push("--json");
    let (code, report) = run_env_json(&context, &json_args, &["dry-run-archive-fixture"])?;
    assert_eq!(code, 0);
    assert_eq!(report["delete_env"], "would-archive");
    assert!(report.get("archived_to").is_none());
    assert_eq!(fs::read_to_string(source)?, contents);
    assert!(!project.path().join("new").exists());
    assert!(
        Cli::try_parse_from(["locket", "import", ".env", "--archive", "backups", "--keep"])
            .is_err()
    );
    Ok(())
}

#[test]
fn import_archive_keeps_source_when_keys_are_skipped_or_filtered()
-> Result<(), Box<dyn std::error::Error>> {
    let project = tempdir()?;
    let context = test_context(&project);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(
        &context,
        &test_secret_write_args("TOKEN"),
        "vault-archive-fixture",
        "manual",
        1000,
    )?;
    let source = project.path().join(".env");
    let contents = "TOKEN=skipped-archive-fixture\nNEW=imported-archive-fixture\n";
    fs::write(&source, contents)?;

    let canaries = ["skipped-archive-fixture", "imported-archive-fixture", "vault-archive-fixture"];
    let skipped = "skipped keys exist; pass --archive-if-matching to verify skipped values against the vault and archive, or --overwrite to replace them";
    let filtered = "filtered keys exist; archive requires importing all keys in the file";
    for (options, reason) in [
        (&["--dry-run"][..], skipped),
        (&["--dry-run", "--only", "TOKEN", "--archive-if-matching"][..], filtered),
        (&["--exclude", "TOKEN", "--overwrite"][..], filtered),
        (&[][..], skipped),
    ] {
        let mut args = vec!["import", ".env", "--archive", "backups"];
        args.extend_from_slice(options);
        let (code, output) = run_env_command(&context, &args, &canaries)?;
        assert_eq!(code, 0);
        assert!(output.contains(&format!("delete_env: kept\narchive_blocked: {reason}\n")));
        assert!(!output.contains("would-archive"));

        args.push("--json");
        let (code, report) = run_env_json(&context, &args, &canaries)?;
        assert_eq!(code, 0);
        assert_eq!(report["delete_env"], "kept");
        assert_eq!(report["archive_blocked_reason"], reason);
        assert!(report.get("archived_to").is_none());
        assert!(report.get("mismatched_names").is_none());
        assert!(report.get("verified_matching").is_none());
        assert!(fs::read(&source)?.as_slice().eq(contents.as_bytes()), "source changed");
        assert!(!project.path().join("backups").exists());
    }
    Ok(())
}

#[test]
fn import_archive_keeps_empty_source() -> Result<(), Box<dyn std::error::Error>> {
    let project = tempdir()?;
    let context = test_context(&project);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    let source = project.path().join(".env");
    fs::write(&source, "# no entries\n")?;

    for options in [&["--dry-run"][..], &[][..]] {
        let mut args = vec!["import", ".env", "--archive", "backups", "--json"];
        args.extend_from_slice(options);
        let (code, report) = run_env_json(&context, &args, &[])?;
        assert_eq!(code, 0);
        assert_eq!(report["delete_env"], "kept");
        assert_eq!(report["archive_blocked_reason"], "no keys to import");
        assert!(report.get("archived_to").is_none());
        assert!(source.is_file());
        assert!(!project.path().join("backups").exists());
    }
    Ok(())
}

#[test]
fn import_archive_if_matching_previews_and_archives_an_already_imported_file()
-> Result<(), Box<dyn std::error::Error>> {
    let project = tempdir()?;
    let outside = tempdir()?;
    let context = test_context(&project);
    let archive = outside.path().join("backups");
    let archive_arg = archive.to_str().ok_or("archive path must be UTF-8")?;
    let source = project.path().join(".env");
    let canaries = [
        "archive-match-token-fixture",
        "archive-match-zeta-fixture",
        "archive-higher-precedence-fixture",
    ];
    let contents = format!(
        "# preserve comment and line endings\r\nZETA=\"{}\"\r\nTOKEN='{}'\r\n",
        canaries[1], canaries[0]
    );
    fs::write(&source, &contents)?;
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    assert_eq!(run_env_json(&context, &["import", ".env", "--keep", "--json"], &canaries)?.0, 0);
    crate::set_secret_value(
        &context,
        &test_secret_write_args_for_source("TOKEN", crate::SecretSourceArg::MachineLocal),
        canaries[2],
        "manual",
        1000,
    )?;

    // A missing endpoint still allows direct key access on Unix.
    #[cfg(unix)]
    let context = RuntimeContext { agent_data_dir: Some(outside.path().join("agent")), ..context };
    let args = [
        "import",
        ".env",
        "--source",
        "user-local",
        "--archive",
        archive_arg,
        "--archive-if-matching",
    ];
    let mut preview = args.to_vec();
    preview.extend(["--dry-run", "--json"]);
    let no_key =
        RuntimeContext { key_store: Arc::new(UnavailableMasterKeyStore), ..context.clone() };
    let (code, report) = run_env_json(&no_key, &preview, &canaries)?;
    assert_eq!(code, 72);
    assert_eq!(report["error"]["code"], "UnlockRequired");
    assert_eq!(
        report["error"]["message"],
        "unlock the project vault with `locket unlock` before verifying skipped values against the vault"
    );
    let (code, report) = run_env_json(&context, &preview, &canaries)?;
    assert_eq!(code, 0);
    assert_eq!(report["skipped"], 2);
    assert_eq!(report["verified_matching"], 2);
    assert_eq!(report["verified_matching_names"], serde_json::json!(["TOKEN", "ZETA"]));
    assert_eq!(report["delete_env"], "would-archive");
    assert!(
        report["archive_scope_note"]
            .as_str()
            .is_some_and(|note| note.contains("checks vault values only")),
        "missing archive_scope_note: {report}"
    );
    assert!(report.get("archive_consumer_warnings").is_none());
    fs::write(
        dir.path().join("docker-compose.yml"),
        "services:\n  web:\n    env_file:\n      - .env\n",
    )?;
    let (code, compose_report) = run_env_json(&context, &preview, &canaries)?;
    assert_eq!(code, 0);
    assert!(
        compose_report["archive_consumer_warnings"].as_array().is_some_and(|items| items
            .iter()
            .any(|item| item.as_str().is_some_and(|s| s.contains("docker-compose.yml")))),
        "expected docker-compose warning: {compose_report}"
    );
    fs::remove_file(dir.path().join("docker-compose.yml"))?;
    assert!(report.get("archive_blocked_reason").is_none());
    assert!(report.get("mismatched_names").is_none());
    assert!(report.get("archived_to").is_none());
    assert!(fs::read(&source)?.as_slice().eq(contents.as_bytes()), "source changed");
    assert!(!archive.exists());

    let (code, output) = run_env_command(&context, &args, &canaries)?;
    assert_eq!(code, 0);
    assert!(output.contains("imported: 0\n"));
    assert!(output.contains("skipped: 2\n"));
    assert!(output.contains("verified_matching: 2\n"));
    assert!(output.contains("delete_env: archived\n"));
    let archived = output
        .lines()
        .find_map(|line| line.strip_prefix("archived_to: "))
        .ok_or("missing archive path")?;
    let archived = Path::new(archived);
    assert_eq!(archived.parent(), Some(archive.canonicalize()?.as_path()));
    assert!(fs::read(archived)?.as_slice().eq(contents.as_bytes()), "backup bytes changed");
    assert!(!source.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(fs::metadata(archived)?.permissions().mode() & 0o777, 0o600);
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Default)]
struct ImportTestKeyStore {
    keys: MemoryMasterKeyStore,
    loads: std::sync::atomic::AtomicUsize,
}

#[cfg(unix)]
impl MasterKeyStore for ImportTestKeyStore {
    fn store_master_key(
        &self,
        project_id: &str,
        key: &locket_crypto::KeyBytes,
    ) -> Result<(), PlatformError> {
        self.keys.store_master_key(project_id, key)
    }

    fn load_master_key(
        &self,
        project_id: &str,
    ) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, PlatformError> {
        self.loads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.keys.load_master_key(project_id)
    }

    fn delete_master_key(&self, project_id: &str) -> Result<(), PlatformError> {
        self.keys.delete_master_key(project_id)
    }
}

#[cfg(unix)]
#[test]
fn import_archive_if_matching_refuses_a_live_locked_vault()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    let project = tempdir()?;
    let archive = project.path().join("backups");
    let source = project.path().join(".env");
    let contents = b"TOKEN=archive-locked-fixture\n";
    fs::write(&source, contents)?;
    let key_store = Arc::new(ImportTestKeyStore::default());
    let context = test_context_with_key_store(&project, key_store.clone());
    // Seed shared metadata first so a premature fingerprint lookup will hit
    // the test key store. The project created next retains an accessible key.
    run_with_context(
        Cli::try_parse_from(["locket", "shared", "init"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--keep"])?,
        &context,
        &mut Vec::new(),
    )?;

    let agent = tempfile::Builder::new().prefix("a").rand_bytes(4).tempdir()?;
    fs::set_permissions(agent.path(), fs::Permissions::from_mode(0o700))?;
    let context = RuntimeContext { agent_data_dir: Some(agent.path().into()), ..context };
    let socket = crate::agent_socket_path(&context);
    let server =
        super::agent_lifecycle::serve_status_requests(socket.clone(), env!("CARGO_PKG_VERSION"), 4);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let project_id = crate::require_project(&context)?.config.project_id;
    drop(key_store.load_master_key(project_id.as_str())?);
    key_store.loads.store(0, Ordering::Relaxed);
    let snapshot =
        crate::commands::agent::request_project_status_snapshot(&socket, project_id.as_str())?;
    assert_eq!(snapshot["project_id"], project_id.as_str());
    assert_eq!(snapshot["lock_state"], "locked");

    let args = ["locket", "import", ".env", "--archive", "backups", "--archive-if-matching"];
    for extra in [&["--dry-run"][..], &["--dry-run", "--json"][..], &[][..]] {
        let mut output = Vec::new();
        let result = run_with_context(
            Cli::try_parse_from(args.into_iter().chain(extra.iter().copied()))?,
            &context,
            &mut output,
        );
        if extra.contains(&"--json") {
            assert_eq!(result?, 72);
            let report: serde_json::Value = serde_json::from_slice(&output)?;
            assert_eq!(report["error"]["code"], "UnlockRequired");
            assert!(report["error"]["message"].as_str().is_some_and(|message| {
                message.contains("unlock the project vault with `locket unlock`")
            }));
        } else {
            let Err(error) = result else {
                return Err("expected the live locked vault to block verification".into());
            };
            assert_eq!(error.exit_code(), 72);
            assert!(matches!(
                error,
                crate::CliError::Typed { kind: locket_core::LocketError::UnlockRequired, .. }
            ));
            assert!(error.to_string().contains("unlock the project vault with `locket unlock`"));
        }
        assert!(fs::read(&source)?.as_slice() == contents, "source changed");
        assert!(!archive.exists());
        assert_eq!(key_store.loads.load(Ordering::Relaxed), 0);
    }
    server.join().map_err(|_| "serve thread panicked")??;
    Ok(())
}

#[test]
fn import_archive_if_matching_keeps_the_source_if_any_skipped_values_differ()
-> Result<(), Box<dyn std::error::Error>> {
    let project = tempdir()?;
    let context = test_context(&project);
    let source = project.path().join(".env");
    let canaries = [
        "archive-vault-zeta-fixture",
        "archive-vault-alpha-fixture",
        "archive-input-zeta-fixture",
        "archive-input-alpha",
        "archive-matching-fixture",
    ];
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    fs::write(
        &source,
        format!("ZETA={}\nALPHA={}\nMATCH={}\n", canaries[0], canaries[1], canaries[4]),
    )?;
    assert_eq!(run_env_json(&context, &["import", ".env", "--keep", "--json"], &canaries)?.0, 0);
    for (options, alpha, matching, mismatched) in [
        (&["--dry-run"][..], canaries[3], &["MATCH"][..], &["ALPHA", "ZETA"][..]),
        (&[][..], canaries[1], &["ALPHA", "MATCH"][..], &["ZETA"][..]),
    ] {
        let contents = format!("ZETA={}\nALPHA={alpha}\nMATCH={}\n", canaries[2], canaries[4]);
        fs::write(&source, &contents)?;
        let mut args = vec!["import", ".env", "--archive", "backups", "--archive-if-matching"];
        args.extend_from_slice(options);
        let reason = format!("skipped keys differ from the vault: {}", mismatched.join(", "));
        let (code, output) = run_env_command(&context, &args, &canaries)?;
        assert_eq!(code, 0);
        assert!(output.contains(&format!("verified_matching: {}\n", matching.len())));
        assert!(output.contains(&format!("mismatched_names: {}\n", mismatched.join(","))));
        assert!(output.contains(&format!("delete_env: kept\narchive_blocked: {reason}\n")));

        args.push("--json");
        let (code, report) = run_env_json(&context, &args, &canaries)?;
        assert_eq!(code, 0);
        assert_eq!(report["skipped"], 3);
        assert_eq!(report["verified_matching"], matching.len());
        assert_eq!(report["verified_matching_names"], serde_json::json!(matching));
        assert_eq!(report["mismatched_names"], serde_json::json!(mismatched));
        assert_eq!(report["archive_blocked_reason"], reason);
        assert_eq!(report["delete_env"], "kept");
        assert!(report.get("archived_to").is_none());
        assert!(fs::read(&source)?.as_slice().eq(contents.as_bytes()), "source changed");
        assert!(!project.path().join("backups").exists());
    }
    Ok(())
}

#[test]
fn import_archive_if_matching_requires_archive() {
    let result = Cli::try_parse_from(["locket", "import", ".env", "--archive-if-matching"]);
    assert!(
        matches!(result, Err(error) if error.kind() == clap::error::ErrorKind::MissingRequiredArgument && error.to_string().contains("--archive <DIR>"))
    );
}

#[test]
fn import_archive_requires_git_ignore_inside_project() -> Result<(), Box<dyn std::error::Error>> {
    let project = tempdir()?;
    run_git(project.path(), &["init", "-q"])?;
    let context = test_context(&project);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    let directory = project.path().join("backups");
    let source = project.path().join(".env");
    let contents = "TOKEN=ignored-archive-fixture\n";
    fs::write(&source, contents)?;
    let (code, report) = run_env_json(
        &context,
        &["import", ".env", "--archive", "backups", "--json"],
        &["ignored-archive-fixture"],
    )?;
    assert_ne!(code, 0);
    assert!(
        report["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("must be ignored by Git"))
    );
    assert_eq!(fs::read_to_string(&source)?, contents);
    assert_eq!(fs::read_dir(&directory)?.count(), 0);

    let mut gitignore =
        fs::OpenOptions::new().append(true).open(project.path().join(".gitignore"))?;
    writeln!(gitignore, "/backups/")?;
    let mut output = Vec::new();
    assert_eq!(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "import",
                ".env",
                "--archive",
                "backups",
                "--overwrite"
            ])?,
            &context,
            &mut output,
        )?,
        0
    );
    let output = String::from_utf8(output)?;
    assert!(output.contains("delete_env: archived"));
    assert!(output.contains("archived_to: "));
    assert!(!output.contains("ignored-archive-fixture"));
    assert!(!source.exists());
    assert_eq!(fs::read_dir(directory)?.count(), 1);
    Ok(())
}

#[cfg(unix)]
#[test]
fn import_archive_rejects_symlink_destination_and_preserves_source()
-> Result<(), Box<dyn std::error::Error>> {
    let project = tempdir()?;
    let outside = tempdir()?;
    let context = test_context(&project);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    let source = project.path().join(".env");
    let contents = "TOKEN=symlink-archive-fixture\n";
    fs::write(&source, contents)?;
    std::os::unix::fs::symlink(outside.path(), project.path().join("backups"))?;
    let mut output = Vec::new();
    let code = run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--archive", "backups/", "--json"])?,
        &context,
        &mut output,
    )?;
    assert_ne!(code, 0);
    let output = String::from_utf8(output)?;
    assert!(output.contains("archive destination must be a directory"));
    assert!(!output.contains("symlink-archive-fixture"));
    assert_eq!(fs::read_to_string(source)?, contents);
    assert_eq!(fs::read_dir(outside.path())?.count(), 0);
    Ok(())
}

#[test]
fn env_import_selects_shared_keys_outside_a_project() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "delete .env");
    let (_, shared) = run_env_json(&context, &["shared", "init", "--json"], &[])?;
    let canaries =
        ["provider-alpha-secret", "provider-beta-secret", "database-secret", "other-secret"];
    let env_path = directory.path().join(".env");
    std::fs::write(
        &env_path,
        format!(
            "OPENAI_API_KEY={}\nANTHROPIC_API_KEY={}\nDATABASE_URL={}\nOTHER={}\n",
            canaries[0], canaries[1], canaries[2], canaries[3]
        ),
    )?;
    let (code, report) = run_env_json(
        &context,
        &[
            "import",
            ".env",
            "--project",
            "@shared",
            "--only",
            "OPENAI_API_KEY,ANTHROPIC_API_KEY",
            "--only",
            "DATABASE_URL",
            "--exclude",
            "DATABASE_URL",
            "--keep",
            "--json",
        ],
        &canaries,
    )?;
    assert_eq!(code, 0);
    assert_eq!(report["project_id"], shared["project_id"]);
    assert_eq!(report["project_name"], "@shared");
    assert_eq!(report["profile"], "default");
    assert_eq!(report["source"], "user-local");
    assert_eq!(report["imported"], 2);
    assert_eq!(
        report["imported_names"],
        serde_json::json!(["ANTHROPIC_API_KEY", "OPENAI_API_KEY"])
    );
    assert_eq!(report["filtered_out"], 2);
    assert_eq!(report["filtered_out_names"], serde_json::json!(["DATABASE_URL", "OTHER"]));
    assert_eq!(report["delete_env"], "kept");
    assert_eq!(report["metadata_only"], true);
    assert!(env_path.is_file());
    for file in ["locket.toml", ".env.example", ".gitignore"] {
        assert!(!directory.path().join(file).exists());
    }

    let project_id = shared["project_id"].as_str().ok_or("missing project id")?;
    let store = locket_store::Store::open_read_only(&context.store_path)?;
    let profile = store.get_profile_by_name(project_id, "default")?.ok_or("missing profile")?;
    assert_eq!(
        crate::active_profile_secret_names(&store, project_id, &profile.id)?,
        BTreeSet::from(["ANTHROPIC_API_KEY".to_owned(), "OPENAI_API_KEY".to_owned()])
    );
    let audit_metadata: Vec<String> = store
        .connection()
        .prepare("SELECT metadata_json FROM audit_log WHERE action='IMPORT'")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    assert_eq!(audit_metadata.len(), 2);
    assert!(audit_metadata.iter().all(|entry| canaries.iter().all(|value| !entry.contains(value))));
    Ok(())
}

#[test]
fn env_import_dry_run_keeps_vault_and_project_files_untouched()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(&context, &test_secret_write_args("EXISTS"), "old", "manual", 1000)?;
    let canaries =
        ["existing-plaintext-fixture", "new-plaintext-fixture", "excluded-plaintext-fixture"];
    let env_text =
        format!("EXISTS={}\nNEW={}\nEXCLUDE_ME={}\n", canaries[0], canaries[1], canaries[2]);
    let env_path = directory.path().join(".env");
    std::fs::write(&env_path, &env_text)?;
    for file in [".env.example", ".gitignore"] {
        std::fs::remove_file(directory.path().join(file))?;
    }
    let original_store = std::fs::read(&context.store_path)?;
    let locked = RuntimeContext { key_store: Arc::new(UnavailableMasterKeyStore), ..context };
    for overwrite in [false, true] {
        let mut args = vec!["import", ".env", "--exclude", "EXCLUDE_ME", "--dry-run", "--json"];
        if overwrite {
            args.push("--overwrite");
        }
        let (code, report) = run_env_json(&locked, &args, &canaries)?;
        assert_eq!(code, 0);
        assert_eq!(report["dry_run"], true);
        assert_eq!(report["imported"], 1);
        assert_eq!(report["imported_names"], serde_json::json!(["NEW"]));
        assert_eq!(report["skipped"], usize::from(!overwrite));
        assert_eq!(report["overwritten"], usize::from(overwrite));
        assert_eq!(report["filtered_out"], 1);
        assert_eq!(report["filtered_out_names"], serde_json::json!(["EXCLUDE_ME"]));
        assert_eq!(report["missing_in_profile"], serde_json::json!([]));
        assert_eq!(report["delete_env"], "kept");
    }
    let store_unchanged = std::fs::read(&locked.store_path)? == original_store;
    assert!(store_unchanged, "dry run changed the vault database");
    assert_eq!(std::fs::read_to_string(env_path)?, env_text);
    for file in [".env.example", ".gitignore"] {
        assert!(!directory.path().join(file).exists());
    }
    Ok(())
}

#[test]
fn env_keys_reports_strict_metadata_without_a_project() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let canaries = ["first-value-fixture", "replacement-value-fixture", "expansion-fixture"];
    std::fs::write(
        directory.path().join(".env"),
        format!("TOKEN={}\nTOKEN={}\nEXPANDED=${{{}}}\n", canaries[0], canaries[1], canaries[2]),
    )?;
    let args = ["env", "keys", ".env", "--json"];
    let (code, report) = run_env_json(&context, &args, &canaries)?;
    assert_eq!(code, 0);
    assert_eq!(report["keys"], serde_json::json!(["TOKEN"]));
    assert_eq!(report["warnings"][0]["line"], 2);
    assert!(report["warnings"][0]["message"].is_string());
    assert_eq!(report["invalid"], 1);
    assert_eq!(report["metadata_only"], true);
    let (_, literal) =
        run_env_json(&context, &["env", "keys", ".env", "--literal", "--json"], &canaries)?;
    assert_eq!(literal["keys"], serde_json::json!(["EXPANDED", "TOKEN"]));
    assert_eq!(literal["invalid"], 0);
    assert!(!context.store_path.exists());
    Ok(())
}

#[test]
fn env_scan_groups_keys_across_repos_and_ignores_templates()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let root = directory.path();
    let canaries = ["scan-one-fixture", "scan-two-fixture", "scan-three-fixture"];
    std::fs::create_dir_all(root.join("one/.git"))?;
    std::fs::create_dir_all(root.join("one/src"))?;
    std::fs::create_dir_all(root.join("one/node_modules/package"))?;
    std::fs::create_dir_all(root.join("two"))?;
    std::fs::write(root.join("two/locket.toml"), "")?;
    std::fs::write(
        root.join("one/src/.env.production"),
        format!(
            "BOTH={}\nOPENAI_API_KEY={}\nSAME_ROOT={}\n",
            canaries[0], canaries[0], canaries[0]
        ),
    )?;
    std::fs::write(root.join("one/.env.local"), format!("SAME_ROOT={}\n", canaries[1]))?;
    std::fs::write(root.join("two/.env.staging"), format!("BOTH={}\n", canaries[2]))?;
    for path in
        ["one/node_modules/package/.env", "two/.env.example", "two/.env.local.bak", "one/.git/.env"]
    {
        std::fs::write(root.join(path), "IGNORED=fixture\n")?;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("two"), root.join("link"))?;

    let (code, report) = run_env_json(&context, &["env", "scan", ".", "--json"], &canaries)?;
    assert_eq!(code, 0);
    assert_eq!(report["metadata_only"], true);
    assert_eq!(report["total_files"], 3);
    assert_eq!(report["total_keys"], 5);
    let files = report["files"].as_array().ok_or("missing files")?;
    assert_eq!(files[0]["suggested_profile"], "dev");
    assert_eq!(files[0]["suggested_source"], "user-local");
    assert_eq!(files[1]["suggested_profile"], "prod");
    assert_eq!(files[1]["has_locket_config"], false);
    assert_eq!(files[1]["project_root"], files[0]["project_root"]);
    assert_eq!(files[2]["suggested_profile"], "staging");
    assert_eq!(files[2]["has_locket_config"], true);
    let candidates = report["shared_candidates"].as_array().ok_or("missing candidates")?;
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0]["key"], "BOTH");
    assert_eq!(candidates[0]["projects"].as_array().map(Vec::len), Some(2));
    assert_eq!(candidates[0]["files"].as_array().map(Vec::len), Some(2));
    assert_eq!(candidates[1]["key"], "OPENAI_API_KEY");
    let (_, shallow) =
        run_env_json(&context, &["env", "scan", "--depth", "2", "--json"], &canaries)?;
    assert_eq!(shallow["total_files"], 2);
    assert!(!context.store_path.exists());
    Ok(())
}

#[test]
fn env_keys_rejects_unsafe_inputs_without_a_project() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let canary = "dotenv-unsafe-input-fixture";
    let mut invalid_utf8 = format!("TOKEN={canary}").into_bytes();
    invalid_utf8.push(0xff);
    std::fs::write(directory.path().join(".env.invalid"), invalid_utf8)?;
    std::fs::File::create(directory.path().join(".env.oversize"))?.set_len(1024 * 1024 + 1)?;
    std::fs::create_dir(directory.path().join(".env.directory"))?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(".env.invalid", directory.path().join(".env.link"))?;
    for (file, message) in [
        (".env.invalid", "UTF-8"),
        (".env.oversize", "1 MiB"),
        (".env.directory", "regular file"),
        #[cfg(unix)]
        (".env.link", "regular file"),
    ] {
        let (code, report) = run_env_json(&context, &["env", "keys", file, "--json"], &[canary])?;
        assert_ne!(code, 0);
        assert!(report["error"]["message"].as_str().is_some_and(|error| error.contains(message)));
    }
    assert!(!context.store_path.exists());
    Ok(())
}

#[test]
fn env_import_refreshes_the_selected_folder_and_keeps_plaintext()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let outside = test_context_with_confirmation(&directory, "delete .env");
    let project_root = directory.path().join("app");
    std::fs::create_dir(&project_root)?;
    let inside = RuntimeContext { cwd: project_root.clone(), ..outside.clone() };
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &inside,
        &mut Vec::new(),
    )?;
    let canary = "dotenv-folder-value-fixture";
    let source = directory.path().join(".env");
    std::fs::write(&source, format!("KEY={canary}\n"))?;
    std::fs::remove_file(project_root.join(".gitignore"))?;
    let mut output = Vec::new();
    assert_eq!(
        run_with_context(
            Cli::try_parse_from(["locket", "import", ".env", "--project", "app", "--keep"])?,
            &outside,
            &mut output,
        )?,
        0
    );
    let output = String::from_utf8(output)?;
    assert!(output.contains("delete_env: kept"));
    assert!(!output.contains("delete_env_prompt"));
    assert!(!output.contains(canary));
    assert!(source.exists());
    assert!(project_root.join(".gitignore").exists());
    let example = std::fs::read_to_string(project_root.join(".env.example"))?;
    assert!(example.contains("KEY=\n"));
    assert!(!example.contains(canary));
    assert!(!directory.path().join(".env.example").exists());
    assert!(!directory.path().join(".gitignore").exists());
    Ok(())
}

#[test]
fn import_overwrite_checks_the_current_profile_policy_before_mutating()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::commands::secrets::import::{EnvImportOptions, import_env_to_target};
    use crate::commands::secrets::set::select_target;
    use crate::{SecretSourceArg, open_store};
    use locket_core::LocketError;

    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let path = directory.path().join(".env");
    std::fs::write(&path, "TOKEN=first-fixture\n")?;
    let mut store = open_store(&context)?;
    let target = select_target(&context, &store, None, None)?;
    let mut options = EnvImportOptions {
        only: Vec::new(),
        exclude: Vec::new(),
        overwrite: false,
        literal: false,
        dry_run: false,
        archive: None,
        link_shared: false,
        promote_duplicates: false,
        confirmed_profiles: Vec::new(),
        source: SecretSourceArg::UserLocal,
    };
    import_env_to_target(&context, &mut store, &target, std::fs::File::open(&path)?, &options)?;
    assert!(store.set_profile_dangerous(&target.project.id, &target.profile.name, true)?);
    std::fs::write(&path, "TOKEN=second-fixture\n")?;
    options.overwrite = true;
    options.dry_run = true;
    let preview =
        import_env_to_target(&context, &mut store, &target, std::fs::File::open(&path)?, &options)?;
    assert_eq!(preview["overwritten"], 1);
    options.dry_run = false;
    let error =
        import_env_to_target(&context, &mut store, &target, std::fs::File::open(&path)?, &options)
            .err()
            .ok_or("overwrite needed confirmation after the policy change")?;
    assert_eq!(error.exit_code(), LocketError::DangerousProfileConfirmationRequired.exit_code());
    let current = store
        .get_secret_by_source(&target.project.id, &target.profile.id, "TOKEN", "user-local")?
        .ok_or("missing fixture secret")?;
    assert_eq!(current.current_version, 1);
    options.confirmed_profiles = vec![target.profile.name.clone()];
    let report =
        import_env_to_target(&context, &mut store, &target, std::fs::File::open(&path)?, &options)?;
    assert_eq!(report["overwritten"], 1);
    Ok(())
}
