#[allow(unused_imports)]
use super::*;

#[test]
fn diff_reports_profile_metadata_only_differences() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/dev-old", "manual", 1_000)?;
    let rotate_args = test_rotate_args("DATABASE_URL", None);
    crate::rotate_secret_value(
        &context,
        &rotate_args,
        "postgres://localhost/dev-new",
        2_000,
        None,
    )?;

    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    crate::set_secret_value(&context, &db_args, "postgres://localhost/staging", "manual", 3_000)?;
    let api_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &api_args, "sk_test_sample", "manual", 4_000)?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "dev", "staging"])?,
        &context,
        &mut diff_output,
    )?;
    let diff_output = String::from_utf8(diff_output)?;
    assert!(diff_output.contains("changed DATABASE_URL source=user-local"));
    assert!(diff_output.contains("dev_version=2"));
    assert!(diff_output.contains("staging_version=1"));
    assert!(diff_output.contains("only staging: API_KEY source=user-local version=1"));
    assert!(!diff_output.contains("postgres://localhost"));
    assert!(!diff_output.contains("sk_test_sample"));

    let mut empty_diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "staging", "staging"])?,
        &context,
        &mut empty_diff_output,
    )?;
    assert_eq!(String::from_utf8(empty_diff_output)?, "no differences\n");
    Ok(())
}

#[test]
fn diff_since_reports_active_profile_metadata_only_changes()
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
    crate::set_secret_value(&context, &db_args, "postgres://localhost/dev-old", "manual", 1_000)?;
    let rotate_args = test_rotate_args("DATABASE_URL", None);
    crate::rotate_secret_value(
        &context,
        &rotate_args,
        "postgres://localhost/dev-new",
        2_000,
        None,
    )?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "1970-01-01T00:00:00Z"])?,
        &context,
        &mut diff_output,
    )?;
    let diff_output = String::from_utf8(diff_output)?;
    assert!(diff_output.contains("profile: dev"));
    assert!(diff_output.contains("metadata_only: yes"));
    assert!(
        diff_output
            .contains("changed DATABASE_URL source=user-local state=active current_version=2")
    );
    assert!(diff_output.contains(
        "version DATABASE_URL source=user-local v1 state=deprecated created_at=1000 deprecated_at=2000"
    ));
    assert!(
        diff_output
            .contains("version DATABASE_URL source=user-local v2 state=current created_at=2000")
    );
    assert!(!diff_output.contains("postgres://localhost"));

    let mut empty_diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "1970-01-01T00:00:01Z"])?,
        &context,
        &mut empty_diff_output,
    )?;
    assert_eq!(String::from_utf8(empty_diff_output)?, "no differences\n");
    Ok(())
}

#[test]
fn diff_since_rejects_profile_arguments() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "diff",
            "--since",
            "1970-01-01T00:00:00Z",
            "dev",
            "staging",
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "diff --since uses the active profile");
    Ok(())
}

#[test]
fn diff_since_reports_only_active_profile() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let dev_args = test_secret_write_args("DEV_ONLY");
    crate::set_secret_value(&context, &dev_args, "dev-secret-value", "manual", 1_000)?;

    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    let staging_args = test_secret_write_args("STAGING_ONLY");
    crate::set_secret_value(&context, &staging_args, "staging-secret-value", "manual", 2_000)?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "1970-01-01T00:00:00Z"])?,
        &context,
        &mut diff_output,
    )?;
    let diff_output = String::from_utf8(diff_output)?;
    assert!(diff_output.contains("profile: staging"));
    assert!(diff_output.contains("changed STAGING_ONLY source=user-local"));
    assert!(!diff_output.contains("DEV_ONLY"));
    assert!(!diff_output.contains("dev-secret-value"));
    assert!(!diff_output.contains("staging-secret-value"));
    Ok(())
}

#[test]
fn diff_since_ignores_access_audit_rows() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/dev", "manual", 1_000)?;

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
    crate::get_command_with_clipboard(
        &context,
        &mut copy_output,
        &mut copy_stderr,
        &copy_args,
        |_value| Ok(()),
    )?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "1970-01-01T00:00:01Z"])?,
        &context,
        &mut diff_output,
    )?;
    assert_eq!(String::from_utf8(diff_output)?, "no differences\n");
    Ok(())
}

#[test]
fn diff_since_reports_metadata_updates() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/dev", "manual", 1_000)?;

    let mut meta_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--description",
            "primary database",
        ])?,
        &context,
        &mut meta_output,
    )?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "1970-01-01T00:00:01Z"])?,
        &context,
        &mut diff_output,
    )?;
    let diff_output = String::from_utf8(diff_output)?;
    assert!(diff_output.contains("action=SECRET_META_UPDATE"));
    assert!(!diff_output.contains("changed DATABASE_URL source=user-local"));
    assert!(!diff_output.contains("postgres://localhost"));
    assert!(!diff_output.contains("primary database"));
    Ok(())
}

#[test]
fn diff_since_parses_iso_offsets_and_fractional_nanos() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(crate::resolve_diff_since(Path::new("."), "1970-01-01T00:00:00.000000001Z")?, 1);
    assert_eq!(
        crate::resolve_diff_since(Path::new("."), "1969-12-31T16:00:00.000000001-08:00")?,
        1
    );
    assert_eq!(crate::resolve_diff_since(Path::new("."), "1970-01-01")?, 0);
    assert_error_contains(
        crate::resolve_diff_since(Path::new("."), "2024-02-30T00:00:00Z"),
        "invalid ISO date/time",
    );
    Ok(())
}

#[test]
fn diff_since_resolves_git_revision_with_direct_args() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    run_git(directory.path(), &["init"])?;
    run_git(directory.path(), &["config", "user.email", "locket@example.test"])?;
    run_git(directory.path(), &["config", "user.name", "Locket Test"])?;
    run_git(directory.path(), &["commit", "--allow-empty", "-m", "baseline"])?;

    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("API_TOKEN");
    crate::set_secret_value(
        &context,
        &args,
        "sk_test_diff_since_git",
        "manual",
        crate::now_unix_nanos()?,
    )?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "HEAD"])?,
        &context,
        &mut diff_output,
    )?;
    let diff_output = String::from_utf8(diff_output)?;
    assert!(diff_output.contains("changed API_TOKEN source=user-local"));
    assert!(!diff_output.contains("sk_test_diff_since_git"));

    let invalid = run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "not-a-real-rev"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(invalid, "could not resolve diff --since value");
    Ok(())
}

#[test]
fn copy_creates_missing_target_profile_secret_without_leaking_value()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let set_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &set_args, "postgres://localhost/dev-copy", "manual", 1_000)?;
    let mut create_profile_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_profile_output,
    )?;

    let mut copy_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "copy",
            "DATABASE_URL",
            "--from",
            "dev",
            "--to",
            "staging",
        ])?,
        &context,
        &mut copy_output,
    )?;
    let copy_output = String::from_utf8(copy_output)?;
    assert!(copy_output.contains("operation=create"));
    assert!(copy_output.contains("version=1"));
    assert!(copy_output.contains("metadata_only=yes"));
    assert!(!copy_output.contains("postgres://localhost/dev-copy"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let staging =
        store.get_profile_by_name(&project_id, "staging")?.ok_or("staging profile should exist")?;
    let secret = store
        .get_secret_by_source(&staging.project_id, &staging.id, "DATABASE_URL", "user-local")?
        .ok_or("target secret should exist")?;
    assert_eq!(secret.current_version, 1);
    assert_eq!(secret.origin, "profile-copy");
    assert_eq!(secret.last_rotated_at, None);
    let versions = store.list_secret_versions(&secret.id)?;
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].state, "current");
    assert_eq!(versions[0].origin, "profile-copy");

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SECRET_COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"target_version\":1"));
    assert!(!metadata.contains("postgres://localhost/dev-copy"));

    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/dev-copy\n");
    Ok(())
}

#[test]
fn copy_rotates_existing_target_with_no_grace_and_no_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let set_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &set_args, "postgres://localhost/source", "manual", 1_000)?;
    let mut create_profile_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_profile_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    crate::set_secret_value(
        &context,
        &set_args,
        "postgres://localhost/target-old",
        "manual",
        2_000,
    )?;

    let copy_args = crate::CopyArgs {
        key: "DATABASE_URL".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: None,
        to_source: None,
    };
    let result = crate::copy_secret_value(&context, &copy_args, 3_000)?;
    assert_eq!(result.operation, "rotate");
    assert_eq!(result.target_version, 2);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let staging =
        store.get_profile_by_name(&project_id, "staging")?.ok_or("staging profile should exist")?;
    let secret = store
        .get_secret_by_source(&project_id, &staging.id, "DATABASE_URL", "user-local")?
        .ok_or("target secret should exist")?;
    assert_eq!(secret.current_version, 2);
    assert_eq!(secret.last_rotated_at, Some(3_000));
    let versions = store.list_secret_versions(&secret.id)?;
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].state, "deprecated");
    assert_eq!(versions[0].deprecated_at, Some(3_000));
    assert_eq!(versions[0].grace_until, None);
    assert_eq!(versions[1].state, "current");
    assert_eq!(versions[1].origin, "profile-copy");

    let mut history_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL", "--profile", "staging"])?,
        &context,
        &mut history_output,
    )?;
    let history_output = String::from_utf8(history_output)?;
    assert!(history_output.contains("v1 state=deprecated"));
    assert!(history_output.contains("grace_until=-"));
    assert!(history_output.contains("v2 state=current"));
    assert!(!history_output.contains("postgres://localhost/source"));
    assert!(!history_output.contains("postgres://localhost/target-old"));

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SECRET_COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"prior_target_version\":1"));
    assert!(metadata.contains("\"target_version\":2"));
    assert!(!metadata.contains("postgres://localhost/source"));
    assert!(!metadata.contains("postgres://localhost/target-old"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/source\n");
    Ok(())
}

#[test]
fn copy_picks_highest_precedence_source_when_unambiguous() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let user_local_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &user_local_args, "user-value", "manual", 1_000)?;
    let machine_local_args = crate::SecretWriteArgs {
        target: crate::commands::secrets::set::WriteTargetArgs::default(),
        key: "API_KEY".to_owned(),
        source: crate::SourceArg { source: Some(crate::SecretSourceArg::MachineLocal) },
        metadata: crate::SecretMetadataFlags::default(),
    };
    crate::set_secret_value(&context, &machine_local_args, "machine-value", "manual", 1_500)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let copy_args = crate::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: None,
        to_source: None,
    };
    let result = crate::copy_secret_value(&context, &copy_args, 2_000)?;
    assert_eq!(result.from_source, "machine-local");
    // Spec: when --to-source omitted and the from-source is absent in the target profile,
    // copy falls back to user-local.
    assert_eq!(result.to_source, "user-local");
    assert_eq!(result.operation, "create");
    assert_eq!(result.target_version, 1);
    assert_eq!(result.prior_target_version, None);
    Ok(())
}

#[test]
fn copy_resolves_explicit_from_source_over_default_precedence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let user_local_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &user_local_args, "user-value", "manual", 1_000)?;
    let machine_local_args = crate::SecretWriteArgs {
        target: crate::commands::secrets::set::WriteTargetArgs::default(),
        key: "API_KEY".to_owned(),
        source: crate::SourceArg { source: Some(crate::SecretSourceArg::MachineLocal) },
        metadata: crate::SecretMetadataFlags::default(),
    };
    crate::set_secret_value(&context, &machine_local_args, "machine-value", "manual", 1_500)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let copy_args = crate::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: Some(crate::SecretSourceArg::UserLocal),
        to_source: None,
    };
    let result = crate::copy_secret_value(&context, &copy_args, 2_000)?;
    assert_eq!(result.from_source, "user-local");
    assert_eq!(result.to_source, "user-local");
    assert_eq!(result.from_version, 1);
    Ok(())
}

#[test]
fn copy_to_source_falls_back_to_user_local_when_target_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let machine_local_args = crate::SecretWriteArgs {
        target: crate::commands::secrets::set::WriteTargetArgs::default(),
        key: "API_KEY".to_owned(),
        source: crate::SourceArg { source: Some(crate::SecretSourceArg::MachineLocal) },
        metadata: crate::SecretMetadataFlags::default(),
    };
    crate::set_secret_value(&context, &machine_local_args, "machine-value", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let copy_args = crate::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: None,
        to_source: None,
    };
    let result = crate::copy_secret_value(&context, &copy_args, 2_000)?;
    assert_eq!(result.from_source, "machine-local");
    assert_eq!(result.to_source, "user-local");
    assert_eq!(result.operation, "create");
    Ok(())
}

#[test]
fn copy_rejects_same_profile_and_same_source() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &args, "value", "manual", 1_000)?;

    let copy_args = crate::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "dev".to_owned(),
        from_source: Some(crate::SecretSourceArg::UserLocal),
        to_source: Some(crate::SecretSourceArg::UserLocal),
    };
    assert_error_contains(crate::copy_secret_value(&context, &copy_args, 2_000), "use rotate");
    Ok(())
}

#[test]
fn copy_within_same_profile_to_different_source_is_allowed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &args, "value", "manual", 1_000)?;

    let copy_args = crate::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "dev".to_owned(),
        from_source: Some(crate::SecretSourceArg::UserLocal),
        to_source: Some(crate::SecretSourceArg::MachineLocal),
    };
    let result = crate::copy_secret_value(&context, &copy_args, 2_000)?;
    assert_eq!(result.from_source, "user-local");
    assert_eq!(result.to_source, "machine-local");
    assert_eq!(result.operation, "create");
    Ok(())
}

#[test]
fn copy_to_deleted_target_source_fails_with_secret_deleted()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &args, "source-value", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(&context, &args, "target-value", "manual", 1_500)?;
    run_with_context(Cli::try_parse_from(["locket", "rm", "API_KEY"])?, &context, &mut Vec::new())?;
    run_with_context(Cli::try_parse_from(["locket", "use", "dev"])?, &context, &mut Vec::new())?;

    let copy_args = crate::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: None,
        to_source: None,
    };
    assert_error_contains(crate::copy_secret_value(&context, &copy_args, 2_000), "SecretDeleted");
    Ok(())
}

#[test]
fn copy_from_deleted_source_secret_fails() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &args, "value", "manual", 1_000)?;
    run_with_context(Cli::try_parse_from(["locket", "rm", "API_KEY"])?, &context, &mut Vec::new())?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let copy_args = crate::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: Some(crate::SecretSourceArg::UserLocal),
        to_source: None,
    };
    assert_error_contains(
        crate::copy_secret_value(&context, &copy_args, 2_000),
        "secret source is deleted",
    );
    Ok(())
}

#[test]
fn copy_refreshes_env_example_after_creating_secret_in_target_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &args, "initial-value", "manual", 1_000)?;
    // Mirror the `set` CLI's example-refresh side-effect.
    crate::refresh_example_for_project_if_enabled(&context)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    // Confirm the project example contains the source secret name before copy.
    let example_path = directory.path().join(".env.example");
    let before = fs::read_to_string(&example_path)?;
    assert!(before.contains("API_KEY="), "before-copy example missing API_KEY: {before}");

    run_with_context(
        Cli::try_parse_from(["locket", "copy", "API_KEY", "--from", "dev", "--to", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let after = fs::read_to_string(&example_path)?;
    // The example collects names from all profiles in the project, so API_KEY remains.
    assert!(after.contains("API_KEY="));
    // No plaintext value leaks into the example file.
    assert!(!after.contains("initial-value"));
    Ok(())
}

#[test]
fn copy_command_output_includes_prior_target_version_on_rotate()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &args, "source-value", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(&context, &args, "target-value", "manual", 1_500)?;
    run_with_context(Cli::try_parse_from(["locket", "use", "dev"])?, &context, &mut Vec::new())?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "copy", "API_KEY", "--from", "dev", "--to", "staging"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("operation=rotate"));
    assert!(output.contains("prior_target_version=1"));
    assert!(output.contains("version=2"));
    assert!(output.contains("from_version=1"));
    // Ensure no plaintext leaks.
    assert!(!output.contains("source-value"));
    assert!(!output.contains("target-value"));
    Ok(())
}

#[test]
fn copy_command_output_uses_dash_for_prior_target_version_on_create()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &args, "value", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "copy", "API_KEY", "--from", "dev", "--to", "staging"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("operation=create"));
    assert!(output.contains("prior_target_version=-"));
    assert!(output.contains("version=1"));
    assert!(output.contains("from_version=1"));
    Ok(())
}
