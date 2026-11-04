#[allow(unused_imports)]
use super::*;

#[test]
fn config_commands_manage_allowlisted_non_secret_preferences()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    let mut empty_list = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "list"])?,
        &context,
        &mut empty_list,
    )?;
    assert_eq!(String::from_utf8(empty_list)?, "no config values\n");

    let mut set_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut set_output,
    )?;
    assert_eq!(String::from_utf8(set_output)?, "set privacy.redact_names\n");

    let config_file = std::fs::read_to_string(directory.path().join("config.toml"))?;
    assert!(config_file.contains("[privacy]"));
    assert!(config_file.contains("redact_names = true"));

    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "get", "privacy.redact_names"])?,
        &context,
        &mut get_output,
    )?;
    assert_eq!(String::from_utf8(get_output)?, "true\n");

    let mut duration_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "reveal.ttl", "5m"])?,
        &context,
        &mut duration_output,
    )?;
    assert_eq!(String::from_utf8(duration_output)?, "set reveal.ttl\n");

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "list"])?,
        &context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("privacy.redact_names=true"));
    assert!(list_output.contains("reveal.ttl=5m"));

    let mut agent_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "agent.autostart", "false"])?,
        &context,
        &mut agent_output,
    )?;
    assert_eq!(String::from_utf8(agent_output)?, "set agent.autostart\n");

    let mut refresh_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "example.auto_refresh", "false"])?,
        &context,
        &mut refresh_output,
    )?;
    assert_eq!(String::from_utf8(refresh_output)?, "set example.auto_refresh\n");

    let mut retention_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "runtime.session_secret_name_retention",
            "off",
        ])?,
        &context,
        &mut retention_output,
    )?;
    assert_eq!(String::from_utf8(retention_output)?, "set runtime.session_secret_name_retention\n");

    let mut unset_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "unset", "privacy.redact_names"])?,
        &context,
        &mut unset_output,
    )?;
    assert_eq!(String::from_utf8(unset_output)?, "unset privacy.redact_names\n");

    let mut get_unset_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "config", "get", "privacy.redact_names"])?,
        &context,
        &mut get_unset_output,
    );
    assert_error_contains(result, "config key is not set");
    Ok(())
}

#[test]
fn config_commands_manage_documented_non_secret_preferences()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    for (key, value) in [
        ("ui.theme", "dark"),
        ("ui.density", "compact"),
        ("editor.default", "vim"),
        ("agent.unlock_ttl", "15m"),
        ("rotation.max_grace_ttl", "30d"),
        ("shell.integration", "prompt-only"),
        ("updates.channel", "stable"),
        ("updates.manifest_url", "https://updates.example.test/manifest.json"),
        ("user_verification_required_for.unlock", "true"),
        ("user_verification_required_for.dangerous_profile_switch", "true"),
    ] {
        let mut output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "config", "set", key, value])?,
            &context,
            &mut output,
        )?;
        assert_eq!(String::from_utf8(output)?, format!("set {key}\n"));
    }

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "list"])?,
        &context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("ui.theme=dark"));
    assert!(list_output.contains("editor.default=vim"));
    assert!(
        list_output.contains("updates.manifest_url=https://updates.example.test/manifest.json")
    );
    assert!(list_output.contains("user_verification_required_for.unlock=true"));
    Ok(())
}

#[test]
fn config_set_rejects_unknown_keys_invalid_values_and_secret_like_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    let mut output = Vec::new();
    let unknown = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "provider.token", "false"])?,
        &context,
        &mut output,
    );
    assert_error_contains(unknown, "unsupported config key");

    let mut output = Vec::new();
    let invalid_bool = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "agent.autostart", "yes"])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_bool, "true or false");

    let mut output = Vec::new();
    let oversized_ttl = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "reveal.ttl", "6m"])?,
        &context,
        &mut output,
    );
    assert_error_contains(oversized_ttl, "5m or less");

    let mut output = Vec::new();
    let invalid_retention = run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "runtime.session_secret_name_retention",
            "forever",
        ])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_retention, "duration or off");

    let mut output = Vec::new();
    let invalid_theme = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "ui.theme", "purple"])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_theme, "system, light, or dark");

    let mut output = Vec::new();
    let invalid_editor = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "editor.default", "~/bin/editor"])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_editor, "shell expansion");

    let mut output = Vec::new();
    let invalid_rotation = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "rotation.max_grace_ttl", "31d"])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_rotation, "30d or less");

    let mut output = Vec::new();
    let invalid_shell = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "shell.integration", "always"])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_shell, "off, prompt-only, or hook");

    let mut output = Vec::new();
    let invalid_manifest = run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "updates.manifest_url",
            "http://updates.example.test/manifest.json",
        ])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_manifest, "HTTPS URL");

    let mut output = Vec::new();
    let token = run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "reveal.ttl",
            "sk_test_sampleTokenValue123",
        ])?,
        &context,
        &mut output,
    );
    assert_error_contains(token, "looks like a secret");
    assert!(!directory.path().join("config.toml").exists());
    Ok(())
}

#[test]
fn config_value_validation_errors_are_typed_metadata_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    assert_typed_config_error(
        run_with_context(
            Cli::try_parse_from(["locket", "config", "set", "agent.autostart", "yes"])?,
            &context,
            &mut Vec::new(),
        ),
        locket_core::LocketError::MetadataInvalid,
        "true or false",
    )?;
    assert_typed_config_error(
        run_with_context(
            Cli::try_parse_from(["locket", "config", "set", "reveal.ttl", "not-a-duration"])?,
            &context,
            &mut Vec::new(),
        ),
        locket_core::LocketError::MetadataInvalid,
        "invalid config duration",
    )?;
    for value in ["0s", "1h30m", "1.5h", "1H", " 1h", "1h "] {
        assert_typed_config_error(
            run_with_context(
                Cli::try_parse_from(["locket", "config", "set", "agent.unlock_ttl", value])?,
                &context,
                &mut Vec::new(),
            ),
            locket_core::LocketError::MetadataInvalid,
            "invalid config duration",
        )?;
    }
    assert_typed_config_error(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "config",
                "set",
                "updates.manifest_url",
                "http://updates.example.test/manifest.json",
            ])?,
            &context,
            &mut Vec::new(),
        ),
        locket_core::LocketError::MetadataInvalid,
        "HTTPS URL",
    )?;
    assert_typed_config_error(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "config",
                "set",
                "reveal.ttl",
                "sk_test_sampleTokenValue123",
            ])?,
            &context,
            &mut Vec::new(),
        ),
        locket_core::LocketError::MetadataLooksLikeSecret,
        "looks like a secret",
    )?;

    fs::write(directory.path().join("config.toml"), "[privacy]\nredact_names = \"yes\"\n")?;
    assert_typed_config_error(
        run_with_context(
            Cli::try_parse_from(["locket", "config", "get", "privacy.redact_names"])?,
            &context,
            &mut Vec::new(),
        ),
        locket_core::LocketError::MetadataInvalid,
        "invalid stored config value",
    )?;

    fs::write(directory.path().join("config.toml"), "agent = \"not-a-table\"\n")?;
    assert_typed_config_error(
        run_with_context(
            Cli::try_parse_from(["locket", "config", "set", "agent.autostart", "true"])?,
            &context,
            &mut Vec::new(),
        ),
        locket_core::LocketError::MetadataInvalid,
        "config section is not a table",
    )?;
    Ok(())
}

#[test]
fn config_get_and_list_reject_malformed_stored_values() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    fs::write(directory.path().join("config.toml"), "[privacy]\nredact_names = \"yes\"\n")?;

    let mut get_output = Vec::new();
    let get = run_with_context(
        Cli::try_parse_from(["locket", "config", "get", "privacy.redact_names"])?,
        &context,
        &mut get_output,
    );
    assert_error_contains(get, "invalid stored config value for privacy.redact_names");

    let mut list_output = Vec::new();
    let list = run_with_context(
        Cli::try_parse_from(["locket", "config", "list"])?,
        &context,
        &mut list_output,
    );
    assert_error_contains(list, "invalid stored config value for privacy.redact_names");
    Ok(())
}

#[test]
fn config_security_relevant_updates_write_metadata_only_audit_when_project_exists()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    let mut set_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "agent.autostart", "true"])?,
        &context,
        &mut set_output,
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'CONFIG_UPDATE'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"key\":\"agent.autostart\""));
    assert!(metadata.contains("\"operation\":\"set\""));
    assert!(!metadata.contains("true"));
    Ok(())
}

fn initialize_project_and_device(
    context: &RuntimeContext,
) -> Result<(), Box<dyn std::error::Error>> {
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        context,
        &mut Vec::new(),
    )?;
    run_with_context(Cli::try_parse_from(["locket", "device", "init"])?, context, &mut Vec::new())?;
    Ok(())
}

#[test]
fn passkey_register_is_unavailable_without_writing_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    initialize_project_and_device(&context)?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let project_id = resolved.config.project_id.to_string();

    let mut register_output = Vec::new();
    let register = run_with_context(
        Cli::try_parse_from(["locket", "passkey", "register", "--label", "work-laptop"])?,
        &context,
        &mut register_output,
    );
    let Err(error) = register else {
        return Err("registration must fail without a platform passkey integration".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::PolicyValidationIncomplete.exit_code(),);
    assert_eq!(register_output.len(), 0);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let credentials = store.list_passkey_credentials(&project_id, true)?;
    assert_eq!(credentials.len(), 0);
    let denied: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PASSKEY_REGISTER' AND status = 'DENIED'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(denied, 1);

    // Lock in the failure-path audit shape required by docs/specs/crypto.md:
    // PASSKEY_REGISTER DENIED rows must carry `passkey_id` (null when no
    // credential could be minted), `credential_id_prefix` (null), an
    // `auth_result` mapped from the platform error, and a
    // `failure_reason` derived from that error's display impl.
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'PASSKEY_REGISTER' AND status = 'DENIED'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["action"], "PASSKEY_REGISTER");
    assert_eq!(metadata["status"], "DENIED");
    assert_eq!(metadata["command"], "passkey register");
    assert!(metadata["passkey_id"].is_null(), "passkey_id null when no credential minted");
    assert!(metadata["credential_id_prefix"].is_null());
    assert_eq!(metadata["auth_result"], "unsupported");
    assert_eq!(metadata["failure_reason"], "platform passkey unsupported");
    Ok(())
}

#[test]
fn passkey_register_rejects_software_keyring_credentials() -> Result<(), Box<dyn std::error::Error>>
{
    use locket_platform::{MemoryPlatformPasskeyRegistrar, PasskeyRegistration};
    let directory = tempdir()?;
    let context = test_context(&directory);
    initialize_project_and_device(&context)?;
    let registration = PasskeyRegistration {
        credential_id: vec![1; 32],
        public_key: vec![2; 32],
        user_handle: vec![3; 32],
        transports: vec!["internal".to_owned(), "platform-keyring".to_owned()],
        prf_capable: true,
        backup_eligible: None,
        backup_state: None,
    };
    let context = super::context_with_passkey_registrar(
        &context,
        Arc::new(MemoryPlatformPasskeyRegistrar::allowing(registration, [7; 32])),
    );
    let result = run_with_context(
        Cli::try_parse_from(["locket", "passkey", "register", "--label", "software"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "software keyring");
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    assert_eq!(
        store.list_passkey_credentials(resolved.config.project_id.as_str(), true)?,
        Vec::new()
    );
    Ok(())
}

#[test]
fn passkey_unavailable_is_reported_before_requesting_user_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    initialize_project_and_device(&context)?;
    let context =
        context_with_user_verifier(&context, Arc::new(MemoryLocalUserVerifier::denying()));
    let result = run_with_context(
        Cli::try_parse_from(["locket", "passkey", "register", "--label", "laptop"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "WebAuthn/FIDO2");
    Ok(())
}

#[test]
fn passkey_register_via_memory_registrar_writes_credential_and_audit()
-> Result<(), Box<dyn std::error::Error>> {
    use locket_platform::{MemoryPlatformPasskeyRegistrar, PasskeyRegistration};
    let directory = tempdir()?;
    let context = test_context(&directory);
    initialize_project_and_device(&context)?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let project_id = resolved.config.project_id.to_string();
    let registration = PasskeyRegistration {
        credential_id: vec![0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a],
        public_key: vec![0x01, 0x02, 0x03, 0x04],
        user_handle: vec![0x55; 32],
        transports: vec!["internal".to_owned(), "hybrid".to_owned()],
        prf_capable: true,
        backup_eligible: Some(true),
        backup_state: Some(false),
    };
    let registrar = Arc::new(MemoryPlatformPasskeyRegistrar::allowing(registration, [7_u8; 32]));
    let registered_context = super::context_with_passkey_registrar(&context, registrar);

    let mut register_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "passkey", "register", "--label", "work-laptop"])?,
        &registered_context,
        &mut register_output,
    )?;
    let register_output = String::from_utf8(register_output)?;
    assert!(register_output.contains("passkey: registered"));
    assert!(register_output.contains("credential_id_prefix: abcdef123456"));
    assert!(register_output.contains("rp_id: locket.localhost"));
    assert!(register_output.contains("prf_capable: yes"));
    assert!(register_output.contains("prf_wrapped: yes"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let credentials = store.list_passkey_credentials(&project_id, false)?;
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].label, "work-laptop");
    assert!(!register_output.contains("555555555555"));
    assert_eq!(credentials[0].public_key, vec![0x01, 0x02, 0x03, 0x04]);
    assert_eq!(credentials[0].user_handle, vec![0x55; 32]);
    assert_eq!(credentials[0].transports, vec!["internal".to_owned(), "hybrid".to_owned()]);
    assert!(credentials[0].prf_capable);
    assert!(store.get_passkey_prf_wrap(&project_id, &credentials[0].id)?.is_some());
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'PASSKEY_REGISTER' AND status = 'SUCCESS'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["action"], "PASSKEY_REGISTER");
    assert_eq!(metadata["status"], "SUCCESS");
    assert_eq!(metadata["command"], "passkey register");
    assert_eq!(metadata["auth_result"], "success");
    assert_eq!(metadata["credential_id_prefix"], "abcdef123456");
    assert_eq!(metadata["prf_capable"], true);
    // PASSKEY_REGISTER schema (docs/specs/crypto.md) requires
    // `passkey_id`, `credential_id_prefix`, and `auth_result` on the
    // success row. The validator pins these as required fields; pin
    // them at the test level too so a regression that drops a field
    // trips this contract before it reaches the validator.
    assert!(
        metadata["passkey_id"].as_str().is_some_and(|id| id.starts_with("lk_passkey_")),
        "passkey_id must be a `lk_passkey_*` identifier, got {:?}",
        metadata["passkey_id"],
    );
    Ok(())
}

#[test]
fn passkey_unlock_round_trips_master_key_through_prf() -> Result<(), Box<dyn std::error::Error>> {
    use locket_platform::{MemoryPlatformPasskeyRegistrar, PasskeyRegistration};

    let directory = tempdir()?;
    let context = test_context(&directory);
    initialize_project_and_device(&context)?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let project_id = resolved.config.project_id.to_string();

    let registration = PasskeyRegistration {
        credential_id: vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
        public_key: vec![0x01, 0x02],
        user_handle: vec![0x66; 32],
        transports: vec!["internal".to_owned()],
        prf_capable: true,
        backup_eligible: Some(false),
        backup_state: Some(false),
    };
    let registrar = Arc::new(MemoryPlatformPasskeyRegistrar::allowing(registration, [13_u8; 32]));
    let registered_context = super::context_with_passkey_registrar(&context, registrar);
    run_with_context(
        Cli::try_parse_from(["locket", "passkey", "register", "--label", "work-laptop"])?,
        &registered_context,
        &mut Vec::new(),
    )?;

    let stored_master =
        registered_context.key_store.load_master_key(&project_id).map(|key| *key)?;
    registered_context.key_store.delete_master_key(&project_id)?;
    assert!(registered_context.key_store.load_master_key(&project_id).is_err());

    // Possession of the PRF wrap must not bypass fresh local verification.
    let denied_context = context_with_user_verifier(
        &registered_context,
        Arc::new(MemoryLocalUserVerifier::denying()),
    );
    let denied = run_with_context(
        Cli::try_parse_from(["locket", "passkey", "unlock"])?,
        &denied_context,
        &mut Vec::new(),
    );
    assert_error_contains(denied, "local user verification failed");
    assert!(registered_context.key_store.load_master_key(&project_id).is_err());

    let mut unlock_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "passkey", "unlock"])?,
        &registered_context,
        &mut unlock_output,
    )?;
    let unlock_output = String::from_utf8(unlock_output)?;
    assert!(unlock_output.contains("passkey: unlocked"));
    assert!(unlock_output.contains("master_key_source:"));

    let recovered = registered_context.key_store.load_master_key(&project_id)?;
    assert_eq!(*recovered, stored_master);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'PASSKEY_AUTH' AND status = 'SUCCESS'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"auth_result\":\"success\""));
    assert!(metadata.contains("\"credential_id_prefix\":\"123456789abc\""));
    Ok(())
}

#[test]
fn passkey_legacy_keyring_recovery_preserves_data_and_identifies_software_factor()
-> Result<(), Box<dyn std::error::Error>> {
    use locket_platform::{MemoryPlatformPasskeyRegistrar, PasskeyRegistration};
    let directory = tempdir()?;
    let context = test_context(&directory);
    initialize_project_and_device(&context)?;
    let registration = PasskeyRegistration {
        credential_id: vec![9; 32],
        public_key: vec![8; 32],
        user_handle: vec![7; 32],
        transports: vec!["internal".to_owned()],
        prf_capable: true,
        backup_eligible: None,
        backup_state: None,
    };
    let context = super::context_with_passkey_registrar(
        &context,
        Arc::new(MemoryPlatformPasskeyRegistrar::allowing(registration, [6; 32])),
    );
    run_with_context(
        Cli::try_parse_from(["locket", "passkey", "register", "--label", "legacy-laptop"])?,
        &context,
        &mut Vec::new(),
    )?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let project_id = resolved.config.project_id.as_str();
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    // Reproduce metadata persisted by the old software keyring registrar.
    store.connection().execute(
        "UPDATE passkey_credentials SET transports_json = ?1 WHERE project_id = ?2",
        rusqlite::params![r#"["internal","platform-keyring","macos-keychain"]"#, project_id],
    )?;
    let master_key = *context.key_store.load_master_key(project_id)?;
    context.key_store.delete_master_key(project_id)?;
    let denied_context =
        context_with_user_verifier(&context, Arc::new(MemoryLocalUserVerifier::denying()));
    let denied = run_with_context(
        Cli::try_parse_from(["locket", "passkey", "unlock"])?,
        &denied_context,
        &mut Vec::new(),
    );
    assert_error_contains(denied, "local user verification failed");
    assert!(context.key_store.load_master_key(project_id).is_err());
    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "passkey", "unlock"])?, &context, &mut output)?;
    assert!(String::from_utf8(output)?.contains("legacy software keyring recovery"));
    assert_eq!(*context.key_store.load_master_key(project_id)?, master_key);
    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "passkey", "list"])?, &context, &mut output)?;
    assert!(String::from_utf8(output)?.contains("kind=legacy-software-keyring"));
    Ok(())
}

#[test]
fn passkey_unlock_with_wrong_prf_output_fails_integrity() -> Result<(), Box<dyn std::error::Error>>
{
    use locket_platform::{MemoryPlatformPasskeyRegistrar, PasskeyRegistration};

    let directory = tempdir()?;
    let context = test_context(&directory);
    initialize_project_and_device(&context)?;

    let credential_id = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
    let registration = PasskeyRegistration {
        credential_id: credential_id.clone(),
        public_key: vec![0x01, 0x02],
        user_handle: vec![0x77; 32],
        transports: vec!["internal".to_owned()],
        prf_capable: true,
        backup_eligible: Some(false),
        backup_state: Some(false),
    };
    let registered_context = super::context_with_passkey_registrar(
        &context,
        Arc::new(MemoryPlatformPasskeyRegistrar::allowing(registration, [7_u8; 32])),
    );
    run_with_context(
        Cli::try_parse_from(["locket", "passkey", "register", "--label", "work-laptop"])?,
        &registered_context,
        &mut Vec::new(),
    )?;

    let wrong_context = super::context_with_passkey_registrar(
        &registered_context,
        Arc::new(MemoryPlatformPasskeyRegistrar::with_known_credential([99_u8; 32], credential_id)),
    );
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "passkey", "unlock"])?,
        &wrong_context,
        &mut output,
    );
    let Err(error) = result else {
        return Err("wrong PRF output must fail unlock".into());
    };
    assert!(matches!(error, crate::CliError::Crypto(locket_crypto::CryptoError::DecryptionFailed)));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let denied: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PASSKEY_AUTH' AND status = 'DENIED'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(denied, 1);
    Ok(())
}

#[test]
fn passkey_unlock_without_registered_passkey_fails() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "passkey", "unlock"])?,
        &context,
        &mut output,
    );
    let Err(error) = result else {
        return Err("unlock without registered passkeys must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidReference.exit_code(),);
    assert!(error.to_string().to_lowercase().contains("passkey"));
    Ok(())
}

#[test]
fn passkey_list_and_remove_use_project_store_and_audit() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "work-laptop\n");
    initialize_project_and_device(&context)?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let project_id = resolved.config.project_id.to_string();
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let credential = locket_store::PasskeyCredentialRecord {
        id: "lk_passkey_test".to_owned(),
        project_id: project_id.clone(),
        device_id: store
            .get_active_local_device(&project_id)?
            .ok_or("local device should exist")?
            .id,
        member_id: None,
        label: "work-laptop".to_owned(),
        credential_id: vec![0xab, 0xcd, 0xef, 0x12, 0x34, 0x56],
        public_key: vec![0x01, 0x02, 0x03, 0x04],
        user_handle: vec![0x88; 32],
        transports: vec!["internal".to_owned(), "usb".to_owned()],
        prf_capable: true,
        webauthn_relying_party_id: locket_store::DEFAULT_WEBAUTHN_RELYING_PARTY_ID.to_owned(),
        backup_eligible: Some(true),
        backup_state: Some(false),
        created_at: 100,
        last_used_at: Some(200),
        revoked_at: None,
    };
    store.insert_passkey_credential(&credential)?;

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "passkey", "list"])?,
        &context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("work-laptop"));
    assert!(list_output.contains("credential_id_prefix=abcdef123456"));
    assert!(list_output.contains("rp_id=locket.localhost"));
    assert!(list_output.contains("transports=internal,usb"));
    assert!(list_output.contains("prf=yes"));
    assert!(list_output.contains("backup_eligible=yes"));
    assert!(list_output.contains("backup_state=no"));
    assert!(list_output.contains("private_key_material: never displayed"));

    let mut remove_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "passkey", "remove", "work-laptop"])?,
        &context,
        &mut remove_output,
    )?;
    let remove_output = String::from_utf8(remove_output)?;
    assert!(remove_output.contains("passkey: revoked"));
    assert!(remove_output.contains("passkey_id: lk_passkey_test"));
    assert!(remove_output.contains("rp_id: locket.localhost"));
    assert!(!remove_output.contains("abcdef123456abcdef"));

    let active = store.list_passkey_credentials(&project_id, false)?;
    assert_eq!(active.len(), 0);
    let all = store.list_passkey_credentials(&project_id, true)?;
    assert_eq!(all.len(), 1);
    assert!(all[0].revoked_at.is_some());
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'PASSKEY_REMOVE'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"credential_id_prefix\":\"abcdef123456\""));
    assert!(metadata.contains("\"webauthn_relying_party_id\":\"locket.localhost\""));
    assert!(metadata.contains("\"backup_eligible\":true"));
    assert!(metadata.contains("\"backup_state\":false"));
    assert!(!metadata.contains("abcdef123456abcdef"));
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["user_verification"]["required"], true);
    assert_eq!(metadata["user_verification"]["satisfied"], true);
    assert_eq!(metadata["user_verification"]["method"], "test");
    Ok(())
}

#[test]
fn passkey_remove_requires_fresh_user_verification_before_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "work-laptop\n");
    initialize_project_and_device(&context)?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let project_id = resolved.config.project_id.to_string();
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let credential = locket_store::PasskeyCredentialRecord {
        id: "lk_passkey_test".to_owned(),
        project_id: project_id.clone(),
        device_id: store
            .get_active_local_device(&project_id)?
            .ok_or("local device should exist")?
            .id,
        member_id: None,
        label: "work-laptop".to_owned(),
        credential_id: vec![0xab, 0xcd, 0xef, 0x12, 0x34, 0x56],
        public_key: vec![0x01, 0x02, 0x03, 0x04],
        user_handle: vec![0x99; 32],
        transports: vec!["internal".to_owned()],
        prf_capable: true,
        webauthn_relying_party_id: locket_store::DEFAULT_WEBAUTHN_RELYING_PARTY_ID.to_owned(),
        backup_eligible: Some(true),
        backup_state: Some(false),
        created_at: 100,
        last_used_at: None,
        revoked_at: None,
    };
    store.insert_passkey_credential(&credential)?;

    let denied_context =
        context_with_user_verifier(&context, Arc::new(MemoryLocalUserVerifier::denying()));
    let mut remove_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "passkey", "remove", "work-laptop"])?,
        &denied_context,
        &mut remove_output,
    );
    let Err(error) = result else {
        return Err("passkey removal must require local user verification".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UserVerificationFailed.exit_code());
    assert!(error.to_string().contains("local user verification"));
    assert_eq!(String::from_utf8(remove_output)?, "");

    let active = store.list_passkey_credentials(&project_id, false)?;
    assert_eq!(active.len(), 1);
    assert!(active[0].revoked_at.is_none());
    let remove_count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PASSKEY_REMOVE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(remove_count, 0);
    Ok(())
}

#[test]
fn lock_and_unlock_use_direct_metadata_only_mode() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    let mut lock_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "lock"])?, &context, &mut lock_output)?;
    let lock_output = String::from_utf8(lock_output)?;
    assert!(lock_output.contains("no agent-held keys"));
    assert!(lock_output.contains("metadata_only: yes"));

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    let mut unlock_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "unlock"])?, &context, &mut unlock_output)?;
    let unlock_output = String::from_utf8(unlock_output)?;
    assert!(unlock_output.contains("metadata-only direct CLI unlock succeeded"));
    assert!(unlock_output.contains("unlock_method: OsKeychain"));
    assert!(unlock_output.contains("cached_keys: no"));
    assert!(unlock_output.contains("verify_user: not requested"));
    Ok(())
}

#[test]
fn unlock_with_verify_user_records_satisfied_verification_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let allowing_context =
        context_with_user_verifier(&context, Arc::new(MemoryLocalUserVerifier::allowing()));
    let mut unlock_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "unlock", "--verify-user"])?,
        &allowing_context,
        &mut unlock_output,
    )?;
    let unlock_output = String::from_utf8(unlock_output)?;
    assert!(unlock_output.contains("metadata-only direct CLI unlock succeeded"));
    assert!(unlock_output.contains("verify_user: satisfied"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'UNLOCK' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["status"], "SUCCESS");
    assert_eq!(metadata["user_verification"]["required"], true);
    assert_eq!(metadata["user_verification"]["satisfied"], true);
    assert_eq!(metadata["user_verification"]["method"], "test");
    Ok(())
}

#[test]
fn unlock_with_verify_user_denial_returns_typed_error_and_writes_no_unlock_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let denying_context =
        context_with_user_verifier(&context, Arc::new(MemoryLocalUserVerifier::denying()));
    let mut unlock_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "unlock", "--verify-user"])?,
        &denying_context,
        &mut unlock_output,
    );
    let Err(error) = result else {
        return Err("denied user verification must fail unlock".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UserVerificationFailed.exit_code());
    assert_eq!(unlock_output.len(), 0);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let unlock_count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'UNLOCK'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(unlock_count, 0, "denied verification must not write an UNLOCK audit row");
    Ok(())
}

#[test]
fn lock_writes_metadata_only_lock_audit_row_when_project_resolves()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    run_with_context(Cli::try_parse_from(["locket", "lock"])?, &context, &mut Vec::new())?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'LOCK' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"LOCK\""));
    assert!(metadata.contains("\"status\":\"SUCCESS\""));
    assert!(metadata.contains("\"command\":\"lock\""));
    assert!(metadata.contains("\"client_kind\":\"direct-cli\""));
    assert!(metadata.contains("\"agent_available\":false"));
    assert!(metadata.contains("\"cached_keys_cleared\":0"));
    assert!(metadata.contains("\"live_grants_revoked\":0"));
    assert!(metadata.contains("\"schema_version\":1"));

    let command_column: String = store.connection().query_row(
        "SELECT command FROM audit_log WHERE action = 'LOCK' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(command_column, "lock");
    Ok(())
}

#[test]
fn unlock_writes_unlock_audit_row_with_method_for_os_keychain()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    run_with_context(Cli::try_parse_from(["locket", "unlock"])?, &context, &mut Vec::new())?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'UNLOCK' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"UNLOCK\""));
    assert!(metadata.contains("\"status\":\"SUCCESS\""));
    assert!(metadata.contains("\"command\":\"unlock\""));
    assert!(metadata.contains("\"client_kind\":\"direct-cli\""));
    assert!(metadata.contains("\"method\":\"OsKeychain\""));
    assert!(metadata.contains("\"agent_available\":false"));
    assert!(metadata.contains("\"cached_keys\":false"));
    assert!(metadata.contains("\"required\":false"));
    assert!(metadata.contains("\"schema_version\":1"));

    let command_column: String = store.connection().query_row(
        "SELECT command FROM audit_log WHERE action = 'UNLOCK' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(command_column, "unlock");
    Ok(())
}

#[test]
fn unlock_records_passphrase_method_when_keychain_is_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    let directory = tempdir()?;
    // Force the OS keystore to fail for the entire project lifecycle so init
    // falls back to the passphrase store and unlock loads through it.
    let key_store = MockMasterKeyStore::default();
    key_store.set_store_failure(Some(MockMasterKeyStoreFailure::MasterKeyNotFound))?;
    key_store.set_load_failure(Some(MockMasterKeyStoreFailure::MasterKeyNotFound))?;
    let context = crate::tests::test_context_with_key_store(&directory, Arc::new(key_store));
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut unlock_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "unlock"])?, &context, &mut unlock_output)?;
    let unlock_output = String::from_utf8(unlock_output)?;
    assert!(unlock_output.contains("unlock_method: Passphrase"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'UNLOCK' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"method\":\"Passphrase\""));
    Ok(())
}

#[test]
fn unlock_returns_unlock_required_when_master_key_is_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    context.key_store.delete_master_key(resolved.config.project_id.as_str())?;

    let mut unlock_output = Vec::new();
    let unlock_result =
        run_with_context(Cli::try_parse_from(["locket", "unlock"])?, &context, &mut unlock_output);
    let Err(unlock_error) = unlock_result else {
        return Err("locked-vault unlock must fail".into());
    };
    assert_eq!(unlock_error.exit_code(), locket_core::LocketError::UnlockRequired.exit_code(),);
    assert_eq!(unlock_output.len(), 0);
    Ok(())
}

#[test]
fn lock_stays_metadata_only_when_vault_is_locked() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    context.key_store.delete_master_key(resolved.config.project_id.as_str())?;

    let mut lock_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "lock"])?, &context, &mut lock_output)?;
    let lock_output = String::from_utf8(lock_output)?;
    assert!(lock_output.contains("metadata_only: yes"));
    assert!(lock_output.contains("project_id:"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'LOCK'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0, "locked-vault lock must not append a LOCK audit row");
    Ok(())
}

fn assert_typed_config_error<T>(
    result: Result<T, crate::CliError>,
    expected_kind: locket_core::LocketError,
    expected_message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Err(error) = result else {
        return Err(format!("expected typed config error containing {expected_message:?}").into());
    };
    assert_eq!(error.exit_code(), expected_kind.exit_code());
    let crate::CliError::Typed { kind, message } = error else {
        return Err(format!("expected typed config error, got {error:?}").into());
    };
    assert_eq!(kind, expected_kind);
    assert!(message.contains(expected_message), "{message}");
    Ok(())
}
