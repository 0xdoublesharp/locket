#[allow(unused_imports)]
use super::*;

#[test]
fn policy_doctor_reports_legacy_index_without_approving_it()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "dev", "--", "pnpm", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let store = locket_store::Store::open(&context.store_path)?;
    store.connection().execute("UPDATE command_policies SET normalized_json = '{}'", [])?;
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "policy", "doctor"])?,
        &context,
        &mut output,
    );
    assert_error_contains(result, "refresh");
    let output = String::from_utf8(output)?;
    assert!(output.contains("policy_doctor: incomplete"), "{output}");
    assert!(output.contains("locket policy refresh dev"), "{output}");
    let resolved = crate::require_project(&context)?;
    assert_eq!(
        store
            .get_command_policy_index(resolved.config.project_id.as_str(), "dev")?
            .ok_or("missing policy")?
            .normalized_json,
        json!({})
    );
    Ok(())
}

#[test]
fn policy_refresh_requires_confirmation_and_rebinds_current_source()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "dev", "--", "pnpm", "dev"])?,
        &context,
        &mut output,
    )?;
    let store = locket_store::Store::open(&context.store_path)?;
    store.connection().execute("UPDATE command_policies SET normalized_json = '{}'", [])?;
    let path = directory.path().join("locket.toml");
    let original = std::fs::read_to_string(&path)?;
    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "policy", "refresh", "dev"])?,
            &context,
            &mut output,
        ),
        "confirmation did not match policy name",
    );
    let resolved = crate::require_project(&context)?;
    let unapproved = store
        .get_command_policy_index(resolved.config.project_id.as_str(), "dev")?
        .ok_or("missing policy")?;
    assert_eq!(unapproved.normalized_json, json!({}));
    let approved_context = context_with_confirmation(&context, "dev\n");
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "refresh", "dev"])?,
        &approved_context,
        &mut output,
    )?;
    let approved = store
        .get_command_policy_index(resolved.config.project_id.as_str(), "dev")?
        .ok_or("missing policy")?;
    assert_eq!(approved.normalized_json["source_path"], json!(path.canonicalize()?));
    let document: toml::Value = toml::from_str(&original)?;
    assert_eq!(
        approved.normalized_json["source_digest"],
        json!(locket_core::policy::policy_source_digest(&document, "dev")?)
    );
    assert_eq!(std::fs::read_to_string(path)?, original);
    assert!(String::from_utf8(output)?.contains("operation: refresh"));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn policy_commands_update_locket_toml_without_duplicates_and_audit_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    output.clear();

    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "dev", "--", "pnpm", "dev"])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "policy",
            "allow",
            "dev",
            "DATABASE_URL",
            "DATABASE_URL",
            "API_KEY",
        ])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "require", "dev", "API_KEY", "API_KEY"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("metadata_only: yes"));
    assert!(!output.contains("pnpm"));

    let policy_text = std::fs::read_to_string(directory.path().join("locket.toml"))?;
    let document = locket_core::PolicyDocument::from_toml_str(&policy_text)?;
    let policy = document.commands.get("dev").ok_or("missing dev policy")?;
    assert_eq!(
        policy.optional_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["DATABASE_URL"]
    );
    assert_eq!(
        policy.required_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["API_KEY"]
    );
    assert_eq!(
        policy.allowed_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["API_KEY", "DATABASE_URL"]
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let mut statement = store.connection().prepare(
        "SELECT metadata_json FROM audit_log WHERE action = 'POLICY_UPDATE' ORDER BY sequence",
    )?;
    let rows =
        statement.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().any(|row| row.contains("\"operation\":\"add\"")));
    assert!(rows.iter().any(|row| row.contains("\"operation\":\"allow\"")));
    assert!(rows.iter().any(|row| row.contains("\"operation\":\"require\"")));
    assert!(rows.iter().all(|row| !row.contains("pnpm")));

    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let indexed_policy: (String, String, i64, i64) = store.connection().query_row(
        "SELECT policy_json, normalized_json, created_at, updated_at
         FROM command_policies
         WHERE project_id = ?1 AND name = 'dev'",
        [project_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let policy_json = serde_json::from_str::<serde_json::Value>(&indexed_policy.0)?;
    let normalized_json = serde_json::from_str::<serde_json::Value>(&indexed_policy.1)?;
    assert_eq!(policy_json["required_secrets"], json!(["API_KEY"]));
    assert_eq!(policy_json["optional_secrets"], json!(["DATABASE_URL"]));
    assert_eq!(normalized_json["required_secrets"], json!(["API_KEY"]));
    assert_eq!(normalized_json["optional_secrets"], json!(["DATABASE_URL"]));
    assert_eq!(normalized_json["ttl_seconds"], json!(900));
    assert!(indexed_policy.3 >= indexed_policy.2);

    let mut doctor_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "doctor"])?,
        &context,
        &mut doctor_output,
    )?;
    let doctor_output = String::from_utf8(doctor_output)?;
    assert!(doctor_output.contains("policy_doctor: ok"));
    assert!(doctor_output.contains("metadata_only: yes"));
    assert!(
        doctor_output
            .contains("minimal_env_allowlist: PATH HOME USER SHELL TMPDIR LANG LC_* TERM CI")
    );
    assert!(
        doctor_output
            .contains("warning: policy dev uses implicit override=locket; set override explicitly")
    );

    let mut rejected_delete_output = Vec::new();
    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "policy", "delete", "dev"])?,
            &context,
            &mut rejected_delete_output,
        ),
        "confirmation did not match policy name",
    );
    let rejected_delete_output = String::from_utf8(rejected_delete_output)?;
    assert!(rejected_delete_output.contains("metadata_only: yes"));
    assert!(rejected_delete_output.contains("type 'dev' to confirm policy delete"));
    let policy_text = std::fs::read_to_string(directory.path().join("locket.toml"))?;
    let document = locket_core::PolicyDocument::from_toml_str(&policy_text)?;
    assert!(document.commands.contains_key("dev"));

    let confirm_context = context_with_confirmation(&context, "dev\n");
    let mut delete_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "delete", "dev"])?,
        &confirm_context,
        &mut delete_output,
    )?;
    let delete_output = String::from_utf8(delete_output)?;
    assert!(delete_output.contains("policy_delete: dev"));
    assert!(delete_output.contains("affected_shell_hooks:"));
    assert!(delete_output.contains("affected_tray_actions:"));
    assert!(delete_output.contains("affected_automation_clients:"));
    assert!(delete_output.contains("affected_vscode_tasks:"));
    assert!(!delete_output.contains("pnpm"));
    let policy_text = std::fs::read_to_string(directory.path().join("locket.toml"))?;
    let document = locket_core::PolicyDocument::from_toml_str(&policy_text)?;
    assert!(!document.commands.contains_key("dev"));
    let delete_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE action = 'POLICY_UPDATE' AND command = 'policy'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(delete_metadata.contains("\"operation\":\"delete\""));
    assert!(delete_metadata.contains("\"metadata_only\":true"));
    assert!(!delete_metadata.contains("pnpm"));
    let indexed_rows_after_delete: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM command_policies WHERE name = 'dev'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(indexed_rows_after_delete, 0);
    let policy_update_rows_after_delete: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'POLICY_UPDATE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(policy_update_rows_after_delete, 4);
    Ok(())
}

#[cfg(unix)]
#[test]
fn policy_edit_uses_configured_editor_validates_and_audits()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "dev", "--", "pnpm", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let editor = directory.path().join("policy-editor.sh");
    std::fs::write(
        &editor,
        r#"#!/bin/sh
set -eu
input="$1"
next="${input}.next"
while IFS= read -r line; do
  printf '%s\n' "$line"
  if [ "$line" = "[commands.dev]" ]; then
    printf '%s\n' "confirm = true"
  fi
done < "$input" > "$next"
mv "$next" "$input"
"#,
    )?;
    let mut permissions = std::fs::metadata(&editor)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&editor, permissions)?;
    std::fs::create_dir_all(context.config_path.parent().ok_or("missing config parent")?)?;
    std::fs::write(
        &context.config_path,
        format!("[editor]\ndefault = \"{}\"\n", editor.display()),
    )?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "edit", "dev"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("policy: dev"));
    assert!(output.contains("operation: edit"));
    assert!(output.contains("metadata_only: yes"));
    assert!(!output.contains("pnpm"));

    let policy_text = std::fs::read_to_string(directory.path().join("locket.toml"))?;
    let document = locket_core::PolicyDocument::from_toml_str(&policy_text)?;
    let policy = document.commands.get("dev").ok_or("missing dev policy")?;
    assert!(policy.confirm);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'POLICY_UPDATE'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"operation\":\"edit\""));
    assert!(metadata.contains("\"policy\":\"dev\""));
    assert!(!metadata.contains("pnpm"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn policy_edit_rejects_editor_failure_without_writing_audit()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "dev", "--", "pnpm", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let editor = directory.path().join("failing-editor.sh");
    std::fs::write(&editor, "#!/bin/sh\nexit 7\n")?;
    let mut permissions = std::fs::metadata(&editor)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&editor, permissions)?;
    std::fs::create_dir_all(context.config_path.parent().ok_or("missing config parent")?)?;
    std::fs::write(
        &context.config_path,
        format!("[editor]\ndefault = \"{}\"\n", editor.display()),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "policy", "edit", "dev"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("failing policy editor should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidPolicy.exit_code());
    assert!(error.to_string().contains("policy editor exited unsuccessfully"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let edit_rows: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'POLICY_UPDATE'
         AND metadata_json LIKE '%\"operation\":\"edit\"%'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(edit_rows, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn policy_edit_rejects_invalid_saved_toml_without_writing_audit()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "dev", "--", "pnpm", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let editor = directory.path().join("invalid-policy-editor.sh");
    std::fs::write(&editor, "#!/bin/sh\nprintf '%s\\n' '[commands.dev' > \"$1\"\n")?;
    let mut permissions = std::fs::metadata(&editor)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&editor, permissions)?;
    std::fs::create_dir_all(context.config_path.parent().ok_or("missing config parent")?)?;
    std::fs::write(
        &context.config_path,
        format!("[editor]\ndefault = \"{}\"\n", editor.display()),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "policy", "edit", "dev"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("invalid edited policy should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidPolicy.exit_code());
    assert!(error.to_string().contains("invalid edited policy TOML"));

    let policy_text = std::fs::read_to_string(directory.path().join("locket.toml"))?;
    let document = locket_core::PolicyDocument::from_toml_str(&policy_text)?;
    assert!(document.commands.contains_key("dev"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let edit_rows: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'POLICY_UPDATE'
         AND metadata_json LIKE '%\"operation\":\"edit\"%'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(edit_rows, 0);
    Ok(())
}

#[test]
fn policy_doctor_reports_non_default_scanner_thresholds() -> Result<(), Box<dyn std::error::Error>>
{
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
            br#"
[scan.high_entropy]
min_length = 24
entropy_threshold = 4.8

[scan.severity]
provider_token = "blocking"

[scan.env]
severity = "blocking"
"#,
        )?;

    let mut doctor_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "doctor"])?,
        &context,
        &mut doctor_output,
    )?;

    let doctor_output = String::from_utf8(doctor_output)?;
    assert!(doctor_output.contains(
        "warning: non-default scanner thresholds high_entropy min_length=24 entropy_threshold=4.8"
    ));
    assert!(doctor_output.contains(
        "warning: non-default scanner severity provider_token=blocking env_file=blocking"
    ));
    assert!(doctor_output.contains("metadata_only: yes"));
    Ok(())
}

#[test]
fn policy_doctor_rejects_invalid_policy_document() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::write(
        directory.path().join("locket.toml"),
        r#"
schema_version = 1
project_id = "lk_proj_0123456789abcdef"
name = "app"
default_profile = "dev"

[commands.dev]
argv = []
"#,
    )?;

    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "policy", "doctor"])?,
            &context,
            &mut Vec::new(),
        ),
        "argv",
    );
    Ok(())
}

#[test]
fn policy_doctor_returns_agent_unavailable_for_unvalidated_lk_references()
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
            br#"
[commands.uses_reference]
argv = ["echo", "lk://dev/DATABASE_URL"]
override = "preserve"
"#,
        )?;

    let mut doctor_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "policy", "doctor"])?,
        &context,
        &mut doctor_output,
    );
    let Err(error) = result else {
        return Err("policy doctor should be incomplete without agent validation".into());
    };

    assert_eq!(error.exit_code(), locket_core::LocketError::AgentUnavailable.exit_code());
    assert!(error.to_string().contains("AgentUnavailable"));
    let doctor_output = String::from_utf8(doctor_output)?;
    assert!(doctor_output.contains("policy_doctor: incomplete"));
    assert!(
        doctor_output.contains("warning: lk:// validation skipped because agent is unavailable")
    );
    assert!(doctor_output.contains("unvalidated_lk_references: present"));
    Ok(())
}

#[test]
fn missing_policy_commands_exit_with_policy_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let allow_result = run_with_context(
        Cli::try_parse_from(["locket", "policy", "allow", "missing", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = allow_result else {
        return Err("missing policy allow should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::PolicyNotFound.exit_code());
    assert!(error.to_string().contains("command policy not found: missing"));

    let delete_result = run_with_context(
        Cli::try_parse_from(["locket", "policy", "delete", "missing"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = delete_result else {
        return Err("missing policy delete should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::PolicyNotFound.exit_code());
    assert!(error.to_string().contains("command policy not found: missing"));
    Ok(())
}

#[test]
fn profile_create_writes_metadata_only_audit_row() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut output,
    )?;
    assert!(String::from_utf8(output)?.contains("created profile staging"));

    let store = crate::open_store(&context)?;
    let (profile_id, metadata): (String, String) = store.connection().query_row(
        "SELECT profile_id, metadata_json FROM audit_log WHERE action = 'PROFILE_CREATE'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert!(profile_id.starts_with("lk_prof_"));
    assert!(metadata.contains("\"action\":\"PROFILE_CREATE\""));
    assert!(metadata.contains("\"status\":\"SUCCESS\""));
    assert!(metadata.contains("\"profile_name\":\"staging\""));
    assert!(metadata.contains("\"dangerous\":false"));
    assert!(
        metadata
            .contains("\"key_purposes_initialized\":[\"profile-secret\",\"profile-fingerprint\"]")
    );
    Ok(())
}

#[test]
fn profile_create_existing_profile_errors_without_audit_row()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "dev"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("duplicate profile create should fail".into());
    };
    assert_eq!(error.exit_code(), 67);
    assert!(error.to_string().contains("profile already exists"));

    let store = crate::open_store(&context)?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PROFILE_CREATE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn profile_create_rejects_reserved_default_name_without_audit_row()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "_default"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("creating the _default profile must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::InvalidProfileName.exit_code());

    let store = crate::open_store(&context)?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PROFILE_CREATE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn use_profile_writes_profile_change_audit_row() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "use", "staging"])?, &context, &mut output)?;
    assert!(String::from_utf8(output)?.contains("active profile: staging"));

    let config = crate::read_project_config(&directory.path().join("locket.toml"))?;
    assert_eq!(config.default_profile.as_str(), "staging");

    let store = crate::open_store(&context)?;
    let (profile_id, command, secret_name, metadata): (
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    ) = store.connection().query_row(
        "SELECT profile_id, command, secret_name, metadata_json
         FROM audit_log
         WHERE action = 'PROFILE_CHANGE' AND command = 'use'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(command.as_deref(), Some("use"));
    assert_eq!(secret_name, None);
    assert_eq!(metadata["action"], json!("PROFILE_CHANGE"));
    assert_eq!(metadata["status"], json!("SUCCESS"));
    assert_eq!(metadata["operation"], json!("use"));
    assert_eq!(metadata["command"], json!("use"));
    assert_eq!(metadata["project_id"].as_str(), Some(config.project_id.as_str()));
    assert_eq!(metadata["prior_profile_name"], json!("dev"));
    assert_eq!(metadata["new_profile_name"], json!("staging"));
    assert_eq!(metadata["new_profile_id"].as_str(), profile_id.as_deref());
    assert_eq!(metadata["root_hash"].as_str().map(str::len), Some(64));
    assert!(metadata.get("secret_name").is_none());
    Ok(())
}

#[test]
fn use_profile_same_default_writes_no_audit_row() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "use", "dev"])?, &context, &mut output)?;
    assert!(String::from_utf8(output)?.contains("unchanged"));

    let store = crate::open_store(&context)?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PROFILE_CHANGE' AND command = 'use'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn use_profile_missing_profile_writes_no_audit_row() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "profile not found");
    let config = crate::read_project_config(&directory.path().join("locket.toml"))?;
    assert_eq!(config.default_profile.as_str(), "dev");

    let store = crate::open_store(&context)?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PROFILE_CHANGE' AND command = 'use'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn profile_mark_dangerous_writes_profile_change_audit_with_prior_flags()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let mark_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n");
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &mark_context,
        &mut Vec::new(),
    )?;

    let store = crate::open_store(&mark_context)?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'PROFILE_CHANGE'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"operation\":\"set_dangerous\""));
    assert!(metadata.contains("\"prior_dangerous\":false"));
    assert!(metadata.contains("\"new_dangerous\":true"));
    assert!(metadata.contains("\"profile_name\":\"dev\""));
    Ok(())
}

#[test]
fn profile_mark_dangerous_rejects_wrong_typed_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let bad_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "wrong\n");
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &bad_context,
        &mut output,
    );
    assert_error_contains(result, "confirmation did not match");
    let store = crate::open_store(&bad_context)?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let profile = store.get_profile_by_name(&project_id, "dev")?.ok_or("profile missing")?;
    assert!(!profile.dangerous, "rejected confirmation must not flip flag");
    Ok(())
}

#[test]
fn profile_mark_dangerous_honors_configured_user_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "user_verification_required_for.dangerous_profile_switch",
            "true",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    let denied_context = context_with_user_verifier(
        &test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n"),
        Arc::new(MemoryLocalUserVerifier::denying()),
    );
    let result = run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &denied_context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("denied user verification must reject dangerous flag change".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UserVerificationFailed.exit_code());
    let store = crate::open_store(&denied_context)?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let profile = store.get_profile_by_name(&project_id, "dev")?.ok_or("profile missing")?;
    assert!(!profile.dangerous);

    let verified_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n");
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &verified_context,
        &mut Vec::new(),
    )?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'PROFILE_CHANGE'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["user_verification"]["required"], json!(true));
    assert_eq!(metadata["user_verification"]["satisfied"], json!(true));
    assert_eq!(metadata["user_verification"]["method"], json!("test"));
    Ok(())
}

#[test]
fn profile_clear_dangerous_requires_clear_prefix_in_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n"),
        &mut Vec::new(),
    )?;

    let bare_name_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n");
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "profile", "clear-dangerous", "dev"])?,
        &bare_name_context,
        &mut output,
    );
    assert_error_contains(result, "confirmation did not match");

    let prefix_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "clear dev\n",
    );
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "clear-dangerous", "dev"])?,
        &prefix_context,
        &mut output,
    )?;
    assert!(String::from_utf8(output)?.contains("dangerous=not-dangerous"));
    Ok(())
}

#[test]
fn profile_mark_dangerous_is_no_op_when_already_dangerous() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n"),
        &mut Vec::new(),
    )?;
    let no_confirmation_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "should-not-be-read\n",
    );
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &no_confirmation_context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("dangerous=dangerous unchanged"));
    let store = crate::open_store(&no_confirmation_context)?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PROFILE_CHANGE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1, "no-op mark must not append a new audit row");
    Ok(())
}

#[test]
fn profile_mark_dangerous_unknown_profile_errors_without_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "missing\n",
    );
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "missing"])?,
        &context,
        &mut output,
    );
    assert_error_contains(result, "profile not found");
    let store = crate::open_store(&context)?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PROFILE_CHANGE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn profile_dangerous_marking_updates_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let init_context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &init_context,
        &mut output,
    )?;

    let mark_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n");
    let mut mark_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &mark_context,
        &mut mark_output,
    )?;
    let mark_output = String::from_utf8(mark_output)?;
    assert!(mark_output.contains("dangerous=dangerous"));
    assert!(mark_output.contains("metadata_only: yes"));
    assert!(mark_output.contains("active_secrets: 0"));
    assert!(mark_output.contains("directory_grants: 0"));
    assert!(mark_output.contains("prior=not-dangerous"));

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "list"])?,
        &mark_context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("* dev"));
    assert!(list_output.contains("dangerous"));

    let clear_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "clear dev\n",
    );
    let mut clear_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "clear-dangerous", "dev"])?,
        &clear_context,
        &mut clear_output,
    )?;
    let clear_output = String::from_utf8(clear_output)?;
    assert!(clear_output.contains("dangerous=not-dangerous"));
    assert!(clear_output.contains("prior=dangerous"));
    let mut list_after_clear = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "list"])?,
        &clear_context,
        &mut list_after_clear,
    )?;
    assert!(!String::from_utf8(list_after_clear)?.contains("dangerous"));
    Ok(())
}

#[test]
fn project_root_commands_manage_trusted_roots() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "list-roots"])?,
        &context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("display_path:"));
    let root_hash = list_output
        .lines()
        .find_map(|line| line.strip_prefix("root_hash: "))
        .ok_or("root hash should be listed")?
        .to_owned();
    assert_eq!(root_hash.len(), 64);

    let mut trust_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "trust-root"])?,
        &context,
        &mut trust_output,
    )?;
    let trust_output = String::from_utf8(trust_output)?;
    assert!(trust_output.contains("canonical_path:"));
    assert!(trust_output.contains("trusted root already present"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let trusted_row_count: u32 =
        store.connection().query_row("SELECT COUNT(*) FROM project_roots", [], |row| row.get(0))?;
    assert_eq!(trusted_row_count, 1);

    let mut failed_trust_output = Vec::new();
    let failed_trust_context = context_with_confirmation(&context, "wrong\n");
    let failed_trust = run_with_context(
        Cli::try_parse_from(["locket", "project", "trust-root"])?,
        &failed_trust_context,
        &mut failed_trust_output,
    );
    assert_error_contains(failed_trust, "confirmation did not match project name");
    let trusted_row_count_after_failed_confirm: u32 =
        store.connection().query_row("SELECT COUNT(*) FROM project_roots", [], |row| row.get(0))?;
    assert_eq!(trusted_row_count_after_failed_confirm, 1);

    let mut untrust_output = Vec::new();
    let untrust_context = context_with_confirmation(&context, &format!("{root_hash}\n"));
    run_with_context(
        Cli::try_parse_from(["locket", "project", "untrust-root", root_hash.as_str()])?,
        &untrust_context,
        &mut untrust_output,
    )?;
    let untrust_output = String::from_utf8(untrust_output)?;
    assert!(untrust_output.contains("trusted root removed"));
    assert!(untrust_output.contains("directory_grants_revoked: 0"));

    let mut status_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "status"])?, &context, &mut status_output)?;
    assert!(String::from_utf8(status_output)?.contains("trusted_root: no"));

    let mut relist_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "list-roots"])?,
        &context,
        &mut relist_output,
    )?;
    assert!(String::from_utf8(relist_output)?.contains("no trusted roots"));

    let mut retrust_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "trust-root"])?,
        &context,
        &mut retrust_output,
    )?;
    assert!(String::from_utf8(retrust_output)?.contains("trusted root added"));

    let audit_actions: Vec<String> = {
        let mut statement = store
            .connection()
            .prepare("SELECT metadata_json FROM audit_log WHERE action = 'TRUST_ROOT'")?;
        statement.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?
    };
    assert_eq!(audit_actions.len(), 3);
    assert!(audit_actions.iter().any(|metadata| metadata.contains("\"operation\":\"refresh\"")));
    assert!(audit_actions.iter().any(|metadata| metadata.contains("\"operation\":\"untrust\"")));
    assert!(audit_actions.iter().any(|metadata| metadata.contains("\"operation\":\"trust\"")));
    Ok(())
}

#[test]
fn shell_snippets_are_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
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

    let mut shellenv_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "shellenv", "--shell", "bash"])?,
        &context,
        &mut shellenv_output,
    )?;
    let shellenv_output = String::from_utf8(shellenv_output)?;
    assert!(shellenv_output.contains(crate::SHELL_HOOK_BEGIN));
    assert!(shellenv_output.contains("__LOCKET_SHELLENV_SOURCED"));
    assert!(shellenv_output.contains("locket_prompt_segment()"));
    assert!(shellenv_output.contains("^project: "));
    assert!(shellenv_output.contains("^default_profile: "));
    assert!(shellenv_output.contains("^lock_state: "));
    assert!(shellenv_output.contains(" · "));
    assert!(shellenv_output.contains("🔒"));
    assert!(shellenv_output.contains("🔓"));
    assert!(!shellenv_output.contains("project_id:"));
    assert!(!shellenv_output.contains("postgres://localhost/app"));
    assert!(!shellenv_output.contains("grant_id"));
    assert!(!shellenv_output.contains("token"));

    let mut fish_shellenv_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "shellenv", "--shell", "fish"])?,
        &context,
        &mut fish_shellenv_output,
    )?;
    let fish_shellenv_output = String::from_utf8(fish_shellenv_output)?;
    assert!(fish_shellenv_output.contains("function locket_prompt_segment"));
    assert!(fish_shellenv_output.contains("^lock_state: "));
    assert!(fish_shellenv_output.contains(" · "));
    assert!(!fish_shellenv_output.contains("postgres://localhost/app"));

    let mut hook_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "hook", "--shell", "zsh"])?,
        &context,
        &mut hook_output,
    )?;
    let hook_output = String::from_utf8(hook_output)?;
    assert!(hook_output.contains(crate::SHELL_HOOK_BEGIN));
    assert!(hook_output.contains("locket.toml"));
    assert!(!hook_output.contains("postgres://localhost/app"));
    assert!(!hook_output.contains("grant_id"));
    assert!(!hook_output.contains("token"));

    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;
    let mut install_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "hook", "--install"])?,
        &context,
        &mut install_output,
    )?;
    let install_output = String::from_utf8(install_output)?;
    assert!(install_output.contains("hook install: durable directory grant present"));
    assert!(install_output.contains("metadata_only: yes"));
    assert!(!install_output.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn team_init_writes_team_init_audit_row_and_team_record() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "init", "platform-team"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("team initialized: platform-team"));
    assert!(output.contains("metadata_only: yes"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let team = store.get_team_by_project(&project_id)?.ok_or("team row should exist")?;
    assert_eq!(team.name, "platform-team");
    assert!(team.id.starts_with("lk_team_"));

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'TEAM_INIT'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "SUCCESS");
    assert_eq!(metadata_json["command"], "team init");
    assert_eq!(metadata_json["team_name"], "platform-team");
    assert_eq!(metadata_json["team_id"], team.id);
    assert_eq!(metadata_json["project_id"], project_id);
    Ok(())
}

#[test]
fn team_init_rejects_already_initialized_project() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "team", "init", "platform-team"])?,
        &context,
        &mut Vec::new(),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "team", "init", "another-team"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("re-init must reject the second team".into());
    };
    assert_eq!(error.exit_code(), 67);
    assert!(error.to_string().contains("team already initialized"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let team_init_count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'TEAM_INIT'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(team_init_count, 1, "rejected re-init must not write a second TEAM_INIT row");
    Ok(())
}

#[test]
fn use_dangerous_profile_requires_typed_confirmation() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "prod"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "prod"])?,
        &test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "prod\n"),
        &mut Vec::new(),
    )?;

    // Wrong confirmation is rejected
    let result = run_with_context(
        Cli::try_parse_from(["locket", "use", "prod"])?,
        &test_context_with_key_store_and_confirmation(
            &directory,
            Arc::clone(&key_store),
            "wrong\n",
        ),
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("use dangerous profile with wrong confirmation must fail".into());
    };
    assert_eq!(error.exit_code(), 68, "ConfirmationFailed is exit 68");
    assert!(error.to_string().contains("confirmation did not match"));

    // Config must not have changed
    let config = crate::read_project_config(&directory.path().join("locket.toml"))?;
    assert_eq!(config.default_profile.as_str(), "dev", "failed use must not switch profile");

    // No PROFILE_CHANGE with command=use written for the failed attempt
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let use_count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PROFILE_CHANGE' AND command = 'use'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(use_count, 0, "rejected dangerous switch must not write a PROFILE_CHANGE audit row");

    Ok(())
}

#[test]
fn use_dangerous_profile_succeeds_with_correct_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "prod"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "prod"])?,
        &test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "prod\n"),
        &mut Vec::new(),
    )?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "prod"])?,
        &test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "prod\n"),
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("dangerous_profile: prod"));
    assert!(output.contains("active profile: prod"));

    let config = crate::read_project_config(&directory.path().join("locket.toml"))?;
    assert_eq!(config.default_profile.as_str(), "prod");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'PROFILE_CHANGE' AND command = 'use'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"new_profile_dangerous\":true"));
    assert!(metadata.contains("\"new_profile_name\":\"prod\""));
    assert!(metadata.contains("\"prior_profile_name\":\"dev\""));
    Ok(())
}

#[test]
fn use_dangerous_profile_honors_configured_user_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "prod"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "prod"])?,
        &test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "prod\n"),
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "user_verification_required_for.dangerous_profile_switch",
            "true",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    let denied_context = context_with_user_verifier(
        &test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "prod\n"),
        Arc::new(MemoryLocalUserVerifier::denying()),
    );
    let result = run_with_context(
        Cli::try_parse_from(["locket", "use", "prod"])?,
        &denied_context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("denied user verification must reject dangerous profile switch".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UserVerificationFailed.exit_code());
    let config = crate::read_project_config(&directory.path().join("locket.toml"))?;
    assert_eq!(config.default_profile.as_str(), "dev");

    let verified_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "prod\n");
    run_with_context(
        Cli::try_parse_from(["locket", "use", "prod"])?,
        &verified_context,
        &mut Vec::new(),
    )?;
    let store = crate::open_store(&verified_context)?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'PROFILE_CHANGE' AND command = 'use'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["user_verification"]["required"], json!(true));
    assert_eq!(metadata["user_verification"]["satisfied"], json!(true));
    assert_eq!(metadata["user_verification"]["method"], json!("test"));
    Ok(())
}

#[test]
fn use_non_dangerous_profile_requires_no_confirmation() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "use", "staging"])?, &context, &mut output)?;
    let output = String::from_utf8(output)?;
    assert!(
        !output.contains("dangerous_profile"),
        "non-dangerous switch must not show dangerous prompt"
    );
    assert!(output.contains("active profile: staging"));
    Ok(())
}
