#[allow(unused_imports)]
use super::*;

#[test]
fn team_pending_cli_accepts_explicit_metadata_resolution_commands()
-> Result<(), Box<dyn std::error::Error>> {
    for argv in [
        vec!["locket", "team", "sync", "pending"],
        vec![
            "locket",
            "team",
            "sync",
            "rename-local-profile",
            "incoming-profile",
            "local-profile",
            "personal-dev",
        ],
        vec!["locket", "team", "sync", "keep-local-value", "incoming-profile", "local-secret"],
    ] {
        Cli::try_parse_from(argv)?;
    }
    assert!(
        Cli::try_parse_from(["locket", "team", "sync", "rename-local-profile", "incoming-profile"])
            .is_err()
    );
    assert!(
        Cli::try_parse_from(["locket", "team", "sync", "keep-local-value", "incoming-profile"])
            .is_err()
    );
    let help = Cli::try_parse_from(["locket", "team", "sync", "pending", "--help"])
        .err()
        .ok_or("help must exit parser")?
        .to_string();
    assert!(help.contains("values"));
    let rename_help =
        Cli::try_parse_from(["locket", "team", "sync", "rename-local-profile", "--help"])
            .err()
            .ok_or("rename help must exit parser")?
            .to_string();
    for consequence in ["default_profile", "lk://", "incoming team profile", "Directory grants"] {
        assert!(rename_help.contains(consequence), "missing rename consequence: {consequence}");
    }
    Ok(())
}

#[test]
fn team_pending_cli_profile_placeholder_has_specific_guidance_without_unlock()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
        &context,
        &mut Vec::new(),
    )?;
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "team",
            "sync",
            "resolve",
            "profile:incoming-profile",
            "keep-local",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let message = result.err().ok_or("profile placeholder must reject")?.to_string();
    assert!(message.contains("team sync pending"));
    assert!(message.contains("rename-local-profile"));
    assert!(message.contains("keep-local-value"));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn team_pending_cli_initial_join_advances_trust_but_holds_dangerous_values()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = tempdir()?;
    let owner_context = test_context_with_secret_value(&owner, "team-pending-synthetic-canary");
    let mut output = Vec::new();
    for argv in [
        vec!["locket", "init", "--name", "app"],
        vec!["locket", "device", "init"],
        vec!["locket", "team", "init", "Synthetic pending team"],
        vec!["locket", "set", "TEAM_TOKEN", "--source", "team-managed"],
    ] {
        run_with_context(Cli::try_parse_from(argv)?, &owner_context, &mut output)?;
    }
    let config = crate::read_project_config(&owner.path().join("locket.toml"))?;
    let project = config.project_id.as_str();
    let owner_store = crate::open_store(&owner_context)?;
    let owner_device = owner_store.get_active_local_device(project)?.ok_or("owner device")?;
    owner_store
        .connection()
        .execute("UPDATE profiles SET dangerous=1 WHERE project_id=?1", [project])?;
    let receiver = tempdir()?;
    fs::copy(owner.path().join("locket.toml"), receiver.path().join("locket.toml"))?;
    let receiver_context = test_context(&receiver);
    run_with_context(
        Cli::try_parse_from(["locket", "team", "join", "--request"])?,
        &receiver_context,
        &mut output,
    )?;
    let receiver_store = crate::open_store(&receiver_context)?;
    let receiver_device =
        receiver_store.get_active_local_device(project)?.ok_or("receiver device")?;
    let descriptor = crate::commands::team::device::encode_device_descriptor(&receiver_device)?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "team",
            "add",
            "Receiver",
            "--device",
            &descriptor,
            "--confirm-device-fingerprint",
            &receiver_device.fingerprint,
            "--profile",
            "dev",
        ])?,
        &context_with_confirmation(&owner_context, "team share dev"),
        &mut output,
    )?;
    let shared = tempdir()?;
    let folder = shared.path().to_str().ok_or("folder")?;
    run_with_context(
        Cli::try_parse_from(["locket", "team", "folder", folder])?,
        &owner_context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "team", "publish"])?,
        &context_with_confirmation(&owner_context, "team share dev"),
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "team",
            "join",
            "--folder",
            folder,
            "--owner",
            &owner_device.fingerprint,
        ])?,
        &receiver_context,
        &mut output,
    )?;
    let status = locket_agent::team_sync::status(&receiver_store, project)?;
    assert!(status.epoch > 0);
    assert_eq!(status.state, "pending-values");
    assert_eq!(status.pending_profiles.len(), 1);
    let secret_count = || {
        receiver_store.connection().query_row(
            "SELECT COUNT(*) FROM secrets WHERE project_id=?1 AND name='TEAM_TOKEN'",
            [project],
            |row| row.get::<_, u32>(0),
        )
    };
    assert_eq!(secret_count()?, 0);
    let mut pending = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "sync", "pending"])?,
        &receiver_context,
        &mut pending,
    )?;
    let pending_text = String::from_utf8(pending)?;
    assert!(pending_text.contains("consent-required"));
    assert!(pending_text.contains("profile_id"));
    assert!(!pending_text.contains("team-pending-synthetic-canary"));
    // Even newly supplied consent cannot turn duplicate delivery into a values retry.
    let mut duplicate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "team",
            "join",
            "--folder",
            folder,
            "--owner",
            &owner_device.fingerprint,
            "--allow-dangerous",
        ])?,
        &receiver_context,
        &mut duplicate_output,
    )?;
    let duplicate_text = String::from_utf8(duplicate_output)?;
    let duplicate_report = duplicate_text
        .lines()
        .find_map(|line| line.strip_prefix("team package verified: "))
        .ok_or("join report")?;
    let duplicate_report: serde_json::Value = serde_json::from_str(duplicate_report)?;
    assert_eq!(duplicate_report["duplicate"], true);
    assert_eq!(duplicate_report["pending_profiles"], 1);
    assert!(duplicate_text.contains("held for local review"));
    assert!(duplicate_text.contains("locket team sync pending"));
    assert!(!duplicate_text.contains("team-pending-synthetic-canary"));
    assert_eq!(secret_count()?, 0);
    assert_eq!(locket_agent::team_sync::status(&receiver_store, project)?.epoch, status.epoch);
    assert!(!String::from_utf8(output)?.contains("team-pending-synthetic-canary"));
    Ok(())
}

#[test]
fn signed_team_dangerous_sharing_requires_sender_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = tempdir()?;
    let context = test_context(&owner);
    for argv in [
        vec!["locket", "init", "--name", "app", "--no-passkey"],
        vec!["locket", "team", "init", "Team"],
    ] {
        run_with_context(Cli::try_parse_from(argv)?, &context, &mut Vec::new())?;
    }
    let resolved = crate::require_project(&context)?;
    let project = resolved.config.project_id.as_str();
    let store = crate::open_store(&context)?;
    store.connection().execute("UPDATE profiles SET dangerous=1 WHERE project_id=?1", [project])?;
    let receiver = tempdir()?;
    fs::copy(owner.path().join("locket.toml"), receiver.path().join("locket.toml"))?;
    let receiver_context = test_context(&receiver);
    run_with_context(
        Cli::try_parse_from(["locket", "team", "join", "--request"])?,
        &receiver_context,
        &mut Vec::new(),
    )?;
    let recipient = crate::open_store(&receiver_context)?
        .get_active_local_device(project)?
        .ok_or("receiver device")?;
    let descriptor = crate::commands::team::device::encode_device_descriptor(&recipient)?;
    let add = || {
        Cli::try_parse_from([
            "locket",
            "team",
            "add",
            "Receiver",
            "--device",
            &descriptor,
            "--confirm-device-fingerprint",
            &recipient.fingerprint,
            "--profile",
            "dev",
        ])
    };
    assert!(
        run_with_context(add()?, &context, &mut Vec::new()).is_err(),
        "dangerous grant needs explicit scope acknowledgement"
    );
    let approved = context_with_confirmation(&context, "team share dev");
    run_with_context(add()?, &approved, &mut Vec::new())?;
    let shared = tempdir()?;
    run_with_context(
        Cli::try_parse_from(["locket", "team", "folder", shared.path().to_str().ok_or("folder")?])?,
        &context,
        &mut Vec::new(),
    )?;
    assert!(
        run_with_context(
            Cli::try_parse_from(["locket", "team", "publish"])?,
            &context,
            &mut Vec::new()
        )
        .is_err(),
        "manual publication also needs explicit scope acknowledgement"
    );
    assert_eq!(fs::read_dir(shared.path())?.count(), 0);
    run_with_context(
        Cli::try_parse_from(["locket", "team", "publish"])?,
        &approved,
        &mut Vec::new(),
    )?;
    assert!(fs::read_dir(shared.path())?.count() > 0);
    Ok(())
}
