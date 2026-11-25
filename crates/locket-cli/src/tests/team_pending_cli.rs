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

#[test]
#[allow(clippy::too_many_lines)]
fn signed_sync_reconciles_collisions_and_revokes_the_recipient()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = tempdir()?;
    let receiver = tempdir()?;
    let shared = tempdir()?;
    let folder = shared.path().to_str().ok_or("folder path must be UTF-8")?;
    let owner_context = test_context_with_secret_value(&owner, "owner-sync-synthetic-canary");
    let recipient_context =
        test_context_with_secret_value(&receiver, "recipient-sync-synthetic-canary");
    let run =
        |context: &RuntimeContext, args: &[&str]| -> Result<String, Box<dyn std::error::Error>> {
            let mut output = Vec::new();
            let code = run_with_context(Cli::try_parse_from(args)?, context, &mut output)?;
            assert_eq!(code, 0);
            let output = String::from_utf8(output)?;
            assert!(!output.contains("owner-sync-synthetic-canary"));
            assert!(!output.contains("recipient-sync-synthetic-canary"));
            Ok(output)
        };

    run(&owner_context, &["locket", "init", "--no-passkey", "--name", "app"])?;
    run(&owner_context, &["locket", "profile", "create", "staging"])?;
    run(
        &owner_context,
        &["locket", "set", "TEAM_TOKEN", "--source", "team-managed", "--profile", "staging"],
    )?;
    run(&owner_context, &["locket", "team", "init", "Sync team"])?;
    run(&owner_context, &["locket", "team", "folder", folder])?;
    fs::copy(owner.path().join("locket.toml"), receiver.path().join("locket.toml"))?;
    run(&recipient_context, &["locket", "team", "join", "--request"])?;
    let resolved = crate::require_project(&owner_context)?;
    let project = resolved.config.project_id.as_str();
    let issuer = crate::open_store(&owner_context)?;
    let recipient = crate::open_store(&recipient_context)?;
    let owner_device = issuer.get_active_local_device(project)?.ok_or("owner device missing")?;
    let join_device =
        recipient.get_active_local_device(project)?.ok_or("recipient device missing")?;
    let descriptor = crate::encode_device_descriptor(&join_device)?;
    let add = |pin| {
        [
            "locket",
            "team",
            "add",
            "Receiver",
            "--device",
            &descriptor,
            "--confirm-device-fingerprint",
            pin,
            "--profile",
            "dev",
            "--role",
            "read-only",
        ]
    };
    let wrong_pin = "0".repeat(64);
    let error = run(&owner_context, &add(&wrong_pin)).err().ok_or("wrong device pin accepted")?;
    assert!(error.to_string().contains("verify the full joining-device fingerprint"));
    run(&owner_context, &add(&join_device.fingerprint))?;
    run(&owner_context, &["locket", "team", "publish"])?;
    let package = fs::read_dir(shared.path())?.next().ok_or("delivery missing")??.path();
    let package = package.to_str().ok_or("package path must be UTF-8")?;
    let join = |pin| ["locket", "team", "join", package, "--owner", pin];
    let error = run(&recipient_context, &join("short")).err().ok_or("accepted short owner pin")?;
    assert!(error.to_string().contains("full owner fingerprint"));
    let wrong_owner = run(&recipient_context, &join(&wrong_pin))
        .err()
        .ok_or("accepted incorrect owner pin")?
        .downcast::<crate::CliError>()?;
    assert_eq!(wrong_owner.exit_code(), locket_core::LocketError::MetadataInvalid.exit_code());
    assert!(locket_agent::team_sync::status(&recipient, project)?.owner_fingerprint.is_none());
    let first = run(&recipient_context, &join(&owner_device.fingerprint.to_ascii_uppercase()))?;
    assert!(first.contains("Owner fingerprint was supplied independently"));
    run(&recipient_context, &["locket", "team", "folder", folder])?;
    for args in [
        vec!["locket", "device", "init", "--force"],
        vec!["locket", "device", "remove", &join_device.id, "--force"],
    ] {
        let mut output = Vec::new();
        let denied = run_with_context(Cli::try_parse_from(args)?, &recipient_context, &mut output);
        assert!(matches!(
            denied,
            Err(crate::CliError::Typed { kind: locket_core::LocketError::AccessDenied, .. })
        ));
        assert_eq!(output, b"");
        assert_eq!(
            recipient.get_active_local_device(project)?.ok_or("device was removed")?.id,
            join_device.id
        );
    }
    let dev = recipient.get_profile_by_name(project, "dev")?.ok_or("joined profile missing")?;
    for context in [&recipient_context, &owner_context] {
        run(context, &["locket", "set", "COLLIDING_TOKEN", "--source", "team-managed"])?;
    }
    let local_secret = recipient
        .get_secret_by_source(project, &dev.id, "COLLIDING_TOKEN", "team-managed")?
        .ok_or("local secret missing")?;
    let local_blob = recipient.get_blob(&local_secret.id, local_secret.current_version)?;

    run(&recipient_context, &["locket", "profile", "create", "staging"])?;
    run(
        &recipient_context,
        &["locket", "set", "LOCAL_TOKEN", "--profile", "staging", "--source", "user-local"],
    )?;
    let local =
        recipient.get_profile_by_name(project, "staging")?.ok_or("local profile missing")?;
    let incoming =
        issuer.get_profile_by_name(project, "staging")?.ok_or("owner profile missing")?;
    let team = issuer.get_team_by_project(project)?.ok_or("team missing")?;
    let member = issuer
        .get_active_team_member_by_device(&team.id, &join_device.id)?
        .ok_or("member missing")?;
    // Seed a scope expansion. The CLI can add recipients and publish their current scope.
    issuer.set_team_member_profiles(&member.id, &["dev".to_owned(), "staging".to_owned()])?;
    run(&owner_context, &["locket", "team", "publish"])?;
    run(&recipient_context, &["locket", "team", "sync", "now"])?;

    let pending = run(&recipient_context, &["locket", "team", "sync", "pending"])?;
    assert!(pending.contains("profile-name-collision"));
    assert!(pending.contains("secret-name-collision"));
    assert!(pending.contains(&local_secret.id));
    assert!(pending.contains(&local.id));
    assert!(pending.contains(&incoming.id));
    let rename =
        |name| ["locket", "team", "sync", "rename-local-profile", &incoming.id, &local.id, name];
    assert!(run(&recipient_context, &rename("dev")).is_err(), "occupied profile must block rename");
    assert_eq!(
        recipient.get_profile_by_name(project, "staging")?.ok_or("local profile missing")?.id,
        local.id
    );
    let report = run(&recipient_context, &rename("personal-staging"))?;
    assert!(report.contains("Directory grants remain bound to the renamed local profile ID"));
    assert!(report.contains("No sync was started by this action"));
    assert!(recipient.get_profile_by_name(project, "staging")?.is_none());
    let preserved = run(
        &recipient_context,
        &["locket", "team", "sync", "keep-local-value", &dev.id, &local_secret.id],
    )?;
    assert!(preserved.contains("Local value preserved as a personal override"));
    assert!(
        recipient
            .get_secret_by_source(project, &dev.id, "COLLIDING_TOKEN", "team-managed")?
            .is_none()
    );
    let restored = recipient
        .get_secret_by_source(project, &dev.id, "COLLIDING_TOKEN", "user-local")?
        .ok_or("local override missing")?;
    assert_eq!(restored.id, local_secret.id);
    assert_eq!(recipient.get_blob(&local_secret.id, local_secret.current_version)?, local_blob);
    run(&recipient_context, &["locket", "team", "sync", "now"])?;
    let team_value = recipient
        .get_secret_by_source(project, &dev.id, "COLLIDING_TOKEN", "team-managed")?
        .ok_or("team value missing after retry")?;
    assert_ne!(team_value.id, local_secret.id);
    let status = run(&recipient_context, &["locket", "team", "sync", "status"])?;
    let status: serde_json::Value = serde_json::from_str(&status)?;
    assert_eq!(status["state"], "verified");
    assert_eq!(status["pending_profiles"], json!({}));
    assert_eq!(
        recipient.get_profile_by_name(project, "staging")?.ok_or("incoming profile missing")?.id,
        incoming.id
    );
    assert_eq!(
        recipient
            .get_profile_by_name(project, "personal-staging")?
            .ok_or("local profile missing")?
            .id,
        local.id
    );
    assert!(
        recipient.get_secret_by_source(project, &local.id, "LOCAL_TOKEN", "user-local")?.is_some()
    );
    assert!(
        recipient
            .get_secret_by_source(project, &incoming.id, "TEAM_TOKEN", "team-managed")?
            .is_some()
    );
    let pending = run(&recipient_context, &["locket", "team", "sync", "pending"])?;
    assert!(pending.contains("No profile values are waiting"));

    let remove = ["locket", "team", "remove", &member.id];
    assert!(run(&owner_context, &remove).is_err());
    assert!(
        issuer.get_team_member(&team.id, &member.id)?.ok_or("member missing")?.removed_at.is_none()
    );
    let confirmed = context_with_confirmation(&owner_context, "Receiver");
    let removed = run(&confirmed, &remove)?;
    let rotation = removed
        .lines()
        .find_map(|line| line.strip_prefix("Rotate credentials at their providers: "))
        .ok_or("missing credential rotation checklist")?;
    assert_eq!(
        rotation.split(", ").collect::<BTreeSet<_>>(),
        BTreeSet::from(["COLLIDING_TOKEN", "TEAM_TOKEN"])
    );
    assert!(removed.contains("Signed revocation delivered"));
    assert!(
        issuer.get_team_member(&team.id, &member.id)?.ok_or("member missing")?.removed_at.is_some()
    );

    let rejected_bundle = owner.path().join("revoked-recipient.locket-bundle");
    let rejected_invite = owner.path().join("revoked-recipient.locket-invite");
    for (args, expected) in [
        (
            vec![
                "locket",
                "export",
                "--sealed",
                "--recipient",
                &descriptor,
                "--profile",
                "dev",
                "--output",
                rejected_bundle.to_str().ok_or("bundle path")?,
            ],
            locket_core::LocketError::AccessDenied,
        ),
        (
            vec![
                "locket",
                "team",
                "invite",
                "Former recipient",
                "--device",
                &descriptor,
                "--profile",
                "dev",
                "--role",
                "developer",
                "--output",
                rejected_invite.to_str().ok_or("invite path")?,
            ],
            locket_core::LocketError::TeamRoleDenied,
        ),
    ] {
        let error = run(&owner_context, &args)
            .err()
            .ok_or("revoked device received sharing material")?
            .downcast::<crate::CliError>()?;
        assert_eq!(error.exit_code(), expected.exit_code());
        assert!(error.to_string().contains("recipient device is revoked"));
    }
    assert!(!rejected_bundle.exists());
    assert!(!rejected_invite.exists());

    run(&recipient_context, &["locket", "team", "sync", "disable"])?;
    let disabled = run(&recipient_context, &["locket", "team", "sync", "status"])?;
    let disabled: serde_json::Value = serde_json::from_str(&disabled)?;
    assert_eq!(disabled["folder"], serde_json::Value::Null);
    assert_eq!(disabled["epoch"], status["epoch"]);
    assert_eq!(disabled["owner_fingerprint"], owner_device.fingerprint);
    Ok(())
}
