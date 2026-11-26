//! Public error and policy contracts shared by the CLI, agent, and desktop.
#![allow(unused_crate_dependencies, clippy::multiple_crate_versions)]

use std::collections::BTreeMap;
use std::path::Path;

use locket_core::{
    EnvMap, LocketError, PolicyDocument, PolicyParseError, SecretAccessPolicy, SecretName,
    VariableClassification, VariableReadinessState, env_value, variable_exposure_warning,
};

#[test]
fn typed_errors_offer_failure_specific_recovery() {
    use LocketError::{
        AccessDenied, AgentSocketInUse, AgentUnavailable, AuditIntegrityFailed,
        AutomationClientNotTrusted, AutomationClientReplayDetected, BundleVerificationFailed,
        ConfirmationFailed, CorruptDb, DangerousProfileConfirmationRequired,
        DeviceDescriptorInvalid, DeviceRevoked, EnvironmentConflict, ExternalSourceUnavailable,
        GitWorktreeRequired, GrantRequired, IdeEnvSessionUnavailable, InvalidPolicy,
        InvalidProfileName, InvalidReference, InvalidSecretName, InviteExpired,
        InviteSignatureInvalid, KeychainUnavailable, LostKeychainEntry, LostRecoveryCode,
        MetadataInvalid, MetadataLooksLikeSecret, PolicyNotFound, PolicyValidationIncomplete,
        ProfileNotFound, ProjectNotFound, ProjectRootUntrusted, ReplayDetected, ScanFindingBlocked,
        SchemaNewerThanBinary, SecretAlreadyExists, SecretDeleted, SecretNotFound,
        SecretVersionExpired, SecretVersionOverflow, SharedVaultNotInitialized, StorageBusy,
        TeamBundleConflict, TeamRoleDenied, TtyRequired, UnlockRequired, UnrecoverableVault,
        UpdateManifestInvalid, UserVerificationFailed,
    };

    let cases = [
        (InvalidReference, "reference syntax"),
        (GitWorktreeRequired, "Git worktree"),
        (InvalidSecretName, "uppercase"),
        (InvalidProfileName, "lowercase"),
        (PolicyValidationIncomplete, "unlock the agent"),
        (InvalidPolicy, "policy document"),
        (PolicyNotFound, "existing policy name"),
        (EnvironmentConflict, "override mode"),
        (MetadataInvalid, "unsupported characters"),
        (MetadataLooksLikeSecret, "secret-like metadata"),
        (ConfirmationFailed, "confirmation exactly"),
        (TtyRequired, "interactive terminal"),
        (ScanFindingBlocked, "rotate exposed values"),
        (SecretAlreadyExists, "rotate/update"),
        (AccessDenied, "required grant"),
        (DangerousProfileConfirmationRequired, "--use-dangerous"),
        (TeamRoleDenied, "owner or maintainer"),
        (ProjectRootUntrusted, "locket project trust-root"),
        (ProjectNotFound, "locket init"),
        (SharedVaultNotInitialized, "locket shared init"),
        (UnlockRequired, "locket unlock"),
        (GrantRequired, "locket allow"),
        (UserVerificationFailed, "verification"),
        (SecretVersionExpired, "grace window"),
        (SecretDeleted, "trusted backup"),
        (SecretNotFound, "secret name"),
        (ProfileNotFound, "existing profile"),
        (AgentUnavailable, "locket agent start"),
        (AgentSocketInUse, "stale agent"),
        (AutomationClientNotTrusted, "Register the client"),
        (AutomationClientReplayDetected, "fresh nonce"),
        (ExternalSourceUnavailable, "external provider"),
        (IdeEnvSessionUnavailable, "VS Code extension"),
        (UpdateManifestInvalid, "trusted release artifact"),
        (SecretVersionOverflow, "store metadata"),
        (CorruptDb, "trusted backup"),
        (StorageBusy, "other command"),
        (SchemaNewerThanBinary, "Upgrade Locket and retry"),
        (AuditIntegrityFailed, "store tampering"),
        (KeychainUnavailable, "passphrase fallback"),
        (LostRecoveryCode, "Rotate recovery"),
        (LostKeychainEntry, "locket recover"),
        (UnrecoverableVault, "trusted device"),
        (BundleVerificationFailed, "fresh bundle"),
        (InviteExpired, "maintainer"),
        (TeamBundleConflict, "metadata-only"),
        (DeviceRevoked, "trusted device"),
        (ReplayDetected, "fresh invite"),
        (DeviceDescriptorInvalid, "Recreate the descriptor"),
        (InviteSignatureInvalid, "Reject the invite"),
    ];
    for (error, recovery) in cases {
        let copy = error.display_copy();
        assert!(copy.next_action.contains(recovery), "{error:?}: {copy:?}");
    }
}

#[test]
fn command_acl_wildcards_match_the_entire_command_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let mut acl = SecretAccessPolicy {
        name: SecretName::new("SERVICE_TOKEN")?,
        allow_commands: Vec::new(),
        allow_argv: Vec::new(),
        allow_paths: Vec::new(),
    };
    let (finished, completion) = std::sync::mpsc::channel();
    let _worker = std::thread::spawn(move || {
        for (pattern, allowed, denied) in [
            ("release", &["release"][..], &["", "release-old", "pre-release"][..]),
            ("release:*", &["release:", "release:prod"], &["release", "pre-release:prod"]),
            ("*-check", &["-check", "pré-check", "*-check"], &["check", "lint-check-extra"]),
            ("re*e:*:prod", &["ree::prod", "release:team:prod"], &["release:team:dev", "r:prod"]),
            ("a*a*b", &["aab", "ababb", "aaxayb"], &["ab", "aaa", "aabx"]),
            ("*", &["", "dev", "*"], &[]),
        ] {
            acl.allow_commands = vec![pattern.to_owned()];
            for command in allowed {
                assert!(acl.allows(command, None, Path::new(".")), "{pattern} vs {command}");
            }
            for command in denied {
                assert!(!acl.allows(command, None, Path::new(".")), "{pattern} vs {command}");
            }
        }
        let _ = finished.send(());
    });
    completion
        .recv_timeout(std::time::Duration::from_secs(10))
        .map_err(|error| format!("wildcard evaluation did not complete: {error}"))?;
    Ok(())
}

#[test]
fn secret_acl_applies_each_configured_dimension_and_accepts_multiple_patterns()
-> Result<(), PolicyParseError> {
    let document = PolicyDocument::from_toml_str(
        r#"
        schema_version = 1
        [commands.release]
        argv = ["tool", "build"]
        required_secrets = ["SERVICE_TOKEN", "OTHER_TOKEN"]

        [secrets.SERVICE_TOKEN]
        allow_commands = ["release", "preview:*"]
        allow_argv = [["tool", "**", "build", "**", "--release"], ["tool", "preview"]]
        allow_paths = ["apps/api/**", "packages/*/tests"]
        "#,
    )?;
    let names = &document.commands["release"].required_secrets;
    let acl = &document.secret_access["SERVICE_TOKEN"];
    let release = ["tool", "--verbose", "build", "target", "--release"].map(str::to_owned);
    let preview = ["tool", "preview"].map(str::to_owned);
    let empty_tail = ["tool", "build", "--release"].map(str::to_owned);
    let missing_token = ["tool", "build", "target"].map(str::to_owned);
    let trailing_token = ["tool", "build", "--release", "other"].map(str::to_owned);
    for (name, argv, cwd, allowed) in [
        ("release", Some(release.as_slice()), "apps/api", true),
        ("release", Some(empty_tail.as_slice()), "apps/api/nested", true),
        ("preview:dev", Some(preview.as_slice()), "packages/core/tests", true),
        ("debug", Some(release.as_slice()), "apps/api", false),
        ("release", None, "apps/api", false),
        ("release", Some(missing_token.as_slice()), "apps/api", false),
        ("release", Some(trailing_token.as_slice()), "apps/api", false),
        ("release", Some(release.as_slice()), "apps/api-sibling", false),
        ("release", Some(release.as_slice()), "apps", false),
    ] {
        assert_eq!(acl.allows(name, argv, Path::new(cwd)), allowed, "{name} at {cwd}");
        let denied = document.denied_secrets(name, argv, Path::new(cwd), names);
        if allowed {
            assert_eq!(denied, [] as [&SecretName; 0]);
        } else {
            assert_eq!(denied, [&names[0]]);
        }
    }
    Ok(())
}

#[test]
fn path_scope_promotes_required_names_and_preserves_command_options()
-> Result<(), Box<dyn std::error::Error>> {
    let document = PolicyDocument::from_toml_str(
        r#"
        schema_version = 1
        [commands.dev]
        argv = ["tool", "dev"]
        require_agent = true
        required_secrets = ["ALREADY_REQUIRED"]
        optional_secrets = ["PROMOTED"]
        [paths."."]
        required_secrets = ["ROOT_ONLY"]
        [paths.apps]
        optional_secrets = ["APPS_ONLY"]
        [paths."apps/api"]
        required_secrets = ["PROMOTED", "API_ONLY"]
        optional_secrets = ["ALREADY_REQUIRED"]
        "#,
    )?;
    let root = Path::new("project");
    for (relative, expected, depth) in
        [(".", ".", 0), ("apps", "apps", 1), ("apps/api/src", "apps/api", 2)]
    {
        let scope = document.path_scope_for(root, &root.join(relative)).ok_or("missing scope")?;
        assert_eq!(scope.path, Path::new(expected));
        assert_eq!(scope.depth(), depth);
    }
    assert!(document.path_scope_for(root, Path::new("elsewhere")).is_none());
    let effective =
        document.effective_command("dev", root, &root.join("apps/api")).ok_or("missing command")?;
    let required: Vec<_> = effective.required_secrets.iter().map(SecretName::as_str).collect();
    let allowed: Vec<_> = effective.allowed_secrets.iter().map(SecretName::as_str).collect();
    assert_eq!(required, ["ALREADY_REQUIRED", "API_ONLY", "PROMOTED"]);
    assert_eq!(allowed, required);
    assert_eq!(effective.optional_secrets, [] as [SecretName; 0]);
    assert!(effective.require_agent);
    assert_eq!(effective.command, document.commands["dev"].command);
    Ok(())
}

#[test]
fn readiness_prioritizes_real_sources_and_does_not_supply_shared_defaults()
-> Result<(), Box<dyn std::error::Error>> {
    let document = PolicyDocument::from_toml_str(
        r#"
        schema_version = 1
        [commands.dev]
        argv = ["tool"]
        required_secrets = ["PORT", "REQUIRED_TOKEN"]
        optional_secrets = ["OPTIONAL_TOKEN"]
        shared_secrets = ["SHARED_PORT"]
        [variables.PORT]
        classification = "public"
        type = "integer"
        default = "5000"
        [variables.SHARED_PORT]
        classification = "public"
        type = "integer"
        default = "6000"
        "#,
    )?;
    let policy = &document.commands["dev"];
    let sources = BTreeMap::from([("PORT".to_owned(), "local-file".to_owned())]);
    let rows = document.variable_readiness(policy, &sources, false);
    let row = |name| rows.iter().find(|row| row.name == name).ok_or("missing readiness row");
    let port = row("PORT")?;
    assert_eq!(port.state, VariableReadinessState::Ready);
    assert_eq!(port.selected_source.as_deref(), Some("local-file"));
    assert!(port.required);
    assert_eq!(port.next_action, None);
    let shared = row("SHARED_PORT")?;
    assert_eq!(shared.state, VariableReadinessState::Missing);
    assert_eq!(shared.selected_source, None);
    assert_eq!(shared.next_action.as_deref(), Some("locket set SHARED_PORT --project @shared"));
    assert_eq!(row("REQUIRED_TOKEN")?.next_action.as_deref(), Some("locket set REQUIRED_TOKEN"));
    assert_eq!(row("OPTIONAL_TOKEN")?.state, VariableReadinessState::Optional);

    let without_sources = document.variable_readiness(policy, &BTreeMap::new(), false);
    assert!(without_sources.iter().any(|row| {
        row.name == "PORT" && row.selected_source.as_deref() == Some("public-default")
    }));
    for row in document.variable_readiness(policy, &sources, true) {
        let expected = if row.name == "PORT" {
            VariableReadinessState::Ready
        } else {
            VariableReadinessState::Unverified
        };
        assert_eq!(row.state, expected, "{}", row.name);
    }
    let mut env = EnvMap::new();
    document.apply_variable_defaults(policy, &mut env);
    assert_eq!(env, EnvMap::from([("PORT".to_owned(), env_value("5000".to_owned()))]));
    env.insert("PORT".into(), env_value("7000".to_owned()));
    document.apply_variable_defaults(policy, &mut env);
    assert_eq!(env.get("PORT").map(|value| value.as_str()), Some("7000"));
    Ok(())
}

#[test]
fn browser_exposure_warnings_are_specific_to_secret_values_with_public_prefixes() {
    use VariableClassification::{Public, Secret};

    for (name, classification, should_warn) in [
        ("VITE_TOKEN", Secret, true),
        ("NEXT_PUBLIC_TOKEN", Secret, true),
        ("VITE_BUILD_MODE", Public, false),
        ("NEXT_PUBLIC_ORIGIN", Public, false),
        ("BACKEND_TOKEN", Secret, false),
    ] {
        let warning = variable_exposure_warning(name, classification);
        assert_eq!(warning.is_some(), should_warn, "{name}");
        if let Some(warning) = warning {
            assert!(warning.contains(name));
            assert!(warning.contains("browser bundles"));
        }
    }
}
