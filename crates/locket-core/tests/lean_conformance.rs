//! Executable vectors for the Lean path, privacy, and core crypto contracts.
#![allow(unused_crate_dependencies)]

use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, SigningKey};
use locket_core::team_package::{DeviceIdentity, SignedStatement, TeamStatement};
use locket_core::{
    AuditHmacInput, EnvMap, PolicyDocument, PolicyParseError, ProjectConfig, SecretName, Timestamp,
    audit_hmac_v1_bytes, env_value, privacy_alias,
};

fn names(names: &[SecretName]) -> Vec<&str> {
    names.iter().map(SecretName::as_str).collect()
}

#[test]
fn deepest_path_scope_is_unique_for_every_toml_order() -> Result<(), Box<dyn Error>> {
    let scopes = [
        "[paths.'.']\nprofile = 'root'\nrequired_secrets = ['ROOT']\n",
        "[paths.app]\nprofile = 'app'\nrequired_secrets = ['APP']\n",
        "[paths.'app/nested']\nprofile = 'nested'\nrequired_secrets = ['PROMOTED']\noptional_secrets = ['NESTED']\n",
    ];
    let command = "schema_version = 1\n[commands.run]\nargv = ['run']\nrequired_secrets = ['BASE']\noptional_secrets = ['PROMOTED']\nshared_secrets = ['SHARED']\n";
    let root = Path::new("project");
    for order in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let input =
            format!("{command}{}{}{}", scopes[order[0]], scopes[order[1]], scopes[order[2]]);
        let document = PolicyDocument::from_toml_str(&input)?;
        for (cwd, path, profile, required, optional) in [
            ("app/nested/sub", "app/nested", "nested", "PROMOTED", "NESTED"),
            ("app/other", "app", "app", "APP", "PROMOTED"),
            ("app2/sub", ".", "root", "ROOT", "PROMOTED"),
        ] {
            let cwd = root.join(cwd);
            let winner = document.path_scope_for(root, &cwd).ok_or("missing scope")?;
            assert_eq!(winner.path, Path::new(path));
            assert_eq!(
                winner.profile.as_ref().map(locket_core::ProfileName::as_str),
                Some(profile)
            );
            let effective =
                document.effective_command("run", root, &cwd).ok_or("missing command")?;
            assert_eq!(names(&effective.shared_secrets), ["SHARED"]);
            assert_eq!(names(&effective.optional_secrets), [optional]);
            let mut expected = ["BASE", required];
            expected.sort_unstable();
            assert_eq!(names(&effective.required_secrets), expected);
        }
    }
    Ok(())
}

#[test]
fn path_scopes_reject_escape_and_component_prefix_tricks() -> Result<(), PolicyParseError> {
    for path in ["..", "app/../other", "/app"] {
        let input = format!("schema_version=1\n[paths.'{path}']\n");
        assert!(matches!(
            PolicyDocument::from_toml_str(&input),
            Err(PolicyParseError::InvalidPathScope { path: rejected }) if rejected == path
        ));
    }
    let duplicates = "schema_version=1\n[paths.app]\n[paths.'app/./']\n";
    assert!(matches!(
        PolicyDocument::from_toml_str(duplicates),
        Err(PolicyParseError::DuplicatePathScope { path }) if path == "app"
    ));
    let document = PolicyDocument::from_toml_str("schema_version=1\n[paths.app]")?;
    let root = Path::new("project");
    for relative in ["/app/sub", "app2/sub", "app/../app/sub", "../project/app"] {
        assert!(!document.path_scopes["app"].matches(Path::new(relative)));
        assert!(document.path_scope_for(root, &root.join(relative)).is_none());
    }
    #[cfg(windows)]
    assert!(!document.path_scopes["app"].matches(Path::new("C:app")));
    Ok(())
}

#[test]
fn shared_collisions_fail_for_direct_and_nonwinning_path_selections() {
    let command = "schema_version=1\n[commands.run]\nargv=['run']\nshared_secrets=['COLLISION']\n";
    for selection in [
        "required_secrets=['COLLISION']",
        "optional_secrets=['COLLISION']",
        "[paths.unrelated]\nrequired_secrets=['COLLISION']",
        "[paths.unrelated]\noptional_secrets=['COLLISION']",
    ] {
        let input = format!("{command}{selection}\n[paths.app]\nrequired_secrets=['SAFE']");
        assert!(matches!(
            PolicyDocument::from_toml_str(&input),
            Err(PolicyParseError::SharedAndProjectSecret { command, name })
                if command == "run" && name == "COLLISION"
        ));
    }
}

#[test]
fn public_defaults_are_subordinate_to_selection_and_secret_acl() -> Result<(), Box<dyn Error>> {
    let document = PolicyDocument::from_toml_str(
        r#"
        schema_version = 1
        [commands.run]
        argv = ["run"]
        shared_secrets = ["SHARED"]
        [paths.app]
        required_secrets = ["FEATURE"]
        [secrets.FEATURE]
        allow_commands = ["run"]
        allow_paths = ["app/allowed/**"]
        [variables.FEATURE]
        classification = "public"
        default = "fallback"
        [variables.SHARED]
        classification = "public"
        default = "cannot-fill-shared"
        "#,
    )?;
    let root = Path::new("project");
    let mut env = EnvMap::new();
    let out_of_scope =
        document.effective_command("run", root, &root.join("app2")).ok_or("missing policy")?;
    document.apply_variable_defaults(&out_of_scope, &mut env);
    assert!(env.is_empty());

    let denied = Path::new("app/denied");
    let policy =
        document.effective_command("run", root, &root.join(denied)).ok_or("missing policy")?;
    let rejected = document.denied_secrets("run", None, denied, &policy.allowed_secrets);
    assert_eq!(rejected.iter().map(|name| name.as_str()).collect::<Vec<_>>(), ["FEATURE"]);

    let allowed = Path::new("app/allowed/sub");
    assert_eq!(
        document.denied_secrets("run", None, allowed, &policy.allowed_secrets),
        Vec::<&SecretName>::new()
    );
    document.apply_variable_defaults(&policy, &mut env);
    assert_eq!(env, EnvMap::from([("FEATURE".into(), env_value("fallback"))]));
    env.insert("FEATURE".into(), env_value("provided"));
    document.apply_variable_defaults(&policy, &mut env);
    assert_eq!(env, EnvMap::from([("FEATURE".into(), env_value("provided"))]));
    Ok(())
}

#[test]
fn canonical_alias_vectors_separate_all_six_kinds() {
    // These digests use the Lean canonicalInput field framing and the Rust SHA-256 display hash.
    let id = "same|id\0é";
    let vectors = [
        ("project", "47bd1ae4"),
        ("profile", "fd8eb898"),
        ("policy", "8b8a88d8"),
        ("device", "96ea64cc"),
        ("member", "4bc68d9f"),
        ("secret", "4790c2d5"),
    ];
    let mut digests = BTreeSet::new();
    for (kind, digest) in vectors {
        let alias = privacy_alias(kind, id);
        assert_eq!(alias, format!("{kind}-{digest}"));
        assert!(digests.insert(alias[kind.len() + 1..].to_owned()));
    }
}

#[test]
fn privacy_projection_preserves_labels_when_only_display_names_change() -> Result<(), Box<dyn Error>>
{
    let input = "schema_version=1\nproject_id='lk_proj_same'\nname='DISPLAY_CANARY'\ndefault_profile='dev'\n";
    let original: ProjectConfig = toml::from_str(input)?;
    let renamed: ProjectConfig = toml::from_str(&input.replace("DISPLAY_CANARY", "renamed"))?;
    assert_ne!(original.name, renamed.name);
    assert_eq!(
        privacy_alias("project", original.project_id.as_str()),
        privacy_alias("project", renamed.project_id.as_str()),
    );
    // A label with no opaque ID uses the name as the canonical hash input.
    assert_ne!(privacy_alias("secret", &original.name), privacy_alias("secret", &renamed.name));
    Ok(())
}

#[test]
fn audit_rows_and_team_signatures_use_their_lean_domains() -> Result<(), Box<dyn Error>> {
    let encoded = audit_hmac_v1_bytes(&AuditHmacInput {
        schema_version: 1,
        sequence: 1,
        timestamp: Timestamp::from_unix_nanos(1),
        project_id: Some("project"),
        profile_id: None,
        action: "IMPORT",
        status: "SUCCESS",
        metadata_json: None,
        previous_hmac: None,
    })?;
    assert!(encoded.starts_with(b"locket-audit-v1"));

    let key = SigningKey::from_bytes(&[42; 32]);
    let device = DeviceIdentity::new("device".into(), key.verifying_key().to_bytes(), [17; 32]);
    let signed = SignedStatement::sign(
        &TeamStatement {
            v: 1,
            team_id: "team".into(),
            project_id: "project".into(),
            epoch: 1,
            previous_digest: String::new(),
            issued_at: 1,
            expires_at: 2,
            nonce: [0; 24],
            publisher: device.clone(),
            recipient: device,
            members: vec![],
            profiles: vec![],
        },
        &key,
    )?;
    let signature = Signature::from_slice(&BASE64URL_NOPAD.decode(signed.signature.as_bytes())?)?;
    let message = [b"locket-team-state-v1\0".as_slice(), &signed.statement].concat();
    key.verifying_key().verify_strict(&message, &signature)?;
    Ok(())
}
