#[allow(unused_imports)]
use super::*;

fn contract_fixture(
    directory: &tempfile::TempDir,
    body: &str,
) -> Result<RuntimeContext, Box<dyn std::error::Error>> {
    let context = test_context(directory);
    fs::create_dir_all(&context.cwd)?;
    fs::write(
        context.cwd.join("locket.toml"),
        format!(
            "schema_version=1\nproject_id='lk_proj_contract_test'\nname='Synthetic fixture'\ndefault_profile='dev'\n{body}"
        ),
    )?;
    Ok(context)
}

#[test]
fn configuration_contract_offline_validate_never_opens_store_or_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = contract_fixture(
        &directory,
        r"
[commands.dev]
argv=['not-a-real-project-command']
required_secrets=['DATABASE_URL','NEXT_PUBLIC_API_URL']
external_env_sources=['compose','ide',{file='file-that-does-not-exist'}]
[variables.DATABASE_URL]
setup_hint='Ask the developer for a local database'
[variables.NEXT_PUBLIC_API_URL]
classification='public'
type='url'
default='http://localhost:3001/canary-public-value'
",
    )?;
    let args = Cli::try_parse_from([
        "locket",
        "env",
        "validate",
        "--policy",
        "dev",
        "--provided-name",
        "DATABASE_URL",
        "--json",
    ])?;
    let mut output = Vec::new();
    run_with_context(args, &context, &mut output)?;
    let text = String::from_utf8(output)?;
    let json: serde_json::Value = serde_json::from_str(&text)?;
    assert_eq!(json["values_checked"], false);
    assert_eq!(json["mode"], "names-only");
    assert_eq!(json["ready"], true);
    assert!(!text.contains("canary-public-value"));
    assert!(!context.store_path.exists());
    Ok(())
}

#[test]
fn configuration_contract_offline_missing_and_scope_acl() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let mut context = contract_fixture(
        &directory,
        r"
[commands.dev]
argv=['not-a-real-command']
required_secrets=['DATABASE_URL']
optional_secrets=['NEXT_PUBLIC_TOKEN']
[variables.DATABASE_URL]
description='Local database'
setup_hint='Ask your teammate'
[variables.PORT]
classification='public'
default='3001'
[paths.'apps/api']
required_secrets=['PORT']
[secrets.DATABASE_URL]
allow_paths=['apps/api/**']
",
    )?;
    fs::create_dir_all(context.cwd.join("apps/api"))?;
    context.cwd = context.cwd.join("apps/api");
    let mut output = Vec::new();
    let error = run_with_context(
        Cli::try_parse_from(["locket", "env", "validate", "--policy", "dev", "--json"])?,
        &context,
        &mut output,
    )
    .err()
    .ok_or("missing required must fail")?;
    assert_eq!(error.exit_code(), 1);
    let text = String::from_utf8(output)?;
    assert!(text.contains("locket set DATABASE_URL"));
    assert!(text.contains("Ask your teammate"));
    assert!(text.contains("browser bundles"));
    assert!(text.contains("public-default"));
    context.cwd = context.cwd.parent().ok_or("parent")?.join("web");
    fs::create_dir_all(&context.cwd)?;
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "env",
            "validate",
            "--policy",
            "dev",
            "--provided-name",
            "DATABASE_URL",
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert!(result.is_err());
    Ok(())
}

#[test]
fn configuration_contract_synthetic_framework_shapes_do_not_execute_scripts()
-> Result<(), Box<dyn std::error::Error>> {
    // These fixtures validate project shapes and contracts. They do not run frameworks.
    for (manifest, contents, public_name) in [
        (
            "package.json",
            r#"{"dependencies":{"next":"synthetic"},"scripts":{"dev":"never-run-this-command"}}"#,
            "NEXT_PUBLIC_API_URL",
        ),
        (
            "package.json",
            r#"{"devDependencies":{"vite":"synthetic"},"scripts":{"dev":"never-run-this-command"}}"#,
            "VITE_API_URL",
        ),
        ("pyproject.toml", "[project]\nname='synthetic-python'", "API_URL"),
        ("Cargo.toml", "[package]\nname='synthetic-rust'\nversion='0.0.0'", "API_URL"),
    ] {
        let directory = tempdir()?;
        let context = contract_fixture(
            &directory,
            &format!(
                "[commands.dev]\nargv=['never-run-this-command']\nrequired_secrets=['{public_name}','TOKEN']\n[variables.{public_name}]\nclassification='public'\ntype='url'\ndefault='http://localhost:3001/fixture-canary'"
            ),
        )?;
        fs::write(context.cwd.join(manifest), contents)?;
        let mut output = Vec::new();
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "env",
                "validate",
                "--policy",
                "dev",
                "--provided-name",
                "TOKEN",
                "--json",
            ])?,
            &context,
            &mut output,
        )?;
        let text = String::from_utf8(output)?;
        assert!(text.contains("\"ready\":true"));
        assert!(!text.contains("fixture-canary"));
        assert!(!context.store_path.exists());
    }
    Ok(())
}

#[test]
fn configuration_contract_offline_invalid_is_redacted_with_exit_two()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = contract_fixture(
        &directory,
        "[commands.dev]\nargv=['never-run']\n[variables.TOKEN]\ndefault='secret-canary-do-not-print'",
    )?;
    let mut output = Vec::new();
    let error = run_with_context(
        Cli::try_parse_from(["locket", "env", "validate", "--policy", "dev", "--json"])?,
        &context,
        &mut output,
    )
    .err()
    .ok_or("secret default must fail")?;
    assert_eq!(error.exit_code(), 2);
    assert!(!error.to_string().contains("secret-canary"));
    assert!(!String::from_utf8(output)?.contains("secret-canary"));
    Ok(())
}

#[test]
fn configuration_contract_docker_and_compose_plans_include_only_authorized_defaults()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "fixture", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let path = context.cwd.join("locket.toml");
    let mut text = fs::read_to_string(&path)?;
    text.push_str("\n[commands.container]\nargv=['docker','run','synthetic-image']\nrequired_secrets=['PORT']\ninherit_env=['PORT']\n[variables.PORT]\nclassification='public'\ntype='integer'\ndefault='3001'\n[variables.UNAUTHORIZED]\nclassification='public'\ndefault='canary-not-in-container'\n");
    fs::write(path, text)?;
    for compose in [false, true] {
        let argv = if compose {
            vec!["docker".into(), "compose".into(), "up".into()]
        } else {
            vec!["docker".into(), "run".into(), "synthetic-image".into()]
        };
        let prepare = if compose {
            crate::commands::exec::docker::prepare_compose_policy_execution
        } else {
            crate::commands::exec::docker::prepare_docker_policy_execution
        };
        let prepared = prepare(&context, "container", &argv, locket_exec::EnvMap::new())?;
        assert_eq!(prepared.plan.injected_names, vec!["PORT"]);
        assert_eq!(prepared.execution.env["PORT"].as_str(), "3001");
        assert!(!prepared.execution.env.contains_key("UNAUTHORIZED"));
        // An explicitly inherited value wins over the fallback without a conflict.
        let parent =
            locket_exec::EnvMap::from_iter([("PORT".into(), locket_exec::env_value("4000"))]);
        let inherited = prepare(&context, "container", &argv, parent)?;
        assert_eq!(inherited.execution.env["PORT"].as_str(), "4000");
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn configuration_contract_exec_validates_before_spawning_child()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "fixture", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    crate::set_secret_value(
        &context,
        &test_secret_write_args("PORT"),
        "secret-canary-not-integer",
        "manual",
        1_000,
    )?;
    let path = context.cwd.join("locket.toml");
    let text = fs::read_to_string(&path)?;
    fs::write(path, format!("{text}\n[variables.PORT]\ntype='integer'\n"))?;
    let marker = context.cwd.join("child-must-not-start");
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--secret",
            "PORT",
            "--",
            "/usr/bin/touch",
            marker.to_str().ok_or("marker")?,
        ])?,
        &context,
        &mut output,
    );
    let Err(error) = result else {
        return Err("invalid value must prevent spawn".into());
    };
    assert!(error.to_string().contains("PORT"));
    assert!(!error.to_string().contains("secret-canary"));
    assert!(!String::from_utf8(output)?.contains("secret-canary"));
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn configuration_contract_absent_vault_public_default_cannot_bypass_secret_acl()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = contract_fixture(
        &directory,
        r"
[commands.denied]
argv=['never-run']
required_secrets=['PUBLIC_URL']
[commands.allowed]
argv=['never-run']
required_secrets=['PUBLIC_URL']
[variables.PUBLIC_URL]
classification='public'
default='https://localhost/public-default-canary'
[secrets.PUBLIC_URL]
allow_commands=['allowed']
",
    )?;
    let resolved = crate::require_project(&context)?;
    assert!(crate::load_effective_command_policy(&resolved, "denied", &context.cwd).is_err());
    let allowed = crate::load_effective_command_policy(&resolved, "allowed", &context.cwd)?.policy;
    let mut child = locket_exec::EnvMap::new();
    crate::commands::exec::run::finalize_configuration_environment(
        &resolved, &allowed, &mut child,
    )?;
    assert!(child.contains_key("PUBLIC_URL"));
    let mut output = Vec::new();
    let error = run_with_context(
        Cli::try_parse_from(["locket", "env", "validate", "--policy", "denied", "--json"])?,
        &context,
        &mut output,
    )
    .err()
    .ok_or("ACL denial must precede fallback")?;
    assert_eq!(error.exit_code(), 2);
    assert!(!String::from_utf8(output)?.contains("public-default-canary"));
    assert!(!context.store_path.exists());
    Ok(())
}

#[test]
fn env_inspect_explains_external_conflicts_scoped_names_and_public_defaults()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "inspect-synthetic-vault-canary");
    let run = |ctx: &RuntimeContext, args: &[&str]| -> Result<String, Box<dyn std::error::Error>> {
        let mut output = Vec::new();
        let code = run_with_context(Cli::try_parse_from(args)?, ctx, &mut output)?;
        assert_eq!(code, 0);
        let output = String::from_utf8(output)?;
        for value in [
            "inspect-synthetic-vault-canary",
            "inspect-synthetic-env-canary",
            "inspect-synthetic-public-default",
        ] {
            assert!(!output.contains(value));
        }
        Ok(output)
    };
    run(&context, &["locket", "init", "--name", "app", "--no-device", "--no-passkey"])?;
    run(&context, &["locket", "profile", "create", "staging"])?;
    run(
        &context,
        &["locket", "set", "APP_TOKEN", "--source", "user-local", "--profile", "staging"],
    )?;
    run(
        &context,
        &["locket", "set", "APP_TOKEN", "--source", "machine-local", "--profile", "staging"],
    )?;
    fs::write(context.cwd.join(".env.dev"), "APP_TOKEN=inspect-synthetic-env-canary\n")?;
    let child_dir = context.cwd.join("apps/api");
    fs::create_dir_all(&child_dir)?;
    let path = context.cwd.join("locket.toml");
    let base = fs::read_to_string(&path)?;
    let scoped = RuntimeContext { cwd: child_dir, ..context.clone() };
    for (mode, decision) in [
        ("error", "error-conflict"),
        ("preserve", "preserve-existing"),
        ("locket", "inject-overwrite"),
    ] {
        let document = format!(
            r"{base}
[commands.dev]
argv = ['never-run']
required_secrets = ['APP_TOKEN', 'PUBLIC_MODE']
optional_secrets = ['OPTIONAL_TOKEN']
shared_secrets = ['SHARED_SERVICE_KEY']
override = '{mode}'
external_env_sources = [{{file = '.env.dev'}}]

[paths.'apps/api']
profile = 'staging'
optional_secrets = ['SCOPED_NAME']

[variables.PUBLIC_MODE]
classification = 'public'
default = 'inspect-synthetic-public-default'
description = 'Public display mode'
setup_hint = 'Choose an app mode'
"
        );
        fs::write(&path, document)?;
        let report = run(&scoped, &["locket", "env", "inspect", "--policy", "dev"])?;
        let scope_line = format!("path_scope={}", Path::new("apps").join("api").display());
        assert!(report.contains(&scope_line));
        assert!(report.contains("path_scope_profile=staging"));
        assert!(report.contains("Public display mode"));
        assert!(report.contains("Choose an app mode"));
        assert!(report.lines().any(|line| {
            line.starts_with("secret APP_TOKEN ")
                && line.contains("conflicts=multiple-active-sources,external-source")
                && line.ends_with(decision)
        }));
        for (name, decision) in [
            ("PUBLIC_MODE", "public-default"),
            ("SHARED_SERVICE_KEY", "missing-required"),
            ("SCOPED_NAME", "skip-missing"),
        ] {
            assert!(report.lines().any(
                |line| line.starts_with(&format!("secret {name} ")) && line.ends_with(decision)
            ));
        }
    }
    assert!(!context.cwd.join("never-run").exists());
    Ok(())
}
