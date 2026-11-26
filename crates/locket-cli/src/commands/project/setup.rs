//! Metadata-only setup guidance for local development flows.

use std::io::{self, IsTerminal, Write};

use locket_core::LocketError;

use super::detect::detect_development_argv;

use crate::{
    CliError, LOCKET_TOML, RuntimeContext, SetupCommand, read_policy_document, resolve_project,
};

pub fn setup_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: Option<SetupCommand>,
) -> Result<(), CliError> {
    if command.is_none()
        && io::stdin().is_terminal()
        && !crate::runtime::prompts::prompts_disabled()
    {
        offer_interactive_setup(context, output)?;
    }
    match command.unwrap_or(SetupCommand::Status) {
        SetupCommand::Status => setup_status(context, output),
        SetupCommand::Agent => setup_agent(output),
        SetupCommand::Share => setup_share(output),
    }
}

fn setup_status(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let Some(resolved) = resolve_project(&context.cwd)? else {
        writeln!(output, "setup: new_project")?;
        writeln!(output, "metadata_only: yes")?;
        writeln!(output, "next_actions:")?;
        writeln!(output, "- locket init --name <name> --profile dev")?;
        writeln!(output, "- locket import .env")?;
        writeln!(output, "- locket policy add dev -- <command>")?;
        writeln!(output, "- locket setup agent")?;
        return Ok(());
    };

    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    writeln!(output, "setup: local_development")?;
    writeln!(output, "project: {}", resolved.config.name)?;
    writeln!(output, "profile: {}", resolved.config.default_profile)?;
    writeln!(output, "policies: {}", policy_document.commands.len())?;
    writeln!(output, "metadata_only: yes")?;
    let store = crate::open_store(context)?;
    let profile = store.get_profile_by_name(
        resolved.config.project_id.as_str(),
        resolved.config.default_profile.as_str(),
    )?;
    let next = if store.get_project(resolved.config.project_id.as_str())?.is_none()
        || profile.is_none()
    {
        "locket init".to_owned()
    } else if !store.project_root_is_trusted(
        resolved.config.project_id.as_str(),
        &crate::root_hash(&resolved.root)?,
    )? {
        "locket project trust-root".to_owned()
    } else if let Some(profile) = profile.as_ref() {
        let names = crate::active_profile_secret_names(
            &store,
            resolved.config.project_id.as_str(),
            &profile.id,
        )?;
        if names.is_empty() && resolved.root.join(".env").exists() {
            "locket import .env".to_owned()
        } else if policy_document.commands.is_empty() {
            detect_development_argv(&resolved.root).ok().flatten().map_or_else(
                || "locket policy add dev -- <command>".to_owned(),
                |argv| format!("locket run -- {}", argv.join(" ")),
            )
        } else {
            let policy = policy_document
                .commands
                .get("dev")
                .or_else(|| policy_document.commands.values().next());
            if let Some(policy) = policy {
                let effective =
                    crate::load_effective_command_policy(&resolved, &policy.name, &context.cwd)?;
                let availability = crate::effective_policy_profile(&store, &resolved, &effective)
                    .and_then(|policy_profile| {
                        crate::commands::exec::run::required_variable_availability(
                            &store,
                            &resolved,
                            &policy_profile,
                            &effective.policy,
                        )
                    });
                let Ok(availability) = availability else {
                    writeln!(output, "next_action: locket env inspect {}", policy.name)?;
                    writeln!(
                        output,
                        "availability: unverified; check local environment files and profiles"
                    )?;
                    return Ok(());
                };
                if let Some(name) = availability.missing_shared.first() {
                    format!("locket set {name} --project @shared")
                } else if let Some(name) = availability.missing.first() {
                    format!("locket set {name}")
                } else if !availability.unknown.is_empty() {
                    format!("locket env inspect {}", policy.name)
                } else {
                    format!("locket run {}", policy.name)
                }
            } else {
                "locket policy add dev -- <command>".to_owned()
            }
        }
    } else {
        "locket init".to_owned()
    };
    writeln!(output, "next_action: {next}")?;
    writeln!(output, "next_actions:")?;
    writeln!(output, "- {next}")?;
    Ok(())
}

fn setup_agent(output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "setup: agent_invite")?;
    writeln!(
        output,
        "limitation: fresh-machine invite acceptance is not yet supported; use explicit sealed export/import and verify the sender separately"
    )?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "steps:")?;
    writeln!(output, "- receiver: locket agent invite request")?;
    writeln!(
        output,
        "- maintainer: locket agent invite create <label> --device <descriptor> --profile dev --role developer --expires-in 7d"
    )?;
    writeln!(output, "- receiver_accept: locket agent invite accept -")?;
    writeln!(output, "paste_flow: request_text_then_invite_text")?;
    Ok(())
}

fn setup_share(output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "setup: share_access")?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "agent_path: locket setup agent")?;
    writeln!(
        output,
        "team_path: locket team invite <name> --device <descriptor> --profile dev --role developer"
    )?;
    writeln!(output, "bundle_path: locket export --sealed --recipient <descriptor> --profile dev")?;
    Ok(())
}

pub fn offer_interactive_setup(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    if let Err(error) = interactive_project_setup(context, output) {
        let detail = match &error {
            CliError::Typed { kind: LocketError::InvalidPolicy, .. } => {
                "Invalid project policy. Check locket.toml.".to_owned()
            }
            CliError::Store(error) => {
                format!("Vault storage failed ({:?}).", error.locket_error())
            }
            CliError::Typed { .. } | CliError::Io(_) | CliError::Crypto(_) | CliError::Time => {
                error.to_string()
            }
            _ => "vault operation failed".to_owned(),
        };
        writeln!(output, "setup_error: {}", detail.escape_debug())?;
        writeln!(
            output,
            "setup_step: skipped; initialization is intact. Run locket setup to retry, or locket import .env --literal for literal dollar expressions."
        )?;
    }
    Ok(())
}

pub fn interactive_project_setup(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let Some(resolved) = resolve_project(&context.cwd)? else {
        return Ok(());
    };
    if resolved.root.join(".env").is_file() {
        writeln!(
            output,
            "Existing .env found. Import it into the encrypted vault and keep the original file? [Y/n]"
        )?;
        output.flush()?;
        let confirmation = context.confirmation_reader.read_confirmation("import existing .env")?;
        if !confirmation.is_empty()
            && matches!(
                confirmation.trim().to_ascii_lowercase().as_str(),
                "" | "y" | "yes" | "import .env"
            )
        {
            crate::commands::secrets::import::import_selected_command(
                context,
                output,
                &crate::ImportArgs {
                    file: resolved.root.join(".env").display().to_string(),
                    profile: None,
                    source: None,
                    overwrite: false,
                    literal: false,
                },
                &crate::ImportSelectionArgs { keep: true, ..Default::default() },
            )?;
        }
    }
    let document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    if !document.commands.contains_key("dev")
        && let Some(argv) = detect_development_argv(&resolved.root)?
    {
        writeln!(output, "Development script detected. Review its command access before saving.")?;
        match crate::commands::exec::run::approve_project_command(context, output, &resolved, argv)
        {
            Ok(()) => {}
            Err(CliError::Typed { kind: LocketError::ConfirmationFailed, .. }) => {
                writeln!(output, "command: not approved")?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    fn init(context: &crate::RuntimeContext) -> Result<(), Box<dyn std::error::Error>> {
        crate::run_with_context(
            crate::Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
            context,
            &mut Vec::new(),
        )?;
        Ok(())
    }

    #[test]
    fn setup_import_confirmation_keeps_dotenv() -> Result<(), Box<dyn std::error::Error>> {
        for (confirmation, imported) in [
            ("\n", true),
            ("y\n", true),
            ("YeS\r\n", true),
            ("import .env\n", true),
            ("n\n", false),
            ("NO\n", false),
            ("maybe\n", false),
            ("", false),
        ] {
            let directory = tempfile::tempdir()?;
            let context = crate::tests::test_context_with_confirmation(&directory, confirmation);
            init(&context)?;
            let path = directory.path().join(".env");
            let contents = "API_TOKEN=onboarding-fixture\n";
            std::fs::write(&path, contents)?;
            let mut output = Vec::new();
            super::interactive_project_setup(&context, &mut output)?;
            let output = String::from_utf8(output)?;
            assert!(output.contains("[Y/n]"), "{output}");
            assert_eq!(output.contains("imported: 1"), imported, "{confirmation:?}");
            assert!(!output.contains("delete_env_prompt"));
            assert_eq!(std::fs::read_to_string(&path)?, contents);
        }
        Ok(())
    }

    #[test]
    fn setup_reports_import_error_before_retry_guidance() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let context = crate::tests::test_context_with_confirmation(&directory, "import .env\n");
        init(&context)?;
        let path = directory.path().join(".env");
        let contents = "API_TOKEN=onboarding-fixture-${BASE}\n";
        std::fs::write(&path, contents)?;
        let mut output = Vec::new();
        super::offer_interactive_setup(&context, &mut output)?;
        let output = String::from_utf8(output)?;
        let detail = output.find("setup_error: line 1:").ok_or("missing error detail")?;
        let guidance = output.find("setup_step: skipped").ok_or("missing retry guidance")?;
        assert!(detail < guidance);
        assert!(
            output[detail..guidance].contains("expansion syntax requires explicit literal mode")
        );
        assert!(output[guidance..].contains("locket import .env --literal"));
        assert!(!output.contains("onboarding-fixture"));
        assert_eq!(std::fs::read_to_string(path)?, contents);
        Ok(())
    }

    #[test]
    fn setup_detects_development_script_without_running_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"scripts":{"dev":"touch should-not-run","build":"vite build"}}"#,
        )?;
        std::fs::write(directory.path().join("pnpm-lock.yaml"), "lockfileVersion: '9.0'")?;
        assert_eq!(
            super::detect_development_argv(directory.path())?,
            Some(vec!["pnpm".to_owned(), "run".to_owned(), "dev".to_owned()])
        );
        assert!(!directory.path().join("should-not-run").exists());
        Ok(())
    }
    #[test]
    fn setup_declining_detected_command_keeps_initialization_successful()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let context = crate::tests::test_context(&directory);
        init(&context)?;
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"scripts":{"dev":"touch should-not-run"}}"#,
        )?;
        super::interactive_project_setup(&context, &mut Vec::new())?;
        let document = crate::read_policy_document(&directory.path().join("locket.toml"))?;
        assert!(document.commands.is_empty());
        assert!(!directory.path().join("should-not-run").exists());
        Ok(())
    }
}
