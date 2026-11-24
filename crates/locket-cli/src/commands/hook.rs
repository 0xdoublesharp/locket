//! Install and inspect Git hooks that invoke the Locket scanner.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use clap::Subcommand;

use crate::commands::scan::scanner::{ensure_git_worktree, git_output};
use crate::{CliError, RuntimeContext, metadata_invalid_error};

const HEADER: &str = "#!/bin/sh\n# Locket scanner hook\n";
const PRE_COMMIT: &str = "exec locket scan --staged --known-if-unlocked\n";
const PRE_PUSH: &str = "exec locket hook scan-push\n";

#[derive(Clone, Copy, Debug, Subcommand)]
pub enum HookCommand {
    /// Install the pre-commit hook by default, or select hooks explicitly.
    Install {
        #[arg(long)]
        pre_commit: bool,
        #[arg(long)]
        pre_push: bool,
        #[arg(long)]
        force: bool,
    },
    /// Show the installed scanner hooks.
    Status,
    #[command(hide = true)]
    ScanPush,
}

pub fn hook_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: HookCommand,
) -> Result<(), CliError> {
    let root = ensure_git_worktree(&context.cwd)?;
    if matches!(command, HookCommand::ScanPush) {
        return crate::commands::scan::scanner::scan_push(
            context,
            output,
            &root,
            &mut io::stdin().lock(),
        );
    }
    let hooks = git_path(&root, "--git-path", Some("hooks"))?;
    let default_hooks = git_path(&root, "--git-common-dir", None)?.join("hooks");
    if hooks != default_hooks {
        return Err(metadata_invalid_error(
            "custom core.hooksPath is configured; automatic installation requires the repository Git hooks directory",
        ));
    }
    let scripts = [("pre-commit", PRE_COMMIT), ("pre-push", PRE_PUSH)];
    if let HookCommand::Install { pre_commit, pre_push, force } = command {
        let selected = [pre_commit || !pre_push, pre_push];
        for ((name, script), _) in scripts.iter().zip(selected).filter(|(_, install)| *install) {
            if hook_status(&hooks.join(name), script)? == HookStatus::Unrelated && !force {
                return Err(metadata_invalid_error(format!(
                    "existing {name} hook is unmanaged; use --force to replace it"
                )));
            }
        }
        fs::create_dir_all(&hooks)?;
        for ((name, script), _) in scripts.iter().zip(selected).filter(|(_, install)| *install) {
            install_hook(&hooks.join(name), script, force)?;
            writeln!(output, "installed {name}")?;
        }
    } else {
        for (name, script) in scripts {
            let status = hook_status(&hooks.join(name), script)?;
            writeln!(output, "{name}: {}", status.as_str())?;
        }
    }
    Ok(())
}

fn git_path(
    root: &Path,
    option: &str,
    argument: Option<&str>,
) -> Result<std::path::PathBuf, CliError> {
    let args = ["rev-parse", "--path-format=absolute", option].into_iter().chain(argument);
    let path = git_output(root, args)?;
    let path = std::str::from_utf8(&path)
        .map_err(|_| metadata_invalid_error("invalid Git hooks directory"))?;
    Ok(root.join(path.trim_end_matches(['\n', '\r'])))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HookStatus {
    Missing,
    Managed,
    Unrelated,
}

impl HookStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Managed => "installed",
            Self::Unrelated => "unmanaged",
        }
    }
}

fn hook_status(path: &Path, script: &str) -> Result<HookStatus, CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file() && metadata.len() == (HEADER.len() + script.len()) as u64 =>
        {
            let contents = fs::read(path)?;
            if contents.strip_prefix(HEADER.as_bytes()) == Some(script.as_bytes()) {
                return Ok(HookStatus::Managed);
            }
            Ok(HookStatus::Unrelated)
        }
        Ok(_) => Ok(HookStatus::Unrelated),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(HookStatus::Missing),
        Err(error) => Err(error.into()),
    }
}

fn install_hook(path: &Path, script: &str, force: bool) -> Result<(), CliError> {
    let parent =
        path.parent().ok_or_else(|| metadata_invalid_error("Git hooks directory is missing"))?;
    let mut new_hook = tempfile::NamedTempFile::new_in(parent)?;
    write!(new_hook, "{HEADER}{script}")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        new_hook.as_file().set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    match hook_status(path, script)? {
        HookStatus::Missing => new_hook.persist_noclobber(path).map_err(|error| error.error)?,
        HookStatus::Managed => new_hook.persist(path).map_err(|error| error.error)?,
        HookStatus::Unrelated if force => new_hook.persist(path).map_err(|error| error.error)?,
        HookStatus::Unrelated => return Err(metadata_invalid_error("Git hook is unmanaged")),
    };
    Ok(())
}
