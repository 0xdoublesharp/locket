use locket_core::{CommandPolicy, CommandSpec, LocketError};
use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, Store};
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;

use crate::{
    CliError, EXAMPLE_FILE, HOOK_BEGIN, HOOK_END, LOCKET_TOML, ResolvedProject, RuntimeContext,
    git_dir_for_worktree, load_project_key, metadata_invalid_error, now_unix_nanos, open_store,
    read_policy_document, require_project, root_hash, yes_no,
};

pub fn bootstrap_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let report = collect_bootstrap_report(context, &resolved, &store)?;
    write_bootstrap_report(output, &report)?;
    write_bootstrap_audit_if_available(context, &mut store, &resolved, &report)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HookState {
    Installed,
    Unmanaged,
    Missing,
    NotGitRepo,
}

impl HookState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Unmanaged => "unmanaged",
            Self::Missing => "missing",
            Self::NotGitRepo => "not_git_repo",
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
struct BootstrapReport {
    project_name: String,
    project_id: String,
    profile_name: String,
    project_in_store: bool,
    profile_ready: bool,
    profile_unlocked: Option<bool>,
    trusted_root: bool,
    agent_running: bool,
    missing_variables: Vec<String>,
    unverified_variables: Vec<String>,
    unverified_commands: Vec<String>,
    run_policy: Option<String>,
    example_exists: bool,
    hook_state: HookState,
    policy_count: usize,
    smoke_policy: Option<String>,
    smoke_policy_present: bool,
    tools_checked: usize,
    missing_tools: Vec<String>,
    unchecked_tools: Vec<String>,
    team_status: &'static str,
}

fn collect_bootstrap_report(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    store: &Store,
) -> Result<BootstrapReport, CliError> {
    let project_id = resolved.config.project_id.as_str();
    let project = store.get_project(project_id)?;
    let profile =
        store.get_profile_by_name(project_id, resolved.config.default_profile.as_str())?;
    let root_hash = root_hash(&resolved.root)?;
    let trusted_root = store.project_root_is_trusted(project_id, &root_hash)?;
    let example_exists = resolved.root.join(EXAMPLE_FILE).exists();
    let hook_state = detect_pre_commit_hook_state(&resolved.root);
    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    let policy_count = policy_document.commands.len();
    let tool_report = check_policy_tools(&policy_document.commands.values().collect::<Vec<_>>());
    let bootstrap_settings = read_bootstrap_settings(&resolved.root.join(LOCKET_TOML))?;
    let smoke_policy = bootstrap_settings.and_then(|settings| settings.smoke_policy);
    let smoke_policy_present = smoke_policy
        .as_ref()
        .is_some_and(|name| policy_document.commands.contains_key(name.as_str()));
    let snapshot = crate::commands::agent::request_project_status_snapshot(
        &crate::agent_socket_path(context),
        resolved.config.project_id.as_str(),
    )
    .ok();
    let profile_unlocked = snapshot
        .as_ref()
        .filter(|snapshot| {
            snapshot.get("project_id").and_then(serde_json::Value::as_str) == Some(project_id)
        })
        .and_then(|snapshot| snapshot.get("lock_state"))
        .and_then(serde_json::Value::as_str)
        .and_then(|state| match state {
            "locked" => Some(false),
            "unlocked" => Some(true),
            _ => None,
        });
    let agent_running = snapshot.is_some();
    let mut missing_variables = BTreeSet::new();
    let mut unverified_variables = BTreeSet::new();
    let mut unverified_commands = Vec::new();
    if project.is_some() && profile.is_some() {
        for (name, base) in &policy_document.commands {
            let availability = crate::load_effective_command_policy(resolved, name, &context.cwd)
                .and_then(|effective| {
                    let policy_profile =
                        crate::effective_policy_profile(store, resolved, &effective)?;
                    crate::commands::exec::run::required_variable_availability(
                        store,
                        resolved,
                        &policy_profile,
                        &effective.policy,
                    )
                });
            if let Ok(availability) = availability {
                missing_variables.extend(availability.missing);
                unverified_variables.extend(availability.unknown);
            } else {
                // Readiness is diagnostic: missing local profiles/files are
                // repair actions, never a reason to lose the whole report.
                unverified_variables
                    .extend(base.required_secrets.iter().map(|name| name.as_str().to_owned()));
                unverified_commands.push(name.clone());
            }
        }
    }
    let run_policy = policy_document
        .commands
        .get("dev")
        .or_else(|| policy_document.commands.values().next())
        .map(|policy| policy.name.clone());
    let team_status =
        if store.get_team_by_project(project_id)?.is_some() { "team" } else { "solo" };

    Ok(BootstrapReport {
        project_name: resolved.config.name.clone(),
        project_id: project_id.to_owned(),
        profile_name: resolved.config.default_profile.to_string(),
        project_in_store: project.is_some(),
        profile_ready: profile.is_some(),
        profile_unlocked,
        trusted_root,
        agent_running,
        missing_variables: missing_variables.into_iter().collect(),
        unverified_variables: unverified_variables.into_iter().collect(),
        unverified_commands,
        run_policy,
        example_exists,
        hook_state,
        policy_count,
        smoke_policy,
        smoke_policy_present,
        tools_checked: tool_report.checked,
        missing_tools: tool_report.missing,
        unchecked_tools: tool_report.unchecked,
        team_status,
    })
}

fn write_bootstrap_report(
    output: &mut impl Write,
    report: &BootstrapReport,
) -> Result<(), CliError> {
    writeln!(output, "project: {}", report.project_name)?;
    writeln!(output, "project_id: {}", report.project_id)?;
    writeln!(output, "profile: {}", report.profile_name)?;
    writeln!(output, "profile_ready: {}", yes_no(report.profile_ready))?;
    writeln!(output, "profile_unlocked: {}", report.profile_unlocked.map_or("unknown", yes_no))?;
    writeln!(output, "store_project: {}", yes_no(report.project_in_store))?;
    writeln!(output, "agent_running: {}", yes_no(report.agent_running))?;
    writeln!(
        output,
        "missing_variables: {}",
        if report.missing_variables.is_empty() {
            "none".to_owned()
        } else {
            report.missing_variables.join(",")
        }
    )?;
    writeln!(
        output,
        "unverified_variables: {}",
        if report.unverified_variables.is_empty() {
            "none".to_owned()
        } else {
            report.unverified_variables.join(",")
        }
    )?;
    writeln!(output, ".env.example: {}", yes_no(report.example_exists))?;
    writeln!(output, "trusted_root: {}", yes_no(report.trusted_root))?;
    writeln!(output, "pre_commit_hook: {}", report.hook_state.as_str())?;
    writeln!(output, "team: {}", report.team_status)?;
    writeln!(output, "policies: {}", report.policy_count)?;
    write_tool_report(output, report)?;
    match &report.smoke_policy {
        Some(name) if report.smoke_policy_present => {
            writeln!(output, "smoke_policy: configured ({name})")?;
        }
        Some(name) => writeln!(output, "smoke_policy: missing ({name})")?,
        None => writeln!(output, "smoke_policy: none")?,
    }
    writeln!(output, "metadata_only: yes")?;
    let actions = bootstrap_next_actions(report);
    writeln!(output, "next_action: {}", actions.first().map_or("none", String::as_str))?;
    writeln!(output, "next_actions:")?;
    if actions.is_empty() {
        writeln!(output, "- none")?;
    } else {
        for action in actions {
            writeln!(output, "- {action}")?;
        }
    }
    Ok(())
}

fn bootstrap_next_actions(report: &BootstrapReport) -> Vec<String> {
    let mut actions = Vec::new();
    if !report.project_in_store || !report.profile_ready {
        actions.push("run locket init to resume local metadata setup".to_owned());
    }
    if report.profile_ready && report.profile_unlocked == Some(false) {
        actions.push("run locket unlock for the active profile".to_owned());
    }
    if !report.agent_running {
        actions.push("run locket agent start".to_owned());
    }
    if !report.example_exists {
        actions.push("run locket emit-example".to_owned());
    }
    if !report.trusted_root {
        actions.push("run locket project trust-root".to_owned());
    }
    if matches!(report.hook_state, HookState::Missing | HookState::Unmanaged) {
        actions.push("run locket install-hooks".to_owned());
    }
    if let Some(name) = &report.smoke_policy
        && !report.smoke_policy_present
    {
        actions.push(format!("run locket policy add {name}"));
    }
    if !report.missing_tools.is_empty() {
        actions.push(format!("install missing tool(s): {}", report.missing_tools.join(", ")));
    }
    if !report.missing_variables.is_empty() {
        for name in &report.missing_variables {
            actions.push(format!("run locket set {name}"));
        }
    }
    for name in &report.unverified_commands {
        actions.push(format!("run locket env inspect {name} to check local files and profiles"));
    }
    if !report.unverified_variables.is_empty()
        && let Some(name) = &report.run_policy
    {
        actions.push(format!("run locket env inspect {name}"));
    }
    if actions.is_empty() {
        if let Some(name) = &report.run_policy {
            actions.push(format!("run locket run {name}"));
        } else {
            actions.push("run locket setup".to_owned());
        }
    }
    actions
}

#[derive(Debug, Default)]
struct ToolReport {
    checked: usize,
    missing: Vec<String>,
    unchecked: Vec<String>,
}

fn check_policy_tools(policies: &[&CommandPolicy]) -> ToolReport {
    let mut checked = BTreeSet::new();
    let mut missing = BTreeSet::new();
    let mut unchecked = BTreeSet::new();

    for policy in policies {
        match &policy.command {
            CommandSpec::Argv(argv) => {
                let Some(program) = argv.first() else {
                    continue;
                };
                checked.insert(program.clone());
                if !tool_is_present(program) {
                    missing.insert(program.clone());
                }
            }
            CommandSpec::Shell(script) => {
                let shell_tools = collect_shell_tools(script);
                for program in shell_tools.programs {
                    checked.insert(program.clone());
                    if !tool_is_present(&program) {
                        missing.insert(program);
                    }
                }
                for reason in shell_tools.unchecked {
                    unchecked.insert(format!("shell:{reason}"));
                }
            }
        }
    }

    ToolReport {
        checked: checked.len(),
        missing: missing.into_iter().collect(),
        unchecked: unchecked.into_iter().collect(),
    }
}

fn tool_is_present(program: &str) -> bool {
    let program_path = Path::new(program);
    if program_path.components().count() > 1 || program_path.is_absolute() {
        return program_path.is_file();
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        if dir.join(program).is_file() {
            return true;
        }
        #[cfg(windows)]
        {
            if Path::new(program).extension().is_some() {
                return false;
            }
            let pathext = std::env::var_os("PATHEXT")
                .unwrap_or_else(|| std::ffi::OsString::from(".COM;.EXE;.BAT;.CMD"));
            pathext.to_string_lossy().split(';').any(|extension| {
                !extension.is_empty() && dir.join(format!("{program}{extension}")).is_file()
            })
        }
        #[cfg(not(windows))]
        {
            false
        }
    })
}

#[derive(Debug, Default)]
struct ShellToolReport {
    programs: BTreeSet<String>,
    unchecked: BTreeSet<&'static str>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ShellToken {
    Word { text: String, has_expansion: bool },
    Separator,
    Redirection,
    Compound,
}

fn collect_shell_tools(script: &str) -> ShellToolReport {
    let tokens = tokenize_shell_script(script);
    let mut report = ShellToolReport::default();
    let mut at_command = true;
    let mut skip_redirection_operand = false;

    for token in tokens {
        match token {
            ShellToken::Separator => {
                at_command = true;
                skip_redirection_operand = false;
            }
            ShellToken::Redirection => {
                skip_redirection_operand = true;
            }
            ShellToken::Compound => {
                report.unchecked.insert("compound");
                at_command = true;
                skip_redirection_operand = false;
            }
            ShellToken::Word { text, has_expansion } => {
                if skip_redirection_operand {
                    skip_redirection_operand = false;
                    continue;
                }
                if !at_command {
                    continue;
                }
                if is_shell_assignment(&text) {
                    if has_expansion {
                        report.unchecked.insert("dynamic");
                    }
                    continue;
                }
                if has_expansion || text.is_empty() {
                    report.unchecked.insert("dynamic");
                    at_command = false;
                    continue;
                }
                if is_shell_keyword(&text) {
                    report.unchecked.insert("compound");
                    at_command = false;
                    continue;
                }
                if is_shell_builtin(&text) {
                    at_command = false;
                    continue;
                }
                report.programs.insert(text);
                at_command = false;
            }
        }
    }

    report
}

fn tokenize_shell_script(script: &str) -> Vec<ShellToken> {
    let chars = script.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut at_word_boundary = true;

    while index < chars.len() {
        let ch = chars[index];
        if ch.is_ascii_whitespace() {
            if ch == '\n' {
                tokens.push(ShellToken::Separator);
            }
            index += 1;
            at_word_boundary = true;
            continue;
        }
        if ch == '#' && at_word_boundary {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if ch == '&' && chars.get(index + 1) == Some(&'&') {
            tokens.push(ShellToken::Separator);
            index += 2;
            at_word_boundary = true;
            continue;
        }
        if ch == '|' {
            tokens.push(ShellToken::Separator);
            index += if chars.get(index + 1) == Some(&'|') { 2 } else { 1 };
            at_word_boundary = true;
            continue;
        }
        if ch == ';' || ch == '&' {
            tokens.push(ShellToken::Separator);
            index += 1;
            at_word_boundary = true;
            continue;
        }
        if ch == '(' || ch == ')' || ch == '{' || ch == '}' {
            tokens.push(ShellToken::Compound);
            index += 1;
            at_word_boundary = true;
            continue;
        }
        if is_redirection_at(&chars, index) {
            tokens.push(ShellToken::Redirection);
            index = consume_redirection(&chars, index);
            at_word_boundary = true;
            continue;
        }

        let (word, has_expansion, next_index) = consume_shell_word(&chars, index);
        tokens.push(ShellToken::Word { text: word, has_expansion });
        index = next_index;
        at_word_boundary = false;
    }

    tokens
}

fn consume_shell_word(chars: &[char], start: usize) -> (String, bool, usize) {
    let mut word = String::new();
    let mut has_expansion = false;
    let mut index = start;

    while index < chars.len() {
        let ch = chars[index];
        if ch.is_ascii_whitespace()
            || ch == ';'
            || ch == '&'
            || ch == '|'
            || ch == '('
            || ch == ')'
            || ch == '<'
            || ch == '>'
        {
            break;
        }
        match ch {
            '\'' => {
                index += 1;
                while index < chars.len() && chars[index] != '\'' {
                    word.push(chars[index]);
                    index += 1;
                }
                if index < chars.len() {
                    index += 1;
                }
            }
            '"' => {
                index += 1;
                while index < chars.len() && chars[index] != '"' {
                    match chars[index] {
                        '\\' if index + 1 < chars.len() => {
                            index += 1;
                            word.push(chars[index]);
                            index += 1;
                        }
                        '$' | '`' => {
                            has_expansion = true;
                            word.push(chars[index]);
                            index += 1;
                        }
                        other => {
                            word.push(other);
                            index += 1;
                        }
                    }
                }
                if index < chars.len() {
                    index += 1;
                }
            }
            '\\' if index + 1 < chars.len() => {
                index += 1;
                word.push(chars[index]);
                index += 1;
            }
            '$' | '`' => {
                has_expansion = true;
                word.push(ch);
                index += 1;
            }
            other => {
                word.push(other);
                index += 1;
            }
        }
    }

    (word, has_expansion, index)
}

fn is_redirection_at(chars: &[char], index: usize) -> bool {
    let ch = chars[index];
    if ch == '<' || ch == '>' {
        return true;
    }
    if ch.is_ascii_digit() {
        let mut cursor = index;
        while cursor < chars.len() && chars[cursor].is_ascii_digit() {
            cursor += 1;
        }
        return matches!(chars.get(cursor), Some('<' | '>'));
    }
    false
}

const fn consume_redirection(chars: &[char], index: usize) -> usize {
    let mut cursor = index;
    while cursor < chars.len() && chars[cursor].is_ascii_digit() {
        cursor += 1;
    }
    if cursor < chars.len() && (chars[cursor] == '<' || chars[cursor] == '>') {
        cursor += 1;
    }
    if cursor < chars.len()
        && (chars[cursor] == '<' || chars[cursor] == '>' || chars[cursor] == '&')
    {
        cursor += 1;
    }
    cursor
}

fn is_shell_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_shell_keyword(word: &str) -> bool {
    matches!(
        word,
        "!" | "[["
            | "case"
            | "do"
            | "done"
            | "elif"
            | "else"
            | "esac"
            | "fi"
            | "for"
            | "function"
            | "if"
            | "in"
            | "select"
            | "then"
            | "until"
            | "while"
    )
}

fn is_shell_builtin(word: &str) -> bool {
    matches!(
        word,
        "." | ":"
            | "["
            | "alias"
            | "bg"
            | "break"
            | "cd"
            | "command"
            | "continue"
            | "declare"
            | "dirs"
            | "disown"
            | "echo"
            | "eval"
            | "exec"
            | "exit"
            | "export"
            | "fc"
            | "fg"
            | "getopts"
            | "hash"
            | "help"
            | "history"
            | "jobs"
            | "kill"
            | "let"
            | "local"
            | "logout"
            | "popd"
            | "printf"
            | "pushd"
            | "pwd"
            | "read"
            | "readonly"
            | "return"
            | "set"
            | "shift"
            | "shopt"
            | "source"
            | "test"
            | "times"
            | "trap"
            | "type"
            | "typeset"
            | "ulimit"
            | "umask"
            | "unalias"
            | "unset"
            | "wait"
    )
}

fn write_tool_report(output: &mut impl Write, report: &BootstrapReport) -> Result<(), CliError> {
    if report.missing_tools.is_empty() {
        writeln!(output, "tools_present: yes (checked {})", report.tools_checked)?;
    } else {
        writeln!(output, "tools_present: missing ({})", report.missing_tools.join(","))?;
    }
    if !report.unchecked_tools.is_empty() {
        writeln!(output, "tools_unchecked: {}", report.unchecked_tools.join(","))?;
    }
    Ok(())
}

fn detect_pre_commit_hook_state(root: &Path) -> HookState {
    let Ok(git_dir) = git_dir_for_worktree(root) else {
        return HookState::NotGitRepo;
    };
    let hook_path = git_dir.join("hooks").join("pre-commit");
    let Ok(content) = fs::read_to_string(&hook_path) else {
        return HookState::Missing;
    };
    if content.contains(HOOK_BEGIN) && content.contains(HOOK_END) {
        HookState::Installed
    } else {
        HookState::Unmanaged
    }
}

#[derive(Debug, Clone, Default)]
struct BootstrapSettings {
    smoke_policy: Option<String>,
}

fn read_bootstrap_settings(path: &Path) -> Result<Option<BootstrapSettings>, CliError> {
    let content = fs::read_to_string(path)?;
    let value: toml::Value = toml::from_str(&content).map_err(CliError::TomlDe)?;
    let Some(table) = value.as_table().and_then(|table| table.get("bootstrap")) else {
        return Ok(None);
    };
    let Some(table) = table.as_table() else {
        return Err(metadata_invalid_error("bootstrap settings must be a table"));
    };
    let smoke_policy = match table.get("smoke_policy") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| metadata_invalid_error("bootstrap.smoke_policy must be a string"))?
                .to_owned(),
        ),
    };
    Ok(Some(BootstrapSettings { smoke_policy }))
}

fn write_bootstrap_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    report: &BootstrapReport,
) -> Result<(), CliError> {
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key = match load_project_key(
        context,
        store,
        resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    ) {
        Ok(key) => key,
        Err(error) if error.exit_code() == LocketError::UnlockRequired.exit_code() => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let profile_id = store
        .get_profile_by_name(
            resolved.config.project_id.as_str(),
            resolved.config.default_profile.as_str(),
        )?
        .map(|profile| profile.id);
    let mut generated_files: Vec<&str> = Vec::new();
    if report.example_exists {
        generated_files.push(EXAMPLE_FILE);
    }
    if matches!(report.hook_state, HookState::Installed) {
        generated_files.push(".git/hooks/pre-commit");
    }
    let metadata = json!({
        "schema_version": 1,
        "action": "BOOTSTRAP",
        "status": "SUCCESS",
        "command": "bootstrap",
        "project_id": resolved.config.project_id.as_str(),
        "default_profile_id": profile_id,
        "generated_files": generated_files,
        "recovery_code_displayed": false,
        "team_status": report.team_status,
        "policy_count": report.policy_count,
        "smoke_policy_configured": report.smoke_policy.is_some(),
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: profile_id.as_deref(),
        action: "BOOTSTRAP",
        status: "SUCCESS",
        secret_name: None,
        command: Some("bootstrap"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

#[cfg(test)]
mod readiness_tests {
    use clap::Parser;
    #[test]
    fn fresh_clone_readiness_reports_init_instead_of_requiring_profile()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let context = crate::tests::test_context(&directory);
        std::fs::write(
            directory.path().join("locket.toml"),
            "schema_version=1\nproject_id=\"lk_proj_clone\"\nname=\"clone\"\ndefault_profile=\"dev\"\n[commands.dev]\nargv=[\"true\"]\nrequired_secrets=[\"API_KEY\"]\n",
        )?;
        let mut output = Vec::new();
        super::bootstrap_command(&context, &mut output)?;
        assert!(String::from_utf8(output)?.contains("run locket init"));
        Ok(())
    }
    #[test]
    fn bootstrap_counts_declared_parent_variables_without_running_children()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let context = crate::tests::test_context(&directory);
        crate::run_with_context(
            crate::Cli::try_parse_from(["locket", "init", "--no-device", "--no-passkey"])?,
            &context,
            &mut Vec::new(),
        )?;
        let path = directory.path().join("locket.toml");
        let mut text = std::fs::read_to_string(&path)?;
        text.push_str("\n[commands.dev]\nargv=[\"/usr/bin/true\"]\nrequired_secrets=[\"PATH\"]\nexternal_env_sources=[\"parent\"]\n");
        std::fs::write(path, text)?;
        let resolved = crate::require_project(&context)?;
        let store = crate::open_store(&context)?;
        let report = super::collect_bootstrap_report(&context, &resolved, &store)?;
        assert_eq!(report.missing_variables, [] as [String; 0]);
        assert!(!crate::agent_socket_path(&context).exists());
        Ok(())
    }
}
