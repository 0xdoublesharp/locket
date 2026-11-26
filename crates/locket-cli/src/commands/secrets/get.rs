//! Implementation of the `locket get` command and clipboard helpers.

use locket_core::SecretName;
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::process::{Command as ProcessCommand, Stdio};
use std::thread;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

use crate::runtime::RuntimeContext;
use crate::runtime::dangerous_profile::{
    DANGEROUS_PROFILE_DENIAL_REASON, ensure_dangerous_profile_consent,
};
use crate::runtime::error::{CliError, external_source_unavailable_error};
use crate::runtime::user_verification::{UserVerificationAudit, require_user_verification};
use crate::support::secret_helpers::{
    ValueAccessAudit, ValueAccessTarget, decrypt_secret_version, resolve_active_secret,
    resolve_active_secret_for_source, resolve_active_secret_in_profile, reveal_ttl_seconds,
    write_value_access_audit_if_available,
};
use crate::{
    GetArgs, access_denied_error, invalid_secret_name_error, secret_deleted_error,
    secret_not_found_error, source_arg_to_str,
};

pub fn get_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &GetArgs,
) -> Result<(), CliError> {
    let mut error_output = io::stderr();
    get_command_with_clipboard_status(
        context,
        output,
        &mut error_output,
        args,
        copy_secret_to_clipboard,
    )
}

#[cfg(test)]
pub fn get_command_with_clipboard(
    context: &RuntimeContext,
    output: &mut impl Write,
    error_output: &mut impl Write,
    args: &GetArgs,
    copy_to_clipboard: impl FnOnce(&str) -> Result<(), String>,
) -> Result<(), CliError> {
    let limit = clipboard_clear_limit(
        select_clipboard_command(CLIPBOARD_COMMANDS, command_exists),
        std::env::var("XDG_SESSION_TYPE").ok().as_deref(),
    );
    get_command_with_clipboard_status_and_limit(
        context,
        output,
        error_output,
        args,
        |value, _ttl_seconds, _limit| {
            copy_to_clipboard(value)?;
            Ok(ClipboardCopyStatus::clearing_unsupported("direct_cli_no_background_clear"))
        },
        limit,
    )
}

#[cfg(test)]
pub fn get_command_with_clipboard_and_limit(
    context: &RuntimeContext,
    output: &mut impl Write,
    error_output: &mut impl Write,
    args: &GetArgs,
    copy_to_clipboard: impl FnOnce(&str) -> Result<(), String>,
    limit: ClipboardClearLimit,
) -> Result<(), CliError> {
    get_command_with_clipboard_status_and_limit(
        context,
        output,
        error_output,
        args,
        |value, _ttl_seconds, _limit| {
            copy_to_clipboard(value)?;
            Ok(ClipboardCopyStatus::clearing_unsupported(
                limit.audit_reason().unwrap_or("direct_cli_no_background_clear"),
            ))
        },
        limit,
    )
}

pub fn get_command_with_clipboard_status(
    context: &RuntimeContext,
    output: &mut impl Write,
    error_output: &mut impl Write,
    args: &GetArgs,
    copy_to_clipboard: impl FnOnce(
        &str,
        u64,
        ClipboardClearLimit,
    ) -> Result<ClipboardCopyStatus, String>,
) -> Result<(), CliError> {
    let limit = clipboard_clear_limit(
        select_clipboard_command(CLIPBOARD_COMMANDS, command_exists),
        std::env::var("XDG_SESSION_TYPE").ok().as_deref(),
    );
    get_command_with_clipboard_status_and_limit(
        context,
        output,
        error_output,
        args,
        copy_to_clipboard,
        limit,
    )
}

pub fn get_command_with_clipboard_status_and_limit(
    context: &RuntimeContext,
    output: &mut impl Write,
    error_output: &mut impl Write,
    args: &GetArgs,
    copy_to_clipboard: impl FnOnce(
        &str,
        u64,
        ClipboardClearLimit,
    ) -> Result<ClipboardCopyStatus, String>,
    limit: ClipboardClearLimit,
) -> Result<(), CliError> {
    let resolved_secret = resolve_value_access(context, args)?;
    super::expiry::check_secret_expiry(
        &crate::commands::discovery::require_metadata_store(context)?,
        &resolved_secret.secret.id,
    )?;
    let (action, access_mode) = get_audit_action_and_access_mode(args);
    enforce_dangerous_profile_consent_or_audit(
        context,
        &resolved_secret,
        action,
        access_mode,
        args.use_dangerous,
        args.force,
    )?;
    if args.copy {
        return get_copy_command(
            context,
            output,
            error_output,
            &resolved_secret,
            args.verify_user,
            copy_to_clipboard,
            limit,
        );
    }
    if args.reveal {
        return get_reveal_command(context, output, &resolved_secret, args.force, args.verify_user);
    }

    writeln!(
        output,
        "{} source={} version={}",
        resolved_secret.secret.name,
        resolved_secret.secret.source,
        resolved_secret.secret.current_version
    )?;
    Ok(())
}

fn resolve_value_access(
    context: &RuntimeContext,
    args: &GetArgs,
) -> Result<ValueAccessTarget, CliError> {
    if args.project.is_none() && args.profile.is_none() {
        let resolved = match args.source.source {
            Some(source) => resolve_active_secret_for_source(context, &args.key, Some(source))?,
            None => resolve_active_secret(context, &args.key)?,
        };
        return Ok(resolved.into());
    }
    let name = SecretName::new(args.key.clone())
        .map_err(|_| invalid_secret_name_error("invalid secret name"))?;
    let store = crate::commands::discovery::require_metadata_store(context)?;
    let target = super::set::select_target(
        context,
        &store,
        args.project.as_deref(),
        args.profile.as_deref(),
    )?;
    let secret = if let Some(source) = args.source.source {
        store
            .get_secret_by_source(
                &target.project.id,
                &target.profile.id,
                name.as_str(),
                source_arg_to_str(source),
            )?
            .ok_or_else(|| secret_not_found_error("secret not found"))?
    } else {
        resolve_active_secret_in_profile(&store, &target.profile, &name)?
    };
    if secret.state != "active" {
        return Err(secret_deleted_error("secret source is deleted"));
    }
    Ok(ValueAccessTarget { profile: target.profile, secret })
}

fn decrypt_access_secret(
    context: &RuntimeContext,
    target: &ValueAccessTarget,
) -> Result<Zeroizing<String>, CliError> {
    let store = crate::open_store(context)?;
    let secret = &target.secret;
    super::expiry::check_secret_expiry(&store, &secret.id)?;
    crate::commands::exec::run::require_linked_secret_access(
        context,
        &store,
        &target.profile,
        secret,
        false,
    )?;
    decrypt_secret_version(
        context,
        &store,
        &secret.project_id,
        &secret.profile_id,
        secret,
        secret.current_version,
    )
}

/// Returns the audit-row `action` and `access_mode` strings that match the
/// requested `get` mode. `--copy` wins over `--reveal` because clap rejects
/// the conflicting combination.
const fn get_audit_action_and_access_mode(args: &GetArgs) -> (&'static str, &'static str) {
    if args.copy {
        ("COPY", "clipboard")
    } else if args.reveal {
        ("REVEAL", "stdout")
    } else {
        ("GET", "get")
    }
}

/// Refuse reads against profiles marked `dangerous` unless `--use-dangerous`
/// was passed. Writes a metadata-only `DENIED` audit row tagged with
/// `failure_reason: "dangerous_profile_unconfirmed"` BEFORE returning the
/// typed error so the audit trail records the refusal even when no other
/// work happens.
fn enforce_dangerous_profile_consent_or_audit(
    context: &RuntimeContext,
    resolved_secret: &ValueAccessTarget,
    action: &'static str,
    access_mode: &'static str,
    use_dangerous: bool,
    force: bool,
) -> Result<(), CliError> {
    if let Err(error) = ensure_dangerous_profile_consent(&resolved_secret.profile, use_dangerous) {
        write_value_access_audit_if_available(&ValueAccessAudit {
            context,
            resolved: resolved_secret,
            action,
            status: "DENIED",
            access_mode,
            ttl_seconds: None,
            force,
            clipboard_supported: None,
            clipboard_clear_supported: None,
            unsupported_reason: None,
            denial_reason: None,
            failure_reason: Some(DANGEROUS_PROFILE_DENIAL_REASON),
            user_verification: UserVerificationAudit::not_required(),
        })?;
        return Err(error);
    }
    Ok(())
}

fn get_copy_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    error_output: &mut impl Write,
    resolved_secret: &ValueAccessTarget,
    verify_user: bool,
    copy_to_clipboard: impl FnOnce(
        &str,
        u64,
        ClipboardClearLimit,
    ) -> Result<ClipboardCopyStatus, String>,
    limit: ClipboardClearLimit,
) -> Result<(), CliError> {
    let ttl_seconds = reveal_ttl_seconds(context)?;
    if let Some(warning) = limit.warning_text() {
        writeln!(error_output, "{warning}")?;
    }
    let user_verification = value_access_user_verification_or_audit_denial(
        context,
        resolved_secret,
        "COPY",
        verify_user,
        Some(ttl_seconds),
        false,
        "clipboard",
    )?;
    let value = decrypt_access_secret(context, resolved_secret).inspect_err(|error| {
        record_locked_vault_refusal_if_applicable(
            context,
            error,
            resolved_secret,
            "COPY",
            "get --copy",
        );
    })?;
    let result = copy_to_clipboard(value.as_str(), ttl_seconds, limit);
    let status = if result.is_ok() { "SUCCESS" } else { "FAILED" };
    let clipboard_clear_supported =
        result.as_ref().ok().map_or(Some(false), |status| Some(status.clear_supported));
    let unsupported_reason = match result.as_ref() {
        Err(error) => Some(error.as_str()),
        Ok(status) => status.unsupported_reason.as_deref(),
    };
    write_value_access_audit_if_available(&ValueAccessAudit {
        context,
        resolved: resolved_secret,
        action: "COPY",
        status,
        access_mode: "clipboard",
        ttl_seconds: Some(ttl_seconds),
        force: false,
        clipboard_supported: Some(result.is_ok()),
        clipboard_clear_supported,
        unsupported_reason,
        denial_reason: None,
        failure_reason: None,
        user_verification,
    })?;
    result.map_err(external_source_unavailable_error)?;
    let clear_supported = if clipboard_clear_supported == Some(true) { "yes" } else { "no" };
    writeln!(
        output,
        "copied {} source={} version={} ttl_seconds={} clipboard_clear_supported={} metadata_only=yes",
        resolved_secret.secret.name,
        resolved_secret.secret.source,
        resolved_secret.secret.current_version,
        ttl_seconds,
        clear_supported
    )?;
    Ok(())
}

fn get_reveal_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    resolved_secret: &ValueAccessTarget,
    force: bool,
    verify_user: bool,
) -> Result<(), CliError> {
    if !force && !io::stdout().is_terminal() {
        write_value_access_audit_if_available(&ValueAccessAudit {
            context,
            resolved: resolved_secret,
            action: "REVEAL",
            status: "DENIED",
            access_mode: "stdout",
            ttl_seconds: None,
            force,
            clipboard_supported: None,
            clipboard_clear_supported: None,
            unsupported_reason: None,
            denial_reason: Some("noninteractive_terminal"),
            failure_reason: None,
            user_verification: UserVerificationAudit::not_required(),
        })?;
        return Err(access_denied_error(
            "get --reveal requires an interactive terminal; pass --force for noninteractive stdout",
        ));
    }
    let user_verification = value_access_user_verification_or_audit_denial(
        context,
        resolved_secret,
        "REVEAL",
        verify_user,
        None,
        force,
        "stdout",
    )?;
    let value = decrypt_access_secret(context, resolved_secret).inspect_err(|error| {
        record_locked_vault_refusal_if_applicable(
            context,
            error,
            resolved_secret,
            "REVEAL",
            "get --reveal",
        );
    })?;
    write_value_access_audit_if_available(&ValueAccessAudit {
        context,
        resolved: resolved_secret,
        action: "REVEAL",
        status: "SUCCESS",
        access_mode: "stdout",
        ttl_seconds: None,
        force,
        clipboard_supported: None,
        clipboard_clear_supported: None,
        unsupported_reason: None,
        denial_reason: None,
        failure_reason: None,
        user_verification,
    })?;
    writeln!(output, "{}", value.as_str())?;
    Ok(())
}

/// Mirrors a refused-while-locked value-access into the degraded-audit
/// log when `error` carries a `PlatformError::MasterKeyNotFound`. Always
/// best-effort: logging failure must not mask the legitimate
/// `UnlockRequired` return.
fn record_locked_vault_refusal_if_applicable(
    context: &RuntimeContext,
    error: &CliError,
    resolved_secret: &ValueAccessTarget,
    action: &'static str,
    command: &'static str,
) {
    if matches!(error, CliError::Platform(locket_platform::PlatformError::MasterKeyNotFound)) {
        crate::runtime::degraded_audit::record_locked_refusal(
            context,
            action,
            Some(&resolved_secret.secret.project_id),
            command,
        );
    }
}

fn value_access_user_verification_or_audit_denial(
    context: &RuntimeContext,
    resolved_secret: &ValueAccessTarget,
    audit_action: &'static str,
    verify_user: bool,
    ttl_seconds: Option<u64>,
    force: bool,
    access_mode: &'static str,
) -> Result<UserVerificationAudit, CliError> {
    let verification_action = if audit_action == "COPY" { "copy" } else { "reveal" };
    match value_access_user_verification(
        context,
        verify_user,
        verification_action,
        &resolved_secret.secret.name,
    ) {
        Ok(audit) => Ok(audit),
        Err(error) => {
            write_value_access_audit_if_available(&ValueAccessAudit {
                context,
                resolved: resolved_secret,
                action: audit_action,
                status: "DENIED",
                access_mode,
                ttl_seconds,
                force,
                clipboard_supported: None,
                clipboard_clear_supported: None,
                unsupported_reason: None,
                denial_reason: Some("user_verification_failed"),
                failure_reason: None,
                user_verification: UserVerificationAudit::failed_required(),
            })?;
            Err(error)
        }
    }
}

fn value_access_user_verification(
    context: &RuntimeContext,
    required: bool,
    action: &'static str,
    secret_name: &str,
) -> Result<UserVerificationAudit, CliError> {
    let reason = format!("{action} secret {secret_name}");
    if required {
        return require_user_verification(context, action, reason);
    }
    let key = if action == "copy" {
        "user_verification_required_for.copy"
    } else {
        "user_verification_required_for.reveal"
    };
    crate::runtime::user_verification::configured_user_verification(context, key, action, reason)
}

#[derive(Debug, Eq, PartialEq)]
pub struct ClipboardCommand {
    pub program: &'static str,
    pub args: &'static [&'static str],
}

pub const CLIPBOARD_COMMANDS: &[ClipboardCommand] = if cfg!(target_os = "macos") {
    &[ClipboardCommand { program: "pbcopy", args: &[] }]
} else if cfg!(target_os = "windows") {
    &[ClipboardCommand { program: "clip", args: &[] }]
} else {
    &[
        ClipboardCommand { program: "wl-copy", args: &[] },
        ClipboardCommand { program: "xclip", args: &["-selection", "clipboard"] },
        ClipboardCommand { program: "xsel", args: &["--clipboard", "--input"] },
    ]
};

/// Why the direct-CLI clipboard path can't reliably clear the value at TTL.
/// Used to drive both the pre-copy stderr warning and the
/// `clipboard_clear_supported`/`unsupported_reason` audit metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardClearLimit {
    /// The selected clipboard tool can read the current clipboard and clear it
    /// after TTL only when the original value is still present.
    Supported,
    /// Direct-CLI copy cannot schedule a background clearer; clearing waits
    /// on the agent path. This is the baseline limit on every platform.
    DirectCli,
    /// Wayland clipboards belong to the source process. When the CLI exits
    /// after writing the value, a strict compositor may drop the selection
    /// before TTL elapses; a permissive one may keep it past TTL with no
    /// way for Locket to clear it. Either failure mode leaks intent.
    WaylandSourceProcessLimited,
}

impl ClipboardClearLimit {
    /// Stable string used in the audit metadata `unsupported_reason` field.
    pub const fn audit_reason(self) -> Option<&'static str> {
        match self {
            Self::Supported => None,
            Self::DirectCli => Some("direct_cli_no_background_clear"),
            Self::WaylandSourceProcessLimited => Some("wayland_source_process_limited"),
        }
    }

    /// Operator-facing pre-copy warning text written to stderr.
    pub const fn warning_text(self) -> Option<&'static str> {
        match self {
            Self::Supported => None,
            Self::DirectCli => {
                Some("warning: clipboard TTL clearing is unsupported in this direct CLI path")
            }
            Self::WaylandSourceProcessLimited => Some(
                "warning: Wayland clipboards belong to the source process; \
                 the value may be cleared before TTL or persist past it",
            ),
        }
    }
}

/// Classifies how reliably the current environment can clear the clipboard
/// after the documented TTL. `xdg_session_type` lets tests inject the
/// session value (`Some("wayland")`) without touching the process env.
pub fn clipboard_clear_limit(
    selected: Option<&ClipboardCommand>,
    xdg_session_type: Option<&str>,
) -> ClipboardClearLimit {
    let Some(command) = selected else {
        return ClipboardClearLimit::DirectCli;
    };
    if command.program == "wl-copy"
        || matches!(xdg_session_type, Some(value) if value.eq_ignore_ascii_case("wayland"))
    {
        return ClipboardClearLimit::WaylandSourceProcessLimited;
    }
    if clipboard_clear_commands(command).is_some() {
        return ClipboardClearLimit::Supported;
    }
    ClipboardClearLimit::DirectCli
}

#[derive(Debug, Eq, PartialEq)]
pub struct ClipboardCopyStatus {
    clear_supported: bool,
    unsupported_reason: Option<String>,
}

impl ClipboardCopyStatus {
    #[must_use]
    pub const fn clearing_scheduled() -> Self {
        Self { clear_supported: true, unsupported_reason: None }
    }

    #[must_use]
    pub fn clearing_unsupported(reason: &str) -> Self {
        Self { clear_supported: false, unsupported_reason: Some(reason.to_owned()) }
    }
}

pub fn copy_secret_to_clipboard(
    value: &str,
    ttl_seconds: u64,
    limit: ClipboardClearLimit,
) -> Result<ClipboardCopyStatus, String> {
    let mut clipboard = SystemClipboard;
    clipboard.copy(value)?;
    if limit != ClipboardClearLimit::Supported {
        return Ok(ClipboardCopyStatus::clearing_unsupported(
            limit.audit_reason().unwrap_or("direct_cli_no_background_clear"),
        ));
    }
    clipboard.schedule_clear_after_ttl(value, ttl_seconds)
}

pub fn copy_secret_to_clipboard_with(
    value: &str,
    commands: &'static [ClipboardCommand],
    exists: impl FnMut(&str) -> bool,
) -> Result<(), String> {
    let Some(command) = select_clipboard_command(commands, exists) else {
        return Err("clipboard command unavailable".to_owned());
    };
    let mut child = ProcessCommand::new(command.program)
        .args(command.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "clipboard command failed to start".to_owned())?;
    {
        let Some(mut stdin) = child.stdin.take() else {
            return Err("clipboard command stdin unavailable".to_owned());
        };
        stdin
            .write_all(value.as_bytes())
            .map_err(|_| "clipboard command rejected stdin".to_owned())?;
    }
    let status = child.wait().map_err(|_| "clipboard command did not finish".to_owned())?;
    if !status.success() {
        return Err("clipboard command failed".to_owned());
    }
    Ok(())
}

pub fn select_clipboard_command(
    commands: &'static [ClipboardCommand],
    mut exists: impl FnMut(&str) -> bool,
) -> Option<&'static ClipboardCommand> {
    commands.iter().find(|command| exists(command.program))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardClearResult {
    Cleared,
    Changed,
    Unsupported,
}

pub trait ClipboardBackend {
    fn copy(&mut self, value: &str) -> Result<(), String>;

    fn clear_if_current(&mut self, expected: &str) -> ClipboardClearResult;

    fn schedule_clear_after_ttl(
        &mut self,
        expected: &str,
        ttl_seconds: u64,
    ) -> Result<ClipboardCopyStatus, String>;
}

#[cfg(test)]
#[derive(Debug, Default, Eq, PartialEq)]
pub struct MemoryClipboard {
    value: Option<String>,
    clear_supported: bool,
}

#[cfg(test)]
impl MemoryClipboard {
    #[must_use]
    pub const fn clearing_supported() -> Self {
        Self { value: None, clear_supported: true }
    }

    #[must_use]
    pub const fn clearing_unsupported() -> Self {
        Self { value: None, clear_supported: false }
    }

    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

#[cfg(test)]
impl ClipboardBackend for MemoryClipboard {
    fn copy(&mut self, value: &str) -> Result<(), String> {
        self.value = Some(value.to_owned());
        Ok(())
    }

    fn clear_if_current(&mut self, expected: &str) -> ClipboardClearResult {
        if !self.clear_supported {
            return ClipboardClearResult::Unsupported;
        }
        if self.value.as_deref() == Some(expected) {
            self.value = None;
            ClipboardClearResult::Cleared
        } else {
            ClipboardClearResult::Changed
        }
    }

    fn schedule_clear_after_ttl(
        &mut self,
        expected: &str,
        _ttl_seconds: u64,
    ) -> Result<ClipboardCopyStatus, String> {
        match self.clear_if_current(expected) {
            ClipboardClearResult::Cleared | ClipboardClearResult::Changed => {
                Ok(ClipboardCopyStatus::clearing_scheduled())
            }
            ClipboardClearResult::Unsupported => {
                Ok(ClipboardCopyStatus::clearing_unsupported("direct_cli_no_background_clear"))
            }
        }
    }
}

pub struct SystemClipboard;

impl ClipboardBackend for SystemClipboard {
    fn copy(&mut self, value: &str) -> Result<(), String> {
        copy_secret_to_clipboard_with(value, CLIPBOARD_COMMANDS, command_exists)
    }

    fn clear_if_current(&mut self, expected: &str) -> ClipboardClearResult {
        let Some(command) = select_clipboard_command(CLIPBOARD_COMMANDS, command_exists) else {
            return ClipboardClearResult::Unsupported;
        };
        if clipboard_clear_limit(Some(command), std::env::var("XDG_SESSION_TYPE").ok().as_deref())
            != ClipboardClearLimit::Supported
        {
            return ClipboardClearResult::Unsupported;
        }
        let Ok(current) = read_clipboard_with(command) else {
            return ClipboardClearResult::Unsupported;
        };
        if current != expected {
            return ClipboardClearResult::Changed;
        }
        if copy_secret_to_clipboard_with("", CLIPBOARD_COMMANDS, command_exists).is_err() {
            return ClipboardClearResult::Unsupported;
        }
        ClipboardClearResult::Cleared
    }

    fn schedule_clear_after_ttl(
        &mut self,
        expected: &str,
        ttl_seconds: u64,
    ) -> Result<ClipboardCopyStatus, String> {
        let executable =
            std::env::current_exe().map_err(|_| "clipboard clear helper unavailable".to_owned())?;
        let mut child = ProcessCommand::new(executable)
            .arg("internal-clipboard-clear")
            .arg("--ttl-seconds")
            .arg(ttl_seconds.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "clipboard clear helper failed to start".to_owned())?;
        {
            let Some(mut stdin) = child.stdin.take() else {
                return Err("clipboard clear helper stdin unavailable".to_owned());
            };
            stdin
                .write_all(expected.as_bytes())
                .map_err(|_| "clipboard clear helper rejected stdin".to_owned())?;
        }
        Ok(ClipboardCopyStatus::clearing_scheduled())
    }
}

pub fn run_internal_clipboard_clear(ttl_seconds: u64) -> Result<(), CliError> {
    let mut expected = String::new();
    io::stdin().read_to_string(&mut expected)?;
    thread::sleep(Duration::from_secs(ttl_seconds));
    let mut clipboard = SystemClipboard;
    let _result = clipboard.clear_if_current(&expected);
    expected.zeroize();
    Ok(())
}

fn read_clipboard_with(command: &ClipboardCommand) -> Result<String, String> {
    let (program, args) = clipboard_clear_commands(command)
        .ok_or_else(|| "clipboard clear unsupported".to_owned())?;
    let output = ProcessCommand::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "clipboard read command failed to start".to_owned())?;
    if !output.status.success() {
        return Err("clipboard read command failed".to_owned());
    }
    String::from_utf8(output.stdout)
        .map_err(|_| "clipboard read command returned non-utf8".to_owned())
}

fn clipboard_clear_commands(
    command: &ClipboardCommand,
) -> Option<(&'static str, &'static [&'static str])> {
    match command.program {
        "pbcopy" => Some(("pbpaste", &[])),
        "xclip" => Some(("xclip", &["-selection", "clipboard", "-o"])),
        "xsel" => Some(("xsel", &["--clipboard", "--output"])),
        _ => None,
    }
}

fn command_exists(program: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|directory| command_exists_in_directory(&directory, program))
}

fn command_exists_in_directory(directory: &Path, program: &str) -> bool {
    let candidate = directory.join(program);
    if candidate.is_file() {
        return true;
    }
    if cfg!(target_os = "windows") {
        let Some(pathext) = std::env::var_os("PATHEXT") else {
            return false;
        };
        return std::env::split_paths(&pathext).any(|extension| {
            let extension = extension.to_string_lossy();
            directory.join(format!("{program}{extension}")).is_file()
        });
    }
    false
}
