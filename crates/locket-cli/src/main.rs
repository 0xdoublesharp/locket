//! Locket command-line entry point.

mod commands;
mod runtime;
mod support;

pub(crate) use runtime::context::RuntimeContext;
use runtime::error::corrupt_db_error;
pub(crate) use runtime::error::{
    CliError, access_denied_error, bundle_verification_error, confirmation_failed_error,
    git_worktree_required_error, invalid_policy_error, invalid_profile_name_error,
    invalid_reference_error, invalid_secret_name_error, metadata_invalid_error,
    metadata_looks_like_secret_error, policy_not_found_error, profile_not_found_error,
    project_not_found_error, project_root_untrusted_error, scan_finding_blocked_error,
    secret_already_exists_error, secret_deleted_error, secret_not_found_error,
    secret_version_overflow_error, team_role_denied_error, tty_required_error,
    unimplemented_in_build_error, unlock_required_error, user_verification_failed_error,
};
pub(crate) use runtime::key_access::{
    MasterKeySource, default_profile, ensure_project_exists, load_master_key,
    load_master_key_verified_by_project_key, load_project_key, load_project_key_with_source,
    store_master_key_with_fallback,
};
use runtime::prompts::validate_secret_value_str;
#[cfg(test)]
pub(crate) use runtime::prompts::{
    ConfirmationReader, PassphraseReader, RecoveryCodeReader, SecretValueReader,
    read_secret_value_from_reader, validate_secret_value,
};

pub(crate) use support::project_files::{
    EXAMPLE_FILE, GITIGNORE_ENTRIES, GITIGNORE_FILE, collect_example_secret_names,
    config_bool_value, ensure_gitignore, refresh_example_for_project_if_enabled,
    write_example_block, write_example_block_for_emit, write_example_emit_audit,
};
#[cfg(test)]
pub(crate) use support::secret_helpers::resolve_pinned_version;
use support::secret_helpers::{
    PolicySecretSelection, ResolvedSecret, SecretEncryptRequest, decrypt_secret_version,
    encrypt_secret_version, resolve_active_secret_for_source, resolve_secret_for_source,
    secret_audit_metadata, select_copy_profiles_and_sources, summarize_names,
};
pub(crate) use support::time::{
    format_optional_str, format_optional_unix_nanos, format_unix_nanos, optional_i64,
    resolve_diff_since, unix_nanos_to_rfc3339,
};

#[cfg(test)]
pub(crate) use commands::exec::docker::{
    compose_argv_with_options, docker_policy_audit_metadata, prepare_compose_policy_execution,
    prepare_docker_policy_execution, write_docker_policy_audit_if_available,
};
#[cfg(test)]
pub(crate) use commands::exec::run::{
    ComposeConfigCommand, expand_runner_command_for_tests, resolve_policy_external_env,
    resolve_policy_external_env_with_compose_config_command, runner_policy_name_for_tests,
};
#[cfg(all(test, unix))]
pub(crate) use commands::exec::run::{
    ide_env_source_context_for_tests, prepare_agent_policy_access_for_tests,
    resolve_external_env_ide_with_session_id,
};
pub(crate) use commands::project::install_hooks::git_dir_for_worktree;
pub(crate) use commands::scan::context::privacy_redact_names_enabled;
#[cfg(test)]
pub(crate) use commands::scan::redact::{
    AiSafeRawChunk, AiSafeStream, AiSafeStreamRedactor, KnownSecretRedaction,
    collect_redaction_values_for_redact, redact_stdin_bytes,
};
#[cfg(test)]
pub(crate) use commands::secrets::get::{
    ClipboardBackend, ClipboardClearLimit, ClipboardClearResult, ClipboardCommand,
    ClipboardCopyStatus, MemoryClipboard, clipboard_clear_limit, copy_secret_to_clipboard_with,
    get_command_with_clipboard, get_command_with_clipboard_and_limit,
    get_command_with_clipboard_status_and_limit, select_clipboard_command,
};
#[cfg(test)]
pub(crate) use commands::secrets::import::{EnvImportEntry, parse_env_import};
#[cfg(test)]
pub(crate) use commands::secrets::set::set_secret_value;
#[cfg(test)]
pub(crate) use commands::shell::SHELL_HOOK_BEGIN;
#[cfg(test)]
pub(crate) use commands::team::device::{device_fingerprint_hex, encode_device_descriptor};
#[cfg(test)]
pub(crate) use commands::vault::recovery::{
    recovery_dir, recovery_rotate_command, restore_from_recovery_code,
};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell as CompletionShell;
use locket_core::{
    CommandPolicy, CommandSpec, Duration as LocketDuration, EnvMode, EnvOverrideMode,
    ExternalEnvSource, KeyId, MetadataPrivacyFinding, MetadataValidationError,
    PROJECT_CONFIG_SCHEMA_VERSION, PathEnvSet, PolicyDocument, PolicyFieldSource, ProfileId,
    ProfileName, ProjectConfig, SecretId, SecretName, validate_metadata_field,
};
use locket_crypto::{
    EncryptedSecretValue, HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose,
    derive_wrapping_key_v1, generate_key, generate_recovery_code_bytes, generate_recovery_salt,
    key_wrap_aad_v1, recovery_code_decode, recovery_code_encode, seal_recovery_entry_v1,
    wrap_key_material_v1,
};
use locket_platform::RecoveryEnvelopeEntry;
#[cfg(test)]
use locket_platform::{RecoveryEnvelope, RecoveryKdfToml, save_recovery_kdf_toml};
#[cfg(test)]
use locket_platform::{load_recovery_envelope, load_recovery_kdf_toml};
use locket_scan::{FindingKind, redact_text, scan_text};
#[cfg(test)]
use locket_store::DeviceRecord;
use locket_store::{
    AuditContext, AuditWrite, KeyRecord, ProfileRecord, SCHEMA_VERSION, SecretBlobRecord,
    SecretCopyTarget, SecretFingerprintRecord, SecretRecord, SecretVersionRecord, Store,
    VersionDeprecation,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExitCode;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use commands::policy::PolicyCommand;
use support::time::NANOS_PER_SECOND;

pub(crate) const LOCKET_TOML: &str = "locket.toml";
pub(crate) const CONFIG_TOML: &str = "config.toml";
pub(crate) const HOOK_BEGIN: &str = "# --- BEGIN LOCKET PRE-COMMIT ---";
pub(crate) const HOOK_END: &str = "# --- END LOCKET PRE-COMMIT ---";
const DEFAULT_MAX_GRACE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const AGENT_LOG_MAX_BYTES: u64 = 1024 * 1024;
const AGENT_LOG_RETAINED_FILES: u8 = 5;
const AGENT_LOG_FOLLOW_SLEEP_MS: u64 = 250;
const AI_SAFE_READ_CHUNK_BYTES: usize = 8 * 1024;
const AI_SAFE_PARTIAL_LINE_MAX_BYTES: usize = 64 * 1024;
const PRE_MIGRATION_BACKUP_DIR: &str = "pre-migration-backups";
const BACKUP_SKIPPED_PREFIX: &str = "backup-skipped-";

pub(crate) fn next_secret_version(current_version: u32) -> Result<u32, CliError> {
    current_version
        .checked_add(1)
        .ok_or_else(|| secret_version_overflow_error("secret version overflow"))
}

#[derive(Debug, Parser)]
#[command(
    name = "locket",
    version,
    about = "Encrypted local secrets with command and path-scoped delivery",
    after_help = "Project files keep policy in locket.toml and values in the encrypted local vault.\n\
                  Monorepos can add [paths.\"relative/path\"] env sets; the deepest matching\n\
                  scope extends the selected [commands.<policy>] entry when run from that subtree."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show metadata-only status.
    Status {
        /// Scan project files for plaintext secrets.
        #[arg(long)]
        scan: bool,
    },
    /// Initialize a Locket project from a template.
    New(NewArgs),
    /// Show metadata-only onboarding checklist.
    Bootstrap,
    /// Show guided local-development setup steps.
    Setup {
        /// Setup guide.
        #[command(subcommand)]
        command: Option<SetupCommand>,
    },
    /// Generate shell completions.
    Completion(CompletionArgs),
    /// Run locked-safe local diagnostics.
    Doctor(DoctorArgs),
    /// Create metadata-only debug artifacts.
    Debug {
        /// Debug command.
        #[command(subcommand)]
        command: DebugCommand,
    },
    /// Initialize a Locket project.
    Init(InitArgs),
    /// Store a new secret.
    Set(SecretWriteArgs),
    /// Import secrets from an env file.
    Import(ImportArgs),
    /// Get secret metadata, reveal, or copy.
    Get(GetArgs),
    /// Reveal a secret value to stdout (alias for `get --reveal`).
    Reveal(RevealArgs),
    /// Copy a secret value to the clipboard (alias for `get --copy`).
    #[command(alias = "clip")]
    Cp(CpArgs),
    /// Tombstone a secret source.
    Rm(SourceKeyArgs),
    /// Destructively purge encrypted versions.
    Purge(PurgeArgs),
    /// List secrets.
    List(ListArgs),
    /// Execute a child process with scoped injection.
    Exec(ExecArgs),
    /// Execute a named command policy, extended by any matching path scope.
    Run(RunArgs),
    /// Inspect runtime environment decisions, including matched path scopes.
    Env {
        /// Environment command.
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Execute Docker Compose with scoped policy and path injection.
    Compose {
        /// Compose command.
        #[command(subcommand)]
        command: ComposeCommand,
    },
    /// Lock local agent-held keys.
    Lock,
    /// Unlock the local vault.
    Unlock(UnlockArgs),
    /// Manage profiles.
    Profile {
        /// Profile command.
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Author command policies in locket.toml.
    #[command(
        after_help = "Path-scoped env sets live in locket.toml under [paths.\"relative/path\"].\n\
                            Use them to add required/optional secret names, or a profile override,\n\
                            for commands run from a monorepo subtree."
    )]
    Policy {
        /// Policy command.
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Switch active profile.
    Use(ProfileNameArgs),
    /// Manage trusted project roots.
    Project {
        /// Project command.
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// Emit shell rc integration.
    Shellenv(ShellenvArgs),
    /// Emit or install a metadata-only shell hook.
    Hook(HookArgs),
    /// Allow shell integration for the trusted project root and active profile.
    Allow,
    /// Revoke shell integration consent for the active profile or project.
    Deny(DenyArgs),
    /// Regenerate .env.example.
    EmitExample,
    /// Install Git hooks.
    InstallHooks,
    /// Scan project files.
    Scan(ScanArgs),
    /// Redact a file or stdin.
    Redact(RedactArgs),
    /// Emit AI-safe context metadata.
    Context(ContextArgs),
    /// Capture and redact command output.
    AiSafe(AiSafeArgs),
    /// Rotate a secret value.
    Rotate(RotateArgs),
    /// Update secret metadata.
    Meta(SecretMetaArgs),
    /// Show secret version history.
    History(HistoryArgs),
    /// Show metadata-only differences.
    Diff(DiffArgs),
    /// Copy a secret between profiles without revealing its value.
    Copy(CopyArgs),
    /// Audit log operations.
    Audit {
        /// Audit command.
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Manage the local agent.
    Agent {
        /// Agent command.
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Manage non-secret user preferences.
    Config {
        /// Config command.
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Manage passkey authenticators.
    Passkey {
        /// Passkey command.
        #[command(subcommand)]
        command: PasskeyCommand,
    },
    /// Manage local/trusted devices.
    Device {
        /// Device command.
        #[command(subcommand)]
        command: DeviceCommand,
    },
    /// Manage team metadata.
    Team {
        /// Team command.
        #[command(subcommand)]
        command: TeamCommand,
    },
    /// Manage automation clients.
    Client {
        /// Automation-client command.
        #[command(subcommand)]
        command: ClientCommand,
    },
    /// Export a sealed local bundle.
    Export(ExportArgs),
    /// Import a sealed local bundle.
    ImportBundle(ImportBundleArgs),
    /// Verify sealed local bundles.
    Bundle {
        /// Bundle command.
        #[command(subcommand)]
        command: BundleCommand,
    },
    /// Restore vault access from a recovery code.
    Recover(RecoverArgs),
    /// Manage recovery codes.
    Recovery {
        /// Recovery command.
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    /// Internal: run the agent daemon serve loop. Hidden from --help.
    ///
    /// Spawned by `locket agent start`. Not intended for direct use.
    #[command(name = "internal-agent-serve", hide = true)]
    InternalAgentServe(InternalAgentServeArgs),
    /// Internal: clear a copied clipboard value after its TTL. Hidden from --help.
    ///
    /// Spawned by `locket get --copy`. The expected clipboard value is read
    /// from stdin so it is never placed in argv or the environment.
    #[command(name = "internal-clipboard-clear", hide = true)]
    InternalClipboardClear(InternalClipboardClearArgs),
}

#[derive(Debug, Args)]
pub(crate) struct InternalAgentServeArgs {
    /// Filesystem path the agent should bind for its Unix socket.
    #[arg(long)]
    pub(crate) socket: PathBuf,
    /// Filesystem path the agent should write its PID file to.
    #[arg(long)]
    pub(crate) pid_file: PathBuf,
    /// Refuse to serve if native session monitoring cannot be initialized.
    #[arg(long)]
    pub(crate) require_session_monitoring: bool,
}

#[derive(Debug, Args)]
pub(crate) struct InternalClipboardClearArgs {
    /// Seconds to wait before checking and clearing the clipboard.
    #[arg(long)]
    ttl_seconds: u64,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Prune expired runtime-session secret-name metadata after reporting it.
    #[arg(long)]
    prune_runtime_session_secret_names: bool,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub(crate) enum SetupCommand {
    /// Summarize setup state and next commands.
    Status,
    /// Show paste-friendly agent invite steps.
    Agent,
    /// Show sharing options for agents, teammates, and sealed bundles.
    Share,
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct InitArgs {
    /// Project display name.
    #[arg(long)]
    pub(crate) name: Option<String>,
    /// Initial profile name.
    #[arg(long)]
    pub(crate) profile: Option<String>,
    /// Create and display an offline recovery code during init.
    #[arg(long)]
    pub(crate) recovery_code: bool,
    /// Skip creating a local device during init.
    #[arg(long)]
    pub(crate) no_device: bool,
    /// Register a passkey after device init using the host name as the label.
    /// Conflicts with --no-passkey.
    #[arg(long, conflicts_with = "no_passkey")]
    pub(crate) register_passkey: bool,
    /// Skip the passkey registration prompt entirely.
    #[arg(long)]
    pub(crate) no_passkey: bool,
}

#[derive(Debug, Args)]
struct NewArgs {
    /// Local or built-in template name.
    #[arg(long)]
    from_template: String,
}

#[derive(Debug, Clone, Copy, Args)]
struct CompletionArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    shell: CompletionShell,
}

#[derive(Debug, Args)]
struct SecretWriteArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
    #[command(flatten)]
    metadata: SecretMetadataFlags,
}

#[derive(Debug, Args)]
struct ImportArgs {
    /// Env file to import.
    file: String,
    /// Profile to import into.
    #[arg(long)]
    profile: Option<String>,
    /// Runtime source to target.
    #[arg(long, value_enum)]
    source: Option<SecretSourceArg>,
    /// Preserve dollar expressions literally without evaluating them.
    #[arg(long)]
    literal: bool,
    /// Rotate duplicate keys instead of skipping them.
    #[arg(long)]
    overwrite: bool,
}

#[derive(Debug, Args)]
#[allow(clippy::struct_excessive_bools)]
struct GetArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
    /// Reveal the value to stdout after policy gates.
    #[arg(long, conflicts_with = "copy")]
    reveal: bool,
    /// Allow reveal when stdout is not an interactive terminal.
    #[arg(long, requires = "reveal")]
    force: bool,
    /// Copy the value to clipboard after policy gates.
    #[arg(long)]
    copy: bool,
    /// Require local user verification before reveal or copy.
    #[arg(long)]
    verify_user: bool,
    /// Confirm read intent against a profile marked dangerous.
    #[arg(long)]
    use_dangerous: bool,
}

#[derive(Debug, Args)]
struct RevealArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
    /// Allow reveal when stdout is not an interactive terminal.
    #[arg(long)]
    force: bool,
    /// Require local user verification before reveal.
    #[arg(long)]
    verify_user: bool,
    /// Confirm read intent against a profile marked dangerous.
    #[arg(long)]
    use_dangerous: bool,
}

#[derive(Debug, Args)]
struct CpArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
    /// Require local user verification before copy.
    #[arg(long)]
    verify_user: bool,
    /// Confirm read intent against a profile marked dangerous.
    #[arg(long)]
    use_dangerous: bool,
}

#[derive(Debug, Args)]
struct SourceKeyArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
}

#[derive(Debug, Args)]
struct PurgeArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
    /// Purge a specific version.
    #[arg(long, conflicts_with = "all_versions")]
    version: Option<u32>,
    /// Purge every version for a deleted source.
    #[arg(long)]
    all_versions: bool,
    /// Skip the typed confirmation prompt.
    ///
    /// Intended for non-interactive automation. Use only when the caller has
    /// already confirmed the destructive scope through another channel.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct ListArgs {
    /// Include deleted sources and deprecated version counts.
    #[arg(long)]
    all: bool,
}

/// Arguments for the `locket exec` command.
#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Secret name to inject. May be repeated.
    #[arg(long = "secret")]
    pub secrets: Vec<String>,
    /// Inject every active profile secret after confirmation.
    #[arg(long, conflicts_with = "secrets")]
    pub all: bool,
    /// Skip the typed confirmation prompt for `--all`.
    ///
    /// Intended for non-interactive automation. The active-profile secret
    /// names are still recorded in the EXEC audit row.
    #[arg(long)]
    pub force: bool,
    /// Command and arguments after `--`.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

/// Arguments for the `locket run` command.
#[derive(Debug, Args)]
#[command(after_help = "With one argument, runs [commands.<policy>] from locket.toml.\n\
                        With a supported runner and target, such as `locket run npm dev`,\n\
                        Locket expands the runner command and applies any matching path scope.\n\
                        Secret ACLs in [secrets.<NAME>] can further limit delivery by command identity,\n\
                        structured argv pattern, and project-relative path.")]
pub struct RunArgs {
    /// Command policy name, or a runner adapter such as npm, pnpm, yarn, bun, cargo, make, just, task, poetry, uv, or python.
    #[arg(default_value = "")]
    pub policy: String,
    /// Runner target and arguments. For example, `locket run npm dev` executes `npm run dev`.
    #[arg(allow_hyphen_values = true)]
    pub runner_args: Vec<String>,
    /// Exact command arguments after --. New commands require interactive approval.
    #[arg(last = true, allow_hyphen_values = true)]
    pub argv: Vec<String>,
}

/// Subcommands for `locket env`.
#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// Validate required-name coverage offline without reading values or the local vault.
    Validate(EnvValidateArgs),
    /// Show metadata-only policy environment decisions.
    Inspect(EnvInspectArgs),
    /// Execute docker run with policy-backed environment injection.
    Docker(EnvDockerArgs),
}

/// Arguments for offline, names-only contract validation.
#[derive(Debug, Args)]
pub struct EnvValidateArgs {
    /// Saved policy whose effective names will be checked.
    #[arg(long)]
    pub policy: String,
    /// Available variable name, repeated as needed. Never pass values.
    #[arg(long)]
    pub provided_name: Vec<String>,
    /// Emit a metadata-only JSON report.
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the `locket env inspect` command.
#[derive(Debug, Args)]
#[command(
    after_help = "This is metadata-only. It prints the selected policy, matched path_scope,\n\
                        path_scope_profile when set, secret names, sources, conflicts, and final\n\
                        injection decisions. It never prints values or shell exports."
)]
pub struct EnvInspectArgs {
    /// Command policy name from [commands.<policy>], before path-scope merging.
    #[arg(long)]
    pub policy: String,
}

/// Arguments for the `locket env docker` command.
#[derive(Debug, Args)]
#[command(
    after_help = "Policy-backed Docker injection includes the deepest matching [paths.\"...\"]\n\
                        env set for the current project directory before Docker receives env names."
)]
pub struct EnvDockerArgs {
    /// Command policy name from [commands.<policy>], before path-scope merging.
    #[arg(long)]
    pub policy: String,
    /// Docker command and arguments after `--`.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

/// Subcommands for `locket compose`.
#[derive(Debug, Subcommand)]
pub enum ComposeCommand {
    /// Execute docker compose with policy-backed environment injection.
    Run(ComposeRunArgs),
}

/// Arguments for the `locket compose run` command.
#[derive(Debug, Args)]
#[command(
    after_help = "Policy-backed Compose injection includes the deepest matching [paths.\"...\"]\n\
                        env set for the current project directory before Compose interpolation."
)]
pub struct ComposeRunArgs {
    /// Command policy name from [commands.<policy>], before path-scope merging.
    #[arg(long)]
    pub policy: String,
    /// Compose project directory to pass to docker compose.
    #[arg(long)]
    pub project_directory: Option<PathBuf>,
    /// Compose profile to pass to docker compose. May be repeated.
    #[arg(long)]
    pub profile: Vec<String>,
    /// Docker Compose command and arguments after `--`.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
struct UnlockArgs {
    /// Require local user verification before unlock.
    #[arg(long)]
    verify_user: bool,
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// Create a profile.
    Create(ProfileNameArgs),
    /// List profiles.
    List,
    /// Mark a profile as dangerous.
    MarkDangerous(ProfileNameArgs),
    /// Clear dangerous-profile marking.
    ClearDangerous(ProfileNameArgs),
}

#[derive(Debug, Args)]
struct ProfileNameArgs {
    /// Profile name.
    profile: String,
}

#[derive(Debug, Args)]
struct ShellenvArgs {
    /// Shell syntax to emit.
    #[arg(long, value_enum)]
    shell: Option<ShellArg>,
}

#[derive(Debug, Args)]
struct HookArgs {
    /// Shell syntax to emit.
    #[arg(long, value_enum)]
    shell: Option<ShellArg>,
    /// Describe installation status. Full agent-backed install is not available in this build.
    #[arg(long)]
    install: bool,
}

#[derive(Debug, Args)]
struct DenyArgs {
    /// Revoke every durable directory grant for this project across profiles.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ShellArg {
    /// Bourne Again Shell syntax.
    Bash,
    /// Z shell syntax.
    Zsh,
    /// Fish shell syntax.
    Fish,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// Trust the current project root.
    TrustRoot,
    /// List trusted roots.
    ListRoots,
    /// Remove a trusted root.
    UntrustRoot {
        /// Trusted root hash.
        root_hash: String,
    },
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// Scan staged Git content.
    #[arg(long)]
    staged: bool,
    /// Require known-value coverage.
    #[arg(long)]
    require_known: bool,
    /// Ignore .gitignore rules.
    #[arg(long)]
    no_gitignore: bool,
    /// Optional path to scan.
    path: Option<String>,
}

#[derive(Debug, Args)]
struct RedactArgs {
    /// File to redact.
    file: Option<String>,
    /// Read from stdin.
    #[arg(long, conflicts_with = "file")]
    stdin: bool,
    /// Require known-value coverage; fails when the vault cannot supply known values.
    #[arg(long)]
    require_known: bool,
    #[command(flatten)]
    redact_names: RedactNamesArgs,
}

#[derive(Debug, Args)]
struct ContextArgs {
    #[command(flatten)]
    redact_names: RedactNamesArgs,
    /// Emit resolved project identity for trusted local integrations.
    #[arg(long, hide = true, conflicts_with = "redact_names")]
    json: bool,
}

#[derive(Debug, Args)]
struct RedactNamesArgs {
    /// Use privacy aliases instead of secret names.
    #[arg(long)]
    redact_names: bool,
}

#[derive(Debug, Args)]
struct AiSafeArgs {
    /// Use pattern-only redaction without known-value coverage.
    #[arg(long)]
    pattern_only: bool,
    /// Combined redacted transcript path.
    #[arg(long)]
    output: Option<String>,
    /// Overwrite an existing transcript path after confirmation.
    #[arg(long)]
    force: bool,
    #[command(flatten)]
    redact_names: RedactNamesArgs,
    /// Command and arguments after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct RotateArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
    #[command(flatten)]
    metadata: SecretMetadataFlags,
    /// Grace TTL for the prior version.
    #[arg(long)]
    grace_ttl: Option<String>,
}

#[derive(Debug, Args)]
struct SecretMetaArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
    #[command(flatten)]
    metadata: SecretMetadataFlags,
}

#[derive(Debug, Args)]
struct HistoryArgs {
    /// Secret key name.
    key: String,
    /// Profile to inspect.
    #[arg(long)]
    profile: Option<String>,
    /// Restrict the listing to a single runtime source.
    #[arg(long, value_enum)]
    source: Option<SecretSourceArg>,
    /// Restrict the listing to versions in a single state.
    #[arg(long, value_enum)]
    state: Option<HistoryStateFilter>,
    /// Maximum number of versions to display per source.
    #[arg(long)]
    limit: Option<u32>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum HistoryStateFilter {
    /// Current/active versions only.
    Current,
    /// Deprecated versions only.
    Deprecated,
    /// Purged versions only.
    Purged,
}

impl HistoryStateFilter {
    fn matches(self, state: &str) -> bool {
        match self {
            Self::Current => state == "current",
            Self::Deprecated => state == "deprecated",
            Self::Purged => state == "purged",
        }
    }
}

#[derive(Debug, Args)]
struct DiffArgs {
    /// First profile, unless --since is used.
    profile_a: Option<String>,
    /// Second profile, unless --since is used.
    profile_b: Option<String>,
    /// Show changes since an ISO date or Git revision.
    #[arg(long)]
    since: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct CopyArgs {
    /// Secret key name.
    pub(crate) key: String,
    /// Source profile name.
    #[arg(long)]
    pub(crate) from: String,
    /// Target profile name.
    #[arg(long)]
    pub(crate) to: String,
    /// Runtime source to copy from.
    #[arg(long, value_enum)]
    pub(crate) from_source: Option<SecretSourceArg>,
    /// Runtime source to copy to.
    #[arg(long, value_enum)]
    pub(crate) to_source: Option<SecretSourceArg>,
}

#[derive(Clone, Debug, Subcommand)]
enum AgentCommand {
    /// Start the local agent.
    Start(AgentStartArgs),
    /// Print agent status.
    Status,
    /// Stop the local agent.
    Stop,
    /// Print redacted agent logs.
    Logs(AgentLogsArgs),
    /// Exchange paste-friendly setup invites between local agents.
    Invite {
        /// Agent invite command.
        #[command(subcommand)]
        command: AgentInviteCommand,
    },
}

#[derive(Clone, Debug, Args)]
struct AgentStartArgs {
    /// Refuse startup unless native lock/sleep monitoring is active.
    #[arg(long)]
    require_session_monitoring: bool,
}

#[derive(Clone, Debug, Args)]
struct AgentLogsArgs {
    /// Number of lines to print.
    #[arg(long, default_value_t = 200)]
    lines: usize,
    /// RFC 3339 UTC timestamp or Unix timestamp in seconds/nanoseconds to filter from.
    #[arg(long)]
    since: Option<String>,
    /// Stream new log entries until interrupted.
    #[arg(long)]
    follow: bool,
}

#[derive(Clone, Debug, Subcommand)]
enum AgentInviteCommand {
    /// Print this device descriptor and a pasteable invite command for an issuer.
    Request(AgentInviteRequestArgs),
    /// Create a sealed invite and print a pasteable accept command for the recipient.
    Create(AgentInviteCreateArgs),
    /// Accept a sealed invite file or stdin payload.
    Accept(TeamAcceptArgs),
}

#[derive(Clone, Debug, Args)]
struct AgentInviteRequestArgs {
    /// Device descriptor to package into a request. Defaults to the active local device.
    #[arg(long)]
    device: Option<String>,
    /// Recipient label to suggest in the issuer's create command.
    #[arg(long)]
    label: Option<String>,
    /// Profile name to request. May be repeated; defaults to the active project profile.
    #[arg(long = "profile")]
    profiles: Vec<String>,
    /// Role to request from the issuer.
    #[arg(long, value_enum, default_value = "developer")]
    role: TeamRoleArg,
    /// Suggested invite validity duration, for example 5m, 2h, or 30d.
    #[arg(long)]
    expires_in: Option<String>,
}

#[derive(Clone, Debug, Args)]
struct AgentInviteCreateArgs {
    /// Human-readable recipient agent or device label.
    name: String,
    /// Recipient device descriptor emitted by `locket agent invite request`.
    #[arg(long)]
    device: String,
    /// Profile name to include in the invite. May be repeated.
    #[arg(long = "profile", required = true)]
    profiles: Vec<String>,
    /// Role to grant when the invite is accepted.
    #[arg(long, value_enum)]
    role: TeamRoleArg,
    /// Invite validity duration, for example 5m, 2h, or 30d.
    #[arg(long)]
    expires_in: Option<String>,
    /// Write the invite file to this path.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum DebugCommand {
    /// Emit a redacted metadata-only support bundle summary.
    Bundle(DebugBundleArgs),
}

#[derive(Debug, Args)]
struct DebugBundleArgs {
    /// Confirm that only redacted metadata may be emitted.
    #[arg(long)]
    redacted: bool,
    /// Write bundle summary to this path instead of stdout.
    #[arg(long)]
    output: Option<String>,
}

#[derive(Clone, Debug, Subcommand)]
enum AuditCommand {
    /// Verify the local audit HMAC chain.
    Verify {
        /// Require the chain to extend an independently retained checkpoint.
        #[arg(long, value_name = "FILE")]
        checkpoint: Option<PathBuf>,
    },
    /// Save an authenticated audit checkpoint for independent retention.
    Checkpoint {
        /// Create a new checkpoint file; existing files are never overwritten.
        #[arg(long, value_name = "FILE")]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// List configured non-secret preferences.
    List,
    /// Get a configured non-secret preference.
    Get(ConfigKeyArgs),
    /// Set a non-secret preference.
    Set(ConfigSetArgs),
    /// Unset a non-secret preference.
    Unset(ConfigKeyArgs),
}

#[derive(Debug, Args)]
struct ConfigKeyArgs {
    /// Config key.
    key: String,
}

#[derive(Debug, Args)]
struct ConfigSetArgs {
    /// Config key.
    key: String,
    /// Config value.
    value: String,
}

#[derive(Debug, Subcommand)]
enum PasskeyCommand {
    /// Register a passkey authenticator.
    Register(PasskeyRegisterArgs),
    /// List passkey authenticators.
    List(PasskeyListArgs),
    /// Remove a passkey authenticator.
    Remove {
        /// Passkey label or credential id prefix.
        passkey: String,
    },
    /// Unlock the project master key using a registered passkey PRF wrap.
    Unlock {
        /// Optional passkey label or credential id prefix.
        passkey: Option<String>,
    },
}

#[derive(Debug, Args)]
struct PasskeyRegisterArgs {
    /// Human-readable label for this passkey.
    #[arg(long)]
    label: String,
    /// `WebAuthn` relying party id used during registration.
    #[arg(long, default_value = locket_store::DEFAULT_WEBAUTHN_RELYING_PARTY_ID)]
    relying_party_id: String,
}

#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// Initialize or rotate the local device descriptor.
    Init(DeviceInitArgs),
    /// Migrate legacy signing material while preserving bundle decryption keys.
    RotateSigning,
    /// Print the active local device descriptor.
    Pubkey,
    /// Add a trusted device descriptor.
    Add(DeviceAddArgs),
    /// List trusted device metadata.
    List(DeviceListArgs),
    /// Revoke a trusted device.
    Remove(DeviceRemoveArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum TeamCommand {
    /// Prepare a fresh device or join an authenticated encrypted team package.
    Join(TeamJoinArgs),
    /// Add a verified device to owner-published team updates.
    Add(TeamAddArgs),
    /// Publish an encrypted signed snapshot to the configured shared folder.
    Publish,
    /// Check or apply authenticated updates from the shared folder.
    Sync {
        #[command(subcommand)]
        command: Option<TeamSyncCommand>,
    },
    /// Choose this machine's shared folder (local consent, never imported).
    Folder(TeamFolderArgs),
    /// Initialize a team for this project.
    Init(TeamInitArgs),
    /// Create a signed team invite for a recipient device.
    Invite(TeamInviteArgs),
    /// Revoke a pending team invite.
    #[command(name = "revoke-invite")]
    RevokeInvite(TeamRevokeInviteArgs),
    /// Accept a signed team invite.
    Accept(TeamAcceptArgs),
    /// List team members and pending invites.
    Members,
    /// Remove a member from the team.
    Remove(TeamRemoveArgs),
    /// Revoke a team member's device.
    #[command(name = "revoke-device")]
    RevokeDevice(TeamRevokeDeviceArgs),
}

#[derive(Debug, Args)]
pub(crate) struct TeamJoinArgs {
    /// Generate a receiving device descriptor without creating shared profile keys.
    #[arg(long, conflicts_with_all = ["package", "owner", "folder"])]
    pub request: bool,
    /// Encrypted .lkpkg provided by the owner.
    #[arg(required_unless_present_any = ["request", "folder"])]
    pub package: Option<PathBuf>,
    /// Full owner fingerprint verified through a separate trusted channel.
    #[arg(long, required_unless_present = "request")]
    pub owner: Option<String>,
    /// Opt into automatic updates from this shared folder after joining.
    #[arg(long)]
    pub folder: Option<PathBuf>,
    /// Explicitly permit dangerous profile values and later folder updates on this machine.
    #[arg(long)]
    pub allow_dangerous: bool,
}

#[derive(Debug, Args)]
pub(crate) struct TeamAddArgs {
    pub name: String,
    /// lkdev2_ descriptor received from the joining device.
    #[arg(long)]
    pub device: String,
    /// Full joining-device fingerprint verified independently of its descriptor.
    #[arg(long)]
    pub confirm_device_fingerprint: String,
    #[arg(long = "profile", required = true)]
    pub profiles: Vec<String>,
    #[arg(long, value_enum, default_value = "developer")]
    pub role: TeamRoleArg,
}

#[derive(Debug, Subcommand)]
pub(crate) enum TeamSyncCommand {
    /// Review held profiles, collision IDs and setup guidance without revealing values.
    Pending,
    /// Rename a local colliding profile, preserving its ID, keys and values.
    #[command(after_help = commands::team::sync::PROFILE_RENAME_CONSEQUENCES)]
    RenameLocalProfile {
        /// Held incoming profile ID shown by `team sync pending`.
        incoming_profile_id: String,
        /// Local colliding profile ID shown by `team sync pending`.
        local_profile_id: String,
        /// New name for the existing local profile, such as personal-dev.
        new_name: String,
    },
    /// Preserve one colliding local value as a personal override before retrying a held profile.
    KeepLocalValue {
        /// Held incoming profile ID shown by `team sync pending`.
        incoming_profile_id: String,
        /// Local colliding secret ID shown by `team sync pending`; never pass its value.
        local_secret_id: String,
    },
    /// Apply available signed updates using this machine's unlocked keys.
    Now,
    /// Show last verified update and any blocked or conflicting updates.
    Status,
    /// Resolve a conflicting value by keeping a personal override or accepting the team value.
    Resolve {
        /// Value-conflict secret ID shown by sync status; held profiles use the pending commands.
        secret: String,
        #[arg(value_enum)]
        choice: TeamConflictChoice,
    },
    /// Disable automatic updates without forgetting the authenticated head.
    Disable,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum TeamConflictChoice {
    KeepLocal,
    TakeTeam,
}

#[derive(Debug, Args)]
pub(crate) struct TeamFolderArgs {
    pub path: PathBuf,
    #[arg(long)]
    pub allow_dangerous: bool,
}

#[derive(Debug, Args)]
pub(crate) struct TeamInitArgs {
    /// Human-readable team name.
    pub name: String,
}

#[derive(Debug, Args)]
pub(crate) struct TeamInviteArgs {
    /// Human-readable recipient name.
    pub name: String,
    /// Recipient device descriptor emitted by `locket device pubkey`.
    #[arg(long)]
    pub device: String,
    /// Profile name to include in the invite. May be repeated.
    #[arg(long = "profile", required = true)]
    pub profiles: Vec<String>,
    /// Role to grant when the invite is accepted.
    #[arg(long, value_enum)]
    pub role: TeamRoleArg,
    /// Invite validity duration, for example 5m, 2h, or 30d.
    #[arg(long)]
    pub expires_in: Option<String>,
    /// Write the invite file to this path.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct TeamRevokeInviteArgs {
    /// Invite id to revoke.
    pub invite_id: String,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct TeamAcceptArgs {
    /// Invite file to accept.
    pub invite: PathBuf,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum TeamRoleArg {
    Owner,
    Maintainer,
    Developer,
    #[value(name = "read-only", alias = "read_only")]
    ReadOnly,
}

#[derive(Debug, Args)]
pub(crate) struct TeamRemoveArgs {
    /// Member display name or member id to remove.
    pub member: String,
}

#[derive(Debug, Args)]
pub(crate) struct TeamRevokeDeviceArgs {
    /// Device name, id, or fingerprint to revoke.
    pub device: String,
}

#[derive(Debug, Args)]
struct DeviceInitArgs {
    /// Replace the active local device descriptor.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct DeviceAddArgs {
    /// Human-readable device name.
    name: String,
    /// Device descriptor emitted by `locket device pubkey`.
    #[arg(long)]
    device: String,
}

#[derive(Debug, Args)]
struct DeviceListArgs {
    /// Include revoked devices.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct DeviceRemoveArgs {
    /// Device name, id, or fingerprint.
    device: String,
    /// Permit removing the active local device.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Subcommand)]
enum ClientCommand {
    /// Create a Locket-managed automation client metadata record.
    Create(ClientCreateArgs),
    /// Add an externally managed automation client public key.
    Add(ClientAddArgs),
    /// List registered automation clients.
    List(ClientListArgs),
    /// Revoke an automation client.
    Revoke {
        /// Client name or id.
        client: String,
    },
}

#[derive(Debug, Args)]
struct ClientCreateArgs {
    /// Client display name.
    name: String,
    /// Locket-managed private-key storage mode metadata.
    #[arg(long, value_enum, default_value_t = ClientStorageArg::OsKeychain)]
    storage: ClientStorageArg,
    /// Allowed automation action. May be repeated.
    #[arg(long = "action")]
    actions: Vec<String>,
    /// Allowed command policy. May be repeated.
    #[arg(long = "policy")]
    policies: Vec<String>,
}

#[derive(Debug, Args)]
struct ClientAddArgs {
    /// Client display name.
    name: String,
    /// Ed25519 public key as 64 lowercase or uppercase hex characters.
    #[arg(long)]
    pubkey: String,
    /// Allowed automation action. May be repeated.
    #[arg(long = "action")]
    actions: Vec<String>,
    /// Allowed command policy. May be repeated.
    #[arg(long = "policy")]
    policies: Vec<String>,
}

#[derive(Debug, Args)]
struct ClientListArgs {
    /// Include revoked clients.
    #[arg(long)]
    all: bool,
}

// These are independent command-line opt-ins.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Args)]
struct ExportArgs {
    /// Require sealed-bundle mode.
    #[arg(long)]
    sealed: bool,
    /// Recipient device descriptor. May be repeated.
    #[arg(long = "recipient", required = true)]
    recipients: Vec<String>,
    /// Profile to include. Defaults to the active profile.
    #[arg(long, conflicts_with = "all_profiles")]
    profile: Option<String>,
    /// Include all profiles.
    #[arg(long)]
    all_profiles: bool,
    /// Include personal secret sources.
    #[arg(long)]
    include_personal: bool,
    /// Include historical encrypted secret versions.
    #[arg(long)]
    include_history: bool,
    /// Include encrypted remote audit rows in the bundle payload.
    #[arg(long)]
    include_audit: bool,
    /// Output path. Defaults to locket-bundle-<utc-timestamp>.locket-bundle.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ImportBundleArgs {
    /// Bundle file to import.
    bundle: PathBuf,
    /// Import remote audit rows when present.
    #[arg(long)]
    include_audit: bool,
    /// Prefer incoming metadata on conflicts.
    #[arg(long, conflicts_with = "accept_local")]
    accept_incoming: bool,
    /// Prefer local metadata on conflicts.
    #[arg(long)]
    accept_local: bool,
}

#[derive(Debug, Subcommand)]
enum BundleCommand {
    /// Verify a sealed bundle without importing it.
    Verify(BundleVerifyArgs),
}

#[derive(Debug, Args)]
struct BundleVerifyArgs {
    /// Bundle file to verify.
    bundle: PathBuf,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ClientStorageArg {
    /// Store client private key in the OS keychain.
    OsKeychain,
    /// Store a wrapped local private-key file.
    WrappedLocalFile,
}

impl ClientStorageArg {
    const fn as_str(self) -> &'static str {
        match self {
            Self::OsKeychain => "os-keychain",
            Self::WrappedLocalFile => "wrapped-local-file",
        }
    }
}

#[derive(Debug, Args)]
struct PasskeyListArgs {
    /// Include revoked credentials.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct RecoverArgs {
    /// Overwrite an existing master key entry.
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum RecoveryCommand {
    /// Rotate the recovery code.
    Rotate,
}

#[derive(Debug, Args)]
struct SourceArg {
    /// Runtime source to target.
    #[arg(long, value_enum)]
    source: Option<SecretSourceArg>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum SecretSourceArg {
    /// Team-managed source.
    TeamManaged,
    /// User-local source.
    UserLocal,
    /// Machine-local source.
    MachineLocal,
}

#[derive(Debug, Args)]
struct SecretMetadataFlags {
    /// Metadata description.
    #[arg(long)]
    description: Option<String>,
    /// Metadata owner.
    #[arg(long)]
    owner: Option<String>,
    /// Metadata tag. May be repeated.
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Mark secret required.
    #[arg(long, conflicts_with = "optional")]
    required: bool,
    /// Mark secret optional.
    #[arg(long)]
    optional: bool,
}

fn main() -> ProcessExitCode {
    // Suppress core dumps and lock memory pages before any secret
    // material can be unwrapped into this process. A degraded
    // hardening state is not a startup failure; diagnostics surface
    // hardening gaps separately.
    let _ = locket_platform::disable_core_dumps();
    let _ = locket_platform::lock_process_memory();
    // keyring-core 1.0 requires registering a credential store before any
    // Entry can resolve. A failure here surfaces later as the same error
    // from whichever command first touches the keychain.
    let _ = locket_platform::init_platform_keyring();

    let cli = Cli::parse();
    if let Some(Command::Completion(args)) = &cli.command {
        let mut output = io::stdout();
        return match completion_command(&mut output, args.shell) {
            Ok(()) => ProcessExitCode::SUCCESS,
            Err(error) => write_error_and_exit(&error),
        };
    }

    let context = match RuntimeContext::default() {
        Ok(context) => context,
        Err(error) => {
            return write_error_and_exit(&error);
        }
    };

    let mut output = io::stdout();
    match run_with_context(cli, &context, &mut output) {
        Ok(code) => ProcessExitCode::from(code),
        Err(error) => write_error_and_exit(&error),
    }
}

fn write_error_and_exit(error: &CliError) -> ProcessExitCode {
    let mut stderr = io::stderr();
    let _ignored = writeln!(stderr, "locket: {error}");
    ProcessExitCode::from(error.exit_code())
}

// Keep the command routing table together; each arm delegates its behavior.
#[allow(clippy::too_many_lines)]
fn run_with_context(
    cli: Cli,
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<u8, CliError> {
    use commands::{
        agent, audit, config, debug, diagnostics, exec, policy, project, scan, secrets, shell,
        team, trust, vault,
    };

    let command = cli.command.unwrap_or(Command::Status { scan: false });

    // The master-key cache is scoped to a single CLI invocation. In
    // production each invocation gets a fresh `RuntimeContext`; tests
    // reuse one context across multiple runs, so clear it here to keep
    // semantics consistent (deleting an OS-stored master key between
    // runs must invalidate any previously cached unlock).
    context.master_key_cache.clear();

    match command {
        Command::Status { scan } => project::status::status_with_scan(context, output, scan)?,
        Command::New(args) => new_command(context, output, &args)?,
        Command::Bootstrap => project::bootstrap::bootstrap_command(context, output)?,
        Command::Setup { command } => project::setup::setup_command(context, output, command)?,
        Command::Completion(args) => completion_command(output, args.shell)?,
        Command::Doctor(args) => {
            return diagnostics::doctor_command(
                context,
                output,
                args.prune_runtime_session_secret_names,
            );
        }
        Command::Debug { command } => debug::debug_command(context, output, command)?,
        Command::Init(args) => project::init::init(context, output, args)?,
        Command::Set(args) => secrets::set::set_command(context, output, &args)?,
        Command::Import(args) => secrets::import::import_command(context, output, &args)?,
        Command::Get(args) => secrets::get::get_command(context, output, &args)?,
        Command::Reveal(args) => secrets::get::get_command(
            context,
            output,
            &GetArgs {
                key: args.key,
                source: args.source,
                reveal: true,
                force: args.force,
                copy: false,
                verify_user: args.verify_user,
                use_dangerous: args.use_dangerous,
            },
        )?,
        Command::Cp(args) => secrets::get::get_command(
            context,
            output,
            &GetArgs {
                key: args.key,
                source: args.source,
                reveal: false,
                force: false,
                copy: true,
                verify_user: args.verify_user,
                use_dangerous: args.use_dangerous,
            },
        )?,
        Command::Rm(args) => secrets::lifecycle::rm_command(context, output, &args)?,
        Command::Purge(args) => secrets::lifecycle::purge_command(context, output, &args)?,
        Command::List(args) => secrets::lifecycle::list_command(context, output, &args)?,
        Command::Exec(args) => exec::exec::exec_command(context, output, &args)?,
        Command::Run(args) => exec::run::run_command(context, output, &args)?,
        Command::Env { command } => exec::env::env_command(context, output, command)?,
        Command::Compose { command } => exec::compose::compose_command(context, output, command)?,
        Command::Rotate(args) => secrets::lifecycle::rotate_command(context, output, &args)?,
        Command::Meta(args) => secrets::meta::meta_command(context, output, &args)?,
        Command::History(args) => secrets::lifecycle::history_command(context, output, &args)?,
        Command::Diff(args) => scan::diff::diff_command(context, output, &args)?,
        Command::Copy(args) => secrets::lifecycle::copy_command(context, output, &args)?,
        Command::Audit { command } => audit::audit_command(context, output, command)?,
        Command::Lock => vault::lock::lock_command(context, output)?,
        Command::Unlock(args) => vault::lock::unlock_command(context, output, &args)?,
        Command::EmitExample => project::emit_example::emit_example_command(context, output)?,
        Command::InstallHooks => project::install_hooks::install_hooks_command(context, output)?,
        Command::Profile { command } => trust::profile::profile_command(context, output, command)?,
        Command::Policy { command } => policy::command(context, output, command)?,
        Command::Project { command } => trust::project::project_command(context, output, command)?,
        Command::Shellenv(args) => shell::shellenv_command(output, &args)?,
        Command::Hook(args) => shell::hook_command(context, output, &args)?,
        Command::Allow => shell::allow_command(context, output)?,
        Command::Deny(args) => shell::deny_command(context, output, &args)?,
        Command::Agent { command } => agent::agent_command(context, output, command)?,
        Command::Use(args) => trust::profile::use_profile_command(context, output, args)?,
        Command::Scan(args) => scan::scanner::scan_command(context, output, &args)?,
        Command::Redact(args) => scan::redact::redact_command(context, output, &args)?,
        Command::Context(args) => {
            if args.json {
                scan::context::context_json_command(context, output)?;
            } else {
                scan::context::context_command(context, output, &args.redact_names)?;
            }
        }
        Command::AiSafe(args) => scan::redact::ai_safe_command(context, output, &args)?,
        Command::Config { command } => config::config_command(context, output, command)?,
        Command::Passkey { command } => vault::passkey::passkey_command(context, output, command)?,
        Command::Device { command } => team::device::device_command(context, output, command)?,
        Command::Team { command } => team::members::team_command(context, output, command)?,
        Command::Client { command } => team::client::client_command(context, output, command)?,
        Command::Export(args) => team::bundle::export_bundle_command(context, output, &args)?,
        Command::ImportBundle(args) => team::bundle::import_bundle_command(context, output, &args)?,
        Command::Bundle { command } => team::bundle::bundle_command(context, output, command)?,
        Command::Recover(args) => vault::recovery::recover_command(context, output, &args)?,
        Command::Recovery { command } => {
            vault::recovery::recovery_command(context, output, command)?;
        }
        Command::InternalAgentServe(args) => agent::run_internal_agent_serve(&args)?,
        Command::InternalClipboardClear(args) => {
            secrets::get::run_internal_clipboard_clear(args.ttl_seconds)?;
        }
    }

    Ok(0)
}

fn completion_command(output: &mut impl Write, shell: CompletionShell) -> Result<(), CliError> {
    let mut command = Cli::command();
    let mut buffer = Vec::new();
    clap_complete::generate(shell, &mut command, "locket", &mut buffer);
    output.write_all(&buffer)?;
    Ok(())
}

fn new_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &NewArgs,
) -> Result<(), CliError> {
    if resolve_project(&context.cwd)?.is_some() {
        return Err(secret_already_exists_error("project already initialized"));
    }
    let config_path = context.cwd.join(LOCKET_TOML);
    if config_path.exists() {
        return Err(metadata_invalid_error("locket.toml already exists but could not be resolved"));
    }

    let template = commands::project::onboarding::load_project_template(
        &context.template_dir,
        &args.from_template,
    )?;
    let rendered = template.render_project_config(template.name.clone())?;
    fs::write(&config_path, rendered)?;
    let config = read_project_config(&config_path)?;
    let mut store = open_store(context)?;
    let timestamp = now_unix_nanos()?;
    let mut master_key_source = MasterKeySource::OsKeyStore;

    if let Err(error) = (|| -> Result<(), CliError> {
        ensure_project_metadata(&store, &config, timestamp)?;
        master_key_source = initialize_project_keys(context, &store, &config, timestamp)?;
        ensure_template_profiles(context, &store, &config, &template, timestamp)?;
        trust_root(&store, &config, &context.cwd, timestamp)?;
        ensure_gitignore(&context.cwd)?;
        write_example_block(&context.cwd, &template.expected_secrets)?;
        write_new_audit(context, &mut store, &config, &template, &args.from_template, timestamp)?;
        Ok(())
    })() {
        let _ignored = fs::remove_file(&config_path);
        return Err(error);
    }

    if support::style::enabled() {
        support::style::write_banner(output, "project", "initialized from template")?;
        support::style::write_kv(output, "project_id", config.project_id.as_str())?;
        support::style::write_kv(output, "template", args.from_template.as_str())?;
        support::style::write_kv(output, "template_source", template.source.label())?;
        support::style::write_kv(output, "default_profile", config.default_profile.as_str())?;
        support::style::write_kv(output, "master_key_source", master_key_source.as_str())?;
        support::style::write_kv(output, "profiles", template.profiles.len())?;
        support::style::write_kv(output, "expected_secrets", template.expected_secrets.len())?;
        support::style::write_kv(output, "commands", template.command_count())?;
        support::style::write_kv(output, "secrets", "not written")?;
    } else {
        writeln!(output, "initialized locket project {}", config.project_id)?;
        writeln!(output, "template: {}", args.from_template)?;
        writeln!(output, "template_source: {}", template.source.label())?;
        writeln!(output, "default_profile: {}", config.default_profile)?;
        writeln!(output, "master_key_source: {}", master_key_source.as_str())?;
        writeln!(output, "profiles: {}", template.profiles.len())?;
        writeln!(output, "expected_secrets: {}", template.expected_secrets.len())?;
        writeln!(output, "commands: {}", template.command_count())?;
        writeln!(output, "secrets: not written")?;
    }
    Ok(())
}

fn write_new_audit(
    context: &RuntimeContext,
    store: &mut Store,
    config: &ProjectConfig,
    template: &commands::project::onboarding::ProjectTemplate,
    requested_template: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let audit_key =
        load_project_key(context, store, config.project_id.as_str(), KeyPurpose::Audit)?;
    let profile = default_profile(store, config)?;
    let mut generated_files = Vec::new();
    if context.cwd.join(".gitignore").exists() {
        generated_files.push(GITIGNORE_FILE);
    }
    if context.cwd.join(".env.example").exists() {
        generated_files.push(EXAMPLE_FILE);
    }
    let template_source_kind = match &template.source {
        commands::project::onboarding::TemplateSource::BuiltIn => "built-in",
        commands::project::onboarding::TemplateSource::Local(_) => "local",
    };
    let metadata = json!({
        "schema_version": 1,
        "action": "INIT",
        "status": "SUCCESS",
        "command": "new",
        "project_id": config.project_id.as_str(),
        "default_profile_id": profile.id,
        "template_name": requested_template,
        "template_source_kind": template_source_kind,
        "profile_count": template.profiles.len(),
        "expected_secret_count": template.expected_secrets.len(),
        "command_count": template.command_count(),
        "trust_root_recorded": true,
        "generated_files": generated_files,
    });
    let audit = AuditWrite {
        project_id: config.project_id.as_str(),
        profile_id: Some(&profile.id),
        action: "INIT",
        status: "SUCCESS",
        secret_name: None,
        command: Some("new"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

pub(crate) fn active_profile_secret_names(
    store: &Store,
    project_id: &str,
    profile_id: &str,
) -> Result<BTreeSet<String>, CliError> {
    Ok(store
        .list_active_secrets_by_profile(project_id, profile_id)?
        .into_iter()
        .map(|secret| secret.name)
        .collect())
}

pub(crate) const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

pub(crate) fn ensure_project_metadata(
    store: &Store,
    config: &ProjectConfig,
    timestamp: i64,
) -> Result<(), CliError> {
    store.insert_project_if_absent(config.project_id.as_str(), &config.name, timestamp)?;
    if store
        .get_profile_by_name(config.project_id.as_str(), config.default_profile.as_str())?
        .is_none()
    {
        let profile_id = ProfileId::generate().map_err(|_| CliError::Time)?;
        store.insert_profile_if_absent(
            profile_id.as_str(),
            config.project_id.as_str(),
            config.default_profile.as_str(),
            false,
            timestamp,
        )?;
    }
    Ok(())
}

fn ensure_template_profiles(
    context: &RuntimeContext,
    store: &Store,
    config: &ProjectConfig,
    template: &commands::project::onboarding::ProjectTemplate,
    timestamp: i64,
) -> Result<(), CliError> {
    for profile_name in &template.profiles {
        if store.get_profile_by_name(config.project_id.as_str(), profile_name.as_str())?.is_some() {
            continue;
        }
        let profile_id = ProfileId::generate().map_err(|_| CliError::Time)?;
        store.insert_profile_if_absent(
            profile_id.as_str(),
            config.project_id.as_str(),
            profile_name.as_str(),
            false,
            timestamp,
        )?;
        initialize_profile_keys(context, store, config, profile_id.as_str(), timestamp)?;
    }
    Ok(())
}

fn initialize_project_keys(
    context: &RuntimeContext,
    store: &Store,
    config: &ProjectConfig,
    timestamp: i64,
) -> Result<MasterKeySource, CliError> {
    let master_key = generate_key()?;
    let source = store_master_key_with_fallback(
        context,
        config.project_id.as_str(),
        &master_key,
        timestamp,
    )?;
    insert_wrapped_key(
        store,
        config.project_id.as_str(),
        None,
        KeyPurpose::ProjectMetadata,
        &master_key,
        timestamp,
    )?;
    insert_wrapped_key(
        store,
        config.project_id.as_str(),
        None,
        KeyPurpose::Audit,
        &master_key,
        timestamp,
    )?;
    let profile = default_profile(store, config)?;
    initialize_profile_keys_with_master(store, config, &profile.id, &master_key, timestamp)?;
    Ok(source)
}

fn initialize_profile_keys(
    context: &RuntimeContext,
    store: &Store,
    config: &ProjectConfig,
    profile_id: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let (master_key, _) = load_master_key_verified_by_project_key(
        context,
        store,
        config.project_id.as_str(),
        KeyPurpose::ProjectMetadata,
    )?;
    initialize_profile_keys_with_master(store, config, profile_id, &master_key, timestamp)
}

fn initialize_profile_keys_with_master(
    store: &Store,
    config: &ProjectConfig,
    profile_id: &str,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<(), CliError> {
    insert_wrapped_key(
        store,
        config.project_id.as_str(),
        Some(profile_id),
        KeyPurpose::ProfileSecret,
        master_key,
        timestamp,
    )?;
    insert_wrapped_key(
        store,
        config.project_id.as_str(),
        Some(profile_id),
        KeyPurpose::ProfileFingerprint,
        master_key,
        timestamp,
    )?;
    Ok(())
}

pub(crate) fn insert_wrapped_key(
    store: &Store,
    project_id: &str,
    profile_id: Option<&str>,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<(), CliError> {
    let key_id = KeyId::generate().map_err(|_| CliError::Time)?;
    let key_material = generate_key()?;
    let wrapping_key =
        derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(project_id, profile_id, purpose))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        key_id.as_str(),
        profile_id,
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = wrap_key_material_v1(&wrapping_key, &key_material, &aad)?;
    store.insert_key(&KeyRecord {
        id: key_id.into_string(),
        project_id: project_id.to_owned(),
        profile_id: profile_id.map(ToOwned::to_owned),
        purpose: purpose.as_str().to_owned(),
        wrapped_material: wrapped.ciphertext,
        nonce: wrapped.nonce,
        created_at: timestamp,
    })?;
    Ok(())
}

fn preflight_rotate_secret_value(
    context: &RuntimeContext,
    args: &RotateArgs,
) -> Result<(), CliError> {
    let name = SecretName::new(args.key.clone())
        .map_err(|err| invalid_secret_name_error(err.to_string()))?;
    resolve_active_secret_for_source(context, name.as_str(), args.source.source)?;
    Ok(())
}

fn rotate_secret_value(
    context: &RuntimeContext,
    args: &RotateArgs,
    value: &str,
    timestamp: i64,
    grace_until: Option<i64>,
) -> Result<(String, u32), CliError> {
    let name = SecretName::new(args.key.clone())
        .map_err(|err| invalid_secret_name_error(err.to_string()))?;
    validate_secret_value_str(value)?;
    let resolved_secret =
        resolve_active_secret_for_source(context, name.as_str(), args.source.source)?;
    let new_version = next_secret_version(resolved_secret.secret.current_version)?;
    let mut store = open_store(context)?;
    let audit_key = load_project_key(
        context,
        &store,
        resolved_secret.project.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let (encrypted, fingerprint) = encrypt_secret_version(
        context,
        &store,
        SecretEncryptRequest {
            project_id: resolved_secret.project.config.project_id.as_str(),
            profile_id: &resolved_secret.profile.id,
            secret_id: &resolved_secret.secret.id,
            secret_name: &resolved_secret.secret.name,
            version: new_version,
            value,
        },
    )?;
    let source = resolved_secret.secret.source.clone();
    let origin = resolved_secret.secret.origin.clone();
    let metadata = json!({
        "schema_version": 1,
        "action": "ROTATE",
        "status": "SUCCESS",
        "secret_name": &resolved_secret.secret.name,
        "profile_id": &resolved_secret.profile.id,
        "source": &source,
        "prior_version": resolved_secret.secret.current_version,
        "deprecated_version": resolved_secret.secret.current_version,
        "target_version": new_version,
        "deprecated_at": timestamp,
        "grace_until": grace_until,
    });
    let audit = AuditWrite {
        project_id: resolved_secret.project.config.project_id.as_str(),
        profile_id: Some(&resolved_secret.profile.id),
        action: "ROTATE",
        status: "SUCCESS",
        secret_name: Some(&resolved_secret.secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };

    store.rotate_secret_with_audit(
        &resolved_secret.secret,
        &SecretVersionRecord {
            secret_id: resolved_secret.secret.id.clone(),
            version: new_version,
            source: source.clone(),
            origin,
            state: "current".to_owned(),
            created_at: timestamp,
            deprecated_at: None,
            grace_until: None,
            purged_at: None,
        },
        &SecretBlobRecord {
            secret_id: resolved_secret.secret.id.clone(),
            version: new_version,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: encrypted.aad_schema_version,
            created_at: timestamp,
        },
        &SecretFingerprintRecord {
            secret_id: resolved_secret.secret.id.clone(),
            version: new_version,
            fingerprint,
            created_at: timestamp,
        },
        VersionDeprecation { deprecated_at: timestamp, grace_until },
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;

    Ok((source, new_version))
}

struct CopySecretResult {
    from_profile: String,
    to_profile: String,
    from_source: String,
    to_source: String,
    from_version: u32,
    target_version: u32,
    prior_target_version: Option<u32>,
    operation: &'static str,
}

struct CopyTargetPlan {
    secret_id: String,
    version: u32,
    prior_version: Option<u32>,
    existing: Option<SecretRecord>,
}

pub(crate) struct CopySelection {
    pub(crate) from_profile: ProfileRecord,
    pub(crate) to_profile: ProfileRecord,
    pub(crate) source_secret: SecretRecord,
    pub(crate) from_source: String,
    pub(crate) to_source: String,
}

#[derive(Clone, Copy)]
struct CopyAuditMetadata<'a> {
    name: &'a str,
    from_profile: &'a ProfileRecord,
    from_source: &'a str,
    from_version: u32,
    to_profile: &'a ProfileRecord,
    to_source: &'a str,
    prior_target_version: Option<u32>,
    target_version: u32,
}

#[derive(Clone, Copy)]
struct CopyWriteRequest<'a> {
    target: &'a CopyTargetPlan,
    project_id: &'a str,
    to_profile_id: &'a str,
    name: &'a str,
    to_source: &'a str,
    timestamp: i64,
    version: &'a SecretVersionRecord,
    blob: &'a SecretBlobRecord,
    fingerprint: &'a SecretFingerprintRecord,
    audit: AuditContext<'a>,
}

fn copy_secret_value(
    context: &RuntimeContext,
    args: &CopyArgs,
    timestamp: i64,
) -> Result<CopySecretResult, CliError> {
    let name = SecretName::new(args.key.clone())
        .map_err(|err| invalid_secret_name_error(err.to_string()))?;
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let project_id = resolved.config.project_id.as_str();
    let selection = select_copy_profiles_and_sources(&store, project_id, name.as_str(), args)?;

    let target = plan_copy_target(
        &store,
        project_id,
        &selection.to_profile.id,
        name.as_str(),
        &selection.to_source,
    )?;
    let value = decrypt_secret_version(
        context,
        &store,
        project_id,
        &selection.from_profile.id,
        &selection.source_secret,
        selection.source_secret.current_version,
    )?;
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let (encrypted, fingerprint) = encrypt_secret_version(
        context,
        &store,
        SecretEncryptRequest {
            project_id,
            profile_id: &selection.to_profile.id,
            secret_id: &target.secret_id,
            secret_name: name.as_str(),
            version: target.version,
            value: value.as_str(),
        },
    )?;
    let metadata = copy_audit_metadata(CopyAuditMetadata {
        name: name.as_str(),
        from_profile: &selection.from_profile,
        from_source: &selection.from_source,
        from_version: selection.source_secret.current_version,
        to_profile: &selection.to_profile,
        to_source: &selection.to_source,
        prior_target_version: target.prior_version,
        target_version: target.version,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: Some(&selection.to_profile.id),
        action: "SECRET_COPY",
        status: "SUCCESS",
        secret_name: Some(name.as_str()),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    let (version, blob, fingerprint) = copied_secret_records(
        &target.secret_id,
        target.version,
        &selection.to_source,
        encrypted,
        fingerprint,
        timestamp,
    );
    let operation = write_copied_secret(
        &mut store,
        CopyWriteRequest {
            target: &target,
            project_id,
            to_profile_id: &selection.to_profile.id,
            name: name.as_str(),
            to_source: &selection.to_source,
            timestamp,
            version: &version,
            blob: &blob,
            fingerprint: &fingerprint,
            audit: AuditContext { key: audit_key.as_ref(), write: &audit },
        },
    )?;

    Ok(CopySecretResult {
        from_profile: selection.from_profile.name,
        to_profile: selection.to_profile.name,
        from_source: selection.from_source,
        to_source: selection.to_source,
        from_version: selection.source_secret.current_version,
        target_version: target.version,
        prior_target_version: target.prior_version,
        operation,
    })
}

fn copy_audit_metadata(request: CopyAuditMetadata<'_>) -> Value {
    json!({
        "schema_version": 1,
        "action": "SECRET_COPY",
        "status": "SUCCESS",
        "secret_name": request.name,
        "from_profile": &request.from_profile.name,
        "from_profile_id": &request.from_profile.id,
        "from_source": request.from_source,
        "from_version": request.from_version,
        "to_profile": &request.to_profile.name,
        "to_profile_id": &request.to_profile.id,
        "to_source": request.to_source,
        "prior_target_version": request.prior_target_version,
        "target_version": request.target_version,
    })
}

fn write_copied_secret(
    store: &mut Store,
    request: CopyWriteRequest<'_>,
) -> Result<&'static str, CliError> {
    if let Some(target_secret) = request.target.existing.as_ref() {
        store.copy_secret_with_audit(
            SecretCopyTarget::Rotate {
                secret: target_secret,
                deprecation: VersionDeprecation {
                    deprecated_at: request.timestamp,
                    grace_until: None,
                },
            },
            request.version,
            request.blob,
            request.fingerprint,
            Some(request.audit),
        )?;
        return Ok("rotate");
    }

    let secret = SecretRecord {
        id: request.target.secret_id.clone(),
        project_id: request.project_id.to_owned(),
        profile_id: request.to_profile_id.to_owned(),
        name: request.name.to_owned(),
        source: request.to_source.to_owned(),
        origin: "profile-copy".to_owned(),
        current_version: request.target.version,
        state: "active".to_owned(),
        created_at: request.timestamp,
        updated_at: request.timestamp,
        last_rotated_at: None,
        deleted_at: None,
    };
    store.copy_secret_with_audit(
        SecretCopyTarget::Create(&secret),
        request.version,
        request.blob,
        request.fingerprint,
        Some(request.audit),
    )?;
    Ok("create")
}

fn plan_copy_target(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    name: &str,
    source: &str,
) -> Result<CopyTargetPlan, CliError> {
    let existing = store.get_secret_by_source(project_id, profile_id, name, source)?;
    if existing.as_ref().is_some_and(|secret| secret.state == "deleted") {
        return Err(secret_deleted_error("SecretDeleted: target secret source is deleted"));
    }
    let prior_version = existing.as_ref().map(|secret| secret.current_version);
    let version = prior_version.map_or(Ok(1), next_secret_version)?;
    let secret_id = existing.as_ref().map_or_else(
        || SecretId::generate().map(SecretId::into_string).map_err(|_| CliError::Time),
        |secret| Ok(secret.id.clone()),
    )?;
    Ok(CopyTargetPlan { secret_id, version, prior_version, existing })
}

fn copied_secret_records(
    secret_id: &str,
    version: u32,
    source: &str,
    encrypted: EncryptedSecretValue,
    fingerprint: Vec<u8>,
    timestamp: i64,
) -> (SecretVersionRecord, SecretBlobRecord, SecretFingerprintRecord) {
    (
        SecretVersionRecord {
            secret_id: secret_id.to_owned(),
            version,
            source: source.to_owned(),
            origin: "profile-copy".to_owned(),
            state: "current".to_owned(),
            created_at: timestamp,
            deprecated_at: None,
            grace_until: None,
            purged_at: None,
        },
        SecretBlobRecord {
            secret_id: secret_id.to_owned(),
            version,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: encrypted.aad_schema_version,
            created_at: timestamp,
        },
        SecretFingerprintRecord {
            secret_id: secret_id.to_owned(),
            version,
            fingerprint,
            created_at: timestamp,
        },
    )
}

pub(crate) fn collect_known_secret_values(
    context: &RuntimeContext,
    project: &ResolvedProject,
    timestamp: i64,
) -> Result<Vec<zeroize::Zeroizing<String>>, CliError> {
    let store = open_store(context)?;
    ensure_trusted_project_root(&store, project)?;
    let mut values = Vec::new();
    for profile in store.list_profiles(project.config.project_id.as_str())? {
        for secret in
            store.list_secrets_by_profile(project.config.project_id.as_str(), &profile.id)?
        {
            for version in store.list_secret_versions(&secret.id)? {
                if should_scan_known_version(&secret, &version, timestamp)
                    && store.get_blob(&secret.id, version.version)?.is_some()
                {
                    values.push(decrypt_secret_version(
                        context,
                        &store,
                        project.config.project_id.as_str(),
                        &profile.id,
                        &secret,
                        version.version,
                    )?);
                }
            }
        }
    }
    Ok(values)
}

/// Stable display alias per `docs/specs/invariants.md:37`.
///
/// Delegates to [`locket_core::privacy_alias`] so the CLI, the agent,
/// and the desktop UI all hash the same canonical bytes (length-prefixed
/// `field()` layout from `docs/specs/crypto.md:134`). Earlier revisions
/// re-implemented the hash here with `format!("kind:{kind};id:{id}")`,
/// which produced a different digest from the spec; the duplicate has
/// been removed.
pub(crate) fn privacy_alias(kind: &str, id: &str) -> String {
    locket_core::privacy_alias(kind, id)
}

fn should_scan_known_version(
    secret: &SecretRecord,
    version: &SecretVersionRecord,
    timestamp: i64,
) -> bool {
    match version.state.as_str() {
        "current" => secret.state == "active" || version.version == secret.current_version,
        "deprecated" => version.grace_until.is_some_and(|grace_until| grace_until > timestamp),
        _ => false,
    }
}

pub(crate) fn trust_root(
    store: &Store,
    config: &ProjectConfig,
    root: &Path,
    timestamp: i64,
) -> Result<(), CliError> {
    let hash = root_hash(root)?;
    let display_path = root.to_string_lossy();
    store.trust_project_root(
        config.project_id.as_str(),
        &hash,
        Some(display_path.as_ref()),
        timestamp,
    )?;
    Ok(())
}

pub(crate) fn open_store(context: &RuntimeContext) -> Result<Store, CliError> {
    if let Some(parent) = context.store_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let existing_store_len = match fs::metadata(&context.store_path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => 0,
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };
    let mut store = Store::open(&context.store_path)?;
    maybe_create_pre_migration_backup(context, &store, existing_store_len)?;
    store.initialize_schema()?;
    Ok(store)
}

fn maybe_create_pre_migration_backup(
    context: &RuntimeContext,
    store: &Store,
    existing_store_len: u64,
) -> Result<(), CliError> {
    if existing_store_len == 0 {
        return Ok(());
    }

    let current_version = store.current_schema_version()?;
    if current_version.is_some_and(|version| version >= i64::from(SCHEMA_VERSION)) {
        return Ok(());
    }

    create_pre_migration_backup(context, current_version)
}

fn create_pre_migration_backup(
    context: &RuntimeContext,
    current_version: Option<i64>,
) -> Result<(), CliError> {
    let backup_root = pre_migration_backup_root(context)?;
    fs::create_dir_all(&backup_root)?;
    set_user_only_dir_permissions(&backup_root)?;

    let from_version =
        current_version.map_or_else(|| "none".to_owned(), |version| version.to_string());
    let backup_dir = backup_root.join(format!(
        "{}-schema-v{}-to-v{}",
        now_unix_nanos()?,
        from_version,
        SCHEMA_VERSION
    ));
    fs::create_dir(&backup_dir)?;
    set_user_only_dir_permissions(&backup_dir)?;

    copy_backup_file(&context.store_path, &backup_dir.join("store.db"))?;
    copy_backup_file_if_present(
        &sqlite_sidecar_path(&context.store_path, "wal"),
        &backup_dir.join("store.db-wal"),
    )?;
    copy_backup_file_if_present(
        &sqlite_sidecar_path(&context.store_path, "shm"),
        &backup_dir.join("store.db-shm"),
    )?;

    let recovery_dir = context.cwd.join(".locket").join("recovery");
    if recovery_dir.exists() {
        let backup_recovery_dir = backup_dir.join("recovery");
        fs::create_dir(&backup_recovery_dir)?;
        set_user_only_dir_permissions(&backup_recovery_dir)?;
        copy_backup_file_if_present(
            &recovery_dir.join("kdf.toml"),
            &backup_recovery_dir.join("kdf.toml"),
        )?;
        copy_backup_file_if_present(
            &recovery_dir.join("envelope.bin"),
            &backup_recovery_dir.join("envelope.bin"),
        )?;
    }

    Ok(())
}

fn copy_backup_file_if_present(source: &Path, destination: &Path) -> Result<(), CliError> {
    match fs::metadata(source) {
        Ok(metadata) if metadata.is_file() => copy_backup_file(source, destination),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn copy_backup_file(source: &Path, destination: &Path) -> Result<(), CliError> {
    fs::copy(source, destination)?;
    set_user_only_file_permissions(destination)?;
    Ok(())
}

fn sqlite_sidecar_path(store_path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}-{suffix}", store_path.display()))
}

fn pre_migration_backup_root(context: &RuntimeContext) -> Result<PathBuf, CliError> {
    let parent = context
        .store_path
        .parent()
        .ok_or_else(|| corrupt_db_error("could not resolve pre-migration backup directory"))?;
    Ok(parent.join(PRE_MIGRATION_BACKUP_DIR))
}

fn pre_migration_backup_relative_label(context: &RuntimeContext, path: &Path) -> String {
    let Some(parent) = context.store_path.parent() else {
        return path.display().to_string();
    };
    path.strip_prefix(parent)
        .map_or_else(|_| path.display().to_string(), |relative| relative.display().to_string())
}

pub(crate) fn ensure_trusted_project_root(
    store: &Store,
    resolved: &ResolvedProject,
) -> Result<(), CliError> {
    let root_hash = root_hash(&resolved.root)?;
    if store.project_root_is_trusted(resolved.config.project_id.as_str(), &root_hash)? {
        return Ok(());
    }
    Err(project_root_untrusted_error())
}

/// Resolves the on-disk directory the agent uses for its Unix socket,
/// pid file, and rotated log files.
///
/// Honors `RuntimeContext::agent_data_dir` when set so production
/// startup can pin the spec-mandated platform path
/// (`$XDG_RUNTIME_DIR/locket`, `~/Library/Application Support/locket`).
/// Tests that build a `RuntimeContext` directly leave the field at
/// `None` and inherit the legacy `store_path.parent()` derivation so
/// each test's tempdir continues to own its own socket.
pub(crate) fn agent_data_dir(context: &RuntimeContext) -> PathBuf {
    if let Some(dir) = context.agent_data_dir.as_ref() {
        return dir.clone();
    }
    context.store_path.parent().map_or_else(|| context.cwd.clone(), Path::to_path_buf)
}

pub(crate) fn agent_socket_path(context: &RuntimeContext) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(pipe_name) = locket_platform::default_agent_pipe_name() {
            return PathBuf::from(pipe_name);
        }
    }
    agent_data_dir(context).join("agent.sock")
}

fn agent_pid_path(context: &RuntimeContext) -> PathBuf {
    agent_data_dir(context).join("agent.pid")
}

fn agent_log_path(context: &RuntimeContext) -> PathBuf {
    agent_data_dir(context).join("agent.log")
}

fn agent_rotated_log_path(context: &RuntimeContext, index: u8) -> PathBuf {
    agent_data_dir(context).join(format!("agent.log.{index}"))
}

fn agent_log_paths_oldest_first(context: &RuntimeContext) -> Vec<PathBuf> {
    let mut paths = (1..=AGENT_LOG_RETAINED_FILES)
        .rev()
        .map(|index| agent_rotated_log_path(context, index))
        .collect::<Vec<_>>();
    paths.push(agent_log_path(context));
    paths
}

fn write_agent_paths(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "socket: {}", agent_socket_path(context).display())?;
    writeln!(output, "pid_file: {}", agent_pid_path(context).display())?;
    writeln!(output, "log_file: {}", agent_log_path(context).display())?;
    Ok(())
}

fn read_agent_pid(context: &RuntimeContext) -> Result<Option<String>, CliError> {
    match fs::read_to_string(agent_pid_path(context)) {
        Ok(pid) => {
            let pid = pid.trim();
            Ok(if pid.is_empty() { None } else { Some(pid.to_owned()) })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn append_agent_log(
    context: &RuntimeContext,
    action: &str,
    status: &str,
    message: &str,
) -> Result<(), CliError> {
    prepare_agent_log_dir(context)?;
    rotate_agent_logs_if_needed(context)?;
    let entry = json!({
        "timestamp": now_unix_nanos()?,
        "severity": "info",
        "component": "agent",
        "action": action,
        "status": status,
        "message": sanitize_agent_log_value(Value::String(message.to_owned())),
    });
    let log_path = agent_log_path(context);
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    set_user_only_file_options(&mut options);
    let mut file = options.open(&log_path)?;
    writeln!(file, "{entry}")?;
    set_user_only_file_permissions(&log_path)?;
    Ok(())
}

fn prepare_agent_log_dir(context: &RuntimeContext) -> Result<(), CliError> {
    let data_dir = agent_data_dir(context);
    fs::create_dir_all(&data_dir)?;
    set_user_only_dir_permissions(&data_dir)?;
    Ok(())
}

fn rotate_agent_logs_if_needed(context: &RuntimeContext) -> Result<(), CliError> {
    let log_path = agent_log_path(context);
    let Ok(metadata) = fs::metadata(&log_path) else {
        return Ok(());
    };
    if metadata.len() < AGENT_LOG_MAX_BYTES {
        return Ok(());
    }
    let oldest = agent_rotated_log_path(context, AGENT_LOG_RETAINED_FILES);
    match fs::remove_file(oldest) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for index in (1..AGENT_LOG_RETAINED_FILES).rev() {
        let from = agent_rotated_log_path(context, index);
        let to = agent_rotated_log_path(context, index + 1);
        match fs::rename(from, to) {
            Ok(()) => set_user_only_file_permissions(&agent_rotated_log_path(context, index + 1))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let rotated = agent_rotated_log_path(context, 1);
    fs::rename(&log_path, &rotated)?;
    set_user_only_file_permissions(&rotated)?;
    Ok(())
}

fn sanitize_agent_log_line(line: &str) -> String {
    serde_json::from_str::<Value>(line).map_or_else(
        |_| redact_text(line).text,
        |value| sanitize_agent_log_value(value).to_string(),
    )
}

fn sanitize_agent_log_value(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut sanitized = serde_json::Map::new();
            for (key, value) in object {
                if agent_log_key_is_forbidden(&key) {
                    continue;
                }
                if agent_log_key_is_path(&key) {
                    if let Some(path) = value.as_str() {
                        let path_hash = privacy_alias("path", path);
                        sanitized.insert(
                            format!("{key}_kind"),
                            Value::String(path_kind(path).to_owned()),
                        );
                        sanitized.insert(format!("{key}_hash"), Value::String(path_hash));
                    }
                    continue;
                }
                sanitized.insert(key, sanitize_agent_log_value(value));
            }
            Value::Object(sanitized)
        }
        Value::Array(values) => {
            Value::Array(values.into_iter().map(sanitize_agent_log_value).collect())
        }
        Value::String(value) => {
            if looks_like_full_path(&value) {
                Value::String(privacy_alias("path", &value))
            } else {
                Value::String(redact_text(&value).text)
            }
        }
        other => other,
    }
}

fn agent_log_key_is_forbidden(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized.contains("secret")
        || normalized.contains("env")
        || normalized.contains("token")
        || normalized.contains("recovery")
        || normalized.contains("wrapped")
        || normalized.contains("private")
        || normalized.contains("credential")
        || normalized.contains("username")
        || normalized.contains("user_name")
        || normalized == "host"
        || normalized == "hostname"
}

fn agent_log_key_is_path(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized == "path" || normalized.ends_with("_path") || normalized.contains("filesystem")
}

fn path_kind(path: &str) -> &'static str {
    if Path::new(path).is_absolute() { "absolute" } else { "relative" }
}

fn looks_like_full_path(value: &str) -> bool {
    Path::new(value).is_absolute()
        || value.contains("\\Users\\")
        || value.contains("\\Program Files\\")
        || value.contains(":/")
}

#[cfg(unix)]
fn set_user_only_file_options(options: &mut fs::OpenOptions) {
    options.mode(0o600);
}

#[cfg(not(unix))]
const fn set_user_only_file_options(_options: &mut fs::OpenOptions) {}

#[cfg(unix)]
fn set_user_only_file_permissions(path: &Path) -> Result<(), CliError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Retain the shared fallible interface; Windows inherits ACLs.
const fn set_user_only_file_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(unix)]
fn set_user_only_dir_permissions(path: &Path) -> Result<(), CliError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Retain the shared fallible interface; Windows inherits ACLs.
const fn set_user_only_dir_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[derive(Clone, Debug)]
/// Project root and configuration loaded from disk.
pub struct ResolvedProject {
    /// Absolute project root path.
    pub root: PathBuf,
    /// Parsed `locket.toml` configuration.
    pub config: ProjectConfig,
}

#[derive(Clone, Debug)]
pub(crate) struct EffectiveCommandPolicy {
    pub policy: CommandPolicy,
    pub path_scope_profile: Option<ProfileName>,
    pub path_scope_path: Option<PathBuf>,
}

pub(crate) fn require_project(context: &RuntimeContext) -> Result<ResolvedProject, CliError> {
    resolve_project(&context.cwd)?.ok_or_else(project_not_found_error)
}

pub(crate) fn resolve_project(start: &Path) -> Result<Option<ResolvedProject>, CliError> {
    let mut current = start.canonicalize()?;
    loop {
        let candidate = current.join(LOCKET_TOML);
        if candidate.exists() {
            let config = read_project_config(&candidate)?;
            return Ok(Some(ResolvedProject { root: current, config }));
        }

        if !current.pop() {
            return Ok(None);
        }
    }
}

fn read_project_config(path: &Path) -> Result<ProjectConfig, CliError> {
    let content = fs::read_to_string(path)?;
    let config = toml::from_str::<ProjectConfig>(&content).map_err(|_| {
        metadata_invalid_error("project configuration could not be parsed (source redacted)")
    })?;
    if config.schema_version != PROJECT_CONFIG_SCHEMA_VERSION {
        return Err(metadata_invalid_error(format!(
            "unsupported locket.toml schema_version {}; supported {}",
            config.schema_version, PROJECT_CONFIG_SCHEMA_VERSION
        )));
    }
    Ok(config)
}

pub(crate) fn load_command_policy(
    resolved: &ResolvedProject,
    policy_name: &str,
) -> Result<CommandPolicy, CliError> {
    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    policy_document
        .commands
        .get(policy_name)
        .cloned()
        .ok_or_else(|| policy_not_found_error(format!("command policy not found: {policy_name}")))
}

pub(crate) fn load_effective_command_policy(
    resolved: &ResolvedProject,
    policy_name: &str,
    cwd: &Path,
) -> Result<EffectiveCommandPolicy, CliError> {
    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    let mut policy = policy_document.commands.get(policy_name).cloned().ok_or_else(|| {
        policy_not_found_error(format!("command policy not found: {policy_name}"))
    })?;
    let canonical_cwd = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let path_scope = policy_document.path_scope_for(&resolved.root, &canonical_cwd).cloned();
    if let Some(scope) = path_scope.as_ref() {
        apply_path_scope_to_policy(&mut policy, scope);
    }
    enforce_secret_access_policies(&policy_document, &policy, &resolved.root, &canonical_cwd)?;
    Ok(EffectiveCommandPolicy {
        policy,
        path_scope_profile: path_scope.as_ref().and_then(|scope| scope.profile.clone()),
        path_scope_path: path_scope.map(|scope| scope.path),
    })
}

pub(crate) fn load_effective_command_policy_for_argv(
    resolved: &ResolvedProject,
    policy_name: impl Into<String>,
    argv: Vec<String>,
    cwd: &Path,
) -> Result<EffectiveCommandPolicy, CliError> {
    let mut policy = CommandPolicy {
        name: policy_name.into(),
        command: CommandSpec::Argv(argv),
        allowed_secrets: Vec::new(),
        required_secrets: Vec::new(),
        optional_secrets: Vec::new(),
        inherit_env: Vec::new(),
        env_mode: EnvMode::Minimal,
        override_behavior: EnvOverrideMode::Locket,
        override_source: PolicyFieldSource::Defaulted,
        external_env_sources: Vec::new(),
        allow_remote_docker: false,
        confirm: false,
        require_user_verification: false,
        require_agent: false,
        ttl: LocketDuration::from_secs(15 * 60),
    };
    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    let canonical_cwd = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let path_scope = policy_document.path_scope_for(&resolved.root, &canonical_cwd).cloned();
    if let Some(scope) = path_scope.as_ref() {
        apply_path_scope_to_policy(&mut policy, scope);
    }
    enforce_secret_access_policies(&policy_document, &policy, &resolved.root, &canonical_cwd)?;
    Ok(EffectiveCommandPolicy {
        policy,
        path_scope_profile: path_scope.as_ref().and_then(|scope| scope.profile.clone()),
        path_scope_path: path_scope.map(|scope| scope.path),
    })
}

pub(crate) fn effective_policy_profile(
    store: &Store,
    resolved: &ResolvedProject,
    effective: &EffectiveCommandPolicy,
) -> Result<ProfileRecord, CliError> {
    if let Some(profile_name) = &effective.path_scope_profile {
        return store
            .get_profile_by_name(resolved.config.project_id.as_str(), profile_name.as_str())?
            .ok_or_else(|| profile_not_found_error("path scope profile not found"));
    }
    default_profile(store, &resolved.config)
}

fn enforce_secret_access_policies(
    document: &PolicyDocument,
    policy: &CommandPolicy,
    project_root: &Path,
    canonical_cwd: &Path,
) -> Result<(), CliError> {
    let relative_cwd = canonical_cwd.strip_prefix(project_root).unwrap_or_else(|_| Path::new("."));
    let relative_cwd =
        if relative_cwd.as_os_str().is_empty() { Path::new(".") } else { relative_cwd };
    let argv = match &policy.command {
        CommandSpec::Argv(argv) => Some(argv.as_slice()),
        CommandSpec::Shell(_) => None,
    };
    let denied = document
        .denied_secrets(&policy.name, argv, relative_cwd, &policy.allowed_secrets)
        .into_iter()
        .map(locket_core::SecretName::as_str)
        .collect::<Vec<_>>();
    if denied.is_empty() {
        return Ok(());
    }
    Err(invalid_policy_error(format!(
        "secret ACL denied command {} for: {}",
        policy.name,
        denied.join(",")
    )))
}

fn apply_path_scope_to_policy(policy: &mut CommandPolicy, scope: &PathEnvSet) {
    scope.apply_to(policy);
}

pub(crate) fn read_policy_document(path: &Path) -> Result<PolicyDocument, CliError> {
    let content = fs::read_to_string(path)?;
    PolicyDocument::from_toml_str(&content).map_err(|error| invalid_policy_error(error.to_string()))
}

pub(crate) const fn command_type(command: &CommandSpec) -> &'static str {
    match command {
        CommandSpec::Argv(_) => "argv",
        CommandSpec::Shell(_) => "shell",
    }
}

pub(crate) fn external_env_source_label(source: &ExternalEnvSource) -> String {
    match source {
        ExternalEnvSource::Parent => "parent".to_owned(),
        ExternalEnvSource::File(path) => format!("file:{}", path.display()),
        ExternalEnvSource::Compose => "compose".to_owned(),
        ExternalEnvSource::Ide => "ide".to_owned(),
    }
}

pub(crate) fn write_project_config(path: &Path, config: &ProjectConfig) -> Result<(), CliError> {
    let content = toml::to_string_pretty(config)?;
    if path.exists() {
        let mut document = locket_platform::PolicyFileDocument::read(path)
            .map_err(|error| metadata_invalid_error(error.to_string()))?;
        let replacement: toml::Value = toml::from_str(&content)?;
        if let (Some(current), Some(fields)) = (document.as_table_mut(), replacement.as_table()) {
            for (key, value) in fields {
                current.insert(key.clone(), value.clone());
            }
        }
        document.save().map_err(|error| metadata_invalid_error(error.to_string()))?;
    } else {
        fs::write(path, content)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_runtime_policy_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
    status: &str,
    selections: &[PolicySecretSelection],
    external_env_names: &[String],
    child_exit: Option<i32>,
    confirmation_source: Option<&str>,
    user_verification: Option<&locket_platform::LocalUserVerification>,
    run_policy_grant: Option<&commands::exec::run::RunPolicyGrantMetadata>,
) -> Result<(), CliError> {
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let secret_names_raw = selections
        .iter()
        .filter(|selection| selection.selected.is_some())
        .map(|selection| selection.name.as_str())
        .collect::<Vec<_>>();
    let secret_names = summarize_names(&secret_names_raw);
    let external_sources =
        policy.external_env_sources.iter().map(external_env_source_label).collect::<Vec<_>>();
    let secrets = policy_secret_audit_entries(selections);
    let allowed_secret_names_raw =
        policy.allowed_secrets.iter().map(locket_core::SecretName::as_str).collect::<Vec<_>>();
    let allowed_secret_names = summarize_names(&allowed_secret_names_raw);
    let required_secret_names_raw =
        policy.required_secrets.iter().map(locket_core::SecretName::as_str).collect::<Vec<_>>();
    let required_secret_names = summarize_names(&required_secret_names_raw);
    let user_verification_metadata = json!({
        "required": policy.require_user_verification,
        "satisfied": user_verification.is_some(),
        "method": user_verification.map(|verified| serde_json::to_value(verified.method).unwrap_or(Value::Null)),
    });
    let mut metadata = json!({
        "schema_version": 1,
        "action": "RUN_POLICY",
        "status": status,
        "command": "run",
        "policy": policy.name,
        "policy_id": policy.name,
        "command_type": command_type(&policy.command),
        "env_mode": policy.env_mode.to_string(),
        "override": policy.override_behavior.to_string(),
        "override_explicit": policy.override_explicit(),
        "secret_names": secret_names,
        "secrets": secrets,
        "allowed_secret_names": allowed_secret_names,
        "required_secret_names": required_secret_names,
        "external_env_sources": external_sources,
        "external_sources": external_sources,
        "external_env_names": summarize_names(&external_env_names.iter().map(String::as_str).collect::<Vec<_>>()),
        "confirmation_source": confirmation_source,
        "user_verification": user_verification_metadata,
        "child_exit": child_exit,
    });
    if let Some(grant) = run_policy_grant
        && let Some(metadata) = metadata.as_object_mut()
    {
        metadata.insert("grant_actions".to_owned(), json!(["RunPolicy"]));
        metadata.insert("ttl_seconds".to_owned(), json!(grant.ttl_seconds));
        metadata.insert("process_id".to_owned(), json!(grant.process_id));
        metadata.insert("process_start_time".to_owned(), json!(grant.process_start_time.as_str()));
    }
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: Some(&profile.id),
        action: "RUN_POLICY",
        status,
        secret_name: None,
        command: Some("run"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

/// Emits a metadata-only `RUN_POLICY` audit row with `status = "DENIED"` for
/// policy executions rejected before the executor spawns the child.
///
/// Callers may pass a fully-resolved `CommandPolicy` when one is available
/// (e.g. failures inside `prepare_policy_execution`) or only the requested
/// policy name when the policy itself could not be loaded
/// (e.g. `policy_not_found`).
pub(crate) fn write_runtime_policy_denial_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    profile: Option<&ProfileRecord>,
    policy: Option<&CommandPolicy>,
    requested_policy_name: &str,
    failure_reason: &str,
) -> Result<(), CliError> {
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let policy_name = policy.map_or(requested_policy_name, |policy| policy.name.as_str());
    let env_mode =
        policy.map_or_else(|| "minimal".to_owned(), |policy| policy.env_mode.to_string());
    let override_mode =
        policy.map_or_else(|| "locket".to_owned(), |policy| policy.override_behavior.to_string());
    let override_explicit = policy.is_some_and(CommandPolicy::override_explicit);
    let command_type_label = policy.map_or("argv", |policy| command_type(&policy.command));
    let allowed_secret_names = policy.map_or_else(Vec::new, |policy| {
        let raw =
            policy.allowed_secrets.iter().map(locket_core::SecretName::as_str).collect::<Vec<_>>();
        summarize_names(&raw)
    });
    let required_secret_names = policy.map_or_else(Vec::new, |policy| {
        let raw =
            policy.required_secrets.iter().map(locket_core::SecretName::as_str).collect::<Vec<_>>();
        summarize_names(&raw)
    });
    let external_sources = policy.map_or_else(Vec::new, |policy| {
        policy.external_env_sources.iter().map(external_env_source_label).collect()
    });
    let user_verification_metadata = json!({
        "required": policy.is_some_and(|policy| policy.require_user_verification),
        "satisfied": false,
        "method": Value::Null,
    });
    let metadata = json!({
        "schema_version": 1,
        "action": "RUN_POLICY",
        "status": "DENIED",
        "command": "run",
        "policy": policy_name,
        "policy_id": policy_name,
        "command_type": command_type_label,
        "env_mode": env_mode,
        "override": override_mode,
        "override_explicit": override_explicit,
        "secret_names": Vec::<String>::new(),
        "secrets": Vec::<Value>::new(),
        "allowed_secret_names": allowed_secret_names,
        "required_secret_names": required_secret_names,
        "external_env_sources": external_sources,
        "external_sources": external_sources,
        "external_env_names": Vec::<String>::new(),
        "confirmation_source": Value::Null,
        "user_verification": user_verification_metadata,
        "child_exit": Value::Null,
        "failure_reason": failure_reason,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: profile.map(|profile| profile.id.as_str()),
        action: "RUN_POLICY",
        status: "DENIED",
        secret_name: None,
        command: Some("run"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn policy_secret_audit_entries(selections: &[PolicySecretSelection]) -> Vec<Value> {
    selections
        .iter()
        .map(|selection| {
            let mut entry = serde_json::Map::new();
            entry.insert("name".to_owned(), json!(selection.name));
            entry.insert("required".to_owned(), json!(selection.required));
            entry.insert("sources".to_owned(), json!(selection.sources));
            if let Some(secret) = &selection.selected {
                entry.insert("selected_source".to_owned(), json!(secret.source));
                entry.insert("selected_version".to_owned(), json!(secret.current_version));
            }
            Value::Object(entry)
        })
        .collect()
}

fn absolutize(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() { path.to_path_buf() } else { cwd.join(path) }
}

fn grace_until_from_args(value: Option<&str>, timestamp: i64) -> Result<Option<i64>, CliError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let duration = LocketDuration::from_str(value)
        .map_err(|_| metadata_invalid_error("invalid grace TTL duration"))?;
    if duration.as_secs() > DEFAULT_MAX_GRACE_TTL_SECONDS {
        return Err(metadata_invalid_error("grace TTL exceeds the default 7d cap"));
    }
    let nanos = i64::try_from(duration.as_secs())
        .ok()
        .and_then(|seconds| seconds.checked_mul(NANOS_PER_SECOND))
        .ok_or(CliError::Time)?;
    timestamp.checked_add(nanos).map(Some).ok_or(CliError::Time)
}

const fn metadata_flags_have_updates(metadata: &SecretMetadataFlags) -> bool {
    metadata.description.is_some()
        || metadata.owner.is_some()
        || !metadata.tags.is_empty()
        || metadata.required
        || metadata.optional
}

const fn metadata_required_update(metadata: &SecretMetadataFlags) -> Option<bool> {
    if metadata.required {
        Some(true)
    } else if metadata.optional {
        Some(false)
    } else {
        None
    }
}

fn metadata_update_field_names(metadata: &SecretMetadataFlags) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if metadata.description.is_some() {
        fields.push("description");
    }
    if metadata.owner.is_some() {
        fields.push("owner");
    }
    if !metadata.tags.is_empty() {
        fields.push("tags");
    }
    if metadata.required || metadata.optional {
        fields.push("required");
    }
    fields
}

fn validate_secret_metadata_update(
    context: &RuntimeContext,
    resolved_secret: &ResolvedSecret,
    metadata: &SecretMetadataFlags,
    timestamp: i64,
) -> Result<(), CliError> {
    let fields = secret_metadata_text_fields(metadata);
    let known_values = collect_known_secret_values(context, &resolved_secret.project, timestamp)
        .unwrap_or_default();
    let known_values =
        known_values.iter().map(|known_value| known_value.as_str()).collect::<Vec<_>>();

    for (field, value) in fields {
        let findings = scan_text(&format!("metadata:{field}"), value)
            .iter()
            .filter_map(metadata_privacy_finding)
            .collect::<Vec<_>>();
        validate_metadata_field(field, value, known_values.iter().copied(), findings)
            .map_err(|error| metadata_validation_error(&error))?;
    }

    Ok(())
}

fn secret_metadata_text_fields(metadata: &SecretMetadataFlags) -> Vec<(&'static str, &str)> {
    let mut fields = Vec::new();
    if let Some(description) = metadata.description.as_deref() {
        fields.push(("description", description));
    }
    if let Some(owner) = metadata.owner.as_deref() {
        fields.push(("owner", owner));
    }
    for tag in &metadata.tags {
        fields.push(("tag", tag.as_str()));
    }
    fields
}

const fn metadata_privacy_finding(
    finding: &locket_scan::ScanFinding,
) -> Option<MetadataPrivacyFinding> {
    match finding.kind {
        FindingKind::HighEntropy => Some(MetadataPrivacyFinding::HighEntropy),
        FindingKind::ProviderTokenPattern => Some(MetadataPrivacyFinding::ProviderToken),
        FindingKind::EnvFileMarker | FindingKind::KnownSecretValue => None,
    }
}

fn metadata_validation_error(error: &MetadataValidationError) -> CliError {
    if error.is_secret_like() {
        metadata_looks_like_secret_error(error.to_string())
    } else {
        metadata_invalid_error(error.to_string())
    }
}

fn write_secret_meta_update_failure_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    resolved_secret: &ResolvedSecret,
    metadata: &SecretMetadataFlags,
    timestamp: i64,
) -> Result<(), CliError> {
    let project_id = resolved_secret.project.config.project_id.as_str();
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    let audit_metadata = secret_meta_update_audit_metadata(
        resolved_secret,
        metadata,
        "FAILED",
        Some("metadata_privacy_validation"),
    );
    let audit = AuditWrite {
        project_id,
        profile_id: Some(&resolved_secret.profile.id),
        action: "SECRET_META_UPDATE",
        status: "FAILED",
        secret_name: Some(&resolved_secret.secret.name),
        command: None,
        metadata_json: &audit_metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn secret_meta_update_audit_metadata(
    resolved_secret: &ResolvedSecret,
    metadata: &SecretMetadataFlags,
    status: &str,
    failure_reason: Option<&str>,
) -> Value {
    let updated_fields = metadata_update_field_names(metadata);
    let updated_field_count = updated_fields.len();
    json!({
        "schema_version": 1,
        "action": "SECRET_META_UPDATE",
        "status": status,
        "secret_name": &resolved_secret.secret.name,
        "profile": &resolved_secret.profile.name,
        "profile_id": &resolved_secret.profile.id,
        "source": &resolved_secret.secret.source,
        "version": resolved_secret.secret.current_version,
        "updated_fields": updated_fields,
        "updated_field_count": updated_field_count,
        "description_updated": metadata.description.is_some(),
        "owner_updated": metadata.owner.is_some(),
        "tag_update_count": metadata.tags.len(),
        "required_update": metadata_required_update(metadata),
        "failure_reason": failure_reason,
    })
}

fn format_versions(versions: &[u32]) -> String {
    versions.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
}

fn active_secret_map(
    store: &Store,
    project_id: &str,
    profile_id: &str,
) -> Result<BTreeMap<(String, String), SecretRecord>, CliError> {
    let secrets = store.list_active_secrets_by_profile(project_id, profile_id)?;
    Ok(secrets
        .into_iter()
        .map(|secret| ((secret.name.clone(), secret.source.clone()), secret))
        .collect())
}

pub(crate) fn active_secrets_by_name(
    store: &Store,
    project_id: &str,
    profile_id: &str,
) -> Result<BTreeMap<String, Vec<SecretRecord>>, CliError> {
    let mut by_name = BTreeMap::<String, Vec<SecretRecord>>::new();
    for secret in store.list_active_secrets_by_profile(project_id, profile_id)? {
        by_name.entry(secret.name.clone()).or_default().push(secret);
    }
    Ok(by_name)
}

pub(crate) const fn source_arg_to_str(source: SecretSourceArg) -> &'static str {
    match source {
        SecretSourceArg::TeamManaged => "team-managed",
        SecretSourceArg::UserLocal => "user-local",
        SecretSourceArg::MachineLocal => "machine-local",
    }
}

pub(crate) const fn source_precedence(source: &str) -> u8 {
    match source.as_bytes() {
        b"team-managed" => 1,
        b"user-local" => 2,
        b"machine-local" => 3,
        _ => 0,
    }
}

pub(crate) fn fallback_project_name(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map_or_else(|| "locket-project".to_owned(), ToOwned::to_owned)
}

pub(crate) fn root_hash(root: &Path) -> Result<[u8; 32], CliError> {
    let canonical = root.canonicalize()?;
    let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

pub(crate) fn format_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn parse_root_hash(value: &str) -> Result<[u8; 32], CliError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        return Err(metadata_invalid_error("root hash must be 64 hex characters"));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, CliError> {
    hex_nibble_with_message(byte, "root hash must be hex encoded")
}

fn hex_nibble_with_message(byte: u8, message: &str) -> Result<u8, CliError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(metadata_invalid_error(message)),
    }
}

pub(crate) fn seal_recovery_envelope_entry(
    unwrap_root: &locket_crypto::KeyBytes,
    kdf_profile_id: &str,
    entry_kind: &str,
    entry_id: &str,
    plaintext: &[u8],
) -> Result<RecoveryEnvelopeEntry, CliError> {
    let (nonce, ciphertext) =
        seal_recovery_entry_v1(unwrap_root, kdf_profile_id, entry_kind, entry_id, plaintext)?;
    Ok(RecoveryEnvelopeEntry {
        entry_kind: entry_kind.to_owned(),
        entry_id: entry_id.to_owned(),
        nonce,
        ciphertext,
    })
}

pub(crate) fn formatted_recovery_code(
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
) -> Result<String, CliError> {
    let encoded = recovery_code_encode(code_bytes);
    let code = std::str::from_utf8(&encoded)
        .map_err(|_| CliError::Crypto(locket_crypto::CryptoError::InvalidSecretValue))?;
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &code[0..8],
        &code[8..16],
        &code[16..24],
        &code[24..32],
        &code[32..34]
    ))
}

pub(crate) fn now_unix_nanos() -> Result<i64, CliError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| CliError::Time)?;
    i64::try_from(elapsed.as_nanos()).map_err(|_| CliError::Time)
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
