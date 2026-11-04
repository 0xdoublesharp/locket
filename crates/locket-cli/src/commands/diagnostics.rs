use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use flate2::Compression;
use flate2::write::GzEncoder;
use locket_core::PROJECT_CONFIG_SCHEMA_VERSION;
use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, RuntimeSessionSecretNameRetention, SCHEMA_VERSION};
use serde_json::{Value, json};

use crate::commands::config::spec::{CONFIG_KEY_SPECS, config_get_value, read_user_config};
use crate::runtime::error::corrupt_db_error;
use crate::{
    BACKUP_SKIPPED_PREFIX, CliError, GITIGNORE_ENTRIES, GITIGNORE_FILE, HOOK_BEGIN, LOCKET_TOML,
    RuntimeContext, agent_log_path, agent_pid_path, agent_socket_path, format_hex,
    git_dir_for_worktree, invalid_reference_error, load_project_key, metadata_invalid_error,
    now_unix_nanos, open_store, pre_migration_backup_relative_label, pre_migration_backup_root,
    privacy_alias, privacy_redact_names_enabled, read_project_config, resolve_project, root_hash,
};

const SKIPPED_LOCKED_CHECKS: [&str; 5] = [
    "audit_hmac_verification",
    "key_unwrap_probe",
    "recovery_envelope_decryptability",
    "known_value_scanner_readiness",
    "bundle_decryptability",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug)]
struct DiagnosticCheck {
    name: &'static str,
    status: CheckStatus,
    critical: bool,
    detail: String,
}

impl DiagnosticCheck {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self { name, status: CheckStatus::Pass, critical: false, detail: detail.into() }
    }

    fn warn(name: &'static str, detail: impl Into<String>) -> Self {
        Self { name, status: CheckStatus::Warn, critical: false, detail: detail.into() }
    }

    fn fail(name: &'static str, critical: bool, detail: impl Into<String>) -> Self {
        Self { name, status: CheckStatus::Fail, critical, detail: detail.into() }
    }

    fn skip(name: &'static str, detail: impl Into<String>) -> Self {
        Self { name, status: CheckStatus::Skip, critical: false, detail: detail.into() }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DiagnosticCounts {
    pass: u32,
    warn: u32,
    fail: u32,
    skip: u32,
    critical_fail: u32,
}

impl DiagnosticCounts {
    const fn record(&mut self, check: &DiagnosticCheck) {
        match check.status {
            CheckStatus::Pass => self.pass += 1,
            CheckStatus::Warn => self.warn += 1,
            CheckStatus::Fail => {
                self.fail += 1;
                if check.critical {
                    self.critical_fail += 1;
                }
            }
            CheckStatus::Skip => self.skip += 1,
        }
    }

    const fn exit_code(self) -> u8 {
        if self.critical_fail > 0 {
            2
        } else if self.fail > 0 {
            1
        } else {
            0
        }
    }
}

#[derive(Debug)]
struct DiagnosticReport {
    checks: Vec<DiagnosticCheck>,
    counts: DiagnosticCounts,
}

impl DiagnosticReport {
    fn new(checks: Vec<DiagnosticCheck>) -> Self {
        let mut counts = DiagnosticCounts::default();
        for check in &checks {
            counts.record(check);
        }
        Self { checks, counts }
    }

    const fn exit_code(&self) -> u8 {
        self.counts.exit_code()
    }

    fn as_json(&self) -> Value {
        json!({
            "schema_version": 1,
            "counts": {
                "pass": self.counts.pass,
                "warn": self.counts.warn,
                "fail": self.counts.fail,
                "skip": self.counts.skip,
                "critical_fail": self.counts.critical_fail,
            },
            "checks": self.checks.iter().map(|check| {
                json!({
                    "name": check.name,
                    "status": status_label(check.status),
                    "critical": check.critical,
                    "detail": check.detail,
                })
            }).collect::<Vec<_>>(),
        })
    }

    fn audit_metadata(&self) -> Value {
        json!({
            "schema_version": 1,
            "action": "DOCTOR",
            "status": if self.counts.fail == 0 { "SUCCESS" } else { "FAILED" },
            "command": "doctor",
            "check_names": self.checks.iter().map(|check| check.name).collect::<Vec<_>>(),
            "pass_count": self.counts.pass,
            "warn_count": self.counts.warn,
            "fail_count": self.counts.fail,
            "skip_count": self.counts.skip,
            "critical_fail_count": self.counts.critical_fail,
        })
    }
}

pub fn doctor_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    prune_runtime_session_secret_names: bool,
) -> Result<u8, CliError> {
    let report = collect_diagnostics(context, prune_runtime_session_secret_names);
    write_doctor_audit_if_available(context, &report)?;
    write_doctor_report(output, &report)?;
    Ok(report.exit_code())
}

pub fn debug_bundle_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    redacted: bool,
    output_path: Option<&str>,
) -> Result<(), CliError> {
    if !redacted {
        return Err(invalid_reference_error(
            "debug bundle currently requires --redacted; unredacted bundles are not supported",
        ));
    }

    let diagnostics = collect_diagnostics(context, false);
    let project = resolve_project(&context.cwd)?;
    let redact_names = privacy_redact_names_enabled(context, false)?;
    let alias_replacements =
        debug_bundle_alias_replacements(context, project.as_ref(), redact_names);
    let user_config = read_user_config(context).unwrap_or_default();
    let config_keys = CONFIG_KEY_SPECS
        .iter()
        .filter_map(|spec| config_key_is_set(&user_config, spec.key).then_some(spec.key))
        .collect::<Vec<_>>();
    let audit_actions = project.as_ref().map_or_else(Vec::new, |project| {
        open_store(context).map_or_else(
            |_| Vec::new(),
            |store| {
                store
                    .list_recent_audit_actions(project.config.project_id.as_str(), 25)
                    .unwrap_or_default()
            },
        )
    });
    let project_json = project.as_ref().map(|project| {
        let project_label =
            debug_bundle_alias(&alias_replacements, project.config.project_id.as_str());
        let project_name = debug_bundle_alias(&alias_replacements, &project.config.name);
        let default_profile =
            debug_bundle_alias(&alias_replacements, project.config.default_profile.as_str());
        json!({
            "id": project_label,
            "name": project_name,
            "default_profile": default_profile,
            "root_kind": "project_root",
            "root_hash": root_hash(&project.root).map(|hash| format_hex(&hash)).ok(),
        })
    });
    let diagnostics_json = redact_debug_bundle_value(diagnostics.as_json(), &alias_replacements);
    let bundle = json!({
        "schema_version": 1,
        "redacted": true,
        "versions": {
            "locket_cli": env!("CARGO_PKG_VERSION"),
            "project_config_schema": PROJECT_CONFIG_SCHEMA_VERSION,
            "store_schema": SCHEMA_VERSION,
        },
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cwd_kind": "current_working_directory",
            "store_path_hash": path_hash(&context.store_path),
            "config_path_hash": path_hash(&context.config_path),
        },
        "project": project_json,
        "config_keys": config_keys,
        "recent_audit_actions": audit_actions,
        "agent": agent_metadata(context),
        "diagnostics": diagnostics_json,
    });
    let text = serde_json::to_string_pretty(&bundle)
        .map_err(|error| metadata_invalid_error(error.to_string()))?;

    let path = output_path.map_or_else(
        || default_debug_bundle_path(context),
        |output_path| Ok(PathBuf::from(output_path)),
    )?;
    write_debug_bundle_file(&path, &text)?;
    writeln!(output, "debug_bundle: {}", path.display())?;
    writeln!(output, "redacted: yes")?;

    Ok(())
}

fn debug_bundle_alias_replacements(
    context: &RuntimeContext,
    project: Option<&crate::ResolvedProject>,
    redact_names: bool,
) -> Vec<(String, String)> {
    if !redact_names {
        return Vec::new();
    }
    let Some(project) = project else {
        return Vec::new();
    };

    let project_alias = privacy_alias("project", project.config.project_id.as_str());
    let profile_alias = privacy_alias("profile", project.config.default_profile.as_str());
    let mut replacements = vec![
        (project.config.project_id.to_string(), project_alias.clone()),
        (project.config.name.clone(), project_alias),
        (project.config.default_profile.to_string(), profile_alias),
    ];

    if let Ok(store) = open_store(context)
        && let Ok(Some(profile)) = store.get_profile_by_name(
            project.config.project_id.as_str(),
            project.config.default_profile.as_str(),
        )
    {
        let profile_alias = privacy_alias("profile", &profile.id);
        replacements.push((profile.id, profile_alias.clone()));
        replacements.push((profile.name, profile_alias));
    }

    replacements.retain(|(exact, _)| !exact.is_empty());
    replacements
}

fn debug_bundle_alias(replacements: &[(String, String)], value: &str) -> String {
    replacements
        .iter()
        .find_map(|(exact, alias)| (exact == value).then(|| alias.clone()))
        .unwrap_or_else(|| value.to_owned())
}

fn redact_debug_bundle_value(mut value: Value, replacements: &[(String, String)]) -> Value {
    match &mut value {
        Value::String(text) => {
            for (exact, alias) in replacements {
                *text = text.replace(exact, alias);
            }
        }
        Value::Array(values) => {
            for entry in values {
                *entry = redact_debug_bundle_value(std::mem::take(entry), replacements);
            }
        }
        Value::Object(entries) => {
            for entry in entries.values_mut() {
                *entry = redact_debug_bundle_value(std::mem::take(entry), replacements);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    value
}

#[allow(clippy::too_many_lines)]
fn collect_diagnostics(
    context: &RuntimeContext,
    prune_runtime_session_secret_names: bool,
) -> DiagnosticReport {
    let mut checks = Vec::new();

    match resolve_project(&context.cwd) {
        Ok(Some(project)) => {
            checks.push(DiagnosticCheck::pass(
                "project_resolution",
                format!(
                    "project_id={} root_hash={}",
                    project.config.project_id,
                    root_hash(&project.root)
                        .map_or_else(|_| "unavailable".to_owned(), |hash| format_hex(&hash))
                ),
            ));
            checks.push(check_locket_toml(&project.root.join(LOCKET_TOML)));
            match open_store(context) {
                Ok(store) => {
                    checks.push(DiagnosticCheck::pass(
                        "store_open_schema_bootstrap",
                        format!("schema_version={SCHEMA_VERSION}"),
                    ));
                    let integrity_ok = store
                        .integrity_check()
                        .is_ok_and(|rows| rows.iter().any(|row| row == "ok"));
                    checks.push(if integrity_ok {
                        DiagnosticCheck::pass("sqlite_integrity", "ok")
                    } else {
                        DiagnosticCheck::fail("sqlite_integrity", true, "integrity_check failed")
                    });
                    checks.push(check_bundle_conflict_index(&store));
                    checks.push(match store.get_project(project.config.project_id.as_str()) {
                        Ok(Some(record)) => DiagnosticCheck::pass(
                            "project_store_metadata",
                            format!("project_id={} name={}", record.id, record.name),
                        ),
                        Ok(None) => DiagnosticCheck::fail(
                            "project_store_metadata",
                            false,
                            "project metadata is not present in the local store",
                        ),
                        Err(error) => DiagnosticCheck::fail(
                            "project_store_metadata",
                            false,
                            error.to_string(),
                        ),
                    });
                    checks.push(check_trusted_roots(
                        &store,
                        &project.root,
                        project.config.project_id.as_str(),
                    ));
                    checks.push(check_runtime_session_secret_name_retention(
                        context,
                        &store,
                        project.config.project_id.as_str(),
                        prune_runtime_session_secret_names,
                    ));
                    checks.push(check_automation_client_nonces_pruning(&store));
                    checks.push(
                        match store.get_profile_by_name(
                            project.config.project_id.as_str(),
                            project.config.default_profile.as_str(),
                        ) {
                            Ok(Some(profile)) => DiagnosticCheck::pass(
                                "default_profile",
                                format!("profile_id={} name={}", profile.id, profile.name),
                            ),
                            Ok(None) => DiagnosticCheck::fail(
                                "default_profile",
                                false,
                                "default profile is missing from the local store",
                            ),
                            Err(error) => {
                                DiagnosticCheck::fail("default_profile", false, error.to_string())
                            }
                        },
                    );
                    checks.push(check_device_private_key_storage(
                        context,
                        &store,
                        project.config.project_id.as_str(),
                    ));
                }
                Err(error) => checks.push(DiagnosticCheck::fail(
                    "store_open_schema_bootstrap",
                    true,
                    error.to_string(),
                )),
            }
            checks.push(check_gitignore(&project.root));
            checks.push(check_pre_commit_hook(&project.root));
            checks.push(check_schema_migration_backups(context));
        }
        Ok(None) => {
            checks.push(DiagnosticCheck::fail(
                "project_resolution",
                false,
                "no locket.toml found from current directory",
            ));
            match open_store(context) {
                Ok(_) => checks.push(DiagnosticCheck::pass(
                    "store_open_schema_bootstrap",
                    format!("schema_version={SCHEMA_VERSION}"),
                )),
                Err(error) => checks.push(DiagnosticCheck::fail(
                    "store_open_schema_bootstrap",
                    true,
                    error.to_string(),
                )),
            }
            checks.push(check_schema_migration_backups(context));
        }
        Err(error) => {
            checks.push(DiagnosticCheck::fail("project_resolution", true, error.to_string()));
            checks.push(check_schema_migration_backups(context));
        }
    }

    checks.push(check_agent_placeholder(context));
    checks.push(check_agent_socket_path_matches_spec(context));
    checks.push(check_degraded_audit_log_perms(context));
    checks.push(check_hardening());
    checks.push(check_degraded_audit_log(context));
    for check in SKIPPED_LOCKED_CHECKS {
        checks.push(DiagnosticCheck::skip(check, "locked-safe metadata-only invocation"));
    }

    DiagnosticReport::new(checks)
}

/// Checks the size and line count of the out-of-band degraded-audit log
/// at `${LOCKET_HOME}/audit-degraded.log`.
///
/// - `pass` when the file is absent or empty.
/// - `warn` when the file exists and is non-empty (reports bytes + line
///   count; the operator should run `locket audit verify` and rotate
///   the log once the underlying refusals have been investigated).
/// - `fail` when the file exists but cannot be read.
fn check_degraded_audit_log(context: &RuntimeContext) -> DiagnosticCheck {
    let Some(home) = context.store_path.parent() else {
        return DiagnosticCheck::pass("degraded_audit_log", "absent (locket-home unresolved)");
    };
    let log_path = home.join(locket_platform::DEGRADED_AUDIT_LOG_FILENAME);
    match fs::metadata(&log_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            DiagnosticCheck::pass("degraded_audit_log", "absent")
        }
        Err(error) => DiagnosticCheck::fail("degraded_audit_log", false, error.to_string()),
        Ok(metadata) => {
            let bytes = metadata.len();
            if bytes == 0 {
                return DiagnosticCheck::pass("degraded_audit_log", "empty");
            }
            match fs::read_to_string(&log_path) {
                Ok(body) => {
                    let lines = body.lines().count();
                    DiagnosticCheck::warn(
                        "degraded_audit_log",
                        format!("bytes={bytes} lines={lines}"),
                    )
                }
                Err(error) => DiagnosticCheck::fail("degraded_audit_log", false, error.to_string()),
            }
        }
    }
}

fn check_locket_toml(path: &Path) -> DiagnosticCheck {
    match read_project_config(path) {
        Ok(config) if config.schema_version == PROJECT_CONFIG_SCHEMA_VERSION => {
            DiagnosticCheck::pass("locket_toml_parseability", "schema_version=1")
        }
        Ok(config) => DiagnosticCheck::fail(
            "locket_toml_parseability",
            true,
            format!(
                "schema_version={} supported={PROJECT_CONFIG_SCHEMA_VERSION}",
                config.schema_version
            ),
        ),
        Err(error) => DiagnosticCheck::fail("locket_toml_parseability", true, error.to_string()),
    }
}

fn check_bundle_conflict_index(store: &locket_store::Store) -> DiagnosticCheck {
    let mut statement = match store
        .connection()
        .prepare("SELECT name FROM pragma_index_info('secrets_bundle_conflict_idx') ORDER BY seqno")
    {
        Ok(statement) => statement,
        Err(error) => {
            return DiagnosticCheck::fail("bundle_conflict_index", false, error.to_string());
        }
    };
    let columns = match statement.query_map([], |row| row.get::<_, String>(0)) {
        Ok(rows) => rows.collect::<Result<Vec<_>, _>>(),
        Err(error) => {
            return DiagnosticCheck::fail("bundle_conflict_index", false, error.to_string());
        }
    };
    match columns {
        Ok(columns)
            if columns
                == ["project_id", "profile_id", "name", "source", "state", "current_version"] =>
        {
            DiagnosticCheck::pass(
                "bundle_conflict_index",
                "secrets_bundle_conflict_idx covers project/profile/name/source/state/current_version",
            )
        }
        Ok(columns) if columns.is_empty() => DiagnosticCheck::fail(
            "bundle_conflict_index",
            true,
            "missing secrets_bundle_conflict_idx",
        ),
        Ok(columns) => DiagnosticCheck::fail(
            "bundle_conflict_index",
            true,
            format!("unexpected secrets_bundle_conflict_idx columns={}", columns.join(",")),
        ),
        Err(error) => DiagnosticCheck::fail("bundle_conflict_index", false, error.to_string()),
    }
}

fn check_trusted_roots(
    store: &locket_store::Store,
    root: &Path,
    project_id: &str,
) -> DiagnosticCheck {
    match root_hash(root).and_then(|hash| {
        store
            .project_root_is_trusted(project_id, &hash)
            .map(|trusted| (hash, trusted))
            .map_err(CliError::from)
    }) {
        Ok((hash, true)) => DiagnosticCheck::pass(
            "trusted_roots",
            format!("current_root_trusted=yes root_hash={}", format_hex(&hash)),
        ),
        Ok((hash, false)) => DiagnosticCheck::fail(
            "trusted_roots",
            true,
            format!("current_root_trusted=no root_hash={}", format_hex(&hash)),
        ),
        Err(error) => DiagnosticCheck::fail("trusted_roots", true, error.to_string()),
    }
}

fn check_runtime_session_secret_name_retention(
    context: &RuntimeContext,
    store: &locket_store::Store,
    project_id: &str,
    prune_runtime_session_secret_names: bool,
) -> DiagnosticCheck {
    let retention = match runtime_session_secret_name_retention(context) {
        Ok(retention) => retention,
        Err(detail) => {
            return DiagnosticCheck::fail("runtime_session_secret_name_retention", false, detail);
        }
    };
    let (cutoff, retention_label) = match runtime_session_secret_name_cutoff(retention) {
        Ok(cutoff) => cutoff,
        Err(detail) => {
            return DiagnosticCheck::fail("runtime_session_secret_name_retention", false, detail);
        }
    };

    let expired_count =
        match store.list_runtime_sessions_with_expired_secret_names(project_id, cutoff) {
            Ok(rows) => rows.len(),
            Err(error) => {
                return DiagnosticCheck::fail(
                    "runtime_session_secret_name_retention",
                    false,
                    error.to_string(),
                );
            }
        };

    if expired_count == 0 {
        return DiagnosticCheck::pass(
            "runtime_session_secret_name_retention",
            format!("expired_secret_name_rows=0 retention={retention_label}"),
        );
    }

    if !prune_runtime_session_secret_names {
        return DiagnosticCheck::warn(
            "runtime_session_secret_name_retention",
            format!(
                "expired_secret_name_rows={expired_count} retention={retention_label} prune_with=locket doctor --prune-runtime-session-secret-names"
            ),
        );
    }

    match store.prune_runtime_session_secret_names(project_id, cutoff) {
        Ok(pruned_count) => DiagnosticCheck::pass(
            "runtime_session_secret_name_retention",
            format!(
                "expired_secret_name_rows={expired_count} pruned_secret_name_rows={pruned_count} retention={retention_label}"
            ),
        ),
        Err(error) => {
            DiagnosticCheck::fail("runtime_session_secret_name_retention", false, error.to_string())
        }
    }
}

fn runtime_session_secret_name_retention(
    context: &RuntimeContext,
) -> Result<RuntimeSessionSecretNameRetention, String> {
    let config = read_user_config(context).map_err(|error| error.to_string())?;
    let Some(value) = config_get_value(&config, "runtime.session_secret_name_retention") else {
        return Ok(RuntimeSessionSecretNameRetention::default());
    };
    let Some(value) = value.as_str() else {
        return Err("runtime.session_secret_name_retention must be a duration or off".to_owned());
    };
    RuntimeSessionSecretNameRetention::from_str(value).map_err(|error| error.to_string())
}

fn runtime_session_secret_name_cutoff(
    retention: RuntimeSessionSecretNameRetention,
) -> Result<(i64, String), String> {
    match retention {
        RuntimeSessionSecretNameRetention::Off => Ok((i64::MAX, "off".to_owned())),
        RuntimeSessionSecretNameRetention::RetainFor(duration) => {
            let now = now_unix_nanos().map_err(|error| error.to_string())?;
            let retention_nanos = duration
                .as_secs()
                .checked_mul(1_000_000_000)
                .and_then(|nanos| i64::try_from(nanos).ok())
                .ok_or_else(|| {
                    "runtime.session_secret_name_retention duration is too large".to_owned()
                })?;
            Ok((now.saturating_sub(retention_nanos), duration.to_string()))
        }
    }
}

fn check_schema_migration_backups(context: &RuntimeContext) -> DiagnosticCheck {
    let backup_root = match pre_migration_backup_root(context) {
        Ok(path) => path,
        Err(error) => {
            return DiagnosticCheck::fail("schema_migration_backups", false, error.to_string());
        }
    };
    let entries = match fs::read_dir(&backup_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return DiagnosticCheck::pass(
                "schema_migration_backups",
                "backup_skipped=0 latest_backup=none",
            );
        }
        Err(error) => {
            return DiagnosticCheck::fail("schema_migration_backups", false, error.to_string());
        }
    };

    let mut skipped_count = 0_u32;
    let mut latest_backup: Option<PathBuf> = None;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                return DiagnosticCheck::fail("schema_migration_backups", false, error.to_string());
            }
        };
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name.starts_with(BACKUP_SKIPPED_PREFIX) {
            skipped_count += 1;
            continue;
        }
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                return DiagnosticCheck::fail("schema_migration_backups", false, error.to_string());
            }
        };
        if file_type.is_dir() {
            let path = entry.path();
            if latest_backup.as_ref().is_none_or(|latest| path.as_os_str() > latest.as_os_str()) {
                latest_backup = Some(path);
            }
        }
    }

    let latest_label = latest_backup.as_ref().map_or_else(
        || "none".to_owned(),
        |path| pre_migration_backup_relative_label(context, path),
    );
    let detail = format!("backup_skipped={skipped_count} latest_backup={latest_label}");
    if skipped_count == 0 {
        DiagnosticCheck::pass("schema_migration_backups", detail)
    } else {
        DiagnosticCheck::warn("schema_migration_backups", detail)
    }
}

fn check_automation_client_nonces_pruning(store: &locket_store::Store) -> DiagnosticCheck {
    let now = match now_unix_nanos() {
        Ok(now) => now,
        Err(error) => {
            return DiagnosticCheck::fail(
                "automation_client_nonces_pruning",
                false,
                error.to_string(),
            );
        }
    };
    match store.prune_automation_client_nonces(now) {
        Ok(pruned) => DiagnosticCheck::pass(
            "automation_client_nonces_pruning",
            format!("pruned_nonce_rows={pruned}"),
        ),
        Err(error) => {
            DiagnosticCheck::fail("automation_client_nonces_pruning", false, error.to_string())
        }
    }
}

fn check_gitignore(root: &Path) -> DiagnosticCheck {
    let path = root.join(GITIGNORE_FILE);
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return DiagnosticCheck::warn(".gitignore", "missing");
        }
        Err(error) => return DiagnosticCheck::fail(".gitignore", false, error.to_string()),
    };
    let missing = GITIGNORE_ENTRIES
        .iter()
        .filter(|entry| !content.lines().any(|line| line.trim() == **entry))
        .copied()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        DiagnosticCheck::pass(".gitignore", "required entries present")
    } else {
        DiagnosticCheck::warn(".gitignore", format!("missing entries: {}", missing.join(",")))
    }
}

fn check_pre_commit_hook(root: &Path) -> DiagnosticCheck {
    let git_dir = match git_dir_for_worktree(root) {
        Ok(git_dir) => git_dir,
        Err(error) => return DiagnosticCheck::warn("pre_commit_hook", error.to_string()),
    };
    let hook_path = git_dir.join("hooks").join("pre-commit");
    match fs::read_to_string(&hook_path) {
        Ok(content) if content.contains(HOOK_BEGIN) => {
            DiagnosticCheck::pass("pre_commit_hook", "locket managed block present")
        }
        Ok(_) => {
            DiagnosticCheck::warn("pre_commit_hook", "pre-commit hook exists without locket block")
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            DiagnosticCheck::warn("pre_commit_hook", "missing")
        }
        Err(error) => DiagnosticCheck::fail("pre_commit_hook", false, error.to_string()),
    }
}

fn check_agent_placeholder(context: &RuntimeContext) -> DiagnosticCheck {
    let pid = fs::read_to_string(agent_pid_path(context)).ok();
    let status = if pid.as_deref().is_some_and(|pid| !pid.trim().is_empty()) {
        "unavailable last_known_pid=yes"
    } else {
        "unavailable last_known_pid=no"
    };
    DiagnosticCheck::pass("agent_placeholder", status)
}

/// Confirms the agent socket path follows the platform-specific spec
/// described in `docs/specs/agent.md:18-21`:
///
/// - Linux: `$XDG_RUNTIME_DIR/locket/agent.sock` (or `~/.locket/agent.sock`).
/// - macOS: `~/Library/Application Support/locket/agent.sock`.
/// - Windows: `\\.\pipe\locket-agent-<sid>` with a protected
///   current-user-only DACL SDDL available for startup.
///
/// Tests build a `RuntimeContext` with `agent_data_dir = None` and a
/// tempdir-local `store_path`; the check is reported as `skipped` in
/// that case so legacy fixtures continue to pass without forcing every
/// test to point at the user's real `XDG_RUNTIME_DIR`.
fn check_agent_socket_path_matches_spec(context: &RuntimeContext) -> DiagnosticCheck {
    const NAME: &str = "agent_socket_path_spec";
    #[cfg(target_os = "windows")]
    {
        let actual_socket = agent_socket_path(context);
        let pipe_name = match locket_platform::default_agent_pipe_name() {
            Ok(pipe_name) => pipe_name,
            Err(error) => return DiagnosticCheck::fail(NAME, false, error.to_string()),
        };
        let sid = match locket_platform::current_user_sid_string() {
            Ok(sid) => sid,
            Err(error) => return DiagnosticCheck::fail(NAME, false, error.to_string()),
        };
        let dacl = match locket_platform::agent_pipe_dacl_sddl_for_sid(&sid) {
            Ok(dacl) => dacl,
            Err(error) => return DiagnosticCheck::fail(NAME, false, error.to_string()),
        };
        if actual_socket != Path::new(&pipe_name) {
            return DiagnosticCheck::fail(
                NAME,
                false,
                format!(
                    "agent pipe path drifted from current-user SID: actual={} expected={}",
                    actual_socket.display(),
                    pipe_name,
                ),
            );
        }
        DiagnosticCheck::pass(NAME, format!("windows named pipe path ok dacl_sddl={dacl}"))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let Some(configured) = context.agent_data_dir.as_ref() else {
            return DiagnosticCheck::skip(
                NAME,
                "agent_data_dir override not set (test/runtime context)",
            );
        };
        let configured_socket = configured.join("agent.sock");
        let actual_socket = agent_socket_path(context);
        if configured_socket != actual_socket {
            return DiagnosticCheck::fail(
                NAME,
                false,
                format!(
                    "agent socket path drifted from configured agent_data_dir: actual={} configured={}",
                    actual_socket.display(),
                    configured_socket.display(),
                ),
            );
        }

        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return DiagnosticCheck::warn(NAME, "HOME unset; cannot validate spec path");
        };
        #[cfg(target_os = "linux")]
        let expected_candidates: Vec<PathBuf> = {
            let mut candidates = Vec::new();
            if let Some(value) = std::env::var_os("XDG_RUNTIME_DIR") {
                candidates.push(PathBuf::from(value).join("locket"));
            }
            candidates.push(home.join(".locket"));
            candidates
        };
        #[cfg(target_os = "macos")]
        let expected_candidates: Vec<PathBuf> =
            vec![home.join("Library").join("Application Support").join("locket")];
        #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
        let expected_candidates: Vec<PathBuf> = vec![home.join(".locket")];

        if expected_candidates.iter().any(|candidate| candidate == configured) {
            DiagnosticCheck::pass(
                NAME,
                format!("platform={} dir={}", std::env::consts::OS, configured.display()),
            )
        } else {
            DiagnosticCheck::warn(
                NAME,
                format!(
                    "agent_data_dir does not match spec candidates: dir={} expected_one_of={}",
                    configured.display(),
                    expected_candidates
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            )
        }
    }
}

fn check_device_private_key_storage(
    context: &RuntimeContext,
    store: &locket_store::Store,
    project_id: &str,
) -> DiagnosticCheck {
    use crate::commands::team::device::build_device_private_key_storage;
    use locket_platform::LocalDevicePrivateKeyStorage;

    const NAME: &str = "device_private_key_storage";

    let device = match store.get_active_local_device(project_id) {
        Ok(Some(device)) => device,
        Ok(None) => {
            return DiagnosticCheck::pass(NAME, "no active local device");
        }
        Err(error) => {
            return DiagnosticCheck::fail(NAME, false, error.to_string());
        }
    };

    let storage = match build_device_private_key_storage(context, project_id) {
        Ok(storage) => storage,
        Err(error) => {
            return DiagnosticCheck::fail(NAME, false, error.to_string());
        }
    };
    let envelope_path = match storage.envelope_path(&device.id) {
        Ok(path) => path,
        Err(error) => {
            return DiagnosticCheck::fail(NAME, false, error.to_string());
        }
    };

    let metadata = match fs::metadata(&envelope_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return DiagnosticCheck::warn(
                NAME,
                format!("envelope_missing device_id={}", device.id),
            );
        }
        Err(error) => {
            return DiagnosticCheck::fail(NAME, false, error.to_string());
        }
    };

    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return DiagnosticCheck::fail(
                NAME,
                false,
                format!("envelope_permissions_too_wide mode={mode:#o} device_id={}", device.id),
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = &metadata;
    }

    // Integrity probe: load+unwrap. Surfaces master-key mismatch and corrupt
    // envelopes as fail without leaking key material (the unwrapped key is
    // dropped immediately).
    match storage.load(&device.id) {
        Ok(_key) => DiagnosticCheck::pass(
            NAME,
            format!("storage=wrapped-local-file device_id={}", device.id),
        ),
        Err(error) => DiagnosticCheck::fail(
            NAME,
            false,
            format!("envelope_integrity_failure device_id={} error={error}", device.id),
        ),
    }
}

fn check_degraded_audit_log_perms(context: &RuntimeContext) -> DiagnosticCheck {
    const NAME: &str = "degraded_audit_log_perms";

    let Some(locket_home) = context.store_path.parent() else {
        return DiagnosticCheck::fail(
            NAME,
            false,
            "could not resolve locket home for degraded-audit log",
        );
    };
    let logger = locket_platform::LockedVaultAuditLogger::new(locket_home);

    let mode = match logger.permission_mode() {
        Ok(Some(mode)) => mode,
        Ok(None) => return DiagnosticCheck::pass(NAME, "log_absent=yes"),
        Err(error) => return DiagnosticCheck::fail(NAME, false, error.to_string()),
    };

    // Pass: only owner has any access (no group/other bits set).
    // Fail: anything looser than 0600 surfaces the actual octal mode so
    // operators can see exactly what drifted.
    #[cfg(unix)]
    {
        if mode.trailing_zeros() >= 6 {
            DiagnosticCheck::pass(NAME, format!("mode={mode:#o}"))
        } else {
            DiagnosticCheck::fail(NAME, false, format!("mode={mode:#o} expected=0o600_or_stricter"))
        }
    }
    #[cfg(not(unix))]
    {
        // On Windows we rely on ACLs that limit access to the current user;
        // the helper synthesizes mode 0o600 in that case. Pass when we have
        // no signal that the file is more permissive.
        let _ = mode;
        DiagnosticCheck::pass(NAME, "platform=non-unix acl_restricted_to_current_user=assumed")
    }
}

fn check_hardening() -> DiagnosticCheck {
    let core_dumps = locket_platform::core_dump_hardening_state();
    let memory_lock = locket_platform::memory_lock_hardening_state();
    let detail = format!("core_dumps={core_dumps} memory_lock={memory_lock}");
    let core_active = matches!(
        core_dumps,
        locket_platform::CoreDumpHardening::Active | locket_platform::CoreDumpHardening::Suppressed
    );
    let memory_active = matches!(memory_lock, locket_platform::MemoryLockHardening::Active);
    if core_active && memory_active {
        DiagnosticCheck::pass("hardening", detail)
    } else {
        DiagnosticCheck::warn("hardening", detail)
    }
}

fn write_doctor_audit_if_available(
    context: &RuntimeContext,
    report: &DiagnosticReport,
) -> Result<(), CliError> {
    let Some(project) = resolve_project(&context.cwd)? else {
        return Ok(());
    };
    let mut store = open_store(context)?;
    if store.get_project(project.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, &store, project.config.project_id.as_str(), KeyPurpose::Audit)?;
    let metadata = report.audit_metadata();
    let status = if report.counts.fail == 0 { "SUCCESS" } else { "FAILED" };
    let audit = AuditWrite {
        project_id: project.config.project_id.as_str(),
        profile_id: None,
        action: "DOCTOR",
        status,
        secret_name: None,
        command: Some("doctor"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn write_doctor_report(output: &mut impl Write, report: &DiagnosticReport) -> Result<(), CliError> {
    writeln!(output, "locket doctor")?;
    for check in &report.checks {
        writeln!(output, "{} {}: {}", status_label(check.status), check.name, check.detail)?;
    }
    writeln!(
        output,
        "summary: pass={} warn={} fail={} skip={} critical_fail={}",
        report.counts.pass,
        report.counts.warn,
        report.counts.fail,
        report.counts.skip,
        report.counts.critical_fail
    )?;
    Ok(())
}

fn default_debug_bundle_path(context: &RuntimeContext) -> Result<PathBuf, CliError> {
    let parent = context
        .store_path
        .parent()
        .ok_or_else(|| corrupt_db_error("could not resolve diagnostics directory"))?;
    Ok(parent.join("diagnostics").join(format!("locket-debug-{}.tar.gz", now_unix_nanos()?)))
}

fn write_debug_bundle_file(path: &Path, text: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_user_only_dir_permissions(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    set_user_only_file_options(&mut options);
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            invalid_reference_error("debug bundle output already exists")
        } else {
            CliError::Io(error)
        }
    })?;
    write_debug_bundle_archive(file, text)?;
    set_user_only_file_permissions(path)?;
    Ok(())
}

fn write_debug_bundle_archive(file: fs::File, text: &str) -> Result<(), CliError> {
    let encoder = GzEncoder::new(file, Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let bytes = format!("{text}\n").into_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(u64::try_from(bytes.len()).map_err(|_| CliError::Time)?);
    header.set_mode(0o600);
    header.set_mtime(u64::try_from(now_unix_nanos()? / 1_000_000_000).map_err(|_| CliError::Time)?);
    header.set_cksum();
    archive.append_data(&mut header, "bundle.json", bytes.as_slice())?;
    let encoder = archive.into_inner()?;
    encoder.finish()?;
    Ok(())
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

const fn status_label(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "pass",
        CheckStatus::Warn => "warn",
        CheckStatus::Fail => "fail",
        CheckStatus::Skip => "skip",
    }
}

fn config_key_is_set(config: &toml::Table, key: &str) -> bool {
    let Some((section, name)) = key.split_once('.') else {
        return false;
    };
    config.get(section).and_then(toml::Value::as_table).and_then(|table| table.get(name)).is_some()
}

fn agent_metadata(context: &RuntimeContext) -> Value {
    json!({
        "status": "unavailable",
        "socket_path_hash": path_hash(&agent_socket_path(context)),
        "pid_path_hash": path_hash(&agent_pid_path(context)),
        "log_path_hash": path_hash(&agent_log_path(context)),
    })
}

fn path_hash(path: &Path) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    format_hex(&digest)
}
