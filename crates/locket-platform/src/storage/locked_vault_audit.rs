//! Out-of-band degraded-audit JSON-lines log for refused-while-locked
//! operations.
//!
//! When the encrypted vault is locked, the agent and CLI cannot append to
//! the project's HMAC-chained audit log because the audit key is sealed
//! with the master key. Refused-while-locked operations would otherwise
//! be silently dropped, hiding a class of security-relevant denials.
//!
//! This module writes a plain-text JSON-lines record per refusal at
//! `${LOCKET_HOME}/audit-degraded.log`, rotated at 1 MiB. Each line
//! carries metadata-only fields - never secret values, never
//! `secret_name`. A `locket doctor` check warns when the file exists and
//! is non-empty.
//!
//! Rotation policy: when `audit-degraded.log` reaches 1 MiB it is
//! renamed to `audit-degraded.log.1`. Existing `.1` becomes `.2` and so
//! on; the log keeps the most recent five rotations and discards older
//! ones.
//!
//! File permissions are 0600 on Unix so the log is readable only by the
//! owning user, matching `store.db` and the recovery envelope.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::PlatformError;
use crate::fs_helpers::write_user_only_file;

/// Default file name for the degraded-audit log.
pub const DEGRADED_AUDIT_LOG_FILENAME: &str = "audit-degraded.log";

/// Rotation threshold in bytes (1 MiB).
pub const DEGRADED_AUDIT_LOG_ROTATE_BYTES: u64 = 1024 * 1024;

/// Maximum number of rotated copies to keep (oldest is discarded).
pub const DEGRADED_AUDIT_LOG_MAX_ROTATIONS: u32 = 5;

/// Schema version recorded on every line.
pub const DEGRADED_AUDIT_LOG_SCHEMA_VERSION: u32 = 1;

/// Single denial record written when an operation is refused because the
/// vault is locked.
///
/// Names only - never values, never `secret_name`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LockedVaultDenialRow<'a> {
    /// Schema version. Always 1 today.
    pub schema_version: u32,
    /// Audit action being refused (`GET`, `REVEAL`, `COPY`, `EXEC`, etc.).
    pub action: &'a str,
    /// Always `"DENIED_LOCKED"`.
    pub status: &'a str,
    /// Optional project identifier when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<&'a str>,
    /// Event timestamp in nanoseconds since the Unix epoch.
    pub ts_unix_nanos: i64,
    /// Stable failure reason (e.g. `"vault_locked"`).
    pub failure_reason: &'a str,
    /// Command surface (e.g. `"get"`, `"agent.Reveal"`).
    pub command: &'a str,
}

impl<'a> LockedVaultDenialRow<'a> {
    /// Constructs a denial row with the standard `DENIED_LOCKED` status.
    #[must_use]
    pub const fn new(
        action: &'a str,
        project_id: Option<&'a str>,
        ts_unix_nanos: i64,
        failure_reason: &'a str,
        command: &'a str,
    ) -> Self {
        Self {
            schema_version: DEGRADED_AUDIT_LOG_SCHEMA_VERSION,
            action,
            status: "DENIED_LOCKED",
            project_id,
            ts_unix_nanos,
            failure_reason,
            command,
        }
    }
}

/// Append-only logger for refused-while-locked operations.
///
/// Each call to [`LockedVaultAuditLogger::append`] serializes the row as
/// canonical compact JSON, appends it (with a trailing newline) to the
/// configured log path, ensures the file mode is 0600 on Unix, and
/// rotates when the threshold is reached.
#[derive(Clone, Debug)]
pub struct LockedVaultAuditLogger {
    log_path: PathBuf,
    rotate_threshold_bytes: u64,
    max_rotations: u32,
}

impl LockedVaultAuditLogger {
    /// Returns the canonical degraded-audit log path under `locket_home`.
    #[must_use]
    pub fn default_path(locket_home: &Path) -> PathBuf {
        locket_home.join(DEGRADED_AUDIT_LOG_FILENAME)
    }

    /// Creates a logger using the default rotation policy.
    #[must_use]
    pub fn new(locket_home: &Path) -> Self {
        Self {
            log_path: Self::default_path(locket_home),
            rotate_threshold_bytes: DEGRADED_AUDIT_LOG_ROTATE_BYTES,
            max_rotations: DEGRADED_AUDIT_LOG_MAX_ROTATIONS,
        }
    }

    /// Creates a logger with a custom log path and rotation policy.
    /// Used by tests to exercise rotation without writing 1 MiB of data.
    #[must_use]
    pub const fn with_policy(
        log_path: PathBuf,
        rotate_threshold_bytes: u64,
        max_rotations: u32,
    ) -> Self {
        Self { log_path, rotate_threshold_bytes, max_rotations }
    }

    /// Returns the configured log path.
    #[must_use]
    pub fn log_path(&self) -> &Path {
        self.log_path.as_path()
    }

    /// Appends a denial row to the degraded-audit log, rotating first if
    /// the existing log already meets or exceeds the rotation threshold.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Io`] when the parent directory is missing
    /// or the file cannot be opened, written, rotated, or chmoded.
    pub fn append(&self, row: &LockedVaultDenialRow<'_>) -> Result<(), PlatformError> {
        if let Some(parent) = self.log_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        if file_size_or_zero(&self.log_path) >= self.rotate_threshold_bytes {
            self.rotate()?;
        }
        let mut line = serde_json::to_string(row).map_err(PlatformError::DegradedAuditEncoding)?;
        line.push('\n');

        if self.log_path.exists() {
            let mut options = fs::OpenOptions::new();
            options.append(true).create(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&self.log_path)?;
            file.write_all(line.as_bytes())?;
        } else {
            write_user_only_file(&self.log_path, line.as_bytes())?;
        }
        ensure_user_only_permissions(&self.log_path)?;
        Ok(())
    }

    /// Returns the byte size of the active log file or zero when absent.
    #[must_use]
    pub fn current_size_bytes(&self) -> u64 {
        file_size_or_zero(&self.log_path)
    }

    /// Returns `true` when the log file exists and has at least one byte.
    #[must_use]
    pub fn has_records(&self) -> bool {
        self.current_size_bytes() > 0
    }

    /// Returns the on-disk permission mode bits of the active log file.
    ///
    /// Returns `Ok(None)` when the file is absent. On non-Unix platforms the
    /// returned mode reflects whatever Rust surfaces via [`fs::Metadata`]; on
    /// Unix the returned value is the lower 9 bits (`mode & 0o777`).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Io`] when the file exists but cannot be
    /// stat'd (e.g. permission denied on the parent directory).
    pub fn permission_mode(&self) -> Result<Option<u32>, PlatformError> {
        permission_mode(&self.log_path)
    }

    fn rotate(&self) -> Result<(), PlatformError> {
        // Discard the oldest, then shift each rotation up by one index.
        let oldest = rotated_path(&self.log_path, self.max_rotations);
        if oldest.exists() {
            fs::remove_file(&oldest)?;
        }
        let mut index = self.max_rotations;
        while index > 1 {
            let from = rotated_path(&self.log_path, index - 1);
            let to = rotated_path(&self.log_path, index);
            if from.exists() {
                fs::rename(&from, &to)?;
            }
            index -= 1;
        }
        let first = rotated_path(&self.log_path, 1);
        if self.log_path.exists() {
            fs::rename(&self.log_path, &first)?;
        }
        Ok(())
    }
}

/// Returns the on-disk permission bits of `path`.
///
/// Returns `Ok(None)` when the path does not exist. On Unix the returned mode
/// is masked to the lower 9 bits (`mode & 0o777`).
///
/// # Errors
///
/// Returns [`PlatformError::Io`] for stat failures other than `NotFound`.
pub fn permission_mode(path: &Path) -> Result<Option<u32>, PlatformError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Ok(Some(metadata.permissions().mode() & 0o777))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(Some(0o600))
    }
}

fn rotated_path(base: &Path, index: u32) -> PathBuf {
    let mut name =
        base.file_name().map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    name.push('.');
    name.push_str(&index.to_string());
    base.with_file_name(name)
}

fn file_size_or_zero(path: &Path) -> u64 {
    fs::metadata(path).map_or(0, |metadata| metadata.len())
}

#[cfg(unix)]
fn ensure_user_only_permissions(path: &Path) -> Result<(), PlatformError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Matches the fallible Unix permission helper.
const fn ensure_user_only_permissions(_path: &Path) -> Result<(), PlatformError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use tempfile::tempdir;

    fn sample_row<'a>(action: &'a str, command: &'a str) -> LockedVaultDenialRow<'a> {
        LockedVaultDenialRow::new(
            action,
            Some("lk_proj_x"),
            1_700_000_000_000_000_000,
            "vault_locked",
            command,
        )
    }

    #[test]
    fn append_writes_one_json_line_per_call() -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let logger = LockedVaultAuditLogger::new(directory.path());
        logger.append(&sample_row("GET", "get"))?;
        logger.append(&sample_row("REVEAL", "get --reveal"))?;

        let body = fs::read_to_string(logger.log_path())?;
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let value: serde_json::Value = serde_json::from_str(line)?;
            assert_eq!(value["schema_version"], 1);
            assert_eq!(value["status"], "DENIED_LOCKED");
            assert_eq!(value["failure_reason"], "vault_locked");
            assert_eq!(value["project_id"], "lk_proj_x");
            assert!(value.get("secret_name").is_none(), "must never include secret_name");
        }
        assert_eq!(serde_json::from_str::<serde_json::Value>(lines[0])?["action"], "GET");
        assert_eq!(serde_json::from_str::<serde_json::Value>(lines[1])?["action"], "REVEAL");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn append_sets_user_only_file_mode() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempdir()?;
        let logger = LockedVaultAuditLogger::new(directory.path());
        logger.append(&sample_row("GET", "get"))?;
        let metadata = fs::metadata(logger.log_path())?;
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "degraded audit log must be mode 0600");
        Ok(())
    }

    #[test]
    fn rotation_at_threshold_keeps_at_most_max_rotations() -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let log_path = directory.path().join("audit-degraded.log");
        // Tiny threshold so a single row triggers rotation.
        let logger = LockedVaultAuditLogger::with_policy(log_path.clone(), 16, 3);

        for _ in 0..6 {
            logger.append(&sample_row("GET", "get"))?;
        }

        assert!(log_path.exists(), "active log re-created after rotation");
        assert!(log_path.with_file_name("audit-degraded.log.1").exists());
        assert!(log_path.with_file_name("audit-degraded.log.2").exists());
        assert!(log_path.with_file_name("audit-degraded.log.3").exists());
        assert!(
            !log_path.with_file_name("audit-degraded.log.4").exists(),
            "rotations beyond max must not exist"
        );
        Ok(())
    }

    #[test]
    fn has_records_reports_log_state() -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let logger = LockedVaultAuditLogger::new(directory.path());
        assert!(!logger.has_records(), "fresh logger reports no records");
        logger.append(&sample_row("GET", "get"))?;
        assert!(logger.has_records(), "logger with one row reports records present");
        assert!(logger.current_size_bytes() > 0);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rotation_creates_new_tip_file_at_user_only_mode() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempdir()?;
        let log_path = directory.path().join("audit-degraded.log");
        let logger = LockedVaultAuditLogger::with_policy(log_path.clone(), 16, 3);

        // Force at least one rotation by writing many rows past the threshold.
        for _ in 0..3 {
            logger.append(&sample_row("GET", "get"))?;
        }
        // The active tip file must be at 0600 even after rotation.
        let metadata = fs::metadata(&log_path)?;
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rotated tip file must remain mode 0600");
        // The first rotated file must also still be 0600 (rename preserves
        // mode bits, the prior tip was 0600 when written).
        let rotated = log_path.with_file_name("audit-degraded.log.1");
        let rotated_meta = fs::metadata(&rotated)?;
        let rotated_mode = rotated_meta.permissions().mode() & 0o777;
        assert_eq!(rotated_mode, 0o600, "rotated copy must remain mode 0600");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn permission_mode_reports_active_tip_mode() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempdir()?;
        let logger = LockedVaultAuditLogger::new(directory.path());
        // Absent file -> None.
        assert_eq!(logger.permission_mode()?, None);
        logger.append(&sample_row("GET", "get"))?;
        assert_eq!(logger.permission_mode()?, Some(0o600));
        // Drift the perms on disk: the helper must surface the actual mode.
        fs::set_permissions(logger.log_path(), fs::Permissions::from_mode(0o644))?;
        assert_eq!(logger.permission_mode()?, Some(0o644));
        Ok(())
    }

    #[test]
    fn never_serializes_secret_name() -> Result<(), Box<dyn Error>> {
        let row = sample_row("REVEAL", "get --reveal");
        let json = serde_json::to_string(&row)?;
        assert!(!json.contains("secret_name"));
        assert!(!json.contains("\"value\""));
        Ok(())
    }
}
