//! Best-effort wiring of [`LockedVaultAuditLogger`] for the agent's
//! refused-while-locked early-return sites.
//!
//! The agent cannot append to the encrypted audit chain while the vault
//! is locked because the audit key is sealed with the master key. Each
//! `UnlockRequired` early-return therefore mirrors a metadata-only row
//! into the degraded-audit log under
//! `${LOCKET_HOME}/audit-degraded.log`. See
//! `crates/locket-platform/src/locked_vault_audit.rs` for the format,
//! rotation policy, and 0600 permission contract.
//!
//! Logging is best-effort: a failure to append never masks the typed
//! `UnlockRequired` response.

use std::path::{Path, PathBuf};

use locket_platform::{LockedVaultAuditLogger, LockedVaultDenialRow};

/// Resolves `${LOCKET_HOME}` for the agent. Prefers `store_path.parent()`
/// when the request supplied a store path, then the `LOCKET_HOME`
/// environment variable, and finally the current instance's platform
/// data directory the rest of the agent uses for production stores.
fn locket_home(store_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(parent) = store_path.and_then(Path::parent)
        && !parent.as_os_str().is_empty()
    {
        return Some(parent.to_path_buf());
    }
    if let Ok(value) = std::env::var("LOCKET_HOME")
        && !value.is_empty()
    {
        return Some(PathBuf::from(value));
    }
    locket_platform::LocketInstance::current()
        .project_dirs()
        .map(|dirs| dirs.data_dir().to_path_buf())
}

fn ts_unix_nanos(now_unix_nanos: i128) -> i64 {
    i64::try_from(now_unix_nanos).unwrap_or(i64::MAX)
}

/// Appends a `DENIED_LOCKED` row mirroring an agent refused-while-locked
/// early return. Best-effort: silently swallows any append failure so
/// the typed `UnlockRequired` response is never blocked on audit
/// availability.
pub fn record_locked_refusal(
    action: &str,
    project_id: Option<&str>,
    command: &str,
    store_path: Option<&Path>,
    now_unix_nanos: i128,
) {
    let Some(home) = locket_home(store_path) else {
        return;
    };
    let logger = LockedVaultAuditLogger::new(&home);
    let row = LockedVaultDenialRow::new(
        action,
        project_id,
        ts_unix_nanos(now_unix_nanos),
        "vault_locked",
        command,
    );
    let _ = logger.append(&row);
}

#[cfg(test)]
mod tests {
    use std::fs;

    use locket_platform::DEGRADED_AUDIT_LOG_FILENAME;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn record_locked_refusal_writes_to_store_path_parent() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let store_path = directory.path().join("store.db");
        record_locked_refusal(
            "REVEAL",
            Some("lk_proj_x"),
            "agent.Reveal",
            Some(&store_path),
            1_700_000_000_000_000_000,
        );
        let log = directory.path().join(DEGRADED_AUDIT_LOG_FILENAME);
        let body = fs::read_to_string(&log)?;
        let value: serde_json::Value = serde_json::from_str(
            body.lines().next().ok_or("degraded audit should include one line")?,
        )?;
        assert_eq!(value["action"], "REVEAL");
        assert_eq!(value["status"], "DENIED_LOCKED");
        assert_eq!(value["project_id"], "lk_proj_x");
        assert_eq!(value["command"], "agent.Reveal");
        assert_eq!(value["failure_reason"], "vault_locked");
        Ok(())
    }

    #[test]
    fn record_locked_refusal_with_no_store_path_uses_project_dirs_or_skips() {
        // We cannot guarantee a project-dirs path on every CI host, but
        // the helper must not panic when one is unavailable.
        record_locked_refusal(
            "PREPARE_EXEC",
            None,
            "agent.PrepareExec",
            None,
            1_700_000_000_000_000_000,
        );
    }
}
