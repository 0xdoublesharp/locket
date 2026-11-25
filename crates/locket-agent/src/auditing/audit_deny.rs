//! Best-effort `AGENT_REVOKE DENIED` audit row emission for grant-denial
//! returns from `Reveal`, `Copy`, `ScanKnownValues`, and `ResolveReference`.
//!
//! Per `docs/specs/audit.md`, refused grant-required operations should leave
//! a metadata-only `DENIED` audit row. The grant-denial paths land in the
//! encrypted store, so the audit append is gated on the project's master key
//! still being cached. When the master key is unavailable (vault locked or
//! never cached) the helper silently skips the append rather than failing
//! the typed error response; the `audit-deny-locked-vault` work covers the
//! degraded-audit channel for the locked-vault case.

use std::path::Path;

use locket_store::AuditWrite;
use serde_json::json;

use crate::grant::GrantAction;
use crate::keys::{master_key_array, open_verified_store_for_state, unwrap_audit_key_with_master};

/// Append a metadata-only `AGENT_REVOKE DENIED` audit row best-effort.
///
/// Returns `true` when a row was successfully appended. Any failure (locked
/// vault, missing keys, store I/O) is swallowed so the agent's typed
/// `GrantRequired` response is never blocked on audit availability.
#[allow(clippy::too_many_arguments)]
pub async fn try_append_grant_denial(
    state: &crate::AgentSocketState,
    project_id: &str,
    profile_id: &str,
    store_path: Option<&Path>,
    master_key: Option<&[u8]>,
    grant_action: GrantAction,
    ttl_seconds: u32,
    timestamp_unix_nanos: i128,
    client_kind: &str,
) -> bool {
    let Some(store_path) = store_path else { return false };
    let Some(master_key) = master_key else { return false };
    let Ok(master_key) = master_key_array(master_key) else { return false };
    let Ok(timestamp) = i64::try_from(timestamp_unix_nanos) else { return false };
    let Ok((mut store, _)) =
        open_verified_store_for_state(state, project_id, store_path, timestamp_unix_nanos).await
    else {
        return false;
    };
    let Ok(audit_key) = unwrap_audit_key_with_master(&store, project_id, &master_key) else {
        return false;
    };
    let action = "AGENT_REVOKE";
    let status = "DENIED";
    let metadata = json!({
        "schema_version": 1,
        "action": action,
        "status": status,
        "project_id": project_id,
        "profile_id": profile_id,
        "client_kind": client_kind,
        "grant_actions": [grant_action_label(grant_action)],
        "ttl_seconds": ttl_seconds,
        "failure_reason": "grant_required",
    });
    let audit = AuditWrite {
        project_id,
        profile_id: Some(profile_id),
        action,
        status,
        secret_name: None,
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit).is_ok()
}

const fn grant_action_label(action: GrantAction) -> &'static str {
    match action {
        GrantAction::RunPolicy => "RunPolicy",
        GrantAction::PrepareExec => "PrepareExec",
        GrantAction::ResolveReference => "ResolveReference",
        GrantAction::ScanKnownValues => "ScanKnownValues",
        GrantAction::Reveal => "Reveal",
        GrantAction::Copy => "Copy",
        GrantAction::Redact => "Redact",
        GrantAction::Export => "Export",
        GrantAction::SetSecret => "SetSecret",
        GrantAction::CreateProfile => "CreateProfile",
        GrantAction::DeleteSecret => "DeleteSecret",
        GrantAction::CopySecretToShared => "CopySecretToShared",
        GrantAction::ImportDotenv => "ImportDotenv",
        GrantAction::ApplyPolicy => "ApplyPolicy",
        GrantAction::TeamSync => "TeamSync",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn try_append_grant_denial_returns_false_without_master_key() {
        let appended = try_append_grant_denial(
            &crate::AgentSocketState::locked("test"),
            "lk_proj_x",
            "lk_profile_x",
            None,
            None,
            GrantAction::Reveal,
            0,
            1_700_000_000_000_000_000,
            "agent",
        )
        .await;
        assert!(!appended, "no master key means no row is appended");
    }

    #[tokio::test]
    async fn try_append_grant_denial_returns_false_without_store_path() {
        let key = [0_u8; 32];
        let appended = try_append_grant_denial(
            &crate::AgentSocketState::locked("test"),
            "lk_proj_x",
            "lk_profile_x",
            None,
            Some(&key),
            GrantAction::Reveal,
            0,
            1_700_000_000_000_000_000,
            "agent",
        )
        .await;
        assert!(!appended, "no store path means no row is appended");
    }

    #[test]
    fn grant_action_labels_are_stable() {
        assert_eq!(grant_action_label(GrantAction::Reveal), "Reveal");
        assert_eq!(grant_action_label(GrantAction::Copy), "Copy");
        assert_eq!(grant_action_label(GrantAction::ScanKnownValues), "ScanKnownValues");
        assert_eq!(grant_action_label(GrantAction::ResolveReference), "ResolveReference");
        assert_eq!(grant_action_label(GrantAction::RunPolicy), "RunPolicy");
        assert_eq!(grant_action_label(GrantAction::SetSecret), "SetSecret");
    }
}
