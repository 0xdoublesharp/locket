//! Unit tests for the locket-agent protocol surface.
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use super::{
    AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, ErrorEnvelope, ListAuditResponse, ListSecretsResponse,
    LockState, PROTOCOL_VERSION, ProtocolError, RequestEnvelope, ResponseEnvelope,
    STATUS_HEARTBEAT_INTERVAL_SECS, StatusEvent, StatusEventKind, StatusEventSequence,
    StatusPayload, SuccessEnvelope, UnknownMethod, VerifyAuditResponse, decode_request_frame,
    decode_response_frame, encode_frame,
};
use serde_json::json;

fn test_grant_record(grant_id: &str, expires_at_unix_nanos: i128) -> crate::grant::GrantRecord {
    crate::grant::GrantRecord::new(crate::grant::GrantRecordFields {
        grant_id: grant_id.to_owned(),
        project_id: "p-1".to_owned(),
        profile_id: "prof-1".to_owned(),
        action: crate::grant::GrantAction::RunPolicy,
        binding: crate::grant::GrantBinding::new(std::process::id(), "0"),
        issued_at_unix_nanos: 0,
        ttl_seconds: 30,
        expires_at_unix_nanos,
    })
}

#[test]
fn agent_methods_round_trip_through_wire_names() -> Result<(), UnknownMethod> {
    let methods = [
        AgentMethod::Status,
        AgentMethod::Unlock,
        AgentMethod::Lock,
        AgentMethod::Shutdown,
        AgentMethod::RegisterClient,
        AgentMethod::RevokeClient,
        AgentMethod::RequestGrant,
        AgentMethod::RevokeGrant,
        AgentMethod::ExpireGrant,
        AgentMethod::ResolveReference,
        AgentMethod::PrepareExec,
        AgentMethod::ScanKnownValues,
        AgentMethod::ListRuntimeSessions,
        AgentMethod::ListPolicies,
        AgentMethod::ListDeviceMembers,
        AgentMethod::ListAudit,
        AgentMethod::Reveal,
        AgentMethod::Copy,
        AgentMethod::VerifyAudit,
        AgentMethod::ReadConfig,
        AgentMethod::WriteConfig,
        AgentMethod::SubscribeStatus,
        AgentMethod::CancelSubscription,
        AgentMethod::ClientHello,
        AgentMethod::ListSecrets,
        AgentMethod::ListVersions,
        AgentMethod::SetActiveProfile,
        AgentMethod::RegisterIdeEnvSession,
        AgentMethod::IdeEnvSession,
        AgentMethod::RegisterCommandPolicies,
        AgentMethod::PolicyDoctor,
        AgentMethod::ExportBundle,
        AgentMethod::ImportBundle,
        AgentMethod::VerifyBundle,
        AgentMethod::RecoveryRotate,
    ];

    for method in methods {
        assert_eq!(method.as_str().parse::<AgentMethod>()?, method);
    }

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn verify_audit_returns_hmac_status_when_unlocked() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::server::{AgentSocketState, dispatch};
    use locket_store::{AuditWrite, Store};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("lk_proj_agent_verify", "agent verify", 100)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "AUDIT_VERIFY",
        "status": "SUCCESS",
        "check_names": ["audit_hmac_chain"],
        "pass_count": 1,
        "warn_count": 0,
        "fail_count": 0,
        "skip_count": 0,
        "rows_verified": 0,
    });
    store.append_audit(
        &[42; 32],
        &AuditWrite {
            project_id: "lk_proj_agent_verify",
            profile_id: None,
            action: "AUDIT_VERIFY",
            status: "SUCCESS",
            secret_name: None,
            command: None,
            metadata_json: &metadata,
            timestamp: 100,
        },
    )?;

    let state = AgentSocketState::locked("test-version");
    state.seed_master_key("lk_proj_agent_verify", &[42; 32])?;
    let unlock = RequestEnvelope::new(
        "unlock",
        AgentMethod::Unlock,
        json!({
            "project_id": "lk_proj_agent_verify",
            "ttl_seconds": 30,
            "method": "OsKeychain"
        }),
    );
    assert!(matches!(dispatch(&unlock, &state).await, ResponseEnvelope::Success(_)));

    let verify = RequestEnvelope::new(
        "verify",
        AgentMethod::VerifyAudit,
        json!({
            "store_path": store_path,
            "project_id": "lk_proj_agent_verify"
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&verify, &state).await else {
        panic!("VerifyAudit should succeed");
    };
    let payload: VerifyAuditResponse = serde_json::from_value(success.payload)?;
    assert_eq!(payload.hmac_ok, Some(true));
    assert_eq!(payload.first_break_sequence, None);
    assert_eq!(payload.first_break_reason, None);
    assert_eq!(payload.rows_verified, 1);
    assert!(!payload.locked);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn verify_audit_is_locked_safe() -> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};

    let state = AgentSocketState::locked("test-version");
    let verify = RequestEnvelope::new(
        "verify",
        AgentMethod::VerifyAudit,
        json!({
            "store_path": "/tmp/locket-verify-audit-locked.db",
            "project_id": "lk_proj_locked"
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&verify, &state).await else {
        panic!("locked VerifyAudit should succeed with skipped status");
    };
    let payload: VerifyAuditResponse = serde_json::from_value(success.payload)?;
    assert_eq!(payload.hmac_ok, None);
    assert_eq!(payload.first_break_sequence, None);
    assert_eq!(payload.first_break_reason, None);
    assert_eq!(payload.rows_verified, 0);
    assert!(payload.locked);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn verify_audit_reports_first_hmac_break() -> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};
    use locket_store::{AuditWrite, Store};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("lk_proj_agent_verify", "agent verify", 100)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "AUDIT_VERIFY",
        "status": "SUCCESS",
        "check_names": ["audit_hmac_chain"],
        "pass_count": 1,
        "warn_count": 0,
        "fail_count": 0,
        "skip_count": 0,
        "rows_verified": 0,
    });
    store.append_audit(
        &[42; 32],
        &AuditWrite {
            project_id: "lk_proj_agent_verify",
            profile_id: None,
            action: "AUDIT_VERIFY",
            status: "SUCCESS",
            secret_name: None,
            command: None,
            metadata_json: &metadata,
            timestamp: 100,
        },
    )?;
    store.connection().execute(
        "UPDATE audit_log SET hmac = zeroblob(32) WHERE project_id = ?1",
        ["lk_proj_agent_verify"],
    )?;

    let state = AgentSocketState::locked("test-version");
    state.seed_master_key("lk_proj_agent_verify", &[42; 32])?;
    let unlock = RequestEnvelope::new(
        "unlock",
        AgentMethod::Unlock,
        json!({
            "project_id": "lk_proj_agent_verify",
            "ttl_seconds": 30,
            "method": "OsKeychain"
        }),
    );
    assert!(matches!(dispatch(&unlock, &state).await, ResponseEnvelope::Success(_)));

    let verify = RequestEnvelope::new(
        "verify",
        AgentMethod::VerifyAudit,
        json!({
            "store_path": store_path,
            "project_id": "lk_proj_agent_verify"
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&verify, &state).await else {
        panic!("VerifyAudit should return a structural failure payload");
    };
    let payload: VerifyAuditResponse = serde_json::from_value(success.payload)?;
    assert_eq!(payload.hmac_ok, Some(false));
    assert_eq!(payload.first_break_sequence, Some(1));
    assert_eq!(payload.first_break_reason.as_deref(), Some("row hmac mismatch"));
    assert_eq!(payload.rows_verified, 0);
    assert!(!payload.locked);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_verify_audit_payload_returns_protocol_error() {
    use crate::server::{AgentSocketState, dispatch};

    let state = AgentSocketState::locked("test-version");
    let request =
        RequestEnvelope::new("verify", AgentMethod::VerifyAudit, json!({"project_id": "p"}));
    let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
        panic!("malformed VerifyAudit payload must fail");
    };
    assert_eq!(error.error, "ProtocolError");
}

#[tokio::test(flavor = "current_thread")]
async fn list_audit_returns_filtered_metadata_and_chain_status()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};
    use locket_store::{AuditWrite, Store};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = Store::open(&store_path)?;
    store.initialize_schema()?;
    store.connection().execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_test', 'lk_proj_test', 'default', 0, 1)",
        [],
    )?;
    for (timestamp, action, secret_name) in
        [(100, "SET", "DATABASE_URL"), (200, "COPY", "DATABASE_URL"), (300, "ROTATE", "API_TOKEN")]
    {
        let mut metadata = json!({
            "schema_version": 1,
            "action": action,
            "status": "SUCCESS",
            "profile_id": "lk_prof_test",
            "secret_name": secret_name,
            "source": "user-local",
            "command": "dev",
        });
        if action == "COPY" {
            metadata["access_mode"] = json!("clipboard");
        }
        store.append_audit(
            &[7; 32],
            &AuditWrite {
                project_id: "lk_proj_test",
                profile_id: Some("lk_prof_test"),
                action,
                status: "SUCCESS",
                secret_name: Some(secret_name),
                command: Some("dev"),
                metadata_json: &metadata,
                timestamp,
            },
        )?;
    }

    let state = AgentSocketState::locked("test-version");
    state.seed_master_key("lk_proj_test", &[7; 32])?;
    let unlock = RequestEnvelope::new(
        "unlock",
        AgentMethod::Unlock,
        json!({
            "project_id": "lk_proj_test",
            "ttl_seconds": 30,
            "method": "OsKeychain"
        }),
    );
    assert!(matches!(dispatch(&unlock, &state).await, ResponseEnvelope::Success(_)));

    let request = RequestEnvelope::new(
        "audit",
        AgentMethod::ListAudit,
        json!({
            "store_path": store_path,
            "project_id": "lk_proj_test",
            "profile_id": "lk_prof_test",
            "action": "COPY",
            "status": "SUCCESS",
            "since_unix_nanos": 150,
            "limit": 10,
            "redact_names": true
        }),
    );
    let response = dispatch(&request, &state).await;
    let ResponseEnvelope::Success(success) = response else {
        panic!("ListAudit should succeed");
    };
    let payload: ListAuditResponse = serde_json::from_value(success.payload)?;

    assert_eq!(payload.rows.len(), 1);
    assert_eq!(payload.rows[0].sequence, 2);
    assert_eq!(payload.rows[0].action, "COPY");
    assert_ne!(payload.rows[0].profile_id.as_deref(), Some("lk_prof_test"));
    assert_ne!(payload.rows[0].secret_name.as_deref(), Some("DATABASE_URL"));
    assert_ne!(payload.rows[0].command.as_deref(), Some("dev"));
    assert_eq!(payload.chain_status.hmac_ok, Some(true));
    assert_eq!(payload.chain_status.first_break_sequence, None);
    assert_eq!(payload.chain_status.rows_verified, 3);
    assert!(!payload.chain_status.locked);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn list_audit_is_locked_safe_but_skips_hmac_status() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::server::{AgentSocketState, dispatch};
    use locket_store::{AuditWrite, Store};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = Store::open(&store_path)?;
    store.initialize_schema()?;
    store.connection().execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_test', 'lk_proj_test', 'default', 0, 1)",
        [],
    )?;
    let metadata = json!({
        "schema_version": 1,
        "action": "SET",
        "status": "SUCCESS",
        "profile_id": "lk_prof_test",
        "secret_name": "DATABASE_URL",
        "source": "user-local",
    });
    store.append_audit(
        &[7; 32],
        &AuditWrite {
            project_id: "lk_proj_test",
            profile_id: Some("lk_prof_test"),
            action: "SET",
            status: "SUCCESS",
            secret_name: Some("DATABASE_URL"),
            command: None,
            metadata_json: &metadata,
            timestamp: 100,
        },
    )?;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "audit",
        AgentMethod::ListAudit,
        json!({
            "store_path": store_path,
            "project_id": "lk_proj_test",
            "limit": 10,
            "redact_names": false
        }),
    );
    let response = dispatch(&request, &state).await;
    let ResponseEnvelope::Success(success) = response else {
        panic!("ListAudit should succeed while locked");
    };
    let payload: ListAuditResponse = serde_json::from_value(success.payload)?;

    assert_eq!(payload.rows.len(), 1);
    assert_eq!(payload.rows[0].secret_name.as_deref(), Some("DATABASE_URL"));
    assert_eq!(payload.chain_status.hmac_ok, None);
    assert_eq!(payload.chain_status.first_break_sequence, None);
    assert_eq!(payload.chain_status.rows_verified, 0);
    assert!(payload.chain_status.locked);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn list_secrets_returns_metadata_ordered_by_source_precedence()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use locket_store::Store;
    use serde_json::json;

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = Store::open(&store_path)?;
    store.initialize_schema()?;
    store.connection().execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_test', 'lk_proj_test', 'default', 0, 1)",
        [],
    )?;
    for (id, name, source, required, version) in [
        ("lk_sec_team", "DATABASE_URL", "team-managed", true, 1),
        ("lk_sec_machine", "DATABASE_URL", "machine-local", false, 3),
        ("lk_sec_user", "DATABASE_URL", "user-local", false, 2),
        ("lk_sec_api", "API_TOKEN", "user-local", true, 1),
    ] {
        store.connection().execute(
            "INSERT INTO secrets(
               id, project_id, profile_id, name, source, origin, required,
               current_version, state, created_at, updated_at, last_rotated_at, deleted_at
             )
             VALUES (?1, 'lk_proj_test', 'lk_prof_test', ?2, ?3, 'manual', ?4, ?5, 'active', 100, 200, NULL, NULL)",
            (id, name, source, required, version),
        )?;
    }

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "secrets",
        AgentMethod::ListSecrets,
        json!({
            "store_path": store_path,
            "project_id": "lk_proj_test",
            "profile_id": "lk_prof_test",
            "redact_names": false
        }),
    );
    let response = dispatch(&request, &state).await;
    let ResponseEnvelope::Success(success) = response else {
        panic!("ListSecrets should succeed");
    };
    let payload: ListSecretsResponse = serde_json::from_value(success.payload)?;

    let ordered = payload
        .rows
        .iter()
        .map(|row| (row.name.as_str(), row.source.as_str(), row.source_precedence))
        .collect::<Vec<_>>();
    assert_eq!(
        ordered,
        vec![
            ("API_TOKEN", "user-local", 2),
            ("DATABASE_URL", "machine-local", 3),
            ("DATABASE_URL", "user-local", 2),
            ("DATABASE_URL", "team-managed", 1),
        ]
    );
    assert!(payload.rows[0].required);
    assert_eq!(payload.rows[1].current_version, 3);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn list_secrets_applies_privacy_aliases_and_remains_locked_safe()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use locket_store::Store;
    use serde_json::json;

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = Store::open(&store_path)?;
    store.initialize_schema()?;
    store.connection().execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_test', 'lk_proj_test', 'default', 0, 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO secrets(
           id, project_id, profile_id, name, source, origin, required,
           current_version, state, created_at, updated_at, last_rotated_at, deleted_at
         )
         VALUES ('lk_sec_test', 'lk_proj_test', 'lk_prof_test', 'DATABASE_URL', 'user-local',
                 'manual', 1, 1, 'active', 100, 200, NULL, NULL)",
        [],
    )?;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "secrets",
        AgentMethod::ListSecrets,
        json!({
            "store_path": store_path,
            "project_id": "lk_proj_test",
            "profile_id": "lk_prof_test",
            "redact_names": true
        }),
    );
    let response = dispatch(&request, &state).await;
    let ResponseEnvelope::Success(success) = response else {
        panic!("ListSecrets should succeed while locked");
    };
    let payload: ListSecretsResponse = serde_json::from_value(success.payload)?;

    assert_eq!(payload.rows.len(), 1);
    assert_ne!(payload.rows[0].name, "DATABASE_URL");
    assert_ne!(payload.rows[0].profile_id, "lk_prof_test");
    assert!(payload.rows[0].name.starts_with("secret-"));
    assert!(payload.rows[0].profile_id.starts_with("profile-"));
    Ok(())
}

#[test]
fn encodes_and_decodes_length_prefixed_request() -> Result<(), ProtocolError> {
    let request = RequestEnvelope::new("req-1", AgentMethod::Status, json!({"client_kind": "cli"}));

    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
    assert_eq!(
        u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize,
        frame.len() - 4
    );

    let (decoded, consumed) = decode_request_frame(&frame, DEFAULT_MAX_MESSAGE_SIZE)?;

    assert_eq!(decoded, request);
    assert_eq!(consumed, frame.len());
    Ok(())
}

#[test]
fn decodes_first_frame_and_reports_consumed_bytes() -> Result<(), ProtocolError> {
    let request = RequestEnvelope::new("req-1", AgentMethod::Status, json!({}));
    let mut bytes = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
    bytes.extend_from_slice(b"trailing bytes");

    let (decoded, consumed) = decode_request_frame(&bytes, DEFAULT_MAX_MESSAGE_SIZE)?;

    assert_eq!(decoded, request);
    assert!(consumed < bytes.len());
    Ok(())
}

#[test]
fn rejects_incomplete_prefix_and_payload() -> Result<(), ProtocolError> {
    assert!(matches!(
        decode_request_frame(&[1, 2], DEFAULT_MAX_MESSAGE_SIZE),
        Err(ProtocolError::IncompleteFrame)
    ));

    let request = RequestEnvelope::new("req-1", AgentMethod::Status, json!({}));
    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
    let partial = &frame[..frame.len() - 1];

    assert!(matches!(
        decode_request_frame(partial, DEFAULT_MAX_MESSAGE_SIZE),
        Err(ProtocolError::IncompleteFrame)
    ));
    Ok(())
}

#[test]
fn rejects_oversized_frames_before_json_decode() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&10_u32.to_le_bytes());
    frame.extend_from_slice(b"0123456789");

    assert!(matches!(
        decode_request_frame(&frame, 9),
        Err(ProtocolError::MessageTooLarge { length: 10, maximum: 9 })
    ));
}

#[test]
fn encode_rejects_payloads_over_configured_maximum() {
    let request = RequestEnvelope::new("req-1", AgentMethod::Status, json!({"data": "x"}));

    assert!(matches!(
        encode_frame(&request, 1),
        Err(ProtocolError::MessageTooLarge { maximum: 1, .. })
    ));
}

#[test]
fn rejects_unknown_protocol_version() -> Result<(), ProtocolError> {
    let request = RequestEnvelope {
        v: 99,
        id: "req-1".to_owned(),
        kind: AgentMethod::Status.as_str().to_owned(),
        payload: json!({}),
    };
    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;

    assert!(matches!(
        decode_request_frame(&frame, DEFAULT_MAX_MESSAGE_SIZE),
        Err(ProtocolError::UnsupportedVersion { version: 99 })
    ));
    Ok(())
}

#[test]
fn unknown_request_methods_decode_then_fail_method_lookup() -> Result<(), ProtocolError> {
    let request = RequestEnvelope {
        v: PROTOCOL_VERSION,
        id: "req-1".to_owned(),
        kind: "Nope".to_owned(),
        payload: json!({}),
    };
    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;

    let (decoded, consumed) = decode_request_frame(&frame, DEFAULT_MAX_MESSAGE_SIZE)?;
    assert_eq!(consumed, frame.len());
    assert_eq!(decoded.kind, "Nope");
    assert!(matches!(
        decoded.method(),
        Err(ProtocolError::UnknownMethod(error)) if error.method == "Nope"
    ));
    Ok(())
}

#[test]
fn constructors_emit_spec_envelope_shapes() {
    let success = SuccessEnvelope::new("req-1", json!({"ok": "payload"}));
    assert_eq!(success.v, PROTOCOL_VERSION);
    assert!(success.ok);
    assert_eq!(success.id, "req-1");

    let error = ErrorEnvelope::new("req-2", "AccessDenied", "access denied", false);
    assert_eq!(error.v, PROTOCOL_VERSION);
    assert!(!error.ok);
    assert!(!error.retryable);
    assert_eq!(error.error, "AccessDenied");
}

#[test]
fn response_envelope_deserializes_by_success_marker_shape() -> Result<(), serde_json::Error> {
    let success_value = json!({
        "v": PROTOCOL_VERSION,
        "id": "req-1",
        "ok": true,
        "payload": {"ready": true}
    });
    let error_value = json!({
        "v": PROTOCOL_VERSION,
        "id": "req-2",
        "ok": false,
        "error": "AccessDenied",
        "message": "access denied",
        "retryable": false
    });

    let success: ResponseEnvelope = serde_json::from_value(success_value)?;
    let error: ResponseEnvelope = serde_json::from_value(error_value)?;

    assert!(matches!(success, ResponseEnvelope::Success(envelope) if envelope.ok));
    assert!(matches!(error, ResponseEnvelope::Error(envelope) if !envelope.ok));
    Ok(())
}

#[test]
fn status_payload_is_metadata_only() {
    let payload = StatusPayload::locked("0.1.0");

    assert_eq!(payload.lock_state, LockState::Locked);
    assert_eq!(payload.live_grant_count, 0);
    assert!(payload.project_id.is_none());
    assert!(payload.profile_name.is_none());
}

#[test]
fn heartbeat_status_event_uses_spec_wire_shape() -> Result<(), serde_json::Error> {
    let payload = StatusPayload::locked("0.1.0");
    let event = StatusEvent::heartbeat(7, payload);
    let value = serde_json::to_value(&event)?;

    assert_eq!(STATUS_HEARTBEAT_INTERVAL_SECS, 30);
    assert_eq!(event.kind, StatusEventKind::Heartbeat);
    assert!(event.is_heartbeat());
    assert!(!event.is_state_change());
    assert_eq!(
        value,
        json!({
            "kind": "heartbeat",
            "sequence": 7,
            "lock_state": "locked",
            "project_id": null,
            "profile_name": null,
            "live_grant_count": 0,
            "agent_version": "0.1.0",
            "unlock_ttl_seconds": null,
            "running_session_count": 0,
            "scan_warning_count": 0,
            "recent_audit_status": "unknown",
            "pinned_reference_warning_count": 0
        })
    );
    Ok(())
}

#[test]
fn status_event_sequence_is_monotonic_and_marks_heartbeat_as_keepalive() {
    let mut sequence = StatusEventSequence::new();
    let first = sequence.status(StatusPayload::locked("0.1.0"));
    let heartbeat = sequence.heartbeat(StatusPayload::locked("0.1.0"));
    let third = sequence.status(StatusPayload::locked("0.1.0"));

    assert_eq!(first.sequence, 1);
    assert_eq!(heartbeat.sequence, 2);
    assert_eq!(third.sequence, 3);
    assert!(first.is_state_change());
    assert!(!heartbeat.is_state_change());
}

#[test]
fn status_event_success_envelope_decodes_for_stream_clients() -> Result<(), ProtocolError> {
    let event = StatusEvent::heartbeat(9, StatusPayload::locked("0.1.0"));
    let response = SuccessEnvelope::new("sub-1", serde_json::to_value(&event)?);
    let frame = encode_frame(&response, DEFAULT_MAX_MESSAGE_SIZE)?;

    let (decoded, consumed) = decode_response_frame(&frame, DEFAULT_MAX_MESSAGE_SIZE)?;
    assert_eq!(consumed, frame.len());
    assert!(matches!(decoded, ResponseEnvelope::Success(_)));
    let ResponseEnvelope::Success(success) = decoded else {
        return Ok(());
    };
    let decoded_event: StatusEvent = serde_json::from_value(success.payload)?;

    assert!(decoded_event.is_heartbeat());
    assert_eq!(decoded_event.sequence, 9);
    assert_eq!(decoded_event.status.lock_state, LockState::Locked);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unlock_then_lock_round_trip() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.seed_master_key("p-1", &[9; 32]).expect("seed master key");
    state.grants.lock().await.insert(test_grant_record("g-live", i128::MAX));

    let unlock = RequestEnvelope::new(
        "req-1",
        AgentMethod::Unlock,
        json!({
            "project_id": "p-1",
            "ttl_seconds": 30,
            "method": "OsKeychain"
        }),
    );
    let response = dispatch(&unlock, &state).await;
    assert!(matches!(response, ResponseEnvelope::Success(_)));
    let populated = !state.unlock_cache.lock().await.is_empty();
    assert!(populated, "Unlock should populate the cache");

    let lock = RequestEnvelope::new("req-2", AgentMethod::Lock, json!({}));
    let response = dispatch(&lock, &state).await;
    assert!(matches!(response, ResponseEnvelope::Success(_)));
    let cleared = state.unlock_cache.lock().await.is_empty();
    assert!(cleared, "Lock must clear every cache entry");
    assert!(state.grants.lock().await.is_empty(), "Lock must clear live grants");
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_locks_and_notifies_daemon_loop() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.seed_master_key("p-1", &[7; 32]).expect("seed master key");
    state.grants.lock().await.insert(test_grant_record("g-live", i128::MAX));

    let unlock = RequestEnvelope::new(
        "req-1",
        AgentMethod::Unlock,
        json!({
            "project_id": "p-1",
            "ttl_seconds": 30,
            "method": "OsKeychain"
        }),
    );
    assert!(matches!(dispatch(&unlock, &state).await, ResponseEnvelope::Success(_)));

    let shutdown_notified = state.shutdown.notified();
    let shutdown =
        RequestEnvelope::new("req-2", AgentMethod::Shutdown, json!({ "source": "process_exit" }));
    assert!(matches!(dispatch(&shutdown, &state).await, ResponseEnvelope::Success(_)));
    shutdown_notified.await;

    assert!(state.unlock_cache.lock().await.is_empty(), "Shutdown must clear cache entries");
    assert!(state.grants.lock().await.is_empty(), "Shutdown must clear live grants");
}

#[tokio::test(flavor = "current_thread")]
async fn unlock_and_lock_publish_status_changes() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.seed_master_key("p-1", &[1; 32]).expect("seed master key");
    let mut subscriber = state.status_hub.subscribe().await;
    let initial = subscriber.next_event().await.expect("initial status event");
    assert_eq!(initial.status.lock_state, LockState::Locked);

    let unlock = RequestEnvelope::new(
        "req-1",
        AgentMethod::Unlock,
        json!({
            "project_id": "p-1",
            "ttl_seconds": 30,
            "method": "OsKeychain"
        }),
    );
    assert!(matches!(dispatch(&unlock, &state).await, ResponseEnvelope::Success(_)));

    let unlocked = subscriber.next_event().await.expect("unlock status event");
    assert!(unlocked.is_state_change());
    assert_eq!(unlocked.status.lock_state, LockState::Unlocked);
    assert_eq!(unlocked.status.unlock_ttl_seconds, Some(30));

    let lock = RequestEnvelope::new("req-2", AgentMethod::Lock, json!({}));
    assert!(matches!(dispatch(&lock, &state).await, ResponseEnvelope::Success(_)));

    let locked = subscriber.next_event().await.expect("lock status event");
    assert!(locked.is_state_change());
    assert_eq!(locked.status.lock_state, LockState::Locked);
    assert_eq!(locked.status.unlock_ttl_seconds, None);
}

#[tokio::test(flavor = "current_thread")]
async fn session_lock_event_clears_cache_grants_and_publishes_status() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use crate::session_lock::SessionLockSource;
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.seed_master_key("p-1", &[1; 32]).expect("seed master key");
    state.grants.lock().await.insert(test_grant_record("g-live", i128::MAX));
    let mut subscriber = state.status_hub.subscribe().await;
    let initial = subscriber.next_event().await.expect("initial status event");
    assert_eq!(initial.status.lock_state, LockState::Locked);

    let unlock = RequestEnvelope::new(
        "req-1",
        AgentMethod::Unlock,
        json!({
            "project_id": "p-1",
            "ttl_seconds": 30,
            "method": "OsKeychain"
        }),
    );
    assert!(matches!(dispatch(&unlock, &state).await, ResponseEnvelope::Success(_)));
    let unlocked = subscriber.next_event().await.expect("unlock status event");
    assert_eq!(unlocked.status.lock_state, LockState::Unlocked);

    let outcome = state
        .lock_for_session_event(SessionLockSource::ScreenLock, crate::server::current_unix_nanos())
        .await
        .expect("session lock succeeds");

    assert_eq!(outcome.cached_keys_cleared, 1);
    assert_eq!(outcome.live_grants_revoked, 1);
    assert!(state.unlock_cache.lock().await.is_empty());
    assert!(state.grants.lock().await.is_empty());
    let locked = subscriber.next_event().await.expect("session-lock status event");
    assert!(locked.is_state_change());
    assert_eq!(locked.status.lock_state, LockState::Locked);
    assert_eq!(locked.status.unlock_ttl_seconds, None);
}

#[tokio::test(flavor = "current_thread")]
async fn lock_with_audit_context_appends_metadata_only_lock_row()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::{Value, json};

    let tempdir = tempfile::tempdir()?;
    let store_path = tempdir.path().join("locket.sqlite3");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.connection().execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_test', 'lk_proj_test', 'default', 0, 1)",
        [],
    )?;
    insert_snapshot_fixture_audit_key(&store, "lk_proj_test")?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    state.seed_master_key("lk_proj_test", &[42; 32])?;
    let unlock = RequestEnvelope::new(
        "req-1",
        AgentMethod::Unlock,
        json!({
            "project_id": "lk_proj_test",
            "ttl_seconds": 30,
            "method": "OsKeychain",
            "audit": {
                "store_path": store_path,
                "profile_id": "lk_prof_test"
            }
        }),
    );
    assert!(matches!(dispatch(&unlock, &state).await, ResponseEnvelope::Success(_)));
    state.grants.lock().await.insert(test_grant_record("g-live", i128::MAX));

    let lock = RequestEnvelope::new(
        "req-2",
        AgentMethod::Lock,
        json!({
            "source": "screen_lock"
        }),
    );
    assert!(matches!(dispatch(&lock, &state).await, ResponseEnvelope::Success(_)));

    let store = locket_store::Store::open(&store_path)?;
    let (action, profile_id, metadata): (String, String, String) = store.connection().query_row(
        "SELECT action, profile_id, metadata_json
         FROM audit_log
         WHERE project_id = 'lk_proj_test' AND action = 'LOCK'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let metadata: Value = serde_json::from_str(&metadata)?;
    assert_eq!(action, "LOCK");
    assert_eq!(profile_id, "lk_prof_test");
    assert_eq!(metadata["source"], "screen_lock");
    assert_eq!(metadata["cached_keys_cleared"], 1);
    assert_eq!(metadata["live_grants_revoked"], 1);
    assert_eq!(metadata["metadata_only"], true);
    assert!(metadata.get("secret_name").is_none());
    assert!(store.verify_audit_chain_read_only("lk_proj_test", &[11; 32])?.hmac_ok);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn lock_audit_failure_returns_corrupt_db_after_clearing_state() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let tempdir = tempfile::tempdir().expect("tempdir");
    let missing_store = tempdir.path().join("missing").join("locket.sqlite3");
    let state = AgentSocketState::locked("test-version");
    state.seed_master_key("lk_proj_test", &[7; 32]).expect("seed master key");
    let unlock = RequestEnvelope::new(
        "req-1",
        AgentMethod::Unlock,
        json!({
            "project_id": "lk_proj_test",
            "ttl_seconds": 30,
            "method": "OsKeychain",
            "audit": {
                "store_path": missing_store,
                "profile_id": "lk_prof_test"
            }
        }),
    );
    assert!(matches!(dispatch(&unlock, &state).await, ResponseEnvelope::Success(_)));
    state.grants.lock().await.insert(test_grant_record("g-live", i128::MAX));

    let lock = RequestEnvelope::new("req-2", AgentMethod::Lock, json!({}));
    let ResponseEnvelope::Error(error) = dispatch(&lock, &state).await else {
        unreachable!("missing audit store should fail lock response");
    };
    assert_eq!(error.error, "CorruptDb");
    assert!(state.unlock_cache.lock().await.is_empty());
    assert!(state.grants.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn session_lock_event_without_audit_context_is_locked_safe() {
    use crate::server::AgentSocketState;
    use crate::session_lock::SessionLockSource;
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};
    use std::time::Duration;

    let state = AgentSocketState::locked("test-version");
    state.unlock_cache.lock().await.insert(
        "p-1".to_owned(),
        UnlockEntry::new(b"k".to_vec(), 0, Duration::from_secs(30), UnlockMethod::Passphrase),
    );
    let outcome = state.lock_for_session_event(SessionLockSource::UserSessionSwitch, 1).await;

    let outcome = outcome.expect("session lock without audit context succeeds");
    assert_eq!(outcome.cached_keys_cleared, 1);
    assert_eq!(outcome.live_grants_revoked, 0);
    assert!(state.unlock_cache.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_unlock_payload_returns_protocol_error() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    let unlock = RequestEnvelope::new(
        "req-1",
        AgentMethod::Unlock,
        // Missing required `ttl_seconds` field.
        json!({
            "project_id": "p-1"
        }),
    );

    let ResponseEnvelope::Error(error) = dispatch(&unlock, &state).await else {
        unreachable!("malformed Unlock payload must fail");
    };
    assert_eq!(error.error, "ProtocolError");
    assert!(state.unlock_cache.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_lock_payload_returns_protocol_error() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    let lock = RequestEnvelope::new(
        "req-1",
        AgentMethod::Lock,
        json!({
            "source": "not-a-source"
        }),
    );

    let ResponseEnvelope::Error(error) = dispatch(&lock, &state).await else {
        unreachable!("malformed Lock payload must fail");
    };
    assert_eq!(error.error, "ProtocolError");
    assert!(state.unlock_cache.lock().await.is_empty());
    assert!(state.grants.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn unlock_pulls_master_key_from_keychain_and_caches_it_for_status()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use crate::status::LockState;
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.seed_master_key("p-keychain", &[11; 32])?;

    let unlock = RequestEnvelope::new(
        "req-keychain",
        AgentMethod::Unlock,
        json!({
            "project_id": "p-keychain",
            "ttl_seconds": 30,
            "method": "OsKeychain"
        }),
    );
    assert!(matches!(dispatch(&unlock, &state).await, ResponseEnvelope::Success(_)));

    // The cache holds the unwrapped master key; the cached method is
    // `OsKeychain` regardless of what the client hinted.
    let method = state
        .unlock_cache
        .lock()
        .await
        .lookup("p-keychain", crate::server::current_unix_nanos())
        .map(crate::unlock_cache::UnlockEntry::method);
    assert_eq!(method, Some(crate::unlock_cache::UnlockMethod::OsKeychain));

    let snapshot = state.status_snapshot(crate::server::current_unix_nanos()).await;
    assert_eq!(snapshot.lock_state, LockState::Unlocked);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unlock_writes_unlock_audit_row_with_agent_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use locket_crypto::{
        HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, derive_wrapping_key_v1, generate_key,
        key_wrap_aad_v1, wrap_key_material_v1,
    };
    use locket_store::KeyRecord;
    use serde_json::{Value, json};

    let tempdir = tempfile::tempdir()?;
    let store_path = tempdir.path().join("store.sqlite3");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.connection().execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_unlock_audit', 'test', 100)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_unlock', 'lk_proj_unlock_audit', 'default', 0, 100)",
        [],
    )?;

    // Generate a real master key and wrap a real audit key under it so
    // the agent's UNLOCK row can derive a chained HMAC key.
    let master_key = *generate_key()?;
    let purpose = KeyPurpose::Audit;
    let audit_key = *generate_key()?;
    let key_record_id = "lk_key_audit_unlock_audit";
    let wrapping_key = derive_wrapping_key_v1(
        &master_key,
        &HkdfWrapInfo::new("lk_proj_unlock_audit", None, purpose),
    )?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_unlock_audit",
        key_record_id,
        None,
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = wrap_key_material_v1(&wrapping_key, &audit_key, &aad)?;
    store.insert_key(&KeyRecord {
        id: key_record_id.to_owned(),
        project_id: "lk_proj_unlock_audit".to_owned(),
        profile_id: None,
        purpose: purpose.as_str().to_owned(),
        wrapped_material: wrapped.ciphertext.clone(),
        nonce: wrapped.nonce,
        created_at: 100,
    })?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    state.seed_master_key("lk_proj_unlock_audit", &master_key)?;

    let unlock = RequestEnvelope::new(
        "req-audit",
        AgentMethod::Unlock,
        json!({
            "project_id": "lk_proj_unlock_audit",
            "ttl_seconds": 45,
            "method": "OsKeychain",
            "audit": {
                "store_path": store_path,
                "profile_id": "lk_prof_unlock"
            }
        }),
    );
    let response = dispatch(&unlock, &state).await;
    assert!(
        matches!(response, ResponseEnvelope::Success(_)),
        "unlock should succeed: {response:?}"
    );

    let store = locket_store::Store::open(&store_path)?;
    let (action, profile_id, command, metadata): (String, String, Option<String>, String) =
        store.connection().query_row(
            "SELECT action, profile_id, command, metadata_json
             FROM audit_log
             WHERE project_id = 'lk_proj_unlock_audit'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    let metadata: Value = serde_json::from_str(&metadata)?;
    assert_eq!(action, "UNLOCK");
    assert_eq!(profile_id, "lk_prof_unlock");
    assert_eq!(command.as_deref(), Some("unlock"));
    assert_eq!(metadata["client_kind"], "agent");
    assert_eq!(metadata["method"], "OsKeychain");
    assert_eq!(metadata["ttl_seconds"], 45);
    assert_eq!(metadata["agent_available"], true);
    assert!(metadata.get("secret_name").is_none());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unlock_falls_back_to_passphrase_when_keychain_is_empty()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::AgentSocketState;
    use locket_crypto::generate_key;
    use locket_platform::{MemoryMasterKeyStore, PassphraseFallbackMasterKeyStore};
    use serde_json::json;
    use std::sync::Arc;

    let tempdir = tempfile::tempdir()?;
    let passphrase_dir = tempdir.path().join("passphrase-fallback");
    let passphrase_store = Arc::new(PassphraseFallbackMasterKeyStore::new(&passphrase_dir));
    let master_key = *generate_key()?;
    passphrase_store.store_master_key(
        "p-passphrase",
        &master_key,
        b"correct horse battery staple",
        100,
    )?;

    // Memory keychain is empty; passphrase store has the entry.
    let key_store: Arc<dyn locket_platform::MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let state = AgentSocketState::with_stores(
        "test-version",
        crate::peer_cred::current_process_uid(),
        key_store,
        passphrase_store,
    );

    let unlock = RequestEnvelope::new(
        "req-passphrase",
        AgentMethod::Unlock,
        json!({
            "project_id": "p-passphrase",
            "passphrase": "correct horse battery staple",
            "ttl_seconds": 30,
            "method": "Passphrase"
        }),
    );
    let response = crate::server::dispatch(&unlock, &state).await;
    assert!(
        matches!(response, ResponseEnvelope::Success(_)),
        "passphrase unlock should succeed: {response:?}"
    );
    let method = state
        .unlock_cache
        .lock()
        .await
        .lookup("p-passphrase", crate::server::current_unix_nanos())
        .map(crate::unlock_cache::UnlockEntry::method);
    assert_eq!(method, Some(crate::unlock_cache::UnlockMethod::Passphrase));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unlock_returns_unlock_required_when_passphrase_is_wrong()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::AgentSocketState;
    use locket_crypto::generate_key;
    use locket_platform::{MemoryMasterKeyStore, PassphraseFallbackMasterKeyStore};
    use serde_json::json;
    use std::sync::Arc;

    let tempdir = tempfile::tempdir()?;
    let passphrase_store =
        Arc::new(PassphraseFallbackMasterKeyStore::new(tempdir.path().join("passphrase-fallback")));
    let master_key = *generate_key()?;
    passphrase_store.store_master_key("p-bad-pass", &master_key, b"the right one", 100)?;

    let state = AgentSocketState::with_stores(
        "test-version",
        crate::peer_cred::current_process_uid(),
        Arc::new(MemoryMasterKeyStore::default()),
        passphrase_store,
    );

    let unlock = RequestEnvelope::new(
        "req-bad-pass",
        AgentMethod::Unlock,
        json!({
            "project_id": "p-bad-pass",
            "passphrase": "the wrong one",
            "ttl_seconds": 30,
            "method": "Passphrase"
        }),
    );
    let response = crate::server::dispatch(&unlock, &state).await;
    let ResponseEnvelope::Error(error) = response else {
        panic!("wrong passphrase must return UnlockRequired, got success");
    };
    assert_eq!(error.error, "UnlockRequired");
    assert!(state.unlock_cache.lock().await.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unlock_with_no_passphrase_and_empty_keychain_returns_unlock_required() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    let unlock = RequestEnvelope::new(
        "req-empty",
        AgentMethod::Unlock,
        json!({
            "project_id": "p-empty",
            "ttl_seconds": 30,
            "method": "OsKeychain"
        }),
    );
    let response = dispatch(&unlock, &state).await;
    let ResponseEnvelope::Error(error) = response else {
        panic!("empty keychain + no passphrase must return UnlockRequired");
    };
    assert_eq!(error.error, "UnlockRequired");
    assert!(state.unlock_cache.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn policy_unlock_reuses_live_passphrase_cache_without_extending_ttl() {
    let state = crate::server::AgentSocketState::locked("test");
    let now = crate::server::current_unix_nanos();
    let entry = crate::UnlockEntry::new(
        vec![7; 32],
        now,
        std::time::Duration::from_secs(30),
        crate::UnlockMethod::Passphrase,
    );
    let expiry = entry.expires_at_unix_nanos();
    state.unlock_cache.lock().await.insert("project".into(), entry);
    let request = crate::RequestEnvelope::new(
        "cached",
        crate::AgentMethod::Unlock,
        serde_json::json!({"project_id":"project","ttl_seconds":900,"method":"OsKeychain","passphrase":null,"reuse_cached":true}),
    );
    let response = crate::server::dispatch(&request, &state).await;
    assert!(
        matches!(response, crate::ResponseEnvelope::Success(_)),
        "cached unlock failed: {response:?}"
    );
    let cache = state.unlock_cache.lock().await;
    assert_eq!(
        cache.lookup("project", now).map(crate::UnlockEntry::expires_at_unix_nanos),
        Some(expiry)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn expired_unlock_revokes_its_grants() {
    let state = crate::server::AgentSocketState::locked("test");
    state.unlock_cache.lock().await.insert(
        "project".into(),
        crate::UnlockEntry::new(
            vec![7; 32],
            0,
            std::time::Duration::from_secs(1),
            crate::UnlockMethod::Passphrase,
        ),
    );
    state
        .grants
        .lock()
        .await
        .issue(
            crate::RequestGrantPayload {
                project_id: "project".into(),
                profile_id: "profile".into(),
                policy_name: None,
                action: crate::GrantAction::ResolveReference,
                ttl_seconds: 900,
                binding: crate::GrantBinding::new(123, "start"),
            },
            0,
            900_000_000_000,
        )
        .unwrap();
    let status = state.status_snapshot(2_000_000_000).await;
    assert_eq!(status.live_grant_count, 0);
    assert!(state.unlock_cache.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn daemon_expiry_removes_keys_without_status_requests() {
    let state = crate::server::AgentSocketState::locked("test");
    state.unlock_cache.lock().await.insert(
        "project".into(),
        crate::UnlockEntry::new(
            vec![7; 32],
            crate::server::current_unix_nanos(),
            std::time::Duration::from_millis(20),
            crate::UnlockMethod::Passphrase,
        ),
    );
    let worker = state.spawn_unlock_expiry();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    worker.abort();
    assert!(state.unlock_cache.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn status_snapshot_includes_tray_safe_counts() {
    use crate::RuntimeSessionSnapshot;
    use crate::server::AgentSocketState;

    let state = AgentSocketState::locked("test-version");
    state
        .set_runtime_sessions_for_tests(vec![
            RuntimeSessionSnapshot {
                session_id: "sess-running".to_owned(),
                project_id: "project-main".to_owned(),
                profile_id: "profile-dev".to_owned(),
                policy_name: Some("test".to_owned()),
                process_id: 101,
                process_start_time: 1,
                started_at: 2,
                ended_at: None,
                exit_status: None,
                secret_name_count: 0,
                spawn_audit_sequence: None,
                completion_audit_sequence: None,
            },
            RuntimeSessionSnapshot {
                session_id: "sess-done".to_owned(),
                project_id: "project-main".to_owned(),
                profile_id: "profile-dev".to_owned(),
                policy_name: Some("test".to_owned()),
                process_id: 102,
                process_start_time: 1,
                started_at: 2,
                ended_at: Some(3),
                exit_status: Some(0),
                secret_name_count: 0,
                spawn_audit_sequence: None,
                completion_audit_sequence: None,
            },
        ])
        .await;
    state.record_scan_warning_count(4).await;

    let status = state.status_snapshot(10).await;

    assert_eq!(status.running_session_count, 1);
    assert_eq!(status.scan_warning_count, 4);
    assert_eq!(status.recent_audit_status, crate::status::RecentAuditStatus::Ok);
    assert_eq!(status.pinned_reference_warning_count, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn list_runtime_sessions_filters_profile_and_applies_aliases() {
    use crate::RuntimeSessionSnapshot;
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state
        .set_runtime_sessions_for_tests(vec![
            RuntimeSessionSnapshot {
                session_id: "sess-old".to_owned(),
                project_id: "project-main".to_owned(),
                profile_id: "profile-prod".to_owned(),
                policy_name: Some("deploy-prod".to_owned()),
                process_id: 101,
                process_start_time: 1_700_000_000,
                started_at: 1_700_000_100,
                ended_at: Some(1_700_000_500),
                exit_status: Some(0),
                secret_name_count: 2,
                spawn_audit_sequence: Some(7),
                completion_audit_sequence: Some(8),
            },
            RuntimeSessionSnapshot {
                session_id: "sess-new".to_owned(),
                project_id: "project-main".to_owned(),
                profile_id: "profile-prod".to_owned(),
                policy_name: Some("deploy-prod".to_owned()),
                process_id: 202,
                process_start_time: 1_700_001_000,
                started_at: 1_700_001_100,
                ended_at: None,
                exit_status: None,
                secret_name_count: 1,
                spawn_audit_sequence: Some(9),
                completion_audit_sequence: None,
            },
            RuntimeSessionSnapshot {
                session_id: "sess-other-profile".to_owned(),
                project_id: "project-main".to_owned(),
                profile_id: "profile-dev".to_owned(),
                policy_name: Some("deploy-prod".to_owned()),
                process_id: 303,
                process_start_time: 1_700_002_000,
                started_at: 1_700_002_100,
                ended_at: None,
                exit_status: None,
                secret_name_count: 3,
                spawn_audit_sequence: Some(10),
                completion_audit_sequence: None,
            },
        ])
        .await;

    let request = RequestEnvelope::new(
        "req-runtime",
        AgentMethod::ListRuntimeSessions,
        json!({
            "project_id": "project-main",
            "profile_id": "profile-prod",
            "privacy_redact_names": true,
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&request, &state).await else {
        unreachable!("valid ListRuntimeSessions payload must succeed");
    };
    let rendered = success.payload().to_string();
    assert!(!rendered.contains("profile-prod"));
    assert!(!rendered.contains("deploy-prod"));
    assert!(!rendered.contains("sess-other-profile"));

    let rows = success.payload().get("rows").and_then(serde_json::Value::as_array).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["session_id"], "sess-new");
    assert_eq!(rows[0]["state"], "running");
    assert_eq!(rows[0]["secret_name_count"], 1);
    assert!(rows[0]["profile"].as_str().unwrap().starts_with("profile-"));
    assert!(rows[0]["policy"].as_str().unwrap().starts_with("policy-"));
    assert_eq!(rows[1]["session_id"], "sess-old");
    assert_eq!(rows[1]["state"], "completed");
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_list_runtime_sessions_payload_returns_protocol_error() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "req-runtime",
        AgentMethod::ListRuntimeSessions,
        json!({
            "project_id": "project-main",
        }),
    );

    let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
        unreachable!("malformed ListRuntimeSessions payload must fail");
    };
    assert_eq!(error.error, "ProtocolError");
    assert!(state.runtime_sessions.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn list_policies_filters_project_and_applies_aliases() {
    use crate::CommandPolicySnapshot;
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state
        .set_command_policies_for_tests(vec![
            CommandPolicySnapshot {
                project_id: "project-main".to_owned(),
                name: "deploy-prod".to_owned(),
                command_kind: "argv".to_owned(),
                command_preview: "pnpm deploy".to_owned(),
                required_secrets: vec!["DATABASE_URL".to_owned()],
                optional_secrets: vec!["OPENAI_API_KEY".to_owned()],
                allowed_secrets: vec!["DATABASE_URL".to_owned(), "OPENAI_API_KEY".to_owned()],
                confirm: true,
                require_user_verification: true,
                require_agent: true,
                allow_remote_docker: false,
                ttl_seconds: 300,
                env_mode: "minimal".to_owned(),
                override_mode: "locket".to_owned(),
                updated_at_unix_nanos: 1_700_000_000,
            },
            CommandPolicySnapshot {
                project_id: "project-main".to_owned(),
                name: "build".to_owned(),
                command_kind: "shell".to_owned(),
                command_preview: "pnpm build".to_owned(),
                required_secrets: Vec::new(),
                optional_secrets: Vec::new(),
                allowed_secrets: Vec::new(),
                confirm: false,
                require_user_verification: false,
                require_agent: false,
                allow_remote_docker: false,
                ttl_seconds: 900,
                env_mode: "strict".to_owned(),
                override_mode: "preserve".to_owned(),
                updated_at_unix_nanos: 1_700_000_100,
            },
            CommandPolicySnapshot {
                project_id: "project-other".to_owned(),
                name: "other-project-policy".to_owned(),
                command_kind: "argv".to_owned(),
                command_preview: "ignored".to_owned(),
                required_secrets: vec!["OTHER_SECRET".to_owned()],
                optional_secrets: Vec::new(),
                allowed_secrets: vec!["OTHER_SECRET".to_owned()],
                confirm: false,
                require_user_verification: false,
                require_agent: false,
                allow_remote_docker: false,
                ttl_seconds: 900,
                env_mode: "minimal".to_owned(),
                override_mode: "locket".to_owned(),
                updated_at_unix_nanos: 1_700_000_200,
            },
        ])
        .await;

    let request = RequestEnvelope::new(
        "req-policies",
        AgentMethod::ListPolicies,
        json!({
            "project_id": "project-main",
            "privacy_redact_names": true,
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&request, &state).await else {
        unreachable!("valid ListPolicies payload must succeed");
    };
    let rendered = success.payload().to_string();
    assert!(!rendered.contains("deploy-prod"));
    assert!(!rendered.contains("DATABASE_URL"));
    assert!(!rendered.contains("OPENAI_API_KEY"));
    assert!(!rendered.contains("other-project-policy"));

    let rows = success.payload().get("rows").and_then(serde_json::Value::as_array).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["command_kind"], "shell");
    assert!(rows[0]["name"].as_str().unwrap().starts_with("policy-"));
    assert_eq!(rows[1]["command_kind"], "argv");
    assert_eq!(rows[1]["ttl_seconds"], 300);
    assert_eq!(rows[1]["confirm"], true);
    assert_eq!(rows[1]["require_agent"], true);
    assert!(rows[1]["required_secrets"][0].as_str().unwrap().starts_with("secret-"));
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_list_policies_payload_returns_protocol_error() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "req-policies",
        AgentMethod::ListPolicies,
        json!({
            "project_id": "project-main",
        }),
    );

    let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
        unreachable!("malformed ListPolicies payload must fail");
    };
    assert_eq!(error.error, "ProtocolError");
    assert!(state.command_policies.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn list_device_members_returns_metadata_only_directory_rows()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use locket_store::{DeviceRecord, Store, TeamRecord};
    use serde_json::json;

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("project-main", "main", 100)?;
    store.insert_device(&DeviceRecord {
        id: "device-local".to_owned(),
        project_id: "project-main".to_owned(),
        member_id: None,
        name: "Justin Laptop".to_owned(),
        label: "Justin Laptop".to_owned(),
        signing_public_key: vec![1; 32],
        sealing_public_key: vec![2; 32],
        fingerprint: "abcdef123456".to_owned(),
        safety_words: vec!["alpha".to_owned(), "bravo".to_owned()],
        local: true,
        created_at: 110,
        last_seen_at: Some(120),
        revoked_at: None,
    })?;
    store.insert_device(&DeviceRecord {
        id: "device-revoked".to_owned(),
        project_id: "project-main".to_owned(),
        member_id: None,
        name: "Old Laptop".to_owned(),
        label: "Old Laptop".to_owned(),
        signing_public_key: vec![3; 32],
        sealing_public_key: vec![4; 32],
        fingerprint: "deadbeef".to_owned(),
        safety_words: vec!["charlie".to_owned(), "delta".to_owned()],
        local: false,
        created_at: 130,
        last_seen_at: None,
        revoked_at: Some(140),
    })?;
    store.insert_team(&TeamRecord {
        id: "team-main".to_owned(),
        project_id: "project-main".to_owned(),
        name: "Main Team".to_owned(),
        created_at: 150,
        updated_at: 150,
    })?;
    store.insert_team_member(
        "member-owner",
        "team-main",
        Some("device-local"),
        "Justin",
        "owner",
        160,
    )?;
    store.remove_team_member("member-owner", 170)?;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "req-device-members",
        AgentMethod::ListDeviceMembers,
        json!({
            "store_path": store_path,
            "project_id": "project-main",
            "redact_names": true,
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&request, &state).await else {
        unreachable!("valid ListDeviceMembers payload must succeed");
    };

    let rendered = success.payload().to_string();
    assert!(!rendered.contains("Justin Laptop"));
    assert!(!rendered.contains("Old Laptop"));
    assert!(!rendered.contains("abcdef123456"));
    assert!(!rendered.contains("Justin"));

    let rows = success.payload().get("rows").and_then(serde_json::Value::as_array).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["kind"], "device");
    assert_eq!(rows[0]["status"], "active");
    assert_eq!(rows[0]["local_device"], true);
    assert!(rows[0]["name"].as_str().unwrap().starts_with("device-"));
    assert!(rows[0]["fingerprint"].as_str().unwrap().starts_with("fingerprint-"));
    assert_eq!(rows[1]["status"], "revoked");
    assert_eq!(rows[2]["kind"], "member");
    assert_eq!(rows[2]["role"], "owner");
    assert_eq!(rows[2]["status"], "removed");
    assert_eq!(rows[2]["trusted_device_count"], 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn status_lazily_evicts_expired_unlock_entries() {
    use crate::server::AgentSocketState;
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};
    use std::time::Duration;

    let state = AgentSocketState::locked("test-version");
    state.unlock_cache.lock().await.insert(
        "p-1".to_owned(),
        UnlockEntry::new(b"k".to_vec(), 0, Duration::from_secs(1), UnlockMethod::Passphrase),
    );

    let snapshot = state.status_snapshot(2_000_000_000).await;

    assert_eq!(snapshot.lock_state, LockState::Locked);
    assert_eq!(snapshot.unlock_ttl_seconds, None);
    assert!(state.unlock_cache.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn request_grant_returns_id_bound_to_caller_process() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "req-1",
        AgentMethod::RequestGrant,
        json!({
            "project_id": "p-1",
            "profile_id": "prof-1",
            "action": "RunPolicy",
            "ttl_seconds": 30,
            "binding": {
                "pid": std::process::id(),
                "process_start_time": "0"
            }
        }),
    );
    let response = dispatch(&request, &state).await;

    let ResponseEnvelope::Success(success) = response else {
        unreachable!("expected success envelope");
    };
    let grant_id = success.payload.get("grant_id").and_then(|v| v.as_str()).unwrap_or_default();
    assert!(!grant_id.is_empty(), "grant id must not be empty");
    let record = {
        let grants = state.grants.lock().await;
        assert_eq!(grants.len(), 1);
        grants.get(grant_id).cloned().unwrap_or_else(|| unreachable!("issued grant is stored"))
    };
    assert_eq!(record.project_id, "p-1");
    assert_eq!(record.profile_id, "prof-1");
    assert_eq!(record.action, crate::grant::GrantAction::RunPolicy);
    assert_eq!(record.ttl_seconds, 30);
    assert_eq!(record.binding.process_start_time, "0");
}

#[tokio::test(flavor = "current_thread")]
async fn request_grant_uses_saved_policy_ttl_when_policy_name_is_present() {
    use crate::CommandPolicySnapshot;
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state
        .set_command_policies_for_tests(vec![CommandPolicySnapshot {
            project_id: "p-1".to_owned(),
            name: "deploy".to_owned(),
            command_kind: "argv".to_owned(),
            command_preview: "pnpm deploy".to_owned(),
            required_secrets: vec!["DATABASE_URL".to_owned()],
            optional_secrets: Vec::new(),
            allowed_secrets: vec!["DATABASE_URL".to_owned()],
            confirm: false,
            require_user_verification: false,
            require_agent: false,
            allow_remote_docker: false,
            ttl_seconds: 300,
            env_mode: "minimal".to_owned(),
            override_mode: "locket".to_owned(),
            updated_at_unix_nanos: 1,
        }])
        .await;
    let request = RequestEnvelope::new(
        "req-policy-ttl",
        AgentMethod::RequestGrant,
        json!({
            "project_id": "p-1",
            "profile_id": "prof-1",
            "policy_name": "deploy",
            "action": "RunPolicy",
            "ttl_seconds": 1,
            "binding": {
                "pid": std::process::id(),
                "process_start_time": "0"
            }
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&request, &state).await else {
        unreachable!("policy-backed grant should succeed");
    };
    let grant_id = success.payload.get("grant_id").and_then(|v| v.as_str()).unwrap_or_default();
    let record = {
        let grants = state.grants.lock().await;
        grants.get(grant_id).cloned().unwrap_or_else(|| unreachable!("issued grant is stored"))
    };
    assert_eq!(record.ttl_seconds, 300);
    assert_eq!(
        record.expires_at_unix_nanos.saturating_sub(record.issued_at_unix_nanos),
        300_000_000_000
    );
}

#[tokio::test(flavor = "current_thread")]
async fn request_grant_fails_closed_when_policy_name_is_missing() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "req-policy-missing",
        AgentMethod::RequestGrant,
        json!({
            "project_id": "p-1",
            "profile_id": "prof-1",
            "policy_name": "deploy",
            "action": "RunPolicy",
            "ttl_seconds": 30,
            "binding": {
                "pid": std::process::id(),
                "process_start_time": "0"
            }
        }),
    );
    let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
        unreachable!("missing policy must fail");
    };
    assert_eq!(error.error, "PolicyNotFound");
    assert!(state.grants.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn revoke_grant_drops_record_and_unknown_returns_grant_required() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.grants.lock().await.insert(test_grant_record("g-1", i128::MAX));

    let revoke =
        RequestEnvelope::new("r-1", AgentMethod::RevokeGrant, json!({ "grant_id": "g-1" }));
    let response = dispatch(&revoke, &state).await;
    assert!(matches!(response, ResponseEnvelope::Success(_)));
    assert!(state.grants.lock().await.is_empty());

    let revoke_missing =
        RequestEnvelope::new("r-2", AgentMethod::RevokeGrant, json!({ "grant_id": "missing" }));
    let response = dispatch(&revoke_missing, &state).await;
    let ResponseEnvelope::Error(error) = response else {
        unreachable!("expected error envelope for unknown grant");
    };
    assert_eq!(error.error, "GrantRequired");
}

#[tokio::test(flavor = "current_thread")]
async fn expire_grant_drops_already_expired_record() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.grants.lock().await.insert(test_grant_record("g-2", 1));

    let request =
        RequestEnvelope::new("r-1", AgentMethod::ExpireGrant, json!({ "grant_id": "g-2" }));
    let response = dispatch(&request, &state).await;
    assert!(matches!(response, ResponseEnvelope::Success(_)));
    assert!(state.grants.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn expire_grant_leaves_live_grant_intact() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.grants.lock().await.insert(test_grant_record("g-live", i128::MAX));

    let request =
        RequestEnvelope::new("r-1", AgentMethod::ExpireGrant, json!({ "grant_id": "g-live" }));
    let response = dispatch(&request, &state).await;

    let ResponseEnvelope::Error(error) = response else {
        unreachable!("ExpireGrant on a live grant must return an error envelope");
    };
    assert_eq!(error.error, "ProtocolError");
    assert!(
        state.grants.lock().await.get("g-live").is_some(),
        "live grant must not be revoked by ExpireGrant"
    );
}

fn automation_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32])
}

fn seed_automation_client_store(
    store_path: &std::path::Path,
    public_key: &[u8; 32],
) -> Result<locket_store::Store, Box<dyn std::error::Error>> {
    let mut store = locket_store::Store::open(store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("lk_proj_auth", "auth", 1)?;
    store.insert_automation_client(&locket_store::AutomationClientRecord {
        id: "lk_client_auth".to_owned(),
        project_id: "lk_proj_auth".to_owned(),
        name: "ci".to_owned(),
        public_key: public_key.to_vec(),
        fingerprint: "auth-fingerprint".to_owned(),
        storage: "external".to_owned(),
        allowed_actions: vec!["run-policy".to_owned()],
        allowed_policies: vec!["deploy".to_owned()],
        created_at: 1,
        last_used_at: None,
        revoked_at: None,
    })?;
    Ok(store)
}

fn write_profile_test_config(
    path: &std::path::Path,
    project_id: &str,
    profile_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = locket_core::ProjectConfig::new(
        locket_core::ProjectId::new(project_id)?,
        "agent profile".to_owned(),
        locket_core::ProfileName::new(profile_name)?,
    );
    std::fs::write(path, toml::to_string_pretty(&config)?)?;
    Ok(())
}

fn read_profile_test_config(
    path: &std::path::Path,
) -> Result<locket_core::ProjectConfig, Box<dyn std::error::Error>> {
    Ok(toml::from_str(&std::fs::read_to_string(path)?)?)
}

fn seed_profile_test_store(
    store_path: &std::path::Path,
    project_id: &str,
) -> Result<locket_store::Store, Box<dyn std::error::Error>> {
    let mut store = locket_store::Store::open(store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent(project_id, "agent profile", 1)?;
    store.insert_profile_if_absent("lk_prof_dev", project_id, "dev", false, 1)?;
    store.insert_profile_if_absent("lk_prof_prod", project_id, "prod", true, 2)?;
    store.insert_profile_if_absent("lk_prof_staging", project_id, "staging", false, 3)?;
    Ok(store)
}

async fn unlock_auth_project(state: &crate::server::AgentSocketState) {
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};
    use std::time::Duration;

    state.unlock_cache.lock().await.insert(
        "lk_proj_auth".to_owned(),
        UnlockEntry::new(
            vec![42_u8; 32],
            crate::server::current_unix_nanos(),
            Duration::from_secs(60),
            UnlockMethod::Passphrase,
        ),
    );
    state
        .set_command_policies_for_tests(vec![crate::CommandPolicySnapshot {
            project_id: "lk_proj_auth".to_owned(),
            name: "deploy".to_owned(),
            command_kind: "argv".to_owned(),
            command_preview: "deploy".to_owned(),
            required_secrets: Vec::new(),
            optional_secrets: Vec::new(),
            allowed_secrets: Vec::new(),
            confirm: false,
            require_user_verification: false,
            require_agent: true,
            allow_remote_docker: false,
            ttl_seconds: 30,
            env_mode: "minimal".to_owned(),
            override_mode: "locket".to_owned(),
            updated_at_unix_nanos: 1,
        }])
        .await;
}

async fn unlock_profile_test_state(state: &crate::server::AgentSocketState, project_id: &str) {
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};
    use std::time::Duration;

    state.unlock_cache.lock().await.insert(
        project_id.to_owned(),
        UnlockEntry::new(
            vec![42_u8; 32],
            crate::server::current_unix_nanos(),
            Duration::from_secs(60),
            UnlockMethod::Passphrase,
        ),
    );
}

fn auth_now_i64() -> i64 {
    i64::try_from(crate::server::current_unix_nanos()).unwrap_or(i64::MAX)
}

fn canonical_test_hash(
    request: &crate::RequestEnvelope,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use sha2::Digest;

    let mut value = serde_json::to_value(request)?;
    if let Some(payload) = value.get_mut("payload").and_then(serde_json::Value::as_object_mut) {
        payload.remove("auth");
    }
    let mut bytes = Vec::new();
    write_test_canonical_json(&value, &mut bytes)?;
    Ok(sha2::Sha256::digest(&bytes).into())
}

fn write_test_canonical_json(
    value: &serde_json::Value,
    out: &mut Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => out.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => out.extend_from_slice(b"false"),
        serde_json::Value::Number(number) => out.extend_from_slice(number.to_string().as_bytes()),
        serde_json::Value::String(text) => {
            out.extend_from_slice(serde_json::to_string(text)?.as_bytes());
        }
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_test_canonical_json(item, out)?;
            }
            out.push(b']');
        }
        serde_json::Value::Object(map) => {
            out.push(b'{');
            let sorted: std::collections::BTreeMap<_, _> = map.iter().collect();
            for (index, (key, item)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_test_canonical_json(&serde_json::Value::String(key.clone()), out)?;
                out.push(b':');
                write_test_canonical_json(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn sign_auth_payload(
    signing_key: &ed25519_dalek::SigningKey,
    request: &crate::RequestEnvelope,
    client_id: &str,
    challenge_id: &str,
    nonce: &str,
    request_timestamp: i64,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use ed25519_dalek::Signer;

    let nonce_bytes = data_encoding::BASE64URL_NOPAD.decode(nonce.as_bytes())?;
    let canonical_hash = canonical_test_hash(request)?;
    let mut signed = Vec::new();
    signed.extend_from_slice(b"locket-client-auth-v1");
    signed.extend_from_slice(client_id.as_bytes());
    signed.extend_from_slice(challenge_id.as_bytes());
    signed.extend_from_slice(&nonce_bytes);
    signed.extend_from_slice(request_timestamp.to_string().as_bytes());
    signed.extend_from_slice(request.id.as_bytes());
    signed.extend_from_slice(&canonical_hash);
    let signature = signing_key.sign(&signed);
    Ok(json!({
        "client_id": client_id,
        "challenge_id": challenge_id,
        "nonce": nonce,
        "request_timestamp": request_timestamp,
        "signature": data_encoding::BASE64URL_NOPAD.encode(&signature.to_bytes()),
    }))
}

async fn sign_automation_request(
    state: &crate::server::AgentSocketState,
    mut request: RequestEnvelope,
) -> Result<RequestEnvelope, Box<dyn std::error::Error>> {
    let hello = RequestEnvelope::new(
        "hello",
        AgentMethod::ClientHello,
        json!({ "client_id": "lk_client_auth" }),
    );
    let ResponseEnvelope::Success(challenge) = crate::server::dispatch(&hello, state).await else {
        return Err("ClientHello should succeed".into());
    };
    let auth = sign_auth_payload(
        &automation_signing_key(),
        &request,
        "lk_client_auth",
        challenge.payload["challenge_id"].as_str().ok_or("challenge id")?,
        challenge.payload["nonce"].as_str().ok_or("challenge nonce")?,
        auth_now_i64(),
    )?;
    request.payload["auth"] = auth;
    Ok(request)
}

fn automation_grant_request(store_path: &std::path::Path, action: &str) -> RequestEnvelope {
    RequestEnvelope::new(
        "signed-grant",
        AgentMethod::RequestGrant,
        json!({
            "project_id": "lk_proj_auth",
            "profile_id": "lk_prof_auth",
            "store_path": store_path,
            "requested_action": "run-policy",
            "policy_name": "deploy",
            "action": action,
            "ttl_seconds": 30,
            "binding": { "pid": std::process::id(), "process_start_time": "auth-test" }
        }),
    )
}

fn assert_no_successful_automation_auth(
    store: &locket_store::Store,
) -> Result<(), Box<dyn std::error::Error>> {
    let (nonce_count, last_used_at, success_count): (i64, Option<i64>, i64) =
        store.connection().query_row(
            "SELECT (SELECT COUNT(*) FROM automation_client_nonces), last_used_at,
             (SELECT COUNT(*) FROM audit_log WHERE action = 'CLIENT_AUTH' AND status = 'SUCCESS')
             FROM automation_clients WHERE id = 'lk_client_auth'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    assert_eq!((nonce_count, last_used_at, success_count), (0, None, 0));
    Ok(())
}

#[tokio::test]
async fn automation_client_auth_rejects_reveal_grant_hidden_as_run_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let store = seed_automation_client_store(
        &store_path,
        automation_signing_key().verifying_key().as_bytes(),
    )?;
    let state = crate::server::AgentSocketState::locked("auth-test");
    unlock_auth_project(&state).await;

    for policy in [None, Some("deploy")] {
        let mut request = automation_grant_request(&store_path, "Reveal");
        if let Some(policy) = policy {
            request.payload["policy_name"] = json!(policy);
        } else {
            request.payload.as_object_mut().ok_or("payload")?.remove("policy_name");
        }
        let signed = sign_automation_request(&state, request).await?;
        let response = crate::server::dispatch(&signed, &state).await;
        assert!(state.grants.lock().await.is_empty(), "unauthorized Reveal grant was issued");
        assert!(matches!(response, ResponseEnvelope::Error(_)), "{response:?}");
        assert_no_successful_automation_auth(&store)?;
    }
    Ok(())
}

#[tokio::test]
async fn automation_client_auth_rejects_method_mismatch_before_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let store = seed_automation_client_store(
        &store_path,
        automation_signing_key().verifying_key().as_bytes(),
    )?;
    let state = crate::server::AgentSocketState::locked("auth-test");
    unlock_auth_project(&state).await;
    state.grants.lock().await.insert(test_grant_record("existing", i128::MAX));
    let grants_before = state.grants.lock().await.clone();
    let mut request = automation_grant_request(&store_path, "RunPolicy");
    request.kind = "Lock".to_owned();
    let signed = sign_automation_request(&state, request).await?;
    let response = crate::server::dispatch(&signed, &state).await;
    assert_eq!(*state.grants.lock().await, grants_before, "denied RPC mutated grants");
    assert!(
        state
            .unlock_cache
            .lock()
            .await
            .lookup("lk_proj_auth", crate::server::current_unix_nanos())
            .is_some(),
        "denied RPC cleared the unlock cache"
    );
    assert!(matches!(response, ResponseEnvelope::Error(_)), "{response:?}");
    assert_no_successful_automation_auth(&store)?;
    Ok(())
}

#[tokio::test]
async fn automation_client_auth_requires_policy_scope() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let store = seed_automation_client_store(
        &store_path,
        automation_signing_key().verifying_key().as_bytes(),
    )?;
    let state = crate::server::AgentSocketState::locked("auth-test");
    unlock_auth_project(&state).await;
    for policy in [None, Some(json!(null)), Some(json!("")), Some(json!(17))] {
        let mut request = automation_grant_request(&store_path, "RunPolicy");
        if let Some(policy) = policy {
            request.payload["policy_name"] = policy;
        } else {
            request.payload.as_object_mut().ok_or("payload")?.remove("policy_name");
        }
        let signed = sign_automation_request(&state, request).await?;
        let response = crate::server::dispatch(&signed, &state).await;
        assert!(state.grants.lock().await.is_empty(), "unscoped grant was issued");
        assert!(matches!(response, ResponseEnvelope::Error(_)), "{response:?}");
        assert_no_successful_automation_auth(&store)?;
    }
    Ok(())
}

#[tokio::test]
async fn automation_client_auth_rejects_unknown_method_and_actions()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let store = seed_automation_client_store(
        &store_path,
        automation_signing_key().verifying_key().as_bytes(),
    )?;
    let state = crate::server::AgentSocketState::locked("auth-test");
    unlock_auth_project(&state).await;
    for (method, action, requested_action) in [
        ("UnknownMethod", "RunPolicy", "run-policy"),
        ("Status", "RunPolicy", "run-policy"),
        ("RequestGrant", "UnknownAction", "run-policy"),
        ("RequestGrant", "RunPolicy", "unknown-action"),
        ("RequestGrant", "PrepareExec", "prepare-exec"),
        ("RequestGrant", "ScanKnownValues", "run-policy"),
        ("RequestGrant", "Copy", "run-policy"),
        ("RequestGrant", "Export", "run-policy"),
        ("RequestGrant", "SetSecret", "run-policy"),
        ("RequestGrant", "ImportDotenv", "run-policy"),
        ("RequestGrant", "ApplyPolicy", "run-policy"),
        ("RequestGrant", "TeamSync", "run-policy"),
    ] {
        let mut request = automation_grant_request(&store_path, action);
        request.kind = method.to_owned();
        request.payload["requested_action"] = json!(requested_action);
        let signed = sign_automation_request(&state, request).await?;
        let response = crate::server::dispatch(&signed, &state).await;
        assert!(matches!(response, ResponseEnvelope::Error(_)), "{response:?}");
        assert!(state.grants.lock().await.is_empty());
        assert_no_successful_automation_auth(&store)?;
    }
    Ok(())
}

#[tokio::test]
async fn automation_client_auth_accepts_permitted_grant_flows()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let store = seed_automation_client_store(
        &store_path,
        automation_signing_key().verifying_key().as_bytes(),
    )?;
    let state = crate::server::AgentSocketState::locked("auth-test");
    unlock_auth_project(&state).await;
    for (action, requested_action) in [
        ("RunPolicy", "run-policy"),
        ("PrepareExec", "run-policy"),
        ("ResolveReference", "run-policy"),
        ("ResolveReference", "resolve-reference"),
        ("ScanKnownValues", "scan-known-values"),
        ("ScanKnownValues", "redact"),
        ("Redact", "redact"),
    ] {
        // Each control has only the permission needed for its flow.
        store.connection().execute(
            "UPDATE automation_clients SET allowed_actions_json = ?1 WHERE id = 'lk_client_auth'",
            [serde_json::to_string(&[requested_action])?],
        )?;
        let mut request = automation_grant_request(&store_path, action);
        request.payload["requested_action"] = json!(requested_action);
        let signed = sign_automation_request(&state, request).await?;
        let response = crate::server::dispatch(&signed, &state).await;
        let ResponseEnvelope::Success(success) = response else {
            return Err(format!("{requested_action} / {action}: {response:?}").into());
        };
        let grant_id = success.payload["grant_id"].as_str().ok_or("grant id")?;
        let grant = state.grants.lock().await.revoke(grant_id).ok_or("issued grant missing")?;
        assert_eq!(serde_json::to_value(grant.action)?, json!(action));
    }
    Ok(())
}

#[tokio::test]
async fn automation_client_auth_allows_resolution_and_scanning_but_requires_grants()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let store = seed_automation_client_store(
        &store_path,
        automation_signing_key().verifying_key().as_bytes(),
    )?;
    let state = crate::server::AgentSocketState::locked("auth-test");
    unlock_auth_project(&state).await;
    for (method, requested_action) in [
        (AgentMethod::ResolveReference, "run-policy"),
        (AgentMethod::ResolveReference, "resolve-reference"),
        (AgentMethod::ScanKnownValues, "scan-known-values"),
        (AgentMethod::ScanKnownValues, "redact"),
    ] {
        store.connection().execute(
            "UPDATE automation_clients SET allowed_actions_json = ?1 WHERE id = 'lk_client_auth'",
            [serde_json::to_string(&[requested_action])?],
        )?;
        let request = RequestEnvelope::new(
            "signed-operation",
            method,
            json!({
                "project_id": "lk_proj_auth", "profile_id": "lk_prof_auth",
                "store_path": store_path, "policy_name": "deploy",
                "requested_action": requested_action, "reference": "lk://dev/TOKEN",
                "require_known": true
            }),
        );
        let signed = sign_automation_request(&state, request).await?;
        let response = crate::server::dispatch(&signed, &state).await;
        let ResponseEnvelope::Error(error) = response else {
            return Err("signed operation should still require a grant".into());
        };
        assert_eq!(error.error, "GrantRequired", "{method:?} / {requested_action}");
        assert!(state.grants.lock().await.is_empty());
    }
    let successful_auths: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'CLIENT_AUTH' AND status = 'SUCCESS'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(successful_auths, 4);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn automation_client_auth_accepts_signed_request_and_audits()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let signing_key = automation_signing_key();
    let verifying_key = signing_key.verifying_key();
    seed_automation_client_store(&store_path, verifying_key.as_bytes())?;

    let state = AgentSocketState::locked("test-version");
    unlock_auth_project(&state).await;
    let hello = RequestEnvelope::new(
        "hello",
        AgentMethod::ClientHello,
        json!({ "client_id": "lk_client_auth" }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&hello, &state).await else {
        return Err("ClientHello should succeed".into());
    };
    let challenge_id = success.payload["challenge_id"].as_str().ok_or("missing challenge_id")?;
    let nonce = success.payload["nonce"].as_str().ok_or("missing nonce")?;
    assert_eq!(data_encoding::BASE64URL_NOPAD.decode(nonce.as_bytes())?.len(), 24);

    let payload = json!({
        "project_id": "lk_proj_auth",
        "profile_id": "lk_prof_auth",
        "store_path": store_path,
        "requested_action": "run-policy",
        "policy_name": "deploy"
    });
    let unsigned = RequestEnvelope::new("signed-1", AgentMethod::PrepareExec, payload.clone());
    let mut signed_payload = payload;
    signed_payload.as_object_mut().ok_or("payload object")?.insert(
        "auth".to_owned(),
        sign_auth_payload(
            &signing_key,
            &unsigned,
            "lk_client_auth",
            challenge_id,
            nonce,
            auth_now_i64(),
        )?,
    );
    let signed = RequestEnvelope::new("signed-1", AgentMethod::PrepareExec, signed_payload);
    let ResponseEnvelope::Success(_) = dispatch(&signed, &state).await else {
        return Err("signed request should authenticate and dispatch".into());
    };
    let grants_before_replay = state.grants.lock().await.clone();
    assert_eq!(grants_before_replay.len(), 1);
    let ResponseEnvelope::Error(replay_error) = dispatch(&signed, &state).await else {
        return Err("reusing a signed challenge must fail".into());
    };
    assert_eq!(replay_error.error, "AutomationClientNotTrusted");
    assert_eq!(*state.grants.lock().await, grants_before_replay);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let nonce_count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM automation_client_nonces WHERE client_id = 'lk_client_auth'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(nonce_count, 1);
    let last_used_at: Option<i64> = store.connection().query_row(
        "SELECT last_used_at FROM automation_clients WHERE id = 'lk_client_auth'",
        [],
        |row| row.get(0),
    )?;
    assert!(last_used_at.is_some());
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'CLIENT_AUTH'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["status"], json!("SUCCESS"));
    assert_eq!(metadata["client_id"], json!("lk_client_auth"));
    assert_eq!(metadata["request_id"], json!("signed-1"));
    assert_eq!(metadata["requested_action"], json!("run-policy"));
    assert_eq!(metadata["requested_policy"], json!("deploy"));
    assert_eq!(metadata["auth_result"], json!("verified"));
    assert!(metadata.get("secret_name").is_none());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn set_active_profile_switches_profile_revokes_project_grants_and_audits()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::grant::{GrantAction, GrantBinding, GrantRecord, GrantRecordFields};
    use crate::method::AgentMethod;
    use crate::profile::SetActiveProfileResponse;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let config_path = directory.path().join("locket.toml");
    let project_id = "lk_proj_agent_profile";
    seed_profile_test_store(&store_path, project_id)?;
    write_profile_test_config(&config_path, project_id, "dev")?;

    let policy_notes =
        "\n# Keep team commands\n[commands.dev]\nargv = [\"npm\", \"dev\"]\nrequire_agent = true\n";
    let original_config = std::fs::read_to_string(&config_path)?;
    std::fs::write(&config_path, format!("{original_config}{policy_notes}"))?;

    let state = AgentSocketState::locked("test-version");
    unlock_profile_test_state(&state, project_id).await;
    state.grants.lock().await.insert(GrantRecord::new(GrantRecordFields {
        grant_id: "lk_grant_profile".to_owned(),
        project_id: project_id.to_owned(),
        profile_id: "lk_prof_dev".to_owned(),
        action: GrantAction::RunPolicy,
        binding: GrantBinding::new(std::process::id(), "0"),
        issued_at_unix_nanos: 0,
        ttl_seconds: 30,
        expires_at_unix_nanos: i128::MAX,
    }));
    state.grants.lock().await.insert(GrantRecord::new(GrantRecordFields {
        grant_id: "lk_grant_other".to_owned(),
        project_id: "lk_proj_other".to_owned(),
        profile_id: "lk_prof_other".to_owned(),
        action: GrantAction::RunPolicy,
        binding: GrantBinding::new(std::process::id(), "0"),
        issued_at_unix_nanos: 0,
        ttl_seconds: 30,
        expires_at_unix_nanos: i128::MAX,
    }));

    let request = RequestEnvelope::new(
        "set-profile",
        AgentMethod::SetActiveProfile,
        json!({
            "config_path": config_path,
            "store_path": store_path,
            "project_id": project_id,
            "profile_name": "staging",
            "privacy_redact_names": true,
            "root_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&request, &state).await else {
        panic!("SetActiveProfile should succeed");
    };
    let payload: SetActiveProfileResponse = serde_json::from_value(success.payload)?;
    assert!(payload.changed);
    assert_eq!(payload.profile_name, "staging");
    assert!(payload.profile_label.starts_with("profile-"));
    assert_eq!(payload.prior_profile_name, "dev");
    assert_eq!(payload.live_grants_revoked, 1);
    assert!(state.grants.lock().await.get("lk_grant_profile").is_none());
    assert!(state.grants.lock().await.get("lk_grant_other").is_some());

    let config = read_profile_test_config(&directory.path().join("locket.toml"))?;
    assert_eq!(config.default_profile.as_str(), "staging");

    let saved = std::fs::read_to_string(&config_path)?;
    assert!(saved.contains("# Keep team commands"));
    assert!(locket_core::PolicyDocument::from_toml_str(&saved)?.commands["dev"].require_agent);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let (profile_id, command, secret_name, metadata): (
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    ) = store.connection().query_row(
        "SELECT profile_id, command, secret_name, metadata_json
         FROM audit_log
         WHERE action = 'PROFILE_CHANGE'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(profile_id.as_deref(), Some("lk_prof_staging"));
    assert_eq!(command.as_deref(), Some("agent set-active-profile"));
    assert_eq!(secret_name, None);
    assert_eq!(metadata["action"], json!("PROFILE_CHANGE"));
    assert_eq!(metadata["status"], json!("SUCCESS"));
    assert_eq!(metadata["operation"], json!("use"));
    assert_eq!(metadata["command"], json!("agent set-active-profile"));
    assert_eq!(metadata["project_id"], json!(project_id));
    assert_eq!(metadata["prior_profile_name"], json!("dev"));
    assert_eq!(metadata["new_profile_name"], json!("staging"));
    assert_eq!(metadata["new_profile_id"], json!("lk_prof_staging"));
    assert_eq!(metadata["live_grants_revoked"], json!(1));
    assert_eq!(metadata["root_hash"].as_str().map(str::len), Some(64));
    assert!(metadata.get("secret_name").is_none());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn set_active_profile_locked_vault_fails_before_writing()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let config_path = directory.path().join("locket.toml");
    let project_id = "lk_proj_agent_profile";
    seed_profile_test_store(&store_path, project_id)?;
    write_profile_test_config(&config_path, project_id, "dev")?;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "set-profile-locked",
        AgentMethod::SetActiveProfile,
        json!({
            "config_path": config_path,
            "store_path": store_path,
            "project_id": project_id,
            "profile_name": "staging"
        }),
    );
    let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
        panic!("locked SetActiveProfile should fail");
    };
    assert_eq!(error.error, "UnlockRequired");
    let config = read_profile_test_config(&directory.path().join("locket.toml"))?;
    assert_eq!(config.default_profile.as_str(), "dev");
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PROFILE_CHANGE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn automation_client_auth_rejects_policy_mismatch_and_replay()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::auth::IssuedChallenge;
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let signing_key = automation_signing_key();
    let verifying_key = signing_key.verifying_key();
    seed_automation_client_store(&store_path, verifying_key.as_bytes())?;

    let state = AgentSocketState::locked("test-version");
    unlock_auth_project(&state).await;
    let bad_policy_payload = json!({
        "project_id": "lk_proj_auth",
        "profile_id": "lk_prof_auth",
        "store_path": store_path,
        "requested_action": "run-policy",
        "policy_name": "prod"
    });
    let bad_unsigned =
        RequestEnvelope::new("signed-deny", AgentMethod::PrepareExec, bad_policy_payload.clone());
    state.automation_challenges.lock().await.insert(
        "deny-challenge".to_owned(),
        IssuedChallenge {
            client_id: "lk_client_auth".to_owned(),
            challenge_id: "deny-challenge".to_owned(),
            nonce: [1; 24],
            issued_at: crate::server::current_unix_nanos(),
        },
    );
    let mut bad_signed_payload = bad_policy_payload;
    bad_signed_payload.as_object_mut().ok_or("payload object")?.insert(
        "auth".to_owned(),
        sign_auth_payload(
            &signing_key,
            &bad_unsigned,
            "lk_client_auth",
            "deny-challenge",
            &data_encoding::BASE64URL_NOPAD.encode(&[1; 24]),
            auth_now_i64(),
        )?,
    );
    let bad_signed =
        RequestEnvelope::new("signed-deny", AgentMethod::PrepareExec, bad_signed_payload);
    let ResponseEnvelope::Error(error) = dispatch(&bad_signed, &state).await else {
        return Err("policy mismatch should fail".into());
    };
    assert_eq!(error.error, "AutomationClientNotTrusted");
    assert!(state.grants.lock().await.is_empty());
    assert_no_successful_automation_auth(&locket_store::Store::open(&store_path)?)?;

    let replay_payload = json!({
        "project_id": "lk_proj_auth",
        "profile_id": "lk_prof_auth",
        "store_path": directory.path().join("store.db"),
        "requested_action": "run-policy",
        "policy_name": "deploy"
    });
    let replay_unsigned =
        RequestEnvelope::new("signed-replay", AgentMethod::PrepareExec, replay_payload.clone());
    state.automation_challenges.lock().await.insert(
        "replay-challenge".to_owned(),
        IssuedChallenge {
            client_id: "lk_client_auth".to_owned(),
            challenge_id: "replay-challenge".to_owned(),
            nonce: [2; 24],
            issued_at: crate::server::current_unix_nanos(),
        },
    );
    let nonce_record = locket_store::AutomationClientNonceRecord {
        client_id: "lk_client_auth".to_owned(),
        nonce: [2; 24],
        request_timestamp: auth_now_i64(),
        seen_at: auth_now_i64(),
        expires_at: i64::MAX,
    };
    let replay_store = locket_store::Store::open(directory.path().join("store.db"))?;
    replay_store.insert_automation_client_nonce(&nonce_record)?;
    let mut replay_signed_payload = replay_payload;
    replay_signed_payload.as_object_mut().ok_or("payload object")?.insert(
        "auth".to_owned(),
        sign_auth_payload(
            &signing_key,
            &replay_unsigned,
            "lk_client_auth",
            "replay-challenge",
            &data_encoding::BASE64URL_NOPAD.encode(&[2; 24]),
            nonce_record.request_timestamp,
        )?,
    );
    let replay_signed =
        RequestEnvelope::new("signed-replay", AgentMethod::PrepareExec, replay_signed_payload);
    let ResponseEnvelope::Error(error) = dispatch(&replay_signed, &state).await else {
        return Err("replayed nonce should fail".into());
    };
    assert_eq!(error.error, "AutomationClientReplayDetected");
    assert!(state.grants.lock().await.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn set_active_profile_rejects_invalid_missing_and_unconfirmed_dangerous_profile()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let config_path = directory.path().join("locket.toml");
    let project_id = "lk_proj_agent_profile";
    seed_profile_test_store(&store_path, project_id)?;
    write_profile_test_config(&config_path, project_id, "dev")?;

    let state = AgentSocketState::locked("test-version");
    unlock_profile_test_state(&state, project_id).await;

    let invalid = RequestEnvelope::new(
        "set-profile-invalid",
        AgentMethod::SetActiveProfile,
        json!({
            "config_path": config_path,
            "store_path": store_path,
            "project_id": project_id,
            "profile_name": "Prod"
        }),
    );
    let ResponseEnvelope::Error(error) = dispatch(&invalid, &state).await else {
        panic!("invalid profile name should fail");
    };
    assert_eq!(error.error, "InvalidProfileName");

    let missing = RequestEnvelope::new(
        "set-profile-missing",
        AgentMethod::SetActiveProfile,
        json!({
            "config_path": directory.path().join("locket.toml"),
            "store_path": directory.path().join("store.db"),
            "project_id": project_id,
            "profile_name": "qa"
        }),
    );
    let ResponseEnvelope::Error(error) = dispatch(&missing, &state).await else {
        panic!("missing profile should fail");
    };
    assert_eq!(error.error, "ProfileNotFound");

    let dangerous = RequestEnvelope::new(
        "set-profile-dangerous",
        AgentMethod::SetActiveProfile,
        json!({
            "config_path": directory.path().join("locket.toml"),
            "store_path": directory.path().join("store.db"),
            "project_id": project_id,
            "profile_name": "prod",
            "confirmation": "wrong"
        }),
    );
    let ResponseEnvelope::Error(error) = dispatch(&dangerous, &state).await else {
        panic!("unconfirmed dangerous profile should fail");
    };
    assert_eq!(error.error, "ConfirmationFailed");

    let config = read_profile_test_config(&directory.path().join("locket.toml"))?;
    assert_eq!(config.default_profile.as_str(), "dev");
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PROFILE_CHANGE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[cfg(unix)]
mod server_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;
    use crate::{
        AgentMethod, AgentSocketConfig, AgentSocketState, ConnectionOutcome, RequestEnvelope,
        ResponseEnvelope, SocketServerError, bind_socket_listener, decode_response_frame,
        encode_frame, handle_connection, socket_permission_mode,
    };
    use serde_json::Value;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    /// Tempfile's `tempdir()` may inherit `0o755` from the system temp
    /// root on macOS/Linux. The agent rejects parent directories with
    /// any group/other bits set, so test setup must explicitly tighten
    /// the directory to `0o700` before binding.
    fn tighten_directory(path: &Path) -> std::io::Result<()> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }

    #[tokio::test]
    async fn binds_socket_with_owner_only_permissions() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let _listener = bind_socket_listener(&config)?;

        let Some(mode) = socket_permission_mode(&socket_path) else {
            return Err("agent socket must exist after bind".into());
        };
        assert_eq!(mode, 0o600, "agent socket must be user-only");

        let parent_mode = std::fs::metadata(directory.path())?.permissions().mode() & 0o777;
        assert_eq!(parent_mode, 0o700, "agent socket parent must be user-only");
        Ok(())
    }

    #[tokio::test]
    async fn second_listener_on_same_path_fails_with_socket_in_use()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let _first = bind_socket_listener(&config)?;

        let second = bind_socket_listener(&config);
        let Err(SocketServerError::AgentSocketInUse { path }) = second else {
            return Err(
                format!("second bind should fail with AgentSocketInUse, got {second:?}").into()
            );
        };
        assert_eq!(path, socket_path);
        Ok(())
    }

    #[tokio::test]
    async fn status_request_round_trips_through_handler() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::locked(config.agent_version.clone());

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let request = RequestEnvelope::new("req-1", AgentMethod::Status, Value::Null);
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
        client.write_all(&frame).await?;
        client.flush().await?;

        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let response = loop {
            let read = client.read(&mut chunk).await?;
            buffer.extend_from_slice(&chunk[..read]);
            if let Ok((response, _)) = decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
                break response;
            }
            if read == 0 {
                return Err("server closed before sending a response".into());
            }
        };
        let ResponseEnvelope::Success(success) = response else {
            return Err(format!("expected Status success, got {response:?}").into());
        };
        assert_eq!(success.id, "req-1");
        assert_eq!(success.payload["lock_state"], "locked");
        assert_eq!(success.payload["agent_version"], "0.0.0-test");

        // Closing the client lets the connection loop return and the
        // server task finish cleanly.
        drop(client);
        let outcome = server.await??;
        assert_eq!(outcome, ConnectionOutcome::PeerClosed);
        Ok(())
    }

    #[tokio::test]
    async fn unknown_methods_return_protocol_error_envelopes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::locked(config.agent_version.clone());

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        // Construct an envelope with a `kind` value that does not parse to a
        // known `AgentMethod`. This exercises the dispatcher's catch-all
        // `ProtocolError` arm without depending on any specific method
        // remaining unimplemented.
        let request = RequestEnvelope {
            v: PROTOCOL_VERSION,
            id: "req-2".into(),
            kind: "DefinitelyNotAnRpc".into(),
            payload: Value::Null,
        };
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
        client.write_all(&frame).await?;
        client.flush().await?;

        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let response = loop {
            let read = client.read(&mut chunk).await?;
            buffer.extend_from_slice(&chunk[..read]);
            if let Ok((response, _)) = decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
                break response;
            }
            if read == 0 {
                return Err("server closed before sending a response".into());
            }
        };
        let ResponseEnvelope::Error(error) = response else {
            return Err(format!("expected ProtocolError envelope, got {response:?}").into());
        };
        assert_eq!(error.id, "req-2");
        assert_eq!(error.error, "ProtocolError");
        assert!(!error.retryable);

        drop(client);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn bind_refuses_when_parent_directory_has_group_or_other_bits()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        // Pre-existing parent with `0o755` — explicitly wider than the
        // agent allows. The bind must refuse rather than silently
        // tighten another principal's directory.
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");

        let result = bind_socket_listener(&config);
        let Err(SocketServerError::SocketPathTooWide { path, mode, expected }) = result else {
            return Err(format!("expected SocketPathTooWide, got {result:?}").into());
        };
        assert_eq!(path, directory.path());
        assert_eq!(mode, 0o755);
        assert_eq!(expected, 0o700);
        // Nothing should have been bound.
        assert!(!socket_path.exists(), "socket must not be created when parent is too wide");
        Ok(())
    }

    #[tokio::test]
    async fn bind_succeeds_when_parent_already_owner_only() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let _listener = bind_socket_listener(&config)?;

        let parent_mode = std::fs::metadata(directory.path())?.permissions().mode() & 0o777;
        assert_eq!(parent_mode, 0o700);
        assert_eq!(socket_permission_mode(&socket_path), Some(0o600));
        Ok(())
    }

    #[tokio::test]
    async fn bind_creates_missing_parent_with_owner_only_permissions()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let nested = directory.path().join("agent");
        let socket_path = nested.join("agent.sock");
        let config = AgentSocketConfig::new(socket_path, "0.0.0-test");

        let _listener = bind_socket_listener(&config)?;
        let nested_mode = std::fs::metadata(&nested)?.permissions().mode() & 0o777;
        assert_eq!(nested_mode, 0o700, "freshly created parent must be owner-only");
        Ok(())
    }

    #[tokio::test]
    async fn handle_connection_rejects_cross_user_peer() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::with_daemon_uid("0.0.0-test", 1000).with_test_peer_uid(1001);

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let request = RequestEnvelope::new("req-1", AgentMethod::Status, Value::Null);
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
        // The server should drop the stream before reading any frame
        // — write may succeed into the kernel buffer, but the read
        // attempt below must observe EOF or a reset (Linux can reset
        // sockets with unread input), without producing response bytes.
        let _ = client.write_all(&frame).await;
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = match client.read(&mut chunk).await {
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => return Err(error.into()),
            };
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        assert!(
            buffer.is_empty(),
            "rejected peer must not receive any response bytes, got {buffer:?}"
        );

        let outcome = server.await??;
        assert!(
            matches!(
                &outcome,
                ConnectionOutcome::Rejected {
                    reason: SocketServerError::PeerCredentialDenied { .. },
                }
            ),
            "expected ConnectionOutcome::Rejected with PeerCredentialDenied, got {outcome:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_connection_accepts_spoofed_same_user_peer()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::with_daemon_uid(config.agent_version.clone(), 1000)
            .with_test_peer_uid(1000);

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let request = RequestEnvelope::new("req-1", AgentMethod::Status, Value::Null);
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
        client.write_all(&frame).await?;
        client.flush().await?;

        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let response = loop {
            let read = client.read(&mut chunk).await?;
            buffer.extend_from_slice(&chunk[..read]);
            if let Ok((response, _)) = decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
                break response;
            }
            if read == 0 {
                return Err("server closed before sending a response".into());
            }
        };
        let ResponseEnvelope::Success(success) = response else {
            return Err(format!("expected Status success, got {response:?}").into());
        };
        assert_eq!(success.id, "req-1");

        drop(client);
        let outcome = server.await??;
        assert_eq!(outcome, ConnectionOutcome::PeerClosed);
        Ok(())
    }

    #[tokio::test]
    async fn handle_connection_accepts_same_uid_peer() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let listener = bind_socket_listener(&config)?;
        // The default constructor captures the live process UID, so
        // a same-process UnixStream::connect() satisfies the peer
        // check.
        let state = AgentSocketState::locked(config.agent_version.clone());

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let request = RequestEnvelope::new("req-1", AgentMethod::Status, Value::Null);
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
        client.write_all(&frame).await?;
        client.flush().await?;

        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let response = loop {
            let read = client.read(&mut chunk).await?;
            buffer.extend_from_slice(&chunk[..read]);
            if let Ok((response, _)) = decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
                break response;
            }
            if read == 0 {
                return Err("server closed before sending a response".into());
            }
        };
        let ResponseEnvelope::Success(success) = response else {
            return Err(format!("expected Status success, got {response:?}").into());
        };
        assert_eq!(success.id, "req-1");

        drop(client);
        let outcome = server.await??;
        assert_eq!(outcome, ConnectionOutcome::PeerClosed);
        Ok(())
    }

    /// Reads a single response frame from the client socket, growing
    /// `buffer` as needed. Returns `None` when the server closes the
    /// connection without sending a frame.
    async fn read_one_response_frame(
        client: &mut UnixStream,
        buffer: &mut Vec<u8>,
    ) -> Result<Option<ResponseEnvelope>, Box<dyn std::error::Error>> {
        loop {
            if let Ok((response, consumed)) =
                decode_response_frame(buffer, DEFAULT_MAX_MESSAGE_SIZE)
            {
                buffer.drain(..consumed);
                return Ok(Some(response));
            }
            let mut chunk = [0_u8; 256];
            let read = client.read(&mut chunk).await?;
            if read == 0 {
                return Ok(None);
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
    }

    async fn write_request_frame(
        client: &mut UnixStream,
        request: &RequestEnvelope,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let frame = encode_frame(request, DEFAULT_MAX_MESSAGE_SIZE)?;
        client.write_all(&frame).await?;
        client.flush().await?;
        Ok(())
    }

    async fn read_required_response_frame(
        client: &mut UnixStream,
        buffer: &mut Vec<u8>,
        label: &str,
    ) -> Result<ResponseEnvelope, Box<dyn std::error::Error>> {
        read_one_response_frame(client, buffer)
            .await?
            .ok_or_else(|| format!("server closed before {label} response").into())
    }

    fn expect_success(
        response: ResponseEnvelope,
        label: &str,
    ) -> Result<SuccessEnvelope, Box<dyn std::error::Error>> {
        let ResponseEnvelope::Success(success) = response else {
            return Err(format!("expected {label} success, got {response:?}").into());
        };
        Ok(success)
    }

    async fn request_success_frame(
        client: &mut UnixStream,
        buffer: &mut Vec<u8>,
        request: &RequestEnvelope,
        label: &str,
    ) -> Result<SuccessEnvelope, Box<dyn std::error::Error>> {
        write_request_frame(client, request).await?;
        let response = read_required_response_frame(client, buffer, label).await?;
        expect_success(response, label)
    }

    async fn assert_locked_status(
        client: &mut UnixStream,
        buffer: &mut Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let status_locked = request_success_frame(
            client,
            buffer,
            &RequestEnvelope::new("status-locked", AgentMethod::Status, Value::Null),
            "initial Status",
        )
        .await?;
        assert_eq!(status_locked.payload["lock_state"], "locked");
        assert_eq!(status_locked.payload["live_grant_count"], 0);
        Ok(())
    }

    async fn unlock_agent_for_e2e(
        client: &mut UnixStream,
        buffer: &mut Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        request_success_frame(
            client,
            buffer,
            &RequestEnvelope::new(
                "unlock",
                AgentMethod::Unlock,
                serde_json::json!({
                    "project_id": "project-main",
                    "ttl_seconds": 60,
                    "method": "OsKeychain"
                }),
            ),
            "Unlock",
        )
        .await?;
        Ok(())
    }

    async fn assert_unlocked_status(
        client: &mut UnixStream,
        buffer: &mut Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let status_unlocked = request_success_frame(
            client,
            buffer,
            &RequestEnvelope::new("status-unlocked", AgentMethod::Status, Value::Null),
            "unlocked Status",
        )
        .await?;
        assert_eq!(status_unlocked.payload["lock_state"], "unlocked");
        let ttl = status_unlocked.payload["unlock_ttl_seconds"].as_u64().unwrap_or_default();
        assert!((1..=60).contains(&ttl), "unlock ttl should remain live, got {ttl}");
        Ok(())
    }

    async fn request_e2e_grant(
        client: &mut UnixStream,
        buffer: &mut Vec<u8>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let grant = request_success_frame(
            client,
            buffer,
            &RequestEnvelope::new(
                "grant",
                AgentMethod::RequestGrant,
                serde_json::json!({
                    "project_id": "project-main",
                    "profile_id": "profile-main",
                    "action": "RunPolicy",
                    "ttl_seconds": 30,
                    "binding": {
                        "pid": std::process::id(),
                        "process_start_time": "e2e-start"
                    }
                }),
            ),
            "RequestGrant",
        )
        .await?;
        let grant_id = grant.payload["grant_id"].as_str().unwrap_or_default().to_owned();
        assert_ne!(grant_id, "");
        Ok(grant_id)
    }

    async fn assert_live_grant_count(
        client: &mut UnixStream,
        buffer: &mut Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let status_granted = request_success_frame(
            client,
            buffer,
            &RequestEnvelope::new("status-granted", AgentMethod::Status, Value::Null),
            "granted Status",
        )
        .await?;
        assert_eq!(status_granted.payload["live_grant_count"], 1);
        Ok(())
    }

    async fn revoke_e2e_grant(
        client: &mut UnixStream,
        buffer: &mut Vec<u8>,
        grant_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        request_success_frame(
            client,
            buffer,
            &RequestEnvelope::new(
                "revoke",
                AgentMethod::RevokeGrant,
                serde_json::json!({ "grant_id": grant_id }),
            ),
            "RevokeGrant",
        )
        .await?;
        Ok(())
    }

    async fn assert_subscription_status(
        client: &mut UnixStream,
        buffer: &mut Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let subscription = request_success_frame(
            client,
            buffer,
            &RequestEnvelope::new("subscribe", AgentMethod::SubscribeStatus, serde_json::json!({})),
            "SubscribeStatus",
        )
        .await?;
        assert_eq!(subscription.id, "subscribe");
        assert_eq!(subscription.payload["kind"], "status");
        assert_eq!(subscription.payload["lock_state"], "unlocked");
        assert_eq!(subscription.payload["live_grant_count"], 0);
        Ok(())
    }

    #[tokio::test]
    async fn e2e_agent_rpc_drives_status_unlock_grants_and_subscription()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "e2e-agent-rpc-test");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::locked(config.agent_version.clone());
        state.seed_master_key("project-main", &[3; 32]).expect("seed master key");
        state.set_test_heartbeat_interval(Duration::from_secs(60)).await;

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let mut buffer = Vec::new();

        assert_locked_status(&mut client, &mut buffer).await?;
        unlock_agent_for_e2e(&mut client, &mut buffer).await?;
        assert_unlocked_status(&mut client, &mut buffer).await?;
        let grant_id = request_e2e_grant(&mut client, &mut buffer).await?;
        assert_live_grant_count(&mut client, &mut buffer).await?;
        revoke_e2e_grant(&mut client, &mut buffer, &grant_id).await?;
        assert_subscription_status(&mut client, &mut buffer).await?;

        write_request_frame(
            &mut client,
            &RequestEnvelope::new(
                "subscribe",
                AgentMethod::CancelSubscription,
                serde_json::json!({}),
            ),
        )
        .await?;
        drop(client);

        let outcome = server.await??;
        assert_eq!(outcome, ConnectionOutcome::PeerClosed);
        Ok(())
    }

    #[tokio::test]
    async fn subscribe_status_writes_initial_event_then_heartbeat_over_socket()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "test-version");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::locked(config.agent_version.clone());
        state.set_test_heartbeat_interval(Duration::from_millis(20)).await;

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let request =
            RequestEnvelope::new("sub-1", AgentMethod::SubscribeStatus, serde_json::json!({}));
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
        client.write_all(&frame).await?;
        client.flush().await?;

        let mut buffer = Vec::new();
        let Some(initial) = read_one_response_frame(&mut client, &mut buffer).await? else {
            return Err("server closed before sending the initial status event".into());
        };
        let ResponseEnvelope::Success(initial_success) = initial else {
            return Err(format!("expected initial Success, got {initial:?}").into());
        };
        assert_eq!(initial_success.id, "sub-1");
        let initial_kind =
            initial_success.payload().get("kind").and_then(Value::as_str).unwrap_or_default();
        assert_eq!(initial_kind, "status");

        let Some(heartbeat) = read_one_response_frame(&mut client, &mut buffer).await? else {
            return Err("server closed before sending a heartbeat".into());
        };
        let ResponseEnvelope::Success(heartbeat_success) = heartbeat else {
            return Err(format!("expected heartbeat Success, got {heartbeat:?}").into());
        };
        let heartbeat_kind =
            heartbeat_success.payload().get("kind").and_then(Value::as_str).unwrap_or_default();
        assert_eq!(heartbeat_kind, "heartbeat");

        drop(client);
        let _ = server.await?;
        Ok(())
    }

    #[tokio::test]
    async fn cancel_subscription_closes_stream_cleanly() -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "v");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::locked(config.agent_version.clone());
        // Long heartbeat so the test does not race a heartbeat against
        // the cancel response — we want the cancel itself to drive the
        // close.
        state.set_test_heartbeat_interval(Duration::from_secs(60)).await;

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let subscribe = encode_frame(
            &RequestEnvelope::new("s-1", AgentMethod::SubscribeStatus, serde_json::json!({})),
            DEFAULT_MAX_MESSAGE_SIZE,
        )?;
        client.write_all(&subscribe).await?;
        client.flush().await?;

        let mut buffer = Vec::new();
        let Some(_initial) = read_one_response_frame(&mut client, &mut buffer).await? else {
            return Err("server closed before sending the initial status event".into());
        };

        let cancel = encode_frame(
            &RequestEnvelope::new("s-1", AgentMethod::CancelSubscription, serde_json::json!({})),
            DEFAULT_MAX_MESSAGE_SIZE,
        )?;
        client.write_all(&cancel).await?;
        client.flush().await?;
        drop(client);

        let outcome = server.await??;
        assert_eq!(outcome, ConnectionOutcome::PeerClosed);
        Ok(())
    }

    fn malformed_request_frames() -> Result<Vec<Vec<u8>>, ProtocolError> {
        let mut unsupported = RequestEnvelope::new("version", AgentMethod::Status, Value::Null);
        unsupported.v = PROTOCOL_VERSION + 1;
        Ok(vec![
            u32::MAX.to_le_bytes().to_vec(),
            vec![1, 0, 0, 0, b'{'],
            encode_frame(&unsupported, DEFAULT_MAX_MESSAGE_SIZE)?,
        ])
    }

    async fn assert_malformed_request_closes_open_client(
        malformed: &[u8],
        subscription: bool,
        coalesced: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;
        use tokio::time::timeout;

        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "framing-test");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::locked("framing-test");
        state.set_test_heartbeat_interval(Duration::from_secs(60)).await;
        let mut server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            Ok::<_, std::io::Error>(handle_connection(stream, state).await)
        });
        let mut client = UnixStream::connect(&socket_path).await?;
        let mut frame = Vec::new();
        if subscription {
            frame = encode_frame(
                &RequestEnvelope::new("subscribe", AgentMethod::SubscribeStatus, json!({})),
                DEFAULT_MAX_MESSAGE_SIZE,
            )?;
            if !coalesced {
                client.write_all(&frame).await?;
                frame.clear();
                let mut buffer = Vec::new();
                timeout(
                    Duration::from_secs(1),
                    read_required_response_frame(&mut client, &mut buffer, "subscription"),
                )
                .await??;
            }
        }
        frame.extend_from_slice(malformed);
        client.write_all(&frame).await?;

        // Keep the write half open. EOF from the peer must not be needed
        // to discover an oversized prefix, invalid JSON or invalid version.
        let result = timeout(Duration::from_secs(1), &mut server).await;
        if result.is_err() {
            server.abort();
            let _ = server.await;
        }
        assert!(result.is_ok(), "permanent decode error waited for client EOF");
        assert_eq!(result???, ConnectionOutcome::Errored);
        let mut remaining = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut remaining)).await??;
        Ok(())
    }

    #[tokio::test]
    async fn request_transport_rejects_oversized_prefix_without_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_malformed_request_closes_open_client(&malformed_request_frames()?[0], false, false)
            .await
    }

    #[tokio::test]
    async fn request_transport_rejects_invalid_json_without_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_malformed_request_closes_open_client(&malformed_request_frames()?[1], false, false)
            .await
    }

    #[tokio::test]
    async fn request_transport_rejects_unsupported_version_without_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_malformed_request_closes_open_client(&malformed_request_frames()?[2], false, false)
            .await
    }

    #[tokio::test]
    async fn subscription_transport_rejects_oversized_prefix_without_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_malformed_request_closes_open_client(&malformed_request_frames()?[0], true, false)
            .await
    }

    #[tokio::test]
    async fn subscription_transport_rejects_invalid_json_without_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_malformed_request_closes_open_client(&malformed_request_frames()?[1], true, false)
            .await
    }

    #[tokio::test]
    async fn subscription_transport_rejects_unsupported_version_without_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_malformed_request_closes_open_client(&malformed_request_frames()?[2], true, false)
            .await
    }

    #[tokio::test]
    async fn subscription_transport_rejects_coalesced_malformed_frames_without_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        for frame in malformed_request_frames()? {
            assert_malformed_request_closes_open_client(&frame, true, true).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn request_transport_preserves_fragmented_and_coalesced_frames()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;
        use tokio::time::timeout;

        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let listener = bind_socket_listener(&AgentSocketConfig::new(socket_path.clone(), "v"))?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            Ok::<_, std::io::Error>(handle_connection(stream, AgentSocketState::locked("v")).await)
        });
        let mut client = UnixStream::connect(&socket_path).await?;
        let frame = encode_frame(
            &RequestEnvelope::new("first", AgentMethod::Status, Value::Null),
            DEFAULT_MAX_MESSAGE_SIZE,
        )?;
        let mut buffer = Vec::new();
        client.write_all(&frame[..2]).await?;
        assert!(
            timeout(Duration::from_millis(30), read_one_response_frame(&mut client, &mut buffer))
                .await
                .is_err()
        );
        client.write_all(&frame[2..frame.len() - 1]).await?;
        assert!(
            timeout(Duration::from_millis(30), read_one_response_frame(&mut client, &mut buffer))
                .await
                .is_err()
        );
        let mut tail = vec![frame[frame.len() - 1]];
        tail.extend(encode_frame(
            &RequestEnvelope::new("second", AgentMethod::Status, Value::Null),
            DEFAULT_MAX_MESSAGE_SIZE,
        )?);
        client.write_all(&tail).await?;
        for id in ["first", "second"] {
            let response = timeout(
                Duration::from_secs(1),
                read_required_response_frame(&mut client, &mut buffer, id),
            )
            .await??;
            assert_eq!(expect_success(response, id)?.id, id);
        }
        drop(client);
        assert_eq!(timeout(Duration::from_secs(1), server).await???, ConnectionOutcome::PeerClosed);
        Ok(())
    }

    #[tokio::test]
    async fn subscription_transport_preserves_fragmented_cancel_and_coalesced_frames()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;
        use tokio::time::timeout;

        for coalesced in [false, true] {
            let directory = tempdir()?;
            tighten_directory(directory.path())?;
            let socket_path = directory.path().join("agent.sock");
            let listener = bind_socket_listener(&AgentSocketConfig::new(socket_path.clone(), "v"))?;
            let mut server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await?;
                Ok::<_, std::io::Error>(
                    handle_connection(stream, AgentSocketState::locked("v")).await,
                )
            });
            let mut client = UnixStream::connect(&socket_path).await?;
            let mut subscribe = encode_frame(
                &RequestEnvelope::new("sub", AgentMethod::SubscribeStatus, json!({})),
                DEFAULT_MAX_MESSAGE_SIZE,
            )?;
            let cancel = encode_frame(
                &RequestEnvelope::new("cancel", AgentMethod::CancelSubscription, json!({})),
                DEFAULT_MAX_MESSAGE_SIZE,
            )?;
            if coalesced {
                subscribe.extend(cancel);
                client.write_all(&subscribe).await?;
            } else {
                client.write_all(&subscribe).await?;
                let mut buffer = Vec::new();
                timeout(
                    Duration::from_secs(1),
                    read_required_response_frame(&mut client, &mut buffer, "subscription"),
                )
                .await??;
                client.write_all(&cancel[..2]).await?;
                assert!(timeout(Duration::from_millis(30), &mut server).await.is_err());
                client.write_all(&cancel[2..cancel.len() - 1]).await?;
                assert!(timeout(Duration::from_millis(30), &mut server).await.is_err());
                client.write_all(&cancel[cancel.len() - 1..]).await?;
            }
            assert_eq!(
                timeout(Duration::from_secs(1), server).await???,
                ConnectionOutcome::PeerClosed
            );
        }
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn register_command_policies_replaces_project_snapshot_and_runs_prepare_exec()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("p-pump", "pump project", 1)?;
    insert_snapshot_fixture_audit_key(&store, "p-pump")?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    unlock_profile_test_state(&state, "p-pump").await;
    {
        let mut cache = state.unlock_cache.lock().await;
        let entry = cache.lookup("p-pump", crate::server::current_unix_nanos()).expect("entry");
        let key = entry.key_bytes().to_vec();
        cache.insert(
            "p-pump".to_owned(),
            crate::unlock_cache::UnlockEntry::new(
                key,
                crate::server::current_unix_nanos(),
                std::time::Duration::from_secs(60),
                crate::unlock_cache::UnlockMethod::Passphrase,
            )
            .with_audit_context(crate::unlock_cache::UnlockAuditContext {
                store_path: store_path.clone(),
                profile_id: None,
            }),
        );
    }

    let request = RequestEnvelope::new(
        "pump-1",
        AgentMethod::RegisterCommandPolicies,
        json!({
            "project_id": "p-pump",
            "store_path": store_path,
            "policies": [{
                "project_id": "p-pump",
                "name": "deploy",
                "command_kind": "argv",
                "command_preview": "pnpm deploy",
                "required_secrets": ["DATABASE_URL"],
                "optional_secrets": [],
                "allowed_secrets": ["DATABASE_URL"],
                "confirm": false,
                "require_user_verification": false,
                "require_agent": false,
                "allow_remote_docker": false,
                "ttl_seconds": 600,
                "env_mode": "minimal",
                "override_mode": "locket",
                "updated_at_unix_nanos": 100,
            }],
        }),
    );
    let response = dispatch(&request, &state).await;
    match response {
        ResponseEnvelope::Success(_) => {}
        ResponseEnvelope::Error(ref err) => {
            unreachable!("dispatch returned error: code={} message={}", err.error, err.message);
        }
    }

    let snapshot = state.command_policies.lock().await;
    let entry =
        snapshot.iter().find(|s| s.project_id == "p-pump" && s.name == "deploy").expect("snapshot");
    assert_eq!(entry.ttl_seconds, 600);

    drop(snapshot);
    let prepare_request = RequestEnvelope::new(
        "pe-1",
        AgentMethod::PrepareExec,
        json!({
            "project_id": "p-pump",
            "profile_id": "prof-1",
            "policy_name": "deploy",
            "binding": { "pid": std::process::id(), "process_start_time": "0" }
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&prepare_request, &state).await else {
        unreachable!("PrepareExec for pumped policy must succeed");
    };
    let decoded: crate::prepare_exec::PrepareExecResponse =
        serde_json::from_value(success.payload)?;
    assert_eq!(decoded.allowed_env_names, vec!["DATABASE_URL"]);
    assert_eq!(decoded.command_kind, "argv");
    assert_eq!(decoded.ttl_seconds, 600);
    assert!(decoded.grant_id.starts_with("lk_grant_"));

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn register_command_policies_requires_unlock() -> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("p-locked", "locked project", 1)?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "pump-locked",
        AgentMethod::RegisterCommandPolicies,
        json!({
            "project_id": "p-locked",
            "store_path": store_path,
            "policies": [],
        }),
    );
    let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
        return Err("locked vault must reject pump".into());
    };
    assert_eq!(error.error, "UnlockRequired");
    assert!(state.command_policies.lock().await.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn policy_doctor_validates_candidate_references_without_values()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("p-doctor", "doctor project", 1)?;
    store.insert_profile_if_absent("prof-dev", "p-doctor", "dev", false, 1)?;
    store.connection().execute(
        "INSERT INTO secrets(
           id, project_id, profile_id, name, source, origin, required, current_version,
           state, created_at, updated_at
         )
         VALUES ('sec-db', 'p-doctor', 'prof-dev', 'DATABASE_URL', 'user-local',
                 'manual', 0, 1, 'active', 1, 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO secret_versions(secret_id, version, source, origin, state, created_at)
         VALUES ('sec-db', 1, 'user-local', 'manual', 'current', 1)",
        [],
    )?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    unlock_profile_test_state(&state, "p-doctor").await;

    let request = RequestEnvelope::new(
        "doctor-1",
        AgentMethod::PolicyDoctor,
        json!({
            "project_id": "p-doctor",
            "profile_id": "prof-dev",
            "store_path": store_path,
            "policy": {
                "project_id": "p-doctor",
                "name": "deploy",
                "command_kind": "argv",
                "command_preview": "echo lk://dev/DATABASE_URL",
                "required_secrets": ["DATABASE_URL", "API_KEY"],
                "optional_secrets": [],
                "allowed_secrets": ["DATABASE_URL", "API_KEY"],
                "confirm": false,
                "require_user_verification": false,
                "require_agent": true,
                "allow_remote_docker": false,
                "ttl_seconds": 600,
                "env_mode": "minimal",
                "override_mode": "locket",
                "updated_at_unix_nanos": 10,
            },
            "references": ["lk://dev/DATABASE_URL"],
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&request, &state).await else {
        return Err("PolicyDoctor must pass for active authorized reference".into());
    };
    assert_eq!(success.payload["status"], "pass");
    assert_eq!(success.payload["references_ok"], 1);
    assert_eq!(success.payload["references_failed"].as_array().map(Vec::len), Some(0));
    assert_eq!(success.payload["env_mode_resolve"], json!(["DATABASE_URL"]));
    assert_eq!(success.payload["env_mode_passthrough"], json!(["API_KEY"]));
    assert!(!success.payload.to_string().contains("postgres://"));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn policy_doctor_reports_denied_and_missing_references()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("p-doctor-fail", "doctor project", 1)?;
    store.insert_profile_if_absent("prof-dev", "p-doctor-fail", "dev", false, 1)?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    unlock_profile_test_state(&state, "p-doctor-fail").await;

    let request = RequestEnvelope::new(
        "doctor-fail",
        AgentMethod::PolicyDoctor,
        json!({
            "project_id": "p-doctor-fail",
            "profile_id": "prof-dev",
            "store_path": store_path,
            "policy": {
                "project_id": "p-doctor-fail",
                "name": "deploy",
                "command_kind": "argv",
                "command_preview": "echo lk://dev/DATABASE_URL lk://dev/API_KEY",
                "required_secrets": ["DATABASE_URL"],
                "optional_secrets": [],
                "allowed_secrets": ["DATABASE_URL"],
                "confirm": false,
                "require_user_verification": false,
                "require_agent": true,
                "allow_remote_docker": false,
                "ttl_seconds": 600,
                "env_mode": "minimal",
                "override_mode": "locket",
                "updated_at_unix_nanos": 10,
            },
            "references": ["lk://dev/DATABASE_URL", "lk://dev/API_KEY"],
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&request, &state).await else {
        return Err("PolicyDoctor must return a report for failed references".into());
    };
    assert_eq!(success.payload["status"], "fail");
    assert_eq!(
        success.payload["references_failed"],
        json!(["lk://dev/DATABASE_URL", "lk://dev/API_KEY"])
    );
    assert_eq!(success.payload["env_mode_denied"], json!(["API_KEY"]));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn register_command_policies_does_not_drop_other_projects()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::CommandPolicySnapshot;
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("p-a", "a", 1)?;
    insert_snapshot_fixture_audit_key(&store, "p-a")?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    state
        .set_command_policies_for_tests(vec![CommandPolicySnapshot {
            project_id: "p-b".to_owned(),
            name: "b-policy".to_owned(),
            command_kind: "argv".to_owned(),
            command_preview: "echo".to_owned(),
            required_secrets: vec![],
            optional_secrets: vec![],
            allowed_secrets: vec![],
            confirm: false,
            require_user_verification: false,
            require_agent: false,
            allow_remote_docker: false,
            ttl_seconds: 60,
            env_mode: "minimal".to_owned(),
            override_mode: "locket".to_owned(),
            updated_at_unix_nanos: 1,
        }])
        .await;
    {
        let mut cache = state.unlock_cache.lock().await;
        cache.insert(
            "p-a".to_owned(),
            crate::unlock_cache::UnlockEntry::new(
                vec![42_u8; 32],
                crate::server::current_unix_nanos(),
                std::time::Duration::from_secs(60),
                crate::unlock_cache::UnlockMethod::Passphrase,
            )
            .with_audit_context(crate::unlock_cache::UnlockAuditContext {
                store_path: store_path.clone(),
                profile_id: None,
            }),
        );
    }

    let request = RequestEnvelope::new(
        "pump-a",
        AgentMethod::RegisterCommandPolicies,
        json!({
            "project_id": "p-a",
            "store_path": store_path,
            "policies": [{
                "project_id": "p-a",
                "name": "a-policy",
                "command_kind": "argv",
                "command_preview": "echo a",
                "required_secrets": [],
                "optional_secrets": [],
                "allowed_secrets": [],
                "confirm": false,
                "require_user_verification": false,
                "require_agent": false,
                "allow_remote_docker": false,
                "ttl_seconds": 60,
                "env_mode": "minimal",
                "override_mode": "locket",
                "updated_at_unix_nanos": 2,
            }],
        }),
    );
    assert!(matches!(dispatch(&request, &state).await, ResponseEnvelope::Success(_)));

    let snapshot_counts = {
        let snapshots = state.command_policies.lock().await;
        [
            snapshots.iter().filter(|s| s.project_id == "p-a").count(),
            snapshots.iter().filter(|s| s.project_id == "p-b").count(),
        ]
    };
    assert_eq!(snapshot_counts, [1, 1]);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn register_client_inserts_record_and_appends_audit() -> Result<(), Box<dyn std::error::Error>>
{
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("p-clients", "clients project", 1)?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    unlock_profile_test_state(&state, "p-clients").await;

    let public_key = [7_u8; 32];
    let request = RequestEnvelope::new(
        "rc-1",
        AgentMethod::RegisterClient,
        json!({
            "project_id": "p-clients",
            "store_path": store_path,
            "name": "ci",
            "public_key": public_key.to_vec(),
            "storage": "external",
            "allowed_actions": ["run-policy"],
            "allowed_policies": ["deploy"],
            "created_by_locket": false,
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&request, &state).await else {
        return Err("RegisterClient should succeed".into());
    };
    let client_id = success.payload["client_id"].as_str().expect("client_id").to_owned();
    let fingerprint = success.payload["fingerprint"].as_str().expect("fingerprint").to_owned();
    assert!(client_id.starts_with("lk_client_"));
    assert_ne!(fingerprint, "");

    let store = locket_store::Store::open(&store_path)?;
    let row = store.get_automation_client("p-clients", &client_id)?.expect("client row written");
    assert_eq!(row.name, "ci");
    assert_eq!(row.public_key, public_key.to_vec());
    assert_eq!(row.allowed_actions, vec!["run-policy".to_owned()]);
    assert_eq!(row.allowed_policies, vec!["deploy".to_owned()]);
    assert!(row.revoked_at.is_none());

    let audit_rows = store.connection().query_row::<i64, _, _>(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'p-clients' AND action = 'CLIENT_ADD'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(audit_rows, 1, "CLIENT_ADD audit row should be appended");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn register_client_requires_unlock() -> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("p-locked-clients", "locked", 1)?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    let public_key = [1_u8; 32].to_vec();
    let request = RequestEnvelope::new(
        "rc-locked",
        AgentMethod::RegisterClient,
        json!({
            "project_id": "p-locked-clients",
            "store_path": store_path,
            "name": "ci",
            "public_key": public_key,
            "storage": "external",
            "allowed_actions": ["run-policy"],
            "allowed_policies": ["deploy"],
        }),
    );
    let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
        return Err("locked vault must reject RegisterClient".into());
    };
    assert_eq!(error.error, "UnlockRequired");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn register_client_rejects_invalid_metadata() -> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("p-bad-clients", "bad", 1)?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    unlock_profile_test_state(&state, "p-bad-clients").await;

    let public_key = [1_u8; 32].to_vec();
    let request = RequestEnvelope::new(
        "rc-bad",
        AgentMethod::RegisterClient,
        json!({
            "project_id": "p-bad-clients",
            "store_path": store_path,
            "name": "BadName",
            "public_key": public_key,
            "storage": "external",
            "allowed_actions": ["run-policy"],
            "allowed_policies": ["deploy"],
        }),
    );
    let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
        return Err("invalid name must be rejected".into());
    };
    assert_eq!(error.error, "MetadataInvalid");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn revoke_client_marks_row_and_appends_audit() -> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("p-rev", "revoke project", 1)?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    unlock_profile_test_state(&state, "p-rev").await;

    let public_key = [9_u8; 32].to_vec();
    let register = RequestEnvelope::new(
        "reg",
        AgentMethod::RegisterClient,
        json!({
            "project_id": "p-rev",
            "store_path": store_path,
            "name": "ci",
            "public_key": public_key,
            "storage": "external",
            "allowed_actions": ["run-policy"],
            "allowed_policies": ["deploy"],
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&register, &state).await else {
        return Err("RegisterClient should succeed".into());
    };
    let client_id = success.payload["client_id"].as_str().expect("client_id").to_owned();

    let revoke = RequestEnvelope::new(
        "rev",
        AgentMethod::RevokeClient,
        json!({
            "project_id": "p-rev",
            "store_path": store_path,
            "client": client_id.clone(),
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&revoke, &state).await else {
        return Err("RevokeClient should succeed".into());
    };
    assert_eq!(success.payload["client_id"], serde_json::Value::String(client_id.clone()));
    assert_eq!(success.payload["newly_revoked"], serde_json::Value::Bool(true));

    let store = locket_store::Store::open(&store_path)?;
    let row = store.get_automation_client("p-rev", &client_id)?.expect("client row");
    assert!(row.revoked_at.is_some(), "client must be marked revoked");

    let audit_rows = store.connection().query_row::<i64, _, _>(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'p-rev' AND action = 'CLIENT_REVOKE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(audit_rows, 1, "CLIENT_REVOKE audit row should be appended");

    // Idempotent re-revocation: second call returns newly_revoked=false and
    // does not append an additional audit row.
    let second = RequestEnvelope::new(
        "rev2",
        AgentMethod::RevokeClient,
        json!({
            "project_id": "p-rev",
            "store_path": store_path,
            "client": client_id,
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&second, &state).await else {
        return Err("second RevokeClient should still succeed".into());
    };
    assert_eq!(success.payload["newly_revoked"], serde_json::Value::Bool(false));
    let audit_rows_after = store.connection().query_row::<i64, _, _>(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'p-rev' AND action = 'CLIENT_REVOKE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(audit_rows_after, 1, "CLIENT_REVOKE audit row stays at one");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn revoke_client_returns_policy_not_found_for_unknown_client()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::server::{AgentSocketState, dispatch};

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = locket_store::Store::open(&store_path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("p-missing", "missing", 1)?;
    drop(store);

    let state = AgentSocketState::locked("test-version");
    unlock_profile_test_state(&state, "p-missing").await;

    let request = RequestEnvelope::new(
        "rev-missing",
        AgentMethod::RevokeClient,
        json!({
            "project_id": "p-missing",
            "store_path": store_path,
            "client": "lk_client_does_not_exist",
        }),
    );
    let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
        return Err("missing client must surface PolicyNotFound".into());
    };
    assert_eq!(error.error, "PolicyNotFound");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn desktop_mutations_require_grants_before_reading_any_input() {
    for kind in ["ImportDotenv", "ApplyPolicy"] {
        let state = crate::AgentSocketState::locked("test");
        let request = crate::RequestEnvelope {
            v: crate::PROTOCOL_VERSION,
            id: "mutation".into(),
            kind: kind.into(),
            payload: serde_json::json!({
                "store_path": "/unreadable/store.db", "project_root": "/unreadable/root",
                "project_id": "project", "profile_id": "profile", "env_path": "/unreadable/env",
                "overwrite": false, "literal": false, "mode": "delete", "original_name": "dev",
                "policy": {"project_id":"project","name":"dev","command_kind":"argv","command_preview":"node","required_secrets":[],"optional_secrets":[],"allowed_secrets":[],"confirm":false,"require_user_verification":false,"require_agent":false,"allow_remote_docker":false,"ttl_seconds":30,"env_mode":"minimal","override_mode":"locket","updated_at_unix_nanos":0}
            }),
        };
        let crate::ResponseEnvelope::Error(error) = crate::dispatch(&request, &state).await else {
            panic!("expected denial")
        };
        assert_eq!(error.error, "GrantRequired", "{kind}");
    }
}

fn insert_snapshot_fixture_audit_key(
    store: &locket_store::Store,
    project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use locket_crypto::{
        HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, derive_wrapping_key_v1,
        key_wrap_aad_v1, wrap_key_material_v1,
    };
    let id = format!("lk_key_snapshot_{project}");
    let purpose = KeyPurpose::Audit;
    let wrapping = derive_wrapping_key_v1(&[42; 32], &HkdfWrapInfo::new(project, None, purpose))?;
    let aad =
        key_wrap_aad_v1(&KeyWrapAad::new(project, &id, None, 0, KeyWrapPurpose::from(purpose)))?;
    let wrapped = wrap_key_material_v1(&wrapping, &[11; 32], &aad)?;
    store.insert_key(&locket_store::KeyRecord {
        id,
        project_id: project.into(),
        profile_id: None,
        purpose: purpose.as_str().into(),
        wrapped_material: wrapped.ciphertext,
        nonce: wrapped.nonce,
        created_at: 1,
    })?;
    Ok(())
}

#[test]
fn pending_profile_reconcile_is_a_registered_typed_method() -> Result<(), Box<dyn std::error::Error>>
{
    let request: crate::RequestEnvelope = serde_json::from_value(
        serde_json::json!({"v":1,"id":"reconcile","kind":"TeamSyncReconcile","payload":{"project_id":"project","incoming_profile_id":"incoming","action":{"kind":"rename_profile","local_profile_id":"local","new_name":"local-preserved"}}}),
    )?;
    assert_eq!(request.method()?.as_str(), "TeamSyncReconcile");
    Ok(())
}
