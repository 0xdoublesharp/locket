//! Agent RPC and grant-table regressions for scoped execution.
#![allow(unused_crate_dependencies, clippy::multiple_crate_versions)]

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use locket_agent::{
    AgentMethod, AgentSocketState, ClientHelloResponse, CommandPolicySnapshot, GrantAction,
    GrantBinding, GrantRecord, GrantRecordFields, GrantTable, GrantValidation,
    PolicyDoctorResponse, RequestEnvelope, ResponseEnvelope, UnlockEntry, UnlockMethod, dispatch,
};
use locket_core::PolicyDocument;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const PROJECT: &str = "lk_proj_fixture";
const CLIENT: &str = "lk_client_fixture";
const MASTER: [u8; 32] = [7; 32];

#[tokio::test]
async fn hello_retains_challenges_inside_the_freshness_window()
-> Result<(), Box<dyn std::error::Error>> {
    let state = AgentSocketState::locked("test");
    let hello =
        RequestEnvelope::new("hello", AgentMethod::ClientHello, json!({"client_id": "fixture"}));
    let now = now_nanos()?;
    let minute = 60_000_000_000;
    let mut challenges = Vec::new();
    for (offset, keep) in [(-6, false), (-4, true), (4, true), (6, false)] {
        let issued: ClientHelloResponse =
            serde_json::from_value(success_payload(dispatch(&hello, &state).await)?)?;
        state
            .automation_challenges
            .lock()
            .await
            .get_mut(&issued.challenge_id)
            .ok_or("hello did not retain its challenge")?
            .issued_at = now + offset * minute;
        challenges.push((issued.challenge_id, keep));
    }
    let fresh: ClientHelloResponse =
        serde_json::from_value(success_payload(dispatch(&hello, &state).await)?)?;
    let retained = state.automation_challenges.lock().await;
    assert!(retained.contains_key(&fresh.challenge_id));
    for (challenge, keep) in challenges {
        assert_eq!(retained.contains_key(&challenge), keep);
    }
    drop(retained);
    Ok(())
}

#[test]
fn grants_enforce_each_scope_and_count_every_project_revocation() {
    use GrantValidation::{Expired, ProcessMismatch, Valid};

    let binding = GrantBinding::new(40, "start");
    let another_binding = GrantBinding::new(40, "new-start");
    let mut grants = GrantTable::default();
    for (id, project) in
        [("prepare-a", "project-a"), ("prepare-b", "project-a"), ("other", "project-b")]
    {
        let mut record = GrantRecord::new(GrantRecordFields {
            grant_id: id.into(),
            project_id: project.into(),
            profile_id: "dev".into(),
            action: GrantAction::PrepareExec,
            binding: binding.clone(),
            issued_at_unix_nanos: 10,
            expires_at_unix_nanos: 20,
            ttl_seconds: 10,
        });
        record.policy_name = Some("build".into());
        grants.insert(record);
    }
    let validate = |project, profile, action, policy, now, binding| {
        grants.validate_any_for_policy(
            "prepare-a",
            project,
            profile,
            &[action],
            policy,
            now,
            binding,
        )
    };
    for (project, profile, action, policy, now, binding, expected) in [
        ("project-a", "dev", GrantAction::PrepareExec, "build", 19, Some(&binding), Valid),
        (
            "project-b",
            "dev",
            GrantAction::PrepareExec,
            "build",
            19,
            Some(&binding),
            ProcessMismatch,
        ),
        (
            "project-a",
            "prod",
            GrantAction::PrepareExec,
            "build",
            19,
            Some(&binding),
            ProcessMismatch,
        ),
        ("project-a", "dev", GrantAction::Reveal, "build", 19, Some(&binding), ProcessMismatch),
        (
            "project-a",
            "dev",
            GrantAction::PrepareExec,
            "deploy",
            19,
            Some(&binding),
            ProcessMismatch,
        ),
        (
            "project-a",
            "dev",
            GrantAction::PrepareExec,
            "build",
            19,
            Some(&another_binding),
            ProcessMismatch,
        ),
        ("project-a", "dev", GrantAction::PrepareExec, "build", 19, None, ProcessMismatch),
        ("project-a", "dev", GrantAction::PrepareExec, "build", 20, Some(&binding), Expired),
    ] {
        assert_eq!(validate(project, profile, action, policy, now, binding), expected);
    }
    assert_eq!(grants.count_for_project("project-a"), 2);
    assert_eq!(grants.revoke_for_project("project-a"), 2);
    assert_eq!(grants.count_for_project("project-a"), 0);
    assert_eq!(grants.count_for_project("project-b"), 1);
    assert!(grants.get("other").is_some());
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tokio::test]
async fn a_peer_can_revoke_only_its_own_grant_or_a_prepare_exec_handoff()
-> Result<(), Box<dyn std::error::Error>> {
    use locket_agent::{PeerIdentity, current_process_uid, dispatch_with_peer};

    let state = AgentSocketState::locked("test");
    let pid = std::process::id();
    let live = locket_platform::process_binding_for_pid(pid)?;
    let binding = GrantBinding::new(pid, live.process_start_time);
    let issuer = pid.wrapping_add(1);
    let peer = PeerIdentity { uid: current_process_uid(), pid: Some(pid), connection_id: 2 };
    for (id, action, issued_by, allowed) in [
        ("owned", GrantAction::ResolveReference, pid, true),
        ("unrelated", GrantAction::ResolveReference, issuer, false),
        ("handoff", GrantAction::PrepareExec, issuer, true),
    ] {
        let mut record = GrantRecord::new(GrantRecordFields {
            grant_id: id.into(),
            project_id: PROJECT.into(),
            profile_id: "lk_prof_dev".into(),
            action,
            binding: binding.clone(),
            issued_at_unix_nanos: 1,
            expires_at_unix_nanos: i128::MAX,
            ttl_seconds: 60,
        });
        record.observed_peer_pid = Some(issued_by);
        record.observed_connection_id = Some(1);
        state.grants.lock().await.insert(record);
        let revoke =
            RequestEnvelope::new("revoke", AgentMethod::RevokeGrant, json!({"grant_id": id}));
        let response = dispatch_with_peer(&revoke, &state, Some(peer)).await;
        if allowed {
            assert!(matches!(response, ResponseEnvelope::Success(_)), "{id}: {response:?}");
        } else {
            assert!(
                matches!(&response, ResponseEnvelope::Error(error) if error.error == "GrantRequired"),
                "{id}: {response:?}"
            );
        }
        assert_eq!(state.grants.lock().await.get(id).is_none(), allowed, "{id}");
    }
    Ok(())
}

#[tokio::test]
async fn authenticated_prepare_records_nonce_through_the_documented_retention_window()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("store.db");
    let signing = SigningKey::from_bytes(&[23; 32]);
    let store = automation_store(&path, &signing)?;
    let state = AgentSocketState::locked("test");
    unlock_project(&state, PROJECT).await?;
    let document = PolicyDocument::from_toml_str(
        "schema_version = 1\n[commands.build]\nargv = ['tool', 'build']",
    )?;
    state.command_policies.lock().await.push(CommandPolicySnapshot::from_policy(
        PROJECT,
        &document.commands["build"],
        1,
    ));

    let request_timestamp = i64::try_from(now_nanos()?)? - 120_000_000_000;
    let request = signed_prepare(&state, &path, &signing, request_timestamp).await?;
    let nonce = BASE64URL_NOPAD.decode(
        request.payload["auth"]["nonce"].as_str().ok_or("missing challenge nonce")?.as_bytes(),
    )?;
    let prepared = success_payload(dispatch(&request, &state).await)?;
    assert!(prepared["grant_id"].is_string());
    let persisted: (Vec<u8>, i64, i64) = store.connection().query_row(
        "SELECT nonce, request_timestamp, expires_at FROM automation_client_nonces WHERE client_id = ?1",
        [CLIENT],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(persisted, (nonce, request_timestamp, request_timestamp + 600_000_000_000));
    Ok(())
}

#[tokio::test]
async fn automation_rejects_a_future_vault_schema_before_recording_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("future.db");
    let signing = SigningKey::from_bytes(&[23; 32]);
    let store = automation_store(&path, &signing)?;
    let future_version = locket_store::SCHEMA_VERSION + 1;
    store.connection().execute(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, 2)",
        [future_version],
    )?;
    let state = AgentSocketState::locked("test");
    unlock_project(&state, PROJECT).await?;
    let request = signed_prepare(&state, &path, &signing, i64::try_from(now_nanos()?)?).await?;
    let response = dispatch(&request, &state).await;
    assert_auth_storage_error(response, "SchemaNewerThanBinary")?;
    assert_no_recorded_auth(&store)?;
    assert_eq!(*state.grants.lock().await, GrantTable::default());
    assert_eq!(store.current_schema_version()?, Some(i64::from(future_version)));
    Ok(())
}

#[tokio::test]
async fn automation_reports_unavailable_vaults_and_refused_audit_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("store.db");
    let signing = SigningKey::from_bytes(&[23; 32]);
    let store = automation_store(&path, &signing)?;
    let state = AgentSocketState::locked("test");
    unlock_project(&state, PROJECT).await?;

    let missing = directory.path().join("missing.db");
    let request = signed_prepare(&state, &missing, &signing, i64::try_from(now_nanos()?)?).await?;
    assert_auth_storage_error(dispatch(&request, &state).await, "AuditIntegrityFailed")?;
    assert!(!missing.exists());

    let oversized_fingerprint = "x".repeat(70_000);
    store.connection().execute(
        "UPDATE automation_clients SET fingerprint = ?1 WHERE id = ?2",
        rusqlite::params![oversized_fingerprint, CLIENT],
    )?;
    let request = signed_prepare(&state, &path, &signing, i64::try_from(now_nanos()?)?).await?;
    assert_auth_storage_error(dispatch(&request, &state).await, "MetadataInvalid")?;
    assert_no_recorded_auth(&store)?;
    assert_eq!(*state.grants.lock().await, GrantTable::default());
    Ok(())
}

#[tokio::test]
async fn automation_reports_a_busy_vault_without_recording_partial_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("store.db");
    let signing = SigningKey::from_bytes(&[23; 32]);
    let mut store = automation_store(&path, &signing)?;
    let state = AgentSocketState::locked("test");
    unlock_project(&state, PROJECT).await?;
    let request = signed_prepare(&state, &path, &signing, i64::try_from(now_nanos()?)?).await?;
    let lock = store
        .connection_mut()
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let response = dispatch(&request, &state).await;
    lock.rollback()?;
    assert_auth_storage_error(response, "StorageBusy")?;
    assert_no_recorded_auth(&store)?;
    assert_eq!(*state.grants.lock().await, GrantTable::default());
    Ok(())
}

async fn signed_prepare(
    state: &AgentSocketState,
    path: &Path,
    signing: &SigningKey,
    request_timestamp: i64,
) -> Result<RequestEnvelope, Box<dyn std::error::Error>> {
    let hello =
        RequestEnvelope::new("hello", AgentMethod::ClientHello, json!({"client_id": CLIENT}));
    let challenge: ClientHelloResponse =
        serde_json::from_value(success_payload(dispatch(&hello, state).await)?)?;
    let mut request = RequestEnvelope::new(
        "prepare",
        AgentMethod::PrepareExec,
        json!({
            "project_id": PROJECT,
            "profile_id": "lk_prof_dev",
            "requested_action": "run-policy",
            "policy_name": "build",
            "store_path": path,
            "client_metadata": {"labels": ["ci", "nightly"], "interactive": false},
        }),
    );
    let nonce = BASE64URL_NOPAD.decode(challenge.nonce.as_bytes())?;
    let signature = sign_request(&request, signing, &challenge, &nonce, request_timestamp)?;
    request.payload["auth"] = json!({
        "client_id": CLIENT,
        "challenge_id": challenge.challenge_id,
        "nonce": challenge.nonce,
        "request_timestamp": request_timestamp,
        "signature": BASE64URL_NOPAD.encode(&signature.to_bytes()),
    });
    Ok(request)
}

fn sign_request(
    request: &RequestEnvelope,
    signing: &SigningKey,
    challenge: &ClientHelloResponse,
    nonce: &[u8],
    timestamp: i64,
) -> Result<ed25519_dalek::Signature, serde_json::Error> {
    let mut canonical = serde_json::to_value(request)?;
    canonical.sort_all_objects();
    let digest = Sha256::digest(serde_json::to_vec(&canonical)?);
    let signed = [
        b"locket-client-auth-v1",
        CLIENT.as_bytes(),
        challenge.challenge_id.as_bytes(),
        nonce,
        timestamp.to_string().as_bytes(),
        request.id.as_bytes(),
        digest.as_slice(),
    ]
    .concat();
    Ok(signing.sign(&signed))
}

fn automation_store(
    path: &Path,
    signing: &SigningKey,
) -> Result<locket_store::Store, Box<dyn std::error::Error>> {
    use locket_crypto::{
        HkdfWrapInfo, KeyPurpose, KeyWrapAad, derive_wrapping_key_v1, key_wrap_aad_v1,
        wrap_key_material_v1,
    };

    let mut store = locket_store::Store::open(path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent(PROJECT, "fixture", 1)?;
    store.insert_profile_if_absent("lk_prof_dev", PROJECT, "dev", false, 1)?;
    let key_id = "lk_key_fixture_audit";
    let purpose = KeyPurpose::Audit;
    let wrapping_key = derive_wrapping_key_v1(&MASTER, &HkdfWrapInfo::new(PROJECT, None, purpose))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(PROJECT, key_id, None, 0, purpose.into()))?;
    let wrapped = wrap_key_material_v1(&wrapping_key, &[11; 32], &aad)?;
    store.insert_key(&locket_store::KeyRecord {
        id: key_id.into(),
        project_id: PROJECT.into(),
        profile_id: None,
        purpose: purpose.as_str().into(),
        wrapped_material: wrapped.ciphertext,
        nonce: wrapped.nonce,
        created_at: 1,
    })?;
    store.insert_automation_client(&locket_store::AutomationClientRecord {
        id: CLIENT.into(),
        project_id: PROJECT.into(),
        name: "build fixture".into(),
        public_key: signing.verifying_key().to_bytes().to_vec(),
        fingerprint: "fixture-only".into(),
        storage: "external".into(),
        allowed_actions: vec!["run-policy".into()],
        allowed_policies: vec!["build".into()],
        created_at: 1,
        last_used_at: None,
        revoked_at: None,
    })?;
    Ok(store)
}

fn assert_auth_storage_error(
    response: ResponseEnvelope,
    code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ResponseEnvelope::Error(error) = response else {
        return Err("expected automation authentication to fail".into());
    };
    assert_eq!(error.error, code);
    assert_eq!(error.message, "automation authentication storage failed");
    Ok(())
}

fn assert_no_recorded_auth(store: &locket_store::Store) -> Result<(), rusqlite::Error> {
    let counts = store.connection().query_row(
        "SELECT (SELECT COUNT(*) FROM automation_client_nonces),
                (SELECT COUNT(*) FROM audit_log WHERE action = 'CLIENT_AUTH'),
                (SELECT last_used_at FROM automation_clients WHERE id = ?1)",
        [CLIENT],
        |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?, row.get::<_, Option<i64>>(2)?)),
    )?;
    assert_eq!(counts, (0, 0, None));
    Ok(())
}

#[tokio::test]
async fn prepare_exec_selects_both_the_project_and_named_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let state = AgentSocketState::locked("test");
    unlock_project(&state, "app").await?;
    let document = PolicyDocument::from_toml_str(
        r#"
        schema_version = 1
        [commands.deploy]
        argv = ["tool", "deploy"]
        required_secrets = ["DEPLOY_TOKEN"]
        ttl = "15m"
        [commands.preview]
        shell = "tool preview"
        optional_secrets = ["PREVIEW_TOKEN"]
        ttl = "10m"
        "#,
    )?;
    *state.command_policies.lock().await = vec![
        CommandPolicySnapshot::from_policy("other", &document.commands["deploy"], 1),
        CommandPolicySnapshot::from_policy("app", &document.commands["preview"], 2),
        CommandPolicySnapshot::from_policy("app", &document.commands["deploy"], 3),
    ];

    let request = |project, policy| {
        RequestEnvelope::new(
            "prepare",
            AgentMethod::PrepareExec,
            json!({"project_id": project, "policy_name": policy, "profile_id": "dev"}),
        )
    };
    let payload = success_payload(dispatch(&request("app", "deploy"), &state).await)?;
    assert_eq!(payload["command_kind"], "argv");
    assert_eq!(payload["ttl_seconds"], 900);
    assert_eq!(payload["allowed_env_names"], json!(["DEPLOY_TOKEN"]));
    let id = payload["grant_id"].as_str().ok_or("no grant id")?;
    let table = state.grants.lock().await;
    let grant = table.get(id).ok_or("grant was not recorded")?;
    assert_eq!(grant.project_id, "app");
    assert_eq!(grant.policy_name.as_deref(), Some("deploy"));
    assert_eq!(grant.binding.pid, std::process::id());
    drop(table);

    for (project, policy) in [("app", "unknown"), ("other", "preview")] {
        let response = dispatch(&request(project, policy), &state).await;
        assert!(
            matches!(response, ResponseEnvelope::Error(error) if error.error == "PolicyNotFound")
        );
    }
    assert_eq!(state.grants.lock().await.len(), 1);
    Ok(())
}

#[test]
fn policy_doctor_scans_fully_quoted_references_and_respects_explicit_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    let (finished, completion) = std::sync::mpsc::channel();
    let _worker = std::thread::spawn(move || {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())
            .and_then(|runtime| {
                runtime
                    .block_on(check_policy_doctor_references())
                    .map_err(|error| error.to_string())
            });
        let _ = finished.send(result);
    });
    completion
        .recv_timeout(Duration::from_secs(10))
        .map_err(|error| format!("policy doctor did not complete: {error}"))??;
    Ok(())
}

async fn check_policy_doctor_references() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("store.db");
    let mut store = locket_store::Store::open(&path)?;
    store.initialize_schema()?;
    store.insert_project_if_absent("app", "app", 1)?;
    store.insert_profile_if_absent("profile-dev", "app", "dev", false, 1)?;
    drop(store);

    let state = AgentSocketState::locked("test");
    unlock_project(&state, "app").await?;
    let document = PolicyDocument::from_toml_str(
        r#"
        schema_version = 1
        [commands.run]
        shell = "'lk://dev/FIRST' \"lk://dev/SECOND\" `lk://dev/THIRD` lk://dev/FOURTH"
        required_secrets = ["UNREFERENCED", "FIRST"]
        "#,
    )?;
    let policy = CommandPolicySnapshot::from_policy("app", &document.commands["run"], 1);
    let mut request = RequestEnvelope::new(
        "doctor",
        AgentMethod::PolicyDoctor,
        json!({"project_id":"app", "profile_id":"profile-dev", "store_path":path, "policy":policy}),
    );
    let inferred: PolicyDoctorResponse =
        serde_json::from_value(success_payload(dispatch(&request, &state).await)?)?;
    assert_eq!(inferred.status, "fail");
    assert_eq!(
        inferred.references_failed,
        ["lk://dev/FIRST", "lk://dev/SECOND", "lk://dev/THIRD", "lk://dev/FOURTH"]
    );
    assert_eq!(inferred.env_mode_denied, ["FOURTH", "SECOND", "THIRD"]);
    assert_eq!(inferred.env_mode_passthrough, ["UNREFERENCED"]);

    request.payload["references"] = json!(["lk://dev/EXPLICIT"]);
    let explicit: PolicyDoctorResponse =
        serde_json::from_value(success_payload(dispatch(&request, &state).await)?)?;
    assert_eq!(explicit.references_failed, ["lk://dev/EXPLICIT"]);
    assert_eq!(explicit.env_mode_denied, ["EXPLICIT"]);
    assert_eq!(explicit.env_mode_passthrough, ["FIRST", "UNREFERENCED"]);
    Ok(())
}

async fn unlock_project(
    state: &AgentSocketState,
    project: &str,
) -> Result<(), std::time::SystemTimeError> {
    let timestamp = now_nanos()?;
    state.unlock_cache.lock().await.insert(
        project.into(),
        UnlockEntry::new(
            MASTER.to_vec(),
            timestamp,
            Duration::from_secs(60),
            UnlockMethod::OsKeychain,
        ),
    );
    Ok(())
}

fn now_nanos() -> Result<i128, std::time::SystemTimeError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(i128::from(now.as_secs()) * 1_000_000_000 + i128::from(now.subsec_nanos()))
}

fn success_payload(response: ResponseEnvelope) -> Result<Value, Box<dyn std::error::Error>> {
    match response {
        ResponseEnvelope::Success(success) => Ok(success.payload),
        ResponseEnvelope::Error(error) => Err(format!("{}: {}", error.error, error.message).into()),
    }
}
