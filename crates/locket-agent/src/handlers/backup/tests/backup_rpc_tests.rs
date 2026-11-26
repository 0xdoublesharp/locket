use super::*;
use crate::{AgentMethod, dispatch};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const AUDIT_KEY: [u8; 32] = [11; 32];
const CANARY: &str = "backup-plaintext-canary-72812";

struct BackupVault {
    dir: tempfile::TempDir,
    state: AgentSocketState,
    store_path: PathBuf,
    master: [u8; 32],
}

impl BackupVault {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let data = dir.path().join(".locket");
        fs::create_dir(&data)?;
        let store_path = data.join("store.db");
        let mut store = Store::open(&store_path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT_ID, "backup", 100)?;
        let master = [42; 32];
        insert_wrapped_key(&store, "audit", None, KeyPurpose::Audit, &master, &AUDIT_KEY)?;
        let state = AgentSocketState::locked("backup test");
        state.seed_master_key(PROJECT_ID, &master)?;
        Ok(Self { dir, state, store_path, master })
    }

    async fn unlock(&self, audit: serde_json::Value) {
        let payload = json!({"project_id": PROJECT_ID, "ttl_seconds": 60, "audit": audit});
        assert!(matches!(
            self.rpc(AgentMethod::Unlock, payload).await,
            ResponseEnvelope::Success(_)
        ));
    }

    async fn rpc(&self, method: AgentMethod, payload: serde_json::Value) -> ResponseEnvelope {
        let request = RequestEnvelope::new("backup", method, payload);
        if request.payload["grant_id"].is_string() {
            crate::tests::dispatch_as_current_process(&request, &self.state).await
        } else {
            dispatch(&request, &self.state).await
        }
    }

    async fn grant(&self, action: GrantAction, scope: &str) -> TestResult<(String, GrantBinding)> {
        let binding = crate::tests::test_process_binding();
        let now = current_unix_nanos();
        let grant = self.state.grants.lock().await.issue_with_peer(
            crate::RequestGrantPayload {
                project_id: PROJECT_ID.to_owned(),
                profile_id: scope.to_owned(),
                policy_name: None,
                action,
                confirm_dangerous: false,
                ttl_seconds: 60,
                binding: binding.clone(),
            },
            now,
            now + 60_000_000_000,
            crate::tests::test_peer(&self.state),
            None,
        )?;
        Ok((grant.grant_id, binding))
    }

    fn audit(&self, action: &str) -> TestResult<Vec<serde_json::Value>> {
        let store = Store::open(&self.store_path)?;
        assert!(store.verify_audit_chain_read_only(PROJECT_ID, &AUDIT_KEY)?.hmac_ok);
        let mut statement = store
            .connection()
            .prepare("SELECT metadata_json FROM audit_log WHERE action = ?1 ORDER BY sequence")?;
        let metadata = statement
            .query_map([action], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        metadata
            .iter()
            .map(|row| {
                assert!(!row.contains(CANARY));
                Ok(serde_json::from_str(row)?)
            })
            .collect()
    }
}

fn assert_denied(response: ResponseEnvelope, code: &str) {
    assert!(
        matches!(&response, ResponseEnvelope::Error(error)
        if error.error == code && !error.message.contains(CANARY)),
        "{response:?}"
    );
}

fn assert_status(response: ResponseEnvelope, status: &str) {
    assert!(
        matches!(&response, ResponseEnvelope::Success(success)
        if success.payload["status"] == status && !success.payload.to_string().contains(CANARY)),
        "{response:?}"
    );
}

#[tokio::test]
async fn recovery_rotation_checks_acknowledgement_and_unlock_without_echoing_code() -> TestResult {
    let vault = BackupVault::new()?;
    let method = AgentMethod::RecoveryRotate;
    assert_denied(vault.rpc(method, json!(CANARY)).await, "ProtocolError");
    let mut request = json!({
        "project_id": PROJECT_ID, "verification": "current-code", "current_recovery_code": CANARY,
        "acknowledged_one_time_display": false, "clear_after_display": true
    });
    assert_denied(vault.rpc(method, request.clone()).await, "ConfirmationFailed");
    request["acknowledged_one_time_display"] = json!(true);
    assert_denied(vault.rpc(method, request.clone()).await, "UnlockRequired");
    vault.unlock(serde_json::Value::Null).await;
    assert_status(vault.rpc(method, request).await, "not-implemented");
    assert!(!vault.dir.path().join(".locket/recovery").exists());
    Ok(())
}

#[tokio::test]
async fn export_checks_scope_recipient_and_path_before_writing_sealed_history() -> TestResult {
    let vault = BackupVault::new()?;
    let mut store = Store::open(&vault.store_path)?;
    let payload = import_fixture(PROFILE_ID, "PERSONAL_TOKEN", 1)?;
    import_apply(&mut store, PROJECT_ID, &payload, ConflictResolution::AcceptIncoming)?;
    let mut next = import_fixture(PROFILE_ID, "PERSONAL_TOKEN", 2)?;
    next.blobs[0].ciphertext_b64 = BASE64URL_NOPAD.encode(&[13, 27, 42]);
    import_apply(&mut store, PROJECT_ID, &next, ConflictResolution::AcceptIncoming)?;
    for (id, purpose, key) in [
        ("profile-secret", KeyPurpose::ProfileSecret, [12; 32]),
        ("profile-fingerprint", KeyPurpose::ProfileFingerprint, [13; 32]),
    ] {
        insert_wrapped_key(&store, id, Some(PROFILE_ID), purpose, &vault.master, &key)?;
    }
    let policy = vault.dir.path().join("locket.toml");
    fs::write(
        &policy,
        "schema_version = 1\n[commands.inspect]\nshell = 'printf safe'\nexternal_env_sources = ['parent', { file = '.env' }, 'compose', 'ide']\n",
    )?;
    let (grant, binding) = vault.grant(GrantAction::Export, PROFILE_ID).await?;
    let mut request = json!({
        "project_id": PROJECT_ID, "recipient_descriptor": test_device_descriptor()?,
        "scope": "active-profile", "include_audit": false
    });
    let method = AgentMethod::ExportBundle;
    assert_denied(vault.rpc(method, json!(CANARY)).await, "ProtocolError");
    assert_denied(vault.rpc(method, request.clone()).await, "GrantRequired");
    request["grant_id"] = json!(grant);
    request["binding"] = json!(binding);
    assert_denied(vault.rpc(method, request.clone()).await, "UnlockRequired");
    vault.unlock(serde_json::Value::Null).await;
    assert_denied(vault.rpc(method, request.clone()).await, "MetadataInvalid");
    vault.unlock(json!({"store_path": vault.store_path, "profile_id": PROFILE_ID})).await;

    let mut alternate = request.clone();
    alternate["store_path"] = json!(vault.dir.path().join("other.db"));
    assert_denied(vault.rpc(method, alternate).await, "AccessDenied");
    for (key, value, code) in [
        ("include_audit", json!(true), "PolicyValidationIncomplete"),
        ("recipient_descriptor", json!(" "), "InvalidReference"),
        ("recipient_descriptor", json!(CANARY), "MetadataInvalid"),
        ("profile_id", json!("other profile"), "ProfileNotFound"),
        ("scope", json!("all-profiles"), "GrantRequired"),
    ] {
        let mut invalid = request.clone();
        invalid[key] = value;
        assert_denied(vault.rpc(method, invalid).await, code);
    }
    let descriptor = test_device_descriptor()?;
    let mut encoded = decode_device_descriptor(&descriptor).map_err(|(_, message)| message)?;
    encoded.v = 1;
    let wrong_version =
        format!("lkdev2_{}", BASE64URL_NOPAD.encode(&serde_json::to_vec(&encoded)?));
    encoded.v = 2;
    encoded.fingerprint_sha256 = "ab".repeat(32);
    let wrong_fingerprint =
        format!("lkdev2_{}", BASE64URL_NOPAD.encode(&serde_json::to_vec(&encoded)?));
    encoded.signing_public_key_ed25519 = "AQ".to_owned();
    let wrong_key = format!("lkdev2_{}", BASE64URL_NOPAD.encode(&serde_json::to_vec(&encoded)?));
    for invalid in [wrong_version, wrong_fingerprint, wrong_key, String::from("lkdev2_%")] {
        let mut denied = request.clone();
        denied["recipient_descriptor"] = json!(invalid);
        assert_denied(vault.rpc(method, denied).await, "MetadataInvalid");
    }
    let recipient = bundle_recipient(&descriptor).map_err(|(_, message)| message)?;
    store.insert_device(&locket_store::DeviceRecord {
        id: "revoked-recipient".to_owned(),
        project_id: PROJECT_ID.to_owned(),
        member_id: None,
        name: "revoked".to_owned(),
        label: "revoked".to_owned(),
        signing_public_key: vec![3; 32],
        sealing_public_key: recipient.sealing_public_key.to_vec(),
        fingerprint: recipient.fingerprint,
        safety_words: Vec::new(),
        local: false,
        created_at: 100,
        last_seen_at: None,
        revoked_at: Some(101),
    })?;
    assert_denied(vault.rpc(method, request.clone()).await, "AccessDenied");
    store.connection().execute("DELETE FROM devices WHERE id = 'revoked-recipient'", [])?;

    let mut invalid_path = request.clone();
    invalid_path["output_path"] = json!(vault.dir.path().join("missing/bundle"));
    assert_denied(vault.rpc(method, invalid_path).await, "CorruptDb");

    let rejected_path = vault.dir.path().join("unaudited.locket-bundle");
    let mut rejected = request.clone();
    rejected["output_path"] = json!(&rejected_path);
    store.connection().execute_batch(
        "CREATE TRIGGER deny_export BEFORE INSERT ON audit_log
         WHEN NEW.action = 'BACKUP_EXPORT' BEGIN SELECT RAISE(ABORT, 'fixture denied'); END",
    )?;
    assert_denied(vault.rpc(method, rejected.clone()).await, "CorruptDb");
    assert!(!rejected_path.exists(), "audit failure left a sealed output behind");
    assert_eq!(vault.audit("BACKUP_EXPORT")?, Vec::<serde_json::Value>::new());
    fs::write(&rejected_path, b"existing bundle")?;
    assert_denied(vault.rpc(method, rejected).await, "InvalidReference");
    assert_eq!(fs::read(&rejected_path)?, b"existing bundle");
    store.connection().execute_batch("DROP TRIGGER deny_export")?;

    request["include_personal"] = json!(true);
    request["include_history"] = json!(true);
    assert_status(vault.rpc(method, request.clone()).await, "exported");
    let paths = fs::read_dir(vault.store_path.parent().ok_or("store directory missing")?)?
        .collect::<Result<Vec<_>, _>>()?;
    let path = paths
        .iter()
        .map(std::fs::DirEntry::path)
        .find(|path| path.extension().is_some_and(|ext| ext == "locket-bundle"))
        .ok_or("bundle missing")?;
    let original = fs::read(&path)?;
    assert!(!original.windows(b"PERSONAL_TOKEN".len()).any(|w| w == b"PERSONAL_TOKEN"));
    request["output_path"] = json!(&path);
    assert_denied(vault.rpc(method, request).await, "InvalidReference");
    assert_eq!(fs::read(&path)?, original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    }
    let audit = vault.audit("BACKUP_EXPORT")?;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["secret_count"], 1);
    assert_eq!(audit[0]["secret_version_count"], 2);
    assert_eq!(audit[0]["command_policy_count"], 1);
    assert_eq!(audit[0]["path_kind"], "store_directory");
    assert!(!audit[0].to_string().contains("PERSONAL_TOKEN"));
    Ok(())
}

fn write_fixture_bundle(
    path: &Path,
    project_id: &str,
    fingerprint: String,
    recipient: [u8; 32],
    plaintext: &[u8],
) -> TestResult {
    let encrypted = encrypt_bundle_payload_for_age_recipients(plaintext, &[recipient])?;
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_V1,
        project_id: project_id.to_owned(),
        recipient_fingerprints: vec![fingerprint],
        created_at: 100,
        profile_count: 1,
        payload_digest: bundle_encrypted_payload_digest(&encrypted),
    };
    fs::write(path, BundleContainer::new(manifest, encrypted)?.serialize()?)?;
    Ok(())
}

#[tokio::test]
async fn import_denies_invalid_bundles_and_grants_then_audits_confirmed_apply_and_replay()
-> TestResult {
    let vault = BackupVault::new()?;
    let store = Store::open(&vault.store_path)?;
    vault.unlock(json!({"store_path": vault.store_path})).await;
    let path = vault.dir.path().join("import.locket-bundle");
    let verify = AgentMethod::VerifyBundle;
    let verification = json!({"bundle_path": path, "require_decryptable": true});
    assert_denied(vault.rpc(verify, json!(CANARY)).await, "ProtocolError");
    assert_denied(vault.rpc(verify, verification.clone()).await, "BundleVerificationFailed");
    fs::write(&path, CANARY)?;
    assert_denied(vault.rpc(verify, verification.clone()).await, "BundleVerificationFailed");

    let signing = [3; 32];
    let sealing_key = Zeroizing::new([4; 32]);
    let sealing =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*sealing_key)).to_bytes();
    let fingerprint = device_fingerprint_hex(&signing, &sealing);
    let write = |project: &str, recipient: &str, public_key: [u8; 32], plaintext: &[u8]| {
        write_fixture_bundle(&path, project, recipient.to_owned(), public_key, plaintext)
    };
    let mut payload = minimal_import_payload("prod", "untrusted-command");
    payload.profiles[0].dangerous = true;
    payload.command_policies[0].argv.push(CANARY.to_owned());
    let plaintext = Zeroizing::new(serde_json::to_vec(&payload)?);
    write(PROJECT_ID, &fingerprint, sealing, &plaintext)?;
    assert_denied(vault.rpc(verify, verification.clone()).await, "BundleVerificationFailed");

    let device = locket_store::DeviceRecord {
        id: "local-backup-device".to_owned(),
        project_id: PROJECT_ID.to_owned(),
        member_id: None,
        name: "local".to_owned(),
        label: "local".to_owned(),
        signing_public_key: signing.to_vec(),
        sealing_public_key: sealing.to_vec(),
        fingerprint: fingerprint.clone(),
        safety_words: Vec::new(),
        local: true,
        created_at: 100,
        last_seen_at: None,
        revoked_at: None,
    };
    store.insert_device(&device)?;
    assert_denied(vault.rpc(verify, verification.clone()).await, "BundleVerificationFailed");
    let unlocked = UnlockedProject {
        store_path: vault.store_path.clone(),
        store_identity: None,
        profile_id: None,
        master_key: Zeroizing::new(vault.master),
    };
    build_device_private_key_storage(&unlocked, &vault.state, PROJECT_ID)
        .map_err(|(_, message)| message)?
        .store(&device.id, &sealing_key)?;

    let other_recipient = "ab".repeat(32);
    for (recipient, public_key, bytes) in [
        (other_recipient.as_str(), sealing, plaintext.as_slice()),
        (fingerprint.as_str(), [19; 32], plaintext.as_slice()),
        (fingerprint.as_str(), sealing, CANARY.as_bytes()),
    ] {
        write(PROJECT_ID, recipient, public_key, bytes)?;
        assert_denied(vault.rpc(verify, verification.clone()).await, "BundleVerificationFailed");
    }
    payload.secret_count = 1;
    write(PROJECT_ID, &fingerprint, sealing, &Zeroizing::new(serde_json::to_vec(&payload)?))?;
    assert_denied(vault.rpc(verify, verification).await, "BundleVerificationFailed");
    payload.secret_count = 0;

    let method = AgentMethod::ImportBundle;
    assert_denied(vault.rpc(method, json!(CANARY)).await, "ProtocolError");
    let (grant, binding) =
        vault.grant(GrantAction::ImportDotenv, BUNDLE_PROJECT_GRANT_SCOPE).await?;
    let mut request = json!({
        "project_id": PROJECT_ID, "bundle_path": path, "include_audit": false,
        "conflict_mode": "accept-incoming", "grant_id": grant
    });
    assert_denied(vault.rpc(method, request.clone()).await, "GrantRequired");
    request["binding"] = json!(binding);
    fs::remove_file(&path)?;
    assert_denied(vault.rpc(method, request.clone()).await, "BundleVerificationFailed");
    write("different-project", &fingerprint, sealing, &plaintext)?;
    assert_denied(vault.rpc(method, request.clone()).await, "BundleVerificationFailed");
    payload.audit_chain = Some(json!({ "imported_audit_payload": CANARY }));
    write(PROJECT_ID, &fingerprint, sealing, &Zeroizing::new(serde_json::to_vec(&payload)?))?;
    request["include_audit"] = json!(true);
    assert_denied(vault.rpc(method, request.clone()).await, "PolicyValidationIncomplete");
    request["include_audit"] = json!(false);
    assert_denied(vault.rpc(method, request.clone()).await, "ConfirmationFailed");
    assert_eq!(store.list_profiles(PROJECT_ID)?, []);
    assert_eq!(vault.audit("BACKUP_IMPORT")?, Vec::<serde_json::Value>::new());

    request["confirm_dangerous"] = json!(true);
    store.connection().execute_batch(
        "CREATE TRIGGER deny_import_audit BEFORE INSERT ON audit_log
         WHEN NEW.action = 'BACKUP_IMPORT' BEGIN SELECT RAISE(ABORT, 'fixture denied'); END",
    )?;
    assert_denied(vault.rpc(method, request.clone()).await, "CorruptDb");
    assert_eq!(store.list_profiles(PROJECT_ID)?, []);
    assert_eq!(vault.audit("BACKUP_IMPORT")?, Vec::<serde_json::Value>::new());
    store.connection().execute_batch("DROP TRIGGER deny_import_audit")?;
    assert_status(vault.rpc(method, request.clone()).await, "applied");
    request["conflict_mode"] = json!("accept-local");
    assert_status(vault.rpc(method, request).await, "applied");
    assert!(store.get_profile_by_name(PROJECT_ID, "prod")?.ok_or("profile missing")?.dangerous);
    assert_eq!(store.list_profiles(PROJECT_ID)?.len(), 1);
    let audit = vault.audit("BACKUP_IMPORT")?;
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0]["conflict_counts"]["applied"], 1);
    assert_eq!(audit[0]["applied_profile_count"], 1);
    assert_eq!(audit[1]["conflict_counts"]["identical"], 1);
    assert_eq!(audit[1]["applied_profile_count"], 0);
    for row in audit {
        assert_eq!(row["applied_command_policy_count"], 0);
        assert_eq!(row["metadata_only"], true);
    }
    Ok(())
}

#[test]
fn malformed_bundle_rows_cannot_leave_partially_applied_profiles_or_keys() -> TestResult {
    let vault = BackupVault::new()?;
    let mut store = Store::open(&vault.store_path)?;
    for (purpose, material) in [
        (CANARY, BASE64URL_NOPAD.encode(&[7; 32])),
        ("profile-secret", CANARY.to_owned()),
        ("profile-fingerprint", "%".repeat(43)),
    ] {
        let mut payload = import_fixture(PROFILE_ID, "TOKEN", 1)?;
        payload.profile_keys.push(SealedBundleProfileKeyV1 {
            profile_id: PROFILE_ID.to_owned(),
            purpose: purpose.to_owned(),
            key_material_b64: Zeroizing::new(material),
        });
        assert!(matches!(apply_bundle_payload(
            &mut store, PROJECT_ID, &payload, ConflictResolution::AcceptIncoming,
            &vault.master, 150, false,
        ), Err(("BundleVerificationFailed", message)) if !message.contains(CANARY)));
        assert_eq!(store.list_profiles(PROJECT_ID)?, []);
    }
    for (dek, nonce) in [("%", "AQ"), ("AQ", "%"), ("AQ", "AQ")] {
        let mut payload = import_fixture(PROFILE_ID, "TOKEN", 1)?;
        payload.blobs[0].encrypted_dek_b64 = dek.to_owned();
        payload.blobs[0].value_nonce_b64 = nonce.to_owned();
        assert!(matches!(
            apply_bundle_payload(
                &mut store,
                PROJECT_ID,
                &payload,
                ConflictResolution::AcceptIncoming,
                &vault.master,
                150,
                false,
            ),
            Err(("BundleVerificationFailed", _))
        ));
        assert_eq!(store.list_profiles(PROJECT_ID)?, []);
        assert!(store.get_blob("TOKEN", 1)?.is_none());
    }
    Ok(())
}

#[test]
fn same_version_blob_conflict_applies_only_after_explicit_choice() -> TestResult {
    let vault = BackupVault::new()?;
    let mut store = Store::open(&vault.store_path)?;
    let mut payload = import_fixture(PROFILE_ID, "TOKEN", 1)?;
    import_apply(&mut store, PROJECT_ID, &payload, ConflictResolution::AcceptIncoming)?;
    let original = store.get_blob("TOKEN", 1)?.ok_or("initial blob missing")?;
    let incoming = [23, 42, 91];
    payload.blobs[0].ciphertext_b64 = BASE64URL_NOPAD.encode(&incoming);
    assert!(matches!(
        import_apply(&mut store, PROJECT_ID, &payload, ConflictResolution::Review)?,
        ApplyOutcome::ReviewRequired { divergent } if divergent == ["blob/TOKEN@1: divergent"]
    ));
    assert_eq!(store.get_blob("TOKEN", 1)?.as_ref(), Some(&original));
    import_apply(&mut store, PROJECT_ID, &payload, ConflictResolution::AcceptLocal)?;
    assert_eq!(store.get_blob("TOKEN", 1)?.as_ref(), Some(&original));

    import_apply(&mut store, PROJECT_ID, &payload, ConflictResolution::AcceptIncoming)?;
    let replacement = store.get_blob("TOKEN", 1)?.ok_or("replacement blob missing")?;
    assert_eq!(replacement.ciphertext, incoming);
    assert_eq!(replacement.encrypted_dek, original.encrypted_dek);
    assert_eq!(replacement.value_nonce, original.value_nonce);
    assert_eq!(store.get_secret_version("TOKEN", 1)?.ok_or("version missing")?.state, "current");
    Ok(())
}

#[test]
fn review_keeps_existing_version_metadata_until_explicitly_accepted() -> TestResult {
    let vault = BackupVault::new()?;
    let mut store = Store::open(&vault.store_path)?;
    let mut payload = import_fixture(PROFILE_ID, "TOKEN", 1)?;
    import_apply(&mut store, PROJECT_ID, &payload, ConflictResolution::AcceptIncoming)?;
    payload.secret_versions[0].created_at = 200;
    let read_version = |store: &Store| -> TestResult<_> {
        Ok(store.get_secret_version("TOKEN", 1)?.ok_or("version missing")?)
    };
    assert!(matches!(
        import_apply(&mut store, PROJECT_ID, &payload, ConflictResolution::Review)?,
        ApplyOutcome::ReviewRequired { divergent }
            if divergent == ["secret_version/TOKEN@1: newer-incoming"]
    ));
    import_apply(&mut store, PROJECT_ID, &payload, ConflictResolution::AcceptLocal)?;
    assert_eq!(read_version(&store)?.created_at, 100);
    import_apply(&mut store, PROJECT_ID, &payload, ConflictResolution::AcceptIncoming)?;
    assert_eq!(read_version(&store)?.created_at, 200);
    Ok(())
}

#[tokio::test]
async fn regression_verify_bundle_rejects_files_over_the_container_limit_before_decoding()
-> TestResult {
    let vault = BackupVault::new()?;
    let path = vault.dir.path().join("oversized.locket-bundle");
    fs::File::create(&path)?.set_len(
        locket_core::BUNDLE_MAX_PAYLOAD_LEN
            + u64::try_from(locket_core::BUNDLE_MAX_MANIFEST_LEN)?
            + 8
            + 2
            + 4
            + 8
            + 1,
    )?;
    let response = vault.rpc(AgentMethod::VerifyBundle, json!({"bundle_path":path})).await;
    assert!(
        matches!(&response, ResponseEnvelope::Error(error)
            if error.error == "BundleVerificationFailed"
                && error.message == "bundle file exceeds the maximum container size"),
        "{response:?}",
    );
    Ok(())
}
