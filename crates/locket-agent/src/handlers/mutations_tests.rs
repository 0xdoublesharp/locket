#![allow(clippy::unwrap_used, clippy::panic, clippy::too_many_lines)]
use super::*;
use crate::{GrantRecord, GrantRecordFields, UnlockEntry, UnlockMethod};
use locket_crypto::{
    HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, derive_wrapping_key_v1, key_wrap_aad_v1,
    wrap_key_material_v1,
};
use std::time::Duration;

const PROJECT: &str = "lk_proj_mutation";
const PROFILE: &str = "lk_prof_actual";
const NOW: i128 = 1_000;
const MASTER: KeyBytes = [7; 32];
const AUDIT: KeyBytes = [10; 32];
const CANARY: &str = "input-canary-never-return";
struct Fixture {
    directory: tempfile::TempDir,
    scope: MutationScope,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("project");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        std::fs::write(
            root.join("locket.toml"),
            format!(
                "# keep notes\nschema_version=1\nproject_id='{PROJECT}'\nname='fixture'\ndefault_profile='dev'\n[commands.dev]\nargv=['node','a b.js'] # keep argv\nrequire_agent=true\ninherit_env=['PATH']\nexternal_env_sources=['ide']\n"
            ),
        )?;
        let scope = MutationScope {
            store_path: dir.path().join("store.db"),
            project_root: root,
            project_id: PROJECT.into(),
            profile_id: PROFILE.into(),
            grant_id: Some("lk_grant_mutation".into()),
            binding: Some(GrantBinding::new(std::process::id(), "test-start")),
        };
        let mut store = Store::open(&scope.store_path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT, "fixture", 1)?;
        store.insert_profile_if_absent(PROFILE, PROJECT, "dev", false, 1)?;
        store.trust_project_root(
            PROJECT,
            &Sha256::digest(scope.project_root.to_string_lossy().as_bytes()).into(),
            scope.project_root.to_str(),
            1,
        )?;
        for (purpose, profile, material) in [
            (KeyPurpose::Audit, None, AUDIT),
            (KeyPurpose::ProfileSecret, Some(PROFILE), [8; 32]),
            (KeyPurpose::ProfileFingerprint, Some(PROFILE), [9; 32]),
        ] {
            let id = format!("lk_key_{}", purpose.as_str());
            let wrap =
                derive_wrapping_key_v1(&MASTER, &HkdfWrapInfo::new(PROJECT, profile, purpose))?;
            let aad = key_wrap_aad_v1(&KeyWrapAad::new(
                PROJECT,
                &id,
                profile,
                0,
                KeyWrapPurpose::from(purpose),
            ))?;
            let wrapped = wrap_key_material_v1(&wrap, &material, &aad)?;
            store.insert_key(&locket_store::KeyRecord {
                id,
                project_id: PROJECT.into(),
                profile_id: profile.map(str::to_owned),
                purpose: purpose.as_str().into(),
                wrapped_material: wrapped.ciphertext,
                nonce: wrapped.nonce,
                created_at: 1,
            })?;
        }
        Ok(Self { directory: dir, scope })
    }
    fn import(&self, text: &str, overwrite: bool) -> ImportDotenvRequest {
        let path = self.scope.project_root.join(".env");
        std::fs::write(&path, text).unwrap();
        ImportDotenvRequest {
            scope: self.scope.clone(),
            env_path: path,
            overwrite,
            literal: false,
            confirmation: None,
        }
    }
    fn policy(&self) -> ApplyPolicyRequest {
        let parsed = PolicyDocument::from_toml_str(
            &std::fs::read_to_string(self.scope.project_root.join("locket.toml")).unwrap(),
        )
        .unwrap();
        let mut policy = CommandPolicySnapshot::from_policy(PROJECT, &parsed.commands["dev"], 1);
        policy.required_secrets = vec!["TOKEN".into()];
        policy.allowed_secrets = policy.required_secrets.clone();
        ApplyPolicyRequest {
            scope: self.scope.clone(),
            mode: "edit".into(),
            original_name: "dev".into(),
            policy,
            confirmation: None,
        }
    }
    async fn state(&self, action: GrantAction) -> crate::AgentSocketState {
        let state = crate::AgentSocketState::locked("test");
        state.unlock_cache.lock().await.insert(
            PROJECT.into(),
            UnlockEntry::new(MASTER.to_vec(), 0, Duration::from_secs(60), UnlockMethod::Passphrase),
        );
        state.grants.lock().await.insert(GrantRecord::new(GrantRecordFields {
            grant_id: "lk_grant_mutation".into(),
            project_id: PROJECT.into(),
            profile_id: PROFILE.into(),
            action,
            binding: self.scope.binding.clone().unwrap(),
            issued_at_unix_nanos: 0,
            ttl_seconds: 30,
            expires_at_unix_nanos: 30_000_000_000,
        }));
        state
    }
    fn store(&self) -> Store {
        Store::open(&self.scope.store_path).unwrap()
    }
}
fn code(response: ResponseEnvelope) -> String {
    match response {
        ResponseEnvelope::Error(e) => e.error,
        ResponseEnvelope::Success(_) => panic!("expected error"),
    }
}
fn envelope<T: Serialize>(method: crate::AgentMethod, request: &T) -> RequestEnvelope {
    RequestEnvelope::new("test", method, serde_json::to_value(request).unwrap())
}

#[tokio::test]
async fn passphrase_cache_import_accepts_empty_multiline_and_preserves_original()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let text = format!("TOKEN={CANARY}\nEMPTY=\nMULTI='a\nb'\nTOKEN=last\n");
    let request = fixture.import(&text, false);
    let state = fixture.state(GrantAction::ImportDotenv).await;
    let response =
        handle_import_dotenv(&envelope(crate::AgentMethod::ImportDotenv, &request), &state, NOW)
            .await;
    let ResponseEnvelope::Success(success) = response else {
        panic!("import failed: {response:?}")
    };
    assert_eq!(success.payload["imported"], 3);
    assert!(!success.payload.to_string().contains(CANARY));
    assert_eq!(std::fs::read_to_string(&request.env_path)?, text);
    let store = fixture.store();
    assert!(store.get_secret_by_source(PROJECT, PROFILE, "EMPTY", "user-local")?.is_some());
    assert!(store.verify_audit_chain_read_only(PROJECT, &AUDIT)?.hmac_ok);
    Ok(())
}

#[tokio::test]
async fn grants_cache_and_profile_fence_precede_import_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let request = fixture.import(&format!("TOKEN={CANARY}\n"), false);
    let state = fixture.state(GrantAction::ApplyPolicy).await;
    assert_eq!(
        code(
            handle_import_dotenv(
                &envelope(crate::AgentMethod::ImportDotenv, &request),
                &state,
                NOW
            )
            .await
        ),
        "GrantRequired"
    );
    let state = fixture.state(GrantAction::ImportDotenv).await;
    state.unlock_cache.lock().await.clear();
    assert_eq!(
        code(
            handle_import_dotenv(
                &envelope(crate::AgentMethod::ImportDotenv, &request),
                &state,
                NOW
            )
            .await
        ),
        "UnlockRequired"
    );
    let mut wrong_profile = request.clone();
    wrong_profile.scope.profile_id = "dev".into();
    assert_eq!(
        import_dotenv_with_master(&wrong_profile, &MASTER, 1).unwrap_err().code,
        "ProfileNotFound"
    );
    assert!(
        fixture.store().get_secret_by_source(PROJECT, PROFILE, "TOKEN", "user-local")?.is_none()
    );
    Ok(())
}

#[test]
fn import_rejects_invalid_final_line_and_rolls_back_late_tombstone()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let bad = fixture.import(&format!("TOKEN={CANARY}\nbad line\n"), false);
    let error = import_dotenv_with_master(&bad, &MASTER, 1).unwrap_err();
    assert!(!error.to_string().contains(CANARY));
    assert!(
        fixture.store().get_secret_by_source(PROJECT, PROFILE, "TOKEN", "user-local")?.is_none()
    );
    import_dotenv_with_master(&fixture.import("LAST=old\n", false), &MASTER, 1)?;
    fixture
        .store()
        .connection()
        .execute("UPDATE secrets SET state='deleted' WHERE name='LAST'", [])?;
    assert_eq!(
        import_dotenv_with_master(&fixture.import("FIRST=new\nLAST=again\n", true), &MASTER, 2)
            .unwrap_err()
            .code,
        "SecretDeleted"
    );
    assert!(
        fixture.store().get_secret_by_source(PROJECT, PROFILE, "FIRST", "user-local")?.is_none()
    );
    Ok(())
}

#[tokio::test]
async fn durable_policy_edit_uses_derived_audit_key_and_preserves_gates()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let request = fixture.policy();
    let state = fixture.state(GrantAction::ApplyPolicy).await;
    let response =
        handle_apply_policy(&envelope(crate::AgentMethod::ApplyPolicy, &request), &state, NOW)
            .await;
    assert!(matches!(response, ResponseEnvelope::Success(_)), "{response:?}");
    let text = std::fs::read_to_string(fixture.scope.project_root.join("locket.toml"))?;
    assert!(text.contains("# keep notes"));
    assert!(text.contains("# keep argv"));
    let parsed = PolicyDocument::from_toml_str(&text)?;
    assert_eq!(
        parsed.commands["dev"].command,
        CommandSpec::Argv(vec!["node".into(), "a b.js".into()])
    );
    assert!(parsed.commands["dev"].require_agent);
    assert_eq!(parsed.commands["dev"].inherit_env, ["PATH"]);
    assert_eq!(parsed.commands["dev"].external_env_sources, [locket_core::ExternalEnvSource::Ide]);
    let store = fixture.store();
    assert!(store.get_command_policy_index(PROJECT, "dev")?.is_some());
    assert!(store.verify_audit_chain_read_only(PROJECT, &AUDIT)?.hmac_ok);
    assert_eq!(state.command_policies.lock().await.len(), 1);
    Ok(())
}

#[test]
fn policy_audit_failure_leaves_source_and_index_unchanged() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new()?;
    let source = std::fs::read_to_string(fixture.scope.project_root.join("locket.toml"))?;
    fixture.store().connection().execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'fixture'); END;")?;
    assert!(apply_policy_with_master(&fixture.policy(), &MASTER, 2).is_err());
    assert_eq!(std::fs::read_to_string(fixture.scope.project_root.join("locket.toml"))?, source);
    assert!(fixture.store().get_command_policy_index(PROJECT, "dev")?.is_none());
    Ok(())
}

#[test]
fn dangerous_policy_and_overwrite_require_actual_profile_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    fixture
        .store()
        .connection()
        .execute("UPDATE profiles SET dangerous=1 WHERE id=?1", [PROFILE])?;
    assert_eq!(
        apply_policy_with_master(&fixture.policy(), &MASTER, 2).unwrap_err().code,
        "ConfirmationFailed"
    );
    let request = fixture.import("TOKEN=value\n", true);
    assert_eq!(
        import_dotenv_with_master(&request, &MASTER, 2).unwrap_err().code,
        "ConfirmationFailed"
    );
    let mut confirmed = request;
    confirmed.confirmation = Some("dev".into());
    assert_eq!(import_dotenv_with_master(&confirmed, &MASTER, 2)?.imported, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn real_passphrase_unlock_then_dispatch_import_and_policy_without_keychain()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    let fixture = Fixture::new()?;
    let passphrases = Arc::new(locket_platform::PassphraseFallbackMasterKeyStore::new(
        fixture.directory.path().join("passphrases"),
    ));
    passphrases.store_master_key(PROJECT, &MASTER, b"fixture passphrase only", 1)?;
    let state = crate::AgentSocketState::with_stores(
        "fixture",
        crate::current_process_uid(),
        Arc::new(locket_platform::MemoryMasterKeyStore::default()),
        passphrases,
    );
    let unlock = RequestEnvelope::new(
        "unlock",
        crate::AgentMethod::Unlock,
        json!({"project_id":PROJECT,"passphrase":"fixture passphrase only","ttl_seconds":60,"audit":{"store_path":fixture.scope.store_path,"profile_id":PROFILE}}),
    );
    assert!(matches!(crate::dispatch(&unlock, &state).await, ResponseEnvelope::Success(_)));
    assert_eq!(
        state
            .unlock_cache
            .lock()
            .await
            .lookup(PROJECT, crate::server::current_unix_nanos())
            .map(UnlockEntry::method),
        Some(UnlockMethod::Passphrase)
    );
    for action in [GrantAction::ImportDotenv, GrantAction::ApplyPolicy] {
        let request = crate::RequestGrantPayload {
            project_id: PROJECT.into(),
            profile_id: PROFILE.into(),
            policy_name: None,
            action,
            ttl_seconds: 30,
            binding: fixture.scope.binding.clone().unwrap(),
        };
        let ResponseEnvelope::Success(grant) =
            crate::dispatch(&envelope(crate::AgentMethod::RequestGrant, &request), &state).await
        else {
            panic!("grant failed")
        };
        let id = grant.payload["grant_id"].as_str().unwrap().to_owned();
        let request = if action == GrantAction::ImportDotenv {
            let mut request = fixture.import(&format!("TOKEN={CANARY}\n"), false);
            request.scope.grant_id = Some(id);
            envelope(crate::AgentMethod::ImportDotenv, &request)
        } else {
            let mut request = fixture.policy();
            request.scope.grant_id = Some(id);
            envelope(crate::AgentMethod::ApplyPolicy, &request)
        };
        let response = crate::dispatch(&request, &state).await;
        assert!(matches!(response, ResponseEnvelope::Success(_)), "{response:?}");
        assert!(!serde_json::to_string(&response)?.contains(CANARY));
    }
    assert!(fixture.store().verify_audit_chain_read_only(PROJECT, &AUDIT)?.hmac_ok);
    let lock = RequestEnvelope::new("lock", crate::AgentMethod::Lock, Value::Null);
    // Lock's structured payload is optional in JSON object form.
    let mut lock = lock;
    lock.payload = json!({});
    assert!(matches!(crate::dispatch(&lock, &state).await, ResponseEnvelope::Success(_)));
    assert_eq!(
        state
            .unlock_cache
            .lock()
            .await
            .lookup(PROJECT, crate::server::current_unix_nanos())
            .map(UnlockEntry::method),
        None
    );
    Ok(())
}

#[test]
fn deferred_database_commit_failure_restores_exact_original_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let source = std::fs::read_to_string(fixture.scope.project_root.join("locket.toml"))?;
    fixture.store().connection().execute_batch("CREATE TABLE parent_fixture(id INTEGER PRIMARY KEY); CREATE TABLE deferred_fixture(id INTEGER REFERENCES parent_fixture(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_commit AFTER INSERT ON audit_log BEGIN INSERT INTO deferred_fixture VALUES(42); END;")?;
    assert!(apply_policy_with_master(&fixture.policy(), &MASTER, 2).is_err());
    assert_eq!(std::fs::read_to_string(fixture.scope.project_root.join("locket.toml"))?, source);
    assert!(fixture.store().get_command_policy_index(PROJECT, "dev")?.is_none());
    assert_eq!(
        fixture
            .store()
            .connection()
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get::<_, i64>(0))?,
        0
    );
    Ok(())
}

#[test]
fn policy_rename_and_delete_change_file_index_and_audit_together()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    apply_policy_with_master(&fixture.policy(), &MASTER, 2)?;
    let mut rename = fixture.policy();
    rename.policy.name = "server".into();
    apply_policy_with_master(&rename, &MASTER, 3)?;
    assert!(fixture.store().get_command_policy_index(PROJECT, "dev")?.is_none());
    assert!(fixture.store().get_command_policy_index(PROJECT, "server")?.is_some());
    rename.mode = "delete".into();
    rename.original_name = "server".into();
    apply_policy_with_master(&rename, &MASTER, 4)?;
    assert!(fixture.store().get_command_policy_index(PROJECT, "server")?.is_none());
    let saved = std::fs::read_to_string(fixture.scope.project_root.join("locket.toml"))?;
    assert!(PolicyDocument::from_toml_str(&saved)?.commands.is_empty());
    assert!(fixture.store().verify_audit_chain_read_only(PROJECT, &AUDIT)?.hmac_ok);
    Ok(())
}

#[test]
fn overwrite_rotates_and_late_version_overflow_rolls_back_earlier_writes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    import_dotenv_with_master(&fixture.import("TOKEN=first\n", false), &MASTER, 1)?;
    let result = import_dotenv_with_master(&fixture.import("TOKEN=second\n", true), &MASTER, 2)?;
    assert_eq!(result.overwritten, 1);
    assert_eq!(
        fixture
            .store()
            .get_secret_by_source(PROJECT, PROFILE, "TOKEN", "user-local")?
            .unwrap()
            .current_version,
        2
    );
    fixture
        .store()
        .connection()
        .execute("UPDATE secrets SET current_version=?1 WHERE name='TOKEN'", [u32::MAX])?;
    assert_eq!(
        import_dotenv_with_master(&fixture.import("FIRST=new\nTOKEN=overflow\n", true), &MASTER, 3)
            .unwrap_err()
            .code,
        "SecretVersionOverflow"
    );
    assert!(
        fixture.store().get_secret_by_source(PROJECT, PROFILE, "FIRST", "user-local")?.is_none()
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn lock_waits_for_authorized_policy_commit_and_snapshot_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let state = fixture.state(GrantAction::ApplyPolicy).await;
    let snapshots = state.command_policies.lock().await;
    let request = envelope(crate::AgentMethod::ApplyPolicy, &fixture.policy());
    let writer_state = state.clone();
    let writer =
        tokio::spawn(async move { handle_apply_policy(&request, &writer_state, NOW).await });
    tokio::task::yield_now().await;
    assert!(state.unlock_cache.try_lock().is_err());
    let lock_state = state.clone();
    let mut lock = tokio::spawn(async move {
        crate::dispatch(
            &RequestEnvelope::new("lock", crate::AgentMethod::Lock, json!({})),
            &lock_state,
        )
        .await
    });
    assert!(tokio::time::timeout(Duration::from_millis(10), &mut lock).await.is_err());
    drop(snapshots);
    assert!(matches!(writer.await?, ResponseEnvelope::Success(_)));
    assert!(matches!(lock.await?, ResponseEnvelope::Success(_)));
    assert!(state.unlock_cache.lock().await.lookup(PROJECT, NOW).is_none());
    Ok(())
}

#[test]
#[cfg(unix)]
fn import_refuses_fifo_and_oversized_input_before_writes() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new()?;
    let mut request = fixture.import("TOKEN=unused\n", false);
    let fifo = fixture.scope.project_root.join("fifo");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status()?.success());
    request.env_path = fifo;
    assert_eq!(
        import_dotenv_with_master(&request, &MASTER, 1).unwrap_err().code,
        "MetadataInvalid"
    );
    request.env_path = fixture.scope.project_root.join("large.env");
    std::fs::write(&request.env_path, vec![b'x'; usize::try_from(MAX_ENV_BYTES)? + 1])?;
    assert_eq!(
        import_dotenv_with_master(&request, &MASTER, 1).unwrap_err().code,
        "MetadataInvalid"
    );
    assert_eq!(fixture.store().list_active_secrets_by_profile(PROJECT, PROFILE)?, Vec::new());
    Ok(())
}

#[tokio::test]
async fn snapshot_registration_uses_project_audit_key() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let state = fixture.state(GrantAction::ApplyPolicy).await;
    let request = crate::RegisterCommandPoliciesRequest {
        project_id: PROJECT.into(),
        policies: vec![fixture.policy().policy],
        store_path: fixture.scope.store_path.clone(),
        audit_profile_id: Some(PROFILE.into()),
    };
    let response = crate::policies::handle_register_command_policies(
        &envelope(crate::AgentMethod::RegisterCommandPolicies, &request),
        &state,
        NOW,
    )
    .await;
    assert!(matches!(response, ResponseEnvelope::Success(_)), "{response:?}");
    assert!(fixture.store().verify_audit_chain_read_only(PROJECT, &AUDIT)?.hmac_ok);
    Ok(())
}

#[tokio::test]
async fn snapshot_registration_audit_failure_does_not_publish_memory()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let state = fixture.state(GrantAction::ApplyPolicy).await;
    fixture.store().connection().execute_batch("CREATE TRIGGER fail_snapshot BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;
    let request = crate::RegisterCommandPoliciesRequest {
        project_id: PROJECT.into(),
        policies: vec![fixture.policy().policy],
        store_path: fixture.scope.store_path.clone(),
        audit_profile_id: Some(PROFILE.into()),
    };
    let response = crate::policies::handle_register_command_policies(
        &envelope(crate::AgentMethod::RegisterCommandPolicies, &request),
        &state,
        NOW,
    )
    .await;
    assert!(matches!(response, ResponseEnvelope::Error(_)));
    assert!(state.command_policies.lock().await.is_empty());
    Ok(())
}

#[test]
fn relative_import_and_policy_request_limit_are_enforced_by_real_services()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut request = fixture.import("TOKEN=relative\n", false);
    request.env_path = PathBuf::from(".env");
    assert_eq!(import_dotenv_with_master(&request, &MASTER, 1)?.imported, 1);
    let source = std::fs::read_to_string(fixture.scope.project_root.join("locket.toml"))?;
    let mut policy = fixture.policy();
    policy.policy.command_preview = "x".repeat(MAX_POLICY_BYTES);
    assert_eq!(apply_policy_with_master(&policy, &MASTER, 2).unwrap_err().code, "MetadataInvalid");
    assert_eq!(std::fs::read_to_string(fixture.scope.project_root.join("locket.toml"))?, source);
    Ok(())
}

#[test]
fn import_preserves_ignore_rules_and_reports_post_commit_maintenance_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let ignore = fixture.scope.project_root.join(".gitignore");
    std::fs::write(&ignore, "# keep notes\ncustom-rule\n")?;
    let result = import_dotenv_with_master(&fixture.import("TOKEN=one\n", false), &MASTER, 1)?;
    assert!(result.maintenance_warning.is_none());
    let contents = std::fs::read_to_string(&ignore)?;
    assert!(contents.contains("# keep notes\ncustom-rule\n"));
    assert!(contents.lines().any(|line| line == ".env"));
    std::fs::remove_file(&ignore)?;
    std::fs::create_dir(&ignore)?;
    let result = import_dotenv_with_master(&fixture.import("SECOND=two\n", false), &MASTER, 2)?;
    assert_eq!(result.imported, 1);
    assert!(result.maintenance_warning.is_some());
    assert!(
        fixture.store().get_secret_by_source(PROJECT, PROFILE, "SECOND", "user-local")?.is_some()
    );
    Ok(())
}

#[tokio::test]
async fn import_grant_scope_binding_and_expiry_fail_before_opening_env()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut request = fixture.import("TOKEN=unused\n", false);
    request.env_path = fixture.scope.project_root.join("does-not-exist");
    let state = fixture.state(GrantAction::ImportDotenv).await;
    let mut missing = request.clone();
    missing.scope.grant_id = None;
    let mut no_binding = request.clone();
    no_binding.scope.binding = None;
    let mut other_project = request.clone();
    other_project.scope.project_id = "other".into();
    let mut other_profile = request.clone();
    other_profile.scope.profile_id = "dev".into();
    let mut wrong_process = request.clone();
    wrong_process.scope.binding = Some(GrantBinding::new(std::process::id(), "forged-start"));
    for denied in [missing, no_binding, other_project, other_profile, wrong_process] {
        assert_eq!(
            code(
                handle_import_dotenv(
                    &envelope(crate::AgentMethod::ImportDotenv, &denied),
                    &state,
                    NOW
                )
                .await
            ),
            "GrantRequired"
        );
    }
    assert_eq!(
        code(
            handle_import_dotenv(
                &envelope(crate::AgentMethod::ImportDotenv, &request),
                &state,
                30_000_000_000
            )
            .await
        ),
        "GrantRequired"
    );
    assert_eq!(fixture.store().list_active_secrets_by_profile(PROJECT, PROFILE)?, Vec::new());
    Ok(())
}
