#![allow(clippy::unwrap_used, clippy::panic, clippy::too_many_lines)]
use super::*;

#[cfg(unix)]
#[test]
fn dotenv_import_rejects_symlinked_source() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut request = fixture.import("TOKEN=value\n", false);
    let source = request.env_path.canonicalize()?;
    request.env_path = source.with_file_name(".env.link");
    std::os::unix::fs::symlink(&source, &request.env_path)?;

    assert_eq!(
        import_dotenv_with_master(&request, &MASTER, 1).unwrap_err().code,
        "MetadataInvalid"
    );
    Ok(())
}
use crate::{GrantRecord, GrantRecordFields, UnlockEntry, UnlockMethod};
use locket_crypto::{
    HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, derive_wrapping_key_v1, key_wrap_aad_v1,
    wrap_key_material_v1,
};
use std::time::Duration;

const PROJECT: &str = "lk_proj_mutation";
const SHARED_PROJECT: &str = "lk_proj_shared_mutation";
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
        Self::for_project(PROJECT, "fixture", "dev")
    }
    fn for_project(
        project: &str,
        project_name: &str,
        profile_name: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("project");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        std::fs::write(
            root.join("locket.toml"),
            format!(
                "# keep notes\nschema_version=1\nproject_id='{project}'\nname='{project_name}'\ndefault_profile='{profile_name}'\n[commands.dev]\nargv=['node','a b.js'] # keep argv\nrequire_agent=true\ninherit_env=['PATH']\nexternal_env_sources=['ide']\n"
            ),
        )?;
        let scope = MutationScope {
            store_path: dir.path().join("store.db"),
            project_root: root,
            project_id: project.into(),
            profile_id: PROFILE.into(),
            grant_id: Some("lk_grant_mutation".into()),
            binding: Some(GrantBinding::new(std::process::id(), "test-start")),
        };
        let mut store = Store::open(&scope.store_path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(project, project_name, 1)?;
        store.insert_profile_if_absent(PROFILE, project, profile_name, false, 1)?;
        store.trust_project_root(
            project,
            &Sha256::digest(scope.project_root.to_string_lossy().as_bytes()).into(),
            scope.project_root.to_str(),
            1,
        )?;
        insert_wrapped_keys(&store, project, PROFILE, &MASTER, &AUDIT)?;
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
            dry_run: false,
            link_to_shared: std::collections::BTreeMap::new(),
            promote_to_shared: std::collections::BTreeMap::new(),
        }
    }
    fn policy(&self) -> ApplyPolicyRequest {
        let parsed = PolicyDocument::from_toml_str(
            &std::fs::read_to_string(self.scope.project_root.join("locket.toml")).unwrap(),
        )
        .unwrap();
        let mut policy =
            CommandPolicySnapshot::from_policy(&self.scope.project_id, &parsed.commands["dev"], 1);
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
        unlock_fixture(&state, &self.scope.project_id, &MASTER).await;
        self.grant(&state, action).await;
        state
    }
    async fn grant(&self, state: &crate::AgentSocketState, action: GrantAction) {
        state.grants.lock().await.insert(GrantRecord::new(GrantRecordFields {
            grant_id: "lk_grant_mutation".into(),
            project_id: self.scope.project_id.clone(),
            profile_id: self.scope.profile_id.clone(),
            action,
            binding: self.scope.binding.clone().unwrap(),
            issued_at_unix_nanos: 0,
            ttl_seconds: 30,
            expires_at_unix_nanos: 30_000_000_000,
        }));
    }
    fn store(&self) -> Store {
        Store::open(&self.scope.store_path).unwrap()
    }
}
fn insert_wrapped_keys(
    store: &Store,
    project: &str,
    profile_id: &str,
    master: &KeyBytes,
    audit: &KeyBytes,
) -> Result<(), Box<dyn std::error::Error>> {
    for (purpose, profile, material) in [
        (KeyPurpose::Audit, None, audit),
        (KeyPurpose::ProfileSecret, Some(profile_id), &[8; 32]),
        (KeyPurpose::ProfileFingerprint, Some(profile_id), &[9; 32]),
    ] {
        let id = format!("lk_key_{project}_{}", purpose.as_str());
        let wrap = derive_wrapping_key_v1(master, &HkdfWrapInfo::new(project, profile, purpose))?;
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(
            project,
            &id,
            profile,
            0,
            KeyWrapPurpose::from(purpose),
        ))?;
        let wrapped = wrap_key_material_v1(&wrap, material, &aad)?;
        store.insert_key(&locket_store::KeyRecord {
            id,
            project_id: project.into(),
            profile_id: profile.map(str::to_owned),
            purpose: purpose.as_str().into(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: 1,
        })?;
    }
    Ok(())
}

async fn unlock_fixture(state: &crate::AgentSocketState, project: &str, master: &KeyBytes) {
    state.unlock_cache.lock().await.insert(
        project.into(),
        UnlockEntry::new(master.to_vec(), 0, Duration::from_secs(60), UnlockMethod::Passphrase),
    );
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
            confirm_dangerous: false,
            ttl_seconds: 30,
            binding: crate::tests::test_process_binding(),
        };
        let ResponseEnvelope::Success(grant) = crate::tests::dispatch_as_current_process(
            &envelope(crate::AgentMethod::RequestGrant, &request),
            &state,
        )
        .await
        else {
            panic!("grant failed")
        };
        let id = grant.payload["grant_id"].as_str().unwrap().to_owned();
        let request = if action == GrantAction::ImportDotenv {
            let mut request = fixture.import(&format!("TOKEN={CANARY}\n"), false);
            request.scope.grant_id = Some(id);
            request.scope.binding = Some(crate::tests::test_process_binding());
            envelope(crate::AgentMethod::ImportDotenv, &request)
        } else {
            let mut request = fixture.policy();
            request.scope.grant_id = Some(id);
            request.scope.binding = Some(crate::tests::test_process_binding());
            envelope(crate::AgentMethod::ApplyPolicy, &request)
        };
        let response = crate::tests::dispatch_as_current_process(&request, &state).await;
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
fn shared_vault_import_accepts_absolute_paths_without_editing_ignores()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::for_project(SHARED_PROJECT, "@shared", "default")?;
    let ignore = fixture.scope.project_root.join(".gitignore");
    let original = "# keep notes\n";
    std::fs::write(&ignore, original)?;
    let mut request = fixture.import("TOKEN=shared\n", false);
    request.scope.project_root = PathBuf::new();

    let result = import_dotenv_with_master(&request, &MASTER, i64::try_from(NOW)?)?;
    assert_eq!(result.imported, 1);
    assert!(result.original_preserved);
    assert!(result.maintenance_warning.is_none());
    assert_eq!(std::fs::read_to_string(&request.env_path)?, "TOKEN=shared\n");
    assert_eq!(std::fs::read_to_string(ignore)?, original);
    assert!(
        fixture
            .store()
            .get_secret_by_source(SHARED_PROJECT, PROFILE, "TOKEN", "user-local")?
            .is_some()
    );
    Ok(())
}

#[test]
fn shared_vault_import_rejects_relative_paths_even_with_a_trusted_folder()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::for_project(SHARED_PROJECT, "@shared", "default")?;
    let mut request = fixture.import("TOKEN=shared\n", false);
    request.env_path = PathBuf::from(".env");

    let failure = import_dotenv_with_master(&request, &MASTER, i64::try_from(NOW)?).unwrap_err();
    assert_eq!(failure.code, "MetadataInvalid");
    assert!(failure.message.contains("absolute env file path"));
    assert!(
        fixture
            .store()
            .get_secret_by_source(SHARED_PROJECT, PROFILE, "TOKEN", "user-local")?
            .is_none()
    );
    Ok(())
}

#[test]
fn shared_vault_policy_edit_requires_a_folder_backed_project_before_reading_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::for_project(SHARED_PROJECT, "@shared", "default")?;
    let config = fixture.scope.project_root.join("locket.toml");
    let source = std::fs::read(&config)?;
    let mut request = fixture.policy();
    for root in [PathBuf::new(), fixture.scope.project_root] {
        request.scope.project_root = root;
        let failure =
            apply_policy_with_master(&request, &[42; 32], i64::try_from(NOW)?).unwrap_err();
        assert_eq!(failure.code, "MetadataInvalid");
        assert!(failure.message.contains("project folder"));
        assert_eq!(std::fs::read(&config)?, source);
    }
    Ok(())
}

#[tokio::test]
async fn shared_vault_profile_switch_rejects_folder_config()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::for_project(SHARED_PROJECT, "@shared", "default")?;
    let state = crate::AgentSocketState::locked("test");
    let request = crate::SetActiveProfileRequest {
        config_path: fixture.scope.project_root.join("locket.toml"),
        store_path: fixture.scope.store_path,
        project_id: SHARED_PROJECT.into(),
        profile_name: "other".into(),
        confirmation: None,
        privacy_redact_names: false,
        root_hash: None,
    };
    let response = super::super::profile::handle_set_active_profile(
        &envelope(crate::AgentMethod::SetActiveProfile, &request),
        &state,
        NOW,
    )
    .await;
    assert_eq!(code(response), "MetadataInvalid");
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

fn crud_request(
    method: crate::AgentMethod,
    scope: &MutationScope,
    fields: Value,
) -> RequestEnvelope {
    let mut payload = serde_json::to_value(scope).unwrap();
    let Value::Object(fields) = fields else { panic!("expected request fields") };
    payload.as_object_mut().unwrap().extend(fields);
    RequestEnvelope::new("desktop-crud", method, payload)
}

async fn call_crud(state: &crate::AgentSocketState, request: &RequestEnvelope) -> ResponseEnvelope {
    let response = handle_desktop_crud(request.method().unwrap(), request, state, NOW).await;
    assert!(!serde_json::to_string(&response).unwrap().contains(CANARY));
    response
}

fn success(response: ResponseEnvelope) -> Value {
    match response {
        ResponseEnvelope::Success(s) => s.payload,
        ResponseEnvelope::Error(e) => panic!("unexpected CRUD error: {e:?}"),
    }
}

#[tokio::test]
async fn create_profile_initializes_wrapped_keys_and_audits_once()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let db = fixture.store();
    let state = fixture.state(GrantAction::CreateProfile).await;
    let method = crate::AgentMethod::CreateProfile;
    let config_path = fixture.scope.project_root.join("locket.toml");
    let original_config = std::fs::read(&config_path)?;
    let valid = crud_request(method, &fixture.scope, json!({"profile_name":"staging"}));
    let invalid = crud_request(method, &fixture.scope, json!({"profile_name":"/invalid"}));
    assert_eq!(code(call_crud(&state, &invalid).await), "InvalidProfileName");
    assert!(state.grants.lock().await.is_empty());
    assert_eq!(code(call_crud(&state, &valid).await), "GrantRequired");

    fixture.grant(&state, GrantAction::CreateProfile).await;
    let result = success(call_crud(&state, &valid).await);
    let profile = db.get_profile_by_name(PROJECT, "staging")?.ok_or("profile")?;
    assert_eq!(
        result,
        json!({
            "profile_id": profile.id, "profile_name": "staging", "dangerous": false, "created": true,
        })
    );
    for purpose in [KeyPurpose::ProfileSecret, KeyPurpose::ProfileFingerprint] {
        crate::keys::unwrap_profile_key_with_master(&db, PROJECT, &profile.id, &MASTER, purpose)?;
    }
    assert_eq!(std::fs::read(config_path)?, original_config);
    fixture.grant(&state, GrantAction::CreateProfile).await;
    assert_eq!(code(call_crud(&state, &valid).await), "SecretAlreadyExists");
    let audit = db.list_audit_rows_since(PROJECT, &profile.id, 0)?;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "PROFILE_CREATE");
    assert!(db.verify_audit_chain_read_only(PROJECT, &AUDIT)?.hmac_ok);
    Ok(())
}

#[tokio::test]
async fn create_profile_rejects_locked_rootless_and_rolls_back_on_audit_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let method = crate::AgentMethod::CreateProfile;
    let state = fixture.state(GrantAction::CreateProfile).await;
    let valid = crud_request(method, &fixture.scope, json!({"profile_name":"staging"}));
    state.unlock_cache.lock().await.evict(PROJECT);
    assert_eq!(code(call_crud(&state, &valid).await), "UnlockRequired");
    assert!(state.grants.lock().await.is_empty());
    unlock_fixture(&state, PROJECT, &MASTER).await;
    let mut rootless = fixture.scope.clone();
    rootless.project_root = PathBuf::new();
    fixture.grant(&state, GrantAction::CreateProfile).await;
    let request = crud_request(method, &rootless, json!({"profile_name":"staging"}));
    assert_eq!(code(call_crud(&state, &request).await), "MetadataInvalid");

    let shared = Fixture::for_project(SHARED_PROJECT, "@shared", "default")?;
    let shared_state = shared.state(GrantAction::CreateProfile).await;
    let request = crud_request(method, &shared.scope, json!({"profile_name":"staging"}));
    assert_eq!(code(call_crud(&shared_state, &request).await), "MetadataInvalid");

    let db = fixture.store();
    db.connection().execute_batch(
        "CREATE TRIGGER refuse_profile_audit BEFORE INSERT ON audit_log
         WHEN NEW.action = 'PROFILE_CREATE' BEGIN SELECT RAISE(ABORT, 'fixture'); END;",
    )?;
    fixture.grant(&state, GrantAction::CreateProfile).await;
    assert_eq!(code(call_crud(&state, &valid).await), "CorruptDb");
    assert!(db.get_profile_by_name(PROJECT, "staging")?.is_none());
    assert_eq!(
        db.connection().query_row("SELECT count(*) FROM keys", [], |row| row.get::<_, u32>(0))?,
        3
    );
    Ok(())
}

#[tokio::test]
async fn delete_secret_requires_exact_confirmation_and_one_grant_in_both_vault_types()
-> Result<(), Box<dyn std::error::Error>> {
    for (project, project_name, profile) in
        [(PROJECT, "fixture", "dev"), (SHARED_PROJECT, "@shared", "default")]
    {
        let fixture = Fixture::for_project(project, project_name, profile)?;
        let mut import = fixture.import(&format!("TOKEN={CANARY}\n"), false);
        let mut scope = fixture.scope.clone();
        if project == SHARED_PROJECT {
            scope.project_root = PathBuf::new();
            import.scope = scope.clone();
        }
        import_dotenv_with_master(&import, &MASTER, 1)?;
        let db = fixture.store();
        db.set_profile_dangerous(project, profile, true)?;
        let method = crate::AgentMethod::DeleteSecret;
        let invalid = crud_request(
            method,
            &scope,
            json!({
                "secret_name": "TOKEN", "source": "user-local", "confirmation": CANARY,
            }),
        );
        let valid = crud_request(
            method,
            &scope,
            json!({
                "secret_name": "TOKEN", "source": "user-local", "confirmation": profile,
            }),
        );
        let state = fixture.state(GrantAction::CopySecretToShared).await;
        assert_eq!(code(call_crud(&state, &valid).await), "GrantRequired");
        fixture.grant(&state, GrantAction::DeleteSecret).await;
        assert_eq!(code(call_crud(&state, &invalid).await), "ConfirmationFailed");
        assert!(db.get_active_secret(project, PROFILE, "TOKEN", "user-local")?.is_some());
        assert!(state.grants.lock().await.is_empty());
        assert_eq!(code(call_crud(&state, &valid).await), "GrantRequired");

        fixture.grant(&state, GrantAction::DeleteSecret).await;
        assert_eq!(
            success(call_crud(&state, &valid).await),
            json!({
                "secret_name": "TOKEN", "source": "user-local", "version": 1, "deleted": true,
            })
        );
        assert!(state.grants.lock().await.is_empty());
        let secret =
            db.get_secret_by_source(project, PROFILE, "TOKEN", "user-local")?.ok_or("tombstone")?;
        assert_eq!(secret.state, "deleted");
        assert!(db.get_blob(&secret.id, 1)?.is_some());
        fixture.grant(&state, GrantAction::DeleteSecret).await;
        assert_eq!(code(call_crud(&state, &valid).await), "SecretNotFound");
        let audit = db.list_audit_rows_since(project, PROFILE, 0)?;
        assert_eq!(audit.iter().filter(|row| row.action == "DELETE").count(), 1);
        assert!(db.connection().query_row(
            "SELECT NOT EXISTS (SELECT 1 FROM audit_log WHERE instr(metadata_json, ?1) > 0)",
            [CANARY],
            |row| row.get::<_, bool>(0),
        )?);
        assert!(db.verify_audit_chain_read_only(project, &AUDIT)?.hmac_ok);
    }
    Ok(())
}

#[tokio::test]
async fn copy_to_shared_requires_both_unlocks_and_rotates_only_with_explicit_overwrite()
-> Result<(), Box<dyn std::error::Error>> {
    const DEST_PROFILE: &str = "lk_prof_global_default";
    const DEST_MASTER: KeyBytes = [22; 32];
    const DEST_AUDIT: KeyBytes = [23; 32];
    let fixture = Fixture::new()?;
    let method = crate::AgentMethod::CopySecretToShared;
    let db = fixture.store();
    db.insert_project_if_absent(SHARED_PROJECT, "@shared", 1)?;
    db.insert_profile_if_absent(DEST_PROFILE, SHARED_PROJECT, "default", false, 1)?;
    insert_wrapped_keys(&db, SHARED_PROJECT, DEST_PROFILE, &DEST_MASTER, &DEST_AUDIT)?;
    import_dotenv_with_master(&fixture.import(&format!("TOKEN={CANARY}\n"), false), &MASTER, 2)?;
    db.set_profile_dangerous(PROJECT, "dev", true)?;
    let unconfirmed = crud_request(method, &fixture.scope, json!({"secret_name":"TOKEN"}));
    let create = crud_request(
        method,
        &fixture.scope,
        json!({
            "secret_name": "TOKEN", "confirmation": "dev",
        }),
    );
    let rotate = crud_request(
        method,
        &fixture.scope,
        json!({
            "secret_name": "TOKEN", "source": "user-local", "overwrite": true, "confirmation": "dev",
        }),
    );
    let state = fixture.state(GrantAction::CopySecretToShared).await;

    let locked = call_crud(&state, &create).await;
    assert!(
        matches!(locked, ResponseEnvelope::Error(e) if e.error == "UnlockRequired" && e.message.contains("unlock the Global Vault"))
    );
    assert!(state.grants.lock().await.is_empty());
    assert!(
        db.get_secret_by_source(SHARED_PROJECT, DEST_PROFILE, "TOKEN", "user-local")?.is_none()
    );
    state.unlock_cache.lock().await.evict(PROJECT);
    unlock_fixture(&state, SHARED_PROJECT, &DEST_MASTER).await;
    fixture.grant(&state, GrantAction::CopySecretToShared).await;
    let locked = call_crud(&state, &create).await;
    assert!(
        matches!(locked, ResponseEnvelope::Error(e) if e.error == "UnlockRequired" && e.message.contains("unlock the source vault"))
    );
    unlock_fixture(&state, PROJECT, &MASTER).await;
    fixture.grant(&state, GrantAction::CopySecretToShared).await;
    assert_eq!(code(call_crud(&state, &unconfirmed).await), "ConfirmationFailed");
    fixture.grant(&state, GrantAction::CopySecretToShared).await;
    assert_eq!(
        success(call_crud(&state, &create).await),
        json!({
            "target_project_id": SHARED_PROJECT, "target_profile_id": DEST_PROFILE,
            "secret_name": "TOKEN", "version": 1, "action": "create",
        })
    );
    assert!(state.grants.lock().await.is_empty());
    fixture.grant(&state, GrantAction::CopySecretToShared).await;
    assert_eq!(code(call_crud(&state, &create).await), "SecretAlreadyExists");
    db.connection().execute_batch(
        "CREATE TRIGGER refuse_source_copy_audit BEFORE INSERT ON audit_log
         WHEN NEW.action = 'SECRET_COPY' AND NEW.project_id = 'lk_proj_mutation'
         BEGIN SELECT RAISE(ABORT, 'fixture'); END;",
    )?;
    fixture.grant(&state, GrantAction::CopySecretToShared).await;
    assert_eq!(code(call_crud(&state, &rotate).await), "CorruptDb");
    let retained = db
        .get_active_secret(SHARED_PROJECT, DEST_PROFILE, "TOKEN", "user-local")?
        .ok_or("target after audit rollback")?;
    assert_eq!(retained.current_version, 1);
    assert!(db.get_secret_version(&retained.id, 2)?.is_none());
    db.connection().execute_batch("DROP TRIGGER refuse_source_copy_audit")?;
    fixture.grant(&state, GrantAction::CopySecretToShared).await;
    assert_eq!(success(call_crud(&state, &rotate).await)["action"], "rotate");
    assert!(state.grants.lock().await.is_empty());
    let target = db
        .get_active_secret(SHARED_PROJECT, DEST_PROFILE, "TOKEN", "user-local")?
        .ok_or("target")?;
    assert_eq!(target.current_version, 2);
    assert_eq!(db.get_secret_version(&target.id, 1)?.ok_or("previous")?.state, "deprecated");
    let value =
        crate::reveal::decrypt_secret(&db, SHARED_PROJECT, DEST_PROFILE, &target, 2, &DEST_MASTER)?;
    assert_eq!(value.as_str(), CANARY);
    let source = db.get_active_secret(PROJECT, PROFILE, "TOKEN", "user-local")?.ok_or("source")?;
    assert_eq!(source.current_version, 1);
    for (project, profile, audit_key) in
        [(PROJECT, PROFILE, AUDIT), (SHARED_PROJECT, DEST_PROFILE, DEST_AUDIT)]
    {
        let audit = db.list_audit_rows_since(project, profile, 0)?;
        assert_eq!(audit.iter().filter(|row| row.action == "SECRET_COPY").count(), 2);
        assert!(db.connection().query_row(
            "SELECT NOT EXISTS (SELECT 1 FROM audit_log WHERE instr(metadata_json, ?1) > 0)",
            [CANARY],
            |row| row.get::<_, bool>(0),
        )?);
        assert!(db.verify_audit_chain_read_only(project, &audit_key)?.hmac_ok);
    }
    Ok(())
}

#[tokio::test]
async fn copy_to_shared_rejects_stale_sources_and_invalid_destinations_without_writes()
-> Result<(), Box<dyn std::error::Error>> {
    const TARGET: &str = "lk_prof_global_default";
    let fixture = Fixture::new()?;
    let db = fixture.store();
    let action = GrantAction::CopySecretToShared;
    let state = fixture.state(action).await;
    let method = crate::AgentMethod::CopySecretToShared;
    let request = crud_request(method, &fixture.scope, json!({"secret_name":"TOKEN"}));
    import_dotenv_with_master(&fixture.import(&format!("TOKEN={CANARY}\n"), false), &MASTER, 2)?;
    let original = db
        .get_active_secret(PROJECT, PROFILE, "TOKEN", "user-local")?
        .ok_or("source not stored")?;
    assert_eq!(code(call_crud(&state, &request).await), "ProjectNotFound");
    db.insert_project_if_absent(SHARED_PROJECT, "@shared", 1)?;
    unlock_fixture(&state, SHARED_PROJECT, &MASTER).await;

    fixture.grant(&state, action).await;
    assert_eq!(code(call_crud(&state, &request).await), "ProfileNotFound");
    db.insert_profile_if_absent(TARGET, SHARED_PROJECT, "default", true, 1)?;
    insert_wrapped_keys(&db, SHARED_PROJECT, TARGET, &MASTER, &AUDIT)?;
    fixture.grant(&state, action).await;
    assert_eq!(code(call_crud(&state, &request).await), "ConfirmationFailed");
    db.set_profile_dangerous(SHARED_PROJECT, "default", false)?;

    let foreign = fixture.directory.path().join("different.db");
    let _foreign_store = Store::open(&foreign)?;
    let mut pinned =
        UnlockEntry::new(MASTER.to_vec(), 0, Duration::from_secs(60), UnlockMethod::Passphrase);
    pinned.store_identity = Some(crate::keys::StoreFileIdentity::capture(&foreign)?.1);
    state.unlock_cache.lock().await.insert(SHARED_PROJECT.to_owned(), pinned);
    fixture.grant(&state, action).await;
    assert_eq!(code(call_crud(&state, &request).await), "AccessDenied");
    unlock_fixture(&state, SHARED_PROJECT, &MASTER).await;

    for (field, value, expected) in [
        ("source", json!(CANARY), "InvalidReference"),
        ("source", json!("team-managed"), "SecretNotFound"),
        ("secret_name", json!("invalid name"), "InvalidSecretName"),
    ] {
        let mut request = request.clone();
        request.payload[field] = value;
        fixture.grant(&state, action).await;
        assert_eq!(code(call_crud(&state, &request).await), expected);
        assert!(state.grants.lock().await.is_empty());
    }

    db.set_secret_expiry_policy(
        &original.id,
        locket_store::SecretExpiryPolicy { expires_at: Some(5), rotate_after_days: None },
        original.updated_at,
    )?;
    fixture.grant(&state, action).await;
    assert_eq!(code(call_crud(&state, &request).await), "MetadataInvalid");
    db.set_secret_expiry_policy(
        &original.id,
        locket_store::SecretExpiryPolicy { expires_at: None, rotate_after_days: None },
        original.updated_at,
    )?;
    db.connection().execute(
        "UPDATE secret_versions SET state = 'deprecated', deprecated_at = 5 WHERE secret_id = ?1",
        [&original.id],
    )?;
    fixture.grant(&state, action).await;
    assert_eq!(code(call_crud(&state, &request).await), "SecretVersionExpired");
    db.connection().execute(
        "UPDATE secret_versions SET state = 'current', deprecated_at = NULL WHERE secret_id = ?1",
        [&original.id],
    )?;
    db.connection().execute(
        "INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at,deleted_at)
         VALUES ('target-tombstone',?1,?2,'TOKEN','user-local','manual',0,1,'deleted',1,1,1)",
        [SHARED_PROJECT, TARGET],
    )?;
    let mut overwrite = request.clone();
    overwrite.payload["overwrite"] = json!(true);
    fixture.grant(&state, action).await;
    assert_eq!(code(call_crud(&state, &overwrite).await), "SecretDeleted");
    assert_eq!(
        db.get_secret_by_source(SHARED_PROJECT, TARGET, "TOKEN", "user-local")?
            .ok_or("tombstone was lost")?
            .state,
        "deleted"
    );
    assert!(db.get_active_secret(SHARED_PROJECT, TARGET, "TOKEN", "user-local")?.is_none());
    assert_eq!(db.list_recent_audit_actions(SHARED_PROJECT, 5)?, Vec::<String>::new());
    assert_eq!(db.get_active_secret(PROJECT, PROFILE, "TOKEN", "user-local")?, Some(original));
    Ok(())
}

#[tokio::test]
async fn policy_create_rename_delete_keep_grant_snapshots_in_sync_with_durable_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let path = fixture.scope.project_root.join("locket.toml");
    let original = std::fs::read(&path)?;
    let action = GrantAction::ApplyPolicy;
    let method = crate::AgentMethod::ApplyPolicy;
    let state = fixture.state(action).await;
    let store = fixture.store();
    let mut request = fixture.policy();
    request.mode = "create".into();
    request.original_name.clear();
    assert_eq!(
        code(handle_apply_policy(&envelope(method, &request), &state, NOW).await),
        "SecretAlreadyExists"
    );
    request.mode = "edit".into();
    request.original_name = "missing".into();
    assert_eq!(
        code(handle_apply_policy(&envelope(method, &request), &state, NOW).await),
        "PolicyNotFound"
    );
    request.original_name = "dev".into();
    request.policy.optional_secrets = request.policy.required_secrets.clone();
    assert_eq!(
        code(handle_apply_policy(&envelope(method, &request), &state, NOW).await),
        "MetadataInvalid"
    );
    assert!(state.command_policies.lock().await.is_empty());
    assert_eq!(std::fs::read(&path)?, original);
    assert!(store.get_command_policy_index(PROJECT, "dev")?.is_none());

    let mut raw = String::from_utf8(original)?;
    raw = raw.replace("['ide']", "['parent', { file = '.env' }, 'compose', 'ide']");
    std::fs::write(&path, raw)?;
    request.policy.optional_secrets.clear();
    request.policy.allowed_secrets.push("SECOND_TOKEN".into());
    request.policy.command_kind = "shell".into();
    request.policy.command_preview = "printf 'fixture'".into();
    assert!(matches!(
        handle_apply_policy(&envelope(method, &request), &state, NOW).await,
        ResponseEnvelope::Success(_)
    ));
    let patched = PolicyDocument::from_toml_str(&std::fs::read_to_string(&path)?)?;
    assert_eq!(
        patched.commands["dev"].optional_secrets.iter().map(SecretName::as_str).collect::<Vec<_>>(),
        ["SECOND_TOKEN"]
    );
    assert_eq!(patched.commands["dev"].external_env_sources.len(), 4);

    request.policy.name = "renamed".into();
    assert!(matches!(
        handle_apply_policy(&envelope(method, &request), &state, NOW + 1).await,
        ResponseEnvelope::Success(_)
    ));
    let snapshots = state.command_policies.lock().await;
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].name, "renamed");
    assert_eq!(snapshots[0].command_kind, "shell");
    drop(snapshots);
    assert!(store.get_command_policy_index(PROJECT, "dev")?.is_none());
    assert!(store.get_command_policy_index(PROJECT, "renamed")?.is_some());

    request.mode = "delete".into();
    request.original_name.clear();
    assert!(matches!(
        handle_apply_policy(&envelope(method, &request), &state, NOW + 2).await,
        ResponseEnvelope::Success(_)
    ));
    assert!(state.command_policies.lock().await.is_empty());
    assert!(store.get_command_policy_index(PROJECT, "renamed")?.is_none());
    assert!(PolicyDocument::from_toml_str(&std::fs::read_to_string(path)?)?.commands.is_empty());
    assert_eq!(store.list_recent_audit_actions(PROJECT, 10)?, vec!["POLICY_UPDATE"; 3]);
    assert!(store.verify_audit_chain_read_only(PROJECT, &AUDIT)?.hmac_ok);
    Ok(())
}

#[test]
fn dotenv_no_overwrite_keeps_prior_ciphertext_and_only_audits_new_names()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    import_dotenv_with_master(&fixture.import(&format!("TOKEN={CANARY}\n"), false), &MASTER, 1)?;
    let store = fixture.store();
    let original = store
        .get_active_secret(PROJECT, PROFILE, "TOKEN", "user-local")?
        .ok_or("original source missing")?;
    let blob = store.get_blob(&original.id, 1)?.ok_or("original ciphertext missing")?;
    let import = fixture.import("TOKEN=unexpected\nNEW_TOKEN=new\n", false);
    let applied = import_dotenv_with_master(&import, &MASTER, 2)?;
    assert_eq!((applied.imported, applied.skipped, applied.overwritten), (1, 1, 0));
    assert_eq!(store.get_active_secret(PROJECT, PROFILE, "TOKEN", "user-local")?, Some(original));
    assert_eq!(store.get_blob(&blob.secret_id, 1)?, Some(blob));
    let rows = store.list_audit_rows_since(PROJECT, PROFILE, 0)?;
    assert!(rows.iter().all(|row| row.action == "IMPORT"));
    let names: Vec<_> = rows.iter().filter_map(|row| row.secret_name.as_deref()).collect();
    assert_eq!(names, ["TOKEN", "NEW_TOKEN"]);
    assert!(store.verify_audit_chain_read_only(PROJECT, &AUDIT)?.hmac_ok);
    Ok(())
}

#[tokio::test]
async fn promote_links_under_alias_detects_import_duplicates_and_warns_before_shared_delete()
-> Result<(), Box<dyn std::error::Error>> {
    const DEST_PROFILE: &str = "lk_prof_global_default";
    const DEST_MASTER: KeyBytes = [22; 32];
    const DEST_AUDIT: KeyBytes = [23; 32];
    let fixture = Fixture::new()?;
    let db = fixture.store();
    db.insert_project_if_absent(SHARED_PROJECT, "@shared", 1)?;
    db.insert_profile_if_absent(DEST_PROFILE, SHARED_PROJECT, "default", false, 1)?;
    insert_wrapped_keys(&db, SHARED_PROJECT, DEST_PROFILE, &DEST_MASTER, &DEST_AUDIT)?;
    let state = fixture.state(GrantAction::ImportDotenv).await;
    unlock_fixture(&state, SHARED_PROJECT, &DEST_MASTER).await;

    // Import RPC_URL into project with @shared unlocked so local dedup tag is recorded.
    let rpc_url = "https://eth-mainnet.example.invalid/v2/shared-rpc-canary";
    let import_req = fixture.import(&format!("RPC_URL={rpc_url}\n"), false);
    assert!(matches!(
        handle_import_dotenv(&envelope(crate::AgentMethod::ImportDotenv, &import_req), &state, NOW)
            .await,
        ResponseEnvelope::Success(_)
    ));

    // Promote RPC_URL -> @shared/ALCHEMY_MAINNET_RPC with replace_with_link=true.
    fixture.grant(&state, GrantAction::CopySecretToShared).await;
    let promote = crud_request(
        crate::AgentMethod::CopySecretToShared,
        &fixture.scope,
        json!({
            "secret_name": "RPC_URL",
            "target_name": "ALCHEMY_MAINNET_RPC",
            "replace_with_link": true,
        }),
    );
    let promoted = success(call_crud(&state, &promote).await);
    assert_eq!(promoted["secret_name"], "ALCHEMY_MAINNET_RPC");
    assert_eq!(promoted["linked"], true);

    // Project local user-local copy is tombstoned and replaced by active shared-link.
    let store = fixture.store();
    assert!(store.get_active_secret(PROJECT, PROFILE, "RPC_URL", "user-local")?.is_none());
    let list_rows = store.list_active_secret_metadata_by_profile(PROJECT, PROFILE)?;
    assert_eq!(list_rows.len(), 1);
    assert_eq!(list_rows[0].name, "RPC_URL");
    assert_eq!(list_rows[0].source, "shared-link");
    assert_eq!(list_rows[0].linked_target_name.as_deref(), Some("ALCHEMY_MAINNET_RPC"));

    // Reveal through the project follows the live link to @shared.
    fixture.grant(&state, GrantAction::Reveal).await;
    let reveal_req = RequestEnvelope::new(
        "rev-link",
        crate::AgentMethod::Reveal,
        json!({
            "store_path": fixture.scope.store_path,
            "project_id": PROJECT,
            "profile_id": PROFILE,
            "secret_name": "RPC_URL",
            "grant_id": fixture.scope.grant_id,
            "binding": fixture.scope.binding,
        }),
    );
    let revealed = success(crate::reveal::handle_reveal(&reveal_req, &state, NOW).await);
    assert_eq!(revealed["value"], rpc_url);

    // Dry-run import of the same URL under a different variable name flags the @shared match.
    fixture.grant(&state, GrantAction::ImportDotenv).await;
    let mut preview = fixture.import(&format!("MAINNET_RPC_URL={rpc_url}\n"), false);
    preview.dry_run = true;
    let preview_res = success(
        handle_import_dotenv(&envelope(crate::AgentMethod::ImportDotenv, &preview), &state, NOW)
            .await,
    );
    let matches = preview_res["duplicate_matches"].as_array().ok_or("no matches")?;
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["local_name"], "MAINNET_RPC_URL");
    assert_eq!(matches[0]["match_kind"], "shared");
    assert_eq!(matches[0]["matched_secret_name"], "ALCHEMY_MAINNET_RPC");

    // Deleting @shared/ALCHEMY_MAINNET_RPC without unlink_all fails with LinkedSecretInUse.
    let shared_secret = store
        .get_active_secret(SHARED_PROJECT, DEST_PROFILE, "ALCHEMY_MAINNET_RPC", "user-local")?
        .ok_or("shared secret missing")?;
    assert_eq!(store.list_shared_secret_usages(&shared_secret.id)?.len(), 1);
    let shared_scope = MutationScope {
        store_path: fixture.scope.store_path.clone(),
        project_root: PathBuf::new(),
        project_id: SHARED_PROJECT.into(),
        profile_id: DEST_PROFILE.into(),
        grant_id: fixture.scope.grant_id.clone(),
        binding: fixture.scope.binding.clone(),
    };
    let mut shared_fixture = Fixture { directory: fixture.directory, scope: shared_scope.clone() };
    shared_fixture.grant(&state, GrantAction::DeleteSecret).await;
    let blocked_req = crud_request(
        crate::AgentMethod::DeleteSecret,
        &shared_scope,
        json!({ "secret_name": "ALCHEMY_MAINNET_RPC", "source": "user-local" }),
    );
    assert_eq!(code(call_crud(&state, &blocked_req).await), "LinkedSecretInUse");

    // Deleting with unlink_all=true atomically tombstones @shared and removes all links.
    shared_fixture.grant(&state, GrantAction::DeleteSecret).await;
    let allow_req = crud_request(
        crate::AgentMethod::DeleteSecret,
        &shared_scope,
        json!({ "secret_name": "ALCHEMY_MAINNET_RPC", "source": "user-local", "unlink_all": true }),
    );
    let deleted = success(call_crud(&state, &allow_req).await);
    assert_eq!(deleted["unlinked_count"], 1);
    assert_eq!(store.list_active_secret_metadata_by_profile(PROJECT, PROFILE)?.len(), 0);
    let _ = &mut shared_fixture;
    Ok(())
}
