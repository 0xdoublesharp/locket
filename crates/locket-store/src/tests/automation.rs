use std::error::Error;

use crate::{
    AutomationClientNonceRecord, AutomationClientPrivateKeyRefRecord, AutomationClientRecord,
};

use super::open_initialized_store;

#[test]
fn automation_clients_store_public_metadata_and_revocation() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    let client = AutomationClientRecord {
        id: "lk_client_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        name: "ci".to_owned(),
        public_key: vec![7; 32],
        fingerprint: "6b86b273ff34fce1".to_owned(),
        storage: "external".to_owned(),
        allowed_actions: vec!["run-policy".to_owned(), "redact".to_owned()],
        allowed_policies: vec!["test".to_owned()],
        created_at: 200,
        last_used_at: None,
        revoked_at: None,
    };

    test_store.store.insert_automation_client(&client)?;
    let clients = test_store.store.list_automation_clients("lk_proj_test", false)?;
    assert_eq!(clients, vec![client]);
    let by_name = test_store
        .store
        .get_automation_client("lk_proj_test", "ci")?
        .ok_or("client should exist")?;
    assert_eq!(by_name.id, "lk_client_test");

    assert!(test_store.store.revoke_automation_client("lk_proj_test", "lk_client_test", 300)?);
    assert_eq!(test_store.store.list_automation_clients("lk_proj_test", false)?.len(), 0);
    let revoked = test_store.store.list_automation_clients("lk_proj_test", true)?;
    assert_eq!(revoked[0].revoked_at, Some(300));
    assert!(!test_store.store.revoke_automation_client("lk_proj_test", "lk_client_test", 400)?);
    Ok(())
}

#[test]
fn automation_client_nonces_are_unique_and_prunable() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_automation_client(&AutomationClientRecord {
        id: "lk_client_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        name: "ci".to_owned(),
        public_key: vec![7; 32],
        fingerprint: "fingerprint".to_owned(),
        storage: "external".to_owned(),
        allowed_actions: vec!["run-policy".to_owned()],
        allowed_policies: vec!["test".to_owned()],
        created_at: 200,
        last_used_at: None,
        revoked_at: None,
    })?;
    let nonce = AutomationClientNonceRecord {
        client_id: "lk_client_test".to_owned(),
        nonce: [9; 24],
        request_timestamp: 210,
        seen_at: 220,
        expires_at: 230,
    };

    test_store.store.insert_automation_client_nonce(&nonce)?;
    assert!(test_store.store.insert_automation_client_nonce(&nonce).is_err());
    assert_eq!(test_store.store.prune_automation_client_nonces(229)?, 0);
    assert_eq!(test_store.store.prune_automation_client_nonces(230)?, 1);
    Ok(())
}

#[test]
fn automation_client_auth_nonce_recording_prunes_expired_rows() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_automation_client(&AutomationClientRecord {
        id: "lk_client_auth".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        name: "auth-ci".to_owned(),
        public_key: vec![7; 32],
        fingerprint: "auth-fingerprint".to_owned(),
        storage: "external".to_owned(),
        allowed_actions: vec!["run-policy".to_owned()],
        allowed_policies: vec!["test".to_owned()],
        created_at: 200,
        last_used_at: None,
        revoked_at: None,
    })?;
    test_store.store.insert_automation_client_nonce(&AutomationClientNonceRecord {
        client_id: "lk_client_auth".to_owned(),
        nonce: [1; 24],
        request_timestamp: 100,
        seen_at: 110,
        expires_at: 150,
    })?;
    test_store.store.insert_automation_client_nonce(&AutomationClientNonceRecord {
        client_id: "lk_client_auth".to_owned(),
        nonce: [2; 24],
        request_timestamp: 180,
        seen_at: 190,
        expires_at: 300,
    })?;
    let accepted = AutomationClientNonceRecord {
        client_id: "lk_client_auth".to_owned(),
        nonce: [3; 24],
        request_timestamp: 220,
        seen_at: 230,
        expires_at: 820,
    };

    test_store.store.record_automation_client_auth_nonce(&accepted, 200)?;

    let rows: Vec<Vec<u8>> = {
        let mut statement = test_store.store.connection().prepare(
            "SELECT nonce FROM automation_client_nonces
             WHERE client_id = 'lk_client_auth'
             ORDER BY nonce",
        )?;
        statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?.collect::<Result<Vec<_>, _>>()?
    };
    assert_eq!(rows, vec![vec![2; 24], vec![3; 24]]);
    Ok(())
}

#[test]
fn automation_client_auth_nonce_replay_keeps_existing_rows_atomic() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_automation_client(&AutomationClientRecord {
        id: "lk_client_auth".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        name: "auth-ci".to_owned(),
        public_key: vec![7; 32],
        fingerprint: "auth-fingerprint".to_owned(),
        storage: "external".to_owned(),
        allowed_actions: vec!["run-policy".to_owned()],
        allowed_policies: vec!["test".to_owned()],
        created_at: 200,
        last_used_at: None,
        revoked_at: None,
    })?;
    test_store.store.insert_automation_client_nonce(&AutomationClientNonceRecord {
        client_id: "lk_client_auth".to_owned(),
        nonce: [1; 24],
        request_timestamp: 100,
        seen_at: 110,
        expires_at: 150,
    })?;
    let replayed = AutomationClientNonceRecord {
        client_id: "lk_client_auth".to_owned(),
        nonce: [2; 24],
        request_timestamp: 180,
        seen_at: 190,
        expires_at: 300,
    };
    test_store.store.insert_automation_client_nonce(&replayed)?;

    assert!(test_store.store.record_automation_client_auth_nonce(&replayed, 200).is_err());

    let count: i64 = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM automation_client_nonces WHERE client_id = 'lk_client_auth'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2, "failed replay insert must not partially prune rows");
    Ok(())
}

#[test]
fn automation_client_private_key_refs_are_metadata_only() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_automation_client(&AutomationClientRecord {
        id: "lk_client_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        name: "ci".to_owned(),
        public_key: vec![7; 32],
        fingerprint: "fingerprint".to_owned(),
        storage: "os-keychain".to_owned(),
        allowed_actions: vec!["run-policy".to_owned()],
        allowed_policies: vec!["test".to_owned()],
        created_at: 200,
        last_used_at: None,
        revoked_at: None,
    })?;
    let reference = AutomationClientPrivateKeyRefRecord {
        client_id: "lk_client_test".to_owned(),
        storage: "os-keychain".to_owned(),
        keychain_service: Some("dev.0xdoublesharp.locket".to_owned()),
        keychain_account: Some("automation-client:lk_client_test".to_owned()),
        local_path_hash: None,
        metadata_json: r#"{"schema_version":1,"storage":"os-keychain"}"#.to_owned(),
        created_at: 210,
        updated_at: 210,
    };

    test_store.store.upsert_automation_client_private_key_ref(&reference)?;
    assert_eq!(
        test_store.store.get_automation_client_private_key_ref("lk_client_test")?,
        Some(reference)
    );

    assert!(test_store.store.delete_automation_client_private_key_ref("lk_client_test")?);
    assert!(test_store.store.get_automation_client_private_key_ref("lk_client_test")?.is_none());
    Ok(())
}

#[test]
fn automation_client_reads_reject_non_list_permissions() -> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    store.insert_automation_client(&AutomationClientRecord {
        id: "lk_client_bad_metadata".into(),
        project_id: "lk_proj_test".into(),
        name: "ci".into(),
        public_key: vec![7; 32],
        fingerprint: "fixture".into(),
        storage: "external".into(),
        allowed_actions: vec!["run-policy".into()],
        allowed_policies: vec!["test".into()],
        created_at: 200,
        last_used_at: None,
        revoked_at: None,
    })?;
    for (actions, policies, column) in [("{}", "[]", 6), ("[]", "{}", 7)] {
        store.connection().execute(
            "UPDATE automation_clients SET allowed_actions_json = ?1, allowed_policies_json = ?2",
            (actions, policies),
        )?;
        assert!(matches!(
            store.get_automation_client("lk_proj_test", "ci"),
            Err(crate::StoreError::Sqlite(rusqlite::Error::FromSqlConversionFailure(
                index, rusqlite::types::Type::Text, _
            ))) if index == column
        ));
    }
    Ok(())
}

#[test]
fn client_registration_and_authentication_roll_back_on_companion_write_failure()
-> Result<(), Box<dyn Error>> {
    use crate::{AuditWrite, StoreError};

    let mut fixture = open_initialized_store()?;
    let store = &mut fixture.store;
    store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    let client = AutomationClientRecord {
        id: "lk_client_atomic".into(),
        project_id: "lk_proj_test".into(),
        name: "ci".into(),
        public_key: vec![7; 32],
        fingerprint: "fixture".into(),
        storage: "os-keychain".into(),
        allowed_actions: vec!["run-policy".into()],
        allowed_policies: vec!["test".into()],
        created_at: 100,
        last_used_at: None,
        revoked_at: None,
    };
    let mut reference = AutomationClientPrivateKeyRefRecord {
        client_id: client.id.clone(),
        storage: "os-keychain".into(),
        keychain_service: Some("locket-test".into()),
        keychain_account: None,
        local_path_hash: None,
        metadata_json: "{}".into(),
        created_at: 100,
        updated_at: 100,
    };
    assert!(matches!(
        store.insert_automation_client_with_private_key_ref(&client, Some(&reference)),
        Err(StoreError::Sqlite(_))
    ));
    assert!(store.get_automation_client("lk_proj_test", "ci")?.is_none());
    reference.keychain_account = Some("fixture-client".into());
    store.insert_automation_client_with_private_key_ref(&client, Some(&reference))?;
    assert_eq!(store.get_automation_client_private_key_ref(&client.id)?, Some(reference));

    let nonce = AutomationClientNonceRecord {
        client_id: client.id.clone(),
        nonce: [3; 24],
        request_timestamp: 110,
        seen_at: 111,
        expires_at: 300,
    };
    let metadata = serde_json::json!({
        "schema_version": 1, "action": "CLIENT_AUTH", "status": "SUCCESS",
        "client_id": client.id, "request_id": "fixture", "auth_result": "verified",
    });
    let audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: None,
        action: "CLIENT_AUTH",
        status: "SUCCESS",
        secret_name: None,
        command: None,
        metadata_json: &metadata,
        timestamp: 111,
    };
    assert!(matches!(
        store.record_automation_client_auth_with_audit(&nonce, 111, &[], &audit),
        Err(StoreError::InvalidAuditKeyLength { .. })
    ));
    assert_eq!(store.get_automation_client("lk_proj_test", "ci")?, Some(client.clone()));
    store.record_automation_client_auth_with_audit(&nonce, 111, &[42; 32], &audit)?;
    assert_eq!(
        store.get_automation_client("lk_proj_test", "ci")?.and_then(|row| row.last_used_at),
        Some(111)
    );
    assert_eq!(store.list_recent_audit_actions("lk_proj_test", 10)?, ["CLIENT_AUTH"]);

    assert!(store.revoke_automation_client("lk_proj_test", &client.id, 112)?);
    let mut after_revoke = nonce;
    after_revoke.nonce = [4; 24];
    let result =
        store.record_automation_client_auth_with_audit(&after_revoke, 113, &[42; 32], &audit);
    assert!(
        matches!(&result, Err(StoreError::AutomationClientRevoked { client_id }) if client_id == &client.id)
    );
    assert_eq!(
        result.err().map(|err| err.locket_error()),
        Some(locket_core::LocketError::AccessDenied)
    );
    assert_eq!(store.prune_automation_client_nonces(300)?, 1);
    assert_eq!(store.list_recent_audit_actions("lk_proj_test", 10)?, ["CLIENT_AUTH"]);
    Ok(())
}
