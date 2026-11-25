use std::error::Error;

use serde_json::json;

use crate::{AuditContext, AuditWrite, StoreError};

use super::{insert_project_profile, open_initialized_store, test_device};

#[test]
fn stores_lists_and_revokes_devices() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let device = test_device();

    test_store.store.insert_device(&device)?;

    assert_eq!(test_store.store.get_active_local_device("lk_proj_test")?, Some(device.clone()));
    assert_eq!(test_store.store.find_device("lk_proj_test", "work-laptop")?, Some(device.clone()));
    assert_eq!(test_store.store.find_device("lk_proj_test", &device.fingerprint)?, Some(device));

    assert!(test_store.store.revoke_device("lk_proj_test", "lk_dev_test", 200)?);
    assert!(test_store.store.get_active_local_device("lk_proj_test")?.is_none());
    assert_eq!(test_store.store.list_devices("lk_proj_test", false)?.len(), 0);
    let all = test_store.store.list_devices("lk_proj_test", true)?;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].revoked_at, Some(200));
    Ok(())
}

#[test]
fn devices_allow_name_and_fingerprint_reuse_after_revocation() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let device = test_device();
    test_store.store.insert_device(&device)?;

    let mut duplicate = device;
    duplicate.id = "lk_dev_duplicate".to_owned();
    assert!(
        test_store.store.insert_device(&duplicate).is_err(),
        "active duplicate name/fingerprint must be rejected"
    );

    assert!(test_store.store.revoke_device("lk_proj_test", "lk_dev_test", 200)?);
    test_store.store.insert_device(&duplicate)?;

    let active = test_store.store.list_devices("lk_proj_test", false)?;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, "lk_dev_duplicate");
    Ok(())
}

#[test]
fn replace_local_device_rolls_back_when_audit_append_fails() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let device = test_device();
    test_store.store.insert_device(&device)?;

    let mut replacement = test_device();
    replacement.id = "lk_dev_replacement".to_owned();
    replacement.name = "replacement-laptop".to_owned();
    replacement.fingerprint = "cd".repeat(32);
    replacement.created_at = 300;
    replacement.last_seen_at = Some(300);

    let revoke_metadata = json!({
        "schema_version": 1,
        "action": "DEVICE_REVOKE",
        "status": "SUCCESS",
        "command": "device init --force",
        "device_id": device.id,
        "device_name": device.name,
        "fingerprint": device.fingerprint,
        "local": device.local,
    });
    let invalid_add_metadata = json!({
        "schema_version": 1,
        "action": "DEVICE_ADD",
        "status": "SUCCESS",
        "command": "device init --force",
        "device_id": replacement.id,
        "device_name": replacement.name,
        "local": replacement.local,
    });
    let revoke_audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: None,
        action: "DEVICE_REVOKE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("device init --force"),
        metadata_json: &revoke_metadata,
        timestamp: 300,
    };
    let add_audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: None,
        action: "DEVICE_ADD",
        status: "SUCCESS",
        secret_name: None,
        command: Some("device init --force"),
        metadata_json: &invalid_add_metadata,
        timestamp: 300,
    };
    let result = test_store.store.replace_local_device(
        "lk_proj_test",
        "lk_dev_test",
        300,
        &replacement,
        Some(AuditContext { key: &[42; 32], write: &revoke_audit }),
        Some(AuditContext { key: &[42; 32], write: &add_audit }),
    );

    assert!(matches!(result, Err(StoreError::AuditMetadataInvalid { .. })));
    assert_eq!(test_store.store.get_active_local_device("lk_proj_test")?, Some(device));
    assert!(test_store.store.find_device("lk_proj_test", "lk_dev_replacement")?.is_none());
    let audit_count: i64 = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action IN ('DEVICE_ADD', 'DEVICE_REVOKE')",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(audit_count, 0);
    Ok(())
}

#[test]
fn bundle_recipient_rejects_revoked_and_removed_devices() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    let device = test_device();
    test.store.insert_device(&device)?;
    assert!(!test.store.bundle_recipient_is_denied("lk_proj_test", &[2; 32])?);
    test.store.revoke_device("lk_proj_test", &device.id, 200)?;
    assert!(test.store.bundle_recipient_is_denied("lk_proj_test", &[2; 32])?);
    Ok(())
}

#[test]
fn absent_device_is_not_replaced_and_corrupt_safety_words_fail_reads() -> Result<(), Box<dyn Error>>
{
    let mut fixture = open_initialized_store()?;
    let store = &mut fixture.store;
    insert_project_profile(store)?;
    let device = test_device();
    assert!(!store.replace_local_device("lk_proj_test", "missing", 100, &device, None, None)?);
    assert!(store.get_active_local_device("lk_proj_test")?.is_none());

    store.insert_device(&device)?;
    store.connection().execute("UPDATE devices SET safety_words_json = '[1]'", [])?;
    assert!(matches!(
        store.get_active_local_device("lk_proj_test"),
        Err(StoreError::Sqlite(rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Text,
            _
        )))
    ));
    Ok(())
}
