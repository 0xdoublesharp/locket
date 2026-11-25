use std::error::Error;

use crate::KeyRecord;

use super::{insert_project_profile, open_initialized_store};

#[test]
fn key_insert_get_by_scope_and_id() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let key = KeyRecord {
        id: "lk_key_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: Some("lk_prof_test".to_owned()),
        purpose: "profile-secret".to_owned(),
        wrapped_material: vec![1, 2, 3],
        nonce: [4; 24],
        created_at: 200,
    };
    test_store.store.insert_key(&key)?;

    let project_key = KeyRecord {
        id: "lk_key_project".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: None,
        purpose: "project-metadata".to_owned(),
        wrapped_material: vec![5, 6, 7],
        nonce: [8; 24],
        created_at: 300,
    };
    test_store.store.insert_key(&project_key)?;

    assert_eq!(test_store.store.get_key("lk_key_test")?, Some(key.clone()));
    assert_eq!(
        test_store.store.get_key_by_scope(
            "lk_proj_test",
            Some("lk_prof_test"),
            "profile-secret"
        )?,
        Some(key)
    );
    assert_eq!(
        test_store.store.get_key_by_scope("lk_proj_test", None, "project-metadata")?,
        Some(project_key.clone())
    );
    assert_eq!(test_store.store.get_key("lk_key_project")?, Some(project_key));

    Ok(())
}

#[test]
fn key_scope_check_rejects_profile_purpose_without_profile() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.connection().execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
        [],
    )?;

    let result = test_store.store.connection().execute(
        "INSERT INTO keys(id, project_id, profile_id, purpose, wrapped_material, nonce, created_at)
         VALUES (
           'lk_key_bad', 'lk_proj_test', NULL, 'profile-secret',
           x'01', x'000000000000000000000000000000000000000000000000', 1
         )",
        [],
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn unavailable_key_table_is_a_storage_error_for_reads_and_writes() -> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    insert_project_profile(store)?;
    let key = KeyRecord {
        id: "key".into(),
        project_id: "lk_proj_test".into(),
        profile_id: Some("lk_prof_test".into()),
        purpose: "profile-secret".into(),
        wrapped_material: vec![1, 2, 3],
        nonce: [4; 24],
        created_at: 100,
    };
    store.insert_key(&key)?;
    store.connection().execute_batch("ALTER TABLE keys RENAME TO unavailable_keys")?;
    for result in [
        store.get_key(&key.id).map(|_| ()),
        store
            .get_key_by_scope(&key.project_id, key.profile_id.as_deref(), &key.purpose)
            .map(|_| ()),
        store.insert_key(&key),
    ] {
        assert!(matches!(
            result,
            Err(crate::StoreError::Sqlite(error)) if error.to_string().contains("no such table: keys")
        ));
    }
    Ok(())
}
