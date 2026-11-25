use std::error::Error;

use super::{insert_project_profile, open_initialized_store, test_device, test_passkey_credential};

#[test]
fn stores_lists_finds_and_revokes_passkey_credentials() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_passkey_project_bindings(&test_store.store)?;
    let credential = test_passkey_credential();

    test_store.store.insert_passkey_credential(&credential)?;

    let listed = test_store.store.list_passkey_credentials("lk_proj_test", false)?;
    assert_eq!(listed[0].device_id, "lk_dev_test");
    assert_eq!(listed[0].member_id.as_deref(), Some("lk_member_test"));
    assert_eq!(listed[0].public_key, vec![0x42; 65]);
    assert_eq!(listed[0].user_handle, vec![0x77; 32]);
    assert_eq!(listed, vec![credential.clone()]);
    assert_eq!(
        test_store.store.find_passkey_credentials("lk_proj_test", "work-laptop")?,
        vec![credential.clone()]
    );
    assert_eq!(
        test_store.store.find_passkey_credentials("lk_proj_test", "abcdef")?,
        vec![credential.clone()]
    );
    assert_eq!(
        test_store.store.find_passkey_credentials("lk_proj_test", "0xABCD")?,
        vec![credential]
    );

    assert!(test_store.store.revoke_passkey_credential("lk_proj_test", "lk_passkey_test", 200)?);
    assert_eq!(test_store.store.list_passkey_credentials("lk_proj_test", false)?.len(), 0);
    let all = test_store.store.list_passkey_credentials("lk_proj_test", true)?;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].revoked_at, Some(200));
    Ok(())
}

#[test]
fn passkey_credentials_default_relying_party_id_when_omitted() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_passkey_project_bindings(&test_store.store)?;
    test_store.store.connection().execute(
        "INSERT INTO passkey_credentials(
           id, project_id, device_id, label, credential_id, public_key, transports_json,
           prf_capable, user_handle, created_at
         )
         VALUES (
           'lk_passkey_default_rp', 'lk_proj_test', 'lk_dev_test', 'default-rp',
           x'ABCDEF', x'01020304', '[]', 1, zeroblob(32), 100
         )",
        [],
    )?;

    let credentials = test_store.store.find_passkey_credentials("lk_proj_test", "default-rp")?;
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].webauthn_relying_party_id, crate::DEFAULT_WEBAUTHN_RELYING_PARTY_ID);
    Ok(())
}

fn insert_passkey_project_bindings(store: &crate::Store) -> Result<(), Box<dyn Error>> {
    insert_project_profile(store)?;
    store.insert_device(&test_device())?;
    store.connection().execute(
        "INSERT INTO teams(id, project_id, name, created_at, updated_at)
         VALUES ('lk_team_test', 'lk_proj_test', 'team', 1, 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO team_members(id, team_id, device_id, display_name, role, joined_at)
         VALUES ('lk_member_test', 'lk_team_test', 'lk_dev_test', 'Work Laptop', 'owner', 1)",
        [],
    )?;
    Ok(())
}

#[test]
fn active_prf_wraps_skip_revoked_and_unwrapped_credentials() -> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    insert_passkey_project_bindings(store)?;
    let credential = test_passkey_credential();
    let mut unwrapped = credential.clone();
    unwrapped.id = "lk_passkey_unwrapped".into();
    unwrapped.label = "without-wrap".into();
    unwrapped.credential_id.push(0);
    store.insert_passkey_credential(&credential)?;
    store.insert_passkey_credential(&unwrapped)?;

    let wrap = crate::PasskeyPrfWrapRecord {
        passkey_id: credential.id.clone(),
        project_id: credential.project_id.clone(),
        prf_salt: vec![1; 32],
        wrapped_master_key: vec![2; 48],
        wrap_nonce: vec![3; 24],
        created_at: 100,
    };
    store.upsert_passkey_prf_wrap(&wrap)?;
    assert_eq!(
        store.list_active_passkey_prf_wraps(&credential.project_id)?,
        [(credential.clone(), wrap.clone())]
    );
    assert!(store.revoke_passkey_credential(&credential.project_id, &credential.id, 200)?);
    assert_eq!(store.list_active_passkey_prf_wraps(&credential.project_id)?, []);
    assert_eq!(store.get_passkey_prf_wrap(&credential.project_id, &credential.id)?, Some(wrap));
    Ok(())
}

#[test]
fn passkey_listing_rejects_transport_metadata_of_the_wrong_type() -> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    insert_passkey_project_bindings(store)?;
    store.insert_passkey_credential(&test_passkey_credential())?;
    store.connection().execute("UPDATE passkey_credentials SET transports_json = '{}'", [])?;
    assert!(matches!(
        store.list_passkey_credentials("lk_proj_test", false),
        Err(crate::StoreError::Sqlite(rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Text,
            _
        )))
    ));
    Ok(())
}

#[test]
fn passkey_lookup_distinguishes_corrupt_wraps_from_absent_wraps() -> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    insert_passkey_project_bindings(store)?;
    let credential = test_passkey_credential();
    store.insert_passkey_credential(&credential)?;
    let project = credential.project_id.as_str();
    let passkey = credential.id.as_str();
    assert_eq!(store.get_passkey_prf_wrap(project, passkey)?, None);

    // SQLite's BLOB affinity permits text when the length constraint still passes.
    store.connection().execute(
        "INSERT INTO passkey_prf_wraps
         (passkey_id, project_id, prf_salt, wrapped_master_key, wrap_nonce, created_at)
         VALUES (?1, ?2, zeroblob(32), 'invalid storage type', zeroblob(24), 100)",
        (passkey, project),
    )?;
    let invalid_type = |error: crate::StoreError| {
        matches!(
            error,
            crate::StoreError::Sqlite(rusqlite::Error::InvalidColumnType(
                3, name, rusqlite::types::Type::Text
            )) if name == "wrapped_master_key"
        )
    };
    assert!(store.get_passkey_prf_wrap(project, passkey).is_err_and(invalid_type));
    assert!(store.list_active_passkey_prf_wraps(project).is_err_and(invalid_type));
    Ok(())
}

#[test]
fn passkey_lookup_uses_only_nonempty_hex_prefixes_and_literal_labels() -> Result<(), Box<dyn Error>>
{
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    insert_passkey_project_bindings(store)?;
    let mut credential = test_passkey_credential();
    credential.label = "work_%".into();
    store.insert_passkey_credential(&credential)?;
    let project = credential.project_id.as_str();

    for selector in ["%", "_", "", "0x"] {
        assert!(store.find_passkey_credentials(project, selector)?.is_empty(), "{selector:?}");
    }
    for selector in ["work_%", "0xAb", credential.id.as_str()] {
        assert_eq!(store.find_passkey_credentials(project, selector)?, [credential.clone()]);
    }
    Ok(())
}

#[test]
fn unavailable_passkey_tables_are_not_reported_as_empty_credentials_or_wraps()
-> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    insert_passkey_project_bindings(store)?;
    let credential = test_passkey_credential();
    store.insert_passkey_credential(&credential)?;
    store
        .connection()
        .execute_batch("ALTER TABLE passkey_prf_wraps RENAME TO unavailable_wraps")?;
    assert!(matches!(
        store.list_active_passkey_prf_wraps(&credential.project_id),
        Err(crate::StoreError::Sqlite(error)) if error.to_string().contains("no such table: passkey_prf_wraps")
    ));
    store
        .connection()
        .execute_batch("ALTER TABLE passkey_credentials RENAME TO unavailable_credentials")?;
    assert!(matches!(
        store.find_passkey_credentials(&credential.project_id, &credential.label),
        Err(crate::StoreError::Sqlite(error)) if error.to_string().contains("no such table: passkey_credentials")
    ));
    Ok(())
}
