use std::error::Error;

use serde_json::json;

use super::{insert_project_profile, open_initialized_store};

#[test]
fn command_policy_index_upserts_and_deletes_metadata_only_rows() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    test_store.store.upsert_command_policy_index(
        "lk_proj_test",
        "dev",
        &json!({ "argv": ["pnpm", "dev"] }),
        &json!({
            "name": "dev",
            "command": { "type": "argv", "argv": ["pnpm", "dev"] },
            "required_secrets": [],
        }),
        100,
        None,
    )?;
    test_store.store.upsert_command_policy_index(
        "lk_proj_test",
        "dev",
        &json!({ "argv": ["pnpm", "dev"], "required_secrets": ["DATABASE_URL"] }),
        &json!({
            "name": "dev",
            "command": { "type": "argv", "argv": ["pnpm", "dev"] },
            "required_secrets": ["DATABASE_URL"],
        }),
        200,
        None,
    )?;

    let row = test_store
        .store
        .get_command_policy_index("lk_proj_test", "dev")?
        .ok_or("missing command policy index row")?;
    assert_eq!(row.created_at, 100);
    assert_eq!(row.updated_at, 200);
    assert_eq!(row.policy_json["required_secrets"], json!(["DATABASE_URL"]));
    assert_eq!(row.normalized_json["required_secrets"], json!(["DATABASE_URL"]));

    assert!(test_store.store.delete_command_policy_index("lk_proj_test", "dev", None)?);
    assert!(test_store.store.get_command_policy_index("lk_proj_test", "dev")?.is_none());
    assert!(!test_store.store.delete_command_policy_index("lk_proj_test", "dev", None)?);
    Ok(())
}

#[test]
fn command_policy_reads_fail_on_corrupt_json_in_either_column() -> Result<(), Box<dyn Error>> {
    let mut fixture = open_initialized_store()?;
    let store = &mut fixture.store;
    insert_project_profile(store)?;
    store.upsert_command_policy_index("lk_proj_test", "dev", &json!({}), &json!({}), 100, None)?;

    // Simulate on-disk corruption in the temporary database.
    store.connection().execute_batch("PRAGMA ignore_check_constraints = ON")?;
    for (policy, normalized, column) in [("{", "{}", 2), ("{}", "{", 3)] {
        store.connection().execute(
            "UPDATE command_policies SET policy_json = ?1, normalized_json = ?2",
            (policy, normalized),
        )?;
        assert!(matches!(
            store.get_command_policy_index("lk_proj_test", "dev"),
            Err(crate::StoreError::Sqlite(rusqlite::Error::FromSqlConversionFailure(
                index, rusqlite::types::Type::Text, _
            ))) if index == column
        ));
    }
    store.connection().execute_batch("PRAGMA ignore_check_constraints = OFF")?;
    Ok(())
}
