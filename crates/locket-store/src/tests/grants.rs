use std::error::Error;

use crate::DirectoryGrantRecord;

use super::open_initialized_store;

#[test]
#[allow(clippy::too_many_lines)]
fn directory_grants_are_profile_scoped_and_revocable() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_profile_if_absent("lk_prof_dev", "lk_proj_test", "dev", false, 100)?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_prod",
        "lk_proj_test",
        "prod",
        false,
        100,
    )?;

    let root_hash = [1_u8; 32];
    let directory_hash = [2_u8; 32];
    let grant = DirectoryGrantRecord {
        grant_id: "lk_dgrant_dev".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: "lk_prof_dev".to_owned(),
        root_hash,
        directory_hash,
        grant_scope: "project-root".to_owned(),
        display_path: Some("/tmp/app".to_owned()),
        granted_by: None,
        created_at: 200,
        updated_at: 200,
        revoked_at: None,
    };

    test_store.store.allow_directory_grant(&grant)?;
    assert_eq!(
        test_store.store.get_directory_grant(
            "lk_proj_test",
            "lk_prof_dev",
            &root_hash,
            &directory_hash,
            "project-root",
        )?,
        Some(grant.clone())
    );
    assert_eq!(
        test_store.store.get_directory_grant(
            "lk_proj_test",
            "lk_prof_prod",
            &root_hash,
            &directory_hash,
            "project-root",
        )?,
        None
    );

    let mut refreshed = grant;
    refreshed.display_path = Some("/tmp/app-renamed".to_owned());
    refreshed.updated_at = 300;
    test_store.store.allow_directory_grant(&refreshed)?;
    let refreshed_row = test_store
        .store
        .get_directory_grant(
            "lk_proj_test",
            "lk_prof_dev",
            &root_hash,
            &directory_hash,
            "project-root",
        )?
        .ok_or("grant should exist")?;
    assert_eq!(refreshed_row.created_at, 200);
    assert_eq!(refreshed_row.updated_at, 300);
    assert_eq!(refreshed_row.display_path.as_deref(), Some("/tmp/app-renamed"));
    assert_eq!(refreshed_row.revoked_at, None);

    assert!(test_store.store.deny_directory_grant(
        "lk_proj_test",
        "lk_prof_dev",
        &root_hash,
        &directory_hash,
        "project-root",
        400,
    )?);

    // Soft-revoke leaves exactly one row in the table with revoked_at set.
    let row_count: i64 = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM directory_grants WHERE grant_id = ?1",
        ["lk_dgrant_dev"],
        |row| row.get(0),
    )?;
    assert_eq!(row_count, 1, "deny must soft-revoke, not hard-delete");

    let revoked_at: Option<i64> = test_store.store.connection().query_row(
        "SELECT revoked_at FROM directory_grants WHERE grant_id = ?1",
        ["lk_dgrant_dev"],
        |row| row.get(0),
    )?;
    assert_eq!(revoked_at, Some(400));

    // Active lookup returns None.
    assert_eq!(
        test_store.store.get_directory_grant(
            "lk_proj_test",
            "lk_prof_dev",
            &root_hash,
            &directory_hash,
            "project-root",
        )?,
        None
    );

    // get_*_any_state still surfaces the prior row for audit emission.
    let prior = test_store
        .store
        .get_directory_grant_any_state(
            "lk_proj_test",
            "lk_prof_dev",
            &root_hash,
            &directory_hash,
            "project-root",
        )?
        .ok_or("revoked grant should be visible to audit emission")?;
    assert_eq!(prior.revoked_at, Some(400));
    assert_eq!(prior.granted_by, None);

    // Re-deny is idempotent: returns false because no active row remains.
    assert!(!test_store.store.deny_directory_grant(
        "lk_proj_test",
        "lk_prof_dev",
        &root_hash,
        &directory_hash,
        "project-root",
        500,
    )?);

    // Subsequent allow revives the prior row by clearing revoked_at and
    // refreshing granted_by/updated_at. Documented in the commit message.
    let revived = DirectoryGrantRecord {
        grant_id: "lk_dgrant_dev".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: "lk_prof_dev".to_owned(),
        root_hash,
        directory_hash,
        grant_scope: "project-root".to_owned(),
        display_path: Some("/tmp/app".to_owned()),
        granted_by: Some("lk_member_alice".to_owned()),
        created_at: 600,
        updated_at: 600,
        revoked_at: None,
    };
    // Insert a member so the FK is satisfied for granted_by.
    test_store.store.connection().execute(
        "INSERT INTO teams(id, project_id, name, created_at, updated_at)
         VALUES ('lk_team_test', 'lk_proj_test', 'app-team', 100, 100)",
        [],
    )?;
    test_store.store.connection().execute(
        "INSERT INTO team_members(id, team_id, display_name, role, joined_at)
         VALUES ('lk_member_alice', 'lk_team_test', 'Alice', 'owner', 100)",
        [],
    )?;
    test_store.store.allow_directory_grant(&revived)?;
    let revived_row = test_store
        .store
        .get_directory_grant(
            "lk_proj_test",
            "lk_prof_dev",
            &root_hash,
            &directory_hash,
            "project-root",
        )?
        .ok_or("revived grant must be active")?;
    assert_eq!(revived_row.revoked_at, None);
    assert_eq!(revived_row.granted_by.as_deref(), Some("lk_member_alice"));

    let store = &test_store.store;
    assert_eq!(store.count_directory_grants_for_profile("lk_proj_test", "lk_prof_dev")?, 1);
    assert_eq!(store.count_directory_grants_for_profile("lk_proj_test", "lk_prof_prod")?, 0);
    assert_eq!(store.deny_all_directory_grants("other-project", 700)?, 0);
    assert_eq!(store.deny_all_directory_grants("lk_proj_test", 700)?, 1);
    assert_eq!(store.deny_all_directory_grants("lk_proj_test", 800)?, 0);
    assert_eq!(store.count_directory_grants_for_profile("lk_proj_test", "lk_prof_dev")?, 0);

    Ok(())
}

#[test]
fn directory_grants_can_be_revoked_by_root() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_profile_if_absent("lk_prof_dev", "lk_proj_test", "dev", false, 100)?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_prod",
        "lk_proj_test",
        "prod",
        false,
        100,
    )?;

    let root_hash = [1_u8; 32];
    let other_root_hash = [9_u8; 32];
    let directory_hash = [2_u8; 32];
    for (grant_id, profile_id, root_hash) in [
        ("lk_dgrant_dev", "lk_prof_dev", root_hash),
        ("lk_dgrant_prod", "lk_prof_prod", root_hash),
        ("lk_dgrant_other", "lk_prof_dev", other_root_hash),
    ] {
        test_store.store.allow_directory_grant(&DirectoryGrantRecord {
            grant_id: grant_id.to_owned(),
            project_id: "lk_proj_test".to_owned(),
            profile_id: profile_id.to_owned(),
            root_hash,
            directory_hash,
            grant_scope: "project-root".to_owned(),
            display_path: Some("/tmp/app".to_owned()),
            granted_by: None,
            created_at: 200,
            updated_at: 200,
            revoked_at: None,
        })?;
    }

    assert_eq!(
        test_store.store.deny_directory_grants_for_root("lk_proj_test", &root_hash, 300)?,
        2
    );
    // Idempotent: the rows are now revoked, so a second pass affects 0.
    assert_eq!(
        test_store.store.deny_directory_grants_for_root("lk_proj_test", &root_hash, 400)?,
        0
    );
    let active_other_root: u32 = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM directory_grants
         WHERE root_hash = ?1 AND revoked_at IS NULL",
        [other_root_hash.as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(active_other_root, 1);
    let revoked_at: Option<i64> = test_store.store.connection().query_row(
        "SELECT revoked_at FROM directory_grants WHERE grant_id = ?1",
        ["lk_dgrant_dev"],
        |row| row.get(0),
    )?;
    assert_eq!(revoked_at, Some(300));

    Ok(())
}
