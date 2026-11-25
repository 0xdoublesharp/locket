use std::error::Error;

use serde_json::Value;

use crate::{ProfileDangerousAudit, ProfileRecord};

use super::open_initialized_store;

#[test]
fn profile_insert_if_absent_handles_duplicate_id_and_name() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;

    let inserted = test_store.store.insert_profile_if_absent(
        "lk_prof_default",
        "lk_proj_test",
        "default",
        false,
        200,
    )?;
    assert!(inserted);

    let inserted = test_store.store.insert_profile_if_absent(
        "lk_prof_default",
        "lk_proj_test",
        "other",
        true,
        300,
    )?;
    assert!(!inserted);

    let inserted = test_store.store.insert_profile_if_absent(
        "lk_prof_duplicate_name",
        "lk_proj_test",
        "default",
        true,
        400,
    )?;
    assert!(!inserted);

    assert_eq!(
        test_store.store.get_profile_by_name("lk_proj_test", "default")?,
        Some(ProfileRecord {
            id: "lk_prof_default".to_owned(),
            project_id: "lk_proj_test".to_owned(),
            name: "default".to_owned(),
            dangerous: false,
            created_at: 200,
        })
    );
    assert_eq!(test_store.store.get_profile_by_name("lk_proj_test", "missing")?, None);

    Ok(())
}

#[test]
fn list_profiles_orders_by_name() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_project_if_absent("lk_proj_other", "other", 100)?;

    test_store.store.insert_profile_if_absent("lk_prof_zed", "lk_proj_test", "zed", false, 300)?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_alpha",
        "lk_proj_test",
        "alpha",
        true,
        100,
    )?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_middle",
        "lk_proj_test",
        "middle",
        false,
        200,
    )?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_other",
        "lk_proj_other",
        "aardvark",
        false,
        100,
    )?;

    let profiles = test_store.store.list_profiles("lk_proj_test")?;
    let names = profiles.iter().map(|profile| profile.name.as_str()).collect::<Vec<_>>();
    assert_eq!(names, ["alpha", "middle", "zed"]);
    assert_eq!(profiles[0].id, "lk_prof_alpha");
    assert!(profiles[0].dangerous);

    Ok(())
}

#[test]
fn profile_dangerous_marker_updates() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_default",
        "lk_proj_test",
        "default",
        false,
        200,
    )?;

    assert!(test_store.store.set_profile_dangerous("lk_proj_test", "default", true)?);
    assert!(
        test_store
            .store
            .get_profile_by_name("lk_proj_test", "default")?
            .ok_or("profile should exist")?
            .dangerous
    );

    assert!(test_store.store.set_profile_dangerous("lk_proj_test", "default", false)?);
    assert!(
        !test_store
            .store
            .get_profile_by_name("lk_proj_test", "default")?
            .ok_or("profile should exist")?
            .dangerous
    );
    assert!(!test_store.store.set_profile_dangerous("lk_proj_test", "missing", true)?);

    Ok(())
}

#[test]
fn profile_dangerous_marker_update_audits_in_same_transaction() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_default",
        "lk_proj_test",
        "default",
        false,
        200,
    )?;

    assert_eq!(
        test_store.store.set_profile_dangerous_with_audit(
            "lk_proj_test",
            "missing",
            true,
            ProfileDangerousAudit { audit_key: &[42; 32], timestamp: 250, command: "agent config" },
        )?,
        None
    );
    assert_eq!(
        test_store.store.list_recent_audit_actions("lk_proj_test", 10)?,
        Vec::<String>::new()
    );

    let change = test_store
        .store
        .set_profile_dangerous_with_audit(
            "lk_proj_test",
            "default",
            true,
            ProfileDangerousAudit { audit_key: &[42; 32], timestamp: 300, command: "agent config" },
        )?
        .ok_or("profile should exist")?;

    assert!(!change.prior_dangerous);
    assert!(change.new_dangerous);
    assert!(
        test_store
            .store
            .get_profile_by_name("lk_proj_test", "default")?
            .ok_or("profile should exist")?
            .dangerous
    );
    assert_eq!(test_store.store.list_recent_audit_actions("lk_proj_test", 1)?, ["PROFILE_CHANGE"]);
    let metadata_json: String = test_store.store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get(0),
    )?;
    let metadata: Value = serde_json::from_str(&metadata_json)?;
    assert_eq!(metadata["action"], "PROFILE_CHANGE");
    assert_eq!(metadata["operation"], "set_dangerous");
    assert_eq!(metadata["profile_name"], "default");
    assert_eq!(metadata["new_dangerous"], true);

    Ok(())
}
