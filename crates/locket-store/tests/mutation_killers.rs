//! Durable consent counts and revocation through the public store.
#![allow(unused_crate_dependencies, clippy::multiple_crate_versions)]

use locket_store::{DirectoryGrantRecord, Store};

#[test]
fn project_revocation_reports_every_transition_and_preserves_unrelated_consent()
-> Result<(), Box<dyn std::error::Error>> {
    let mut store = Store::open(":memory:")?;
    store.initialize_schema()?;
    for (project, profile) in [("project-a", "profile-a"), ("project-b", "profile-b")] {
        store.insert_project_if_absent(project, project, 100)?;
        store.insert_profile_if_absent(profile, project, "dev", false, 100)?;
    }
    let root = [1; 32];
    let first = [2; 32];
    let second = [3; 32];
    for (grant, project, profile, directory_hash) in [
        ("grant-a1", "project-a", "profile-a", first),
        ("grant-a2", "project-a", "profile-a", second),
        ("grant-b1", "project-b", "profile-b", first),
    ] {
        store.allow_directory_grant(&DirectoryGrantRecord {
            grant_id: grant.into(),
            project_id: project.into(),
            profile_id: profile.into(),
            root_hash: root,
            directory_hash,
            grant_scope: "project-root".into(),
            display_path: None,
            granted_by: None,
            created_at: 200,
            updated_at: 200,
            revoked_at: None,
        })?;
    }
    assert_eq!(store.count_directory_grants_for_profile("project-a", "profile-a")?, 2);
    assert_eq!(store.deny_all_directory_grants("project-a", 300)?, 2);
    assert_eq!(store.deny_all_directory_grants("project-a", 400)?, 0);
    assert_eq!(store.count_directory_grants_for_profile("project-a", "profile-a")?, 0);
    assert_eq!(store.count_directory_grants_for_profile("project-b", "profile-b")?, 1);
    for directory_hash in [first, second] {
        let revoked = store
            .get_directory_grant_any_state(
                "project-a",
                "profile-a",
                &root,
                &directory_hash,
                "project-root",
            )?
            .ok_or("revocation should retain the audit identity")?;
        assert_eq!(revoked.revoked_at, Some(300));
        assert_eq!(revoked.updated_at, 300);
    }
    Ok(())
}
