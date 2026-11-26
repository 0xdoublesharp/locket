use std::error::Error;

use sha2::{Digest, Sha256};

use crate::{
    ProfileRecord, ProjectRecord, ProjectRootRecord, ProjectSelectorResolution,
    ProjectSummaryRecord,
};

use super::{insert_project_profile_secret, open_initialized_store};

#[test]
fn project_insert_if_absent_is_idempotent() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;

    let inserted = test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    assert!(inserted);

    let inserted = test_store.store.insert_project_if_absent("lk_proj_test", "changed", 200)?;
    assert!(!inserted);

    assert_eq!(
        test_store.store.get_project("lk_proj_test")?,
        Some(ProjectRecord {
            id: "lk_proj_test".to_owned(),
            name: "test".to_owned(),
            created_at: 100,
        })
    );
    assert_eq!(test_store.store.get_project("lk_proj_missing")?, None);

    Ok(())
}

#[test]
fn delete_project_removes_team_sync_state() -> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    store.insert_project_if_absent("removed", "removed", 1)?;
    store.insert_project_if_absent("retained", "retained", 1)?;
    for id in ["removed", "retained"] {
        store.connection().execute_batch(&format!(
            "INSERT INTO team_sync_anchors VALUES ('{id}', 'team', '{{}}', 1);
             INSERT INTO team_sync_join_checkpoints VALUES ('{id}', 1);
             INSERT INTO team_sync_heads VALUES ('{id}', 1, 'digest', '[]', 'verified', 1);
             INSERT INTO team_sync_pending_packages VALUES ('{id}', 1, 'digest', x'00');
             INSERT INTO team_sync_pending_profiles VALUES ('{id}', 'profile', 'pending');
             INSERT INTO team_sync_folders(project_id, path, device_key_root)
                 VALUES ('{id}', 'folder', 'keys');
             INSERT INTO team_sync_credentials(project_id, ciphertext, nonce, updated_at)
                 VALUES ('{id}', x'00', zeroblob(24), 1);
             INSERT INTO team_sync_seen VALUES ('{id}', 'digest', 1, 'applied');
             INSERT INTO team_sync_values VALUES ('{id}', 'secret', 'digest');
             INSERT INTO team_sync_profile_epochs VALUES ('{id}', 'profile', 1);
             INSERT INTO team_sync_conflicts VALUES ('{id}', 'secret', 1, x'00');
             INSERT INTO team_sync_outbound VALUES ('{id}', 'recipient', 1, 'digest', 'digest', 1);
             INSERT INTO team_sync_publications VALUES ('{id}', '[]', '[]');
             INSERT INTO team_sync_outbox(project_id, filename, recipient, ciphertext)
                 VALUES ('{id}', 'name', 'recipient', x'00');"
        ))?;
    }
    {
        let transaction = store.connection().unchecked_transaction()?;
        assert!(store.delete_project("removed")?);
        transaction.rollback()?;
    }
    assert!(store.get_project("removed")?.is_some());
    store.connection().execute_batch(
        "CREATE TEMP TRIGGER reject_project_delete BEFORE DELETE ON projects
         BEGIN SELECT RAISE(ABORT, 'project deletion blocked'); END;",
    )?;
    assert!(store.delete_project("removed").is_err());
    let pending_profiles: i64 = store.connection().query_row(
        "SELECT count(*) FROM team_sync_pending_profiles",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(pending_profiles, 2);
    store.connection().execute_batch("DROP TRIGGER reject_project_delete")?;
    assert!(store.delete_project("removed")?);
    assert!(!store.delete_project("removed")?);
    assert!(store.get_project("retained")?.is_some());
    for table in [
        "team_sync_anchors",
        "team_sync_join_checkpoints",
        "team_sync_heads",
        "team_sync_pending_packages",
        "team_sync_pending_profiles",
        "team_sync_folders",
        "team_sync_credentials",
        "team_sync_seen",
        "team_sync_values",
        "team_sync_profile_epochs",
        "team_sync_conflicts",
        "team_sync_outbound",
        "team_sync_publications",
        "team_sync_outbox",
    ] {
        let mut statement =
            store.connection().prepare(&format!("SELECT project_id FROM {table}"))?;
        let projects = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(projects, ["retained"], "{table}");
    }
    Ok(())
}

#[test]
fn lists_ordered_projects_and_summaries_with_only_active_secrets() -> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    assert_eq!(store.list_projects()?, Vec::<ProjectRecord>::new());
    assert_eq!(store.list_project_summaries()?, Vec::<ProjectSummaryRecord>::new());

    insert_project_profile_secret(store)?;
    store.insert_project_if_absent("aa", "test", 1)?;
    store.insert_project_if_absent("zz", "alpha", 1)?;
    store.insert_profile_if_absent("new", "lk_proj_test", "aaa", true, 2)?;
    store.trust_project_root("lk_proj_test", &[0; 32], Some("/one"), 1)?;
    store.trust_project_root("lk_proj_test", &[1; 32], None, 2)?;
    store.connection().execute(
        "INSERT INTO secrets(id, project_id, profile_id, name, source, origin,
                             required, current_version, state, created_at, updated_at)
         VALUES ('deleted', 'lk_proj_test', 'new', 'DELETED', 'user-local',
                 'manual', 0, 1, 'deleted', 2, 2),
                ('also-active', 'lk_proj_test', 'new', 'DATABASE_URL', 'machine-local',
                 'manual', 0, 1, 'active', 2, 2)",
        [],
    )?;
    store.connection().execute_batch("DROP TABLE blobs; DROP TABLE fingerprints;")?;

    let projects = store.list_projects()?;
    assert_eq!(
        projects.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
        ["zz", "aa", "lk_proj_test"]
    );
    let summaries = store.list_project_summaries()?;
    assert_eq!(
        summaries.iter().map(|summary| &summary.project).collect::<Vec<_>>(),
        projects.iter().collect::<Vec<_>>()
    );
    assert_eq!(summaries[0].active_secret_count, 0);
    assert_eq!(summaries[0].profiles, Vec::<ProfileRecord>::new());
    assert_eq!(summaries[0].trusted_roots, Vec::<ProjectRootRecord>::new());
    let summary = &summaries[2];
    assert_eq!(summary.active_secret_count, 2);
    assert_eq!(
        summary.profiles.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
        ["aaa", "default"]
    );
    assert!(summary.profiles[0].dangerous);
    assert_eq!(summary.trusted_roots.len(), 2);
    assert_eq!(summary.trusted_roots[0].display_path.as_deref(), Some("/one"));
    assert_eq!(summary.trusted_roots[1].display_path, None);
    Ok(())
}

#[test]
fn project_selector_uses_id_name_and_distinct_trusted_roots_in_order() -> Result<(), Box<dyn Error>>
{
    use ProjectSelectorResolution::{Ambiguous, Found, NotFound};

    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    store.insert_project_if_absent("a", "Shared", 1)?;
    store.insert_project_if_absent("b", "Shared", 2)?;
    store.insert_project_if_absent("Shared", "Unique", 3)?;
    store.insert_project_if_absent("c", "Tie", 4)?;
    store.insert_project_if_absent("d", "Tie", 5)?;
    let project =
        |id| store.get_project(id)?.ok_or_else(|| Box::<dyn Error>::from("project absent"));
    let (a, b, shared, c, d) =
        (project("a")?, project("b")?, project("Shared")?, project("c")?, project("d")?);

    store.trust_project_root("a", &[0; 32], Some("Unique"), 1)?;
    store.trust_project_root("a", &[1; 32], Some("Tie"), 1)?;
    store.trust_project_root("a", &[2; 32], Some("/duplicate"), 1)?;
    store.trust_project_root("a", &[3; 32], Some("/duplicate"), 1)?;
    assert_eq!(store.resolve_project_selector("Shared")?, Found(shared.clone()));
    assert_eq!(store.resolve_project_selector("Unique")?, Found(shared));
    assert_eq!(store.resolve_project_selector("Tie")?, Ambiguous(vec![c, d]));
    assert_eq!(store.resolve_project_selector("shared")?, NotFound);
    assert_eq!(store.resolve_project_selector("/duplicate")?, Found(a.clone()));
    store.trust_project_root("b", &[4; 32], Some("/duplicate"), 1)?;
    assert_eq!(store.resolve_project_selector("/duplicate")?, Ambiguous(vec![a.clone(), b]));

    let canonical = fixture.directory.path().canonicalize()?;
    let canonical_path = canonical.to_str().ok_or("non-UTF-8 fixture path")?;
    let hash: [u8; 32] = Sha256::digest(canonical_path.as_bytes()).into();
    store.trust_project_root("a", &hash, None, 1)?;
    let alternate = fixture.directory.path().join(".");
    assert_eq!(
        store.resolve_project_selector(alternate.to_str().ok_or("fixture path")?)?,
        Found(a)
    );
    Ok(())
}
