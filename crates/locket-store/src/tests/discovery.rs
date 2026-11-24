use std::error::Error;

use crate::{DiscoveredSecretRecord, SecretDiscoveryFilter, Store, StoreError};

use super::open_initialized_store;

fn seed_discovery(store: &Store) -> Result<(), StoreError> {
    store.connection().execute_batch(
        r#"INSERT INTO projects(id, name, created_at)
               VALUES ('p2', 'Acme', 1), ('p1', 'Acme', 1), ('ops', 'Ops', 1);
           INSERT INTO profiles(id, project_id, name, dangerous, created_at)
               VALUES ('f1', 'p1', 'dev', 0, 1), ('f2', 'p2', 'dev', 0, 1),
                      ('f3', 'p1', 'ops', 1, 1), ('f4', 'ops', 'dev', 0, 1);
           INSERT INTO secrets(id, project_id, profile_id, name, source, origin, description,
                               owner, tags_json, required, current_version, state, created_at,
                               updated_at, last_rotated_at)
               VALUES ('team', 'p1', 'f1', 'API_KEY', 'team-managed', 'team-accept', NULL,
                       NULL, '[]', 0, 1, 'active', 1, 1, NULL),
                      ('machine', 'p1', 'f1', 'API_KEY', 'machine-local', 'manual', 'Prod %_ token',
                       'Équipe Infra', '["OnCall","quote\"tag"]', 1, 3, 'active', 1, 10, 8),
                      ('user', 'p1', 'f1', 'API_KEY', 'user-local', 'manual', NULL,
                       NULL, '[]', 0, 1, 'active', 1, 1, NULL),
                      ('alpha', 'p1', 'f1', 'ALPHA_KEY', 'user-local', 'manual', NULL,
                       NULL, '[]', 0, 1, 'active', 1, 1, NULL),
                      ('tombstone', 'p1', 'f1', 'OLD_KEY', 'machine-local', 'manual', NULL,
                       NULL, '["OnCall"]', 0, 1, 'deleted', 1, 1, NULL),
                      ('danger', 'p1', 'f3', 'ADMIN_KEY', 'machine-local', 'manual', NULL,
                       NULL, '[]', 0, 1, 'active', 1, 1, NULL),
                      ('other', 'p2', 'f2', 'API_KEY', 'user-local', 'manual', NULL,
                       NULL, '[]', 0, 1, 'active', 1, 1, NULL),
                      ('foreign', 'ops', 'f4', 'OTHER', 'user-local', 'manual', NULL,
                       NULL, '[]', 0, 1, 'active', 1, 1, NULL);
           DROP TABLE blobs;
           DROP TABLE fingerprints;"#,
    )?;
    store.trust_project_root("p1", &[1; 32], Some("/second"), 2)?;
    store.trust_project_root("p1", &[2; 32], Some("/first"), 1)?;
    store.trust_project_root("p1", &[3; 32], None, 3)?;
    Ok(())
}

#[test]
fn discovery_returns_ordered_cross_project_metadata_without_values() -> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    assert_eq!(
        store.discover_secrets(&SecretDiscoveryFilter::default())?,
        Vec::<DiscoveredSecretRecord>::new()
    );
    seed_discovery(store)?;
    let records = store.discover_secrets(&SecretDiscoveryFilter::default())?;
    assert_eq!(
        records.iter().map(|record| record.secret_id.as_str()).collect::<Vec<_>>(),
        ["alpha", "machine", "user", "team", "danger", "other", "foreign"]
    );
    assert_eq!(
        records[1],
        DiscoveredSecretRecord {
            project_id: "p1".into(),
            project_name: "Acme".into(),
            project_roots: vec!["/first".into(), "/second".into()],
            profile_id: "f1".into(),
            profile_name: "dev".into(),
            profile_dangerous: false,
            secret_id: "machine".into(),
            name: "API_KEY".into(),
            description: Some("Prod %_ token".into()),
            owner: Some("Équipe Infra".into()),
            tags: vec!["OnCall".into(), "quote\"tag".into()],
            source: "machine-local".into(),
            source_precedence: 3,
            origin: "manual".into(),
            current_version: 3,
            state: "active".into(),
            required: true,
            created_at: 1,
            updated_at: 10,
            last_rotated_at: Some(8),
        }
    );
    assert_eq!(records[2].source_precedence, 2);
    assert_eq!(records[3].source_precedence, 1);
    assert!(records[4].profile_dangerous);
    assert_eq!(records[4].project_roots, records[1].project_roots);
    assert_eq!(records[5].project_roots, Vec::<String>::new());
    let metadata = store.get_secret_mutable_metadata("machine")?.ok_or("metadata absent")?;
    assert_eq!(metadata.description, records[1].description);
    assert_eq!(metadata.tags, records[1].tags);
    assert!(store.get_secret_mutable_metadata("tombstone")?.is_some());
    assert!(store.get_secret_mutable_metadata("missing")?.is_none());
    Ok(())
}

#[test]
fn discovery_filters_exact_selectors_and_case_insensitive_text() -> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    seed_discovery(store)?;
    let ids = |filter: SecretDiscoveryFilter| -> Result<Vec<String>, StoreError> {
        Ok(store.discover_secrets(&filter)?.into_iter().map(|record| record.secret_id).collect())
    };
    assert_eq!(
        ids(SecretDiscoveryFilter {
            project: Some("Acme".into()),
            profile: Some("dev".into()),
            name_glob: Some("a?i_*".into()),
            ..SecretDiscoveryFilter::default()
        })?,
        ["machine", "user", "team", "other"],
    );
    assert_eq!(
        ids(SecretDiscoveryFilter {
            project: Some("p1".into()),
            profile: Some("f1".into()),
            name_glob: Some("a?i_*".into()),
            tag: Some("OnCall".into()),
            owner: Some("ÉQUIPE".into()),
            source: Some("machine-local".into()),
            query: Some("%_".into()),
            ..SecretDiscoveryFilter::default()
        })?,
        ["machine"],
    );
    assert_eq!(
        ids(SecretDiscoveryFilter {
            tag: Some("OnCall".into()),
            include_deleted: true,
            ..SecretDiscoveryFilter::default()
        })?,
        ["machine", "tombstone"],
    );
    for query in ["api_key", "PrOd", "équipe", "ONCALL", "QUOTE\"TAG", "aCmE"] {
        assert!(
            ids(SecretDiscoveryFilter {
                query: Some(query.into()),
                ..SecretDiscoveryFilter::default()
            })?
            .contains(&"machine".to_owned()),
            "{query}"
        );
    }
    for filter in [
        SecretDiscoveryFilter { project: Some("acme".into()), ..SecretDiscoveryFilter::default() },
        SecretDiscoveryFilter { profile: Some("DEV".into()), ..SecretDiscoveryFilter::default() },
        SecretDiscoveryFilter { tag: Some("oncall".into()), ..SecretDiscoveryFilter::default() },
        SecretDiscoveryFilter { tag: Some("On".into()), ..SecretDiscoveryFilter::default() },
        SecretDiscoveryFilter { owner: Some("missing".into()), ..SecretDiscoveryFilter::default() },
        SecretDiscoveryFilter {
            source: Some("MACHINE-LOCAL".into()),
            ..SecretDiscoveryFilter::default()
        },
        SecretDiscoveryFilter { query: Some("unknown".into()), ..SecretDiscoveryFilter::default() },
        SecretDiscoveryFilter { name_glob: Some("API".into()), ..SecretDiscoveryFilter::default() },
    ] {
        assert_eq!(ids(filter)?, Vec::<String>::new());
    }
    Ok(())
}

#[test]
fn discovery_limits_matching_rows_and_rejects_invalid_tags() -> Result<(), Box<dyn Error>> {
    let fixture = open_initialized_store()?;
    let store = &fixture.store;
    store.insert_project_if_absent("p", "project", 1)?;
    store.insert_profile_if_absent("f", "p", "profile", false, 1)?;
    store.connection().execute(
        "WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM numbers WHERE n < 1001)
         INSERT INTO secrets(id, project_id, profile_id, name, source, origin, required,
                             current_version, state, created_at, updated_at)
         SELECT printf('%04d', n), 'p', 'f', printf('SECRET_%04d', n),
                'user-local', 'manual', 0, 1, 'active', 1, 1 FROM numbers",
        [],
    )?;
    let default = SecretDiscoveryFilter::default();
    assert_eq!(store.discover_secrets(&default)?.len(), 200);
    for (limit, length) in [(0, 0), (2, 2), (1_001, 1_000), (usize::MAX, 1_000)] {
        assert_eq!(
            store
                .discover_secrets(&SecretDiscoveryFilter { limit: Some(limit), ..default.clone() })?
                .len(),
            length
        );
    }
    let records = store.discover_secrets(&SecretDiscoveryFilter {
        query: Some("secret_1001".into()),
        limit: Some(1),
        ..default.clone()
    })?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].secret_id, "1001");

    store.connection().execute("UPDATE secrets SET tags_json = '{}' WHERE id = '0001'", [])?;
    assert!(matches!(store.discover_secrets(&default), Err(StoreError::Json(_))));
    assert!(matches!(store.get_secret_mutable_metadata("0001"), Err(StoreError::Json(_))));
    Ok(())
}
