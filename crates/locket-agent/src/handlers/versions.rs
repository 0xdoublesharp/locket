//! Metadata-only secret version listing RPC payloads and helpers.

use std::path::PathBuf;

use locket_core::privacy_alias;
use locket_store::{Store, StoreError};
use serde::{Deserialize, Serialize};

/// Wire payload for the `ListVersions` RPC.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListVersionsRequest {
    /// `SQLite` store path to read.
    pub store_path: PathBuf,
    /// Project id whose active-profile rows are listed.
    pub project_id: String,
    /// Active profile id.
    pub profile_id: String,
    /// Optional secret-name filter.
    pub secret_name: Option<String>,
    /// Optional source filter.
    pub source: Option<String>,
    /// Timestamp used for grace-window derived fields.
    pub now_unix_nanos: i64,
    /// Whether profile and secret names should be aliased.
    #[serde(default)]
    pub redact_names: bool,
}

/// Metadata-only `ListVersions` response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListVersionsResponse {
    /// Version metadata rows ordered by name, source precedence, and version.
    pub rows: Vec<ListVersionsRow>,
}

/// Metadata-only secret version row for agent clients.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListVersionsRow {
    /// Secret row id.
    pub secret_id: String,
    /// Profile id or privacy alias.
    pub profile_id: String,
    /// Secret name or privacy alias.
    pub name: String,
    /// Runtime source.
    pub source: String,
    /// Numeric source precedence, with larger values winning runtime resolution.
    pub source_precedence: u8,
    /// Metadata origin.
    pub origin: String,
    /// Whole-secret state.
    pub secret_state: String,
    /// Current version pointer on the parent secret.
    pub current_version: u32,
    /// Last rotation timestamp on the parent secret.
    pub last_rotated_at: Option<i64>,
    /// Version number.
    pub version: u32,
    /// Version state.
    pub version_state: String,
    /// Version creation timestamp.
    pub created_at: i64,
    /// Deprecation timestamp.
    pub deprecated_at: Option<i64>,
    /// Grace-window expiration timestamp.
    pub grace_until: Option<i64>,
    /// Purge timestamp.
    pub purged_at: Option<i64>,
    /// Whether a pinned `lk://...@vN` reference may resolve this version at `now`.
    pub pinned_reference_eligible: bool,
    /// Whether known-value scanning should include this version at `now`.
    pub scan_included: bool,
}

/// Lists version metadata. This never reads encrypted values.
///
/// # Errors
///
/// Returns [`StoreError`] when the store cannot be opened or queried.
#[cfg(test)]
pub fn list_versions(request: &ListVersionsRequest) -> Result<ListVersionsResponse, StoreError> {
    let (store, _) = crate::keys::open_verified_store(&request.store_path, None)?;
    list_versions_from_store(&store, request)
}

pub fn list_versions_from_store(
    store: &Store,
    request: &ListVersionsRequest,
) -> Result<ListVersionsResponse, StoreError> {
    let rows = store
        .list_secret_version_metadata_by_profile(&request.project_id, &request.profile_id)?
        .into_iter()
        .filter(|row| request.secret_name.as_ref().is_none_or(|name| row.name == *name))
        .filter(|row| request.source.as_ref().is_none_or(|source| row.source == *source))
        .map(|row| {
            let eligible = version_resolves_at(
                &row.version_state,
                row.secret_state.as_str(),
                row.current_version,
                row.version,
                row.grace_until,
                request.now_unix_nanos,
            );
            let scan_included = match row.version_state.as_str() {
                "current" => row.secret_state == "active" || row.version == row.current_version,
                "deprecated" => row.grace_until.is_some_and(|until| until > request.now_unix_nanos),
                _ => false,
            };
            ListVersionsRow {
                secret_id: row.secret_id,
                profile_id: profile_label(&row.profile_id, request.redact_names),
                name: secret_label(&row.name, request.redact_names),
                source: row.source,
                source_precedence: row.source_precedence,
                origin: row.origin,
                secret_state: row.secret_state,
                current_version: row.current_version,
                last_rotated_at: row.last_rotated_at,
                version: row.version,
                version_state: row.version_state,
                created_at: row.created_at,
                deprecated_at: row.deprecated_at,
                grace_until: row.grace_until,
                purged_at: row.purged_at,
                pinned_reference_eligible: eligible,
                scan_included,
            }
        })
        .collect();
    Ok(ListVersionsResponse { rows })
}

fn version_resolves_at(
    version_state: &str,
    secret_state: &str,
    current_version: u32,
    version: u32,
    grace_until: Option<i64>,
    now_unix_nanos: i64,
) -> bool {
    if secret_state != "active" {
        return false;
    }
    match version_state {
        "current" => version == current_version,
        "deprecated" => grace_until.is_some_and(|grace_until| grace_until > now_unix_nanos),
        _ => false,
    }
}

fn profile_label(value: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("profile", value) } else { value.to_owned() }
}

fn secret_label(value: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("secret", value) } else { value.to_owned() }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::PathBuf;

    use locket_core::privacy_alias;
    use locket_store::Store;
    use rusqlite::params;
    use tempfile::tempdir;

    use super::{
        ListVersionsRequest, ListVersionsResponse, ListVersionsRow, list_versions, profile_label,
        secret_label, version_resolves_at,
    };

    #[test]
    fn version_payloads_round_trip_through_json() -> Result<(), serde_json::Error> {
        let request = ListVersionsRequest {
            store_path: "store.db".into(),
            project_id: "lk_proj_test".to_owned(),
            profile_id: "lk_prof_test".to_owned(),
            secret_name: Some("DATABASE_URL".to_owned()),
            source: Some("machine-local".to_owned()),
            now_unix_nanos: 123,
            redact_names: true,
        };
        let decoded: ListVersionsRequest = serde_json::from_value(serde_json::to_value(&request)?)?;
        assert_eq!(decoded, request);

        let response = ListVersionsResponse {
            rows: vec![ListVersionsRow {
                secret_id: "lk_sec_test".to_owned(),
                profile_id: "lk_prof_test".to_owned(),
                name: "DATABASE_URL".to_owned(),
                source: "machine-local".to_owned(),
                source_precedence: 3,
                origin: "manual".to_owned(),
                secret_state: "active".to_owned(),
                current_version: 2,
                last_rotated_at: Some(200),
                version: 1,
                version_state: "deprecated".to_owned(),
                created_at: 100,
                deprecated_at: Some(200),
                grace_until: Some(300),
                purged_at: None,
                pinned_reference_eligible: true,
                scan_included: true,
            }],
        };
        let decoded: ListVersionsResponse =
            serde_json::from_value(serde_json::to_value(&response)?)?;
        assert_eq!(decoded, response);
        Ok(())
    }

    #[test]
    fn labels_redact_only_when_requested() {
        assert_eq!(profile_label("prod", false), "prod");
        assert_eq!(secret_label("DATABASE_URL", false), "DATABASE_URL");
        assert_eq!(profile_label("prod", true), privacy_alias("profile", "prod"));
        assert_eq!(secret_label("DATABASE_URL", true), privacy_alias("secret", "DATABASE_URL"));
    }

    #[test]
    fn version_resolution_matches_current_and_grace_rules() {
        assert!(version_resolves_at("current", "active", 2, 2, None, 100));
        assert!(!version_resolves_at("current", "deleted", 2, 2, None, 100));
        assert!(!version_resolves_at("current", "active", 2, 1, None, 100));
        assert!(version_resolves_at("deprecated", "active", 2, 1, Some(101), 100));
        assert!(!version_resolves_at("deprecated", "active", 2, 1, Some(100), 100));
        assert!(!version_resolves_at("deprecated", "active", 2, 1, None, 100));
        assert!(!version_resolves_at("purged", "active", 2, 1, Some(200), 100));
    }

    #[test]
    fn deleted_deprecated_version_is_not_resolvable_during_grace() {
        assert!(!version_resolves_at("deprecated", "deleted", 2, 1, Some(101), 100));
    }

    #[test]
    fn list_versions_returns_store_errors() -> Result<(), Box<dyn Error>> {
        let directory = tempdir()?;
        let request = ListVersionsRequest {
            store_path: directory.path().join("missing/parent/store.db"),
            project_id: "lk_proj_test".to_owned(),
            profile_id: "lk_prof_test".to_owned(),
            secret_name: None,
            source: None,
            now_unix_nanos: 100,
            redact_names: false,
        };
        assert!(list_versions(&request).is_err());
        Ok(())
    }

    fn version_store_fixture() -> Result<(tempfile::TempDir, PathBuf), Box<dyn Error>> {
        let directory = tempdir()?;
        let store_path = directory.path().join("store.db");
        let mut store = Store::open(&store_path)?;
        store.initialize_schema()?;
        store.connection().execute(
            "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
            [],
        )?;
        store.connection().execute(
            "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
             VALUES ('lk_prof_test', 'lk_proj_test', 'default', 0, 1)",
            [],
        )?;

        for (id, name, source, current_version, state, last_rotated_at) in [
            ("lk_sec_machine", "DATABASE_URL", "machine-local", 2, "active", Some(200)),
            ("lk_sec_team", "DATABASE_URL", "team-managed", 1, "active", None),
            ("lk_sec_other", "API_TOKEN", "machine-local", 1, "active", None),
            ("lk_sec_deleted", "DATABASE_URL", "user-local", 2, "deleted", None),
        ] {
            store.connection().execute(
                "INSERT INTO secrets(
                   id, project_id, profile_id, name, source, origin, required,
                   current_version, state, created_at, updated_at, last_rotated_at, deleted_at
                 )
                 VALUES (?1, 'lk_proj_test', 'lk_prof_test', ?2, ?3, 'manual', 1,
                         ?4, ?5, 100, 200, ?6, NULL)",
                params![id, name, source, current_version, state, last_rotated_at],
            )?;
        }

        for (secret_id, version, state, created_at, deprecated_at, grace_until, purged_at) in [
            ("lk_sec_machine", 1, "deprecated", 100, Some(200), Some(900), None::<i64>),
            ("lk_sec_machine", 2, "current", 200, None, None, None),
            ("lk_sec_team", 1, "current", 100, None, None, None),
            ("lk_sec_other", 1, "current", 100, None, None, None),
            ("lk_sec_deleted", 1, "deprecated", 100, Some(200), Some(900), None),
            ("lk_sec_deleted", 2, "current", 200, None, None, None),
        ] {
            store.connection().execute(
                "INSERT INTO secret_versions(
                   secret_id, version, source, origin, state, created_at,
                   deprecated_at, grace_until, purged_at
                 )
                 VALUES (
                   ?1,
                   ?2,
                   (SELECT source FROM secrets WHERE id = ?1),
                   'manual',
                   ?3,
                   ?4,
                   ?5,
                   ?6,
                   ?7
                 )",
                params![
                    secret_id,
                    version,
                    state,
                    created_at,
                    deprecated_at,
                    grace_until,
                    purged_at
                ],
            )?;
        }
        drop(store);

        Ok((directory, store_path))
    }

    #[test]
    fn list_versions_filters_and_redacts_metadata_rows() -> Result<(), Box<dyn Error>> {
        let (_directory, store_path) = version_store_fixture()?;
        let response = list_versions(&ListVersionsRequest {
            store_path: store_path.clone(),
            project_id: "lk_proj_test".to_owned(),
            profile_id: "lk_prof_test".to_owned(),
            secret_name: Some("DATABASE_URL".to_owned()),
            source: Some("machine-local".to_owned()),
            now_unix_nanos: 500,
            redact_names: true,
        })?;

        assert_eq!(response.rows.len(), 2);
        assert_eq!(response.rows[0].secret_id, "lk_sec_machine");
        assert_eq!(response.rows[0].name, privacy_alias("secret", "DATABASE_URL"));
        assert_eq!(response.rows[0].profile_id, privacy_alias("profile", "lk_prof_test"));
        assert_eq!(response.rows[0].version, 2);
        assert!(response.rows[0].pinned_reference_eligible);
        assert!(response.rows[0].scan_included);
        assert_eq!(response.rows[1].version, 1);
        assert_eq!(response.rows[1].grace_until, Some(900));
        assert!(response.rows[1].pinned_reference_eligible);
        assert!(response.rows[1].scan_included);

        let mut request = ListVersionsRequest {
            store_path,
            project_id: "lk_proj_test".to_owned(),
            profile_id: "lk_prof_test".to_owned(),
            secret_name: None,
            source: Some("user-local".to_owned()),
            now_unix_nanos: 500,
            redact_names: false,
        };
        let deleted = list_versions(&request)?;
        assert_eq!(deleted.rows.len(), 2);
        assert_eq!(deleted.rows[0].name, "DATABASE_URL");
        assert_eq!(deleted.rows[0].profile_id, "lk_prof_test");
        for row in &deleted.rows {
            assert!(!row.pinned_reference_eligible);
            assert!(row.scan_included, "deleted current and in-grace versions still detect leaks");
        }
        request.now_unix_nanos = 900;
        let expired = list_versions(&request)?;
        assert!(expired.rows[0].scan_included);
        assert!(!expired.rows[1].scan_included);
        request.source = None;
        assert_eq!(list_versions(&request)?.rows.len(), 6);
        request.profile_id = "lk_prof_other".to_owned();
        assert_eq!(list_versions(&request)?.rows.len(), 0);

        Ok(())
    }
}
