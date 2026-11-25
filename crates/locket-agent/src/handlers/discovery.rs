//! Cross-project metadata-only RPC methods.

use locket_core::privacy_alias;
use locket_store::{
    DiscoveredSecretRecord, ProjectSelectorResolution, SecretDiscoveryFilter, Store, StoreError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};

/// Request for metadata-only local project summaries.
#[derive(Debug, Deserialize, Serialize)]
pub struct ListProjectsRequest {
    /// Path to the user-scoped store database.
    pub store_path: String,
    /// Whether human-readable names and paths should be aliased.
    #[serde(default)]
    pub redact_names: bool,
}

/// Filters for metadata-only cross-project discovery.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DiscoveryFilters {
    /// Exact project id, name, or trusted root. Redacted discovery accepts id or alias.
    pub project: Option<String>,
    /// Exact profile id or displayed name (alias in redacted discovery).
    pub profile: Option<String>,
    /// Search term applied to names and descriptive metadata.
    pub query: Option<String>,
    /// Name glob using `*` and `?`.
    pub name_glob: Option<String>,
    /// Exact tag.
    pub tag: Option<String>,
    /// Case-insensitive substring of the owner.
    pub owner: Option<String>,
    /// Exact persisted source.
    pub source: Option<String>,
    /// Include deleted secrets.
    pub include_deleted: bool,
    /// Maximum number of returned records.
    pub limit: Option<usize>,
    /// Alias names and paths and omit free-form descriptive fields.
    pub redact_names: bool,
}

/// Request for metadata-only secret discovery.
#[derive(Debug, Deserialize, Serialize)]
pub struct DiscoverSecretsRequest {
    /// Path to the user-scoped store database.
    pub store_path: String,
    /// Cross-project metadata filters.
    #[serde(flatten)]
    pub filters: DiscoveryFilters,
}

/// Errors returned by cross-project metadata queries.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// No project matched the selector.
    #[error("project selector did not match a local project")]
    ProjectNotFound,
    /// More than one project matched.
    #[error("project selector is ambiguous; select by project id")]
    AmbiguousProject,
    /// Store metadata could not be read.
    #[error("could not read vault metadata")]
    Store(#[from] StoreError),
}

/// Lists project summaries using only store metadata.
///
/// # Errors
///
/// Returns an error if the project metadata cannot be read.
pub fn list_projects(store: &Store, redact_names: bool) -> Result<Value, DiscoveryError> {
    let projects = store
        .list_project_summaries()?
        .into_iter()
        .map(|summary| {
            let profiles = summary
                .profiles
                .into_iter()
                .map(|profile| {
                    json!({
                        "id": profile.id,
                        "name": label("profile", &profile.id, &profile.name, redact_names),
                        "dangerous": profile.dangerous,
                    })
                })
                .collect::<Vec<_>>();
            let trusted_roots = summary
                .trusted_roots
                .into_iter()
                .filter_map(|root| root.display_path)
                .map(|path| label("root", &path, &path, redact_names))
                .collect::<Vec<_>>();
            json!({
                "project_id": summary.project.id,
                "name": label("project", &summary.project.id, &summary.project.name, redact_names),
                "profiles": profiles,
                "trusted_roots": trusted_roots,
                "active_secret_count": summary.active_secret_count,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!(projects))
}

/// Discovers matching secret metadata without loading any secret blobs.
///
/// # Errors
///
/// Returns an error if the project selector is ambiguous or missing, or if store metadata cannot
/// be read.
pub fn discover_secrets(store: &Store, filters: DiscoveryFilters) -> Result<Value, DiscoveryError> {
    let project = filters
        .project
        .map(|selector| resolve_discovery_project(store, &selector, filters.redact_names))
        .transpose()?;
    let filter = SecretDiscoveryFilter {
        project: project.clone(),
        profile: filters.profile,
        query: filters.query,
        name_glob: filters.name_glob,
        tag: filters.tag,
        owner: filters.owner,
        source: filters.source,
        include_deleted: filters.include_deleted,
        limit: filters.limit,
    };
    let records = if filters.redact_names {
        store.discover_redacted_secrets(&filter)?
    } else {
        store.discover_secrets(&filter)?
    };
    let notices = if store
        .current_schema_version()?
        .is_some_and(|version| version >= i64::from(locket_store::SCHEMA_VERSION))
    {
        store.list_expiring_or_stale_secrets(
            project.as_deref(),
            i64::try_from(crate::server::current_unix_nanos()).unwrap_or(i64::MAX),
            7 * 86_400_000_000_000,
        )?
    } else {
        Vec::new()
    };
    let notices = notices
        .iter()
        .map(|notice| (notice.secret_id.as_str(), notice))
        .collect::<std::collections::BTreeMap<_, _>>();
    Ok(json!(
        records
            .iter()
            .filter(|record| project.as_ref().is_none_or(|id| &record.project_id == id))
            .map(|record| {
                let notice = notices.get(record.secret_id.as_str()).copied();
                secret_row(record, notice)
            })
            .collect::<Vec<_>>()
    ))
}

fn resolve_discovery_project(
    store: &Store,
    selector: &str,
    redact_names: bool,
) -> Result<String, DiscoveryError> {
    if !redact_names {
        return match store.resolve_project_selector(selector)? {
            ProjectSelectorResolution::Found(project) => Ok(project.id),
            ProjectSelectorResolution::NotFound => Err(DiscoveryError::ProjectNotFound),
            ProjectSelectorResolution::Ambiguous(_) => Err(DiscoveryError::AmbiguousProject),
        };
    }
    if let Some(project) = store.get_project(selector)? {
        return Ok(project.id);
    }
    let mut matches = store
        .list_projects()?
        .into_iter()
        .filter(|project| privacy_alias("project", &project.id) == selector);
    let project = matches.next().ok_or(DiscoveryError::ProjectNotFound)?;
    if matches.next().is_some() {
        return Err(DiscoveryError::AmbiguousProject);
    }
    Ok(project.id)
}

fn secret_row(
    record: &DiscoveredSecretRecord,
    notice: Option<&locket_store::SecretExpirationNotice>,
) -> Value {
    let mut row = json!({
        "project_id": record.project_id,
        "project_name": record.project_name,
        "trusted_roots": record.project_roots,
        "profile_id": record.profile_id,
        "profile": record.profile_name,
        "dangerous": record.profile_dangerous,
        "secret_id": record.secret_id,
        "name": record.name,
        "source": record.source,
        "source_precedence": record.source_precedence,
        "origin": record.origin,
        "version": record.current_version,
        "state": record.state,
        "description": record.description,
        "owner": record.owner,
        "tags": record.tags,
        "required": record.required,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "last_rotated_at": record.last_rotated_at,
        "reference": format!("lk://{}/{}", record.profile_name, record.name),
    });
    if let Some(notice) = notice {
        let status = notice.expiry_status.map(|status| match status {
            locket_store::SecretExpiryStatus::Expired => "expired",
            locket_store::SecretExpiryStatus::ExpiringSoon => "expiring_soon",
        });
        row["expiry_status"] = json!(status);
        row["expires_at"] = json!(notice.policy.expires_at);
        row["rotate_after_days"] = json!(notice.policy.rotate_after_days);
        row["stale"] = json!(notice.stale);
    }
    row
}

fn label(kind: &str, id: &str, name: &str, redact: bool) -> String {
    if redact { privacy_alias(kind, id) } else { name.to_owned() }
}

pub fn handle_list_projects(
    request: &RequestEnvelope,
    state: &crate::AgentSocketState,
) -> ResponseEnvelope {
    let Ok(payload) = ListProjectsRequest::deserialize(&request.payload) else {
        return invalid_payload(request);
    };
    let Ok((store, _)) = state.open_store(std::path::Path::new(&payload.store_path), None, true)
    else {
        return crate::server::error_response(
            request,
            "AccessDenied",
            "could not verify discovery store",
        );
    };
    let result = list_projects(&store, payload.redact_names);
    response(request, result, "projects")
}

pub fn handle_discover_secrets(
    request: &RequestEnvelope,
    state: &crate::AgentSocketState,
) -> ResponseEnvelope {
    let Ok(payload) = DiscoverSecretsRequest::deserialize(&request.payload) else {
        return invalid_payload(request);
    };
    let Ok((store, _)) = state.open_store(std::path::Path::new(&payload.store_path), None, true)
    else {
        return crate::server::error_response(
            request,
            "AccessDenied",
            "could not verify discovery store",
        );
    };
    let result = discover_secrets(&store, payload.filters);
    response(request, result, "secrets")
}

fn invalid_payload(request: &RequestEnvelope) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(
        request.id.clone(),
        "ProtocolError",
        "invalid discovery payload",
        false,
    ))
}

fn response(
    request: &RequestEnvelope,
    result: Result<Value, DiscoveryError>,
    key: &str,
) -> ResponseEnvelope {
    match result {
        Ok(rows) => ResponseEnvelope::Success(SuccessEnvelope::new(
            request.id.clone(),
            json!({(key): rows}),
        )),
        Err(error) => {
            let code = match error {
                DiscoveryError::ProjectNotFound => "ProjectNotFound",
                DiscoveryError::AmbiguousProject => "AmbiguousProject",
                DiscoveryError::Store(_) => "CorruptDb",
            };
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                code,
                error.to_string(),
                false,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentMethod, AgentSocketState, dispatch};

    #[tokio::test(flavor = "current_thread")]
    async fn locked_cross_project_dispatch_only_queries_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("store.db");
        let mut store = Store::open(&path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent("lk_proj_one", "First project", 0)?;
        store.insert_project_if_absent("lk_proj_two", "Second project", 0)?;
        store.insert_profile_if_absent("lk_prof_one", "lk_proj_one", "dev", false, 0)?;
        store.insert_profile_if_absent("lk_prof_two", "lk_proj_two", "prod", true, 0)?;
        store.connection().execute_batch(
            "INSERT INTO secrets
                (id, project_id, profile_id, name, source, origin, current_version, state,
                 created_at, updated_at, owner, tags_json, required)
             VALUES
                ('lk_sec_one', 'lk_proj_one', 'lk_prof_one', 'SERVICE_KEY', 'user-local',
                 'manual', 1, 'active', 0, 0, 'Platform', '[\"service\"]', 0),
                ('lk_sec_two', 'lk_proj_two', 'lk_prof_two', 'SERVICE_TOKEN', 'team-managed',
                 'manual', 1, 'active', 0, 0, 'Platform', '[\"service\"]', 0);
             DROP TABLE blobs;",
        )?;
        let now = i64::try_from(crate::server::current_unix_nanos())?;
        store.set_secret_expiry_policy(
            "lk_sec_one",
            locket_store::SecretExpiryPolicy { expires_at: Some(now - 1), rotate_after_days: None },
            now,
        )?;
        store.set_secret_expiry_policy(
            "lk_sec_two",
            locket_store::SecretExpiryPolicy {
                expires_at: Some(now + 86_400_000_000_000),
                rotate_after_days: None,
            },
            now,
        )?;
        let state = AgentSocketState::locked("test");
        let list =
            RequestEnvelope::new("list", AgentMethod::ListProjects, json!({"store_path": path}));
        let ResponseEnvelope::Success(list) = dispatch(&list, &state).await else {
            return Err("could not list project metadata".into());
        };
        assert_eq!(list.payload["projects"][0]["active_secret_count"], 1);
        assert_eq!(list.payload["projects"][1]["profiles"][0]["dangerous"], true);

        let search = RequestEnvelope::new(
            "discovery",
            AgentMethod::DiscoverSecrets,
            json!({
                "store_path": path, "name_glob": "SERVICE_*", "tag": "service", "owner": "plat",
            }),
        );
        let ResponseEnvelope::Success(search) = dispatch(&search, &state).await else {
            return Err("could not discover secret metadata".into());
        };
        assert_eq!(search.payload["secrets"].as_array().ok_or("expected rows")?.len(), 2);
        assert_eq!(search.payload["secrets"][0]["reference"], "lk://dev/SERVICE_KEY");
        assert_eq!(search.payload["secrets"][1]["reference"], "lk://prod/SERVICE_TOKEN");

        assert_eq!(search.payload["secrets"][0]["expiry_status"], "expired");
        assert_eq!(search.payload["secrets"][1]["expiry_status"], "expiring_soon");

        let search = RequestEnvelope::new(
            "redact",
            AgentMethod::DiscoverSecrets,
            json!({
                "store_path": path, "project": "lk_proj_two", "redact_names": true,
            }),
        );
        let ResponseEnvelope::Success(search) = dispatch(&search, &state).await else {
            return Err("could not redact secret metadata".into());
        };
        assert_eq!(search.payload["secrets"].as_array().ok_or("expected rows")?.len(), 1);
        assert_eq!(search.payload["secrets"][0]["expiry_status"], "expiring_soon");
        assert_eq!(
            search.payload["secrets"][0]["reference"],
            format!(
                "lk://{}/{}",
                privacy_alias("profile", "lk_prof_two"),
                privacy_alias("secret", "SERVICE_TOKEN"),
            )
        );
        let payload = search.payload.to_string();
        for hidden in ["SERVICE_TOKEN", "prod", "Second project", "Platform"] {
            assert!(!payload.contains(hidden));
        }
        Ok(())
    }

    #[test]
    fn redacted_discovery_filters_projected_labels_before_limiting()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = Store::open(":memory:")?;
        store.initialize_schema()?;
        store.insert_project_if_absent("lk_proj_one", "First project", 0)?;
        store.insert_project_if_absent("lk_proj_two", "Second project", 0)?;
        store.insert_profile_if_absent("lk_prof_one", "lk_proj_one", "dev", false, 0)?;
        store.insert_profile_if_absent("lk_prof_two", "lk_proj_two", "prod", true, 0)?;
        store.connection().execute_batch(
            r#"INSERT INTO secrets
                (id, project_id, profile_id, name, source, origin, current_version, state,
                 created_at, updated_at, owner, tags_json, required)
             VALUES
                ('lk_sec_one', 'lk_proj_one', 'lk_prof_one', 'SERVICE_KEY', 'user-local',
                 'manual', 1, 'active', 0, 0, 'Platform', '["service"]', 0),
                ('lk_sec_two', 'lk_proj_two', 'lk_prof_two', 'SERVICE_TOKEN', 'team-managed',
                 'manual', 1, 'active', 0, 0, 'Platform', '["service"]', 0);"#,
        )?;
        let search = |mut filter: Value| {
            filter["redact_names"] = json!(true);
            filter["limit"] = json!(1);
            discover_secrets(&store, serde_json::from_value(filter)?)
                .map_err(Box::<dyn std::error::Error>::from)
        };

        for filters in [
            json!({"query": "SERVICE_"}),
            json!({"query": "service"}),
            json!({"query": "PLATFORM"}),
            json!({"query": "Second project"}),
            json!({"name_glob": "SERVICE_*"}),
            json!({"tag": "service"}),
            json!({"owner": "plat"}),
            json!({"profile": "prod"}),
        ] {
            assert_eq!(search(filters.clone())?, json!([]), "redacted filter {filters}");
        }
        assert!(matches!(
            discover_secrets(
                &store,
                DiscoveryFilters {
                    project: Some("Second project".into()),
                    redact_names: true,
                    ..Default::default()
                },
            ),
            Err(DiscoveryError::ProjectNotFound)
        ));

        let project_alias = privacy_alias("project", "lk_proj_two");
        let profile_alias = privacy_alias("profile", "lk_prof_two");
        let secret_alias = privacy_alias("secret", "SERVICE_TOKEN");
        for filter in [
            json!({"query": project_alias.to_uppercase()}),
            json!({"query": profile_alias.to_uppercase()}),
            json!({"query": secret_alias.to_uppercase()}),
            json!({"project": project_alias, "profile": profile_alias, "name_glob": secret_alias}),
        ] {
            let matches = search(filter)?;
            assert_eq!(matches.as_array().ok_or("expected rows")?.len(), 1);
            assert_eq!(matches[0]["name"], secret_alias);
        }

        let first = search(json!({}))?;
        let matching = search(json!({"query": project_alias}))?;
        store.connection().execute_batch(
            "UPDATE projects SET name = 'A different project' WHERE id = 'lk_proj_two';
             UPDATE profiles SET name = 'renamed' WHERE id = 'lk_prof_two';
             UPDATE secrets SET owner = 'Different owner', tags_json = '[]';",
        )?;
        assert_eq!(search(json!({}))?, first);
        assert_eq!(search(json!({"query": project_alias}))?, matching);
        Ok(())
    }
}
