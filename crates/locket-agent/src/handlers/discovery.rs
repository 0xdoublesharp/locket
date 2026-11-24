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
    /// Exact project id, name, or trusted root.
    pub project: Option<String>,
    /// Exact profile id or name.
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
        .map(|selector| match store.resolve_project_selector(&selector)? {
            ProjectSelectorResolution::Found(project) => Ok(project.id),
            ProjectSelectorResolution::NotFound => Err(DiscoveryError::ProjectNotFound),
            ProjectSelectorResolution::Ambiguous(_) => Err(DiscoveryError::AmbiguousProject),
        })
        .transpose()?;
    let records = store.discover_secrets(&SecretDiscoveryFilter {
        project: project.clone(),
        profile: filters.profile,
        query: filters.query,
        name_glob: filters.name_glob,
        tag: filters.tag,
        owner: filters.owner,
        source: filters.source,
        include_deleted: filters.include_deleted,
        limit: filters.limit,
    })?;
    Ok(json!(
        records
            .into_iter()
            .filter(|record| project.as_ref().is_none_or(|id| &record.project_id == id))
            .map(|record| secret_row(record, filters.redact_names))
            .collect::<Vec<_>>()
    ))
}

fn secret_row(record: DiscoveredSecretRecord, redact: bool) -> Value {
    let name = label("secret", &record.name, &record.name, redact);
    let profile = label("profile", &record.profile_id, &record.profile_name, redact);
    let roots = record
        .project_roots
        .iter()
        .map(|path| label("root", path, path, redact))
        .collect::<Vec<_>>();
    json!({
        "project_id": record.project_id,
        "project_name": label("project", &record.project_id, &record.project_name, redact),
        "trusted_roots": roots,
        "profile_id": record.profile_id,
        "profile": profile,
        "dangerous": record.profile_dangerous,
        "secret_id": record.secret_id,
        "name": name,
        "source": record.source,
        "source_precedence": record.source_precedence,
        "origin": record.origin,
        "version": record.current_version,
        "state": record.state,
        "description": record.description.filter(|_| !redact),
        "owner": record.owner.filter(|_| !redact),
        "tags": if redact { Vec::new() } else { record.tags },
        "required": record.required,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "last_rotated_at": record.last_rotated_at,
        "reference": format!("lk://{profile}/{name}"),
    })
}

fn label(kind: &str, id: &str, name: &str, redact: bool) -> String {
    if redact { privacy_alias(kind, id) } else { name.to_owned() }
}

pub fn handle_list_projects(request: &RequestEnvelope) -> ResponseEnvelope {
    let Ok(payload) = ListProjectsRequest::deserialize(&request.payload) else {
        return invalid_payload(request);
    };
    let result = Store::open_read_only(payload.store_path)
        .map_err(DiscoveryError::from)
        .and_then(|store| list_projects(&store, payload.redact_names));
    response(request, result, "projects")
}

pub fn handle_discover_secrets(request: &RequestEnvelope) -> ResponseEnvelope {
    let Ok(payload) = DiscoverSecretsRequest::deserialize(&request.payload) else {
        return invalid_payload(request);
    };
    let result = Store::open_read_only(payload.store_path)
        .map_err(DiscoveryError::from)
        .and_then(|store| discover_secrets(&store, payload.filters));
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

        let search = RequestEnvelope::new(
            "redact",
            AgentMethod::DiscoverSecrets,
            json!({
                "store_path": path, "project": "Second project", "redact_names": true,
            }),
        );
        let ResponseEnvelope::Success(search) = dispatch(&search, &state).await else {
            return Err("could not redact secret metadata".into());
        };
        assert_eq!(search.payload["secrets"].as_array().ok_or("expected rows")?.len(), 1);
        let payload = search.payload.to_string();
        for hidden in ["SERVICE_TOKEN", "prod", "Second project", "Platform"] {
            assert!(!payload.contains(hidden));
        }
        Ok(())
    }
}
