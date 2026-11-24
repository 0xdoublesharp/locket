//! Cross-project queries over secret metadata.

use rusqlite::{Row, params};

use crate::{Store, StoreError};

use super::{SecretMutableMetadata, mutable_metadata_from_row};

const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 1_000;

/// Filters metadata-only secret discovery. All supplied filters must match.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecretDiscoveryFilter {
    /// Exact project id or name.
    pub project: Option<String>,
    /// Exact profile id or name.
    pub profile: Option<String>,
    /// Case-insensitive substring in the name, description, owner, tags, or project name.
    pub query: Option<String>,
    /// Case-insensitive name pattern where `*` matches any run and `?` matches one character.
    pub name_glob: Option<String>,
    /// Exact tag.
    pub tag: Option<String>,
    /// Case-insensitive substring in the owner.
    pub owner: Option<String>,
    /// Exact persisted source.
    pub source: Option<String>,
    /// Include deleted secrets alongside active ones.
    pub include_deleted: bool,
    /// Maximum number of results. Defaults to 200 and is capped at 1,000.
    pub limit: Option<usize>,
}

/// Secret metadata joined with its project, trusted root display paths, and profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredSecretRecord {
    /// Project identifier.
    pub project_id: String,
    /// Human-readable project name.
    pub project_name: String,
    /// Display paths of trusted roots with a recorded path.
    pub project_roots: Vec<String>,
    /// Profile identifier.
    pub profile_id: String,
    /// Human-readable profile name.
    pub profile_name: String,
    /// Whether the profile is marked dangerous.
    pub profile_dangerous: bool,
    /// Secret identifier.
    pub secret_id: String,
    /// Secret name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Optional owner.
    pub owner: Option<String>,
    /// Full tag list.
    pub tags: Vec<String>,
    /// Persisted secret source string.
    pub source: String,
    /// Source precedence, with larger values winning runtime resolution.
    pub source_precedence: u8,
    /// Persisted secret origin string.
    pub origin: String,
    /// Current secret version.
    pub current_version: u32,
    /// Persisted secret state string.
    pub state: String,
    /// Whether command policies should treat the secret as required.
    pub required: bool,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last metadata update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
    /// Last rotation timestamp in nanoseconds since the Unix epoch.
    pub last_rotated_at: Option<i64>,
}

impl DiscoveredSecretRecord {
    fn from_row(row: &Row<'_>) -> Result<Self, StoreError> {
        let SecretMutableMetadata { description, owner, tags, required } =
            mutable_metadata_from_row(row, 8)?;
        Ok(Self {
            project_id: row.get(0)?,
            project_name: row.get(1)?,
            project_roots: Vec::new(),
            profile_id: row.get(2)?,
            profile_name: row.get(3)?,
            profile_dangerous: row.get(4)?,
            secret_id: row.get(5)?,
            name: row.get(6)?,
            source: row.get(7)?,
            description,
            owner,
            tags,
            required,
            source_precedence: row.get(12)?,
            origin: row.get(13)?,
            current_version: row.get(14)?,
            state: row.get(15)?,
            created_at: row.get(16)?,
            updated_at: row.get(17)?,
            last_rotated_at: row.get(18)?,
        })
    }
}

impl Store {
    /// Discovers secret metadata across projects and profiles.
    ///
    /// Results are ordered by project name and id, profile name, secret name,
    /// descending source precedence, and source. The limit applies after all filters.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when metadata cannot be queried or decoded.
    pub fn discover_secrets(
        &self,
        filter: &SecretDiscoveryFilter,
    ) -> Result<Vec<DiscoveredSecretRecord>, StoreError> {
        let limit = filter.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut statement = self.connection.prepare_cached(
            "SELECT p.id, p.name, f.id, f.name, f.dangerous, s.id, s.name, s.source,
                    s.description, s.owner, s.tags_json, s.required,
                    CASE s.source
                      WHEN 'machine-local' THEN 3
                      WHEN 'user-local' THEN 2
                      WHEN 'team-managed' THEN 1
                      ELSE 0
                    END AS source_precedence,
                    s.origin, s.current_version, s.state, s.created_at, s.updated_at, s.last_rotated_at
             FROM secrets s
             JOIN projects p ON p.id = s.project_id
             JOIN profiles f ON f.id = s.profile_id AND f.project_id = p.id
             WHERE (?1 IS NULL OR p.id = ?1 OR p.name = ?1)
               AND (?2 IS NULL OR f.id = ?2 OR f.name = ?2)
               AND (?3 IS NULL OR s.source = ?3)
               AND (?4 OR s.state = 'active')
             ORDER BY p.name, p.id, f.name, s.name, source_precedence DESC, s.source
             LIMIT ?5",
        )?;
        // Only let SQL stop early when no remaining filters can discard rows.
        let needs_text_filter = filter.query.is_some()
            || filter.name_glob.is_some()
            || filter.tag.is_some()
            || filter.owner.is_some();
        let sql_limit = if needs_text_filter { -1 } else { i64::try_from(limit).unwrap_or(-1) };
        let mut rows = statement.query(params![
            filter.project.as_deref(),
            filter.profile.as_deref(),
            filter.source.as_deref(),
            filter.include_deleted,
            sql_limit,
        ])?;

        let query = filter.query.as_deref().map(str::to_lowercase);
        let owner = filter.owner.as_deref().map(str::to_lowercase);
        let mut results: Vec<DiscoveredSecretRecord> = Vec::new();
        while let Some(row) = rows.next()? {
            let mut record = DiscoveredSecretRecord::from_row(row)?;
            if filter.tag.as_ref().is_some_and(|tag| !record.tags.contains(tag))
                || filter
                    .name_glob
                    .as_deref()
                    .is_some_and(|pattern| !glob_matches(pattern, &record.name))
                || owner
                    .as_deref()
                    .is_some_and(|owner| !contains_lowercase(record.owner.as_deref(), owner))
                || query.as_deref().is_some_and(|query| !matches_query(&record, query))
            {
                continue;
            }

            // Ordered rows put every result for a project together, so its roots
            // need to be read only once.
            let previous = results.last().filter(|last| last.project_id == record.project_id);
            record.project_roots = if let Some(last) = previous {
                last.project_roots.clone()
            } else {
                self.list_project_roots(&record.project_id)?
                    .into_iter()
                    .filter_map(|root| root.display_path)
                    .collect()
            };
            results.push(record);
            if results.len() == limit {
                break;
            }
        }
        Ok(results)
    }
}

fn contains_lowercase(value: Option<&str>, lower_query: &str) -> bool {
    value.is_some_and(|value| value.to_lowercase().contains(lower_query))
}

fn matches_query(record: &DiscoveredSecretRecord, query: &str) -> bool {
    record.name.to_lowercase().contains(query)
        || record.project_name.to_lowercase().contains(query)
        || contains_lowercase(record.description.as_deref(), query)
        || contains_lowercase(record.owner.as_deref(), query)
        || record.tags.iter().any(|tag| tag.to_lowercase().contains(query))
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let mut matches = vec![false; pattern.chars().count() + 1];
    matches[0] = true;
    for (index, character) in pattern.chars().enumerate() {
        matches[index + 1] = character == '*' && matches[index];
    }

    for character in value.chars() {
        let mut diagonal = matches[0];
        matches[0] = false;
        for (index, token) in pattern.chars().enumerate() {
            let above = matches[index + 1];
            matches[index + 1] = match token {
                '*' => above || matches[index],
                '?' => diagonal,
                literal => diagonal && literal.to_lowercase().eq(character.to_lowercase()),
            };
            diagonal = above;
        }
    }

    matches.last().copied().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::glob_matches;

    #[test]
    fn glob_matches_entire_names_in_polynomial_time() {
        assert!(glob_matches("a?*z", "Aé-bZ"));
        assert!(glob_matches("É?", "é🦀"));
        assert!(!glob_matches("a?z", "AZ"));
        assert!(!glob_matches("a?z", "AAAZ"));
        assert!(!glob_matches("abc", "zabc"));
        assert!(glob_matches("**", ""));
        assert!(glob_matches("", ""));
        assert!(!glob_matches("", "x"));
        let pattern = format!("{}z*", "*a".repeat(30));
        let mut name = "A".repeat(120);
        assert!(!glob_matches(&pattern, &name));
        name.push('Z');
        assert!(glob_matches(&pattern, &name));
    }
}
