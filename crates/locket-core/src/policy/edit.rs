//! Comment-preserving edits of the durable project policy document.

use thiserror::Error;
use toml_edit::{DocumentMut, Item, Table};

use super::{CommandPolicy, CommandSpec, ExternalEnvSource, PolicyDocument, PolicyParseError};

/// Invalid input to a durable project-policy edit.
#[derive(Debug, Error)]
pub enum PolicyEditError {
    /// The source or replacement is not a valid TOML document.
    #[error("project configuration could not be parsed")]
    InvalidDocument,
    /// The resulting command definitions do not pass policy validation.
    #[error(transparent)]
    InvalidPolicy(#[from] PolicyParseError),
}

/// Updates a project document while retaining comments on unchanged content.
///
/// # Errors
///
/// Rejects invalid TOML or a replacement that does not pass policy validation.
pub fn render_policy_document(
    source: &str,
    desired: &toml::Value,
) -> Result<String, PolicyEditError> {
    let previous: toml::Value =
        toml::from_str(source).map_err(|_| PolicyEditError::InvalidDocument)?;
    let rendered = toml::to_string_pretty(desired).map_err(|_| PolicyEditError::InvalidDocument)?;
    PolicyDocument::from_toml_str(&rendered)?;
    let mut document =
        source.parse::<DocumentMut>().map_err(|_| PolicyEditError::InvalidDocument)?;
    let template = rendered.parse::<DocumentMut>().map_err(|_| PolicyEditError::InvalidDocument)?;
    let before = previous.as_table().ok_or(PolicyEditError::InvalidDocument)?;
    let after = desired.as_table().ok_or(PolicyEditError::InvalidDocument)?;
    sync_table(document.as_table_mut(), before, after, template.as_table());
    let result = document.to_string();
    PolicyDocument::from_toml_str(&result)?;
    Ok(result)
}

fn sync_table(target: &mut Table, before: &toml::Table, after: &toml::Table, template: &Table) {
    for key in before.keys().filter(|key| !after.contains_key(*key)) {
        target.remove(key);
    }
    for (key, value) in after {
        if before.get(key) == Some(value) {
            continue;
        }
        let Some(next) = template.get(key) else { continue };
        if let (Some(old_table), Some(new_table), Some(target_table), Some(template_table)) = (
            before.get(key).and_then(toml::Value::as_table),
            value.as_table(),
            target.get_mut(key).and_then(Item::as_table_mut),
            next.as_table(),
        ) {
            sync_table(target_table, old_table, new_table, template_table);
        } else {
            let mut replacement = next.clone();
            if let (Some(old), Some(new)) =
                (target.get(key).and_then(Item::as_value), replacement.as_value_mut())
            {
                *new.decor_mut() = old.decor().clone();
            }
            target.insert(key, replacement);
        }
    }
}

/// Serializes a parsed policy back to its canonical project-file fields.
#[must_use]
pub fn command_policy_value(policy: &CommandPolicy) -> toml::Value {
    let mut table = toml::Table::new();
    match &policy.command {
        CommandSpec::Argv(argv) => {
            table.insert("argv".into(), strings(argv.iter().map(String::as_str)));
        }
        CommandSpec::Shell(shell) => {
            table.insert("shell".into(), toml::Value::String(shell.clone()));
        }
    }
    table.insert(
        "required_secrets".into(),
        strings(policy.required_secrets.iter().map(crate::SecretName::as_str)),
    );
    table.insert(
        "optional_secrets".into(),
        strings(policy.optional_secrets.iter().map(crate::SecretName::as_str)),
    );
    if !policy.shared_secrets.is_empty() {
        table.insert(
            "shared_secrets".into(),
            strings(policy.shared_secrets.iter().map(crate::SecretName::as_str)),
        );
    }
    table.insert("inherit_env".into(), strings(policy.inherit_env.iter().map(String::as_str)));
    table.insert("env_mode".into(), toml::Value::String(policy.env_mode.as_str().into()));
    table.insert("override".into(), toml::Value::String(policy.override_behavior.as_str().into()));
    for (name, value) in [
        ("confirm", policy.confirm),
        ("require_user_verification", policy.require_user_verification),
        ("require_agent", policy.require_agent),
        ("allow_remote_docker", policy.allow_remote_docker),
    ] {
        table.insert(name.into(), toml::Value::Boolean(value));
    }
    table.insert("ttl".into(), toml::Value::String(format!("{}s", policy.ttl.as_secs())));
    let external = policy
        .external_env_sources
        .iter()
        .map(|source| match source {
            ExternalEnvSource::Parent => toml::Value::String("parent".into()),
            ExternalEnvSource::Compose => toml::Value::String("compose".into()),
            ExternalEnvSource::Ide => toml::Value::String("ide".into()),
            ExternalEnvSource::File(path) => toml::Value::Table(toml::Table::from_iter([(
                "file".into(),
                toml::Value::String(path.to_string_lossy().into_owned()),
            )])),
        })
        .collect();
    table.insert("external_env_sources".into(), toml::Value::Array(external));
    toml::Value::Table(table)
}

/// Fingerprints one command and the project rules that can change its access.
/// Unrelated commands and presentation metadata do not invalidate this cache.
///
/// # Errors
/// Returns a serialization error if the metadata cannot be represented as JSON.
pub fn policy_source_digest(
    document: &toml::Value,
    name: &str,
) -> Result<String, serde_json::Error> {
    use sha2::{Digest, Sha256};
    let relevant = serde_json::json!({
        "schema_version": document.get("schema_version"),
        "project_id": document.get("project_id"),
        "command": document.get("commands").and_then(|commands| commands.get(name)),
        "paths": document.get("paths"),
        "secrets": document.get("secrets"),
        "variables": document.get("variables"),
    });
    Ok(data_encoding::HEXLOWER.encode(&Sha256::digest(serde_json::to_vec(&relevant)?)))
}

fn strings<'a>(values: impl IntoIterator<Item = &'a str>) -> toml::Value {
    toml::Value::Array(values.into_iter().map(|value| toml::Value::String(value.into())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secrets_round_trip_and_change_source_digest() -> Result<(), Box<dyn std::error::Error>>
    {
        let source =
            "schema_version=1\n[commands.dev]\nargv=['true']\nrequired_secrets=['LOCAL']\n";
        let mut desired: toml::Value = toml::from_str(source)?;
        let original = policy_source_digest(&desired, "dev")?;
        desired["commands"]["dev"]
            .as_table_mut()
            .ok_or("command table")?
            .insert("shared_secrets".into(), strings(["GLOBAL_TOKEN"]));
        assert_ne!(policy_source_digest(&desired, "dev")?, original);
        let parsed = PolicyDocument::from_toml_value(&desired)?;
        desired["commands"]["dev"] = command_policy_value(&parsed.commands["dev"]);
        let rendered = render_policy_document(source, &desired)?;
        let round_trip = PolicyDocument::from_toml_str(&rendered)?;
        assert_eq!(round_trip.commands["dev"].shared_secrets[0].as_str(), "GLOBAL_TOKEN");
        let rendered: toml::Value = toml::from_str(&rendered)?;
        let digest = policy_source_digest(&rendered, "dev")?;
        let mut changed = rendered;
        changed["commands"]["dev"]["shared_secrets"] = strings(["OTHER_TOKEN"]);
        assert_ne!(policy_source_digest(&changed, "dev")?, digest);
        Ok(())
    }

    #[test]
    fn shared_secrets_cannot_overlap_project_secrets() {
        for field in ["required_secrets", "optional_secrets"] {
            let input = format!(
                "schema_version=1\n[commands.dev]\nargv=['true']\n{field}=['TOKEN']\nshared_secrets=['TOKEN']"
            );
            let error = PolicyDocument::from_toml_str(&input).err();
            assert!(error.is_some_and(|error| error.to_string().contains("both")));
        }
    }

    #[test]
    fn shared_secrets_cannot_overlap_path_scoped_project_secrets() {
        let input = "schema_version=1\n[commands.dev]\nargv=['true']\nshared_secrets=['TOKEN']\n[paths.api]\nrequired_secrets=['TOKEN']";
        assert!(matches!(
            PolicyDocument::from_toml_str(input),
            Err(PolicyParseError::SharedAndProjectSecret { .. })
        ));
    }

    #[test]
    fn source_digest_changes_only_for_relevant_authorization_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut document: toml::Value =
            toml::from_str("schema_version=1\n[commands.dev]\nargv=[\"true\"]")?;
        let original = policy_source_digest(&document, "dev")?;
        document["commands"]
            .as_table_mut()
            .ok_or("commands")?
            .insert("test".into(), toml::from_str::<toml::Value>("argv=[\"false\"]")?);
        assert_eq!(policy_source_digest(&document, "dev")?, original);
        document.as_table_mut().ok_or("root")?.insert(
            "paths".into(),
            toml::from_str::<toml::Value>("[api]\nrequired_secrets=[\"TOKEN\"]")?,
        );
        assert_ne!(policy_source_digest(&document, "dev")?, original);
        Ok(())
    }

    #[test]
    fn policy_edit_preserves_comments_and_unmodified_gates()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = r#"# Shared project configuration
schema_version = 1
name = "sample"

[commands.dev]
argv = ["npm", "run", "dev"] # launch the app
required_secrets = ["DATABASE_URL"] # database access
require_agent = true

[commands.test]
argv = ["cargo", "test"] # keep this command
"#;
        let mut desired: toml::Value = toml::from_str(source)?;
        desired["commands"]["dev"]["required_secrets"] =
            toml::Value::Array(vec![toml::Value::String("API_KEY".into())]);
        let edited = render_policy_document(source, &desired)?;
        assert!(edited.contains("# Shared project configuration"));
        assert!(edited.contains("# database access"));
        assert!(edited.contains("# keep this command"));
        let parsed = crate::PolicyDocument::from_toml_str(&edited)?;
        assert!(parsed.commands["dev"].require_agent);
        assert_eq!(parsed.commands["dev"].required_secrets[0].as_str(), "API_KEY");
        Ok(())
    }

    #[test]
    fn policy_edit_rejects_invalid_configuration() -> Result<(), Box<dyn std::error::Error>> {
        let source = "schema_version = 1\n[commands.dev]\nargv = [\"npm\", \"dev\"]\n";
        let mut desired: toml::Value = toml::from_str(source)?;
        desired["commands"]["dev"]
            .as_table_mut()
            .ok_or("command table")?
            .insert("ttl".into(), toml::Value::String("99h".into()));
        assert!(render_policy_document(source, &desired).is_err());
        Ok(())
    }
}
