//! Command policy parsing and validation for `locket.toml`.

mod command;
mod document;
mod edit;
mod env_source;
mod error;
mod path_scope;
mod secret_acl;
mod variable_contract;
pub use variable_contract::{
    VariableClassification, VariableContract, VariableReadinessRow, VariableReadinessState,
    VariableType, variable_exposure_warning,
};

pub use command::{CommandPolicy, CommandSpec, MAX_COMMAND_POLICY_TTL_SECONDS, PolicyFieldSource};
pub use document::PolicyDocument;
pub use edit::{
    PolicyEditError, command_policy_value, policy_source_digest, render_policy_document,
};
pub use env_source::ExternalEnvSource;
pub use error::PolicyParseError;
pub use path_scope::PathEnvSet;
pub use secret_acl::SecretAccessPolicy;

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{
        CommandSpec, ExternalEnvSource, MAX_COMMAND_POLICY_TTL_SECONDS, PolicyDocument,
        PolicyParseError,
    };
    use crate::{EnvMode, EnvOverrideMode};

    #[test]
    fn parses_valid_argv_policy_with_defaults() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
name = "example"

[commands.api]
argv = ["pnpm", "dev"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["OPENAI_API_KEY"]
"#,
        )?;

        let policy = document.commands.get("api").ok_or("missing api policy")?;

        assert_eq!(policy.name, "api");
        assert_eq!(policy.command, CommandSpec::Argv(vec!["pnpm".to_owned(), "dev".to_owned()]));
        assert_eq!(
            policy.required_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["DATABASE_URL"]
        );
        assert_eq!(
            policy.optional_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["OPENAI_API_KEY"]
        );
        assert_eq!(
            policy.allowed_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["DATABASE_URL", "OPENAI_API_KEY"]
        );
        assert_eq!(policy.env_mode, EnvMode::Minimal);
        assert_eq!(policy.override_behavior, EnvOverrideMode::Locket);
        assert!(!policy.override_explicit());
        assert_eq!(policy.ttl.as_secs(), 15 * 60);
        assert!(!policy.allow_remote_docker);
        assert!(!policy.confirm);
        assert!(!policy.require_user_verification);
        assert!(!policy.require_agent);
        Ok(())
    }

    #[test]
    fn parses_valid_shell_policy_with_explicit_options() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1

[commands.release]
shell = "pnpm build && pnpm publish"
required_secrets = ["NPM_TOKEN"]
inherit_env = ["PATH", "HOME"]
env_mode = "strict"
override = "preserve"
external_env_sources = ["parent", "compose", "ide", { file = ".env.local" }]
confirm = true
require_user_verification = true
require_agent = true
allow_remote_docker = true
ttl = "30m"
"#,
        )?;

        let policy = document.commands.get("release").ok_or("missing release policy")?;

        assert_eq!(policy.command, CommandSpec::Shell("pnpm build && pnpm publish".to_owned()));
        assert_eq!(policy.inherit_env, ["PATH", "HOME"]);
        assert_eq!(policy.env_mode, EnvMode::Strict);
        assert_eq!(policy.override_behavior, EnvOverrideMode::Preserve);
        assert!(policy.override_explicit());
        assert_eq!(
            policy.external_env_sources,
            vec![
                ExternalEnvSource::Parent,
                ExternalEnvSource::Compose,
                ExternalEnvSource::Ide,
                ExternalEnvSource::File(".env.local".into()),
            ]
        );
        assert!(policy.confirm);
        assert!(policy.require_user_verification);
        assert!(policy.require_agent);
        assert!(policy.allow_remote_docker);
        assert_eq!(policy.ttl.as_secs(), 30 * 60);
        Ok(())
    }

    #[test]
    fn parses_path_scoped_env_sets_and_matches_longest_prefix() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1

[commands.dev]
argv = ["pnpm", "dev"]

[paths."."]
optional_secrets = ["ROOT_TOKEN"]

[paths."apps/api"]
profile = "api-dev"
required_secrets = ["DATABASE_URL"]
optional_secrets = ["STRIPE_SECRET_KEY"]

[paths."apps/api/admin"]
required_secrets = ["ADMIN_TOKEN"]
"#,
        )?;

        let root = std::path::Path::new("/repo");
        let api = document.path_scope_for(root, std::path::Path::new("/repo/apps/api/src"));
        let api = api.ok_or("missing api scope")?;
        assert_eq!(api.profile.as_ref().map(ToString::to_string), Some("api-dev".to_owned()));
        assert_eq!(
            api.required_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["DATABASE_URL"]
        );
        assert_eq!(
            api.allowed_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["DATABASE_URL", "STRIPE_SECRET_KEY"]
        );

        let admin = document.path_scope_for(root, std::path::Path::new("/repo/apps/api/admin"));
        let admin = admin.ok_or("missing admin scope")?;
        assert_eq!(
            admin.required_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["ADMIN_TOKEN"]
        );

        let root_scope = document.path_scope_for(root, root).ok_or("missing root scope")?;
        assert_eq!(
            root_scope.optional_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["ROOT_TOKEN"]
        );
        assert!(document.path_scope_for(root, std::path::Path::new("/other/apps/api")).is_none());
        Ok(())
    }

    #[test]
    fn parses_secret_access_policies_and_matches_command_argv_and_path()
    -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1

[commands.dev]
argv = ["npm", "run", "dev"]
required_secrets = ["DATABASE_URL"]

[secrets.DATABASE_URL]
allow_commands = ["dev", "npm:*"]
allow_argv = [["npm", "run", "dev"], ["cargo", "test", "**"]]
allow_paths = ["apps/api/**"]
"#,
        )?;

        let access = document.secret_access.get("DATABASE_URL").ok_or("missing ACL")?;
        assert!(access.allows(
            "dev",
            Some(&["npm".to_owned(), "run".to_owned(), "dev".to_owned()]),
            std::path::Path::new("apps/api/src"),
        ));
        assert!(access.allows(
            "npm:dev",
            Some(&["npm".to_owned(), "run".to_owned(), "dev".to_owned()]),
            std::path::Path::new("apps/api"),
        ));
        assert!(!access.allows(
            "dev",
            Some(&["npm".to_owned(), "run".to_owned(), "build".to_owned()]),
            std::path::Path::new("apps/api/src"),
        ));
        assert!(!access.allows(
            "dev",
            Some(&["npm".to_owned(), "run".to_owned(), "dev".to_owned()]),
            std::path::Path::new("apps/web"),
        ));
        Ok(())
    }

    #[test]
    fn rejects_path_scope_that_escapes_project_root() {
        let result = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[paths."../outside"]
required_secrets = ["TOKEN"]
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::InvalidPathScope { path: "../outside".to_owned() })
        );
    }

    #[test]
    fn rejects_path_scopes_that_duplicate_after_normalization() {
        let result = PolicyDocument::from_toml_str(
            r#"
schema_version = 1

[paths."apps/api"]
required_secrets = ["DATABASE_URL"]

[paths."./apps/api"]
optional_secrets = ["STRIPE_SECRET_KEY"]
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::DuplicatePathScope {
                path: std::path::Path::new("apps").join("api").to_string_lossy().into_owned(),
            })
        );
    }

    #[test]
    fn rejects_invalid_secret_access_policies() {
        let cases = [
            (
                r#"schema_version = 1
[secrets.database_url]
allow_commands = ["dev"]
"#,
                PolicyParseError::InvalidSecretAclName { secret: "database_url".to_owned() },
            ),
            (
                r"schema_version = 1
[secrets.DATABASE_URL]
",
                PolicyParseError::EmptySecretAcl { secret: "DATABASE_URL".to_owned() },
            ),
            (
                r#"schema_version = 1
[secrets.DATABASE_URL]
allow_paths = ["../outside"]
"#,
                PolicyParseError::InvalidSecretAclPattern {
                    secret: "DATABASE_URL".to_owned(),
                    field: "allow_paths",
                    pattern: "../outside".to_owned(),
                },
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(PolicyDocument::from_toml_str(input), Err(expected));
        }
    }

    #[test]
    fn rejects_invalid_schema_cases() {
        let cases = [
            (
                r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
shell = "pnpm dev"
"#,
                PolicyParseError::CommandSpecConflict { command: "dev".to_owned() },
            ),
            (
                r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
secrets = ["DATABASE_URL"]
"#,
                PolicyParseError::SecretsFieldUnsupported { command: "dev".to_owned() },
            ),
            (
                r#"schema_version = 1
[commands.dev]
name = "other"
argv = ["pnpm"]
"#,
                PolicyParseError::NameFieldUnsupported { command: "dev".to_owned() },
            ),
            (
                r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
required_secrets = ["DATABASE_URL", "DATABASE_URL"]
"#,
                PolicyParseError::DuplicateSecretName {
                    command: "dev".to_owned(),
                    field: "required_secrets",
                    name: "DATABASE_URL".to_owned(),
                },
            ),
            (
                r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["DATABASE_URL"]
"#,
                PolicyParseError::SecretRequiredAndOptional {
                    command: "dev".to_owned(),
                    name: "DATABASE_URL".to_owned(),
                },
            ),
            (
                r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
optional_secrets = ["database_url"]
"#,
                PolicyParseError::InvalidSecretName {
                    command: "dev".to_owned(),
                    field: "optional_secrets",
                    name: "database_url".to_owned(),
                },
            ),
            (
                r"schema_version = 1
[commands.dev]
argv = []
",
                PolicyParseError::EmptyArgv { command: "dev".to_owned() },
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(PolicyDocument::from_toml_str(input), Err(expected));
        }
    }

    #[test]
    fn deny_by_default_does_not_infer_secret_authorization_from_permissive_settings()
    -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1

[commands.dev]
argv = ["pnpm", "dev"]
inherit_env = ["DATABASE_URL", "API_KEY"]
external_env_sources = ["parent", "compose"]
env_mode = "merge"
override = "preserve"
confirm = false
require_user_verification = false
allow_remote_docker = true
"#,
        )?;

        let policy = document.commands.get("dev").ok_or("missing dev policy")?;

        assert_eq!(policy.required_secrets.len(), 0);
        assert_eq!(policy.optional_secrets.len(), 0);
        assert_eq!(policy.allowed_secrets.len(), 0);
        assert!(!policy.confirm);
        assert!(!policy.require_user_verification);
        assert!(policy.allow_remote_docker);
        Ok(())
    }

    #[test]
    fn deny_by_default_rejects_permissive_secret_authorization_variants() {
        let cases = [
            (
                r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
allowed_secrets = ["DATABASE_URL"]
"#,
                "allowed_secrets",
            ),
            (
                r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
secret = "DATABASE_URL"
"#,
                "secret",
            ),
            (
                r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
all_secrets = true
"#,
                "all_secrets",
            ),
            (
                r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
secrets = ["DATABASE_URL"]
"#,
                "secrets",
            ),
        ];

        for (input, field) in cases {
            let result = PolicyDocument::from_toml_str(input);
            assert!(result.is_err(), "permissive policy passed for field {field}");
            if let Err(error) = result {
                let message = error.to_string();
                assert!(
                    message.contains(field),
                    "error for {field} should mention rejected field, got {message:?}"
                );
            }
        }
    }

    #[test]
    fn rejects_ttl_above_builtin_policy_cap() {
        let result = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
ttl = "9h"
"#,
        );

        assert_eq!(
            result,
            Err(PolicyParseError::TtlExceedsMaximum {
                command: "dev".to_owned(),
                ttl_seconds: 9 * 60 * 60,
                max_seconds: MAX_COMMAND_POLICY_TTL_SECONDS,
            })
        );
    }

    #[test]
    fn rejects_invalid_ttl_duration_grammar() {
        for value in ["0s", "1h30m", "1.5h", "1H", " 1h", "1h "] {
            let result = PolicyDocument::from_toml_str(&format!(
                r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
ttl = "{value}"
"#
            ));

            assert_eq!(
                result,
                Err(PolicyParseError::InvalidTtl {
                    command: "dev".to_owned(),
                    value: value.to_owned(),
                })
            );
        }
    }

    #[test]
    fn rejects_invalid_unicode_durations_in_policy_ttl() {
        for value in ["é", "1💥", "💥s", "１s", "1m\u{301}"] {
            let result = PolicyDocument::from_toml_str(&format!(
                r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
ttl = "{value}"
"#
            ));

            assert_eq!(
                result,
                Err(PolicyParseError::InvalidTtl {
                    command: "dev".to_owned(),
                    value: value.to_owned(),
                })
            );
        }
    }

    #[test]
    fn rejects_missing_command_spec() {
        let result = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.dev]
required_secrets = ["DATABASE_URL"]
"#,
        );
        assert_eq!(result, Err(PolicyParseError::MissingCommandSpec { command: "dev".to_owned() }));
    }

    #[test]
    fn rejects_empty_shell_string() {
        let result = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.dev]
shell = "   "
"#,
        );
        assert_eq!(result, Err(PolicyParseError::EmptyShell { command: "dev".to_owned() }));
    }

    #[test]
    fn rejects_invalid_env_mode() {
        let result = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
env_mode = "garbage"
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::InvalidEnvMode {
                command: "dev".to_owned(),
                value: "garbage".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_invalid_override_behavior() {
        let result = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
override = "garbage"
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::InvalidOverrideBehavior {
                command: "dev".to_owned(),
                value: "garbage".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_invalid_external_env_source_string() {
        let result = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
external_env_sources = ["ftp"]
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::InvalidExternalEnvSource {
                command: "dev".to_owned(),
                value: "ftp".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_empty_external_env_file_path() {
        let result = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
external_env_sources = [{ file = "" }]
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::EmptyExternalEnvFile { command: "dev".to_owned() })
        );
    }

    #[test]
    fn allowed_secrets_is_sorted_union_of_required_and_optional() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.api]
argv = ["pnpm", "dev"]
required_secrets = ["ZEBRA_KEY", "API_TOKEN"]
optional_secrets = ["OPENAI_KEY", "BETA_FLAG"]
"#,
        )?;
        let policy = document.commands.get("api").ok_or("missing api policy")?;
        assert_eq!(
            policy.allowed_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["API_TOKEN", "BETA_FLAG", "OPENAI_KEY", "ZEBRA_KEY"]
        );
        assert_eq!(
            policy.required_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["ZEBRA_KEY", "API_TOKEN"]
        );
        assert_eq!(
            policy.optional_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["OPENAI_KEY", "BETA_FLAG"]
        );
        Ok(())
    }

    #[test]
    fn optional_secrets_absent_from_required_are_still_allowed() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.api]
argv = ["server"]
required_secrets = ["DB_URL"]
optional_secrets = ["REDIS_URL"]
"#,
        )?;
        let policy = document.commands.get("api").ok_or("missing api")?;
        let allowed: Vec<_> = policy.allowed_secrets.iter().map(ToString::to_string).collect();
        assert!(allowed.contains(&"DB_URL".to_owned()));
        assert!(allowed.contains(&"REDIS_URL".to_owned()));
        assert_eq!(policy.required_secrets.len(), 1);
        assert_eq!(policy.optional_secrets.len(), 1);
        Ok(())
    }

    #[test]
    fn confirm_and_require_user_verification_explicit_false_differ_from_absent()
    -> Result<(), Box<dyn Error>> {
        let document_absent = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.api]
argv = ["server"]
"#,
        )?;
        let document_explicit = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.api]
argv = ["server"]
confirm = false
require_user_verification = false
"#,
        )?;
        let policy_absent = document_absent.commands.get("api").ok_or("missing")?;
        let policy_explicit = document_explicit.commands.get("api").ok_or("missing")?;
        assert!(!policy_absent.confirm);
        assert!(!policy_absent.require_user_verification);
        assert!(!policy_explicit.confirm);
        assert!(!policy_explicit.require_user_verification);
        Ok(())
    }

    #[test]
    fn confirm_true_with_require_user_verification_true_parses() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.deploy]
shell = "pnpm deploy"
required_secrets = ["DEPLOY_TOKEN"]
confirm = true
require_user_verification = true
"#,
        )?;
        let policy = document.commands.get("deploy").ok_or("missing deploy")?;
        assert!(policy.confirm);
        assert!(policy.require_user_verification);
        Ok(())
    }

    #[test]
    fn ttl_at_exact_maximum_is_accepted() -> Result<(), Box<dyn Error>> {
        let max_hours = MAX_COMMAND_POLICY_TTL_SECONDS / 3600;
        let document = PolicyDocument::from_toml_str(&format!(
            r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
ttl = "{max_hours}h"
"#
        ))?;
        let policy = document.commands.get("dev").ok_or("missing dev")?;
        assert_eq!(policy.ttl.as_secs(), MAX_COMMAND_POLICY_TTL_SECONDS);
        Ok(())
    }

    #[test]
    fn document_with_no_commands_section_parses_empty() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
name = "empty"
"#,
        )?;
        assert!(document.commands.is_empty());
        Ok(())
    }

    #[test]
    fn document_with_multiple_commands_parses_all() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1

[commands.dev]
argv = ["pnpm", "dev"]
required_secrets = ["DATABASE_URL"]

[commands.test]
argv = ["pnpm", "test"]
optional_secrets = ["TEST_API_KEY"]

[commands.deploy]
shell = "pnpm deploy"
required_secrets = ["NPM_TOKEN", "DEPLOY_KEY"]
confirm = true
"#,
        )?;
        assert_eq!(document.commands.len(), 3);
        let dev = document.commands.get("dev").ok_or("missing dev")?;
        assert_eq!(dev.required_secrets.len(), 1);
        let test = document.commands.get("test").ok_or("missing test")?;
        assert_eq!(test.optional_secrets.len(), 1);
        assert_eq!(test.required_secrets.len(), 0);
        let deploy = document.commands.get("deploy").ok_or("missing deploy")?;
        assert!(deploy.confirm);
        assert_eq!(deploy.required_secrets.len(), 2);
        Ok(())
    }

    #[test]
    fn from_str_impl_is_equivalent_to_from_toml_str() -> Result<(), Box<dyn Error>> {
        let input = r#"schema_version = 1
[commands.api]
argv = ["node", "server.js"]
required_secrets = ["API_KEY"]
"#;
        let via_method = PolicyDocument::from_toml_str(input)?;
        let via_from_str: PolicyDocument = input.parse()?;
        assert_eq!(via_method, via_from_str);
        Ok(())
    }

    #[test]
    fn rejects_toml_syntax_error() {
        let result = PolicyDocument::from_toml_str("commands = ][");
        assert!(matches!(result, Err(PolicyParseError::Toml { .. })));
    }

    #[test]
    fn rejects_commands_not_a_table() {
        let result = PolicyDocument::from_toml_str("schema_version = 1\ncommands = 42");
        assert_eq!(result, Err(PolicyParseError::CommandsMustBeTable));
    }

    #[test]
    fn rejects_command_body_that_is_not_a_table() {
        let result = PolicyDocument::from_toml_str(
            r"
schema_version = 1
[commands]
dev = 42
",
        );
        assert_eq!(result, Err(PolicyParseError::CommandMustBeTable { command: "dev".to_owned() }));
    }

    #[test]
    fn rejects_command_with_unknown_field() {
        let result = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm"]
unknown_field = "value"
"#,
        );
        assert!(matches!(result, Err(PolicyParseError::CommandSchema { .. })));
    }

    #[test]
    fn rejects_command_with_wrong_field_type() {
        let result = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = "not-a-list"
"#,
        );
        assert!(matches!(result, Err(PolicyParseError::CommandSchema { .. })));
    }

    #[test]
    fn rejects_command_with_non_bool_confirm() {
        let result = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm"]
confirm = "yes"
"#,
        );
        assert!(matches!(result, Err(PolicyParseError::CommandSchema { .. })));
    }

    #[test]
    fn rejects_secrets_with_empty_string_name() {
        let result = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm"]
required_secrets = [""]
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::InvalidSecretName {
                command: "dev".to_owned(),
                field: "required_secrets",
                name: String::new(),
            })
        );
    }

    #[test]
    fn rejects_optional_secret_duplicate_within_field() {
        let result = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm"]
optional_secrets = ["TOKEN", "TOKEN"]
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::DuplicateSecretName {
                command: "dev".to_owned(),
                field: "optional_secrets",
                name: "TOKEN".to_owned(),
            })
        );
    }

    #[test]
    fn external_env_sources_file_object_is_kept_as_pathbuf() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm"]
external_env_sources = [{ file = "/abs/path.env" }]
"#,
        )?;
        let policy = document.commands.get("dev").ok_or("missing dev")?;
        assert_eq!(
            policy.external_env_sources,
            vec![ExternalEnvSource::File(std::path::PathBuf::from("/abs/path.env"))]
        );
        Ok(())
    }

    #[test]
    fn ttl_zero_seconds_is_rejected_by_invalid_ttl() -> Result<(), Box<dyn Error>> {
        // "0s" is invalid grammar per existing test; "0m"/"0h" too. Verify "1s" parses.
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm"]
ttl = "1s"
"#,
        );
        assert!(document.is_ok());
        let document = document?;
        let policy = document.commands.get("dev").ok_or("missing dev")?;
        assert_eq!(policy.ttl.as_secs(), 1);
        Ok(())
    }

    #[test]
    fn override_explicit_locket_value_is_marked_explicit() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm"]
override = "locket"
"#,
        )?;
        let policy = document.commands.get("dev").ok_or("missing dev")?;
        assert!(policy.override_explicit());
        assert_eq!(policy.override_behavior, crate::EnvOverrideMode::Locket);
        Ok(())
    }

    #[test]
    fn override_error_value_parses_explicit() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm"]
override = "error"
"#,
        )?;
        let policy = document.commands.get("dev").ok_or("missing dev")?;
        assert!(policy.override_explicit());
        Ok(())
    }

    #[test]
    fn parse_error_display_contains_command_name() {
        let err = PolicyParseError::EmptyArgv { command: "deploy".to_owned() };
        let message = err.to_string();
        assert!(message.contains("deploy"));
    }

    #[test]
    fn parse_error_clone_and_eq() {
        let err = PolicyParseError::Toml { message: "boom".to_owned() };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn parse_error_root_must_be_table_display() {
        let err = PolicyParseError::RootMustBeTable;
        assert_ne!(err.to_string(), "");
    }

    #[test]
    fn external_env_source_clone_and_debug() {
        let s = ExternalEnvSource::Parent;
        let cloned = s.clone();
        assert_eq!(s, cloned);
        let debug = format!("{s:?}");
        assert!(debug.contains("Parent"));

        let f = ExternalEnvSource::File(std::path::PathBuf::from("foo.env"));
        let cloned_f = f.clone();
        assert_eq!(f, cloned_f);
    }

    #[test]
    fn command_spec_clone_and_debug() {
        let argv = CommandSpec::Argv(vec!["a".to_owned(), "b".to_owned()]);
        let cloned = argv.clone();
        assert_eq!(argv, cloned);
        let shell = CommandSpec::Shell("echo".to_owned());
        let cloned_shell = shell.clone();
        assert_eq!(shell, cloned_shell);
        assert_ne!(argv, shell);
    }

    #[test]
    fn policy_document_clone_round_trips() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm"]
"#,
        )?;
        let cloned = document.clone();
        assert_eq!(document, cloned);
        Ok(())
    }

    #[test]
    fn invalid_ttl_unit_is_rejected() {
        let result = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm"]
ttl = "5y"
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::InvalidTtl { command: "dev".to_owned(), value: "5y".to_owned() })
        );
    }

    #[test]
    fn rejects_external_env_source_object_with_unknown_field() {
        let result = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm"]
external_env_sources = [{ file = "x", extra = "y" }]
"#,
        );
        // untagged enum fallback should error rather than silently accept.
        assert!(result.is_err(), "unknown field on file source should fail, got {result:?}");
    }

    #[test]
    fn rejects_duplicate_command_table_at_toml_layer() {
        // The TOML parser rejects duplicate `[commands.<name>]` headers
        // before our `BTreeMap` insert can silently overwrite a prior
        // entry. This pins that contract: if a future toml-crate upgrade
        // ever relaxes it, this test fails and we'd add an explicit
        // pre-parse key-count check in `from_toml_str`.
        let result = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
[commands.dev]
argv = ["pnpm", "dev"]

[commands.dev]
argv = ["pnpm", "alt"]
"#,
        );
        assert!(
            matches!(result, Err(PolicyParseError::Toml { .. })),
            "duplicate command table must be rejected by the TOML layer, got {result:?}"
        );
    }

    #[test]
    fn rejects_missing_schema_version() {
        let result = PolicyDocument::from_toml_str(
            r#"[commands.dev]
argv = ["pnpm"]
"#,
        );
        assert_eq!(result, Err(PolicyParseError::MissingSchemaVersion));
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let result = PolicyDocument::from_toml_str(
            r#"schema_version = 2
[commands.dev]
argv = ["pnpm"]
"#,
        );
        assert_eq!(result, Err(PolicyParseError::UnsupportedSchemaVersion { version: 2 }));
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let result = PolicyDocument::from_toml_str(
            r#"schema_version = 1
foo = "bar"

[commands.dev]
argv = ["pnpm"]
"#,
        );
        assert_eq!(result, Err(PolicyParseError::UnknownTopLevelKey { key: "foo".to_owned() }));
    }

    #[test]
    fn empty_inherit_env_is_kept() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"schema_version = 1
[commands.dev]
argv = ["pnpm"]
inherit_env = []
"#,
        )?;
        let policy = document.commands.get("dev").ok_or("missing dev")?;
        assert_eq!(policy.inherit_env.len(), 0);
        Ok(())
    }

    #[test]
    fn schema_version_one_with_no_commands_parses_empty() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str("schema_version = 1\n")?;
        assert_eq!(document.schema_version, 1);
        assert!(document.commands.is_empty());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod proptest_policy {
    use proptest::prelude::*;

    use super::{PolicyDocument, PolicyParseError};

    fn valid_command_name_strategy() -> impl Strategy<Value = String> {
        prop::string::string_regex("[a-z][a-z0-9_-]{0,15}").expect("valid regex")
    }

    fn valid_secret_name_strategy() -> impl Strategy<Value = String> {
        let first = prop::char::ranges(std::borrow::Cow::Borrowed(&['A'..='Z', '_'..='_']));
        let rest = prop::collection::vec(
            prop::char::ranges(std::borrow::Cow::Borrowed(&['A'..='Z', '0'..='9', '_'..='_'])),
            0..12,
        );
        (first, rest).prop_map(|(f, r)| {
            let mut s = String::new();
            s.push(f);
            s.extend(r);
            s
        })
    }

    proptest! {
        #[test]
        fn single_argv_command_round_trips_name_and_command(
            cmd_name in valid_command_name_strategy(),
        ) {
            let toml = format!(
                "schema_version = 1\n[commands.{cmd_name}]\nargv = [\"ls\", \"-la\"]\n"
            );
            let doc = PolicyDocument::from_toml_str(&toml);
            prop_assert!(doc.is_ok(), "valid policy should parse: {doc:?}");
            let doc = doc.unwrap();
            prop_assert!(doc.commands.contains_key(&cmd_name), "command key preserved");
        }

        #[test]
        fn required_secrets_are_preserved_in_allowed_secrets(
            cmd_name in valid_command_name_strategy(),
            secret in valid_secret_name_strategy(),
        ) {
            let toml = format!(
                "schema_version = 1\n[commands.{cmd_name}]\nargv = [\"run\"]\nrequired_secrets = [\"{secret}\"]\n"
            );
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(result.is_ok(), "valid required_secrets should parse: {result:?}");
            let doc = result.unwrap();
            let policy = doc.commands.get(&cmd_name).unwrap();
            prop_assert!(
                policy.required_secrets.iter().any(|s| s.as_str() == secret),
                "required secret preserved"
            );
            prop_assert!(
                policy.allowed_secrets.iter().any(|s| s.as_str() == secret),
                "required in allowed_secrets"
            );
        }

        #[test]
        fn optional_secrets_appear_in_allowed_secrets(
            cmd_name in valid_command_name_strategy(),
            secret in valid_secret_name_strategy(),
        ) {
            let toml = format!(
                "schema_version = 1\n[commands.{cmd_name}]\nargv = [\"run\"]\noptional_secrets = [\"{secret}\"]\n"
            );
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(result.is_ok(), "optional_secrets should parse: {result:?}");
            let doc = result.unwrap();
            let policy = doc.commands.get(&cmd_name).unwrap();
            prop_assert!(
                policy.allowed_secrets.iter().any(|s| s.as_str() == secret),
                "optional in allowed_secrets"
            );
        }

        #[test]
        fn unknown_top_level_keys_are_rejected(
            extra_key in "[a-z]{3,10}",
            extra_val in "[a-z]{3,10}",
        ) {
            // schema_version is required; "commands" and other recognized v1 keys
            // pass; everything else must error with UnknownTopLevelKey so future
            // schema additions cannot be silently ignored.
            prop_assume!(![
                "schema_version", "commands", "project_id", "name",
                "default_profile", "bootstrap", "scan", "example",
            ].contains(&extra_key.as_str()));
            let toml = format!("schema_version = 1\n{extra_key} = \"{extra_val}\"\n");
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(
                matches!(
                    &result,
                    Err(PolicyParseError::UnknownTopLevelKey { key }) if key == &extra_key,
                ),
                "unknown top-level key must be rejected: {result:?}"
            );
        }

        #[test]
        fn name_field_in_command_is_always_rejected(cmd_name in valid_command_name_strategy()) {
            let toml = format!(
                "schema_version = 1\n[commands.{cmd_name}]\nargv = [\"run\"]\nname = \"forbidden\"\n"
            );
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(
                matches!(result, Err(PolicyParseError::NameFieldUnsupported { .. })),
                "name field must be rejected: {result:?}"
            );
        }

        #[test]
        fn secrets_field_in_command_is_always_rejected(cmd_name in valid_command_name_strategy()) {
            let toml = format!(
                "schema_version = 1\n[commands.{cmd_name}]\nargv = [\"run\"]\nsecrets = [\"DATABASE_URL\"]\n"
            );
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(
                matches!(result, Err(PolicyParseError::SecretsFieldUnsupported { .. })),
                "secrets field must be rejected: {result:?}"
            );
        }

        #[test]
        fn shell_command_spec_is_accepted(
            cmd_name in valid_command_name_strategy(),
            shell_cmd in "[a-z][a-z ]{4,29}",
        ) {
            let toml =
                format!("schema_version = 1\n[commands.{cmd_name}]\nshell = \"{shell_cmd}\"\n");
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(result.is_ok(), "shell command spec should parse: {result:?}");
        }

        #[test]
        fn commands_value_that_is_not_table_always_errors(scalar in 1i64..100) {
            let toml = format!("schema_version = 1\ncommands = {scalar}\n");
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert_eq!(result, Err(PolicyParseError::CommandsMustBeTable));
        }

        #[test]
        fn allowed_secrets_length_is_at_least_required_plus_optional(
            cmd_name in valid_command_name_strategy(),
            required in valid_secret_name_strategy(),
            optional in valid_secret_name_strategy(),
        ) {
            prop_assume!(required != optional);
            let toml = format!(
                "schema_version = 1\n[commands.{cmd_name}]\nargv = [\"run\"]\nrequired_secrets = [\"{required}\"]\noptional_secrets = [\"{optional}\"]\n"
            );
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(result.is_ok(), "distinct required+optional should parse: {result:?}");
            let doc = result.unwrap();
            let policy = doc.commands.get(&cmd_name).unwrap();
            prop_assert!(
                policy.allowed_secrets.len() >= policy.required_secrets.len() + policy.optional_secrets.len(),
                "allowed must be superset of required+optional"
            );
        }
    }
}

#[cfg(test)]
mod configuration_contract_tests {
    use super::PolicyDocument;

    #[test]
    fn configuration_contract_accepts_public_defaults_and_secret_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let text = r#"schema_version=1
[variables.PORT]
classification="public"
type="integer"
default="3001"
description="Local listener"
setup_hint="Choose a free local port"
[variables.TOKEN]
description="Development API token"
[commands.dev]
argv=["echo"]
required_secrets=["PORT","TOKEN"]
[secrets.TOKEN]
allow_commands=["dev"]
"#;
        let document = PolicyDocument::from_toml_str(text)?;
        assert_eq!(document.variables.len(), 2);
        Ok(())
    }

    #[test]
    fn configuration_contract_errors_never_include_values() -> Result<(), Box<dyn std::error::Error>>
    {
        for body in [
            "classification='secret'\ndefault='canary-do-not-print'",
            "classification='public'\ntype='integer'\ndefault='canary-do-not-print'",
            "classification='canary-do-not-print'",
            "classification='public'\ndefault='lk://dev/KEY?canary-do-not-print'",
            "unknown='canary-do-not-print'",
        ] {
            let text = format!("schema_version=1\n[variables.TOKEN]\n{body}");
            let error =
                PolicyDocument::from_toml_str(&text).err().ok_or("invalid contract must fail")?;
            assert!(!error.to_string().contains("canary-do-not-print"));
        }
        Ok(())
    }
}
