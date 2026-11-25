//! Docker and Compose helpers for Locket.

// age 0.11 enters through locket-core and carries older transitive crates
// alongside workspace versions. The sealed-bundle dependency owns that skew.
#![allow(clippy::multiple_crate_versions)]

use locket_core::EnvMap;
use thiserror::Error;

/// Default policy for remote Docker contexts.
pub const DEFAULT_ALLOW_REMOTE_DOCKER: bool = false;

/// Docker endpoint class for local-secret injection policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerContextClass {
    /// Local Docker daemon or platform pipe/socket.
    Local,
    /// Remote Docker endpoint such as TCP or SSH.
    Remote,
    /// Endpoint could not be classified from available metadata.
    Unknown,
}

/// Docker helper delivery mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerDeliveryMode {
    /// Values stay in the Docker client process environment and Docker receives
    /// only variable names as command-line flags.
    EnvironmentNames,
    /// Values are written to an ephemeral env file by a higher layer.
    EphemeralEnvFile,
}

/// Prepared Docker invocation metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerInjectionPlan {
    /// Original Docker argv plus safe env-name flags.
    pub argv: Vec<String>,
    /// Environment supplied to the Docker or Compose client process.
    pub env: EnvMap,
    /// Secret names injected into `env`.
    pub injected_names: Vec<String>,
    /// Delivery mode used by the helper.
    pub delivery_mode: DockerDeliveryMode,
    /// Classified Docker endpoint.
    pub context_class: DockerContextClass,
}

/// Error returned while preparing Docker/Compose injection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DockerError {
    /// The target Docker context is remote and policy did not allow it.
    #[error("remote Docker context is not allowed for secret injection")]
    RemoteContextDenied,
    /// The endpoint cannot be safely classified, even with remote permission.
    #[error("Docker endpoint is unknown or malformed; secret injection is denied")]
    UnknownEndpoint,
    /// A secret would change Docker's destination or connection configuration.
    #[error(
        "Docker routing variable {name} cannot be injected as a secret; inherit it explicitly instead"
    )]
    RoutingSecretDenied {
        /// Variable name only; never its value.
        name: String,
    },
    /// A secret name is unsafe as an environment variable or Docker env argument.
    #[error("invalid Docker environment variable name")]
    InvalidEnvironmentName,
    /// No Docker or Compose argv was supplied.
    #[error("empty Docker command")]
    EmptyCommand,
    /// The argv does not look like the expected Docker command family.
    #[error("unexpected Docker command: {program}")]
    UnexpectedCommand {
        /// First argv element.
        program: String,
    },
}

/// Classifies a Docker endpoint string such as `DOCKER_HOST`.
///
/// `None` represents the platform-local default for callers that have already
/// resolved context selection. Empty, malformed, and unrecognized endpoints
/// are unknown. An inherited file descriptor cannot establish locality.
#[must_use]
pub fn classify_docker_endpoint(endpoint: Option<&str>) -> DockerContextClass {
    let Some(endpoint) = endpoint else {
        return DockerContextClass::Local;
    };
    if endpoint.trim() != endpoint || endpoint.chars().any(char::is_control) {
        return DockerContextClass::Unknown;
    }
    let normalized = endpoint.to_ascii_lowercase();
    let Some((scheme, address)) = normalized.split_once("://") else {
        return DockerContextClass::Unknown;
    };
    match scheme {
        "unix" if address.starts_with('/') && address.len() > 1 => DockerContextClass::Local,
        "npipe" => classify_named_pipe(address),
        "tcp" | "ssh" | "http" | "https" if valid_remote_address(scheme, address) => {
            DockerContextClass::Remote
        }
        _ => DockerContextClass::Unknown,
    }
}

fn classify_named_pipe(address: &str) -> DockerContextClass {
    let address = address.replace('\\', "/");
    let Some((server, pipe)) = address.strip_prefix("//").and_then(|path| path.split_once('/'))
    else {
        return DockerContextClass::Unknown;
    };
    let Some(name) = pipe.strip_prefix("pipe/") else {
        return DockerContextClass::Unknown;
    };
    if name.is_empty() || name.split('/').any(|part| matches!(part, "" | "." | "..")) {
        return DockerContextClass::Unknown;
    }
    if server == "." {
        DockerContextClass::Local
    } else if valid_host_name(server) {
        DockerContextClass::Remote
    } else {
        DockerContextClass::Unknown
    }
}

fn valid_host_name(host: &str) -> bool {
    host.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn valid_remote_address(scheme: &str, address: &str) -> bool {
    if address.chars().any(char::is_whitespace) || address.contains(['?', '#', '\\']) {
        return false;
    }
    let (authority, path) =
        address.split_once('/').map_or((address, None), |(host, path)| (host, Some(path)));
    if scheme == "tcp" && path.is_some() {
        return false;
    }
    let authority = if let Some((user, host)) = authority.split_once('@') {
        if scheme != "ssh" || !valid_host_name(user) {
            return false;
        }
        host
    } else {
        authority
    };
    let port = if let Some(ipv6) = authority.strip_prefix('[') {
        let Some((host, suffix)) = ipv6.split_once(']') else {
            return false;
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        if suffix.is_empty() {
            return true;
        }
        let Some(port) = suffix.strip_prefix(':') else {
            return false;
        };
        Some(port)
    } else {
        let (host, port) =
            authority.split_once(':').map_or((authority, None), |(host, port)| (host, Some(port)));
        if !valid_host_name(host) {
            return false;
        }
        port
    };
    port.is_none_or(|port| {
        port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port > 0)
    })
}

/// Rejects secret names that Docker uses to select its endpoint or configuration.
/// Call this before decryption when the policy's names are available separately.
///
/// # Errors
///
/// Returns [`DockerError::RoutingSecretDenied`] for a Docker routing variable
/// or [`DockerError::InvalidEnvironmentName`] for an invalid name.
pub fn validate_injected_names<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<(), DockerError> {
    const ROUTING_VARIABLES: &[&str] = &[
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "HOME",
        "USERPROFILE",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
    ];
    for name in names {
        if ROUTING_VARIABLES.iter().any(|reserved| name.eq_ignore_ascii_case(reserved)) {
            return Err(DockerError::RoutingSecretDenied { name: name.to_owned() });
        }
        if name.is_empty() || name.starts_with('-') || name.contains(['=', '\0']) {
            return Err(DockerError::InvalidEnvironmentName);
        }
    }
    Ok(())
}

/// Prepares a `docker run` invocation so Docker reads secrets from its own
/// process environment by name.
///
/// Secret values are placed only in the returned environment map. The returned
/// argv contains `--env KEY` pairs, never `KEY=value`.
///
/// # Errors
///
/// Returns [`DockerError::EmptyCommand`] for empty argv,
/// [`DockerError::UnexpectedCommand`] when the command is not `docker`, and
/// [`DockerError::RemoteContextDenied`] when a remote endpoint is detected
/// without explicit policy permission. Unknown endpoints and routing secrets
/// return [`DockerError::UnknownEndpoint`] and [`DockerError::RoutingSecretDenied`].
/// Invalid secret names return [`DockerError::InvalidEnvironmentName`].
pub fn prepare_docker_run(
    argv: &[String],
    base_env: &EnvMap,
    locket_env: &EnvMap,
    endpoint: Option<&str>,
    allow_remote: bool,
) -> Result<DockerInjectionPlan, DockerError> {
    let context_class = validate_remote(endpoint, allow_remote)?;
    validate_injected_names(locket_env.keys().map(String::as_str))?;
    validate_program(argv, "docker")?;
    validate_subcommand(argv, "run")?;

    let mut prepared_argv = Vec::with_capacity(argv.len() + locket_env.len() * 2);
    prepared_argv.extend(argv.iter().take(2).cloned());
    let injected_names = sorted_names(locket_env);
    for name in &injected_names {
        prepared_argv.push("--env".to_owned());
        prepared_argv.push(name.clone());
    }
    prepared_argv.extend(argv.iter().skip(2).cloned());

    Ok(DockerInjectionPlan {
        argv: prepared_argv,
        env: merged_env(base_env, locket_env),
        injected_names,
        delivery_mode: DockerDeliveryMode::EnvironmentNames,
        context_class,
    })
}

/// Prepares a Docker Compose invocation by injecting values into the Compose
/// client process environment.
///
/// # Errors
///
/// Returns [`DockerError::EmptyCommand`] for empty argv,
/// [`DockerError::UnexpectedCommand`] when the command is not `docker`, and
/// [`DockerError::RemoteContextDenied`] when a remote endpoint is detected
/// without explicit policy permission. Unknown endpoints and routing secrets
/// return [`DockerError::UnknownEndpoint`] and [`DockerError::RoutingSecretDenied`].
/// Invalid secret names return [`DockerError::InvalidEnvironmentName`].
pub fn prepare_compose(
    argv: &[String],
    base_env: &EnvMap,
    locket_env: &EnvMap,
    endpoint: Option<&str>,
    allow_remote: bool,
) -> Result<DockerInjectionPlan, DockerError> {
    let context_class = validate_remote(endpoint, allow_remote)?;
    validate_injected_names(locket_env.keys().map(String::as_str))?;
    validate_program(argv, "docker")?;
    validate_subcommand(argv, "compose")?;
    let injected_names = sorted_names(locket_env);

    Ok(DockerInjectionPlan {
        argv: argv.to_vec(),
        env: merged_env(base_env, locket_env),
        injected_names,
        delivery_mode: DockerDeliveryMode::EnvironmentNames,
        context_class,
    })
}

fn validate_remote(
    endpoint: Option<&str>,
    allow_remote: bool,
) -> Result<DockerContextClass, DockerError> {
    match classify_docker_endpoint(endpoint) {
        DockerContextClass::Unknown => Err(DockerError::UnknownEndpoint),
        DockerContextClass::Remote if !allow_remote => Err(DockerError::RemoteContextDenied),
        class => Ok(class),
    }
}

fn validate_program(argv: &[String], expected: &str) -> Result<(), DockerError> {
    let Some(program) = argv.first() else {
        return Err(DockerError::EmptyCommand);
    };
    if program != expected {
        return Err(DockerError::UnexpectedCommand { program: program.clone() });
    }
    Ok(())
}

fn validate_subcommand(argv: &[String], expected: &str) -> Result<(), DockerError> {
    let Some(subcommand) = argv.get(1) else {
        return Err(DockerError::UnexpectedCommand { program: argv[0].clone() });
    };
    if subcommand != expected {
        return Err(DockerError::UnexpectedCommand {
            program: format!("{} {subcommand}", argv[0]),
        });
    }
    Ok(())
}

fn merged_env(base_env: &EnvMap, locket_env: &EnvMap) -> EnvMap {
    let mut env = base_env.clone();
    env.extend(locket_env.iter().map(|(name, value)| (name.clone(), value.clone())));
    env
}

fn sorted_names(locket_env: &EnvMap) -> Vec<String> {
    locket_env.keys().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::{
        DockerContextClass, DockerDeliveryMode, DockerError, classify_docker_endpoint,
        prepare_compose, prepare_docker_run,
    };
    use locket_core::EnvMap;

    fn env(values: &[(&str, &str)]) -> EnvMap {
        values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), locket_core::env_value(*value)))
            .collect()
    }

    #[test]
    fn classifies_local_and_remote_endpoints() {
        assert_eq!(classify_docker_endpoint(None), DockerContextClass::Local);
        assert_eq!(classify_docker_endpoint(Some("   ")), DockerContextClass::Unknown);
        assert_eq!(
            classify_docker_endpoint(Some("unix:///var/run/docker.sock")),
            DockerContextClass::Local
        );
        assert_eq!(
            classify_docker_endpoint(Some("npipe:////./pipe/docker_engine")),
            DockerContextClass::Local
        );
        assert_eq!(
            classify_docker_endpoint(Some("tcp://example.com:2376")),
            DockerContextClass::Remote
        );
        assert_eq!(classify_docker_endpoint(Some("ssh://builder")), DockerContextClass::Remote);
        assert_eq!(
            classify_docker_endpoint(Some("HTTPS://builder.example")),
            DockerContextClass::Remote
        );
        assert_eq!(classify_docker_endpoint(Some("desktop-linux")), DockerContextClass::Unknown);
    }

    #[test]
    fn docker_run_uses_env_names_without_values_in_argv() -> Result<(), DockerError> {
        let argv = vec!["docker".to_owned(), "run".to_owned(), "postgres".to_owned()];
        let locket_env = env(&[("DATABASE_URL", "postgres://secret"), ("API_KEY", "hidden")]);

        let plan = prepare_docker_run(&argv, &EnvMap::new(), &locket_env, None, false)?;

        assert_eq!(plan.delivery_mode, DockerDeliveryMode::EnvironmentNames);
        assert_eq!(plan.injected_names, ["API_KEY", "DATABASE_URL"]);
        assert_eq!(
            plan.env.get("DATABASE_URL").map(|value| value.as_str()),
            Some("postgres://secret")
        );
        assert!(plan.argv.windows(2).any(|pair| pair == ["--env", "API_KEY"]));
        assert!(plan.argv.windows(2).any(|pair| pair == ["--env", "DATABASE_URL"]));
        assert!(!plan.argv.iter().any(|item| item.contains("postgres://secret")));
        assert!(!plan.argv.iter().any(|item| item.contains("hidden")));
        Ok(())
    }

    #[test]
    fn docker_helpers_reject_invalid_environment_names() {
        for name in ["", "INVALID=NAME", "INVALID\0NAME", "-INVALID"] {
            for subcommand in ["run", "compose"] {
                let prepare =
                    if subcommand == "run" { prepare_docker_run } else { prepare_compose };
                let argv = ["docker".to_owned(), subcommand.to_owned()];
                assert_eq!(
                    prepare(&argv, &EnvMap::new(), &env(&[(name, "value")]), None, false),
                    Err(DockerError::InvalidEnvironmentName)
                );
            }
        }
    }

    #[test]
    fn compose_injects_environment_without_adding_env_flags() -> Result<(), DockerError> {
        let argv = vec!["docker".to_owned(), "compose".to_owned(), "up".to_owned()];
        let base_env = env(&[("PATH", "/bin")]);
        let locket_env = env(&[("DATABASE_URL", "postgres://secret")]);

        let plan = prepare_compose(&argv, &base_env, &locket_env, None, false)?;

        assert_eq!(plan.argv, argv);
        assert_eq!(plan.env.get("PATH").map(|value| value.as_str()), Some("/bin"));
        assert_eq!(
            plan.env.get("DATABASE_URL").map(|value| value.as_str()),
            Some("postgres://secret")
        );
        assert_eq!(plan.injected_names, ["DATABASE_URL"]);
        Ok(())
    }

    #[test]
    fn remote_context_requires_explicit_policy() {
        let argv = vec!["docker".to_owned(), "run".to_owned(), "app".to_owned()];
        let result = prepare_docker_run(
            &argv,
            &EnvMap::new(),
            &EnvMap::new(),
            Some("tcp://host:2376"),
            false,
        );

        assert_eq!(result, Err(DockerError::RemoteContextDenied));
    }

    #[test]
    fn allowed_remote_context_is_recorded_in_plan() -> Result<(), DockerError> {
        let argv = vec!["docker".to_owned(), "run".to_owned(), "app".to_owned()];

        let plan =
            prepare_docker_run(&argv, &EnvMap::new(), &EnvMap::new(), Some("ssh://builder"), true)?;

        assert_eq!(plan.context_class, DockerContextClass::Remote);
        Ok(())
    }

    #[test]
    fn locket_environment_overrides_base_environment() -> Result<(), DockerError> {
        let argv =
            vec!["docker".to_owned(), "compose".to_owned(), "run".to_owned(), "app".to_owned()];
        let base_env = env(&[("TOKEN", "base"), ("PATH", "/bin")]);
        let locket_env = env(&[("TOKEN", "locket")]);

        let plan = prepare_compose(&argv, &base_env, &locket_env, None, false)?;

        assert_eq!(plan.env.get("TOKEN").map(|value| value.as_str()), Some("locket"));
        assert_eq!(plan.env.get("PATH").map(|value| value.as_str()), Some("/bin"));
        assert_eq!(plan.injected_names, ["TOKEN"]);
        Ok(())
    }

    #[test]
    fn docker_canary_values_stay_out_of_argv_and_metadata() -> Result<(), DockerError> {
        let canary = "lk-canary-docker-value-1234567890abcdef";
        let argv = vec!["docker".to_owned(), "run".to_owned(), "--rm".to_owned(), "app".to_owned()];
        let locket_env = env(&[("DATABASE_URL", canary), ("API_TOKEN", "safe-value")]);

        let run_plan = prepare_docker_run(&argv, &EnvMap::new(), &locket_env, None, false)?;
        let compose_plan = prepare_compose(
            &["docker".to_owned(), "compose".to_owned(), "up".to_owned()],
            &EnvMap::new(),
            &locket_env,
            None,
            false,
        )?;

        let safe_surfaces = [
            run_plan.argv.join(" "),
            run_plan.injected_names.join(","),
            compose_plan.argv.join(" "),
            compose_plan.injected_names.join(","),
        ];
        for surface in safe_surfaces {
            assert!(!surface.contains(canary));
        }
        assert_eq!(run_plan.env.get("DATABASE_URL").map(|value| value.as_str()), Some(canary));
        assert_eq!(compose_plan.env.get("DATABASE_URL").map(|value| value.as_str()), Some(canary));
        Ok(())
    }

    #[test]
    fn validates_docker_program() {
        let argv = vec!["podman".to_owned(), "run".to_owned(), "app".to_owned()];
        let result = prepare_docker_run(&argv, &EnvMap::new(), &EnvMap::new(), None, false);

        assert_eq!(result, Err(DockerError::UnexpectedCommand { program: "podman".to_owned() }));
    }

    #[test]
    fn compose_rejects_a_missing_or_wrong_subcommand() {
        for (argv, program) in [
            (vec!["docker".to_owned()], "docker"),
            (vec!["docker".to_owned(), "run".to_owned()], "docker run"),
        ] {
            assert_eq!(
                prepare_compose(&argv, &EnvMap::new(), &EnvMap::new(), None, false),
                Err(DockerError::UnexpectedCommand { program: program.into() })
            );
        }
    }

    #[test]
    fn validates_empty_docker_command() {
        let result = prepare_compose(&[], &EnvMap::new(), &EnvMap::new(), None, false);

        assert_eq!(result, Err(DockerError::EmptyCommand));
    }

    #[test]
    fn docker_unknown_or_malformed_endpoints_fail_closed_even_when_remote_allowed() {
        for endpoint in [
            "",
            "   ",
            "desktop-linux",
            "fd://3",
            "fd://",
            "unix://",
            "unix://host/socket",
            "npipe://",
            "npipe:////./pipe/",
            "npipe:////server/not-pipe/docker_engine",
            "tcp://",
            "tcp://:2376",
            "tcp://host:invalid",
            "tcp://host:65536",
            "tcp://[::1",
            "tcp://[invalid]:2376",
            "tcp://[::1]suffix",
            "tcp://user@host",
            "npipe:////-/pipe/docker_engine",
            "ssh://",
            "ssh://user@",
            "https://?missing-host",
            "unix:///socket\n",
            "tcp://host/path",
            "ssh://host?query",
        ] {
            assert_eq!(
                classify_docker_endpoint(Some(endpoint)),
                DockerContextClass::Unknown,
                "endpoint {endpoint:?}"
            );
            for allow_remote in [false, true] {
                for subcommand in ["run", "compose"] {
                    let argv = ["docker".to_owned(), subcommand.to_owned(), "app".to_owned()];
                    let prepare =
                        if subcommand == "run" { prepare_docker_run } else { prepare_compose };
                    assert_eq!(
                        prepare(
                            &argv,
                            &EnvMap::new(),
                            &EnvMap::new(),
                            Some(endpoint),
                            allow_remote
                        ),
                        Err(DockerError::UnknownEndpoint),
                        "unknown endpoint must be refused: {endpoint:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn docker_named_pipe_server_controls_remote_policy() -> Result<(), DockerError> {
        for endpoint in
            ["npipe:////server/pipe/docker_engine", r"npipe://\\server\pipe\docker_engine"]
        {
            assert_eq!(classify_docker_endpoint(Some(endpoint)), DockerContextClass::Remote);
            for subcommand in ["run", "compose"] {
                let argv = ["docker".to_owned(), subcommand.to_owned(), "app".to_owned()];
                let prepare =
                    if subcommand == "run" { prepare_docker_run } else { prepare_compose };
                assert_eq!(
                    prepare(&argv, &EnvMap::new(), &EnvMap::new(), Some(endpoint), false),
                    Err(DockerError::RemoteContextDenied)
                );
                assert_eq!(
                    prepare(&argv, &EnvMap::new(), &EnvMap::new(), Some(endpoint), true)?
                        .context_class,
                    DockerContextClass::Remote
                );
            }
        }
        for endpoint in [
            "npipe:////./pipe/docker_engine",
            r"npipe://\\.\pipe\docker_engine",
            "unix:///var/run/docker.sock",
        ] {
            assert_eq!(classify_docker_endpoint(Some(endpoint)), DockerContextClass::Local);
        }
        for endpoint in
            ["tcp://[::1]", "tcp://[::1]:2376", "ssh://user@builder:2222", "tcp://localhost:2375"]
        {
            assert_eq!(classify_docker_endpoint(Some(endpoint)), DockerContextClass::Remote);
        }
        Ok(())
    }

    #[test]
    fn docker_unknown_named_endpoint_is_denied_even_when_remote_allowed() {
        let argv = ["docker".into(), "run".into(), "app".into()];
        for allow_remote in [false, true] {
            assert!(
                prepare_docker_run(
                    &argv,
                    &EnvMap::new(),
                    &EnvMap::new(),
                    Some("unknown-endpoint"),
                    allow_remote
                )
                .is_err()
            );
        }
    }

    #[test]
    fn docker_routing_secrets_are_rejected_by_both_helpers() {
        for name in [
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "HOME",
            "USERPROFILE",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        ] {
            for subcommand in ["run", "compose"] {
                let argv = ["docker".into(), subcommand.into(), "app".into()];
                let prepare =
                    if subcommand == "run" { prepare_docker_run } else { prepare_compose };
                let result = prepare(
                    &argv,
                    &EnvMap::new(),
                    &env(&[(name, "routing-secret-canary")]),
                    None,
                    true,
                );
                assert_eq!(result, Err(DockerError::RoutingSecretDenied { name: name.into() }));
                assert!(
                    result.is_err_and(|error| !error.to_string().contains("routing-secret-canary"))
                );
            }
        }
    }
}
