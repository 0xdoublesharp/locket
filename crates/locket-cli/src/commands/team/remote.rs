//! Local configuration and credential input for team delivery backends.

use super::{device, sync};
use crate::runtime::key_access::load_master_key;
use crate::runtime::prompts::validate_secret_value;
use crate::{
    CliError, RuntimeContext, TeamFolderArgs, TeamJoinArgs, ensure_trusted_project_root,
    metadata_invalid_error, open_store, require_project,
};
use clap::{Args, Subcommand, ValueEnum};
use locket_agent::team_sync::{
    self, CredentialMode, TransportConfig, TransportSecretInput, WebDavAuthKind,
};
use locket_crypto::KeyBytes;
use locket_store::Store;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use zeroize::Zeroizing;

const DEFAULT_S3_REGION: &str = "us-east-1";
const WEBDAV_SECRET: &[&str] = &["LOCKET_WEBDAV_SECRET", "LOCKET_WEBDAV_TOKEN"];

#[derive(Debug, Subcommand)]
pub enum RemoteCommand {
    /// Choose a delivery backend and its local credential source.
    Set {
        #[command(subcommand)]
        command: RemoteSetCommand,
    },
    /// Show the locally configured backend without credentials.
    Status,
    /// Check that the configured backend can list encrypted packages.
    Test,
    /// Prune superseded packages from the configured backend (pinned owner only).
    Prune(PruneArgs),
    /// Clear delivery and stored transport credentials while retaining trust history.
    Clear,
}

#[derive(Args, Debug)]
pub struct PruneArgs {
    /// Recent delivered epochs to keep per recipient (at least one).
    #[arg(long, default_value_t = 5)]
    keep_epochs: usize,
    /// Show the packages eligible for deletion.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum RemoteSetCommand {
    /// Use AWS S3 or another S3-compatible object store.
    S3(S3SetArgs),
    /// Use a `WebDAV` collection.
    #[command(name = "webdav")]
    WebDav(WebDavSetArgs),
    /// Use a shared directory on this machine.
    Folder(TeamFolderArgs),
}

#[derive(Args)]
pub struct S3SetArgs {
    /// Existing bucket for encrypted packages.
    #[arg(long)]
    bucket: String,
    /// S3 signing region.
    #[arg(long, default_value = DEFAULT_S3_REGION)]
    region: String,
    /// Object prefix containing the team's packages.
    #[arg(long, default_value = "")]
    prefix: String,
    /// Custom S3 endpoint, which implies path-style addressing.
    #[arg(long)]
    endpoint: Option<String>,
    /// Put the bucket name in the URL path.
    #[arg(long)]
    path_style: bool,
    /// Store credentials in the vault or read them from the environment.
    #[arg(long, value_enum, default_value = "vault")]
    credentials: S3CredentialsArg,
    /// Access key identifier for vault credentials.
    #[arg(long)]
    access_key_id: Option<String>,
    /// Permit automatic delivery of dangerous profile values on this machine.
    #[arg(long)]
    allow_dangerous: bool,
}

impl std::fmt::Debug for S3SetArgs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("S3SetArgs")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .field("endpoint", &self.endpoint)
            .field("path_style", &self.path_style)
            .field("credentials", &self.credentials)
            .field("access_key_id", &self.access_key_id.as_ref().map(|_| "[redacted]"))
            .field("allow_dangerous", &self.allow_dangerous)
            .finish()
    }
}

#[derive(Args)]
pub struct WebDavSetArgs {
    /// Existing collection for encrypted packages.
    #[arg(long)]
    url: String,
    /// HTTP authentication method.
    #[arg(long, value_enum, default_value = "none")]
    auth: WebDavAuthArg,
    /// `WebDAV` Basic username.
    #[arg(long)]
    username: Option<String>,
    /// Credential source (defaults to vault for Basic and Bearer, none without authentication).
    #[arg(long, value_enum)]
    credentials: Option<RemoteCredentialsArg>,
    /// Permit automatic delivery of dangerous profile values on this machine.
    #[arg(long)]
    allow_dangerous: bool,
}

impl std::fmt::Debug for WebDavSetArgs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebDavSetArgs")
            .field("url", &self.url)
            .field("auth", &self.auth)
            .field("username", &self.username.as_ref().map(|_| "[redacted]"))
            .field("credentials", &self.credentials)
            .field("allow_dangerous", &self.allow_dangerous)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum S3CredentialsArg {
    Vault,
    Env,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RemoteCredentialsArg {
    None,
    Vault,
    Env,
}

impl From<RemoteCredentialsArg> for CredentialMode {
    fn from(arg: RemoteCredentialsArg) -> Self {
        match arg {
            RemoteCredentialsArg::None => Self::None,
            RemoteCredentialsArg::Vault => Self::Vault,
            RemoteCredentialsArg::Env => Self::Env,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum WebDavAuthArg {
    #[default]
    None,
    Basic,
    Bearer,
}

impl From<WebDavAuthArg> for WebDavAuthKind {
    fn from(arg: WebDavAuthArg) -> Self {
        match arg {
            WebDavAuthArg::None => Self::None,
            WebDavAuthArg::Basic => Self::Basic,
            WebDavAuthArg::Bearer => Self::Bearer,
        }
    }
}

pub fn run(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: RemoteCommand,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let project = resolved.config.project_id.as_str();
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    match command {
        RemoteCommand::Set { command } => {
            let (setup, allow_dangerous) = match command {
                RemoteSetCommand::Folder(args) => {
                    return sync::configure_shared_folder(
                        context, output, &mut store, project, &args,
                    );
                }
                RemoteSetCommand::S3(args) => {
                    let mode = match args.credentials {
                        S3CredentialsArg::Vault => CredentialMode::Vault,
                        S3CredentialsArg::Env => CredentialMode::Env,
                    };
                    let config = s3_config(
                        args.bucket,
                        args.region,
                        args.prefix,
                        args.endpoint,
                        args.path_style,
                        mode,
                    );
                    (RemoteSetup::s3(context, config, args.access_key_id)?, args.allow_dangerous)
                }
                RemoteSetCommand::WebDav(args) => (
                    RemoteSetup::webdav(
                        context,
                        args.url,
                        args.auth,
                        args.username,
                        args.credentials,
                    )?,
                    args.allow_dangerous,
                ),
            };
            let (master, _) = load_master_key(context, project)?;
            sync::ensure_owner_anchor(&mut store, project)?;
            setup.configure(
                &store,
                project,
                &device::device_private_key_root(context)?,
                &master,
                allow_dangerous,
            )?;
            writeln!(output, "Shared delivery backend configured on this machine.")?;
        }
        RemoteCommand::Status => {
            let status = team_sync::status(&store, project).map_err(sync::failure)?;
            let transport = serde_json::json!({
                "transport_kind": status.transport_kind,
                "remote_target": status.remote_target,
                "remote_endpoint": status.remote_endpoint,
                "remote_region": status.remote_region,
                "credential_mode": status.credential_mode,
                "folder": status.folder,
            });
            writeln!(output, "{}", serde_json::to_string_pretty(&transport)?)?;
        }
        RemoteCommand::Test => {
            let (master, _) = load_master_key(context, project)?;
            let result = team_sync::test_configured_transport(&store, project, Some(&master))
                .map_err(sync::failure)?;
            writeln!(output, "{}", serde_json::to_string_pretty(&result)?)?;
        }
        RemoteCommand::Prune(args) => {
            let (master, _) = load_master_key(context, project)?;
            let result = team_sync::prune_remote_packages(
                &store,
                project,
                Some(&master),
                args.keep_epochs,
                args.dry_run,
            )
            .map_err(sync::failure)?;
            writeln!(output, "{}", serde_json::to_string_pretty(&result)?)?;
        }
        RemoteCommand::Clear => {
            team_sync::clear_transport(&store, project).map_err(sync::failure)?;
            writeln!(
                output,
                "Cleared remote delivery and locally stored transport credentials. Kept authenticated history."
            )?;
        }
    }
    Ok(())
}

const fn s3_config(
    bucket: String,
    region: String,
    prefix: String,
    endpoint: Option<String>,
    path_style: bool,
    credential_mode: CredentialMode,
) -> TransportConfig {
    TransportConfig::S3 {
        bucket,
        region,
        prefix,
        path_style: path_style || endpoint.is_some(),
        endpoint,
        credential_mode,
    }
}

pub(super) struct RemoteSetup {
    config: TransportConfig,
    secret: Option<TransportSecretInput>,
}

impl RemoteSetup {
    fn s3(
        context: &RuntimeContext,
        config: TransportConfig,
        access_key_id: Option<String>,
    ) -> Result<Self, CliError> {
        let secret = if matches!(
            config,
            TransportConfig::S3 { credential_mode: CredentialMode::Vault, .. }
        ) {
            let locket_id = env_value(&["LOCKET_S3_ACCESS_KEY_ID"])?;
            let locket_key = env_value(&["LOCKET_S3_SECRET_ACCESS_KEY"])?;
            let locket_token = env_value(&["LOCKET_S3_SESSION_TOKEN"])?;
            let use_locket_family =
                locket_id.is_some() || locket_key.is_some() || locket_token.is_some();
            let (env_id, env_secret, env_token) = if use_locket_family {
                (locket_id, locket_key, locket_token)
            } else if access_key_id.is_some() {
                (None, None, None)
            } else {
                (
                    env_value(&["AWS_ACCESS_KEY_ID"])?,
                    env_value(&["AWS_SECRET_ACCESS_KEY"])?,
                    env_value(&["AWS_SESSION_TOKEN"])?,
                )
            };
            let mut access_key_id = match access_key_id.map(Zeroizing::new).or(env_id) {
                Some(id) => id,
                None if io::stdin().is_terminal() => {
                    context.secret_value_reader.read_secret_value("S3 access key ID")?
                }
                None => {
                    return Err(metadata_invalid_error(
                        "provide the S3 access key ID with --access-key-id or Locket/AWS environment variables",
                    ));
                }
            };
            let secret_access_key = if !io::stdin().is_terminal()
                && let Some(secret) = env_secret
            {
                validate_secret_value(secret)?
            } else {
                context.secret_value_reader.read_secret_value("S3 secret access key")?
            };
            Some(TransportSecretInput::S3 {
                access_key_id: std::mem::take(&mut *access_key_id),
                secret_access_key,
                session_token: env_token,
            })
        } else {
            None
        };
        Ok(Self { config, secret })
    }

    fn webdav(
        context: &RuntimeContext,
        url: String,
        auth: WebDavAuthArg,
        username: Option<String>,
        mode: Option<RemoteCredentialsArg>,
    ) -> Result<Self, CliError> {
        let auth_kind = WebDavAuthKind::from(auth);
        let credential_mode = mode.map_or_else(
            || match auth_kind {
                WebDavAuthKind::None => CredentialMode::None,
                _ => CredentialMode::Vault,
            },
            CredentialMode::from,
        );
        if (auth_kind == WebDavAuthKind::None) != (credential_mode == CredentialMode::None) {
            return Err(metadata_invalid_error(
                "WebDAV Basic and Bearer require vault or env credentials. Unauthenticated WebDAV requires none.",
            ));
        }
        if username.is_some() && auth_kind != WebDavAuthKind::Basic {
            return Err(metadata_invalid_error("a WebDAV username requires Basic authentication"));
        }
        let (username, secret) = if credential_mode == CredentialMode::Vault {
            let username = if auth_kind == WebDavAuthKind::Basic {
                let username = match username {
                    Some(username) => Some(Zeroizing::new(username)),
                    None => env_value(&["LOCKET_WEBDAV_USERNAME"])?,
                }
                    .ok_or_else(|| metadata_invalid_error(
                        "provide a WebDAV Basic username with the username option or LOCKET_WEBDAV_USERNAME",
                    ))?;
                Some(username)
            } else {
                None
            };
            let prompt = if auth_kind == WebDavAuthKind::Basic {
                "WebDAV password"
            } else {
                "WebDAV bearer token"
            };
            let secret = read_credential(context, prompt, WEBDAV_SECRET)?;
            let username = username.map(|mut name| std::mem::take(&mut *name));
            (None, Some(TransportSecretInput::WebDav { username, secret }))
        } else {
            (username, None)
        };
        let config = TransportConfig::WebDav { url, auth_kind, username, credential_mode };
        Ok(Self { config, secret })
    }

    pub(super) fn from_join_args(
        context: &RuntimeContext,
        args: &TeamJoinArgs,
    ) -> Result<Option<Self>, CliError> {
        if let Some(bucket) = &args.s3_bucket {
            let mode = match args.credentials {
                None | Some(RemoteCredentialsArg::Vault) => CredentialMode::Vault,
                Some(RemoteCredentialsArg::Env) => CredentialMode::Env,
                Some(RemoteCredentialsArg::None) => {
                    return Err(metadata_invalid_error("S3 credentials must be vault or env"));
                }
            };
            let config = s3_config(
                bucket.clone(),
                args.s3_region.as_deref().unwrap_or(DEFAULT_S3_REGION).to_owned(),
                args.s3_prefix.clone().unwrap_or_default(),
                args.s3_endpoint.clone(),
                args.s3_path_style,
                mode,
            );
            return Self::s3(context, config, None).map(Some);
        }
        args.webdav_url
            .as_ref()
            .map(|url| {
                Self::webdav(
                    context,
                    url.clone(),
                    args.webdav_auth.unwrap_or_default(),
                    args.webdav_username.clone(),
                    args.credentials,
                )
            })
            .transpose()
    }

    pub(super) fn join_packages(
        &self,
        recipient_fingerprint: &str,
    ) -> Result<team_sync::JoinPackages, CliError> {
        // The iterator owns its credentials. Keep the original for persistence after verification.
        let secret = self.secret.as_ref().map(|secret| match secret {
            TransportSecretInput::S3 { access_key_id, secret_access_key, session_token } => {
                TransportSecretInput::S3 {
                    access_key_id: access_key_id.clone(),
                    secret_access_key: secret_access_key.clone(),
                    session_token: session_token.clone(),
                }
            }
            TransportSecretInput::WebDav { username, secret } => {
                TransportSecretInput::WebDav { username: username.clone(), secret: secret.clone() }
            }
        });
        team_sync::list_and_read_join_packages_for_recipient(
            &self.config,
            secret,
            recipient_fingerprint,
        )
        .map_err(sync::failure)
    }

    pub(super) fn configure(
        self,
        store: &Store,
        project: &str,
        device_key_root: &Path,
        master: &KeyBytes,
        allow_dangerous: bool,
    ) -> Result<(), CliError> {
        team_sync::configure_transport(
            store,
            project,
            self.config,
            self.secret,
            device_key_root,
            Some(master),
            allow_dangerous,
        )
        .map_err(sync::failure)
    }
}

fn read_credential(
    context: &RuntimeContext,
    prompt: &str,
    env_names: &[&str],
) -> Result<Zeroizing<String>, CliError> {
    if !io::stdin().is_terminal()
        && let Some(secret) = env_value(env_names)?
    {
        return validate_secret_value(secret);
    }
    context.secret_value_reader.read_secret_value(prompt)
}

fn env_value(names: &[&str]) -> Result<Option<Zeroizing<String>>, CliError> {
    for name in names {
        match std::env::var(name) {
            Ok(value) if !value.is_empty() => return Ok(Some(Zeroizing::new(value))),
            Ok(_) | Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(metadata_invalid_error(format!(
                    "invalid credential environment variable {name}"
                )));
            }
        }
    }
    Ok(None)
}
