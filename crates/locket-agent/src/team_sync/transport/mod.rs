//! Delivery of opaque, authenticated team packages over local and remote storage.

mod credentials;
mod folder;
mod http;
mod s3;
mod webdav;
mod xml;

use std::path::{Path, PathBuf};

use locket_crypto::KeyBytes;
use locket_store::Store;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::{CommitAuthorization, Result, reject};
pub use credentials::TransportSecretInput;
use folder::Folder;
pub use folder::read_package_file;
use http::Endpoint;
use s3::S3;
use webdav::WebDav;

const PACKAGE_LIMIT: usize = locket_core::team_package::MAX_PACKAGE_BYTES + 18;
const LIST_LIMIT: usize = 8 * 1024 * 1024;
const ENTRY_LIMIT: usize = 100_000;

/// Source of transport authentication material.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    #[default]
    None,
    Vault,
    Env,
}

impl CredentialMode {
    const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Vault => "vault",
            Self::Env => "env",
        }
    }
}

/// HTTP authentication used by a `WebDAV` collection.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebDavAuthKind {
    #[default]
    None,
    Basic,
    Bearer,
}

/// Persisted transport metadata. Authentication secrets are supplied separately.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransportConfig {
    Folder {
        path: String,
    },
    S3 {
        bucket: String,
        region: String,
        #[serde(default)]
        prefix: String,
        #[serde(default)]
        endpoint: Option<String>,
        #[serde(default)]
        path_style: bool,
        credential_mode: CredentialMode,
    },
    #[serde(rename = "webdav")]
    WebDav {
        url: String,
        #[serde(default)]
        auth_kind: WebDavAuthKind,
        #[serde(default)]
        username: Option<String>,
        credential_mode: CredentialMode,
    },
}

impl TransportConfig {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Folder { .. } => "folder",
            Self::S3 { .. } => "s3",
            Self::WebDav { .. } => "webdav",
        }
    }

    const fn credential_mode(&self) -> CredentialMode {
        match self {
            Self::Folder { .. } => CredentialMode::None,
            Self::S3 { credential_mode, .. } | Self::WebDav { credential_mode, .. } => {
                *credential_mode
            }
        }
    }

    pub(super) fn summary(&self) -> Result<TransportSummary> {
        let (target, endpoint, region) = match self {
            Self::Folder { path } => (path.clone(), None, None),
            Self::S3 { bucket, region, prefix, .. } => {
                let (endpoint, _) = s3::endpoint(self)?;
                let target = format!("s3://{bucket}/{}", s3::prefix(prefix));
                (target, Some(endpoint.url()), Some(region.clone()))
            }
            Self::WebDav { url, auth_kind, username, credential_mode } => {
                webdav::validate_auth(*auth_kind, username.as_deref(), *credential_mode)?;
                let url = Endpoint::parse(url)?.url();
                (url.clone(), Some(url), None)
            }
        };
        Ok(TransportSummary {
            target,
            endpoint,
            region,
            transport_kind: self.kind().into(),
            credential_mode: self.credential_mode().name().into(),
        })
    }
}

/// Safe metadata for local status and connection tests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransportSummary {
    pub transport_kind: String,
    pub target: String,
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub credential_mode: String,
}

/// Result of a read-only connection and package listing check.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RemoteTestResult {
    pub ok: bool,
    pub transport_kind: String,
    pub target: String,
    pub package_count: usize,
    pub writable_checked: bool,
    pub message: String,
}

/// Outcome of a create-only upload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutOutcome {
    Written,
    AlreadyPresent,
    Conflict,
}

/// A package delivery channel. Callers must authenticate and verify downloaded bytes.
pub trait TeamTransport: Send + Sync {
    /// List sorted package basenames, with a limit of 100,000 entries.
    /// # Errors
    /// Returns an error if listing fails or exceeds its limits.
    fn list_packages(&self) -> Result<Vec<String>>;
    /// Read one bounded, encrypted package by basename.
    /// # Errors
    /// Rejects invalid names, oversized responses, and failed reads.
    fn get_package(&self, filename: &str) -> Result<Vec<u8>>;
    /// Create a package, preserving any different content at the requested name.
    /// # Errors
    /// Rejects invalid names, oversized packages, and failed writes.
    fn put_package(&self, filename: &str, bytes: &[u8]) -> Result<PutOutcome>;
    /// Return the transport's public configuration metadata.
    fn summary(&self) -> TransportSummary;

    /// Verify read access by listing packages.
    /// # Errors
    /// Returns an error if connection, authentication, or listing fails.
    fn test_connection(&self) -> Result<RemoteTestResult> {
        let package_count = self.list_packages()?.len();
        let summary = self.summary();
        Ok(RemoteTestResult {
            ok: true,
            transport_kind: summary.transport_kind,
            target: summary.target,
            package_count,
            writable_checked: false,
            message: "Package listing succeeded".into(),
        })
    }
}

pub(super) fn validate_filename(name: &str) -> Result<()> {
    if !name.rsplit_once('.').is_some_and(|(stem, ext)| !stem.is_empty() && ext == "lkpkg")
        || name.contains(['/', '\\'])
        || name.contains("..")
        || name.chars().any(char::is_control)
    {
        return Err(reject("invalid team package filename"));
    }
    Ok(())
}

pub(super) fn new_transport(
    config: &TransportConfig,
    secret: Option<TransportSecretInput>,
) -> Result<Box<dyn TeamTransport>> {
    let summary = config.summary()?;
    let secret = credentials::resolve(config, secret)?;
    Ok(match config {
        TransportConfig::Folder { path } => Box::new(Folder::new(PathBuf::from(path), summary)?),
        TransportConfig::S3 { .. } => Box::new(S3::new(config, summary, secret)?),
        TransportConfig::WebDav { .. } => Box::new(WebDav::new(config, summary, secret.as_ref())?),
    })
}

pub(super) struct ConfiguredTransport {
    pub(super) config: TransportConfig,
    pub(super) key_root: PathBuf,
    pub(super) allow_dangerous: bool,
}

pub(super) fn configured(store: &Store, project: &str) -> Result<Option<ConfiguredTransport>> {
    // Named access to the optional new columns also supports locked, read-only
    // status queries against vaults that have not yet run the schema upgrade.
    type Row = (String, PathBuf, bool, String, Option<String>);
    let row: Option<Row> = store
        .connection()
        .query_row(
            "SELECT * FROM team_sync_folders WHERE project_id=?1 AND enabled=1",
            [project],
            |row| {
                let key_root: String = row.get("device_key_root")?;
                let (kind, config) = if row.as_ref().column_index("transport_kind").is_ok() {
                    (row.get("transport_kind")?, row.get("transport_config_json")?)
                } else {
                    ("folder".into(), None)
                };
                Ok((row.get("path")?, key_root.into(), row.get("allow_dangerous")?, kind, config))
            },
        )
        .optional()?;
    let Some((path, key_root, allow_dangerous, kind, json)) = row else {
        return Ok(None);
    };
    let config = match json {
        Some(json) => serde_json::from_str::<TransportConfig>(&json)?,
        None if kind == "folder" => TransportConfig::Folder { path },
        None => return Err(reject("team transport configuration missing")),
    };
    if config.kind() != kind {
        return Err(reject("team transport configuration kind mismatch"));
    }
    Ok(Some(ConfiguredTransport { config, key_root, allow_dangerous }))
}

pub(super) fn open_configured(
    store: &Store,
    project: &str,
    master: Option<&KeyBytes>,
) -> Result<(Box<dyn TeamTransport>, ConfiguredTransport)> {
    // Read the config and its credentials from the same database snapshot.
    let tx = store.connection().unchecked_transaction()?;
    let configured =
        configured(store, project)?.ok_or_else(|| reject("team transport not configured"))?;
    let secret = credentials::load(store, project, &configured.config, master)?;
    tx.commit()?;
    Ok((new_transport(&configured.config, secret)?, configured))
}

/// Configure delivery for a project anchored to an independently pinned owner.
/// # Errors
/// Rejects invalid settings, missing credentials, trust, or database failures.
pub fn configure_transport(
    store: &Store,
    project: &str,
    config: TransportConfig,
    secret: Option<TransportSecretInput>,
    device_key_root: &Path,
    master: Option<&KeyBytes>,
    allow_dangerous: bool,
) -> Result<()> {
    configure_transport_guarded(
        store,
        project,
        config,
        secret,
        device_key_root,
        master,
        allow_dangerous,
        None,
    )
}

/// Configure delivery with live authorization at the local transaction.
/// # Errors
/// Also rejects expired or invalidated authorization.
pub fn configure_transport_guarded(
    store: &Store,
    project: &str,
    mut config: TransportConfig,
    secret: Option<TransportSecretInput>,
    device_key_root: &Path,
    master: Option<&KeyBytes>,
    allow_dangerous: bool,
    authorization: Option<&CommitAuthorization>,
) -> Result<()> {
    let key_root = device_key_root.canonicalize()?;
    if let TransportConfig::Folder { path } = &mut config {
        let canonical = folder::canonicalize(Path::new(path), &key_root)?;
        *path =
            canonical.to_str().ok_or_else(|| reject("shared folder path must be UTF-8"))?.into();
    }
    let legacy_path =
        if let TransportConfig::Folder { path } = &config { path.as_str() } else { "" };
    config.summary()?;
    let json = serde_json::to_string(&config)?;
    let sealed = credentials::seal(project, &config, secret.as_ref(), master)?;
    drop(secret);
    let tx = Transaction::new_unchecked(store.connection(), TransactionBehavior::Immediate)?;
    let _authorization = authorization.map(|authorize| authorize()).transpose()?;
    if super::snapshot::anchor(store, project)?.is_none() {
        return Err(reject("join with independent owner pin before enabling automatic sync"));
    }
    tx.execute(
        "INSERT INTO team_sync_folders
         (project_id,path,device_key_root,allow_dangerous,enabled,transport_kind,transport_config_json)
         VALUES (?1,?2,?3,?4,1,?5,?6)
         ON CONFLICT(project_id) DO UPDATE SET path=excluded.path,device_key_root=excluded.device_key_root,
           allow_dangerous=excluded.allow_dangerous,enabled=1,transport_kind=excluded.transport_kind,
           transport_config_json=excluded.transport_config_json,
           scan_after=CASE WHEN transport_config_json=excluded.transport_config_json
                           THEN scan_after ELSE NULL END,
           last_error=NULL",
        params![project,legacy_path,key_root.to_string_lossy(),allow_dangerous,config.kind(),json],
    )?;
    credentials::save(&tx, project, sealed)?;
    tx.commit()?;
    Ok(())
}

/// Clear the configured transport and any stored credentials for a project.
/// # Errors
/// Returns a database error if the transaction cannot be committed.
pub fn clear_transport(store: &Store, project: &str) -> Result<()> {
    let tx = Transaction::new_unchecked(store.connection(), TransactionBehavior::Immediate)?;
    tx.execute("DELETE FROM team_sync_folders WHERE project_id=?1", [project])?;
    credentials::save(&tx, project, None)?;
    tx.commit()?;
    Ok(())
}

/// Test an ad hoc transport without writing to the vault or endpoint.
/// # Errors
/// Returns an error if configuration, authentication, TLS or listing fails.
pub fn test_transport(
    config: &TransportConfig,
    secret: Option<TransportSecretInput>,
) -> Result<RemoteTestResult> {
    new_transport(config, secret)?.test_connection()
}

/// Test the stored transport using its configured credential source.
/// # Errors
/// Also returns an error if configured vault credentials cannot be opened.
pub fn test_configured_transport(
    store: &Store,
    project: &str,
    master: Option<&KeyBytes>,
) -> Result<RemoteTestResult> {
    open_configured(store, project, master)?.0.test_connection()
}

/// List and stream encrypted join candidates from an ad hoc transport in filename order.
/// Pass each candidate through the normal independently pinned join verifier.
/// # Errors
/// Returns listing failures immediately and download failures through the iterator.
pub fn list_and_read_join_packages(
    config: &TransportConfig,
    secret: Option<TransportSecretInput>,
) -> Result<JoinPackages> {
    JoinPackages::new(new_transport(config, secret)?)
}

/// List and stream encrypted join candidates from a configured transport.
/// # Errors
/// Returns configuration or listing failures immediately and download failures through the iterator.
pub fn list_and_read_configured_join_packages(
    store: &Store,
    project: &str,
    master: Option<&KeyBytes>,
) -> Result<JoinPackages> {
    JoinPackages::new(open_configured(store, project, master)?.0)
}

/// Bounded per-object download iterator for encrypted join candidates.
pub struct JoinPackages {
    transport: Box<dyn TeamTransport>,
    names: std::vec::IntoIter<String>,
}

impl JoinPackages {
    fn new(transport: Box<dyn TeamTransport>) -> Result<Self> {
        let names = transport.list_packages()?.into_iter();
        Ok(Self { transport, names })
    }
}

impl Iterator for JoinPackages {
    type Item = Result<(String, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        let name = self.names.next()?;
        Some(self.transport.get_package(&name).map(|bytes| (name, bytes)))
    }
}
