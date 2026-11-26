use std::env;
use std::fmt;

use data_encoding::HEXLOWER;
use locket_crypto::{KeyBytes, NonceBytes, open_recovery_entry_v1, seal_recovery_entry_v1};
use locket_store::Store;
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use super::{CredentialMode, Result, TransportConfig, WebDavAuthKind, reject};

const ENTRY_KIND: &str = "locket-team-sync-credentials";
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

/// In-memory credentials. Secret fields and credential identifiers are cleared on drop.
pub enum TransportSecretInput {
    S3 {
        access_key_id: String,
        secret_access_key: Zeroizing<String>,
        session_token: Option<Zeroizing<String>>,
    },
    WebDav {
        username: Option<String>,
        secret: Zeroizing<String>,
    },
}

impl fmt::Debug for TransportSecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransportSecretInput([redacted])")
    }
}

impl Drop for TransportSecretInput {
    fn drop(&mut self) {
        match self {
            Self::S3 { access_key_id, .. } => access_key_id.zeroize(),
            Self::WebDav { username, .. } => username.zeroize(),
        }
    }
}

// Use the same JSON shape at both boundaries. The decrypted representation
// owns zeroizing strings, while encryption borrows directly from the input.
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StoredTransportCredentials<T> {
    S3 { access_key_id: T, secret_access_key: T, session_token: Option<T> },
    WebDav { username: Option<T>, secret: T },
}

struct SecretString(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

impl<'a> From<&'a TransportSecretInput> for StoredTransportCredentials<&'a str> {
    fn from(input: &'a TransportSecretInput) -> Self {
        match input {
            TransportSecretInput::S3 { access_key_id, secret_access_key, session_token } => {
                Self::S3 {
                    access_key_id,
                    secret_access_key,
                    session_token: session_token.as_ref().map(|token| token.as_str()),
                }
            }
            TransportSecretInput::WebDav { username, secret } => {
                Self::WebDav { username: username.as_deref(), secret }
            }
        }
    }
}

impl From<StoredTransportCredentials<SecretString>> for TransportSecretInput {
    fn from(stored: StoredTransportCredentials<SecretString>) -> Self {
        match stored {
            StoredTransportCredentials::S3 {
                access_key_id: SecretString(mut id),
                secret_access_key: SecretString(key),
                session_token,
            } => Self::S3 {
                access_key_id: std::mem::take(&mut *id),
                secret_access_key: key,
                session_token: session_token.map(|SecretString(value)| value),
            },
            StoredTransportCredentials::WebDav { username, secret: SecretString(secret) } => {
                Self::WebDav {
                    username: username.map(|SecretString(mut name)| std::mem::take(&mut *name)),
                    secret,
                }
            }
        }
    }
}

pub(super) struct SealedCredentials {
    nonce: NonceBytes,
    ciphertext: Vec<u8>,
}

pub(super) fn seal(
    project: &str,
    config: &TransportConfig,
    input: Option<&TransportSecretInput>,
    master: Option<&KeyBytes>,
) -> Result<Option<SealedCredentials>> {
    if config.credential_mode() != CredentialMode::Vault {
        if input.is_some() {
            return Err(reject("explicit credentials require vault credential mode"));
        }
        return Ok(None);
    }
    let input = input.ok_or_else(|| reject("vault transport credentials required"))?;
    validate(config, input)?;
    let master =
        master.ok_or_else(|| reject("unlock the project to store transport credentials"))?;
    let mut json = Zeroizing::new(Vec::with_capacity(MAX_CREDENTIAL_BYTES));
    serde_json::to_writer(&mut *json, &StoredTransportCredentials::from(input))?;
    if json.len() > MAX_CREDENTIAL_BYTES {
        return Err(reject("team transport credentials exceed size limit"));
    }
    let scope = config_scope(config)?;
    let (nonce, ciphertext) = seal_recovery_entry_v1(master, &scope, ENTRY_KIND, project, &json)?;
    Ok(Some(SealedCredentials { nonce, ciphertext }))
}

fn config_scope(config: &TransportConfig) -> Result<String> {
    let json = serde_json::to_vec(config)?;
    Ok(HEXLOWER.encode(&Sha256::digest(json)))
}

pub(super) fn save(
    tx: &Transaction<'_>,
    project: &str,
    sealed: Option<SealedCredentials>,
) -> Result<()> {
    if let Some(SealedCredentials { nonce, ciphertext }) = sealed {
        let now = i64::try_from(crate::server::current_unix_nanos())
            .map_err(|_| reject("clock unavailable"))?;
        tx.execute(
            "INSERT INTO team_sync_credentials(project_id,ciphertext,nonce,aad_schema_version,updated_at)
             VALUES (?1,?2,?3,1,?4) ON CONFLICT(project_id) DO UPDATE SET
             ciphertext=excluded.ciphertext,nonce=excluded.nonce,
             aad_schema_version=excluded.aad_schema_version,updated_at=excluded.updated_at",
            params![project, ciphertext, nonce.as_slice(), now],
        )?;
    } else {
        tx.execute("DELETE FROM team_sync_credentials WHERE project_id=?1", [project])?;
    }
    Ok(())
}

pub(super) fn load(
    store: &Store,
    project: &str,
    config: &TransportConfig,
    master: Option<&KeyBytes>,
) -> Result<Option<TransportSecretInput>> {
    if config.credential_mode() != CredentialMode::Vault {
        return Ok(None);
    }
    let master =
        master.ok_or_else(|| reject("unlock the project to use vault transport credentials"))?;
    let maximum = i64::try_from(MAX_CREDENTIAL_BYTES + locket_crypto::TAG_LEN)
        .map_err(|_| reject("invalid team credential size limit"))?;
    let stored = store
        .connection()
        .query_row(
            "SELECT nonce,ciphertext FROM team_sync_credentials WHERE project_id=?1
         AND aad_schema_version=1 AND length(ciphertext)<=?2",
            (project, maximum),
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let (nonce, ciphertext) =
        stored.ok_or_else(|| reject("vault transport credentials missing or invalid"))?;
    let nonce: NonceBytes = nonce.try_into().map_err(|_| reject("invalid credential nonce"))?;
    let scope = config_scope(config)?;
    let json = open_recovery_entry_v1(master, &scope, ENTRY_KIND, project, &nonce, &ciphertext)?;
    Ok(Some(serde_json::from_slice::<StoredTransportCredentials<SecretString>>(&json)?.into()))
}

pub(super) fn resolve(
    config: &TransportConfig,
    input: Option<TransportSecretInput>,
) -> Result<Option<TransportSecretInput>> {
    let input = match (config.credential_mode(), input) {
        (CredentialMode::Vault, Some(input)) => input,
        (CredentialMode::Vault, None) => {
            return Err(reject("vault transport credentials required"));
        }
        (CredentialMode::None, None) => return Ok(None),
        (CredentialMode::Env, None) => from_env(config)?,
        (_, Some(_)) => return Err(reject("explicit credentials require vault credential mode")),
    };
    validate(config, &input)?;
    Ok(Some(input))
}

fn env_value(names: &[&str]) -> Result<Option<String>> {
    for name in names {
        match env::var(name) {
            Ok(value) if !value.is_empty() => return Ok(Some(value)),
            Ok(_) | Err(env::VarError::NotPresent) => {}
            Err(env::VarError::NotUnicode(_)) => {
                return Err(reject("invalid credential environment variable"));
            }
        }
    }
    Ok(None)
}

fn from_env(config: &TransportConfig) -> Result<TransportSecretInput> {
    match config {
        TransportConfig::S3 { .. } => {
            let key = env_value(&["LOCKET_S3_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"])?
                .map(Zeroizing::new)
                .ok_or_else(|| reject("S3 environment credentials are missing"))?;
            Ok(TransportSecretInput::S3 {
                access_key_id: env_value(&["LOCKET_S3_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"])?
                    .ok_or_else(|| reject("S3 environment credentials are missing"))?,
                secret_access_key: key,
                session_token: env_value(&["LOCKET_S3_SESSION_TOKEN", "AWS_SESSION_TOKEN"])?
                    .map(Zeroizing::new),
            })
        }
        TransportConfig::WebDav { .. } => {
            let secret = env_value(&["LOCKET_WEBDAV_SECRET", "LOCKET_WEBDAV_TOKEN"])?
                .map(Zeroizing::new)
                .ok_or_else(|| reject("WebDAV environment credentials are missing"))?;
            Ok(TransportSecretInput::WebDav {
                username: env_value(&["LOCKET_WEBDAV_USERNAME"])?,
                secret,
            })
        }
        TransportConfig::Folder { .. } => Err(reject("shared folder does not use credentials")),
    }
}

fn validate(config: &TransportConfig, input: &TransportSecretInput) -> Result<()> {
    match (config, input) {
        (
            TransportConfig::S3 { .. },
            TransportSecretInput::S3 { access_key_id, secret_access_key, session_token },
        ) if access_key_id.len() <= 256
            && !access_key_id.is_empty()
            && access_key_id
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'-' | b'_'))
            && !secret_access_key.is_empty()
            && secret_access_key.len() <= 1024
            && session_token.as_ref().is_none_or(|token| header_secret(token)) =>
        {
            Ok(())
        }
        (
            TransportConfig::WebDav { auth_kind, username, .. },
            TransportSecretInput::WebDav { username: supplied, secret },
        ) => match auth_kind {
            WebDavAuthKind::Basic
                if username.as_deref().or(supplied.as_deref()).is_some_and(valid_username)
                    && !secret.is_empty()
                    && secret.len() <= 4096
                    && !secret.chars().any(char::is_control) =>
            {
                Ok(())
            }
            WebDavAuthKind::Bearer if header_secret(secret) => Ok(()),
            _ => Err(reject("invalid WebDAV credentials")),
        },
        _ => Err(reject("invalid credentials for team transport")),
    }
}

pub(super) fn valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 1024
        && !username.contains(':')
        && !username.chars().any(char::is_control)
}

fn header_secret(secret: &str) -> bool {
    !secret.is_empty() && secret.len() <= 8192 && secret.bytes().all(|byte| byte.is_ascii_graphic())
}
