//! Shared unwrapping for keys protected by a project's master key.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use locket_crypto::{
    CryptoError, HkdfWrapInfo, KeyBytes, KeyPurpose, KeyWrapAad, KeyWrapPurpose,
    WrappedKeyMaterial, derive_wrapping_key_v1, key_wrap_aad_v1, unwrap_key_material_v1,
};
use locket_store::{Store, StoreError};
use zeroize::Zeroizing;

use crate::server::AgentSocketState;

/// File identity captured independently of the path used to reach it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    path: PathBuf,
}

impl StoreFileIdentity {
    pub(crate) fn capture(path: &Path) -> io::Result<(PathBuf, Self)> {
        let path = fs::canonicalize(path)?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "store must be a regular file",
            ));
        }
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            Self { device: metadata.dev(), inode: metadata.ino() }
        };
        #[cfg(not(unix))]
        let identity = Self { path: path.clone() };
        Ok((path, identity))
    }

    pub(crate) fn matches(&self, path: &Path) -> bool {
        Self::capture(path).is_ok_and(|(_, identity)| *self == identity)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid cached master key length")]
    InvalidMasterKey,
    #[error("wrapped {0} key is missing")]
    Missing(&'static str),
    #[error("could not read wrapped key")]
    Store(#[from] StoreError),
    #[error("invalid wrapped key metadata")]
    Metadata(#[source] CryptoError),
    #[error("wrapped key authentication failed")]
    Unwrap(#[source] CryptoError),
}

pub fn master_key_array(bytes: &[u8]) -> Result<Zeroizing<KeyBytes>, KeyError> {
    if bytes.len() != std::mem::size_of::<KeyBytes>() {
        return Err(KeyError::InvalidMasterKey);
    }
    let mut key = Zeroizing::new(KeyBytes::default());
    key.copy_from_slice(bytes);
    Ok(key)
}

pub async fn cached_master_key(
    state: &AgentSocketState,
    project_id: &str,
    now_unix_nanos: i128,
) -> Result<Option<Zeroizing<KeyBytes>>, KeyError> {
    state
        .unlock_cache
        .lock()
        .await
        .lookup(project_id, now_unix_nanos)
        .map(|entry| master_key_array(entry.key_bytes()))
        .transpose()
}

pub fn unwrap_project_key_with_master(
    store: &Store,
    project_id: &str,
    master_key: &KeyBytes,
    purpose: KeyPurpose,
) -> Result<Zeroizing<KeyBytes>, KeyError> {
    unwrap_scoped_key(store, project_id, None, master_key, purpose)
}

pub fn unwrap_audit_key_with_master(
    store: &Store,
    project_id: &str,
    master_key: &KeyBytes,
) -> Result<Zeroizing<KeyBytes>, KeyError> {
    unwrap_project_key_with_master(store, project_id, master_key, KeyPurpose::Audit)
}

pub fn unwrap_profile_key_with_master(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    master_key: &KeyBytes,
    purpose: KeyPurpose,
) -> Result<Zeroizing<KeyBytes>, KeyError> {
    unwrap_scoped_key(store, project_id, Some(profile_id), master_key, purpose)
}

fn unwrap_scoped_key(
    store: &Store,
    project_id: &str,
    profile_id: Option<&str>,
    master_key: &KeyBytes,
    purpose: KeyPurpose,
) -> Result<Zeroizing<KeyBytes>, KeyError> {
    let record = store
        .get_key_by_scope(project_id, profile_id, purpose.as_str())?
        .ok_or(KeyError::Missing(purpose.as_str()))?;
    let wrapping_key =
        derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(project_id, profile_id, purpose))
            .map_err(KeyError::Metadata)?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        profile_id,
        0,
        KeyWrapPurpose::from(purpose),
    ))
    .map_err(KeyError::Metadata)?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    unwrap_key_material_v1(&wrapping_key, &wrapped, &aad).map_err(KeyError::Unwrap)
}
