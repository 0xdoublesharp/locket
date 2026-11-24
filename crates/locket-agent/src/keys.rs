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
        let metadata = check_store_files(path)?;
        let canonical = fs::canonicalize(path)?;
        let metadata = if canonical == path { metadata } else { check_store_files(&canonical)? };
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            Self { device: metadata.dev(), inode: metadata.ino() }
        };
        #[cfg(not(unix))]
        let identity = Self { path: canonical.clone() };
        Ok((canonical, identity))
    }

    pub(crate) fn matches(&self, path: &Path) -> bool {
        Self::capture(path).is_ok_and(|(_, identity)| *self == identity)
    }
}

fn check_store_files(path: &Path) -> io::Result<fs::Metadata> {
    let main = fs::symlink_metadata(path)?;
    if main.is_symlink() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "store must not be a symlink"));
    }
    if !main.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "store must be a regular file"));
    }
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        match fs::symlink_metadata(sidecar) {
            Ok(metadata) if metadata.is_file() => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "store sidecar must be a regular file",
                ));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(main)
}

#[derive(Debug, thiserror::Error)]
pub enum StoreIdentityError {
    #[error("could not inspect the vault file")]
    Path(#[from] io::Error),
    #[error("could not open the vault database")]
    Store(#[from] StoreError),
    #[error("could not inspect the open vault database")]
    Sqlite(#[from] rusqlite::Error),
    #[error("store does not match the pinned vault")]
    Mismatch,
}

impl StoreIdentityError {
    pub fn is_identity_error(&self) -> bool {
        match self {
            Self::Mismatch => true,
            Self::Path(error) => matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied
            ),
            Self::Store(_) | Self::Sqlite(_) => false,
        }
    }
}

impl From<StoreIdentityError> for StoreError {
    fn from(error: StoreIdentityError) -> Self {
        match error {
            StoreIdentityError::Store(error) => error,
            StoreIdentityError::Sqlite(error) => Self::Sqlite(error),
            error => Self::AuditIntegrity { sequence: 0, reason: error.to_string() },
        }
    }
}

pub fn open_verified_store(
    path: &Path,
    expected_identity: Option<&StoreFileIdentity>,
) -> Result<(Store, StoreFileIdentity), StoreIdentityError> {
    open_verified_store_with(path, expected_identity, false)
}

pub fn open_verified_store_with(
    path: &Path,
    expected_identity: Option<&StoreFileIdentity>,
    read_only: bool,
) -> Result<(Store, StoreFileIdentity), StoreIdentityError> {
    let (canonical_path, before) = StoreFileIdentity::capture(path)?;
    if expected_identity.is_some_and(|expected| expected != &before) {
        return Err(StoreIdentityError::Mismatch);
    }
    let store = if read_only {
        Store::open_read_only(&canonical_path)?
    } else {
        Store::open(&canonical_path)?
    };
    let opened: String = store.connection().query_row(
        "SELECT file FROM pragma_database_list WHERE name = 'main'",
        [],
        |row| row.get(0),
    )?;
    let (opened_path, after) = StoreFileIdentity::capture(Path::new(&opened))?;
    if opened_path != canonical_path || after != before {
        return Err(StoreIdentityError::Mismatch);
    }
    // The Unix VFS compares its open descriptor's device/inode to the pathname.
    #[cfg(unix)]
    {
        let mut moved = 0;
        store
            .connection()
            .file_control(Some("main"), rusqlite::FileControl::HasMoved(&mut moved))?;
        if moved != 0 {
            return Err(StoreIdentityError::Mismatch);
        }
    }
    if StoreFileIdentity::capture(path)?.1 != after {
        return Err(StoreIdentityError::Mismatch);
    }
    Ok((store, after))
}

pub async fn open_verified_store_for_state(
    state: &AgentSocketState,
    project_id: &str,
    requested_path: &Path,
    now_unix_nanos: i128,
) -> Result<(Store, StoreFileIdentity), StoreIdentityError> {
    open_verified_store_for_state_with(state, project_id, requested_path, now_unix_nanos, false)
        .await
}

pub async fn open_verified_store_for_state_with(
    state: &AgentSocketState,
    project_id: &str,
    requested_path: &Path,
    now_unix_nanos: i128,
    read_only: bool,
) -> Result<(Store, StoreFileIdentity), StoreIdentityError> {
    let cache = state.unlock_cache.lock().await;
    let pin =
        cache.lookup(project_id, now_unix_nanos).and_then(|entry| entry.store_identity.as_ref());
    let opened = state.open_store(requested_path, pin, read_only);
    drop(cache);
    opened
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
