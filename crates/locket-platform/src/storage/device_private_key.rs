//! Device private-key storage trait and wrapped-local-file implementation.
//!
//! Each Locket device owns an X25519 sealing private key used to decrypt sealed
//! bundle payloads. The key material is wrapped by the local master key and
//! persisted in `<directory>/devices/<device_id>.priv` with owner-only file
//! permissions on Unix.

use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use locket_crypto::{
    CryptoError, KEY_LEN, KeyBytes, TAG_LEN, WrappedKeyMaterial, unwrap_key_material_v1,
    wrap_key_material_v1,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::PlatformError;
use crate::fs_helpers::{
    decode_bytes, decode_nonce, encode_bytes, secure_directory, validate_path_component,
    write_user_only_file,
};
use crate::master_key::MasterKeyStore;

/// Schema version of wrapped device private-key envelopes.
pub const DEVICE_PRIVATE_KEY_SCHEMA_VERSION: u16 = 1;

const DEVICE_PRIVATE_KEY_ALGORITHM: &str = "xchacha20poly1305-key-wrap-v1";
const DEVICE_PRIVATE_KEY_FILE_SUFFIX: &str = ".priv";
const DEVICE_PRIVATE_KEY_DIRECTORY: &str = "devices";

/// Fixed-length device private-key bytes (32 bytes for X25519 secret scalar).
pub type PrivateKeyBytes = KeyBytes;

/// Local storage backend for device private keys.
///
/// Implementations persist the per-device X25519 sealing private key used to
/// decrypt sealed bundle payloads. The plaintext key bytes are never written
/// to disk by the wrapped-local-file backend; an envelope encrypted with the
/// local master key is written instead.
pub trait LocalDevicePrivateKeyStorage {
    /// Stores the device private key under `device_id`, replacing any previous
    /// envelope.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] if the master key cannot be loaded, the
    /// envelope cannot be sealed, or the filesystem write fails.
    fn store(&self, device_id: &str, private_key: &PrivateKeyBytes) -> Result<(), PlatformError>;

    /// Loads the device private key for `device_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::DevicePrivateKeyNotFound`] when no envelope
    /// exists, [`PlatformError::DevicePrivateKeyIntegrityFailure`] when the
    /// envelope is corrupt or sealed by a different master key, and
    /// [`PlatformError::DevicePrivateKeyPermissionsTooWide`] when on-disk
    /// permissions are wider than 0600 on Unix.
    fn load(&self, device_id: &str) -> Result<Zeroizing<PrivateKeyBytes>, PlatformError>;

    /// Deletes the device private-key envelope for `device_id`.
    ///
    /// Idempotent: returns `Ok(())` when no envelope exists.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Io`] for filesystem failures other than a
    /// missing file.
    fn delete(&self, device_id: &str) -> Result<(), PlatformError>;

    /// Returns the device ids for which an envelope exists, sorted ascending.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::Io`] if the storage directory cannot be read.
    fn list(&self) -> Result<Vec<String>, PlatformError>;
}

/// Wrapped-local-file device private-key storage rooted at a directory.
///
/// Files are written to `<directory>/devices/<device_id>.priv` with owner-only
/// permissions where the platform supports them. The envelope is sealed using
/// a wrapping key derived from the master key looked up via the configured
/// [`MasterKeyStore`] using `project_id`.
#[derive(Clone)]
pub struct WrappedLocalFileDevicePrivateKeyStorage {
    directory: PathBuf,
    signing: bool,
    project_id: String,
    master_key_store: Arc<dyn MasterKeyStore + Send + Sync>,
}

impl std::fmt::Debug for WrappedLocalFileDevicePrivateKeyStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedLocalFileDevicePrivateKeyStorage")
            .field("directory", &self.directory)
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

impl WrappedLocalFileDevicePrivateKeyStorage {
    /// Creates a new wrapped-local-file storage rooted at `directory`.
    ///
    /// Files are placed under `<directory>/devices/`. Wrapping keys are derived
    /// from the master key returned by `master_key_store` for `project_id`.
    pub fn new(
        directory: impl Into<PathBuf>,
        project_id: impl Into<String>,
        master_key_store: Arc<dyn MasterKeyStore + Send + Sync>,
    ) -> Self {
        Self {
            directory: directory.into(),
            signing: false,
            project_id: project_id.into(),
            master_key_store,
        }
    }

    /// Selects separate files and authenticated domain for Ed25519 signing seeds.
    /// Use the signing fingerprint as the storage identifier to stage rotations safely.
    #[must_use]
    pub const fn for_signing(mut self) -> Self {
        self.signing = true;
        self
    }

    /// Returns the on-disk path for `device_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InvalidProjectId`] when `device_id` contains
    /// characters disallowed in path components.
    pub fn envelope_path(&self, device_id: &str) -> Result<PathBuf, PlatformError> {
        validate_path_component(device_id)?;
        Ok(self.devices_directory().join(format!("{device_id}{DEVICE_PRIVATE_KEY_FILE_SUFFIX}")))
    }

    fn devices_directory(&self) -> PathBuf {
        self.directory.join(if self.signing {
            "device-signing-v2"
        } else {
            DEVICE_PRIVATE_KEY_DIRECTORY
        })
    }

    fn temp_envelope_path(&self, device_id: &str) -> Result<PathBuf, PlatformError> {
        validate_path_component(device_id)?;
        Ok(self.devices_directory().join(format!("{device_id}.tmp")))
    }

    fn wrap_aad(&self, device_id: &str) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(if self.signing {
            b"locket-device-signing-private-key-v2"
        } else {
            b"locket-device-private-key-v1"
        });
        aad.extend_from_slice(self.project_id.as_bytes());
        aad.push(0);
        aad.extend_from_slice(device_id.as_bytes());
        aad
    }

    fn master_key(&self) -> Result<Zeroizing<KeyBytes>, PlatformError> {
        self.master_key_store.load_master_key(&self.project_id)
    }
}

impl LocalDevicePrivateKeyStorage for WrappedLocalFileDevicePrivateKeyStorage {
    fn store(&self, device_id: &str, private_key: &PrivateKeyBytes) -> Result<(), PlatformError> {
        let path = self.envelope_path(device_id)?;
        let temp_path = self.temp_envelope_path(device_id)?;
        let wrapping_key = self.master_key()?;
        let aad = self.wrap_aad(device_id);
        let wrapped = wrap_key_material_v1(&wrapping_key, private_key, &aad)?;
        let envelope = DevicePrivateKeyEnvelope {
            version: DEVICE_PRIVATE_KEY_SCHEMA_VERSION,
            algorithm: DEVICE_PRIVATE_KEY_ALGORITHM.to_owned(),
            project_id: self.project_id.clone(),
            device_id: device_id.to_owned(),
            nonce: encode_bytes(&wrapped.nonce),
            wrapped_private_key: encode_bytes(&wrapped.ciphertext),
        };
        secure_directory(&self.devices_directory())?;
        let rendered = toml::to_string_pretty(&envelope)?;
        write_user_only_file(&temp_path, rendered.as_bytes())?;
        fs::rename(&temp_path, &path)?;
        Ok(())
    }

    fn load(&self, device_id: &str) -> Result<Zeroizing<PrivateKeyBytes>, PlatformError> {
        let path = self.envelope_path(device_id)?;
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(PlatformError::DevicePrivateKeyNotFound);
            }
            Err(error) => return Err(error.into()),
        };
        check_envelope_permissions(&metadata)?;
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(PlatformError::DevicePrivateKeyNotFound);
            }
            Err(error) => return Err(error.into()),
        };
        let envelope: DevicePrivateKeyEnvelope = toml::from_str(&text).map_err(|error| {
            PlatformError::DevicePrivateKeyIntegrityFailure(format!(
                "device private-key envelope is malformed: {error}"
            ))
        })?;
        envelope.validate(&self.project_id, device_id)?;
        let nonce = decode_nonce(&envelope.nonce).map_err(|_| {
            PlatformError::DevicePrivateKeyIntegrityFailure(
                "device private-key envelope nonce is invalid".into(),
            )
        })?;
        let ciphertext = decode_bytes(&envelope.wrapped_private_key).map_err(|_| {
            PlatformError::DevicePrivateKeyIntegrityFailure(
                "device private-key envelope ciphertext is invalid".into(),
            )
        })?;
        if ciphertext.len() != KEY_LEN + TAG_LEN {
            return Err(PlatformError::DevicePrivateKeyIntegrityFailure(
                "device private-key envelope ciphertext has unexpected length".into(),
            ));
        }
        let wrapping_key = self.master_key()?;
        let aad = self.wrap_aad(device_id);
        let wrapped = WrappedKeyMaterial { ciphertext, nonce };
        unwrap_key_material_v1(&wrapping_key, &wrapped, &aad).map_err(|error| match error {
            CryptoError::DecryptionFailed | CryptoError::InvalidWrappedKey => {
                PlatformError::DevicePrivateKeyIntegrityFailure(
                    "device private-key envelope failed authentication".into(),
                )
            }
            other => PlatformError::Crypto(other),
        })
    }

    fn delete(&self, device_id: &str) -> Result<(), PlatformError> {
        let path = self.envelope_path(device_id)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn list(&self) -> Result<Vec<String>, PlatformError> {
        let directory = self.devices_directory();
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut device_ids = Vec::new();
        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let Some(stripped) = name.strip_suffix(DEVICE_PRIVATE_KEY_FILE_SUFFIX) else {
                continue;
            };
            if validate_path_component(stripped).is_err() {
                continue;
            }
            device_ids.push(stripped.to_owned());
        }
        device_ids.sort();
        Ok(device_ids)
    }
}

/// Deterministic in-memory device private-key storage for tests.
#[derive(Debug, Default)]
pub struct MemoryDevicePrivateKeyStorage {
    keys: Mutex<BTreeMap<String, PrivateKeyBytes>>,
}

impl LocalDevicePrivateKeyStorage for MemoryDevicePrivateKeyStorage {
    fn store(&self, device_id: &str, private_key: &PrivateKeyBytes) -> Result<(), PlatformError> {
        let mut keys = self.keys.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        if let Some(old_key) = keys.get_mut(device_id) {
            old_key.zeroize();
        }
        keys.insert(device_id.to_owned(), *private_key);
        drop(keys);
        Ok(())
    }

    fn load(&self, device_id: &str) -> Result<Zeroizing<PrivateKeyBytes>, PlatformError> {
        let keys = self.keys.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        let Some(key) = keys.get(device_id).copied() else {
            return Err(PlatformError::DevicePrivateKeyNotFound);
        };
        drop(keys);
        Ok(Zeroizing::new(key))
    }

    fn delete(&self, device_id: &str) -> Result<(), PlatformError> {
        let mut keys = self.keys.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        if let Some(mut key) = keys.remove(device_id) {
            key.zeroize();
        }
        drop(keys);
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>, PlatformError> {
        let keys = self.keys.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        let ids = keys.keys().cloned().collect::<Vec<_>>();
        drop(keys);
        Ok(ids)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct DevicePrivateKeyEnvelope {
    version: u16,
    algorithm: String,
    project_id: String,
    device_id: String,
    nonce: String,
    wrapped_private_key: String,
}

impl DevicePrivateKeyEnvelope {
    fn validate(
        &self,
        expected_project_id: &str,
        expected_device_id: &str,
    ) -> Result<(), PlatformError> {
        if self.version != DEVICE_PRIVATE_KEY_SCHEMA_VERSION {
            return Err(PlatformError::DevicePrivateKeyIntegrityFailure(format!(
                "unsupported device private-key envelope version {}",
                self.version
            )));
        }
        if self.algorithm != DEVICE_PRIVATE_KEY_ALGORITHM {
            return Err(PlatformError::DevicePrivateKeyIntegrityFailure(format!(
                "unsupported device private-key envelope algorithm {}",
                self.algorithm
            )));
        }
        if self.project_id != expected_project_id {
            return Err(PlatformError::DevicePrivateKeyIntegrityFailure(
                "device private-key envelope project_id mismatch".into(),
            ));
        }
        if self.device_id != expected_device_id {
            return Err(PlatformError::DevicePrivateKeyIntegrityFailure(
                "device private-key envelope device_id mismatch".into(),
            ));
        }
        Ok(())
    }
}

// Keep the fallible cross-platform interface; POSIX mode checks only apply on Unix.
#[cfg_attr(not(unix), allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps))]
fn check_envelope_permissions(metadata: &fs::Metadata) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(PlatformError::DevicePrivateKeyPermissionsTooWide(mode));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
    }
    Ok(())
}
