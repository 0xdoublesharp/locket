//! Master-key store trait and OS keyring / in-memory implementations.

use std::sync::Mutex;

use data_encoding::BASE64URL_NOPAD;
use keyring_core::Entry;
use locket_crypto::{KEY_LEN, KeyBytes};
use zeroize::Zeroizing;

use crate::LocketInstance;
use crate::error::PlatformError;

const MASTER_KEY_ACCOUNT_PREFIX: &str = "master:";

/// Interface for local master-key storage.
pub trait MasterKeyStore {
    /// Stores a master key for `project_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] when the platform storage backend rejects the
    /// write.
    fn store_master_key(
        &self,
        project_id: &str,
        master_key: &KeyBytes,
    ) -> Result<(), PlatformError>;

    /// Loads a master key for `project_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MasterKeyNotFound`] when no key exists and
    /// [`PlatformError`] for backend failures or invalid key material.
    fn load_master_key(&self, project_id: &str) -> Result<Zeroizing<KeyBytes>, PlatformError>;

    /// Deletes a master key for `project_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] when the backend rejects deletion.
    fn delete_master_key(&self, project_id: &str) -> Result<(), PlatformError>;
}

/// OS keychain-backed master-key store.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyringMasterKeyStore;

impl MasterKeyStore for KeyringMasterKeyStore {
    fn store_master_key(
        &self,
        project_id: &str,
        master_key: &KeyBytes,
    ) -> Result<(), PlatformError> {
        let entry = master_key_entry(project_id)?;
        entry.set_password(&encode_key(master_key)).map_err(PlatformError::Keyring)
    }

    fn load_master_key(&self, project_id: &str) -> Result<Zeroizing<KeyBytes>, PlatformError> {
        let entry = master_key_entry(project_id)?;
        let encoded = Zeroizing::new(entry.get_secret().map_err(map_keyring_get_error)?);
        drop(entry);
        decode_key(&encoded)
    }

    fn delete_master_key(&self, project_id: &str) -> Result<(), PlatformError> {
        let entry = master_key_entry(project_id)?;
        entry.delete_credential().map_err(PlatformError::Keyring)
    }
}

/// In-memory master-key store for short-lived operations and deterministic tests.
#[derive(Default)]
pub struct MemoryMasterKeyStore {
    key: Mutex<Option<(String, Zeroizing<KeyBytes>)>>,
}

impl std::fmt::Debug for MemoryMasterKeyStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("MemoryMasterKeyStore").finish_non_exhaustive()
    }
}
impl MasterKeyStore for MemoryMasterKeyStore {
    fn store_master_key(
        &self,
        project_id: &str,
        master_key: &KeyBytes,
    ) -> Result<(), PlatformError> {
        *self.key.lock().map_err(|_| PlatformError::MemoryPoisoned)? =
            Some((project_id.to_owned(), Zeroizing::new(*master_key)));
        Ok(())
    }

    fn load_master_key(&self, project_id: &str) -> Result<Zeroizing<KeyBytes>, PlatformError> {
        let guard = self.key.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        let loaded = guard
            .as_ref()
            .filter(|(stored_project_id, _)| stored_project_id == project_id)
            .map(|(_, key)| key.clone());
        drop(guard);
        loaded.ok_or(PlatformError::MasterKeyNotFound)
    }

    fn delete_master_key(&self, project_id: &str) -> Result<(), PlatformError> {
        let mut guard = self.key.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        if guard.as_ref().is_some_and(|(stored_project_id, _)| stored_project_id == project_id) {
            *guard = None;
        }
        drop(guard);
        Ok(())
    }
}

/// Deterministic master-key store mock with per-operation failure injection.
#[derive(Debug, Default)]
pub struct MockMasterKeyStore {
    store: MemoryMasterKeyStore,
    failures: Mutex<MockMasterKeyStoreFailures>,
}

/// Failure mode returned by [`MockMasterKeyStore`] operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MockMasterKeyStoreFailure {
    /// Return [`PlatformError::MasterKeyNotFound`].
    MasterKeyNotFound,
    /// Return [`PlatformError::InvalidMasterKey`].
    InvalidMasterKey,
    /// Return [`PlatformError::MemoryPoisoned`].
    MemoryPoisoned,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MockMasterKeyStoreFailures {
    store: Option<MockMasterKeyStoreFailure>,
    load: Option<MockMasterKeyStoreFailure>,
    delete: Option<MockMasterKeyStoreFailure>,
}

impl MockMasterKeyStoreFailure {
    const fn into_platform_error(self) -> PlatformError {
        match self {
            Self::MasterKeyNotFound => PlatformError::MasterKeyNotFound,
            Self::InvalidMasterKey => PlatformError::InvalidMasterKey,
            Self::MemoryPoisoned => PlatformError::MemoryPoisoned,
        }
    }
}

impl MockMasterKeyStore {
    /// Configures the next and future store operations to return `failure`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MemoryPoisoned`] if the mock's failure state is poisoned.
    pub fn set_store_failure(
        &self,
        failure: Option<MockMasterKeyStoreFailure>,
    ) -> Result<(), PlatformError> {
        self.failures.lock().map_err(|_| PlatformError::MemoryPoisoned)?.store = failure;
        Ok(())
    }

    /// Configures the next and future load operations to return `failure`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MemoryPoisoned`] if the mock's failure state is poisoned.
    pub fn set_load_failure(
        &self,
        failure: Option<MockMasterKeyStoreFailure>,
    ) -> Result<(), PlatformError> {
        self.failures.lock().map_err(|_| PlatformError::MemoryPoisoned)?.load = failure;
        Ok(())
    }

    /// Configures the next and future delete operations to return `failure`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MemoryPoisoned`] if the mock's failure state is poisoned.
    pub fn set_delete_failure(
        &self,
        failure: Option<MockMasterKeyStoreFailure>,
    ) -> Result<(), PlatformError> {
        self.failures.lock().map_err(|_| PlatformError::MemoryPoisoned)?.delete = failure;
        Ok(())
    }

    fn configured_failure(
        &self,
        operation: impl FnOnce(&MockMasterKeyStoreFailures) -> Option<MockMasterKeyStoreFailure>,
    ) -> Result<Option<PlatformError>, PlatformError> {
        let failures = self.failures.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        Ok(operation(&failures).map(MockMasterKeyStoreFailure::into_platform_error))
    }
}

impl MasterKeyStore for MockMasterKeyStore {
    fn store_master_key(
        &self,
        project_id: &str,
        master_key: &KeyBytes,
    ) -> Result<(), PlatformError> {
        if let Some(error) = self.configured_failure(|failures| failures.store)? {
            return Err(error);
        }
        self.store.store_master_key(project_id, master_key)
    }

    fn load_master_key(&self, project_id: &str) -> Result<Zeroizing<KeyBytes>, PlatformError> {
        if let Some(error) = self.configured_failure(|failures| failures.load)? {
            return Err(error);
        }
        self.store.load_master_key(project_id)
    }

    fn delete_master_key(&self, project_id: &str) -> Result<(), PlatformError> {
        if let Some(error) = self.configured_failure(|failures| failures.delete)? {
            return Err(error);
        }
        self.store.delete_master_key(project_id)
    }
}

pub fn master_key_entry(project_id: &str) -> Result<Entry, PlatformError> {
    Entry::new(LocketInstance::current().keyring_service(), &master_key_account(project_id))
        .map_err(PlatformError::Keyring)
}

pub fn master_key_account(project_id: &str) -> String {
    format!("{MASTER_KEY_ACCOUNT_PREFIX}{project_id}")
}

pub fn encode_key(key: &KeyBytes) -> Zeroizing<String> {
    Zeroizing::new(BASE64URL_NOPAD.encode(key))
}

pub fn decode_key(encoded: &[u8]) -> Result<Zeroizing<KeyBytes>, PlatformError> {
    if encoded.len() != BASE64URL_NOPAD.encode_len(KEY_LEN) {
        return Err(PlatformError::InvalidMasterKey);
    }

    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    BASE64URL_NOPAD.decode_mut(encoded, &mut *key).map_err(|_| PlatformError::InvalidMasterKey)?;
    Ok(key)
}

pub fn map_keyring_get_error(error: keyring_core::Error) -> PlatformError {
    match error {
        keyring_core::Error::NoEntry => PlatformError::MasterKeyNotFound,
        other => PlatformError::Keyring(other),
    }
}
