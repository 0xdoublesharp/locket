//! Automation-client private-key storage helpers.

use std::collections::BTreeMap;
use std::sync::Mutex;

use keyring_core::Entry;
use locket_crypto::KeyBytes;
use zeroize::Zeroizing;

use crate::LocketInstance;
use crate::error::PlatformError;

const AUTOMATION_CLIENT_ACCOUNT_PREFIX: &str = "automation-client:";

/// OS-keychain reference for a stored automation-client private key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationClientKeychainRef {
    /// Keychain service name.
    pub service: String,
    /// Keychain account name.
    pub account: String,
}

/// Storage backend for Locket-managed automation-client private keys.
pub trait AutomationClientKeyStore {
    /// Stores a private signing seed and returns the metadata-only keychain ref.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] when the platform storage backend rejects the
    /// write.
    fn store_client_key(
        &self,
        client_id: &str,
        private_key: &KeyBytes,
    ) -> Result<AutomationClientKeychainRef, PlatformError>;

    /// Deletes a stored private signing seed if present.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] when the platform storage backend rejects the
    /// deletion.
    fn delete_client_key(&self, client_id: &str) -> Result<(), PlatformError>;
}

/// OS keychain-backed automation-client private-key store.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyringAutomationClientKeyStore;

impl AutomationClientKeyStore for KeyringAutomationClientKeyStore {
    fn store_client_key(
        &self,
        client_id: &str,
        private_key: &KeyBytes,
    ) -> Result<AutomationClientKeychainRef, PlatformError> {
        let reference = automation_client_keychain_ref(client_id);
        let entry = automation_client_key_entry(client_id)?;
        entry.set_password(&encode_client_key(private_key)).map_err(PlatformError::Keyring)?;
        Ok(reference)
    }

    fn delete_client_key(&self, client_id: &str) -> Result<(), PlatformError> {
        let entry = automation_client_key_entry(client_id)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(error) => Err(PlatformError::Keyring(error)),
        }
    }
}

/// In-memory automation-client private-key store for tests.
#[derive(Default)]
pub struct MemoryAutomationClientKeyStore {
    keys: Mutex<BTreeMap<String, Zeroizing<KeyBytes>>>,
}

impl std::fmt::Debug for MemoryAutomationClientKeyStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("MemoryAutomationClientKeyStore").finish_non_exhaustive()
    }
}

impl MemoryAutomationClientKeyStore {
    /// Returns a copy of a stored seed for assertions.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MemoryPoisoned`] if the test store lock is poisoned.
    pub fn load_client_key(
        &self,
        client_id: &str,
    ) -> Result<Option<Zeroizing<KeyBytes>>, PlatformError> {
        let keys = self.keys.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        let key = keys.get(client_id).cloned();
        drop(keys);
        Ok(key)
    }
}

impl AutomationClientKeyStore for MemoryAutomationClientKeyStore {
    fn store_client_key(
        &self,
        client_id: &str,
        private_key: &KeyBytes,
    ) -> Result<AutomationClientKeychainRef, PlatformError> {
        let mut keys = self.keys.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        keys.insert(client_id.to_owned(), Zeroizing::new(*private_key));
        drop(keys);
        Ok(automation_client_keychain_ref(client_id))
    }

    fn delete_client_key(&self, client_id: &str) -> Result<(), PlatformError> {
        let mut keys = self.keys.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        keys.remove(client_id);
        drop(keys);
        Ok(())
    }
}

#[must_use]
pub fn automation_client_keychain_ref(client_id: &str) -> AutomationClientKeychainRef {
    AutomationClientKeychainRef {
        service: LocketInstance::current().keyring_service().to_owned(),
        account: automation_client_key_account(client_id),
    }
}

fn automation_client_key_entry(client_id: &str) -> Result<Entry, PlatformError> {
    let reference = automation_client_keychain_ref(client_id);
    Entry::new(&reference.service, &reference.account).map_err(PlatformError::Keyring)
}

fn automation_client_key_account(client_id: &str) -> String {
    format!("{AUTOMATION_CLIENT_ACCOUNT_PREFIX}{client_id}")
}

fn encode_client_key(private_key: &KeyBytes) -> Zeroizing<String> {
    crate::master_key::encode_key(private_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master_key::decode_key;
    use locket_crypto::KEY_LEN;

    const CLIENT_ID: &str = "lk_client_test";
    const KEY: KeyBytes = [0x42; KEY_LEN];

    #[test]
    fn keychain_reference_uses_metadata_only_account() {
        let reference = automation_client_keychain_ref(CLIENT_ID);

        assert_eq!(reference.service, crate::LocketInstance::current().keyring_service());
        assert_eq!(reference.account, "automation-client:lk_client_test");
    }

    #[test]
    fn client_key_encoding_round_trips_without_padding() -> Result<(), PlatformError> {
        let encoded = encode_client_key(&KEY);

        assert!(!encoded.contains('='));
        assert_eq!(&*decode_key(encoded.as_bytes())?, &KEY);
        Ok(())
    }

    #[test]
    fn memory_store_replaces_and_deletes_client_keys() -> Result<(), PlatformError> {
        let store = MemoryAutomationClientKeyStore::default();
        let replacement = [0x7A; KEY_LEN];

        let reference = store.store_client_key(CLIENT_ID, &KEY)?;
        assert_eq!(reference.account, "automation-client:lk_client_test");
        let Some(stored) = store.load_client_key(CLIENT_ID)? else {
            return Err(PlatformError::MasterKeyNotFound);
        };
        assert_eq!(&*stored, &KEY);

        store.store_client_key(CLIENT_ID, &replacement)?;
        let Some(stored) = store.load_client_key(CLIENT_ID)? else {
            return Err(PlatformError::MasterKeyNotFound);
        };
        assert_eq!(&*stored, &replacement);

        store.delete_client_key(CLIENT_ID)?;
        assert!(store.load_client_key(CLIENT_ID)?.is_none());
        store.delete_client_key(CLIENT_ID)?;
        Ok(())
    }
}
