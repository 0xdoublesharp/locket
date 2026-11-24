//! Passphrase fallback master-key store backed by an Argon2id-encrypted file.

use std::fs;
use std::path::PathBuf;

use data_encoding::HEXLOWER;
use locket_crypto::{
    CryptoError, KEY_LEN, KeyBytes, PASSPHRASE_FALLBACK_SALT_LEN, PassphraseKdfParams, TAG_LEN,
    WrappedKeyMaterial, derive_passphrase_fallback_key_v1, generate_passphrase_salt,
    passphrase_fallback_aad_v1, unwrap_key_material_v1, wrap_key_material_v1,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::PlatformError;
use crate::fs_helpers::{
    decode_bytes, decode_nonce, encode_bytes, secure_directory, validate_path_component,
    write_user_only_file,
};

const PASSPHRASE_FALLBACK_SCHEMA_VERSION: u16 = 1;
const PASSPHRASE_FALLBACK_ALGORITHM: &str = "argon2id";

/// File-backed passphrase fallback for local master-key storage.
#[derive(Debug, Clone)]
pub struct PassphraseFallbackMasterKeyStore {
    directory: PathBuf,
}

impl PassphraseFallbackMasterKeyStore {
    /// Creates a passphrase fallback store rooted at `directory`.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self { directory: directory.into() }
    }

    /// Returns whether a fallback envelope exists for `project_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] if `project_id` is invalid for local path use.
    pub fn contains_project(&self, project_id: &str) -> Result<bool, PlatformError> {
        Ok(self.envelope_path(project_id)?.exists())
    }

    /// Stores `master_key` encrypted by an Argon2id key derived from `passphrase`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] when KDF derivation, encryption, serialization,
    /// or filesystem writes fail.
    pub fn store_master_key(
        &self,
        project_id: &str,
        master_key: &KeyBytes,
        passphrase: &[u8],
        created_at: i64,
    ) -> Result<(), PlatformError> {
        let path = self.envelope_path(project_id)?;
        let salt = generate_passphrase_salt()?;
        let kdf_profile_id = kdf_profile_id_from_salt(&salt);
        let params = PassphraseKdfParams::fallback_v1();
        let wrapping_key = derive_passphrase_fallback_key_v1(passphrase, &salt, params)?;
        let aad = passphrase_fallback_aad_v1(project_id, &kdf_profile_id)?;
        let wrapped = wrap_key_material_v1(&wrapping_key, master_key, &aad)?;
        let envelope = PassphraseFallbackEnvelope {
            version: PASSPHRASE_FALLBACK_SCHEMA_VERSION,
            algorithm: PASSPHRASE_FALLBACK_ALGORITHM.to_owned(),
            kdf_profile_id,
            salt: encode_bytes(&salt),
            m_cost: params.m_cost,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            output_len: params.output_len,
            nonce: encode_bytes(&wrapped.nonce),
            wrapped_master_key: encode_bytes(&wrapped.ciphertext),
            created_at,
        };

        secure_directory(&self.directory)?;
        let rendered = toml::to_string_pretty(&envelope)?;
        write_user_only_file(&path, rendered.as_bytes())
    }

    /// Loads a master key from the passphrase fallback envelope for `project_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MasterKeyNotFound`] when no envelope exists,
    /// [`PlatformError::InvalidPassphrase`] when authentication fails, and
    /// [`PlatformError`] for malformed envelopes or filesystem failures.
    pub fn load_master_key(
        &self,
        project_id: &str,
        passphrase: &[u8],
    ) -> Result<Zeroizing<KeyBytes>, PlatformError> {
        let path = self.envelope_path(project_id)?;
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(PlatformError::MasterKeyNotFound);
            }
            Err(error) => return Err(error.into()),
        };
        let envelope: PassphraseFallbackEnvelope = toml::from_str(&text)?;
        envelope.validate()?;
        let salt = decode_bytes(&envelope.salt)?;
        if salt.len() != PASSPHRASE_FALLBACK_SALT_LEN {
            return Err(PlatformError::InvalidPassphraseFallback);
        }
        let nonce = decode_nonce(&envelope.nonce)?;
        let ciphertext = decode_bytes(&envelope.wrapped_master_key)?;
        if ciphertext.len() != KEY_LEN + TAG_LEN {
            return Err(PlatformError::InvalidPassphraseFallback);
        }
        let params = PassphraseKdfParams {
            m_cost: envelope.m_cost,
            t_cost: envelope.t_cost,
            p_cost: envelope.p_cost,
            output_len: envelope.output_len,
        };
        let wrapping_key = derive_passphrase_fallback_key_v1(passphrase, &salt, params)?;
        let aad = passphrase_fallback_aad_v1(project_id, &envelope.kdf_profile_id)?;
        let wrapped = WrappedKeyMaterial { ciphertext, nonce };

        unwrap_key_material_v1(&wrapping_key, &wrapped, &aad).map_err(|error| match error {
            CryptoError::DecryptionFailed => PlatformError::InvalidPassphrase,
            other => PlatformError::Crypto(other),
        })
    }

    /// Deletes the fallback envelope for `project_id` when present.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] for filesystem failures other than a missing file.
    pub fn delete_master_key(&self, project_id: &str) -> Result<(), PlatformError> {
        let path = self.envelope_path(project_id)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn envelope_path(&self, project_id: &str) -> Result<PathBuf, PlatformError> {
        validate_path_component(project_id)?;
        Ok(self.directory.join(format!("{project_id}.toml")))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct PassphraseFallbackEnvelope {
    version: u16,
    algorithm: String,
    kdf_profile_id: String,
    salt: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: u32,
    nonce: String,
    wrapped_master_key: String,
    created_at: i64,
}

impl PassphraseFallbackEnvelope {
    fn validate(&self) -> Result<(), PlatformError> {
        let expected = PassphraseKdfParams::fallback_v1();
        if self.version != PASSPHRASE_FALLBACK_SCHEMA_VERSION
            || self.algorithm != PASSPHRASE_FALLBACK_ALGORITHM
            || !self.kdf_profile_id.starts_with("lk_kdf_")
            || self.m_cost != expected.m_cost
            || self.t_cost != expected.t_cost
            || self.p_cost != expected.p_cost
            || self.output_len != expected.output_len
        {
            return Err(PlatformError::InvalidPassphraseFallback);
        }
        Ok(())
    }
}

fn kdf_profile_id_from_salt(salt: &[u8]) -> String {
    let prefix_len = salt.len().min(16);
    format!("lk_kdf_{}", HEXLOWER.encode(&salt[..prefix_len]))
}
