//! Recovery envelope KDF, per-entry HKDF/AAD construction, and seal/open helpers.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aad::{
    RECOVERY_ENTRY_AAD_V1_PREFIX, RECOVERY_ENTRY_HKDF_V1_PREFIX, append_canonical_field,
    append_u16_le, canonical_fields_len,
};
use crate::aead::{aead_decrypt, aead_encrypt};
use crate::error::{CryptoError, CryptoResult};
use crate::random::random_bytes;
use crate::{
    KEY_LEN, KeyBytes, NONCE_LEN, NonceBytes, RECOVERY_CODE_BYTES, RECOVERY_ENVELOPE_SCHEMA_V1,
    RECOVERY_M_COST, RECOVERY_P_COST, RECOVERY_T_COST,
};

/// Argon2id parameters for recovery envelope key derivation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RecoveryKdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iteration count.
    pub t_cost: u32,
    /// Parallelism degree.
    pub p_cost: u32,
    /// Output length in bytes.
    pub output_len: u32,
}

impl RecoveryKdfParams {
    /// Returns the v1 default recovery KDF parameters.
    #[must_use]
    pub const fn recovery_v1() -> Self {
        // KEY_LEN is 32, well within u32 range.
        #[allow(clippy::cast_possible_truncation)]
        let output_len = KEY_LEN as u32;
        Self {
            m_cost: RECOVERY_M_COST,
            t_cost: RECOVERY_T_COST,
            p_cost: RECOVERY_P_COST,
            output_len,
        }
    }
}

/// Derives the recovery unwrap root key from a raw recovery code and stored KDF params.
///
/// Uses Argon2id with the stored parameters. Returns a zeroizing 32-byte key.
///
/// # Errors
///
/// Returns `CryptoError::InvalidKdfParameters` if params are zero or unsupported,
/// or `CryptoError::KeyDerivationFailed` on Argon2id failure.
pub fn derive_recovery_key_v1(
    recovery_code_bytes: &[u8; RECOVERY_CODE_BYTES],
    salt: &[u8],
    params: RecoveryKdfParams,
) -> CryptoResult<Zeroizing<KeyBytes>> {
    if salt.is_empty() || params.m_cost == 0 || params.t_cost == 0 || params.p_cost == 0 {
        return Err(CryptoError::InvalidKdfParameters);
    }
    let argon_params =
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(params.output_len as usize))
            .map_err(|_| CryptoError::InvalidKdfParameters)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(recovery_code_bytes, salt, &mut *key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

/// Derives the per-entry HKDF key for a recovery envelope entry.
///
/// `info = b"locket-recovery-entry-v1" || field("entry_kind", entry_kind) || field("entry_id", entry_id) || field("kdf_profile_id", kdf_profile_id)`
///
/// # Errors
///
/// Returns `CryptoError` if field encoding or HKDF expansion fails.
pub fn recovery_entry_key_v1(
    unwrap_root: &KeyBytes,
    entry_kind: &str,
    entry_id: &str,
    kdf_profile_id: &str,
) -> CryptoResult<Zeroizing<KeyBytes>> {
    let fields =
        [("entry_kind", entry_kind), ("entry_id", entry_id), ("kdf_profile_id", kdf_profile_id)];
    let mut info =
        Vec::with_capacity(RECOVERY_ENTRY_HKDF_V1_PREFIX.len() + canonical_fields_len(&fields));
    info.extend_from_slice(RECOVERY_ENTRY_HKDF_V1_PREFIX);
    for (name, value) in fields {
        append_canonical_field(&mut info, name, value)?;
    }
    let hkdf = Hkdf::<Sha256>::new(None, unwrap_root);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(&info, &mut *key).map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

/// Constructs canonical AAD for a recovery envelope entry.
///
/// `aad = b"locket-recovery-envelope-v1" || u16_le(schema_version) || field("kdf_profile_id", kdf_profile_id) || field("entry_kind", entry_kind) || field("entry_id", entry_id)`
///
/// # Errors
///
/// Returns `CryptoError` if any field is too long.
pub fn recovery_entry_aad_v1(
    kdf_profile_id: &str,
    entry_kind: &str,
    entry_id: &str,
) -> CryptoResult<Vec<u8>> {
    let fields =
        [("kdf_profile_id", kdf_profile_id), ("entry_kind", entry_kind), ("entry_id", entry_id)];
    let mut aad =
        Vec::with_capacity(RECOVERY_ENTRY_AAD_V1_PREFIX.len() + 2 + canonical_fields_len(&fields));
    aad.extend_from_slice(RECOVERY_ENTRY_AAD_V1_PREFIX);
    append_u16_le(&mut aad, RECOVERY_ENVELOPE_SCHEMA_V1);
    for (name, value) in fields {
        append_canonical_field(&mut aad, name, value)?;
    }
    Ok(aad)
}

/// Encrypts a recovery envelope entry payload using the v1 per-entry key schedule.
///
/// # Errors
///
/// Returns an error if key derivation, nonce generation, or encryption fails.
pub fn seal_recovery_entry_v1(
    unwrap_root: &KeyBytes,
    kdf_profile_id: &str,
    entry_kind: &str,
    entry_id: &str,
    plaintext: &[u8],
) -> CryptoResult<(NonceBytes, Vec<u8>)> {
    let entry_key = recovery_entry_key_v1(unwrap_root, entry_kind, entry_id, kdf_profile_id)?;
    let aad = recovery_entry_aad_v1(kdf_profile_id, entry_kind, entry_id)?;
    let nonce = random_bytes::<NONCE_LEN>()?;
    let ciphertext = aead_encrypt(&entry_key, &nonce, plaintext, &aad)?;
    Ok((nonce, ciphertext))
}

/// Decrypts a recovery envelope entry payload using the v1 per-entry key schedule.
///
/// # Errors
///
/// Returns an error if key derivation fails or ciphertext authentication fails.
pub fn open_recovery_entry_v1(
    unwrap_root: &KeyBytes,
    kdf_profile_id: &str,
    entry_kind: &str,
    entry_id: &str,
    nonce: &NonceBytes,
    ciphertext: &[u8],
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let entry_key = recovery_entry_key_v1(unwrap_root, entry_kind, entry_id, kdf_profile_id)?;
    let aad = recovery_entry_aad_v1(kdf_profile_id, entry_kind, entry_id)?;
    aead_decrypt(&entry_key, nonce, ciphertext, &aad)
}
