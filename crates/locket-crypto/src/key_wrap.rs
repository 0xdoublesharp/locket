//! Key wrap, unwrap, and HKDF wrapping-key derivation helpers.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aad::{
    HkdfWrapInfo, append_canonical_field, append_u16_le, canonical_fields_len, hkdf_wrap_info_v1,
};
use crate::aead::{aead_decrypt, aead_encrypt};
use crate::error::{CryptoError, CryptoResult};
use crate::random::random_bytes;
use crate::{KEY_LEN, KeyBytes, NONCE_LEN, NonceBytes, TAG_LEN};

/// Domain-separated AAD prefix for passkey-PRF master-key wraps.
pub const PASSKEY_PRF_WRAP_V1_PREFIX: &[u8] = b"locket-passkey-prf-v1";

/// AAD schema version for passkey-PRF master-key wraps.
pub const PASSKEY_PRF_WRAP_SCHEMA_V1: u16 = 1;

/// Constructs canonical AAD for a passkey-PRF master-key wrap.
///
/// # Errors
///
/// Returns an error if any field cannot be represented by the canonical v1
/// length prefixes.
pub fn passkey_prf_wrap_aad_v1(project_id: &str) -> CryptoResult<Vec<u8>> {
    let mut aad = Vec::with_capacity(
        PASSKEY_PRF_WRAP_V1_PREFIX.len() + 2 + canonical_fields_len(&[("project_id", project_id)]),
    );
    aad.extend_from_slice(PASSKEY_PRF_WRAP_V1_PREFIX);
    append_u16_le(&mut aad, PASSKEY_PRF_WRAP_SCHEMA_V1);
    append_canonical_field(&mut aad, "project_id", project_id)?;
    Ok(aad)
}

/// Encrypted stored key material for a `keys` row.
#[derive(Clone, Eq, PartialEq)]
pub struct WrappedKeyMaterial {
    /// Wrapped key ciphertext without the nonce.
    pub ciphertext: Vec<u8>,
    /// Nonce used for key-wrap encryption.
    pub nonce: NonceBytes,
}

/// Derives a 32-byte wrapping key from a master key and canonical HKDF wrap info.
///
/// # Errors
///
/// Returns an error if wrap-info construction or HKDF expansion fails.
pub fn derive_wrapping_key_v1(
    master_key: &KeyBytes,
    metadata: &HkdfWrapInfo<'_>,
) -> CryptoResult<Zeroizing<KeyBytes>> {
    let info = hkdf_wrap_info_v1(metadata)?;
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    hkdf.expand(&info, &mut *key).map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

/// Wraps stored project/profile key material using separate nonce storage.
///
/// # Errors
///
/// Returns an error if random generation or encryption fails.
pub fn wrap_key_material_v1(
    wrapping_key: &KeyBytes,
    key_material: &KeyBytes,
    aad: &[u8],
) -> CryptoResult<WrappedKeyMaterial> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let ciphertext = aead_encrypt(wrapping_key, &nonce, key_material, aad)?;
    Ok(WrappedKeyMaterial { ciphertext, nonce })
}

/// Unwraps stored project/profile key material using separate nonce storage.
///
/// # Errors
///
/// Returns an error if authentication fails or plaintext length is invalid.
pub fn unwrap_key_material_v1(
    wrapping_key: &KeyBytes,
    wrapped: &WrappedKeyMaterial,
    aad: &[u8],
) -> CryptoResult<Zeroizing<KeyBytes>> {
    decrypt_key(wrapping_key, &wrapped.nonce, &wrapped.ciphertext, aad)
}

fn decrypt_key(
    wrapping_key: &KeyBytes,
    nonce: &NonceBytes,
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Zeroizing<KeyBytes>> {
    let plaintext = aead_decrypt(wrapping_key, nonce, ciphertext, aad)?;
    if plaintext.len() != KEY_LEN {
        return Err(CryptoError::InvalidWrappedKey);
    }

    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Wraps a 32-byte DEK using key-wrap v1 embedded nonce layout.
///
/// The returned bytes are `wrap_nonce || wrap_ciphertext`.
///
/// # Errors
///
/// Returns an error if random generation or encryption fails.
pub fn wrap_dek_v1(wrapping_key: &KeyBytes, dek: &KeyBytes, aad: &[u8]) -> CryptoResult<Vec<u8>> {
    let wrap_nonce = random_bytes::<NONCE_LEN>()?;
    let wrap_ciphertext = aead_encrypt(wrapping_key, &wrap_nonce, dek, aad)?;

    let mut wrapped = Vec::with_capacity(NONCE_LEN + wrap_ciphertext.len());
    wrapped.extend_from_slice(&wrap_nonce);
    wrapped.extend_from_slice(&wrap_ciphertext);
    Ok(wrapped)
}

/// Unwraps a 32-byte DEK using key-wrap v1 embedded nonce layout.
///
/// # Errors
///
/// Returns an error if the embedded layout is invalid or authentication fails.
pub fn unwrap_dek_v1(
    wrapping_key: &KeyBytes,
    encrypted_dek: &[u8],
    aad: &[u8],
) -> CryptoResult<Zeroizing<KeyBytes>> {
    let expected_len = NONCE_LEN + KEY_LEN + TAG_LEN;
    if encrypted_dek.len() != expected_len {
        return Err(CryptoError::InvalidWrappedKey);
    }

    let (wrap_nonce, wrap_ciphertext) = encrypted_dek.split_at(NONCE_LEN);
    let wrap_nonce: &NonceBytes =
        wrap_nonce.try_into().map_err(|_| CryptoError::InvalidWrappedKey)?;
    decrypt_key(wrapping_key, wrap_nonce, wrap_ciphertext, aad)
}

/// Wraps a master key under the 32-byte `WebAuthn` PRF output for `project_id`.
///
/// The PRF output is treated as the wrapping key directly. AAD ties the wrap
/// to the project plus the `locket-passkey-prf-v1` domain-separation prefix
/// so a wrap from a different project or domain cannot be confused with this
/// one.
///
/// # Errors
///
/// Returns an error if random generation, AAD construction, or encryption
/// fails.
pub fn wrap_master_key_with_passkey_prf(
    master_key: &KeyBytes,
    prf_output: &[u8; 32],
    project_id: &str,
) -> CryptoResult<WrappedKeyMaterial> {
    let aad = passkey_prf_wrap_aad_v1(project_id)?;
    wrap_key_material_v1(prf_output, master_key, &aad)
}

/// Unwraps a master key previously wrapped under a passkey PRF output.
///
/// # Errors
///
/// Returns [`CryptoError::DecryptionFailed`] when the PRF output, project id,
/// AAD, or wrap material does not authenticate, and
/// [`CryptoError::InvalidWrappedKey`] when the wrapped plaintext length is
/// not the expected master-key size.
pub fn unwrap_master_key_with_passkey_prf(
    wrapped: &WrappedKeyMaterial,
    prf_output: &[u8; 32],
    project_id: &str,
) -> CryptoResult<Zeroizing<KeyBytes>> {
    let aad = passkey_prf_wrap_aad_v1(project_id)?;
    unwrap_key_material_v1(prf_output, wrapped, &aad)
}
