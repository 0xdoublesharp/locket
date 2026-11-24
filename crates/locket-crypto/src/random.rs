//! Random byte and key generation helpers.

use rand::TryRng as _;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

use crate::error::{CryptoError, CryptoResult};
use crate::{
    KEY_LEN, KeyBytes, PASSPHRASE_FALLBACK_SALT_LEN, RECOVERY_CODE_BYTES, RECOVERY_SALT_LEN,
};

/// Fills a fixed-size byte array with operating-system randomness.
///
/// # Errors
///
/// Returns [`CryptoError::RandomFailed`] when operating-system randomness is
/// unavailable.
pub fn random_bytes<const N: usize>() -> CryptoResult<[u8; N]> {
    let mut bytes = [0_u8; N];
    SysRng.try_fill_bytes(&mut bytes).map_err(|_| CryptoError::RandomFailed)?;
    Ok(bytes)
}

/// Generates a random 32-byte symmetric key.
///
/// # Errors
///
/// Returns [`CryptoError::RandomFailed`] when operating-system randomness is
/// unavailable.
pub fn generate_key() -> CryptoResult<Zeroizing<KeyBytes>> {
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    SysRng.try_fill_bytes(&mut *key).map_err(|_| CryptoError::RandomFailed)?;
    Ok(key)
}

/// Generates a random salt for passphrase fallback KDF profiles.
///
/// # Errors
///
/// Returns [`CryptoError::RandomFailed`] when operating-system randomness is
/// unavailable.
pub fn generate_passphrase_salt() -> CryptoResult<[u8; PASSPHRASE_FALLBACK_SALT_LEN]> {
    random_bytes::<PASSPHRASE_FALLBACK_SALT_LEN>()
}

/// Generates a fresh 20-byte random recovery code.
///
/// # Errors
///
/// Returns `CryptoError::RandomFailed` if the OS RNG fails.
pub fn generate_recovery_code_bytes() -> CryptoResult<[u8; RECOVERY_CODE_BYTES]> {
    let mut bytes = Zeroizing::new([0u8; RECOVERY_CODE_BYTES]);
    SysRng.try_fill_bytes(&mut *bytes).map_err(|_| CryptoError::RandomFailed)?;
    Ok(*bytes)
}

/// Generates a fresh random recovery salt.
///
/// # Errors
///
/// Returns `CryptoError::RandomFailed` if the OS RNG fails.
pub fn generate_recovery_salt() -> CryptoResult<[u8; RECOVERY_SALT_LEN]> {
    random_bytes::<RECOVERY_SALT_LEN>()
}
