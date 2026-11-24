//! Internal AEAD encrypt/decrypt helpers and shared input validation.

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::error::{CryptoError, CryptoResult};
use crate::{KeyBytes, NonceBytes};

pub fn validate_secret_value(value: &str) -> CryptoResult<()> {
    if value.as_bytes().contains(&0) { Err(CryptoError::InvalidSecretValue) } else { Ok(()) }
}

pub fn aead_encrypt(
    key: &KeyBytes,
    nonce: &NonceBytes,
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::EncryptionFailed)
}

pub fn aead_decrypt(
    key: &KeyBytes,
    nonce: &NonceBytes,
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::DecryptionFailed)
}
