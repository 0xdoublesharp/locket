//! Cryptographic primitives for Locket.

// rand 0.9 transitively brings rand_core 0.6 (via chacha20poly1305) and 0.9,
// which triggers this lint. This cannot be fixed without upgrading all crates.
#![allow(clippy::multiple_crate_versions)]

// criterion is a dev-dep used only by the bench target; pull it in for the
// lib-test target so `unused_crate_dependencies` stays quiet.
#[cfg(test)]
use criterion as _;

mod aad;
mod aead;
mod error;
mod key_wrap;
mod passphrase;
mod purpose;
mod random;
mod recovery_code;
mod recovery_envelope;
mod secret_value;

pub use aad::{
    AAD_SCHEMA_V1, HKDF_WRAP_INFO_SCHEMA_V1, HkdfWrapInfo, KEY_WRAP_SCHEMA_V1, KeyWrapAad,
    SecretBlobAad, append_canonical_field, append_u16_le, append_u32_le, canonical_field,
    hkdf_wrap_info_v1, key_wrap_aad_v1, passphrase_fallback_aad_v1, secret_blob_aad_v1,
};
pub use error::{CryptoError, CryptoResult};
pub use key_wrap::{
    PASSKEY_PRF_WRAP_SCHEMA_V1, PASSKEY_PRF_WRAP_V1_PREFIX, WrappedKeyMaterial,
    derive_wrapping_key_v1, passkey_prf_wrap_aad_v1, unwrap_dek_v1, unwrap_key_material_v1,
    unwrap_master_key_with_passkey_prf, wrap_dek_v1, wrap_key_material_v1,
    wrap_master_key_with_passkey_prf,
};
pub use passphrase::{PassphraseKdfParams, derive_passphrase_fallback_key_v1};
pub use purpose::{KeyPurpose, KeyWrapPurpose};
pub use random::{
    generate_key, generate_passphrase_salt, generate_recovery_code_bytes, generate_recovery_salt,
    random_bytes,
};
pub use recovery_code::{recovery_code_decode, recovery_code_encode};
pub use recovery_envelope::{
    RecoveryKdfParams, derive_recovery_key_v1, open_recovery_entry_v1, recovery_entry_aad_v1,
    recovery_entry_key_v1, seal_recovery_entry_v1,
};
pub use secret_value::{
    EncryptedSecretValue, decrypt_secret_value_v1, encrypt_secret_value_v1, local_dedup_tag_v1,
    secret_fingerprint_v1,
};

/// Size in bytes of Locket symmetric keys.
pub const KEY_LEN: usize = 32;

/// Size in bytes of `XChaCha20-Poly1305` nonces.
pub const NONCE_LEN: usize = 24;

/// Size in bytes of `Poly1305` authentication tags.
pub const TAG_LEN: usize = 16;

/// Size in bytes of keyed secret fingerprints.
pub const FINGERPRINT_LEN: usize = 32;

/// Recovery envelope magic bytes.
pub const RECOVERY_MAGIC: &[u8; 16] = b"LOCKET-RECOVERY\0";

/// Recovery envelope schema version.
pub const RECOVERY_ENVELOPE_SCHEMA_V1: u16 = 1;

/// Argon2id memory cost in KiB for recovery envelopes (m=65536).
pub const RECOVERY_M_COST: u32 = 65_536;

/// Argon2id iteration count for recovery envelopes (t=3).
pub const RECOVERY_T_COST: u32 = 3;

/// Argon2id parallelism for recovery envelopes (p=4).
pub const RECOVERY_P_COST: u32 = 4;

/// Recovery code random byte length (160 bits).
pub const RECOVERY_CODE_BYTES: usize = 20;

/// Recovery code data character count (32 Crockford Base32 chars).
pub const RECOVERY_CODE_DATA_CHARS: usize = 32;

/// Recovery code total character count including checksum (34 chars).
pub const RECOVERY_CODE_TOTAL_CHARS: usize = 34;

/// Salt length in bytes for new recovery envelopes.
pub const RECOVERY_SALT_LEN: usize = 32;

/// Argon2id memory cost in KiB for passphrase fallback envelopes.
pub const PASSPHRASE_FALLBACK_M_COST: u32 = 32_768;

/// Argon2id iteration count for passphrase fallback envelopes.
pub const PASSPHRASE_FALLBACK_T_COST: u32 = 2;

/// Argon2id parallelism for passphrase fallback envelopes.
pub const PASSPHRASE_FALLBACK_P_COST: u32 = 4;

/// Argon2id output length for passphrase fallback envelopes.
pub const PASSPHRASE_FALLBACK_OUTPUT_LEN: u32 = 32;

/// Salt length in bytes for new passphrase fallback envelopes.
pub const PASSPHRASE_FALLBACK_SALT_LEN: usize = 32;

/// Fixed-size symmetric key bytes.
pub type KeyBytes = [u8; KEY_LEN];

/// Fixed-size `XChaCha20-Poly1305` nonce bytes.
pub type NonceBytes = [u8; NONCE_LEN];

/// Fixed-size keyed fingerprint bytes.
pub type FingerprintBytes = [u8; FINGERPRINT_LEN];

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(kani)]
mod kani_proofs;
