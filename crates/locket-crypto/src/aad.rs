//! Canonical AAD (additional authenticated data) construction.
//!
//! This module owns the v1 schema versions, prefix constants, and the helper
//! functions that build deterministic AAD/HKDF info byte strings used by the
//! rest of the crate.

use crate::error::{CryptoError, CryptoResult};
use crate::purpose::{KeyPurpose, KeyWrapPurpose};

/// Current deterministic AAD schema version for encrypted secret values.
pub const AAD_SCHEMA_V1: u16 = 1;

/// Current key-wrap schema version.
pub const KEY_WRAP_SCHEMA_V1: u16 = 1;

/// Current HKDF wrap-info schema version.
pub const HKDF_WRAP_INFO_SCHEMA_V1: u16 = 1;

pub const AAD_V1_PREFIX: &[u8] = b"locket-aad-v1";
pub const KEY_WRAP_V1_PREFIX: &[u8] = b"locket-key-wrap-v1";
pub const HKDF_WRAP_INFO_V1_PREFIX: &[u8] = b"locket-wrap-v1";
pub const PASSPHRASE_FALLBACK_AAD_V1_PREFIX: &[u8] = b"locket-passphrase-fallback-v1";
pub const RECOVERY_ENTRY_AAD_V1_PREFIX: &[u8] = b"locket-recovery-envelope-v1";
pub const RECOVERY_ENTRY_HKDF_V1_PREFIX: &[u8] = b"locket-recovery-entry-v1";

/// Metadata used to derive canonical AAD for a secret blob.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SecretBlobAad<'a> {
    project_id: &'a str,
    profile_id: &'a str,
    secret_id: &'a str,
    secret_name: &'a str,
    version: u32,
}

impl<'a> SecretBlobAad<'a> {
    /// Creates secret blob AAD metadata.
    #[must_use]
    pub const fn new(
        project_id: &'a str,
        profile_id: &'a str,
        secret_id: &'a str,
        secret_name: &'a str,
        version: u32,
    ) -> Self {
        Self { project_id, profile_id, secret_id, secret_name, version }
    }
}

/// Metadata used to derive canonical AAD for a key wrap.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct KeyWrapAad<'a> {
    project_id: &'a str,
    key_id: &'a str,
    profile_id: Option<&'a str>,
    version: u32,
    purpose: KeyWrapPurpose,
}

impl<'a> KeyWrapAad<'a> {
    /// Creates key-wrap AAD metadata.
    ///
    /// Use `None` for `profile_id` when wrapping project-scoped keys.
    #[must_use]
    pub const fn new(
        project_id: &'a str,
        key_id: &'a str,
        profile_id: Option<&'a str>,
        version: u32,
        purpose: KeyWrapPurpose,
    ) -> Self {
        Self { project_id, key_id, profile_id, version, purpose }
    }
}

/// Metadata used to construct HKDF wrap info.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct HkdfWrapInfo<'a> {
    project_id: &'a str,
    profile_id: Option<&'a str>,
    purpose: KeyPurpose,
}

impl<'a> HkdfWrapInfo<'a> {
    /// Creates HKDF wrap-info metadata.
    ///
    /// Use `None` for `profile_id` when deriving project-scoped wrapping keys.
    #[must_use]
    pub const fn new(
        project_id: &'a str,
        profile_id: Option<&'a str>,
        purpose: KeyPurpose,
    ) -> Self {
        Self { project_id, profile_id, purpose }
    }
}

/// Appends a little-endian `u16` to an output buffer.
pub fn append_u16_le(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

/// Appends a little-endian `u32` to an output buffer.
pub fn append_u32_le(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

/// Appends a canonical v1 UTF-8 field to an output buffer.
///
/// # Errors
///
/// Returns [`CryptoError::FieldNameTooLong`] or [`CryptoError::FieldValueTooLong`]
/// if either component cannot be represented by the v1 length prefixes.
pub fn append_canonical_field(output: &mut Vec<u8>, name: &str, value: &str) -> CryptoResult<()> {
    let name_len = u16::try_from(name.len()).map_err(|_| CryptoError::FieldNameTooLong)?;
    let value_len = u32::try_from(value.len()).map_err(|_| CryptoError::FieldValueTooLong)?;

    append_u16_le(output, name_len);
    output.extend_from_slice(name.as_bytes());
    append_u32_le(output, value_len);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

pub fn canonical_fields_len(fields: &[(&str, &str)]) -> usize {
    fields.iter().map(|(name, value)| 2 + name.len() + 4 + value.len()).sum()
}

/// Returns the canonical v1 UTF-8 field encoding.
///
/// # Errors
///
/// Returns [`CryptoError::FieldNameTooLong`] or [`CryptoError::FieldValueTooLong`]
/// if either component cannot be represented by the v1 length prefixes.
pub fn canonical_field(name: &str, value: &str) -> CryptoResult<Vec<u8>> {
    let mut output = Vec::new();
    append_canonical_field(&mut output, name, value)?;
    Ok(output)
}

/// Constructs canonical secret blob AAD v1.
///
/// # Errors
///
/// Returns an error if any field cannot be represented by the canonical v1
/// length prefixes.
pub fn secret_blob_aad_v1(metadata: &SecretBlobAad<'_>) -> CryptoResult<Vec<u8>> {
    let fields = [
        ("project_id", metadata.project_id),
        ("profile_id", metadata.profile_id),
        ("secret_id", metadata.secret_id),
        ("secret_name", metadata.secret_name),
    ];
    let mut aad = Vec::with_capacity(AAD_V1_PREFIX.len() + 6 + canonical_fields_len(&fields));
    aad.extend_from_slice(AAD_V1_PREFIX);
    append_u16_le(&mut aad, AAD_SCHEMA_V1);
    for (name, value) in fields {
        append_canonical_field(&mut aad, name, value)?;
    }
    append_u32_le(&mut aad, metadata.version);
    Ok(aad)
}

/// Constructs canonical key-wrap AAD v1.
///
/// # Errors
///
/// Returns an error if any field cannot be represented by the canonical v1
/// length prefixes.
pub fn key_wrap_aad_v1(metadata: &KeyWrapAad<'_>) -> CryptoResult<Vec<u8>> {
    let profile_id = metadata.profile_id.unwrap_or("");
    let purpose = metadata.purpose.as_str();
    let fields = [
        ("project_id", metadata.project_id),
        ("key_id", metadata.key_id),
        ("profile_id", profile_id),
        ("purpose", purpose),
    ];
    let mut aad = Vec::with_capacity(KEY_WRAP_V1_PREFIX.len() + 6 + canonical_fields_len(&fields));
    aad.extend_from_slice(KEY_WRAP_V1_PREFIX);
    append_canonical_field(&mut aad, "project_id", metadata.project_id)?;
    append_canonical_field(&mut aad, "key_id", metadata.key_id)?;
    append_canonical_field(&mut aad, "profile_id", profile_id)?;
    append_u32_le(&mut aad, metadata.version);
    append_canonical_field(&mut aad, "purpose", purpose)?;
    append_u16_le(&mut aad, KEY_WRAP_SCHEMA_V1);
    Ok(aad)
}

/// Constructs canonical HKDF wrap info v1.
///
/// # Errors
///
/// Returns an error if any field cannot be represented by the canonical v1
/// length prefixes.
pub fn hkdf_wrap_info_v1(metadata: &HkdfWrapInfo<'_>) -> CryptoResult<Vec<u8>> {
    let fields = [
        ("project_id", metadata.project_id),
        ("profile_id", metadata.profile_id.unwrap_or("")),
        ("purpose", metadata.purpose.as_str()),
    ];
    let mut info =
        Vec::with_capacity(HKDF_WRAP_INFO_V1_PREFIX.len() + 2 + canonical_fields_len(&fields));
    info.extend_from_slice(HKDF_WRAP_INFO_V1_PREFIX);
    append_u16_le(&mut info, HKDF_WRAP_INFO_SCHEMA_V1);
    for (name, value) in fields {
        append_canonical_field(&mut info, name, value)?;
    }
    Ok(info)
}

/// Constructs canonical AAD for passphrase fallback master-key envelopes.
///
/// # Errors
///
/// Returns an error if either field cannot be represented by the canonical v1
/// length prefixes.
pub fn passphrase_fallback_aad_v1(project_id: &str, kdf_profile_id: &str) -> CryptoResult<Vec<u8>> {
    let fields = [("project_id", project_id), ("kdf_profile_id", kdf_profile_id)];
    let mut aad = Vec::with_capacity(
        PASSPHRASE_FALLBACK_AAD_V1_PREFIX.len() + 2 + canonical_fields_len(&fields),
    );
    aad.extend_from_slice(PASSPHRASE_FALLBACK_AAD_V1_PREFIX);
    append_u16_le(&mut aad, KEY_WRAP_SCHEMA_V1);
    for (name, value) in fields {
        append_canonical_field(&mut aad, name, value)?;
    }
    Ok(aad)
}
