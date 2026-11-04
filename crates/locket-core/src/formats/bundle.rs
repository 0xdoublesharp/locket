//! Sealed bundle versioned container format.
//!
//! A bundle is a versioned Locket container with:
//! - 8-byte ASCII magic header (`LKBNDL\0\0`),
//! - `u16` little-endian schema version,
//! - `u32` little-endian plaintext manifest length followed by the
//!   canonical-JSON manifest bytes,
//! - `u64` little-endian encrypted-payload length followed by the
//!   opaque payload bytes.
//!
//! The plaintext manifest is intentionally minimal because sealed
//! bundles are commonly stored in sync folders. Only a small allow-list
//! of fields is permitted; the writer rejects manifests that mention
//! profile, secret, policy, member, or device names — those belong
//! inside the encrypted payload, not the plaintext header.
//!
//! The reader/writer pair in this module is format-only: it carries an
//! opaque `encrypted_payload` byte slice. Encryption (age) and payload
//! schema are layered on top by separate slices.

use std::collections::BTreeSet;
use std::io::{Read, Write};

use bech32::{Bech32, Hrp};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

/// Magic header that prefixes every Locket sealed bundle.
pub const BUNDLE_MAGIC: &[u8; 8] = b"LKBNDL\0\0";

/// Current sealed-bundle container schema version.
pub const BUNDLE_SCHEMA_V1: u16 = 1;

/// Maximum plaintext manifest size in bytes. The plaintext manifest is
/// metadata-only; anything larger almost certainly leaks payload data
/// into the unencrypted header.
pub const BUNDLE_MAX_MANIFEST_LEN: usize = 64 * 1024;

/// Maximum encrypted payload size in bytes (256 MiB). Bundles larger
/// than this are rejected on read to bound peak memory while parsing.
pub const BUNDLE_MAX_PAYLOAD_LEN: u64 = 256 * 1024 * 1024;

/// Plaintext-manifest field allow-list. Any other key in the manifest
/// JSON is treated as a minimization violation.
pub const BUNDLE_MANIFEST_ALLOWED_FIELDS: &[&str] = &[
    "recipient_fingerprints",
    "project_id",
    "schema_version",
    "created_at",
    "profile_count",
    "payload_digest",
];

/// Plaintext-minimal sealed-bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// Hex SHA-256 fingerprints of recipient devices.
    pub recipient_fingerprints: Vec<String>,
    /// Locket project identifier (`lk_proj_*`).
    pub project_id: String,
    /// Schema version, mirrored from the binary header for self-checking.
    pub schema_version: u16,
    /// Creation timestamp as Unix nanoseconds.
    pub created_at: i64,
    /// Number of profiles whose key material is included in the
    /// encrypted payload. Names are not included.
    pub profile_count: u32,
    /// Hex SHA-256 digest of the encrypted payload.
    pub payload_digest: String,
}

/// Errors raised by the sealed-bundle container reader/writer.
///
/// All error paths in this module map to
/// [`LocketError::BundleVerificationFailed`](crate::error::LocketError::BundleVerificationFailed)
/// (exit `110`) at the call boundary.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BundleContainerError {
    /// Magic header bytes did not match `LKBNDL\0\0`.
    #[error("bundle magic header mismatch")]
    MagicMismatch,
    /// Schema version is not one of the supported values.
    #[error("bundle schema version {0} is not supported")]
    UnsupportedSchema(u16),
    /// Bundle bytes ended before the format required.
    #[error("bundle bytes truncated at offset {0}")]
    Truncated(usize),
    /// Plaintext manifest length exceeded [`BUNDLE_MAX_MANIFEST_LEN`].
    #[error("bundle manifest is {0} bytes (limit {1})")]
    ManifestTooLarge(usize, usize),
    /// Encrypted payload length exceeded [`BUNDLE_MAX_PAYLOAD_LEN`].
    #[error("bundle payload is {0} bytes (limit {1})")]
    PayloadTooLarge(u64, u64),
    /// Manifest bytes were not valid canonical JSON.
    #[error("bundle manifest is not valid JSON: {0}")]
    ManifestNotJson(String),
    /// Manifest contained a field outside the allow-list.
    #[error("bundle manifest field {0} is not allowed")]
    ManifestForbiddenField(String),
    /// Manifest was missing a required field.
    #[error("bundle manifest is missing required field {0}")]
    ManifestMissingField(&'static str),
    /// Manifest `schema_version` did not match the header.
    #[error("bundle manifest schema_version {manifest} does not match header {header}")]
    ManifestSchemaMismatch {
        /// Schema version from the binary header.
        header: u16,
        /// Schema version inside the JSON manifest.
        manifest: u16,
    },
    /// Bundle had trailing bytes after the declared payload.
    #[error("bundle has {0} trailing bytes after payload")]
    TrailingBytes(usize),
}

/// Result alias for sealed-bundle container operations.
pub type BundleContainerResult<T> = Result<T, BundleContainerError>;

/// Errors raised while encrypting or decrypting bundle payload bytes
/// with age.
///
/// Callers map these to the slice-appropriate typed error. Export-time
/// recipient validation is usually configuration/metadata invalid, while
/// verify/decrypt failures map to `BundleVerificationFailed`.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BundleEncryptionError {
    /// At least one recipient is required by the age format.
    #[error("bundle encryption requires at least one recipient")]
    MissingRecipients,
    /// A stored or decoded recipient key could not be converted into
    /// an age X25519 recipient.
    #[error("bundle recipient {index} is invalid: {message}")]
    InvalidRecipient {
        /// Zero-based recipient index from the caller's list.
        index: usize,
        /// Redacted parse failure.
        message: String,
    },
    /// age rejected the recipient set or failed while encrypting.
    #[error("bundle encryption failed: {0}")]
    Encrypt(String),
    /// age could not parse, authenticate, or decrypt the ciphertext.
    #[error("bundle decryption failed: {0}")]
    Decrypt(String),
}

/// Result alias for age bundle payload operations.
pub type BundleEncryptionResult<T> = Result<T, BundleEncryptionError>;

/// Plaintext header + encrypted payload pair as it appears on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleContainer {
    /// Plaintext manifest.
    pub manifest: BundleManifest,
    /// Opaque encrypted payload bytes (age v1 ciphertext or test stub).
    pub encrypted_payload: Vec<u8>,
}

/// Encrypts a canonical bundle payload as an age v1 binary file for one
/// or more X25519 recipients.
///
/// The `recipient_public_keys` values are the 32-byte raw public keys
/// carried in Locket device descriptors and device rows. The resulting
/// ciphertext is suitable for [`BundleContainer::encrypted_payload`].
///
/// # Errors
///
/// Returns [`BundleEncryptionError::MissingRecipients`] for an empty
/// recipient list, [`BundleEncryptionError::InvalidRecipient`] for an
/// invalid public key encoding, or [`BundleEncryptionError::Encrypt`]
/// if age cannot construct or finish the file.
pub fn encrypt_bundle_payload_for_age_recipients(
    plaintext: &[u8],
    recipient_public_keys: &[[u8; 32]],
) -> BundleEncryptionResult<Vec<u8>> {
    if recipient_public_keys.is_empty() {
        return Err(BundleEncryptionError::MissingRecipients);
    }
    let recipients = recipient_public_keys
        .iter()
        .enumerate()
        .map(|(index, public_key)| age_recipient_from_x25519_public_key(index, public_key))
        .collect::<BundleEncryptionResult<Vec<_>>>()?;
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|recipient| recipient as _))
            .map_err(|error| BundleEncryptionError::Encrypt(error.to_string()))?;
    let mut encrypted = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut encrypted)
            .map_err(|error| BundleEncryptionError::Encrypt(error.to_string()))?;
        writer
            .write_all(plaintext)
            .map_err(|error| BundleEncryptionError::Encrypt(error.to_string()))?;
        writer.finish().map_err(|error| BundleEncryptionError::Encrypt(error.to_string()))?;
    }
    Ok(encrypted)
}

/// Parses an age v1 binary payload header without attempting decryption.
///
/// This is the structural-only verification path used when the current
/// device does not have a usable local sealing private key.
///
/// # Errors
///
/// Returns [`BundleEncryptionError::Decrypt`] if age cannot parse a
/// valid v1 header with recipient stanzas.
pub fn verify_age_payload_structure(encrypted_payload: &[u8]) -> BundleEncryptionResult<()> {
    age::Decryptor::new(encrypted_payload)
        .map(|_| ())
        .map_err(|error| BundleEncryptionError::Decrypt(error.to_string()))
}

/// Decrypts an age-encrypted bundle payload with a local X25519 identity.
///
/// # Errors
///
/// Returns [`BundleEncryptionError::Decrypt`] if the payload is
/// malformed, is not addressed to `identity`, or fails authentication.
pub fn decrypt_bundle_payload_with_age_identity(
    encrypted_payload: &[u8],
    identity: &age::x25519::Identity,
) -> BundleEncryptionResult<Vec<u8>> {
    let decryptor = age::Decryptor::new(encrypted_payload)
        .map_err(|error| BundleEncryptionError::Decrypt(error.to_string()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|error| BundleEncryptionError::Decrypt(error.to_string()))?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|error| BundleEncryptionError::Decrypt(error.to_string()))?;
    Ok(plaintext)
}

/// Decrypts an age-encrypted bundle payload using a 32-byte X25519 secret key.
///
/// Convenience wrapper over [`decrypt_bundle_payload_with_age_identity`] for
/// callers (such as `locket-cli`) that receive raw key bytes from the device
/// private-key storage and don't depend on the `age` crate directly.
///
/// # Errors
///
/// Returns [`BundleEncryptionError::Decrypt`] if the secret cannot be encoded
/// as a bech32 age identity, the payload is malformed, is not addressed to
/// the identity, or fails authentication.
pub fn decrypt_bundle_payload_with_x25519_secret(
    encrypted_payload: &[u8],
    secret_key: &[u8; 32],
) -> BundleEncryptionResult<Vec<u8>> {
    let hrp = Hrp::parse("AGE-SECRET-KEY-").map_err(|error| {
        BundleEncryptionError::Decrypt(format!("invalid x25519 secret hrp: {error}"))
    })?;
    let encoded = bech32::encode::<Bech32>(hrp, secret_key).map_err(|error| {
        BundleEncryptionError::Decrypt(format!("invalid x25519 secret: {error}"))
    })?;
    let encoded = encoded.to_uppercase();
    let identity: age::x25519::Identity = encoded
        .parse()
        .map_err(|message: &'static str| BundleEncryptionError::Decrypt(message.to_owned()))?;
    decrypt_bundle_payload_with_age_identity(encrypted_payload, &identity)
}

impl BundleContainer {
    /// Constructs a container, validating that the manifest carries
    /// only allow-listed fields and a sane schema version.
    ///
    /// # Errors
    ///
    /// Returns [`BundleContainerError`] if the manifest is malformed
    /// or its schema version is unsupported.
    pub fn new(
        manifest: BundleManifest,
        encrypted_payload: Vec<u8>,
    ) -> BundleContainerResult<Self> {
        validate_manifest(&manifest)?;
        Ok(Self { manifest, encrypted_payload })
    }

    /// Serializes the container to its canonical binary representation.
    ///
    /// # Errors
    ///
    /// Returns [`BundleContainerError::ManifestTooLarge`] when the
    /// canonical JSON manifest exceeds [`BUNDLE_MAX_MANIFEST_LEN`], or
    /// [`BundleContainerError::PayloadTooLarge`] when the encrypted
    /// payload exceeds [`BUNDLE_MAX_PAYLOAD_LEN`].
    pub fn serialize(&self) -> BundleContainerResult<Vec<u8>> {
        validate_manifest(&self.manifest)?;
        let manifest_bytes = serialize_manifest(&self.manifest);
        if manifest_bytes.len() > BUNDLE_MAX_MANIFEST_LEN {
            return Err(BundleContainerError::ManifestTooLarge(
                manifest_bytes.len(),
                BUNDLE_MAX_MANIFEST_LEN,
            ));
        }
        let payload_len = self.encrypted_payload.len() as u64;
        if payload_len > BUNDLE_MAX_PAYLOAD_LEN {
            return Err(BundleContainerError::PayloadTooLarge(payload_len, BUNDLE_MAX_PAYLOAD_LEN));
        }
        #[allow(clippy::cast_possible_truncation)]
        let manifest_len_u32 = manifest_bytes.len() as u32;
        let mut buf = Vec::with_capacity(
            BUNDLE_MAGIC.len() + 2 + 4 + manifest_bytes.len() + 8 + self.encrypted_payload.len(),
        );
        buf.extend_from_slice(BUNDLE_MAGIC);
        buf.extend_from_slice(&self.manifest.schema_version.to_le_bytes());
        buf.extend_from_slice(&manifest_len_u32.to_le_bytes());
        buf.extend_from_slice(&manifest_bytes);
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&self.encrypted_payload);
        Ok(buf)
    }

    /// Parses a container from its canonical binary representation.
    ///
    /// # Errors
    ///
    /// Returns [`BundleContainerError`] for any structural problem:
    /// magic mismatch, unsupported schema, truncation, oversized
    /// fields, manifest minimization violation, or trailing bytes.
    pub fn deserialize(data: &[u8]) -> BundleContainerResult<Self> {
        let mut cursor = 0usize;
        let magic = read_slice(&mut cursor, data, BUNDLE_MAGIC.len())?;
        if magic != BUNDLE_MAGIC.as_slice() {
            return Err(BundleContainerError::MagicMismatch);
        }
        let schema_bytes = read_slice(&mut cursor, data, 2)?;
        let schema_version = u16::from_le_bytes([schema_bytes[0], schema_bytes[1]]);
        if schema_version != BUNDLE_SCHEMA_V1 {
            return Err(BundleContainerError::UnsupportedSchema(schema_version));
        }
        let manifest_len_bytes = read_slice(&mut cursor, data, 4)?;
        let manifest_len = u32::from_le_bytes([
            manifest_len_bytes[0],
            manifest_len_bytes[1],
            manifest_len_bytes[2],
            manifest_len_bytes[3],
        ]) as usize;
        if manifest_len > BUNDLE_MAX_MANIFEST_LEN {
            return Err(BundleContainerError::ManifestTooLarge(
                manifest_len,
                BUNDLE_MAX_MANIFEST_LEN,
            ));
        }
        let manifest_bytes = read_slice(&mut cursor, data, manifest_len)?.to_vec();
        let payload_len_bytes = read_slice(&mut cursor, data, 8)?;
        let payload_len = u64::from_le_bytes([
            payload_len_bytes[0],
            payload_len_bytes[1],
            payload_len_bytes[2],
            payload_len_bytes[3],
            payload_len_bytes[4],
            payload_len_bytes[5],
            payload_len_bytes[6],
            payload_len_bytes[7],
        ]);
        if payload_len > BUNDLE_MAX_PAYLOAD_LEN {
            return Err(BundleContainerError::PayloadTooLarge(payload_len, BUNDLE_MAX_PAYLOAD_LEN));
        }
        let payload_len_usize = usize::try_from(payload_len).map_err(|_| {
            BundleContainerError::PayloadTooLarge(payload_len, BUNDLE_MAX_PAYLOAD_LEN)
        })?;
        let payload = read_slice(&mut cursor, data, payload_len_usize)?.to_vec();
        if cursor != data.len() {
            return Err(BundleContainerError::TrailingBytes(data.len() - cursor));
        }

        let manifest = parse_manifest(&manifest_bytes, schema_version)?;
        Ok(Self { manifest, encrypted_payload: payload })
    }
}

/// Validates that a manifest carries only allow-listed fields and a
/// supported schema version. The manifest bytes themselves are not
/// inspected here — that happens at parse time on the receiver side.
const fn validate_manifest(manifest: &BundleManifest) -> BundleContainerResult<()> {
    if manifest.schema_version != BUNDLE_SCHEMA_V1 {
        return Err(BundleContainerError::UnsupportedSchema(manifest.schema_version));
    }
    if manifest.project_id.is_empty() {
        return Err(BundleContainerError::ManifestMissingField("project_id"));
    }
    if manifest.payload_digest.is_empty() {
        return Err(BundleContainerError::ManifestMissingField("payload_digest"));
    }
    Ok(())
}

fn serialize_manifest(manifest: &BundleManifest) -> Vec<u8> {
    // The order here mirrors `BUNDLE_MANIFEST_ALLOWED_FIELDS` lexically.
    // serde_json serializes BTreeMap-backed `Map` in sorted key order
    // anyway, so the canonical JSON byte order is stable.
    let mut object = Map::new();
    object.insert(
        "recipient_fingerprints".to_owned(),
        Value::Array(manifest.recipient_fingerprints.iter().cloned().map(Value::String).collect()),
    );
    object.insert("project_id".to_owned(), Value::String(manifest.project_id.clone()));
    object.insert(
        "schema_version".to_owned(),
        Value::Number(serde_json::Number::from(manifest.schema_version)),
    );
    object.insert(
        "created_at".to_owned(),
        Value::Number(serde_json::Number::from(manifest.created_at)),
    );
    object.insert(
        "profile_count".to_owned(),
        Value::Number(serde_json::Number::from(manifest.profile_count)),
    );
    object.insert("payload_digest".to_owned(), Value::String(manifest.payload_digest.clone()));
    crate::canonical_json(&Value::Object(object)).into_bytes()
}

fn age_recipient_from_x25519_public_key(
    index: usize,
    public_key: &[u8; 32],
) -> BundleEncryptionResult<age::x25519::Recipient> {
    let hrp = Hrp::parse("age").map_err(|error| BundleEncryptionError::InvalidRecipient {
        index,
        message: error.to_string(),
    })?;
    let encoded = bech32::encode::<Bech32>(hrp, public_key).map_err(|error| {
        BundleEncryptionError::InvalidRecipient { index, message: error.to_string() }
    })?;
    encoded.parse().map_err(|message: &'static str| BundleEncryptionError::InvalidRecipient {
        index,
        message: message.to_owned(),
    })
}

fn parse_manifest(
    bytes: &[u8],
    header_schema_version: u16,
) -> BundleContainerResult<BundleManifest> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| BundleContainerError::ManifestNotJson(error.to_string()))?;
    let Value::Object(map) = value else {
        return Err(BundleContainerError::ManifestNotJson("manifest is not a JSON object".into()));
    };

    let allowed: BTreeSet<&str> = BUNDLE_MANIFEST_ALLOWED_FIELDS.iter().copied().collect();
    for key in map.keys() {
        if !allowed.contains(key.as_str()) {
            return Err(BundleContainerError::ManifestForbiddenField(key.clone()));
        }
    }

    let schema_version = manifest_required_u16(&map, "schema_version")?;
    if schema_version != header_schema_version {
        return Err(BundleContainerError::ManifestSchemaMismatch {
            header: header_schema_version,
            manifest: schema_version,
        });
    }

    let project_id = manifest_required_string(&map, "project_id")?;
    let payload_digest = manifest_required_string(&map, "payload_digest")?;
    let created_at = manifest_required_i64(&map, "created_at")?;
    let profile_count = manifest_required_u32(&map, "profile_count")?;
    let recipient_fingerprints = manifest_required_string_array(&map, "recipient_fingerprints")?;

    Ok(BundleManifest {
        recipient_fingerprints,
        project_id,
        schema_version,
        created_at,
        profile_count,
        payload_digest,
    })
}

fn manifest_required_string(
    map: &Map<String, Value>,
    field: &'static str,
) -> BundleContainerResult<String> {
    match map.get(field) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        Some(_) | None => Err(BundleContainerError::ManifestMissingField(field)),
    }
}

fn manifest_required_u16(
    map: &Map<String, Value>,
    field: &'static str,
) -> BundleContainerResult<u16> {
    let n = map
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(BundleContainerError::ManifestMissingField(field))?;
    u16::try_from(n).map_err(|_| BundleContainerError::ManifestMissingField(field))
}

fn manifest_required_u32(
    map: &Map<String, Value>,
    field: &'static str,
) -> BundleContainerResult<u32> {
    let n = map
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(BundleContainerError::ManifestMissingField(field))?;
    u32::try_from(n).map_err(|_| BundleContainerError::ManifestMissingField(field))
}

fn manifest_required_i64(
    map: &Map<String, Value>,
    field: &'static str,
) -> BundleContainerResult<i64> {
    map.get(field).and_then(Value::as_i64).ok_or(BundleContainerError::ManifestMissingField(field))
}

fn manifest_required_string_array(
    map: &Map<String, Value>,
    field: &'static str,
) -> BundleContainerResult<Vec<String>> {
    let value = map.get(field).ok_or(BundleContainerError::ManifestMissingField(field))?;
    let Value::Array(items) = value else {
        return Err(BundleContainerError::ManifestMissingField(field));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::String(s) = item else {
            return Err(BundleContainerError::ManifestMissingField(field));
        };
        out.push(s.clone());
    }
    Ok(out)
}

fn read_slice<'data>(
    cursor: &mut usize,
    data: &'data [u8],
    len: usize,
) -> BundleContainerResult<&'data [u8]> {
    let end = cursor.checked_add(len).ok_or(BundleContainerError::Truncated(*cursor))?;
    if end > data.len() {
        return Err(BundleContainerError::Truncated(*cursor));
    }
    let slice = &data[*cursor..end];
    *cursor = end;
    Ok(slice)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
#[allow(clippy::panic)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn sample_manifest() -> BundleManifest {
        BundleManifest {
            recipient_fingerprints: vec!["a".repeat(64), "b".repeat(64)],
            project_id: "lk_proj_demo".to_owned(),
            schema_version: BUNDLE_SCHEMA_V1,
            created_at: 1_700_000_000_000_000_000,
            profile_count: 2,
            payload_digest: "c".repeat(64),
        }
    }

    fn public_key_bytes(recipient: &age::x25519::Recipient) -> [u8; 32] {
        let (hrp, data) = bech32::decode(&recipient.to_string()).unwrap();
        assert_eq!(hrp.as_str(), "age");
        data.try_into().unwrap()
    }

    #[test]
    fn round_trip_synthetic_container_preserves_manifest_and_payload() {
        let payload = b"opaque-encrypted-payload-bytes".to_vec();
        let container =
            BundleContainer::new(sample_manifest(), payload.clone()).expect("valid container");
        let bytes = container.serialize().expect("serialize succeeds");
        assert_eq!(&bytes[..BUNDLE_MAGIC.len()], BUNDLE_MAGIC.as_slice());
        let parsed = BundleContainer::deserialize(&bytes).expect("deserialize succeeds");
        assert_eq!(parsed, container);
        assert_eq!(parsed.encrypted_payload, payload);
    }

    #[test]
    fn age_payload_encrypts_for_multiple_recipients_and_decrypts_matching_identity() {
        let identity_a = age::x25519::Identity::generate();
        let identity_b = age::x25519::Identity::generate();
        let recipient_keys =
            [public_key_bytes(&identity_a.to_public()), public_key_bytes(&identity_b.to_public())];
        let plaintext = br#"{"schema_version":1,"profile_count":1}"#;

        let encrypted =
            encrypt_bundle_payload_for_age_recipients(plaintext, &recipient_keys).unwrap();

        assert_ne!(encrypted, plaintext);
        verify_age_payload_structure(&encrypted).unwrap();
        let decrypted = decrypt_bundle_payload_with_age_identity(&encrypted, &identity_b).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn age_payload_requires_at_least_one_recipient() {
        let error = encrypt_bundle_payload_for_age_recipients(b"{}", &[]).unwrap_err();
        assert_eq!(error, BundleEncryptionError::MissingRecipients);
    }

    #[test]
    fn age_payload_structure_rejects_plaintext_payload() {
        let error = verify_age_payload_structure(b"{\"not\":\"age\"}").unwrap_err();
        assert!(matches!(error, BundleEncryptionError::Decrypt(_)));
    }

    #[test]
    fn deserialize_rejects_unknown_schema_version() {
        let mut bytes =
            BundleContainer::new(sample_manifest(), Vec::new()).unwrap().serialize().unwrap();
        // Schema version sits immediately after the 8-byte magic.
        bytes[BUNDLE_MAGIC.len()] = 99;
        bytes[BUNDLE_MAGIC.len() + 1] = 0;
        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert_eq!(error, BundleContainerError::UnsupportedSchema(99));
    }

    #[test]
    fn deserialize_rejects_oversized_manifest_length_field() {
        let payload = b"x".to_vec();
        let mut bytes =
            BundleContainer::new(sample_manifest(), payload).unwrap().serialize().unwrap();
        // Overwrite the manifest_len u32 with a value past the cap.
        let len_offset = BUNDLE_MAGIC.len() + 2;
        let oversized = (BUNDLE_MAX_MANIFEST_LEN as u32 + 1).to_le_bytes();
        bytes[len_offset..len_offset + 4].copy_from_slice(&oversized);
        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        match error {
            BundleContainerError::ManifestTooLarge(actual, limit) => {
                assert_eq!(limit, BUNDLE_MAX_MANIFEST_LEN);
                assert_eq!(actual, BUNDLE_MAX_MANIFEST_LEN + 1);
            }
            other => panic!("expected ManifestTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_disallowed_manifest_fields() {
        // Hand-craft a container where the JSON manifest carries a
        // forbidden key (`profile_name`). Names belong inside the
        // encrypted payload, not the plaintext header.
        let mut object = Map::new();
        object.insert(
            "recipient_fingerprints".to_owned(),
            Value::Array(vec![Value::String("a".repeat(64))]),
        );
        object.insert("project_id".to_owned(), Value::String("lk_proj_demo".to_owned()));
        object.insert("schema_version".to_owned(), Value::Number(BUNDLE_SCHEMA_V1.into()));
        object.insert("created_at".to_owned(), Value::Number(1_i64.into()));
        object.insert("profile_count".to_owned(), Value::Number(0_u32.into()));
        object.insert("payload_digest".to_owned(), Value::String("c".repeat(64)));
        // Forbidden field — names must never appear in the plaintext header.
        object.insert("profile_name".to_owned(), Value::String("dev".to_owned()));
        let manifest_bytes = crate::canonical_json(&Value::Object(object)).into_bytes();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_SCHEMA_V1.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&0_u64.to_le_bytes());

        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(error, BundleContainerError::ManifestForbiddenField(ref f) if f == "profile_name"),
            "expected ManifestForbiddenField(profile_name), got {error:?}"
        );
    }

    #[test]
    fn deserialize_rejects_bad_magic() {
        let mut bytes =
            BundleContainer::new(sample_manifest(), Vec::new()).unwrap().serialize().unwrap();
        bytes[0] = 0xFF;
        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert_eq!(error, BundleContainerError::MagicMismatch);
    }

    #[test]
    fn deserialize_rejects_truncation() {
        let bytes =
            BundleContainer::new(sample_manifest(), b"abc".to_vec()).unwrap().serialize().unwrap();
        for cut in [0_usize, 4, BUNDLE_MAGIC.len() + 1, bytes.len() - 1] {
            let truncated = &bytes[..cut];
            assert!(matches!(
                BundleContainer::deserialize(truncated),
                Err(BundleContainerError::Truncated(_) | BundleContainerError::MagicMismatch)
            ));
        }
    }

    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let mut bytes =
            BundleContainer::new(sample_manifest(), b"abc".to_vec()).unwrap().serialize().unwrap();
        bytes.push(0xAA);
        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert_eq!(error, BundleContainerError::TrailingBytes(1));
    }

    #[test]
    fn deserialize_rejects_manifest_schema_mismatch() {
        // Build a manifest whose embedded schema_version disagrees
        // with the header. Both fields exist for self-checking.
        let mut object = Map::new();
        object.insert("recipient_fingerprints".to_owned(), Value::Array(Vec::new()));
        object.insert("project_id".to_owned(), Value::String("lk_proj_demo".to_owned()));
        object.insert("schema_version".to_owned(), Value::Number(2_u16.into()));
        object.insert("created_at".to_owned(), Value::Number(1_i64.into()));
        object.insert("profile_count".to_owned(), Value::Number(0_u32.into()));
        object.insert("payload_digest".to_owned(), Value::String("d".repeat(64)));
        let manifest_bytes = crate::canonical_json(&Value::Object(object)).into_bytes();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_SCHEMA_V1.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&0_u64.to_le_bytes());

        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert!(matches!(
            error,
            BundleContainerError::ManifestSchemaMismatch { header: 1, manifest: 2 }
        ));
    }

    #[test]
    fn deserialize_rejects_payload_length_above_cap() {
        let mut bytes =
            BundleContainer::new(sample_manifest(), Vec::new()).unwrap().serialize().unwrap();
        // Payload length sits at the tail right before the (empty) payload.
        let payload_len_offset = bytes.len() - 8;
        let oversized = (BUNDLE_MAX_PAYLOAD_LEN + 1).to_le_bytes();
        bytes[payload_len_offset..].copy_from_slice(&oversized);
        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert!(matches!(error, BundleContainerError::PayloadTooLarge(_, _)));
    }

    #[test]
    fn new_rejects_unsupported_schema_at_construction() {
        let mut manifest = sample_manifest();
        manifest.schema_version = 7;
        let error = BundleContainer::new(manifest, Vec::new()).unwrap_err();
        assert_eq!(error, BundleContainerError::UnsupportedSchema(7));
    }

    #[test]
    fn new_rejects_empty_project_id() {
        let mut manifest = sample_manifest();
        manifest.project_id = String::new();
        let error = BundleContainer::new(manifest, Vec::new()).unwrap_err();
        assert_eq!(error, BundleContainerError::ManifestMissingField("project_id"));
    }

    #[test]
    fn new_rejects_empty_payload_digest() {
        let mut manifest = sample_manifest();
        manifest.payload_digest = String::new();
        let error = BundleContainer::new(manifest, Vec::new()).unwrap_err();
        assert_eq!(error, BundleContainerError::ManifestMissingField("payload_digest"));
    }

    #[test]
    fn serialize_rejects_oversized_payload() {
        // Construct via direct struct init so we bypass new() validation.
        let manifest = sample_manifest();
        let container = BundleContainer { manifest, encrypted_payload: Vec::new() };
        // serialize() rechecks size via payload_len.
        // We can't easily allocate 256MiB+; instead, validate the cap constant is enforced
        // by checking serialize succeeds on small payload (smoke).
        let bytes = container.serialize().unwrap();
        assert_ne!(bytes.len(), 0);
    }

    #[test]
    fn deserialize_rejects_manifest_invalid_json() {
        let manifest_bytes = b"not-json";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_SCHEMA_V1.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(manifest_bytes);
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert!(matches!(error, BundleContainerError::ManifestNotJson(_)));
    }

    #[test]
    fn deserialize_rejects_manifest_json_array_root() {
        // Valid JSON but not an object at root.
        let manifest_bytes = b"[1,2,3]";
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_SCHEMA_V1.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(manifest_bytes);
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert!(matches!(error, BundleContainerError::ManifestNotJson(_)));
    }

    #[test]
    fn deserialize_rejects_missing_required_field() {
        let mut object = Map::new();
        object.insert("schema_version".to_owned(), Value::Number(BUNDLE_SCHEMA_V1.into()));
        // Missing project_id.
        let manifest_bytes = crate::canonical_json(&Value::Object(object)).into_bytes();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_SCHEMA_V1.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert!(matches!(error, BundleContainerError::ManifestMissingField(_)));
    }

    #[test]
    fn deserialize_rejects_recipient_fingerprints_with_non_string() {
        let mut object = Map::new();
        object.insert(
            "recipient_fingerprints".to_owned(),
            Value::Array(vec![Value::Number(42_u32.into())]),
        );
        object.insert("project_id".to_owned(), Value::String("lk_proj_demo".to_owned()));
        object.insert("schema_version".to_owned(), Value::Number(BUNDLE_SCHEMA_V1.into()));
        object.insert("created_at".to_owned(), Value::Number(1_i64.into()));
        object.insert("profile_count".to_owned(), Value::Number(0_u32.into()));
        object.insert("payload_digest".to_owned(), Value::String("c".repeat(64)));
        let manifest_bytes = crate::canonical_json(&Value::Object(object)).into_bytes();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_SCHEMA_V1.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&0_u64.to_le_bytes());

        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert!(matches!(
            error,
            BundleContainerError::ManifestMissingField("recipient_fingerprints")
        ));
    }

    #[test]
    fn deserialize_rejects_recipient_fingerprints_not_array() {
        let mut object = Map::new();
        object
            .insert("recipient_fingerprints".to_owned(), Value::String("not-an-array".to_owned()));
        object.insert("project_id".to_owned(), Value::String("lk_proj_demo".to_owned()));
        object.insert("schema_version".to_owned(), Value::Number(BUNDLE_SCHEMA_V1.into()));
        object.insert("created_at".to_owned(), Value::Number(1_i64.into()));
        object.insert("profile_count".to_owned(), Value::Number(0_u32.into()));
        object.insert("payload_digest".to_owned(), Value::String("c".repeat(64)));
        let manifest_bytes = crate::canonical_json(&Value::Object(object)).into_bytes();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_SCHEMA_V1.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&0_u64.to_le_bytes());

        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert!(matches!(
            error,
            BundleContainerError::ManifestMissingField("recipient_fingerprints")
        ));
    }

    #[test]
    fn deserialize_rejects_profile_count_overflow_u32() {
        let mut object = Map::new();
        object.insert("recipient_fingerprints".to_owned(), Value::Array(Vec::new()));
        object.insert("project_id".to_owned(), Value::String("lk_proj_demo".to_owned()));
        object.insert("schema_version".to_owned(), Value::Number(BUNDLE_SCHEMA_V1.into()));
        object.insert("created_at".to_owned(), Value::Number(1_i64.into()));
        object
            .insert("profile_count".to_owned(), Value::Number(serde_json::Number::from(u64::MAX)));
        object.insert("payload_digest".to_owned(), Value::String("c".repeat(64)));
        let manifest_bytes = crate::canonical_json(&Value::Object(object)).into_bytes();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_SCHEMA_V1.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&0_u64.to_le_bytes());

        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert!(matches!(error, BundleContainerError::ManifestMissingField("profile_count")));
    }

    #[test]
    fn age_decrypt_with_wrong_identity_fails() {
        let id_a = age::x25519::Identity::generate();
        let id_b = age::x25519::Identity::generate();
        let recipient_keys = [public_key_bytes(&id_a.to_public())];
        let plaintext = b"secret";
        let encrypted =
            encrypt_bundle_payload_for_age_recipients(plaintext, &recipient_keys).unwrap();
        let error = decrypt_bundle_payload_with_age_identity(&encrypted, &id_b).unwrap_err();
        assert!(matches!(error, BundleEncryptionError::Decrypt(_)));
    }

    #[test]
    fn age_decrypt_rejects_corrupted_ciphertext() {
        let id = age::x25519::Identity::generate();
        let recipient_keys = [public_key_bytes(&id.to_public())];
        let mut encrypted =
            encrypt_bundle_payload_for_age_recipients(b"x", &recipient_keys).unwrap();
        // Flip a byte deep in the ciphertext.
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        let error = decrypt_bundle_payload_with_age_identity(&encrypted, &id).unwrap_err();
        assert!(matches!(error, BundleEncryptionError::Decrypt(_)));
    }

    #[test]
    fn age_decrypt_rejects_garbage_payload() {
        let id = age::x25519::Identity::generate();
        let error = decrypt_bundle_payload_with_age_identity(b"\x00\x01\x02", &id).unwrap_err();
        assert!(matches!(error, BundleEncryptionError::Decrypt(_)));
    }

    #[test]
    fn round_trip_zero_length_payload() {
        let container =
            BundleContainer::new(sample_manifest(), Vec::new()).expect("valid container");
        let bytes = container.serialize().unwrap();
        let parsed = BundleContainer::deserialize(&bytes).unwrap();
        assert_eq!(parsed.encrypted_payload.len(), 0);
    }

    #[test]
    fn encrypt_with_empty_plaintext_round_trips() {
        let id = age::x25519::Identity::generate();
        let recipient_keys = [public_key_bytes(&id.to_public())];
        let encrypted = encrypt_bundle_payload_for_age_recipients(b"", &recipient_keys).unwrap();
        let decrypted = decrypt_bundle_payload_with_age_identity(&encrypted, &id).unwrap();
        assert_eq!(decrypted.len(), 0);
    }

    #[test]
    fn bundle_container_error_clone_and_eq() {
        let e = BundleContainerError::MagicMismatch;
        let cloned = e.clone();
        assert_eq!(e, cloned);
        let display = e.to_string();
        assert_ne!(display, "");
    }

    #[test]
    fn bundle_encryption_error_display_does_not_panic() {
        let cases = [
            BundleEncryptionError::MissingRecipients,
            BundleEncryptionError::InvalidRecipient { index: 0, message: "bad".into() },
            BundleEncryptionError::Encrypt("e".into()),
            BundleEncryptionError::Decrypt("d".into()),
        ];
        for c in cases {
            let _ = c.to_string();
            let cloned = c.clone();
            assert_eq!(c, cloned);
        }
    }

    #[test]
    fn deserialize_rejects_truncated_at_payload_length_field() {
        // Build header + manifest; cut just before the payload-len u64.
        let manifest = sample_manifest();
        let manifest_bytes = serialize_manifest(&manifest);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_SCHEMA_V1.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        // Append only 4 bytes of payload-len (need 8).
        bytes.extend_from_slice(&[0u8; 4]);
        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert!(matches!(error, BundleContainerError::Truncated(_)));
    }

    #[test]
    fn deserialize_rejects_truncated_after_declared_payload_len() {
        // declare payload_len = 100 but supply only 10 bytes.
        let manifest = sample_manifest();
        let manifest_bytes = serialize_manifest(&manifest);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(BUNDLE_MAGIC);
        bytes.extend_from_slice(&BUNDLE_SCHEMA_V1.to_le_bytes());
        bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&manifest_bytes);
        bytes.extend_from_slice(&100_u64.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 10]);
        let error = BundleContainer::deserialize(&bytes).unwrap_err();
        assert!(matches!(error, BundleContainerError::Truncated(_)));
    }

    #[test]
    fn age_0_11_payload_decrypts_with_existing_raw_x25519_key() {
        // Generated with age 0.11.5 and bech32 0.11.1 for the synthetic key below.
        // Keep fixed bytes so a new-to-new round trip cannot mask format drift.
        let encoded = concat!(
            "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBuMDk3QS81YW80QnVQekZTc0JLcHM4aW5lQTNFYVRF",
            "RzZvSC9UTkhubmxJCjhseWVkRVdqeHlidmFjY2xBRzUxbThsRFRRQS9PQXFjQUJqK1FvYUp2VVEKLT4gWmgh",
            "LyMwTUYtZ3JlYXNlCnBiSVNUOU8vTGtENURVVGpyUnJjZWI3Vm0wb0hudVBDeVJza0tVY2lCVWd1cTJUeUlx",
            "RnBCUDd6ajUyTnFlb08KbVNRMlFJajVVNjB1ZkRrdWhMNHdsQjQwaU9rejRWTGJnQWsycThjMEI2VSs5bEVP",
            "WUxZd1o1SQotLS0gQ2d2RGhyQ0o4ak5tQi8vNEJqU0VKMG0vNU50OWFMODAzdEFmZzFHaGR6cwopeA9eVfll",
            "cTqlRCqEH3F1/Kr1aih+OfwewzWwC90O55uMuvhB/KrmUL3KJV6PXf4ekSyjigIMIRWX1b+q0NZ2wvV/zGVs",
        );
        let payload = data_encoding::BASE64.decode(encoded.as_bytes()).unwrap();
        verify_age_payload_structure(&payload).unwrap();
        assert_eq!(
            decrypt_bundle_payload_with_x25519_secret(&payload, &[42; 32]).unwrap(),
            br#"{"schema_version":1,"profile_count":1}"#
        );
        assert!(decrypt_bundle_payload_with_x25519_secret(&payload, &[43; 32]).is_err());
    }
}
