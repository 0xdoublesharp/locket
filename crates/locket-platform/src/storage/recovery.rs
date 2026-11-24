//! Recovery envelope and KDF metadata persistence (TOML and binary formats).

use std::fs;
use std::path::Path;

use data_encoding::BASE64URL_NOPAD;
use locket_crypto::NONCE_LEN;
use serde::{Deserialize, Serialize};

use crate::error::PlatformError;
use crate::fs_helpers::{secure_directory, write_user_only_file};

/// Schema version for recovery KDF TOML files.
pub const RECOVERY_KDF_TOML_VERSION: u32 = 1;

const MIN_SERIALIZED_RECOVERY_ENTRY_LEN: usize =
    2 + "entry_kind".len() + 4 + 2 + "entry_id".len() + 4 + NONCE_LEN + 4;

/// KDF parameters for the recovery envelope, embedded in `recovery/envelope.bin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKdfToml {
    /// Unique identifier for this KDF parameter set.
    pub kdf_profile_id: String,
    /// Algorithm name (always `"argon2id"`).
    pub algorithm: String,
    /// Schema version.
    pub version: u32,
    /// Base64URL-nopad encoded salt.
    pub salt: String,
    /// Argon2id memory cost in KiB.
    pub m_cost: u32,
    /// Argon2id iteration count.
    pub t_cost: u32,
    /// Argon2id parallelism.
    pub p_cost: u32,
    /// Output length in bytes.
    pub output_len: u32,
    /// Creation timestamp in Unix nanoseconds.
    pub created_at: i64,
}

impl RecoveryKdfToml {
    /// Creates a new v1 `RecoveryKdfToml` from a profile ID, salt bytes, and creation timestamp.
    #[must_use]
    pub fn new_v1(kdf_profile_id: String, salt_bytes: &[u8], created_at_nanos: i64) -> Self {
        use locket_crypto::{KEY_LEN, RECOVERY_M_COST, RECOVERY_P_COST, RECOVERY_T_COST};
        // KEY_LEN is 32, well within u32 range.
        #[allow(clippy::cast_possible_truncation)]
        let output_len = KEY_LEN as u32;
        Self {
            kdf_profile_id,
            algorithm: "argon2id".to_owned(),
            version: RECOVERY_KDF_TOML_VERSION,
            salt: BASE64URL_NOPAD.encode(salt_bytes),
            m_cost: RECOVERY_M_COST,
            t_cost: RECOVERY_T_COST,
            p_cost: RECOVERY_P_COST,
            output_len,
            created_at: created_at_nanos,
        }
    }

    /// Decodes the base64url-nopad salt field back to bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InvalidRecoveryEnvelope`] if the salt is not valid base64url.
    pub fn decode_salt(&self) -> Result<Vec<u8>, PlatformError> {
        BASE64URL_NOPAD
            .decode(self.salt.as_bytes())
            .map_err(|_| PlatformError::InvalidRecoveryEnvelope("invalid kdf salt encoding".into()))
    }

    /// Validates persisted recovery KDF metadata before it is used for derivation.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InvalidRecoveryEnvelope`] when the schema or
    /// Argon2id parameters do not match the supported v1 recovery profile.
    pub fn validate(&self) -> Result<(), PlatformError> {
        use locket_crypto::{
            KEY_LEN, RECOVERY_M_COST, RECOVERY_P_COST, RECOVERY_SALT_LEN, RECOVERY_T_COST,
        };

        if self.version != RECOVERY_KDF_TOML_VERSION {
            return Err(PlatformError::InvalidRecoveryEnvelope(
                "unsupported kdf metadata version".into(),
            ));
        }
        if self.algorithm != "argon2id" {
            return Err(PlatformError::InvalidRecoveryEnvelope("unsupported kdf algorithm".into()));
        }
        if self.kdf_profile_id.is_empty()
            || self.kdf_profile_id.len() > 128
            || !self
                .kdf_profile_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(PlatformError::InvalidRecoveryEnvelope("invalid kdf profile id".into()));
        }
        if self.decode_salt()?.len() != RECOVERY_SALT_LEN {
            return Err(PlatformError::InvalidRecoveryEnvelope("invalid kdf salt length".into()));
        }
        let expected_output_len = u32::try_from(KEY_LEN)
            .map_err(|_| PlatformError::InvalidRecoveryEnvelope("invalid key length".into()))?;
        if self.m_cost != RECOVERY_M_COST
            || self.t_cost != RECOVERY_T_COST
            || self.p_cost != RECOVERY_P_COST
            || self.output_len != expected_output_len
        {
            return Err(PlatformError::InvalidRecoveryEnvelope(
                "unsupported kdf parameters".into(),
            ));
        }
        Ok(())
    }

    /// Converts the stored parameters to a [`locket_crypto::RecoveryKdfParams`].
    #[must_use]
    pub const fn to_crypto_params(&self) -> locket_crypto::RecoveryKdfParams {
        locket_crypto::RecoveryKdfParams {
            m_cost: self.m_cost,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
            output_len: self.output_len,
        }
    }
}

/// A single entry in the recovery envelope (plaintext kind/id + encrypted payload).
#[derive(Debug, Clone)]
pub struct RecoveryEnvelopeEntry {
    /// Entry kind, e.g. `"master_key"`.
    pub entry_kind: String,
    /// Entry identifier, e.g. the project ID.
    pub entry_id: String,
    /// Nonce used for the AEAD encryption of this entry.
    pub nonce: locket_crypto::NonceBytes,
    /// AEAD ciphertext (plaintext + tag).
    pub ciphertext: Vec<u8>,
}

/// Recovery envelope binary container.
///
/// Stored at `recovery/envelope.bin`. All integers are little-endian.
#[derive(Debug, Clone)]
pub struct RecoveryEnvelope {
    /// KDF profile identifier matching the embedded KDF metadata.
    pub kdf_profile_id: String,
    /// Creation timestamp in Unix nanoseconds (i128 LE).
    pub created_at_unix_nanos: i128,
    /// Encrypted entries within this envelope.
    pub entries: Vec<RecoveryEnvelopeEntry>,
}

impl RecoveryEnvelope {
    /// Serializes the envelope to its canonical binary format.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InvalidRecoveryEnvelope`] if entry counts overflow.
    pub fn serialize(&self) -> Result<Vec<u8>, PlatformError> {
        use locket_crypto::{RECOVERY_ENVELOPE_SCHEMA_V1, RECOVERY_MAGIC};
        let mut buf = Vec::new();
        buf.extend_from_slice(RECOVERY_MAGIC);
        buf.extend_from_slice(&RECOVERY_ENVELOPE_SCHEMA_V1.to_le_bytes());
        write_field(&mut buf, "kdf_profile_id", self.kdf_profile_id.as_bytes())?;
        buf.extend_from_slice(&self.created_at_unix_nanos.to_le_bytes());
        let entry_count = u32::try_from(self.entries.len())
            .map_err(|_| PlatformError::InvalidRecoveryEnvelope("too many entries".into()))?;
        buf.extend_from_slice(&entry_count.to_le_bytes());
        for entry in &self.entries {
            write_field(&mut buf, "entry_kind", entry.entry_kind.as_bytes())?;
            write_field(&mut buf, "entry_id", entry.entry_id.as_bytes())?;
            buf.extend_from_slice(&entry.nonce);
            let ct_len = u32::try_from(entry.ciphertext.len()).map_err(|_| {
                PlatformError::InvalidRecoveryEnvelope("ciphertext too large".into())
            })?;
            buf.extend_from_slice(&ct_len.to_le_bytes());
            buf.extend_from_slice(&entry.ciphertext);
        }
        Ok(buf)
    }

    /// Deserializes an envelope from its canonical binary format.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InvalidRecoveryEnvelope`] if the data is truncated or corrupt,
    /// or [`PlatformError::RecoveryEnvelopeSchemaUnsupported`] for unknown schema versions.
    pub fn deserialize(data: &[u8]) -> Result<Self, PlatformError> {
        use locket_crypto::{RECOVERY_ENVELOPE_SCHEMA_V1, RECOVERY_MAGIC};
        let mut cur = 0usize;

        // Magic
        let magic = read_exact(&mut cur, 16, data)?;
        if magic != RECOVERY_MAGIC.as_slice() {
            return Err(PlatformError::InvalidRecoveryEnvelope("bad magic bytes".into()));
        }
        // Schema version
        let ver_bytes = read_exact(&mut cur, 2, data)?;
        let schema_version = u16::from_le_bytes([ver_bytes[0], ver_bytes[1]]);
        if schema_version != RECOVERY_ENVELOPE_SCHEMA_V1 {
            return Err(PlatformError::RecoveryEnvelopeSchemaUnsupported(schema_version));
        }
        // kdf_profile_id field
        let kdf_profile_id = read_field_string(&mut cur, data)?;
        // created_at (i128 LE = 16 bytes)
        let created_bytes = read_exact(&mut cur, 16, data)?;
        let created_at_unix_nanos =
            i128::from_le_bytes(created_bytes.try_into().map_err(|_| {
                PlatformError::InvalidRecoveryEnvelope("truncated timestamp".into())
            })?);
        // entry_count
        let count_bytes = read_exact(&mut cur, 4, data)?;
        let entry_count =
            u32::from_le_bytes([count_bytes[0], count_bytes[1], count_bytes[2], count_bytes[3]]);
        let entry_count = usize::try_from(entry_count)
            .map_err(|_| PlatformError::InvalidRecoveryEnvelope("entry count too large".into()))?;
        let max_possible_entries =
            data.len().saturating_sub(cur) / MIN_SERIALIZED_RECOVERY_ENTRY_LEN;
        if entry_count > max_possible_entries {
            return Err(PlatformError::InvalidRecoveryEnvelope(
                "entry count exceeds envelope length".into(),
            ));
        }
        // Entries
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let entry_kind = read_field_string(&mut cur, data)?;
            let entry_id = read_field_string(&mut cur, data)?;
            let nonce_bytes = read_exact(&mut cur, NONCE_LEN, data)?;
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(nonce_bytes);
            let ct_len_bytes = read_exact(&mut cur, 4, data)?;
            let ct_len = u32::from_le_bytes([
                ct_len_bytes[0],
                ct_len_bytes[1],
                ct_len_bytes[2],
                ct_len_bytes[3],
            ]) as usize;
            let ciphertext = read_exact(&mut cur, ct_len, data)?.to_vec();
            entries.push(RecoveryEnvelopeEntry { entry_kind, entry_id, nonce, ciphertext });
        }
        Ok(Self { kdf_profile_id, created_at_unix_nanos, entries })
    }
}

fn write_field(buf: &mut Vec<u8>, name: &str, value: &[u8]) -> Result<(), PlatformError> {
    let name_len = u16::try_from(name.len())
        .map_err(|_| PlatformError::InvalidRecoveryEnvelope("field name too long".into()))?;
    let value_len = u32::try_from(value.len())
        .map_err(|_| PlatformError::InvalidRecoveryEnvelope("field value too long".into()))?;
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(name.as_bytes());
    buf.extend_from_slice(&value_len.to_le_bytes());
    buf.extend_from_slice(value);
    Ok(())
}

fn read_exact<'a>(cur: &mut usize, n: usize, data: &'a [u8]) -> Result<&'a [u8], PlatformError> {
    let end = cur
        .checked_add(n)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| PlatformError::InvalidRecoveryEnvelope("truncated".into()))?;
    let slice = &data[*cur..end];
    *cur = end;
    Ok(slice)
}

fn read_field_string(cur: &mut usize, data: &[u8]) -> Result<String, PlatformError> {
    let name = read_exact(cur, 2, data)?;
    let name_len = usize::from(u16::from_le_bytes([name[0], name[1]]));
    read_exact(cur, name_len, data)?;
    let value = read_exact(cur, 4, data)?;
    let value_len = u32::from_le_bytes([value[0], value[1], value[2], value[3]]) as usize;
    std::str::from_utf8(read_exact(cur, value_len, data)?)
        .map(str::to_owned)
        .map_err(|_| PlatformError::InvalidRecoveryEnvelope("non-utf8 field value".into()))
}

/// Loads the KDF metadata and encrypted entries from `envelope.bin`.
///
/// # Errors
///
/// Returns [`PlatformError::Io`] if the file cannot be read, or
/// [`PlatformError::InvalidRecoveryEnvelope`] if it is not a valid recovery
/// container.
pub fn load_recovery_state(
    recovery_dir: &Path,
) -> Result<(RecoveryKdfToml, RecoveryEnvelope), PlatformError> {
    let data = fs::read(recovery_dir.join("envelope.bin")).map_err(PlatformError::Io)?;
    decode_recovery_state(&data)
}

/// Loads the KDF metadata embedded in `envelope.bin`.
///
/// # Errors
///
/// Propagates [`load_recovery_state`] errors.
pub fn load_recovery_kdf_toml(recovery_dir: &Path) -> Result<RecoveryKdfToml, PlatformError> {
    Ok(load_recovery_state(recovery_dir)?.0)
}

/// Loads the encrypted entries embedded in `envelope.bin`.
///
/// # Errors
///
/// Propagates [`load_recovery_state`] errors.
pub fn load_recovery_envelope(recovery_dir: &Path) -> Result<RecoveryEnvelope, PlatformError> {
    Ok(load_recovery_state(recovery_dir)?.1)
}

/// Replaces the encrypted entries while keeping the stored KDF metadata,
/// including its salt. Callers replacing the KDF use [`save_recovery_state`].
///
/// # Errors
///
/// Fails when no recovery container exists yet, or propagates
/// [`save_recovery_state`] errors.
pub fn save_recovery_envelope(
    recovery_dir: &Path,
    envelope: &RecoveryEnvelope,
) -> Result<(), PlatformError> {
    let kdf = load_recovery_kdf_toml(recovery_dir)?;
    save_recovery_state(recovery_dir, &kdf, envelope)
}

const RECOVERY_STATE_MAGIC: &[u8] = b"LOCKET-RECOVERY-STATE-V1\0";

/// Saves KDF metadata and encrypted entries as one durable atomic replacement.
///
/// # Errors
/// Rejects mismatched metadata or filesystem failures without truncating the old envelope.
pub fn save_recovery_state(
    recovery_dir: &Path,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
) -> Result<(), PlatformError> {
    kdf.validate()?;
    if kdf.kdf_profile_id != envelope.kdf_profile_id {
        return Err(PlatformError::InvalidRecoveryEnvelope("kdf profile mismatch".into()));
    }
    let metadata = toml::to_string(kdf)
        .map_err(|error| PlatformError::InvalidRecoveryEnvelope(error.to_string()))?;
    let length = u32::try_from(metadata.len())
        .map_err(|_| PlatformError::InvalidRecoveryEnvelope("kdf metadata too large".into()))?;
    let mut bytes = RECOVERY_STATE_MAGIC.to_vec();
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(metadata.as_bytes());
    bytes.extend_from_slice(&envelope.serialize()?);
    write_recovery_atomically(recovery_dir, &bytes)
}

/// Decodes an atomic recovery container.
///
/// # Errors
/// Rejects input without the container header, truncated containers, oversized
/// KDF metadata, unsupported parameters, invalid inner envelopes and mismatched
/// KDF profile identifiers.
pub fn decode_recovery_state(
    bytes: &[u8],
) -> Result<(RecoveryKdfToml, RecoveryEnvelope), PlatformError> {
    if !bytes.starts_with(RECOVERY_STATE_MAGIC) {
        return Err(PlatformError::InvalidRecoveryEnvelope("not a recovery container".into()));
    }
    let mut cursor = RECOVERY_STATE_MAGIC.len();
    let length = u32::from_le_bytes(
        read_exact(&mut cursor, 4, bytes)?
            .try_into()
            .map_err(|_| PlatformError::InvalidRecoveryEnvelope("invalid kdf length".into()))?,
    ) as usize;
    if length > 16 * 1024 {
        return Err(PlatformError::InvalidRecoveryEnvelope("kdf metadata too large".into()));
    }
    let text = std::str::from_utf8(read_exact(&mut cursor, length, bytes)?)
        .map_err(|_| PlatformError::InvalidRecoveryEnvelope("invalid kdf text".into()))?;
    let kdf: RecoveryKdfToml = toml::from_str(text)
        .map_err(|_| PlatformError::InvalidRecoveryEnvelope("invalid kdf metadata".into()))?;
    kdf.validate()?;
    let envelope = RecoveryEnvelope::deserialize(&bytes[cursor..])?;
    if kdf.kdf_profile_id != envelope.kdf_profile_id {
        return Err(PlatformError::InvalidRecoveryEnvelope("kdf profile mismatch".into()));
    }
    Ok((kdf, envelope))
}

fn write_recovery_atomically(recovery_dir: &Path, data: &[u8]) -> Result<(), PlatformError> {
    secure_directory(recovery_dir)?;
    write_user_only_file(&recovery_dir.join("envelope.bin"), data)
}
