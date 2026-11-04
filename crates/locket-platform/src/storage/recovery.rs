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

/// Persisted KDF parameters for the recovery envelope (stored in `recovery/kdf.toml`).
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
    /// KDF profile identifier matching the `kdf.toml` file.
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
    let err = || PlatformError::InvalidRecoveryEnvelope("truncated field".into());
    if *cur + 2 > data.len() {
        return Err(err());
    }
    let name_len = u16::from_le_bytes([data[*cur], data[*cur + 1]]) as usize;
    *cur += 2;
    if *cur + name_len > data.len() {
        return Err(err());
    }
    *cur += name_len; // skip name bytes (we do not validate them here)
    if *cur + 4 > data.len() {
        return Err(err());
    }
    let value_len =
        u32::from_le_bytes([data[*cur], data[*cur + 1], data[*cur + 2], data[*cur + 3]]) as usize;
    *cur += 4;
    if *cur + value_len > data.len() {
        return Err(err());
    }
    let s = std::str::from_utf8(&data[*cur..*cur + value_len])
        .map_err(|_| PlatformError::InvalidRecoveryEnvelope("non-utf8 field value".into()))?
        .to_owned();
    *cur += value_len;
    Ok(s)
}

/// Loads and parses `kdf.toml` from a recovery directory.
///
/// # Errors
///
/// Returns [`PlatformError::Io`] if the file cannot be read, or
/// [`PlatformError::InvalidRecoveryEnvelope`] if the TOML is malformed.
pub fn load_recovery_kdf_toml(recovery_dir: &Path) -> Result<RecoveryKdfToml, PlatformError> {
    match fs::read(recovery_dir.join("envelope.bin")) {
        Ok(data) => {
            if let Some((kdf, _)) = decode_recovery_state(&data)? {
                return Ok(kdf);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let path = recovery_dir.join("kdf.toml");
    let text = fs::read_to_string(&path).map_err(PlatformError::Io)?;
    let kdf: RecoveryKdfToml =
        toml::from_str(&text).map_err(|e| PlatformError::InvalidRecoveryEnvelope(e.to_string()))?;
    kdf.validate()?;
    Ok(kdf)
}

/// Saves `kdf.toml` to a recovery directory (creates the directory if absent).
///
/// # Errors
///
/// Returns [`PlatformError::Io`] on filesystem errors, or
/// [`PlatformError::InvalidRecoveryEnvelope`] if TOML serialization fails.
pub fn save_recovery_kdf_toml(
    recovery_dir: &Path,
    kdf: &RecoveryKdfToml,
) -> Result<(), PlatformError> {
    kdf.validate()?;
    secure_directory(recovery_dir)?;
    let path = recovery_dir.join("kdf.toml");
    let text =
        toml::to_string(kdf).map_err(|e| PlatformError::InvalidRecoveryEnvelope(e.to_string()))?;
    write_user_only_file(&path, text.as_bytes())
}

/// Loads and deserializes `envelope.bin` from a recovery directory.
///
/// # Errors
///
/// Returns [`PlatformError::Io`] if the file cannot be read, or propagates
/// [`RecoveryEnvelope::deserialize`] errors.
pub fn load_recovery_envelope(recovery_dir: &Path) -> Result<RecoveryEnvelope, PlatformError> {
    let path = recovery_dir.join("envelope.bin");
    let data = fs::read(&path).map_err(PlatformError::Io)?;
    if let Some((_, envelope)) = decode_recovery_state(&data)? {
        return Ok(envelope);
    }
    RecoveryEnvelope::deserialize(&data)
}

/// Atomically writes `envelope.bin` to a recovery directory.
///
/// # Errors
///
/// Returns [`PlatformError::Io`] on filesystem errors or propagates
/// [`RecoveryEnvelope::serialize`] errors.
pub fn save_recovery_envelope(
    recovery_dir: &Path,
    envelope: &RecoveryEnvelope,
) -> Result<(), PlatformError> {
    if recovery_dir.join("kdf.toml").exists()
        || fs::read(recovery_dir.join("envelope.bin"))
            .is_ok_and(|bytes| bytes.starts_with(RECOVERY_STATE_MAGIC))
    {
        // Entry updates must preserve the authoritative KDF, including its salt.
        // Callers replacing the KDF must supply the full pair to save_recovery_state.
        let kdf = load_recovery_kdf_toml(recovery_dir)?;
        return save_recovery_state(recovery_dir, &kdf, envelope);
    }
    write_recovery_atomically(recovery_dir, &envelope.serialize()?)
}

const RECOVERY_STATE_MAGIC: &[u8] = b"LOCKET-RECOVERY-STATE-V1\0";

/// Saves KDF metadata and encrypted entries as one durable atomic replacement.
/// Legacy separate KDF/envelope files remain readable. Embedded metadata is authoritative.
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

/// Decodes a modern atomic recovery container, returning `None` for legacy input.
///
/// # Errors
/// Rejects truncated containers, oversized KDF metadata, unsupported parameters,
/// invalid inner envelopes and mismatched KDF profile identifiers.
pub fn decode_recovery_state(
    bytes: &[u8],
) -> Result<Option<(RecoveryKdfToml, RecoveryEnvelope)>, PlatformError> {
    if !bytes.starts_with(RECOVERY_STATE_MAGIC) {
        return Ok(None);
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
    Ok(Some((kdf, envelope)))
}

fn write_recovery_atomically(recovery_dir: &Path, data: &[u8]) -> Result<(), PlatformError> {
    secure_directory(recovery_dir)?;
    let path = recovery_dir.join("envelope.bin");
    let suffix = BASE64URL_NOPAD.encode(&locket_crypto::random_bytes::<16>()?);
    let temporary = recovery_dir.join(format!(".envelope-{suffix}.tmp"));
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<(), PlatformError> {
        use std::io::Write;
        let mut file = options.open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        #[cfg(unix)]
        fs::File::open(recovery_dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
