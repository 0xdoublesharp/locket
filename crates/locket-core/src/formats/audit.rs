//! Audit canonicalization and HMAC byte construction.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{ProjectId, Timestamp};

/// Number of bytes in an audit HMAC digest.
pub const AUDIT_HMAC_LEN: usize = 32;

/// Maximum JSON size accepted for an externally retained audit checkpoint.
pub const AUDIT_CHECKPOINT_MAX_BYTES: usize = 4096;

/// Authenticated metadata anchoring one nonempty project audit history.
///
/// Retain the newest trusted checkpoint independently of the vault and its
/// backups. Authentication detects alteration, not replacement by an older
/// authentic checkpoint. The authentication tag uses the project audit key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCheckpoint {
    /// Checkpoint format version, currently 1.
    pub schema_version: u16,
    /// Project to which the anchored audit chain belongs.
    pub project_id: ProjectId,
    /// Last verified sequence; zero is never a valid checkpoint.
    pub sequence: u64,
    /// HMAC of the anchored audit row.
    pub row_hmac: [u8; AUDIT_HMAC_LEN],
    /// Domain-separated HMAC authenticating the other checkpoint fields.
    pub authentication_tag: [u8; AUDIT_HMAC_LEN],
}

/// Encodes the authenticated checkpoint fields independently of JSON formatting.
///
/// # Errors
/// Returns [`AuditCanonicalizationError`] if the project identifier is too long.
pub fn audit_checkpoint_v1_bytes(
    checkpoint: &AuditCheckpoint,
) -> Result<Vec<u8>, AuditCanonicalizationError> {
    let mut encoded = b"locket-audit-checkpoint-v1".to_vec();
    encoded.extend_from_slice(&checkpoint.schema_version.to_le_bytes());
    encoded.extend_from_slice(&field("project_id", checkpoint.project_id.as_str())?);
    encoded.extend_from_slice(&checkpoint.sequence.to_le_bytes());
    encoded.extend_from_slice(&checkpoint.row_hmac);
    Ok(encoded)
}

const DOMAIN_SEPARATOR: &[u8] = b"locket-audit-v1";

/// Error returned when an audit canonical byte field cannot be encoded.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum AuditCanonicalizationError {
    /// The field name exceeds the `u16` length prefix.
    #[error("audit field name too long")]
    NameTooLong,
    /// The field value exceeds the `u32` length prefix.
    #[error("audit field value too long")]
    ValueTooLong,
}

/// Input fields for audit HMAC v1 canonical byte construction.
#[derive(Debug, Clone, Copy)]
pub struct AuditHmacInput<'a> {
    /// Audit schema version recorded on the row.
    pub schema_version: u16,
    /// Monotonic audit sequence number.
    pub sequence: u64,
    /// Audit event timestamp.
    pub timestamp: Timestamp,
    /// Project identifier, or `None` when the row has no project scope.
    pub project_id: Option<&'a str>,
    /// Profile identifier, or `None` when the row has no profile scope.
    pub profile_id: Option<&'a str>,
    /// Audit action.
    pub action: &'a str,
    /// Audit status.
    pub status: &'a str,
    /// HMAC-covered metadata. `None` is encoded as canonical JSON `null`.
    pub metadata_json: Option<&'a Value>,
    /// Previous row HMAC. `None` is encoded as 32 zero bytes.
    pub previous_hmac: Option<&'a [u8; AUDIT_HMAC_LEN]>,
}

/// Encodes a UTF-8 field using Locket's length-prefixed format.
///
/// # Errors
///
/// Returns [`AuditCanonicalizationError`] when a name or value exceeds the
/// fixed length prefix width.
pub fn field(name: &str, value: &str) -> Result<Vec<u8>, AuditCanonicalizationError> {
    bytes(name, value.as_bytes())
}

/// Encodes a raw byte field using Locket's length-prefixed format.
///
/// # Errors
///
/// Returns [`AuditCanonicalizationError`] when a name or value exceeds the
/// fixed length prefix width.
pub fn bytes(name: &str, value: &[u8]) -> Result<Vec<u8>, AuditCanonicalizationError> {
    let name_len =
        u16::try_from(name.len()).map_err(|_| AuditCanonicalizationError::NameTooLong)?;
    let value_len =
        u32::try_from(value.len()).map_err(|_| AuditCanonicalizationError::ValueTooLong)?;

    let mut encoded = Vec::with_capacity(usize::from(name_len) + value.len() + 6);
    encoded.extend_from_slice(&name_len.to_le_bytes());
    encoded.extend_from_slice(name.as_bytes());
    encoded.extend_from_slice(&value_len.to_le_bytes());
    encoded.extend_from_slice(value);
    Ok(encoded)
}

/// Renders canonical JSON bytes for an optional audit metadata value.
///
/// `None` is encoded as the four ASCII bytes `null`.
#[must_use]
pub fn canonical_json_bytes(value: Option<&Value>) -> Vec<u8> {
    canonical_json_string(value).into_bytes()
}

/// Renders canonical JSON for an optional audit metadata value.
///
/// `None` is encoded as `null`.
#[must_use]
pub fn canonical_json_string(value: Option<&Value>) -> String {
    value.map_or_else(|| "null".to_owned(), canonical_json_value)
}

/// Renders canonical JSON for a concrete [`serde_json::Value`].
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    canonical_json_value(value)
}

/// Builds the canonical bytes covered by audit HMAC v1.
///
/// # Errors
///
/// Returns [`AuditCanonicalizationError`] when any length-prefixed field is too
/// large to encode.
pub fn audit_hmac_v1_bytes(
    input: &AuditHmacInput<'_>,
) -> Result<Vec<u8>, AuditCanonicalizationError> {
    let previous_hmac = input.previous_hmac.copied().unwrap_or([0; AUDIT_HMAC_LEN]);
    let metadata_json = canonical_json_bytes(input.metadata_json);

    let mut encoded = Vec::new();
    encoded.extend_from_slice(DOMAIN_SEPARATOR);
    encoded.extend_from_slice(&input.schema_version.to_le_bytes());
    encoded.extend_from_slice(&input.sequence.to_le_bytes());
    encoded.extend_from_slice(&input.timestamp.audit_i128_le_bytes());
    encoded.extend_from_slice(&field("project_id", input.project_id.unwrap_or(""))?);
    encoded.extend_from_slice(&field("profile_id", input.profile_id.unwrap_or(""))?);
    encoded.extend_from_slice(&field("action", input.action)?);
    encoded.extend_from_slice(&field("status", input.status)?);
    encoded.extend_from_slice(&bytes("metadata_json", &metadata_json)?);
    encoded.extend_from_slice(&bytes("previous_hmac", &previous_hmac)?);
    Ok(encoded)
}

/// Inserts audit convenience metadata fields, omitting absent values.
///
/// This is intentionally not a generic optional-field helper: `secret_name` and
/// `command` must be omitted, not encoded as JSON `null`, when the matching
/// top-level audit convenience column is absent.
pub fn insert_convenience_metadata(
    metadata: &mut Map<String, Value>,
    secret_name: Option<&str>,
    command: Option<&str>,
) {
    if let Some(value) = secret_name {
        metadata.insert("secret_name".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = command {
        metadata.insert("command".to_owned(), Value::String(value.to_owned()));
    }
}

fn canonical_json_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(true) => "true".to_owned(),
        Value::Bool(false) => "false".to_owned(),
        Value::Number(number) => number.to_string(),
        Value::String(value) => canonical_json_string_literal(value),
        Value::Array(values) => canonical_json_array(values),
        Value::Object(values) => canonical_json_object(values),
    }
}

fn canonical_json_array(values: &[Value]) -> String {
    let mut encoded = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            encoded.push(',');
        }
        encoded.push_str(&canonical_json_value(value));
    }
    encoded.push(']');
    encoded
}

fn canonical_json_object(values: &Map<String, Value>) -> String {
    let mut entries = values.iter().collect::<Vec<_>>();
    entries.sort_unstable_by_key(|(key, _)| *key);

    let mut encoded = String::from("{");
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index != 0 {
            encoded.push(',');
        }
        encoded.push_str(&canonical_json_string_literal(key));
        encoded.push(':');
        encoded.push_str(&canonical_json_value(value));
    }
    encoded.push('}');
    encoded
}

fn canonical_json_string_literal(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push('"');
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\u{08}' => encoded.push_str("\\b"),
            '\u{0c}' => encoded.push_str("\\f"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            '\u{00}'..='\u{1f}' => {
                encoded.push_str("\\u00");
                encoded.push(LOWER_HEX[(u32::from(character) >> 4) as usize]);
                encoded.push(LOWER_HEX[(u32::from(character) & 0x0f) as usize]);
            }
            _ => encoded.push(character),
        }
    }
    encoded.push('"');
    encoded
}

const LOWER_HEX: [char; 16] =
    ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::{
        AUDIT_HMAC_LEN, AuditHmacInput, audit_hmac_v1_bytes, bytes, canonical_json,
        canonical_json_bytes, field, insert_convenience_metadata,
    };
    use crate::Timestamp;

    #[test]
    fn audit_checkpoint_authentication_bytes_are_versioned_and_stable()
    -> Result<(), Box<dyn std::error::Error>> {
        let checkpoint = super::AuditCheckpoint {
            schema_version: 1,
            project_id: crate::ProjectId::new("lk_proj_test")?,
            sequence: 7,
            row_hmac: [42; super::AUDIT_HMAC_LEN],
            authentication_tag: [11; super::AUDIT_HMAC_LEN],
        };
        let expected = [
            b"locket-audit-checkpoint-v1".as_slice(),
            &[1, 0],
            &[10, 0],
            b"project_id",
            &[12, 0, 0, 0],
            b"lk_proj_test",
            &7_u64.to_le_bytes(),
            &[42; super::AUDIT_HMAC_LEN],
        ]
        .concat();
        assert_eq!(super::audit_checkpoint_v1_bytes(&checkpoint)?, expected);
        let serialized = serde_json::to_vec(&checkpoint)?;
        assert_eq!(serde_json::from_slice::<super::AuditCheckpoint>(&serialized)?, checkpoint);
        Ok(())
    }

    #[test]
    fn field_and_bytes_use_length_prefixed_encoding() {
        let encoded_field = field("action", "SET");
        assert_eq!(
            encoded_field,
            Ok([6, 0, b'a', b'c', b't', b'i', b'o', b'n', 3, 0, 0, 0, b'S', b'E', b'T',].to_vec())
        );

        let encoded_bytes = bytes("previous_hmac", &[1, 2, 3]);
        assert_eq!(
            encoded_bytes,
            Ok([
                13, 0, b'p', b'r', b'e', b'v', b'i', b'o', b'u', b's', b'_', b'h', b'm', b'a',
                b'c', 3, 0, 0, 0, 1, 2, 3,
            ]
            .to_vec())
        );
    }

    #[test]
    fn canonical_json_sorts_keys_and_omits_whitespace() {
        let value = json!({
            "z": [3, 2, 1],
            "a": {"b": true, "a": "line\none"},
            "m": null
        });

        assert_eq!(
            canonical_json(&value),
            "{\"a\":{\"a\":\"line\\none\",\"b\":true},\"m\":null,\"z\":[3,2,1]}"
        );
    }

    #[test]
    fn canonical_json_none_is_null_bytes() {
        assert_eq!(canonical_json_bytes(None), b"null".to_vec());
    }

    #[test]
    fn absent_convenience_metadata_is_omitted_not_null() {
        let mut metadata = Map::new();
        metadata.insert("schema_version".to_owned(), Value::from(1));
        insert_convenience_metadata(&mut metadata, Some("DATABASE_URL"), None);
        let value = Value::Object(metadata);

        assert_eq!(
            canonical_json(&value),
            "{\"schema_version\":1,\"secret_name\":\"DATABASE_URL\"}"
        );
        assert!(!canonical_json(&value).contains("\"command\""));
        assert!(!canonical_json(&value).contains("null"));
    }

    #[test]
    fn audit_hmac_bytes_are_deterministic_for_object_key_order() {
        let left = json!({
            "schema_version": 1,
            "status": "SUCCESS",
            "action": "SET",
            "secret_name": "DATABASE_URL"
        });
        let right = json!({
            "secret_name": "DATABASE_URL",
            "action": "SET",
            "status": "SUCCESS",
            "schema_version": 1
        });
        let previous_hmac = [7; AUDIT_HMAC_LEN];

        let left_bytes = audit_hmac_v1_bytes(&AuditHmacInput {
            schema_version: 1,
            sequence: 42,
            timestamp: Timestamp::from_unix_nanos(-5),
            project_id: Some("lk_proj_demo"),
            profile_id: Some("lk_prof_default"),
            action: "SET",
            status: "SUCCESS",
            metadata_json: Some(&left),
            previous_hmac: Some(&previous_hmac),
        });
        let right_bytes = audit_hmac_v1_bytes(&AuditHmacInput {
            schema_version: 1,
            sequence: 42,
            timestamp: Timestamp::from_unix_nanos(-5),
            project_id: Some("lk_proj_demo"),
            profile_id: Some("lk_prof_default"),
            action: "SET",
            status: "SUCCESS",
            metadata_json: Some(&right),
            previous_hmac: Some(&previous_hmac),
        });

        assert_eq!(left_bytes, right_bytes);
    }

    #[test]
    fn audit_hmac_uses_null_metadata_and_zero_previous_hmac_defaults() {
        let encoded = audit_hmac_v1_bytes(&AuditHmacInput {
            schema_version: 1,
            sequence: 1,
            timestamp: Timestamp::from_unix_nanos(10),
            project_id: None,
            profile_id: None,
            action: "AUDIT_VERIFY",
            status: "SUCCESS",
            metadata_json: None,
            previous_hmac: None,
        });

        let encoded = encoded.unwrap_or_default();
        assert!(encoded.windows(4).any(|window| window == b"null"));
        assert!(encoded.ends_with(&[0; AUDIT_HMAC_LEN]));
    }
}
