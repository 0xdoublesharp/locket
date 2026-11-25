//! Signed external receipts for project audit checkpoints.

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonical_json;

/// Current external audit witness statement schema version.
pub const AUDIT_WITNESS_SCHEMA_VERSION: u16 = 1;

/// Domain prefix for audit witness signatures.
pub const AUDIT_WITNESS_DOMAIN: &str = "locket-audit-witness-v1";

/// The signed metadata identifying a project audit checkpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditWitnessStatement {
    /// Statement format version.
    pub schema_version: u16,
    /// Project whose audit chain was checkpointed.
    pub project_id: String,
    /// Positive audit checkpoint sequence number.
    pub seq_no: u64,
    /// The 32-byte checkpoint HMAC encoded as lowercase hex.
    pub checkpoint_hmac_hex: String,
    /// SHA-256 digest of the previous canonical receipt, if any, in lowercase hex.
    pub prev_receipt_sha256_hex: Option<String>,
    /// Identifier of the party submitting the checkpoint.
    pub signer_id: String,
    /// Identifier of the external witness.
    pub witness_id: String,
    /// Fresh nonce encoded as nonempty lowercase hex.
    pub nonce_hex: String,
    /// Witness issuance time in Unix nanoseconds.
    pub issued_at_unix_nanos: i64,
}

/// An external witness's Ed25519 signature over an audit checkpoint statement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditWitnessReceipt {
    /// Signed audit checkpoint metadata.
    pub statement: AuditWitnessStatement,
    /// Witness verification key in unpadded base64url.
    pub witness_public_key_b64: String,
    /// Ed25519 signature in unpadded base64url.
    pub signature_b64: String,
}

/// A witness statement or receipt failed encoding, signature, or chain validation.
#[derive(Debug, Error)]
pub enum AuditWitnessError {
    /// The statement uses an unsupported schema version.
    #[error("unsupported audit witness schema version {0}")]
    UnsupportedSchema(u16),

    /// The receipt belongs to a different project.
    #[error("audit witness project mismatch")]
    ProjectMismatch,

    /// The statement contains a malformed field.
    #[error("invalid audit witness field {0}")]
    InvalidField(&'static str),

    /// The receipt key differs from the trusted witness key or is invalid.
    #[error("invalid or unexpected audit witness key")]
    WitnessKeyMismatch,

    /// The receipt signature could not be decoded or verified.
    #[error("invalid audit witness signature")]
    InvalidSignature,

    /// The checkpoint sequence did not advance beyond the previous receipt.
    #[error("audit witness checkpoint sequence did not advance")]
    SequenceNotAdvanced,

    /// The previous receipt digest differs from the expected chain head.
    #[error("audit witness previous receipt digest mismatch")]
    PreviousReceiptMismatch,

    /// A nonce has already been used in the project receipt chain.
    #[error("audit witness nonce was already used")]
    DuplicateNonce,

    /// A statement or receipt could not be encoded as JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Builds the bytes covered by an audit witness signature.
///
/// The domain prefix is followed by a NUL byte and UTF-8 canonical JSON with
/// lexicographically sorted object keys.
///
/// # Errors
///
/// Returns [`AuditWitnessError`] if the statement cannot be serialized.
pub fn canonical_witness_statement_bytes(
    statement: &AuditWitnessStatement,
) -> Result<Vec<u8>, AuditWitnessError> {
    let json = serde_json::to_value(statement)?;
    let mut payload = AUDIT_WITNESS_DOMAIN.as_bytes().to_vec();
    payload.push(0);
    payload.extend_from_slice(canonical_json(&json).as_bytes());
    Ok(payload)
}

/// Signs a valid statement with an independent external Ed25519 witness key.
///
/// # Errors
///
/// Returns [`AuditWitnessError`] if the statement is invalid or unencodable.
pub fn sign_audit_witness_statement(
    statement: AuditWitnessStatement,
    witness_signing_key: &SigningKey,
) -> Result<AuditWitnessReceipt, AuditWitnessError> {
    validate_statement(&statement)?;
    let signature = witness_signing_key.sign(&canonical_witness_statement_bytes(&statement)?);
    Ok(AuditWitnessReceipt {
        statement,
        witness_public_key_b64: BASE64URL_NOPAD
            .encode(witness_signing_key.verifying_key().as_bytes()),
        signature_b64: BASE64URL_NOPAD.encode(&signature.to_bytes()),
    })
}

/// Verifies the receipt against a trusted witness key, project, and chain head.
///
/// Pass the previously verified head for that project, or `None` for the
/// first receipt. The first receipt may checkpoint any positive sequence.
/// This checks nonce reuse against the supplied head. Chain storage can
/// additionally reject nonce reuse across the full history.
///
/// Returns the lowercase SHA-256 digest of the canonical receipt JSON for
/// use as the next statement's previous-receipt digest.
///
/// # Errors
///
/// Returns [`AuditWitnessError`] if any statement field, signature, or chain
/// link is invalid.
pub fn verify_audit_witness_receipt(
    receipt: &AuditWitnessReceipt,
    expected_witness_public_key: &[u8; 32],
    expected_project_id: &str,
    prev_receipt: Option<&AuditWitnessReceipt>,
) -> Result<String, AuditWitnessError> {
    let statement = &receipt.statement;
    validate_statement(statement)?;
    if statement.project_id != expected_project_id {
        return Err(AuditWitnessError::ProjectMismatch);
    }
    if receipt.witness_public_key_b64 != BASE64URL_NOPAD.encode(expected_witness_public_key) {
        return Err(AuditWitnessError::WitnessKeyMismatch);
    }
    let key = VerifyingKey::from_bytes(expected_witness_public_key)
        .map_err(|_| AuditWitnessError::WitnessKeyMismatch)?;
    let mut signature_bytes = [0; 64];
    if receipt.signature_b64.len() != BASE64URL_NOPAD.encode_len(signature_bytes.len()) {
        return Err(AuditWitnessError::InvalidSignature);
    }
    BASE64URL_NOPAD
        .decode_mut(receipt.signature_b64.as_bytes(), &mut signature_bytes)
        .map_err(|_| AuditWitnessError::InvalidSignature)?;
    key.verify_strict(
        &canonical_witness_statement_bytes(statement)?,
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| AuditWitnessError::InvalidSignature)?;

    let expected_previous_digest = if let Some(previous) = prev_receipt {
        if previous.statement.project_id != expected_project_id {
            return Err(AuditWitnessError::ProjectMismatch);
        }
        if statement.seq_no <= previous.statement.seq_no {
            return Err(AuditWitnessError::SequenceNotAdvanced);
        }
        if statement.nonce_hex == previous.statement.nonce_hex {
            return Err(AuditWitnessError::DuplicateNonce);
        }
        Some(receipt_digest(previous)?)
    } else {
        None
    };
    if statement.prev_receipt_sha256_hex != expected_previous_digest {
        return Err(AuditWitnessError::PreviousReceiptMismatch);
    }

    receipt_digest(receipt)
}

fn receipt_digest(receipt: &AuditWitnessReceipt) -> Result<String, AuditWitnessError> {
    let json = serde_json::to_value(receipt)?;
    Ok(HEXLOWER.encode(&Sha256::digest(canonical_json(&json))))
}

fn validate_statement(statement: &AuditWitnessStatement) -> Result<(), AuditWitnessError> {
    if statement.schema_version != AUDIT_WITNESS_SCHEMA_VERSION {
        return Err(AuditWitnessError::UnsupportedSchema(statement.schema_version));
    }
    if statement.seq_no == 0 {
        return Err(AuditWitnessError::InvalidField("seq_no"));
    }
    validate_digest(&statement.checkpoint_hmac_hex, "checkpoint_hmac_hex")?;
    if let Some(digest) = &statement.prev_receipt_sha256_hex {
        validate_digest(digest, "prev_receipt_sha256_hex")?;
    }
    if statement.nonce_hex.is_empty()
        || !statement.nonce_hex.len().is_multiple_of(2)
        || !statement.nonce_hex.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(AuditWitnessError::InvalidField("nonce_hex"));
    }
    Ok(())
}

fn validate_digest(digest: &str, field: &'static str) -> Result<(), AuditWitnessError> {
    let mut bytes = [0; 32];
    if digest.len() != HEXLOWER.encode_len(bytes.len()) {
        return Err(AuditWitnessError::InvalidField(field));
    }
    HEXLOWER
        .decode_mut(digest.as_bytes(), &mut bytes)
        .map_err(|_| AuditWitnessError::InvalidField(field))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROJECT: &str = "lk_proj_witness";

    fn statement(seq_no: u64, previous: Option<String>, nonce: &str) -> AuditWitnessStatement {
        AuditWitnessStatement {
            schema_version: AUDIT_WITNESS_SCHEMA_VERSION,
            project_id: PROJECT.to_owned(),
            seq_no,
            checkpoint_hmac_hex: "ab".repeat(32),
            prev_receipt_sha256_hex: previous,
            signer_id: "device".to_owned(),
            witness_id: "external".to_owned(),
            nonce_hex: nonce.to_owned(),
            issued_at_unix_nanos: 17,
        }
    }

    #[test]
    fn signing_payload_has_stable_domain_and_canonical_json() -> Result<(), AuditWitnessError> {
        let payload = canonical_witness_statement_bytes(&statement(7, None, "0102"))?;
        let (domain, json) = payload.split_at(AUDIT_WITNESS_DOMAIN.len() + 1);
        assert_eq!(domain, b"locket-audit-witness-v1\0");
        assert_eq!(
            std::str::from_utf8(json).ok(),
            Some(concat!(
                r#"{"checkpoint_hmac_hex":"abababababababababababababababababababababababababababababababab","#,
                r#""issued_at_unix_nanos":17,"nonce_hex":"0102","prev_receipt_sha256_hex":null,"#,
                r#""project_id":"lk_proj_witness","schema_version":1,"seq_no":7,"#,
                r#""signer_id":"device","witness_id":"external"}"#,
            )),
        );
        Ok(())
    }

    #[test]
    fn witnesses_chain_by_canonical_receipt_digest() -> Result<(), AuditWitnessError> {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public_key = key.verifying_key();
        let first = sign_audit_witness_statement(statement(7, None, "0102"), &key)?;
        let first_digest =
            verify_audit_witness_receipt(&first, public_key.as_bytes(), PROJECT, None)?;
        let second =
            sign_audit_witness_statement(statement(19, Some(first_digest.clone()), "0304"), &key)?;
        let mut wrong_previous = first.clone();
        wrong_previous.statement.project_id = "other-project".into();
        assert!(matches!(
            verify_audit_witness_receipt(
                &second,
                public_key.as_bytes(),
                PROJECT,
                Some(&wrong_previous)
            ),
            Err(AuditWitnessError::ProjectMismatch)
        ));
        let second_digest =
            verify_audit_witness_receipt(&second, public_key.as_bytes(), PROJECT, Some(&first))?;
        let json_receipt = serde_json::from_str(&serde_json::to_string_pretty(&second)?)?;

        assert_ne!(first_digest, second_digest);
        assert_eq!(second_digest.len(), 64);
        assert_eq!(
            verify_audit_witness_receipt(
                &json_receipt,
                public_key.as_bytes(),
                PROJECT,
                Some(&first)
            )?,
            second_digest
        );
        assert!(matches!(
            verify_audit_witness_receipt(&second, public_key.as_bytes(), PROJECT, None),
            Err(AuditWitnessError::PreviousReceiptMismatch)
        ));
        Ok(())
    }

    #[test]
    fn witness_rejects_cross_project_wrong_key_and_tampering() -> Result<(), AuditWitnessError> {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public_key = key.verifying_key();
        let wrong_key = SigningKey::from_bytes(&[8; 32]).verifying_key();
        let receipt = sign_audit_witness_statement(statement(7, None, "0102"), &key)?;
        assert!(matches!(
            verify_audit_witness_receipt(&receipt, public_key.as_bytes(), "other-project", None),
            Err(AuditWitnessError::ProjectMismatch)
        ));
        assert!(matches!(
            verify_audit_witness_receipt(&receipt, wrong_key.as_bytes(), PROJECT, None),
            Err(AuditWitnessError::WitnessKeyMismatch)
        ));
        let mut tampered = receipt.clone();
        tampered.statement.seq_no += 1;
        assert!(matches!(
            verify_audit_witness_receipt(&tampered, public_key.as_bytes(), PROJECT, None),
            Err(AuditWitnessError::InvalidSignature)
        ));
        tampered = receipt.clone();
        tampered.statement.checkpoint_hmac_hex = "cd".repeat(32);
        assert!(matches!(
            verify_audit_witness_receipt(&tampered, public_key.as_bytes(), PROJECT, None),
            Err(AuditWitnessError::InvalidSignature)
        ));
        tampered = receipt;
        tampered.signature_b64.clear();
        assert!(matches!(
            verify_audit_witness_receipt(&tampered, public_key.as_bytes(), PROJECT, None),
            Err(AuditWitnessError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn witness_rejects_rollback_fork_and_nonce_reuse() -> Result<(), AuditWitnessError> {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public_key = key.verifying_key();
        let head = sign_audit_witness_statement(statement(7, None, "0102"), &key)?;
        let head_digest =
            verify_audit_witness_receipt(&head, public_key.as_bytes(), PROJECT, None)?;
        for seq_no in [6, 7] {
            let rollback = sign_audit_witness_statement(
                statement(seq_no, Some(head_digest.clone()), "0304"),
                &key,
            )?;
            assert!(matches!(
                verify_audit_witness_receipt(
                    &rollback,
                    public_key.as_bytes(),
                    PROJECT,
                    Some(&head)
                ),
                Err(AuditWitnessError::SequenceNotAdvanced)
            ));
        }
        let fork = sign_audit_witness_statement(statement(8, Some("ff".repeat(32)), "0304"), &key)?;
        assert!(matches!(
            verify_audit_witness_receipt(&fork, public_key.as_bytes(), PROJECT, Some(&head)),
            Err(AuditWitnessError::PreviousReceiptMismatch)
        ));
        let replay = sign_audit_witness_statement(statement(8, Some(head_digest), "0102"), &key)?;
        assert!(matches!(
            verify_audit_witness_receipt(&replay, public_key.as_bytes(), PROJECT, Some(&head)),
            Err(AuditWitnessError::DuplicateNonce)
        ));
        Ok(())
    }

    #[test]
    fn witness_rejects_invalid_statement_fields() -> Result<(), AuditWitnessError> {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public_key = key.verifying_key();
        let mut receipt = sign_audit_witness_statement(statement(7, None, "0102"), &key)?;
        receipt.statement.schema_version = 2;
        assert!(matches!(
            verify_audit_witness_receipt(&receipt, public_key.as_bytes(), PROJECT, None),
            Err(AuditWitnessError::UnsupportedSchema(2))
        ));
        receipt.statement.schema_version = AUDIT_WITNESS_SCHEMA_VERSION;
        receipt.statement.checkpoint_hmac_hex = "01".to_owned();
        assert!(matches!(
            verify_audit_witness_receipt(&receipt, public_key.as_bytes(), PROJECT, None),
            Err(AuditWitnessError::InvalidField("checkpoint_hmac_hex"))
        ));
        assert!(matches!(
            sign_audit_witness_statement(statement(7, None, ""), &key),
            Err(AuditWitnessError::InvalidField("nonce_hex"))
        ));
        assert!(matches!(
            sign_audit_witness_statement(statement(0, None, "0102"), &key),
            Err(AuditWitnessError::InvalidField("seq_no"))
        ));
        Ok(())
    }
}
