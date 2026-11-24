//! Persistence for verified external audit witness receipts.

use locket_core::{AuditWitnessError, AuditWitnessReceipt, verify_audit_witness_receipt};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};

use crate::{Store, StoreError};

/// A verified audit witness receipt and its local storage metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditWitnessReceiptRecord {
    /// Local identifier for the receipt.
    pub id: String,
    /// Signed external receipt.
    pub receipt: AuditWitnessReceipt,
    /// SHA-256 hex digest of the canonical receipt, used to link the next receipt.
    pub receipt_sha256_hex: String,
    /// Time the store recorded the receipt, in Unix nanoseconds.
    pub recorded_at: i64,
}

impl Store {
    /// Verifies and appends a receipt to the specified project's witness chain.
    ///
    /// The current head is read under a write transaction. The receipt must name
    /// its digest and advance its sequence, or have no predecessor for an empty
    /// chain. A nonce may only be used once per project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AuditWitness`] if the receipt is invalid, fails to
    /// extend the stored chain, or reuses a nonce. Returns [`StoreError::Sqlite`]
    /// for database failures, including duplicate row IDs and sequence numbers
    /// outside the signed 64-bit range supported by `SQLite`.
    pub fn insert_audit_witness_receipt(
        &self,
        id: &str,
        project_id: &str,
        receipt: &AuditWitnessReceipt,
        expected_witness_public_key: &[u8; 32],
        recorded_at: i64,
    ) -> Result<AuditWitnessReceiptRecord, StoreError> {
        let sequence = i64::try_from(receipt.statement.seq_no)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let previous = latest_receipt(&transaction, project_id)?;
        let receipt_sha256_hex = verify_audit_witness_receipt(
            receipt,
            expected_witness_public_key,
            project_id,
            previous.as_ref().map(|record| &record.receipt),
        )?;
        let statement = &receipt.statement;
        if statement.prev_receipt_sha256_hex.as_deref()
            != previous.as_ref().map(|record| record.receipt_sha256_hex.as_str())
        {
            return Err(AuditWitnessError::PreviousReceiptMismatch.into());
        }
        let nonce_exists = transaction.query_row(
            "SELECT EXISTS (
               SELECT 1 FROM audit_witness_receipts
               WHERE project_id = ?1 AND json_extract(receipt_json, '$.statement.nonce_hex') = ?2
             )",
            params![project_id, statement.nonce_hex],
            |row| row.get::<_, bool>(0),
        )?;
        if nonce_exists {
            return Err(AuditWitnessError::DuplicateNonce.into());
        }
        transaction.execute(
            "INSERT INTO audit_witness_receipts (
               id, project_id, seq_no, checkpoint_hmac_hex, prev_receipt_sha256_hex,
               receipt_sha256_hex, witness_id, signer_id, receipt_json, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                id,
                project_id,
                sequence,
                statement.checkpoint_hmac_hex,
                statement.prev_receipt_sha256_hex,
                receipt_sha256_hex,
                statement.witness_id,
                statement.signer_id,
                serde_json::to_string(receipt)?,
                recorded_at,
            ],
        )?;
        transaction.commit()?;
        Ok(AuditWitnessReceiptRecord {
            id: id.to_owned(),
            receipt: receipt.clone(),
            receipt_sha256_hex,
            recorded_at,
        })
    }

    /// Returns the latest stored witness receipt for a project, if present.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when a stored receipt cannot be read or decoded.
    pub fn get_latest_audit_witness_receipt(
        &self,
        project_id: &str,
    ) -> Result<Option<AuditWitnessReceiptRecord>, StoreError> {
        latest_receipt(&self.connection, project_id)
    }

    /// Lists a project's stored witness receipts in ascending sequence order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when stored receipts cannot be read or decoded.
    pub fn list_audit_witness_receipts(
        &self,
        project_id: &str,
    ) -> Result<Vec<AuditWitnessReceiptRecord>, StoreError> {
        let mut statement = self.connection.prepare_cached(
            "SELECT id, receipt_json, receipt_sha256_hex, recorded_at
             FROM audit_witness_receipts WHERE project_id = ?1 ORDER BY seq_no",
        )?;
        Ok(statement
            .query_map([project_id], receipt_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

fn latest_receipt(
    connection: &Connection,
    project_id: &str,
) -> Result<Option<AuditWitnessReceiptRecord>, StoreError> {
    Ok(connection
        .prepare_cached(
            "SELECT id, receipt_json, receipt_sha256_hex, recorded_at
             FROM audit_witness_receipts WHERE project_id = ?1 ORDER BY seq_no DESC LIMIT 1",
        )?
        .query_row([project_id], receipt_from_row)
        .optional()?)
}

fn receipt_from_row(row: &Row<'_>) -> rusqlite::Result<AuditWitnessReceiptRecord> {
    let receipt = serde_json::from_str(row.get_ref(1)?.as_str()?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(AuditWitnessReceiptRecord {
        id: row.get(0)?,
        receipt,
        receipt_sha256_hex: row.get(2)?,
        recorded_at: row.get(3)?,
    })
}
