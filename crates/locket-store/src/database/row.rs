//! Row deserializers shared across `Store` modules.

use rusqlite::types::Type;

use crate::error::{InvalidFixedBytesLength, InvalidNonceLength};

pub fn root_hash_from_row(
    row: &rusqlite::Row<'_>,
    column: usize,
    field: &'static str,
) -> rusqlite::Result<[u8; 32]> {
    let bytes: Vec<u8> = row.get(column)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Blob,
            Box::new(InvalidFixedBytesLength { field, expected: 32, actual: bytes.len() }),
        )
    })
}

pub fn nonce_from_row(
    row: &rusqlite::Row<'_>,
    column: usize,
    field: &'static str,
) -> rusqlite::Result<[u8; 24]> {
    let bytes: Vec<u8> = row.get(column)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Blob,
            Box::new(InvalidNonceLength { field, actual: bytes.len() }),
        )
    })
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, Error, types::Type};

    use super::*;

    #[test]
    fn row_decoders_reject_blobs_with_noncanonical_lengths() -> rusqlite::Result<()> {
        let connection = Connection::open_in_memory()?;
        for bad_length in [31, 33] {
            let result = connection.query_row("SELECT zeroblob(?1)", [bad_length], |row| {
                root_hash_from_row(row, 0, "test.root_hash")
            });
            assert!(matches!(
                result,
                Err(Error::FromSqlConversionFailure(0, Type::Blob, error))
                    if error.is::<InvalidFixedBytesLength>()
            ));
        }
        for bad_length in [23, 25] {
            let result = connection.query_row("SELECT zeroblob(?1)", [bad_length], |row| {
                nonce_from_row(row, 0, "test.nonce")
            });
            assert!(matches!(
                result,
                Err(Error::FromSqlConversionFailure(0, Type::Blob, error))
                    if error.is::<InvalidNonceLength>()
            ));
        }
        Ok(())
    }
}
