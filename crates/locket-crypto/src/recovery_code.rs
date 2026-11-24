//! Recovery code encoding/decoding using Crockford Base32.

use zeroize::Zeroizing;

use crate::error::{CryptoError, CryptoResult};
use crate::{RECOVERY_CODE_BYTES, RECOVERY_CODE_DATA_CHARS, RECOVERY_CODE_TOTAL_CHARS};

/// Crockford Base32 symbol alphabet (32 data symbols).
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Crockford Base32 checksum symbols (37 symbols for mod-37 checksum).
const CROCKFORD_CHECK: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";

/// Encodes 20 raw bytes as 32 Crockford Base32 data chars + 2 checksum chars.
///
/// The output is 34 characters: 32 data + 2 checksum, suitable for grouping.
#[must_use]
pub fn recovery_code_encode(bytes: &[u8; RECOVERY_CODE_BYTES]) -> [u8; RECOVERY_CODE_TOTAL_CHARS] {
    let mut out = [0u8; RECOVERY_CODE_TOTAL_CHARS];
    // Encode 160 bits as 32 x 5-bit Crockford Base32 symbols.
    for (i, slot) in out[..RECOVERY_CODE_DATA_CHARS].iter_mut().enumerate() {
        let bit_offset = i * 5;
        let byte_idx = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let bits = if bit_shift <= 3 {
            (bytes[byte_idx] >> (3 - bit_shift)) & 0x1F
        } else {
            let lo = (bytes[byte_idx] << (bit_shift - 3)) & 0x1F;
            let hi = bytes[byte_idx + 1] >> (11 - bit_shift);
            lo | hi
        };
        *slot = CROCKFORD_ALPHABET[usize::from(bits)];
    }
    // The checksum is one symbol for (acc mod 37). We store two checksum chars
    // for forward compatibility: char 33 is the primary checksum, char 34 is 0-padded.
    out[RECOVERY_CODE_DATA_CHARS] = checksum_symbol(bytes);
    out[RECOVERY_CODE_DATA_CHARS + 1] = CROCKFORD_CHECK[0]; // reserved, always '0'
    out
}

/// Decodes 32 or 34 Crockford Base32 characters back into 20 raw bytes.
///
/// Accepts uppercase and lowercase input. Ignores spaces and hyphens.
/// Returns `Err(CryptoError::InvalidSecretValue)` on invalid characters or checksum mismatch.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSecretValue`] if the input is too short, contains
/// invalid characters, or the checksum does not match.
pub fn recovery_code_decode(input: &str) -> CryptoResult<[u8; RECOVERY_CODE_BYTES]> {
    let mut chars =
        input.bytes().filter(|&b| b != b'-' && b != b' ').map(|b| b.to_ascii_uppercase());

    // Pack 32 x 5-bit values into 20 bytes.
    let mut bytes = Zeroizing::new([0u8; RECOVERY_CODE_BYTES]);
    for i in 0..RECOVERY_CODE_DATA_CHARS {
        let val = crockford_decode_char(chars.next().ok_or(CryptoError::InvalidSecretValue)?)?;
        let bit_offset = i * 5;
        let byte_idx = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        if bit_shift <= 3 {
            bytes[byte_idx] |= val << (3 - bit_shift);
        } else {
            bytes[byte_idx] |= val >> (bit_shift - 3);
            bytes[byte_idx + 1] |= val << (11 - bit_shift);
        }
    }

    // Verify checksum if provided.
    if let Some(check) = chars.next()
        && (check != checksum_symbol(&bytes)
            || chars.next() != Some(b'0')
            || chars.next().is_some())
    {
        return Err(CryptoError::InvalidSecretValue);
    }

    Ok(*bytes)
}

fn checksum_symbol(bytes: &[u8; RECOVERY_CODE_BYTES]) -> u8 {
    // Treat the code as a big-endian integer modulo the checksum alphabet length.
    let remainder =
        bytes.iter().fold(0, |acc, &byte| (acc * 256 + usize::from(byte)) % CROCKFORD_CHECK.len());
    CROCKFORD_CHECK[remainder]
}

const fn crockford_decode_char(c: u8) -> CryptoResult<u8> {
    match c {
        b'0' | b'O' => Ok(0),
        b'1' | b'I' | b'L' => Ok(1),
        b'2' => Ok(2),
        b'3' => Ok(3),
        b'4' => Ok(4),
        b'5' => Ok(5),
        b'6' => Ok(6),
        b'7' => Ok(7),
        b'8' => Ok(8),
        b'9' => Ok(9),
        b'A' => Ok(10),
        b'B' => Ok(11),
        b'C' => Ok(12),
        b'D' => Ok(13),
        b'E' => Ok(14),
        b'F' => Ok(15),
        b'G' => Ok(16),
        b'H' => Ok(17),
        b'J' => Ok(18),
        b'K' => Ok(19),
        b'M' => Ok(20),
        b'N' => Ok(21),
        b'P' => Ok(22),
        b'Q' => Ok(23),
        b'R' => Ok(24),
        b'S' => Ok(25),
        b'T' => Ok(26),
        b'V' => Ok(27),
        b'W' => Ok(28),
        b'X' => Ok(29),
        b'Y' => Ok(30),
        b'Z' => Ok(31),
        _ => Err(CryptoError::InvalidSecretValue),
    }
}
