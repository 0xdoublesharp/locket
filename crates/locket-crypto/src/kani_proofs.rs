//! Bounded checks of production framing and a fixed-input AEAD fixture.

use crate::key_wrap::{split_wrapped_dek_v1, wrap_dek_with_nonce_v1};
use crate::{CryptoError, KEY_LEN, NONCE_LEN, TAG_LEN, canonical_field, unwrap_dek_v1};

#[kani::proof]
#[kani::unwind(12)]
fn canonical_field_preserves_utf8_boundaries() {
    // Four bytes cover every 1–4 byte UTF-8 sequence and every split point
    // without triggering stdlib's 8-byte SWAR UTF-8 validation path.
    let bytes: [u8; 4] = kani::any();
    let split: usize = kani::any();
    kani::assume(split <= bytes.len());
    let (name, value) = bytes.split_at(split);
    if let (Ok(name), Ok(value)) = (std::str::from_utf8(name), std::str::from_utf8(value)) {
        let Ok(encoded) = canonical_field(name, value) else {
            unreachable!("bounded fields fit their length prefixes");
        };
        let value_offset = 2 + name.len();
        assert_eq!(encoded.len(), bytes.len() + 6);
        assert_eq!(u16::from_le_bytes([encoded[0], encoded[1]]) as usize, name.len());
        assert_eq!(&encoded[2..value_offset], name.as_bytes());
        let length = &encoded[value_offset..value_offset + 4];
        assert_eq!(
            u32::from_le_bytes([length[0], length[1], length[2], length[3]]) as usize,
            value.len()
        );
        assert_eq!(&encoded[value_offset + 4..], value.as_bytes());
    }
}

#[kani::proof]
#[kani::unwind(80)]
fn embedded_nonce_and_ciphertext_require_exact_lengths() {
    const FRAME_LEN: usize = NONCE_LEN + KEY_LEN + TAG_LEN;
    let bytes: [u8; FRAME_LEN + 1] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    match split_wrapped_dek_v1(&bytes[..len]) {
        Ok((nonce, ciphertext)) => {
            assert_eq!(len, FRAME_LEN);
            assert_eq!(nonce.as_slice(), &bytes[..NONCE_LEN]);
            assert_eq!(ciphertext, &bytes[NONCE_LEN..FRAME_LEN]);
        }
        Err(error) => {
            assert_ne!(len, FRAME_LEN);
            assert_eq!(error, CryptoError::InvalidWrappedKey);
        }
    }
}

#[kani::proof]
#[kani::unwind(80)]
fn fixed_wrap_round_trips_and_rejects_a_flipped_tag_bit() {
    let key = [7; KEY_LEN];
    let nonce = [11; NONCE_LEN];
    let material = [19; KEY_LEN];
    let aad = b"locket proof fixture";
    let Ok(mut envelope) = wrap_dek_with_nonce_v1(&key, &material, aad, &nonce) else {
        unreachable!("fixture fits the cipher bounds");
    };
    assert_eq!(envelope.len(), NONCE_LEN + KEY_LEN + TAG_LEN);
    assert_eq!(&envelope[..NONCE_LEN], &nonce);
    let Ok(opened) = unwrap_dek_v1(&key, &envelope, aad) else {
        unreachable!("the original envelope authenticates");
    };
    assert_eq!(*opened, material);

    let index: usize = kani::any();
    let bit: u8 = kani::any();
    kani::assume(index < TAG_LEN && bit < 8);
    envelope[NONCE_LEN + KEY_LEN + index] ^= 1 << bit;
    assert_eq!(unwrap_dek_v1(&key, &envelope, aad).err(), Some(CryptoError::DecryptionFailed));
}
