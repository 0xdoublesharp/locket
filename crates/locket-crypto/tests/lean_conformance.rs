//! Executable vectors for `CryptoDomainSeparation.lean`.
#![allow(unused_crate_dependencies)]

use std::collections::BTreeSet;

use hmac::{Hmac, KeyInit, Mac};
use locket_crypto::{
    CryptoError, HkdfWrapInfo, KEY_LEN, KeyBytes, KeyPurpose, KeyWrapAad, KeyWrapPurpose,
    SecretBlobAad, canonical_field, hkdf_wrap_info_v1, key_wrap_aad_v1, local_dedup_tag_v1,
    passkey_prf_wrap_aad_v1, passphrase_fallback_aad_v1, recovery_entry_aad_v1, secret_blob_aad_v1,
    secret_fingerprint_v1,
};
use sha2::Sha256;

#[test]
fn length_prefixes_distinguish_every_boundary_pair() -> Result<(), Box<dyn std::error::Error>> {
    // Includes equal delimiter-joined strings, embedded NULs, and different UTF-8 byte widths.
    // Under Miri, use a compact representative subset so the 4D Cartesian product stays fast.
    let parts: &[&str] = if cfg!(miri) {
        &["", "a|b", "\0", "é"]
    } else {
        &["", "a", "b", "c", "a|b", "b|c", "|", "\0", "a\0", "\0b", "é", "🦀"]
    };
    let mut seen_fields = BTreeSet::new();
    let mut seen_aad = BTreeSet::new();
    for &name in parts {
        for &value in parts {
            assert!(seen_fields.insert(canonical_field(name, value)?), "{name:?}, {value:?}");
            for &secret_id in parts {
                for &secret_name in parts {
                    for version in [0, u32::MAX] {
                        let aad = SecretBlobAad::new(name, value, secret_id, secret_name, version);
                        assert!(seen_aad.insert(secret_blob_aad_v1(&aad)?), "{aad:?}");
                    }
                }
            }
        }
    }
    assert_eq!(canonical_field("", "")?, [0; 6]);
    assert_eq!(canonical_field("é", "\0")?, [2, 0, 0xc3, 0xa9, 1, 0, 0, 0, 0]);
    let name_limit = usize::from(u16::MAX);
    assert_eq!(&canonical_field(&"a".repeat(name_limit), "")?[..2], &[255, 255]);
    assert_eq!(
        canonical_field(&"a".repeat(name_limit + 1), ""),
        Err(CryptoError::FieldNameTooLong),
    );
    Ok(())
}

#[test]
fn secret_blob_aad_matches_the_lean_field_order_and_widths() -> Result<(), CryptoError> {
    let aad = secret_blob_aad_v1(&SecretBlobAad::new("p", "", "\0", "é", 0x0102_0304))?;
    let expected = [
        b"locket-aad-v1\x01\x00".as_slice(),
        b"\x0a\x00project_id\x01\x00\x00\x00p",
        b"\x0a\x00profile_id\x00\x00\x00\x00",
        b"\x09\x00secret_id\x01\x00\x00\x00\x00",
        b"\x0b\x00secret_name\x02\x00\x00\x00\xc3\xa9",
        b"\x04\x03\x02\x01",
    ]
    .concat();
    assert_eq!(aad, expected);
    Ok(())
}

#[test]
fn authentication_domains_have_no_common_prefix_at_the_shorter_length() -> Result<(), CryptoError> {
    let live_encodings: &[(&[u8], Vec<u8>)] = &[
        (b"locket-aad-v1", secret_blob_aad_v1(&SecretBlobAad::new("", "", "", "", 0))?),
        (
            b"locket-key-wrap-v1",
            key_wrap_aad_v1(&KeyWrapAad::new("", "", Some(""), 0, KeyWrapPurpose::ProfileSecret))?,
        ),
        (b"locket-recovery-envelope-v1", recovery_entry_aad_v1("", "", "")?),
        (
            b"locket-wrap-v1",
            hkdf_wrap_info_v1(&HkdfWrapInfo::new("", Some(""), KeyPurpose::ProfileSecret))?,
        ),
        (b"locket-passphrase-fallback-v1", passphrase_fallback_aad_v1("", "")?),
        (b"locket-passkey-prf-v1", passkey_prf_wrap_aad_v1("")?),
    ];
    for (domain, encoded) in live_encodings {
        assert!(encoded.starts_with(domain));
    }
    let key = [42; KEY_LEN];
    let value = "dedup conformance 🦀";
    // The keyed encoders return only their MAC. Verify their input prefixes
    // by reproducing the MAC with the bytes modeled in Lean.
    let keyed_encodings: &[(&[u8], [u8; 32])] = &[
        (b"locket-secret-fingerprint-v1", secret_fingerprint_v1(&key, value)?),
        (b"locket-local-dedup-v1", local_dedup_tag_v1(&key, value)?),
    ];
    for (domain, tag) in keyed_encodings {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        mac.update(domain);
        mac.update(value.as_bytes());
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(*tag, expected);
    }
    // The audit, team package, and backup encoders are owned by other crates.
    let domains = live_encodings
        .iter()
        .map(|(domain, _)| *domain)
        .chain(keyed_encodings.iter().map(|(domain, _)| *domain))
        .chain([
            b"locket-audit-v1".as_slice(),
            b"locket-team-state-v1\0",
            b"locket-bundle-audit-chain-v1\0",
        ])
        .collect::<Vec<_>>();
    for (index, left) in domains.iter().enumerate() {
        for right in &domains[index + 1..] {
            let width = left.len().min(right.len());
            assert_ne!(left[..width], right[..width]);
        }
    }
    Ok(())
}

#[test]
fn canonical_symmetric_keys_accept_exactly_32_bytes() {
    assert_eq!(KEY_LEN, 32);
    let bytes = [42; 65];
    for length in 0..=bytes.len() {
        assert_eq!(KeyBytes::try_from(&bytes[..length]).is_ok(), length == 32, "length {length}");
    }
}
