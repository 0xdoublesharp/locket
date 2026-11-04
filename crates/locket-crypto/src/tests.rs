use super::{
    AAD_SCHEMA_V1, CryptoError, HKDF_WRAP_INFO_SCHEMA_V1, HkdfWrapInfo, KEY_LEN,
    KEY_WRAP_SCHEMA_V1, KeyPurpose, KeyWrapAad, KeyWrapPurpose, NONCE_LEN,
    PASSKEY_PRF_WRAP_SCHEMA_V1, PASSPHRASE_FALLBACK_OUTPUT_LEN, PassphraseKdfParams,
    RECOVERY_CODE_BYTES, RECOVERY_CODE_DATA_CHARS, RECOVERY_ENVELOPE_SCHEMA_V1, SecretBlobAad,
    TAG_LEN, canonical_field, decrypt_secret_value_v1, derive_passphrase_fallback_key_v1,
    derive_wrapping_key_v1, hkdf_wrap_info_v1, key_wrap_aad_v1, open_recovery_entry_v1,
    passkey_prf_wrap_aad_v1, passphrase_fallback_aad_v1, recovery_code_decode,
    recovery_code_encode, recovery_entry_aad_v1, recovery_entry_key_v1, seal_recovery_entry_v1,
    secret_blob_aad_v1, secret_fingerprint_v1, unwrap_dek_v1, unwrap_key_material_v1,
    unwrap_master_key_with_passkey_prf, wrap_dek_v1, wrap_key_material_v1,
    wrap_master_key_with_passkey_prf,
};

const PROFILE_SECRET_KEY: [u8; KEY_LEN] = [7; KEY_LEN];
const MASTER_KEY: [u8; KEY_LEN] = [11; KEY_LEN];

#[test]
fn secret_blob_aad_bytes_are_stable() -> Result<(), CryptoError> {
    let metadata = SecretBlobAad::new("lk_proj_123", "lk_prof_dev", "lk_sec_db", "DATABASE_URL", 7);

    let aad = secret_blob_aad_v1(&metadata)?;
    let expected = [
        b"locket-aad-v1".as_slice(),
        &AAD_SCHEMA_V1.to_le_bytes(),
        &[10, 0],
        b"project_id",
        &[11, 0, 0, 0],
        b"lk_proj_123",
        &[10, 0],
        b"profile_id",
        &[11, 0, 0, 0],
        b"lk_prof_dev",
        &[9, 0],
        b"secret_id",
        &[9, 0, 0, 0],
        b"lk_sec_db",
        &[11, 0],
        b"secret_name",
        &[12, 0, 0, 0],
        b"DATABASE_URL",
        &[7, 0, 0, 0],
    ]
    .concat();

    assert_eq!(aad, expected);
    Ok(())
}

#[test]
fn key_wrap_aad_bytes_are_stable() -> Result<(), CryptoError> {
    let metadata = KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        7,
        KeyWrapPurpose::SecretDek,
    );

    let aad = key_wrap_aad_v1(&metadata)?;
    let expected = [
        b"locket-key-wrap-v1".as_slice(),
        &[10, 0],
        b"project_id",
        &[11, 0, 0, 0],
        b"lk_proj_123",
        &[6, 0],
        b"key_id",
        &[9, 0, 0, 0],
        b"lk_sec_db",
        &[10, 0],
        b"profile_id",
        &[11, 0, 0, 0],
        b"lk_prof_dev",
        &[7, 0, 0, 0],
        &[7, 0],
        b"purpose",
        &[10, 0, 0, 0],
        b"secret-dek",
        &KEY_WRAP_SCHEMA_V1.to_le_bytes(),
    ]
    .concat();

    assert_eq!(aad, expected);
    Ok(())
}

#[test]
fn hkdf_wrap_info_encodes_missing_profile_as_empty_field() -> Result<(), CryptoError> {
    let info =
        hkdf_wrap_info_v1(&HkdfWrapInfo::new("lk_proj_123", None, KeyPurpose::ProjectMetadata))?;
    let expected = [
        b"locket-wrap-v1".as_slice(),
        &HKDF_WRAP_INFO_SCHEMA_V1.to_le_bytes(),
        &[10, 0],
        b"project_id",
        &[11, 0, 0, 0],
        b"lk_proj_123",
        &[10, 0],
        b"profile_id",
        &[0, 0, 0, 0],
        &[7, 0],
        b"purpose",
        &[16, 0, 0, 0],
        b"project-metadata",
    ]
    .concat();

    assert_eq!(info, expected);
    Ok(())
}

#[test]
fn passphrase_fallback_aad_bytes_are_stable() -> Result<(), CryptoError> {
    let aad = passphrase_fallback_aad_v1("lk_proj_123", "lk_kdf_passphrase_v1")?;
    let expected = [
        b"locket-passphrase-fallback-v1".as_slice(),
        &KEY_WRAP_SCHEMA_V1.to_le_bytes(),
        &[10, 0],
        b"project_id",
        &[11, 0, 0, 0],
        b"lk_proj_123",
        &[14, 0],
        b"kdf_profile_id",
        &[20, 0, 0, 0],
        b"lk_kdf_passphrase_v1",
    ]
    .concat();

    assert_eq!(aad, expected);
    Ok(())
}

#[test]
fn passphrase_fallback_key_derivation_is_salt_and_passphrase_bound() -> Result<(), CryptoError> {
    let params = PassphraseKdfParams {
        m_cost: 32,
        t_cost: 1,
        p_cost: 1,
        output_len: PASSPHRASE_FALLBACK_OUTPUT_LEN,
    };

    let first = derive_passphrase_fallback_key_v1(b"correct horse", b"salt-one", params)?;
    let second = derive_passphrase_fallback_key_v1(b"correct horse", b"salt-one", params)?;
    let changed_passphrase =
        derive_passphrase_fallback_key_v1(b"wrong horse", b"salt-one", params)?;
    let changed_salt = derive_passphrase_fallback_key_v1(b"correct horse", b"salt-two", params)?;

    assert_eq!(&*first, &*second);
    assert_ne!(&*first, &*changed_passphrase);
    assert_ne!(&*first, &*changed_salt);
    Ok(())
}

#[test]
fn passphrase_fallback_rejects_empty_passphrase_or_salt() {
    let params = PassphraseKdfParams::fallback_v1();

    assert!(matches!(
        derive_passphrase_fallback_key_v1(b"", b"salt", params),
        Err(CryptoError::InvalidKdfParameters)
    ));
    assert!(matches!(
        derive_passphrase_fallback_key_v1(b"passphrase", b"", params),
        Err(CryptoError::InvalidKdfParameters)
    ));
}

#[test]
fn canonical_field_rejects_oversized_field_name() {
    let name = "n".repeat(usize::from(u16::MAX) + 1);

    assert!(matches!(canonical_field(&name, "value"), Err(CryptoError::FieldNameTooLong)));
}

#[test]
fn secret_value_uses_separate_value_and_wrap_nonces() -> Result<(), CryptoError> {
    let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_dev",
        "lk_sec_db",
        "DATABASE_URL",
        1,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;

    let encrypted = super::encrypt_secret_value_v1(
        &PROFILE_SECRET_KEY,
        "postgres://localhost/app",
        &value_aad,
        &wrap_aad,
    )?;

    assert_eq!(encrypted.value_nonce.len(), NONCE_LEN);
    assert_eq!(encrypted.encrypted_dek.len(), NONCE_LEN + KEY_LEN + TAG_LEN);
    assert_ne!(&encrypted.encrypted_dek[..NONCE_LEN], encrypted.value_nonce.as_slice());
    assert_eq!(encrypted.aad_schema_version, AAD_SCHEMA_V1);
    Ok(())
}

#[test]
fn changed_aad_fails_secret_decryption() -> Result<(), CryptoError> {
    let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_dev",
        "lk_sec_db",
        "DATABASE_URL",
        1,
    ))?;
    let changed_value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_prod",
        "lk_sec_db",
        "DATABASE_URL",
        1,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;

    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret-value", &value_aad, &wrap_aad)?;
    let result =
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &changed_value_aad, &wrap_aad);

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn changed_dek_wrap_aad_fails_secret_decryption() -> Result<(), CryptoError> {
    let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_dev",
        "lk_sec_db",
        "DATABASE_URL",
        1,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;
    let changed_wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        2,
        KeyWrapPurpose::SecretDek,
    ))?;

    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    let result =
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &value_aad, &changed_wrap_aad);

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

/// Builds the canonical AAD pair for `lk_proj_123/lk_prof_dev/lk_sec_db/DATABASE_URL@v1`.
fn canonical_secret_aads() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_dev",
        "lk_sec_db",
        "DATABASE_URL",
        1,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;
    Ok((value_aad, wrap_aad))
}

#[test]
fn unsupported_aad_schema_fails_secret_decryption() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let mut encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    assert_eq!(
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &value_aad, &wrap_aad)?.as_str(),
        "secret"
    );

    for schema_version in [0, 2, u16::MAX] {
        encrypted.aad_schema_version = schema_version;
        assert_eq!(
            decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &value_aad, &wrap_aad),
            Err(CryptoError::DecryptionFailed),
            "unsupported AAD schema {schema_version}"
        );
    }
    Ok(())
}

#[test]
fn unsupported_aad_schema_is_rejected_before_unwrapping() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let mut encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    encrypted.aad_schema_version = 2;
    encrypted.encrypted_dek.clear();

    assert_eq!(
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &value_aad, &wrap_aad),
        Err(CryptoError::DecryptionFailed)
    );
    Ok(())
}

#[test]
fn wrong_profile_secret_key_fails_secret_decryption() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    let mut wrong_key = PROFILE_SECRET_KEY;
    wrong_key[0] ^= 0xff;
    let result = decrypt_secret_value_v1(&wrong_key, &encrypted, &value_aad, &wrap_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn tampered_value_nonce_fails_secret_decryption() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let mut encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    encrypted.value_nonce[0] ^= 0x01;
    let result = decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &value_aad, &wrap_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn tampered_wrap_nonce_fails_dek_unwrap() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let mut encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    encrypted.encrypted_dek[0] ^= 0x01;
    let result = decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &value_aad, &wrap_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn tampered_ciphertext_body_fails_secret_decryption() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let mut encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    encrypted.ciphertext[0] ^= 0x01;
    let result = decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &value_aad, &wrap_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn tampered_dek_ciphertext_body_fails_secret_decryption() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let mut encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    // Flip a byte in the DEK ciphertext body (past the NONCE_LEN wrap-nonce prefix).
    encrypted.encrypted_dek[NONCE_LEN] ^= 0x01;
    let result = decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &value_aad, &wrap_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn changed_project_id_aad_fails_secret_decryption() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let changed_value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_999",
        "lk_prof_dev",
        "lk_sec_db",
        "DATABASE_URL",
        1,
    ))?;
    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    let result =
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &changed_value_aad, &wrap_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn changed_secret_id_aad_fails_secret_decryption() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let changed_value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_dev",
        "lk_sec_other",
        "DATABASE_URL",
        1,
    ))?;
    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    let result =
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &changed_value_aad, &wrap_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn changed_secret_name_aad_fails_secret_decryption() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let changed_value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_dev",
        "lk_sec_db",
        "API_KEY",
        1,
    ))?;
    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    let result =
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &changed_value_aad, &wrap_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn changed_value_version_aad_fails_secret_decryption() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let changed_value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
        "lk_proj_123",
        "lk_prof_dev",
        "lk_sec_db",
        "DATABASE_URL",
        2,
    ))?;
    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    let result =
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &changed_value_aad, &wrap_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn changed_wrap_project_id_aad_fails_dek_unwrap() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let changed_wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_999",
        "lk_sec_db",
        Some("lk_prof_dev"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;
    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    let result =
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &value_aad, &changed_wrap_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn changed_wrap_key_id_aad_fails_dek_unwrap() -> Result<(), CryptoError> {
    let (value_aad, wrap_aad) = canonical_secret_aads()?;
    let changed_wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_other",
        Some("lk_prof_dev"),
        1,
        KeyWrapPurpose::SecretDek,
    ))?;
    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "secret", &value_aad, &wrap_aad)?;
    let result =
        decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &value_aad, &changed_wrap_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn secret_values_reject_nul_bytes_before_encryption_or_fingerprinting() {
    let encrypted =
        super::encrypt_secret_value_v1(&PROFILE_SECRET_KEY, "bad\0value", b"value", b"wrap");
    let fingerprint = secret_fingerprint_v1(&PROFILE_SECRET_KEY, "bad\0value");

    assert!(matches!(encrypted, Err(CryptoError::InvalidSecretValue)));
    assert!(matches!(fingerprint, Err(CryptoError::InvalidSecretValue)));
}

#[test]
fn wrap_and_unwrap_dek_round_trip() -> Result<(), CryptoError> {
    let dek = [19; KEY_LEN];
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_sec_db",
        Some("lk_prof_dev"),
        3,
        KeyWrapPurpose::SecretDek,
    ))?;

    let wrapped = wrap_dek_v1(&PROFILE_SECRET_KEY, &dek, &aad)?;
    let unwrapped = unwrap_dek_v1(&PROFILE_SECRET_KEY, &wrapped, &aad)?;

    assert_eq!(&*unwrapped, &dek);
    Ok(())
}

#[test]
fn unwrap_dek_rejects_noncanonical_embedded_nonce_layout() {
    let encrypted_dek = vec![0_u8; NONCE_LEN + KEY_LEN + TAG_LEN - 1];

    assert!(matches!(
        unwrap_dek_v1(&PROFILE_SECRET_KEY, &encrypted_dek, b"aad"),
        Err(CryptoError::InvalidWrappedKey)
    ));
}

#[test]
fn hkdf_wrap_info_uses_canonical_purpose_strings() -> Result<(), CryptoError> {
    let project_key = derive_wrapping_key_v1(
        &MASTER_KEY,
        &HkdfWrapInfo::new("lk_proj_123", None, KeyPurpose::Audit),
    )?;
    let profile_key = derive_wrapping_key_v1(
        &MASTER_KEY,
        &HkdfWrapInfo::new("lk_proj_123", Some("lk_prof_dev"), KeyPurpose::ProfileSecret),
    )?;

    assert_ne!(&*project_key, &*profile_key);
    Ok(())
}

#[test]
fn stored_key_wrap_round_trips_with_separate_nonce() -> Result<(), CryptoError> {
    let key_material = [23; KEY_LEN];
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_key_profile",
        Some("lk_prof_dev"),
        0,
        KeyWrapPurpose::ProfileSecret,
    ))?;

    let wrapped = wrap_key_material_v1(&PROFILE_SECRET_KEY, &key_material, &aad)?;
    let unwrapped = unwrap_key_material_v1(&PROFILE_SECRET_KEY, &wrapped, &aad)?;

    assert_eq!(wrapped.nonce.len(), NONCE_LEN);
    assert_eq!(&*unwrapped, &key_material);
    Ok(())
}

#[test]
fn recovery_code_round_trips_with_and_without_checksum() -> Result<(), CryptoError> {
    let code_bytes = [7_u8; RECOVERY_CODE_BYTES];
    let encoded = recovery_code_encode(&code_bytes);
    let encoded = String::from_utf8_lossy(&encoded);
    let grouped =
        format!("{}-{}-{}-{}", &encoded[0..8], &encoded[8..16], &encoded[16..24], &encoded[24..]);

    assert_eq!(recovery_code_decode(&encoded)?, code_bytes);
    assert_eq!(recovery_code_decode(&encoded[..RECOVERY_CODE_DATA_CHARS])?, code_bytes);
    assert_eq!(recovery_code_decode(&grouped)?, code_bytes);
    Ok(())
}

#[test]
fn recovery_code_rejects_malformed_lengths_and_checksum() {
    let code_bytes = [9_u8; RECOVERY_CODE_BYTES];
    let encoded = recovery_code_encode(&code_bytes);
    let encoded = String::from_utf8_lossy(&encoded);
    let mut bad_check = encoded.as_bytes().to_vec();
    bad_check[RECOVERY_CODE_DATA_CHARS] =
        if bad_check[RECOVERY_CODE_DATA_CHARS] == b'0' { b'1' } else { b'0' };
    let bad_check = String::from_utf8_lossy(&bad_check);
    let mut bad_reserved = encoded.as_bytes().to_vec();
    bad_reserved[RECOVERY_CODE_DATA_CHARS + 1] = b'1';
    let bad_reserved = String::from_utf8_lossy(&bad_reserved);

    assert!(matches!(
        recovery_code_decode(&encoded[..=RECOVERY_CODE_DATA_CHARS]),
        Err(CryptoError::InvalidSecretValue)
    ));
    assert!(matches!(
        recovery_code_decode(&format!("{encoded}A")),
        Err(CryptoError::InvalidSecretValue)
    ));
    assert!(matches!(recovery_code_decode(&bad_check), Err(CryptoError::InvalidSecretValue)));
    assert!(matches!(recovery_code_decode(&bad_reserved), Err(CryptoError::InvalidSecretValue)));
}

#[test]
fn secret_fingerprint_is_keyed_and_stable() -> Result<(), CryptoError> {
    let first = secret_fingerprint_v1(&PROFILE_SECRET_KEY, "secret-value")?;
    let second = secret_fingerprint_v1(&PROFILE_SECRET_KEY, "secret-value")?;
    let other_key = secret_fingerprint_v1(&MASTER_KEY, "secret-value")?;

    assert_eq!(first, second);
    assert_ne!(first, other_key);
    Ok(())
}

#[test]
fn hkdf_wrap_info_with_profile_bytes_are_stable() -> Result<(), CryptoError> {
    let info = hkdf_wrap_info_v1(&HkdfWrapInfo::new(
        "lk_proj_123",
        Some("lk_prof_dev"),
        KeyPurpose::ProfileSecret,
    ))?;
    let expected = [
        b"locket-wrap-v1".as_slice(),
        &HKDF_WRAP_INFO_SCHEMA_V1.to_le_bytes(),
        &[10, 0],
        b"project_id",
        &[11, 0, 0, 0],
        b"lk_proj_123",
        &[10, 0],
        b"profile_id",
        &[11, 0, 0, 0],
        b"lk_prof_dev",
        &[7, 0],
        b"purpose",
        &[14, 0, 0, 0],
        b"profile-secret",
    ]
    .concat();

    assert_eq!(info, expected);
    Ok(())
}

#[test]
fn key_wrap_aad_encodes_missing_profile_as_empty_field() -> Result<(), CryptoError> {
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        "lk_proj_123",
        "lk_key_master",
        None,
        0,
        KeyWrapPurpose::ProjectMetadata,
    ))?;
    let expected = [
        b"locket-key-wrap-v1".as_slice(),
        &[10, 0],
        b"project_id",
        &[11, 0, 0, 0],
        b"lk_proj_123",
        &[6, 0],
        b"key_id",
        &[13, 0, 0, 0],
        b"lk_key_master",
        &[10, 0],
        b"profile_id",
        &[0, 0, 0, 0],
        &[0, 0, 0, 0],
        &[7, 0],
        b"purpose",
        &[16, 0, 0, 0],
        b"project-metadata",
        &KEY_WRAP_SCHEMA_V1.to_le_bytes(),
    ]
    .concat();

    assert_eq!(aad, expected);
    Ok(())
}

#[test]
fn recovery_entry_aad_bytes_are_stable() -> Result<(), CryptoError> {
    let aad = recovery_entry_aad_v1("lk_kdf_recovery_v1", "master_key", "lk_key_01")?;
    let expected = [
        b"locket-recovery-envelope-v1".as_slice(),
        &RECOVERY_ENVELOPE_SCHEMA_V1.to_le_bytes(),
        &[14, 0],
        b"kdf_profile_id",
        &[18, 0, 0, 0],
        b"lk_kdf_recovery_v1",
        &[10, 0],
        b"entry_kind",
        &[10, 0, 0, 0],
        b"master_key",
        &[8, 0],
        b"entry_id",
        &[9, 0, 0, 0],
        b"lk_key_01",
    ]
    .concat();

    assert_eq!(aad, expected);
    Ok(())
}

#[test]
fn recovery_entry_key_is_deterministic_and_domain_separated() -> Result<(), CryptoError> {
    let unwrap_root = [0x55_u8; KEY_LEN];

    let k1 = recovery_entry_key_v1(&unwrap_root, "master_key", "lk_key_01", "lk_kdf_v1")?;
    let k2 = recovery_entry_key_v1(&unwrap_root, "master_key", "lk_key_01", "lk_kdf_v1")?;
    let k_other_kind =
        recovery_entry_key_v1(&unwrap_root, "profile_key", "lk_key_01", "lk_kdf_v1")?;
    let k_other_id = recovery_entry_key_v1(&unwrap_root, "master_key", "lk_key_02", "lk_kdf_v1")?;

    assert_eq!(&*k1, &*k2);
    assert_ne!(&*k1, &*k_other_kind);
    assert_ne!(&*k1, &*k_other_id);
    Ok(())
}

#[test]
fn recovery_entry_seal_open_round_trips() -> Result<(), CryptoError> {
    let unwrap_root = [0x77_u8; KEY_LEN];
    let plaintext = b"secret-key-material";

    let (nonce, ciphertext) =
        seal_recovery_entry_v1(&unwrap_root, "lk_kdf_v1", "master_key", "lk_key_01", plaintext)?;
    let recovered = open_recovery_entry_v1(
        &unwrap_root,
        "lk_kdf_v1",
        "master_key",
        "lk_key_01",
        &nonce,
        &ciphertext,
    )?;

    assert_eq!(&*recovered, plaintext);
    Ok(())
}

#[test]
fn recovery_entry_open_fails_on_tampered_ciphertext() -> Result<(), CryptoError> {
    let unwrap_root = [0x77_u8; KEY_LEN];
    let plaintext = b"secret-key-material";

    let (nonce, mut ciphertext) =
        seal_recovery_entry_v1(&unwrap_root, "lk_kdf_v1", "master_key", "lk_key_01", plaintext)?;
    ciphertext[0] ^= 0xFF;

    let result = open_recovery_entry_v1(
        &unwrap_root,
        "lk_kdf_v1",
        "master_key",
        "lk_key_01",
        &nonce,
        &ciphertext,
    );

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn recovery_entry_open_fails_on_wrong_entry_id() -> Result<(), CryptoError> {
    let unwrap_root = [0x77_u8; KEY_LEN];

    let (nonce, ciphertext) =
        seal_recovery_entry_v1(&unwrap_root, "lk_kdf_v1", "master_key", "lk_key_01", b"payload")?;
    let result = open_recovery_entry_v1(
        &unwrap_root,
        "lk_kdf_v1",
        "master_key",
        "lk_key_02",
        &nonce,
        &ciphertext,
    );

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn canonical_field_rejects_oversized_field_value() {
    let value = "v".repeat(usize::try_from(u32::MAX).unwrap_or(usize::MAX).saturating_add(1));

    // On 64-bit platforms the value will exceed u32::MAX; on 32-bit platforms
    // saturating_add returns usize::MAX which also exceeds u32::MAX.
    if value.len() > usize::try_from(u32::MAX).unwrap_or(usize::MAX) {
        assert!(matches!(canonical_field("name", &value), Err(CryptoError::FieldValueTooLong)));
    }
    // The above is a no-op on 32-bit where the oversized string cannot be
    // allocated. The name-too-long path (covered elsewhere) exercises the same
    // error-code path for the v1 constraints.
}

#[test]
fn passkey_prf_wrap_aad_includes_domain_separation_and_project() -> Result<(), CryptoError> {
    let aad = passkey_prf_wrap_aad_v1("lk_proj_demo")?;
    let expected = [
        b"locket-passkey-prf-v1".as_slice(),
        &PASSKEY_PRF_WRAP_SCHEMA_V1.to_le_bytes(),
        &[10, 0],
        b"project_id",
        &[12, 0, 0, 0],
        b"lk_proj_demo",
    ]
    .concat();
    assert_eq!(aad, expected);
    Ok(())
}

#[test]
fn passkey_prf_wrap_round_trip_recovers_master_key() -> Result<(), CryptoError> {
    let master_key = [42_u8; KEY_LEN];
    let prf_output = [9_u8; 32];
    let wrapped = wrap_master_key_with_passkey_prf(&master_key, &prf_output, "lk_proj_demo")?;
    let recovered = unwrap_master_key_with_passkey_prf(&wrapped, &prf_output, "lk_proj_demo")?;
    assert_eq!(*recovered, master_key);
    Ok(())
}

#[test]
fn passkey_prf_unwrap_rejects_wrong_prf_output() -> Result<(), CryptoError> {
    let master_key = [42_u8; KEY_LEN];
    let wrapped = wrap_master_key_with_passkey_prf(&master_key, &[9_u8; 32], "lk_proj_demo")?;
    let result = unwrap_master_key_with_passkey_prf(&wrapped, &[10_u8; 32], "lk_proj_demo");
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn passkey_prf_unwrap_rejects_wrong_project_id() -> Result<(), CryptoError> {
    let master_key = [42_u8; KEY_LEN];
    let wrapped = wrap_master_key_with_passkey_prf(&master_key, &[9_u8; 32], "lk_proj_demo")?;
    let result = unwrap_master_key_with_passkey_prf(&wrapped, &[9_u8; 32], "lk_proj_other");
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    Ok(())
}

#[test]
fn passphrase_key_matches_argon2_0_5_fixture() -> Result<(), CryptoError> {
    // Generated with argon2 0.5.3, Argon2id v0x13, using synthetic inputs.
    // Reduced memory cost keeps this compatibility check inexpensive.
    let params = PassphraseKdfParams { m_cost: 32, t_cost: 2, p_cost: 4, output_len: 32 };
    let key = derive_passphrase_fallback_key_v1(
        b"synthetic legacy passphrase",
        b"locket-compat-v1-salt",
        params,
    )?;
    assert_eq!(
        *key,
        [
            147, 101, 133, 193, 187, 13, 164, 45, 195, 230, 163, 13, 1, 146, 233, 232, 250, 248,
            38, 130, 86, 135, 72, 81, 67, 221, 36, 192, 107, 166, 91, 248,
        ]
    );
    Ok(())
}

#[test]
fn recovery_key_matches_argon2_0_5_fixture() -> Result<(), CryptoError> {
    // Generated with argon2 0.5.3, Argon2id v0x13, using synthetic inputs.
    let params = super::RecoveryKdfParams { m_cost: 64, t_cost: 3, p_cost: 4, output_len: 32 };
    let key = super::derive_recovery_key_v1(
        &[19; RECOVERY_CODE_BYTES],
        b"locket-compat-v1-salt",
        params,
    )?;
    assert_eq!(
        *key,
        [
            202, 195, 207, 24, 142, 227, 144, 7, 97, 239, 11, 38, 10, 186, 206, 128, 193, 151, 197,
            42, 23, 39, 86, 111, 193, 20, 249, 35, 228, 254, 229, 142,
        ]
    );
    Ok(())
}

#[test]
fn xchacha20_poly1305_reads_0_10_ciphertext_and_wrapped_key() -> Result<(), CryptoError> {
    // Generated with chacha20poly1305 0.10.1. Fixed keys/nonces are test-only.
    let key = [7; KEY_LEN];
    let nonce = [11; NONCE_LEN];
    let aad = b"locket-compat-v1-aad";
    let ciphertext = [
        51, 191, 129, 92, 99, 73, 211, 187, 244, 110, 179, 83, 39, 105, 33, 5, 251, 88, 24, 165,
        141, 39, 41, 127, 62, 94, 237, 178, 44, 186, 201, 154, 206, 140, 252, 183, 94, 19, 233,
    ];
    let plaintext = b"synthetic legacy secret";
    assert_eq!(super::aead::aead_decrypt(&key, &nonce, &ciphertext, aad)?, plaintext);
    assert_eq!(super::aead::aead_encrypt(&key, &nonce, plaintext, aad)?, ciphertext);

    let wrapped = super::WrappedKeyMaterial {
        nonce,
        ciphertext: vec![
            83, 213, 252, 59, 24, 63, 180, 193, 132, 93, 204, 37, 83, 27, 81, 111, 200, 56, 110,
            213, 236, 81, 78, 192, 67, 0, 21, 253, 151, 179, 35, 81, 153, 87, 150, 126, 123, 201,
            202, 207, 97, 20, 182, 85, 184, 205, 200, 234,
        ],
    };
    assert_eq!(*unwrap_key_material_v1(&key, &wrapped, aad)?, [19; KEY_LEN]);
    assert!(matches!(
        unwrap_key_material_v1(&key, &wrapped, b"different aad"),
        Err(CryptoError::DecryptionFailed)
    ));
    Ok(())
}
