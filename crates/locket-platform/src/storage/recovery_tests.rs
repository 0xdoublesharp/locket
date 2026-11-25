use super::*;

fn assert_invalid<T>(result: Result<T, PlatformError>, expected: &str) {
    assert!(matches!(
        result,
        Err(PlatformError::InvalidRecoveryEnvelope(message)) if message == expected
    ));
}

#[test]
fn recovery_metadata_rejects_unsupported_profiles_before_derivation() {
    let valid =
        RecoveryKdfToml::new_v1("kdf_test".into(), &[7; locket_crypto::RECOVERY_SALT_LEN], 19);
    assert!(valid.validate().is_ok());
    let params = valid.to_crypto_params();
    assert_eq!(params.m_cost, locket_crypto::RECOVERY_M_COST);
    assert_eq!(params.t_cost, locket_crypto::RECOVERY_T_COST);
    assert_eq!(params.p_cost, locket_crypto::RECOVERY_P_COST);
    assert_eq!(params.output_len as usize, locket_crypto::KEY_LEN);

    for (metadata, expected) in [
        (RecoveryKdfToml { version: 2, ..valid.clone() }, "unsupported kdf metadata version"),
        (
            RecoveryKdfToml { algorithm: "argon2i".into(), ..valid.clone() },
            "unsupported kdf algorithm",
        ),
        (
            RecoveryKdfToml { kdf_profile_id: "../other".into(), ..valid.clone() },
            "invalid kdf profile id",
        ),
        (
            RecoveryKdfToml { salt: "not base64".into(), ..valid.clone() },
            "invalid kdf salt encoding",
        ),
        (RecoveryKdfToml { salt: "AA".into(), ..valid.clone() }, "invalid kdf salt length"),
        (RecoveryKdfToml { output_len: 16, ..valid }, "unsupported kdf parameters"),
    ] {
        assert_invalid(metadata.validate(), expected);
    }
}

fn container(metadata: &[u8], envelope: &[u8]) -> Result<Vec<u8>, std::num::TryFromIntError> {
    Ok([RECOVERY_STATE_MAGIC, &u32::try_from(metadata.len())?.to_le_bytes(), metadata, envelope]
        .concat())
}

#[test]
fn recovery_container_rejects_corruption_and_profile_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let kdf =
        RecoveryKdfToml::new_v1("kdf_test".into(), &[0; locket_crypto::RECOVERY_SALT_LEN], 19);
    let metadata = toml::to_string(&kdf)?;
    let envelope = RecoveryEnvelope {
        kdf_profile_id: "kdf_test".into(),
        created_at_unix_nanos: 19,
        entries: vec![],
    };
    let canonical = envelope.serialize()?;
    let valid = container(metadata.as_bytes(), &canonical)?;
    assert!(decode_recovery_state(&valid).is_ok());

    assert_invalid(decode_recovery_state(&valid[1..]), "not a recovery container");
    assert_invalid(decode_recovery_state(RECOVERY_STATE_MAGIC), "truncated");
    assert_invalid(
        decode_recovery_state(&container(&vec![0; 16 * 1024 + 1], &[])?),
        "kdf metadata too large",
    );
    assert_invalid(decode_recovery_state(&container(b"\xff", &canonical)?), "invalid kdf text");
    assert_invalid(
        decode_recovery_state(&container(b"invalid x", &canonical)?),
        "invalid kdf metadata",
    );

    let mut corrupt = canonical.clone();
    corrupt[0] ^= 1;
    assert_invalid(RecoveryEnvelope::deserialize(&corrupt), "bad magic bytes");
    let mut corrupt = canonical.clone();
    corrupt[16..18].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(matches!(
        RecoveryEnvelope::deserialize(&corrupt),
        Err(PlatformError::RecoveryEnvelopeSchemaUnsupported(u16::MAX))
    ));

    let mut corrupt = canonical;
    let first_value = 16 + 2 + 2 + "kdf_profile_id".len() + 4;
    corrupt[first_value] = 0xff;
    assert_invalid(RecoveryEnvelope::deserialize(&corrupt), "non-utf8 field value");

    let mismatched_id = RecoveryEnvelope { kdf_profile_id: "different".into(), ..envelope };
    let mismatched = container(metadata.as_bytes(), &mismatched_id.serialize()?)?;
    assert_invalid(decode_recovery_state(&mismatched), "kdf profile mismatch");
    Ok(())
}
