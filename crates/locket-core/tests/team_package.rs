//! Raw signature and external trust binding tests.
#![allow(unused_crate_dependencies)]
use ed25519_dalek::SigningKey;
use locket_core::team_package::{DeviceIdentity, SignedStatement, TeamMember, TeamStatement};

fn fixture() -> TeamStatement {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let device = DeviceIdentity::new("owner".into(), signer.verifying_key().to_bytes(), [8; 32]);
    TeamStatement {
        v: 1,
        team_id: "team".into(),
        project_id: "project".into(),
        epoch: 1,
        previous_digest: String::new(),
        issued_at: 100,
        expires_at: 200,
        nonce: [3; 24],
        publisher: device.clone(),
        recipient: device.clone(),
        members: vec![TeamMember {
            id: "member".into(),
            name: "owner".into(),
            role: "owner".into(),
            profiles: vec![],
            device,
            removed: false,
        }],
        profiles: vec![],
    }
}

#[test]
fn statement_signature_requires_external_pin_and_exact_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let statement = fixture();
    let key = SigningKey::from_bytes(&[7; 32]);
    let signed = SignedStatement::sign(&statement, &key)?;
    assert!(
        signed
            .verify(&statement.publisher.fingerprint, "project", &statement.recipient, 150)
            .is_ok()
    );
    assert!(signed.verify(&"a".repeat(64), "project", &statement.recipient, 150).is_err());
    let mut tampered = signed.clone();
    tampered.statement.push(b' ');
    assert!(
        tampered
            .verify(&statement.publisher.fingerprint, "project", &statement.recipient, 150)
            .is_err()
    );
    assert!(
        signed
            .verify(&statement.publisher.fingerprint, "other", &statement.recipient, 150)
            .is_err()
    );
    assert!(
        signed
            .verify(&statement.publisher.fingerprint, "project", &statement.recipient, 501)
            .is_err()
    );
    Ok(())
}

#[test]
fn forwarded_statement_and_self_declared_non_owner_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let mut statement = fixture();
    let key = SigningKey::from_bytes(&[7; 32]);
    let other = DeviceIdentity::new("other".into(), [9; 32], [10; 32]);
    let signed = SignedStatement::sign(&statement, &key)?;
    assert!(signed.verify(&statement.publisher.fingerprint, "project", &other, 150).is_err());
    statement.members[0].role = "maintainer".into();
    assert!(
        SignedStatement::sign(&statement, &key)?
            .verify(&statement.publisher.fingerprint, "project", &statement.recipient, 150)
            .is_err()
    );
    Ok(())
}

#[test]
fn established_updates_verify_after_join_expiry_without_changing_clock()
-> Result<(), Box<dyn std::error::Error>> {
    let statement = fixture();
    let signed = SignedStatement::sign(&statement, &SigningKey::from_bytes(&[7; 32]))?;
    assert!(
        signed
            .verify(&statement.publisher.fingerprint, "project", &statement.recipient, 1000)
            .is_err()
    );
    assert!(
        signed
            .verify_update(&statement.publisher.fingerprint, "project", &statement.recipient, 1000)
            .is_ok()
    );
    assert!(
        signed
            .verify_update(&statement.publisher.fingerprint, "project", &statement.recipient, -1000)
            .is_err()
    );
    Ok(())
}

#[test]
fn signed_team_statements_must_have_valid_membership_and_complete_profile_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut duplicate_member = fixture();
    duplicate_member.members.push(duplicate_member.members[0].clone());
    let mut missing_profile = fixture();
    missing_profile.members[0].profiles.push("production".into());

    for (statement, message) in
        [(duplicate_member, "invalid membership"), (missing_profile, "incomplete profile scope")]
    {
        let signed = SignedStatement::sign(&statement, &key)?;
        let result =
            signed.verify(&statement.publisher.fingerprint, "project", &statement.recipient, 150);
        assert!(matches!(result, Err(error) if error.0 == message));
    }
    Ok(())
}

#[test]
fn v2_team_container_rejects_an_inconsistent_declared_length() {
    let mut bytes = locket_core::BUNDLE_MAGIC.to_vec();
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&12_u64.to_le_bytes());
    bytes.push(0);

    assert!(matches!(
        SignedStatement::open(&bytes, &[0; 32]),
        Err(error) if error.0 == "incomplete container"
    ));
}

#[test]
fn sealed_team_package_binds_recipient_and_checks_snapshot_shape()
-> Result<(), Box<dyn std::error::Error>> {
    use age::secrecy::ExposeSecret as _;
    use locket_core::team_package::{TeamProfile, TeamSecret};

    let mut statement = fixture();
    let key = SigningKey::from_bytes(&[7; 32]);
    let identity = age::x25519::Identity::generate();
    let (_, recipient_bytes) = bech32::decode(&identity.to_public().to_string())?;
    let (_, secret_bytes) = bech32::decode(identity.to_string().expose_secret())?;
    let recipient_key: [u8; 32] =
        recipient_bytes.try_into().map_err(|_| "invalid fixture recipient")?;
    let secret_key: [u8; 32] = secret_bytes.try_into().map_err(|_| "invalid fixture identity")?;
    let device = DeviceIdentity::new("owner".into(), key.verifying_key().to_bytes(), recipient_key);
    statement.publisher = device.clone();
    statement.recipient = device.clone();
    statement.members[0].device = device;
    statement.members[0].profiles = vec!["dev".into()];
    statement.profiles = vec![TeamProfile {
        id: "dev".into(),
        name: "dev".into(),
        dangerous: false,
        created_at: 100,
        key_epoch: 1,
        secret_key: [0x11; 32],
        fingerprint_key: [0x22; 32],
        secrets: vec![TeamSecret {
            id: "secret".into(),
            name: "API_TOKEN".into(),
            version: 1,
            deleted: true,
            created_at: 110,
            blob: None,
        }],
    }];

    let signed = SignedStatement::sign(&statement, &key)?;
    let sealed = signed.seal(&recipient_key)?;
    let opened = SignedStatement::open(&sealed, &secret_key)?;
    let pin = &statement.publisher.fingerprint;
    let verified = opened.verify(pin, "project", &statement.recipient, 150)?;
    assert_eq!(verified.statement.profiles[0].secrets, statement.profiles[0].secrets);
    assert_eq!(verified.digest, locket_core::team_package::digest(&signed.statement));
    assert!(SignedStatement::open(&sealed, &[0x33; 32]).is_err());

    statement.profiles[0].secrets[0].version = 0;
    let invalid = SignedStatement::sign(&statement, &key)?;
    let result = invalid.verify(pin, "project", &statement.recipient, 150);
    assert!(matches!(result, Err(error) if error.0 == "invalid secret snapshot"));
    Ok(())
}

#[test]
fn verifier_rejects_oversized_statements_before_processing_signatures() {
    use locket_core::team_package::MAX_PACKAGE_BYTES;

    let statement = fixture();
    let oversized = SignedStatement {
        statement: vec![b' '; MAX_PACKAGE_BYTES + 1],
        signing_key: [0; 32],
        signature: String::new(),
    };
    assert!(matches!(
        oversized.verify(&statement.publisher.fingerprint, "project", &statement.recipient, 150),
        Err(error) if error.0 == "statement too large"
    ));
}

#[test]
fn a_valid_signature_does_not_make_an_unknown_statement_schema_valid() {
    use data_encoding::BASE64URL_NOPAD;
    use ed25519_dalek::Signer as _;

    let statement = fixture();
    let key = SigningKey::from_bytes(&[7; 32]);
    let malformed = br#"{"unknown_field":true}"#.to_vec();
    let signed_bytes = [b"locket-team-state-v1\0".as_slice(), &malformed].concat();
    let signed = SignedStatement {
        statement: malformed,
        signing_key: key.verifying_key().to_bytes(),
        signature: BASE64URL_NOPAD.encode(&key.sign(&signed_bytes).to_bytes()),
    };

    let result =
        signed.verify(&statement.publisher.fingerprint, "project", &statement.recipient, 150);
    assert!(matches!(result, Err(error) if error.0 == "invalid statement schema"));
}
