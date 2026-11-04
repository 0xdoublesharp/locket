use super::*;

#[test]
fn version_protocol_requires_supported_stable_tools() {
    for good in [b"1.17.0\n".as_slice(), b"1.18.1\n"] {
        assert!(supported_version(good));
    }
    for bad in ["1.16.0\n", "2.0.0\n", "1.17.0", "1.17.0-beta\n", "1.17.0\nextra", "1.17.x\n"] {
        assert!(!supported_version(bad.as_bytes()), "{bad}");
    }
}

#[test]
fn protocol_rejects_unbound_or_malformed_fields() {
    for rp in ["", "a\nb", "a\0b", "https://example.com", "-a", "a..b", "a-", "a b"] {
        assert!(validate_rp(rp).is_err());
    }
    assert!(validate_rp("locket.localhost").is_ok());
    assert!(transcript_lines(b"one\r\ntwo\n").is_err());
    assert!(transcript_lines(b"one\ntwo").is_err());
    assert!(verify_binding(&["wrong", "locket.localhost"], &[1; 32], "locket.localhost").is_err());
    assert!(
        verify_binding(&[&BASE64.encode(&[1; 32]), "evil.localhost"], &[1; 32], "locket.localhost")
            .is_err()
    );
    assert!(!has_option("options: noclientPin\n", "options: ", "clientPin"));
    assert!(!has_option(
        "extension strings: hmac-secret-mc\n",
        "extension strings: ",
        "hmac-secret"
    ));
    assert!(single_device(b"").is_err());
    assert!(single_device(b"-evil: vendor=0x0000\n").is_err());
    let path = if cfg!(target_os = "macos") { "ioreg://123" } else { "/dev/hidraw0" };
    let listing = format!("{path}: vendor=0x1050, product=0x0407 (Yubico Security Key)\n");
    assert_eq!(single_device(listing.as_bytes()).ok().as_deref(), Some(path));
    assert!(single_device(format!("{listing}{listing}").as_bytes()).is_err());
}

#[test]
fn prf_uses_webauthn_domain_and_exact_secret_length() -> Result<(), PlatformError> {
    let salt = [7; 32];
    let expected: [u8; 32] = Sha256::digest([b"WebAuthn PRF\0".as_slice(), &salt].concat()).into();
    assert_eq!(prf_salt(&salt), expected);
    assert_ne!(prf_salt(&salt), salt);
    for size in [0, 1, 31, 33, 64] {
        assert!(decode_prf(&BASE64.encode(&vec![8; size])).is_err());
    }
    assert!(decode_prf(&"!".repeat(44)).is_err());
    assert_eq!(*decode_prf(&BASE64.encode(&[8; 32]))?, [8; 32]);
    Ok(())
}

#[test]
fn subprocess_reaps_timeouts_and_bounds_both_output_streams() -> Result<(), PlatformError> {
    let before = Instant::now();
    assert!(run(Path::new("/bin/sleep"), &["10"], &[], Duration::from_millis(50)).is_err());
    assert!(before.elapsed() < Duration::from_secs(3));
    assert!(run(Path::new("/usr/bin/yes"), &["output"], &[], Duration::from_secs(2)).is_err());
    assert!(
        run(
            Path::new("/bin/sh"),
            &["-c", "exec /usr/bin/yes output >&2"],
            &[],
            Duration::from_secs(2)
        )
        .is_err()
    );
    let echo = run(Path::new("/bin/cat"), &[] as &[&str], b"bounded input", PROBE_TIMEOUT)?;
    assert_eq!(&*echo.stdout, b"bounded input");
    assert!(echo.stderr.is_empty());
    Ok(())
}

#[test]
#[ignore = "requires a controlling terminal; does not access hardware"]
fn timeout_restores_hidden_input_terminal_settings() -> Result<(), Box<dyn std::error::Error>> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let original = tcgetattr(&tty)?;
    {
        let _guard = terminal()?;
        assert!(
            run(
                Path::new("/bin/sh"),
                &["-c", "stty -echo < /dev/tty; exec sleep 10"],
                &[],
                Duration::from_millis(150)
            )
            .is_err()
        );
        assert!(!tcgetattr(&tty)?.local_modes.contains(rustix::termios::LocalModes::ECHO));
    }
    assert_eq!(tcgetattr(&tty)?.local_modes, original.local_modes);
    Ok(())
}

// These fixtures are freshly signed using a throwaway software test key. They
// exercise the actual installed libfido2 verifiers, never authenticator I/O.
// They do not validate hardware PIN prompts or hmac-secret derivation.
#[test]
#[ignore = "requires installed libfido2 1.17+ tools and /usr/bin/openssl; no hardware access"]
fn installed_libfido2_verifies_signed_fixtures_and_rejects_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    let tools = Tools::discover()?;
    let fixture = Fixture::new()?;
    let challenge = [2; 32];
    let rp = "locket.localhost";
    let id = [3; 32];
    let registration = fixture.registration(rp, &challenge, &id, 0xc5)?;
    let enrolled = verify_registration(&tools, registration.as_bytes(), &challenge, rp, [4; 32])?;
    assert_eq!(enrolled.credential_id, id);
    assert!(enrolled.prf_capable);
    let context = PasskeyAssertionContext {
        credential_id: &id,
        relying_party_id: rp,
        public_key: &enrolled.public_key,
    };
    let assertion = fixture.assertion(rp, &challenge, 0x85, true)?;
    assert_eq!(*verify_assertion(&tools, assertion.as_bytes(), context, &challenge)?, [9; 32]);

    // Independently signed fixtures remove UP, UV, or the requested extension.
    for flags in [0x84, 0x81] {
        let bad = fixture.assertion(rp, &challenge, flags, true)?;
        assert!(verify_assertion(&tools, bad.as_bytes(), context, &challenge).is_err());
    }
    let bad = fixture.assertion(rp, &challenge, 0x05, false)?;
    assert!(verify_assertion(&tools, bad.as_bytes(), context, &challenge).is_err());
    for flags in [0xc4, 0xc1] {
        let bad = fixture.registration(rp, &challenge, &id, flags)?;
        assert!(verify_registration(&tools, bad.as_bytes(), &challenge, rp, [4; 32]).is_err());
    }
    assert!(verify_assertion(&tools, assertion.as_bytes(), context, &[8; 32]).is_err());
    assert!(
        verify_assertion(
            &tools,
            assertion.as_bytes(),
            PasskeyAssertionContext { relying_party_id: "other.localhost", ..context },
            &challenge
        )
        .is_err()
    );
    let changed_challenge =
        assertion.replacen(&BASE64.encode(&challenge), &BASE64.encode(&[8; 32]), 1);
    assert!(verify_assertion(&tools, changed_challenge.as_bytes(), context, &[8; 32]).is_err());
    let changed_rp = assertion.replacen(rp, "other.localhost", 1);
    assert!(
        verify_assertion(
            &tools,
            changed_rp.as_bytes(),
            PasskeyAssertionContext { relying_party_id: "other.localhost", ..context },
            &challenge
        )
        .is_err()
    );
    let changed_id = registration.replacen(&BASE64.encode(&id), &BASE64.encode(&[8; 32]), 1);
    assert!(verify_registration(&tools, changed_id.as_bytes(), &challenge, rp, [4; 32]).is_err());
    let other = Fixture::new()?;
    let wrong_key = other.public_pem()?;
    assert!(
        verify_assertion(
            &tools,
            assertion.as_bytes(),
            PasskeyAssertionContext { public_key: &wrong_key, ..context },
            &challenge
        )
        .is_err()
    );
    // Valid signature but malformed PRF must fail without panicking or exposing it.
    let bad_prf = assertion.replace(&BASE64.encode(&[9; 32]), &BASE64.encode(&[9; 33]));
    assert!(verify_assertion(&tools, bad_prf.as_bytes(), context, &challenge).is_err());
    Ok(())
}

struct Fixture {
    key: tempfile::NamedTempFile,
    point: Vec<u8>,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let private = run(
            Path::new("/usr/bin/openssl"),
            &["ecparam", "-name", "prime256v1", "-genkey", "-noout"],
            &[],
            VERIFY_TIMEOUT,
        )?;
        let mut key = tempfile::NamedTempFile::new()?;
        key.write_all(&private.stdout)?;
        let der = run(
            Path::new("/usr/bin/openssl"),
            &["pkey", "-pubout", "-outform", "DER"],
            &private.stdout,
            VERIFY_TIMEOUT,
        )?;
        assert_eq!(der.stdout.len(), 91);
        assert_eq!(der.stdout[26], 4);
        Ok(Self { key, point: der.stdout[27..].to_vec() })
    }

    fn public_pem(&self) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
        let output = run(
            Path::new("/usr/bin/openssl"),
            &[
                OsStr::new("pkey"),
                OsStr::new("-pubout"),
                OsStr::new("-in"),
                self.key.path().as_os_str(),
            ],
            &[],
            VERIFY_TIMEOUT,
        )?;
        Ok(output.stdout)
    }

    fn sign(&self, raw: &[u8], challenge: &[u8; 32]) -> Result<String, PlatformError> {
        let message = [raw, challenge].concat();
        let output = run(
            Path::new("/usr/bin/openssl"),
            &[
                OsStr::new("dgst"),
                OsStr::new("-sha256"),
                OsStr::new("-sign"),
                self.key.path().as_os_str(),
            ],
            &message,
            VERIFY_TIMEOUT,
        )?;
        Ok(BASE64.encode(&output.stdout))
    }

    fn registration(
        &self,
        rp: &str,
        challenge: &[u8; 32],
        id: &[u8; 32],
        flags: u8,
    ) -> Result<String, PlatformError> {
        let mut raw = Sha256::digest(rp.as_bytes()).to_vec();
        raw.push(flags);
        raw.extend_from_slice(&[0; 20]); // counter and AAGUID
        raw.extend_from_slice(&[0, 32]);
        raw.extend_from_slice(id);
        raw.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        raw.extend_from_slice(&self.point[..32]);
        raw.extend_from_slice(&[0x22, 0x58, 0x20]);
        raw.extend_from_slice(&self.point[32..]);
        raw.extend_from_slice(b"\xa1\x6bhmac-secret\xf5");
        Ok(format!(
            "{}\n{rp}\npacked\n{}\n{}\n{}\n",
            BASE64.encode(challenge),
            encode_authdata(&raw),
            BASE64.encode(id),
            self.sign(&raw, challenge)?
        ))
    }

    fn assertion(
        &self,
        rp: &str,
        challenge: &[u8; 32],
        flags: u8,
        extension: bool,
    ) -> Result<String, PlatformError> {
        let mut raw = Sha256::digest(rp.as_bytes()).to_vec();
        raw.push(flags);
        raw.extend_from_slice(&[0; 4]);
        if extension {
            raw.extend_from_slice(b"\xa1\x6bhmac-secret\x58\x20");
            raw.extend_from_slice(&[0; 32]);
        }
        Ok(format!(
            "{}\n{rp}\n{}\n{}\n{}\n",
            BASE64.encode(challenge),
            encode_authdata(&raw),
            self.sign(&raw, challenge)?,
            BASE64.encode(&[9; 32])
        ))
    }
}

fn encode_authdata(raw: &[u8]) -> String {
    let length = u16::try_from(raw.len()).unwrap_or_default();
    let [high, low] = length.to_be_bytes();
    let prefix = if high == 0 { vec![0x58, low] } else { vec![0x59, high, low] };
    BASE64.encode(&[prefix.as_slice(), raw].concat())
}
