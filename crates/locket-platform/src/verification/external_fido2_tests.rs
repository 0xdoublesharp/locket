use super::*;

fn assert_auth_failed<T>(result: &Result<T, PlatformError>) {
    assert!(matches!(result, Err(PlatformError::PasskeyAuthFailed)));
}

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
    assert_auth_failed(&run(Path::new("/bin/sleep"), &["10"], &[], Duration::from_millis(50)));
    assert!(before.elapsed() < Duration::from_secs(3));
    assert_auth_failed(&run(Path::new("/usr/bin/yes"), &["output"], &[], Duration::from_secs(2)));
    assert_auth_failed(&run(
        Path::new("/bin/sh"),
        &["-c", "exec /usr/bin/yes output >&2"],
        &[],
        Duration::from_secs(2),
    ));
    let echo = run(Path::new("/bin/cat"), &[] as &[&str], b"bounded input", PROBE_TIMEOUT)?;
    assert_eq!(&*echo.stdout, b"bounded input");
    assert!(echo.stderr.is_empty());
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn timeout_restores_hidden_input_in_a_private_terminal() -> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "LOCKET_FIDO2_PRIVATE_PTY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // macOS script allocates a new foreground PTY for all child I/O.
        let output = Command::new("/usr/bin/script")
            .args(["-q", "/dev/null"])
            .arg(std::env::current_exe()?)
            .args(["timeout_restores_hidden_input_in_a_private_terminal", "--nocapture"])
            .env(CHILD, "1")
            .output()?;
        let transcript = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{transcript}");
        assert!(transcript.contains("1 passed"), "{transcript}");
        assert!(transcript.contains("enter your security key PIN"), "{transcript}");
        return Ok(());
    }

    let mut terminal = terminal()?;
    let original = tcgetattr(&terminal.file)?;
    terminal.prompt()?;
    let mut hidden = original.clone();
    hidden.local_modes.remove(LocalModes::ECHO);
    tcsetattr(&terminal.file, OptionalActions::Now, &hidden)?;
    assert_auth_failed(&run(Path::new("/bin/sleep"), &["10"], &[], Duration::from_millis(50)));
    assert!(!tcgetattr(&terminal.file)?.local_modes.contains(LocalModes::ECHO));
    let tty = terminal.file.try_clone()?;
    drop(terminal);
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

const RP: &str = "locket.localhost";
const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n";

const fn usb_path() -> &'static str {
    if cfg!(target_os = "macos") { "ioreg://123" } else { "/dev/hidraw3" }
}

fn script(directory: &Path, name: &str, body: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = directory.join(name);
    std::fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

fn fake_tools(directory: &Path) -> Result<Tools, PlatformError> {
    // Temp roots may be world-writable. Only the fixture resolver bypasses
    // host installation policy, which is exercised separately below.
    Tools::in_directory(directory, |path| Ok(path.to_owned()))
}

#[test]
fn fake_helpers_round_trip_enrollment_and_assertion_protocol()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path();
    let device = usb_path();
    let id = BASE64.encode(&[3; 32]);
    let prf = BASE64.encode(&[9; 32]);
    let salt = [7; 32];
    let ctap_salt = BASE64.encode(&prf_salt(&salt));
    script(
        path,
        "fido2-token",
        &format!(
            r#"
        test "$LC_ALL" = C && test "$PATH" = /usr/bin:/bin
        case "$*" in
          -V) printf '1.17.0\n' >&2 ;;
          -L) printf '%s: vendor=0x1050\n' '{device}' ;;
          '-I -- {device}') printf 'extension strings: credProtect, hmac-secret\noptions: rk, clientPin\n' ;;
          *) exit 1 ;;
        esac
    "#
        ),
    )?;
    script(
        path,
        "fido2-cred",
        &format!(
            r#"
        case "$*" in
          '-M -h -t pin=true -- {device} es256')
            IFS= read -r challenge && IFS= read -r rp && IFS= read -r name && IFS= read -r user || exit 2
            test "$rp" = '{RP}' && test "$name" = Locket && test "${{#challenge}}" = 44 && test "${{#user}}" = 44 || exit 3
            if IFS= read -r extra; then exit 4; fi
            printf '%s\n%s\npacked\nauthdata\n%s\nsignature\n' "$challenge" "$rp" '{id}'
            ;;
          '-V -h -v es256')
            IFS= read -r challenge && IFS= read -r rp && IFS= read -r kind && IFS= read -r authdata && IFS= read -r credential && IFS= read -r signature || exit 2
            test "$rp" = '{RP}' && test "$kind" = packed && test "$authdata" = authdata && test "$credential" = '{id}' && test "$signature" = signature || exit 3
            if IFS= read -r extra; then exit 4; fi
            printf '%s\n%s' '{id}' '{PUBLIC_KEY}'
            ;;
          *) exit 1 ;;
        esac
    "#
        ),
    )?;
    script(
        path,
        "fido2-assert",
        &format!(
            r#"
        test "$#" = 6
        IFS= read -r challenge && IFS= read -r rp && IFS= read -r third && IFS= read -r fourth || exit 2
        test "$rp" = '{RP}' && test "${{#challenge}}" = 44 || exit 3
        if IFS= read -r extra; then exit 4; fi
        case "$1 $2 $3 $4" in
          '-G -h -p -v')
            test "$5" = -- && test "$6" = '{device}' && test "$third" = '{id}' && test "$fourth" = '{ctap_salt}' || exit 5
            printf '%s\n%s\nauthdata\nsignature\n%s\n' "$challenge" "$rp" '{prf}'
            ;;
          '-V -h -p -v')
            test "$6" = es256 && test "$third" = authdata && test "$fourth" = signature || exit 6
            printf '%s' '{PUBLIC_KEY}' | cmp -s - "$5" || exit 7
            printf '%s' "$5" > verified-key-path
            ;;
          *) exit 1 ;;
        esac
    "#
        ),
    )?;

    let tools = fake_tools(path)?;
    let prompts = std::cell::Cell::new(0);
    let prompt = || {
        prompts.set(prompts.get() + 1);
        Ok(())
    };
    let registration = register_with_tools(&tools, RP, prompt)?;
    assert_eq!(registration.credential_id, [3; 32]);
    assert_eq!(registration.public_key, PUBLIC_KEY.as_bytes());
    assert_eq!(registration.user_handle.len(), 32);
    assert_eq!(registration.transports, ["usb"]);
    assert!(registration.prf_capable);
    let credential = PasskeyAssertionContext {
        credential_id: &registration.credential_id,
        relying_party_id: RP,
        public_key: &registration.public_key,
    };
    assert_eq!(*evaluate_with_tools(&tools, credential, &salt, prompt)?, [9; 32]);
    assert_eq!(prompts.get(), 2);
    let verified_key_path = std::fs::read_to_string(path.join("verified-key-path"))?;
    assert!(!Path::new(&verified_key_path).exists());
    Ok(())
}

#[test]
fn fake_discovery_rejects_mixed_helpers_bad_versions_and_missing_device_options()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path();
    let device = usb_path();
    script(path, "fido2-token", "printf '1.16.0\n' >&2")?;
    assert!(matches!(fake_tools(path), Err(PlatformError::PasskeyUnsupported)));
    script(path, "fido2-token", "printf '1.17.0\n'")?;
    assert!(matches!(fake_tools(path), Err(PlatformError::PasskeyUnsupported)));
    script(path, "fido2-token", "exit 1")?;
    assert!(matches!(fake_tools(path), Err(PlatformError::PasskeyAuthFailed)));

    assert!(matches!(
        Tools::in_directory(path, |candidate| {
            if candidate.ends_with("fido2-assert") {
                Ok(path.join("other/fido2-assert"))
            } else {
                Ok(candidate.to_owned())
            }
        }),
        Err(PlatformError::PasskeyUnsupported)
    ));

    for info in [
        r"extension strings: hmac-secret\noptions: noclientPin\n",
        r"extension strings: hmac-secret-mc\noptions: clientPin\n",
        r"\377\n",
    ] {
        script(
            path,
            "fido2-token",
            &format!(
                r#"
            case "$*" in
              -V) printf '1.17.0\n' >&2 ;;
              -L) printf '%s: vendor=0x1050\n' '{device}' ;;
              '-I -- {device}') printf '{info}' ;;
              *) exit 1 ;;
            esac
        "#
            ),
        )?;
        assert!(matches!(fake_tools(path)?.device(), Err(PlatformError::PasskeyAuthFailed)));
    }
    Ok(())
}

#[test]
fn enrollment_and_assertion_reject_invalid_helper_transcripts()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path();
    let tools = Tools {
        token: path.join("fido2-token"),
        cred: path.join("fido2-cred"),
        assert: path.join("fido2-assert"),
    };
    let challenge = [2; 32];
    let challenge_line = BASE64.encode(&challenge);
    let id = BASE64.encode(&[3; 32]);
    let valid = format!("{challenge_line}\n{RP}\npacked\nauthdata\n{id}\nsignature\n");
    for stdout in [
        "no-line-break".to_owned(),
        format!("different-id\n{PUBLIC_KEY}"),
        format!("{id}\nwrong-key-format\n"),
        format!("{id}\n-----BEGIN PUBLIC KEY-----\nno-end-marker\n"),
        format!(
            "{id}\n-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            "x".repeat(4096)
        ),
    ] {
        script(path, "fido2-cred", &format!("cat >/dev/null\nprintf '%s' '{stdout}'"))?;
        assert!(matches!(
            verify_registration(&tools, valid.as_bytes(), &challenge, RP, [4; 32]),
            Err(PlatformError::PasskeyAuthFailed)
        ));
    }

    for unusable_id in ["?".to_owned(), String::new(), BASE64.encode(&[0; 1025])] {
        let registration =
            format!("{challenge_line}\n{RP}\npacked\nauthdata\n{unusable_id}\nsignature\n");
        script(
            path,
            "fido2-cred",
            &format!("cat >/dev/null\nprintf '%s\\n%s' '{unusable_id}' '{PUBLIC_KEY}'"),
        )?;
        assert!(matches!(
            verify_registration(&tools, registration.as_bytes(), &challenge, RP, [4; 32]),
            Err(PlatformError::PasskeyAuthFailed)
        ));
    }
    assert_auth_failed(&verify_registration(&tools, b"too\nshort\n", &challenge, RP, [4; 32]));
    assert_auth_failed(&verify_registration(&tools, valid.as_bytes(), &[0; 32], RP, [4; 32]));

    let assertion =
        format!("{challenge_line}\n{RP}\nauthdata\nsignature\n{}\n", BASE64.encode(&[9; 32]));
    let credential = PasskeyAssertionContext {
        credential_id: &[3; 32],
        relying_party_id: RP,
        public_key: PUBLIC_KEY.as_bytes(),
    };
    script(path, "fido2-assert", "cat >/dev/null\nexit 1")?;
    assert!(matches!(
        verify_assertion(&tools, assertion.as_bytes(), credential, &challenge),
        Err(PlatformError::PasskeyAuthFailed)
    ));
    assert_auth_failed(&verify_assertion(&tools, b"too\nshort\n", credential, &challenge));
    script(path, "fido2-assert", "cat >/dev/null")?;
    let malformed_prf = format!("{challenge_line}\n{RP}\nauthdata\nsignature\ninvalid\n");
    assert_auth_failed(&verify_assertion(&tools, malformed_prf.as_bytes(), credential, &challenge));
    Ok(())
}

#[test]
fn malformed_inputs_fail_before_a_terminal_or_helper_is_needed() {
    assert!(matches!(register("test", "bad RP"), Err(PlatformError::PasskeyAuthFailed)));
    let valid = PasskeyAssertionContext {
        credential_id: &[3; 32],
        relying_party_id: RP,
        public_key: PUBLIC_KEY.as_bytes(),
    };
    for (credential, salt) in [
        (PasskeyAssertionContext { credential_id: &[], ..valid }, &[0; 32][..]),
        (PasskeyAssertionContext { credential_id: &[0; 1025], ..valid }, &[0; 32][..]),
        (PasskeyAssertionContext { public_key: &[0; 4097], ..valid }, &[0; 32][..]),
        (PasskeyAssertionContext { relying_party_id: "-invalid", ..valid }, &[0; 32][..]),
        (valid, &[0; 31][..]),
    ] {
        assert!(matches!(evaluate(credential, salt), Err(PlatformError::PasskeyAuthFailed)));
    }
    assert!(!supported_version(b"\xff\n"));
    for malformed in [b"\xff".as_slice(), b"not a listing", b"ioreg://a\t: vendor=0\n"] {
        assert_auth_failed(&single_device(malformed));
    }
    assert_auth_failed(&single_device(format!("{}: vendor=0\n", "x".repeat(4097)).as_bytes()));
    assert_auth_failed(&transcript_lines(b"\xff\n"));
    assert_auth_failed(&transcript_lines(&vec![b'\n'; MAX_OUTPUT + 1]));
    assert_auth_failed(&verify_binding(&[], &[0; 32], RP));
}

#[test]
fn runner_rejects_oversize_input_and_exactly_bounds_output() -> Result<(), PlatformError> {
    let exact = vec![0xa5; MAX_OUTPUT];
    let output = run(Path::new("/bin/cat"), &[] as &[&str], &exact, PROBE_TIMEOUT)?;
    assert_eq!(*output.stdout, exact);
    assert_auth_failed(&run(
        Path::new("/bin/cat"),
        &[] as &[&str],
        &vec![0; MAX_OUTPUT + 1],
        PROBE_TIMEOUT,
    ));
    let directory = tempfile::tempdir()?;
    let missing = directory.path().join("absent-helper");
    assert_auth_failed(&run(&missing, &["-V"], &[], PROBE_TIMEOUT));
    assert!(trusted_executable(Path::new("/bin/sh")).is_ok());
    assert!(matches!(trusted_executable(Path::new("/")), Err(PlatformError::PasskeyUnsupported)));
    Ok(())
}

#[test]
fn discovery_falls_back_to_the_first_compatible_installation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let old = directory.path().join("old");
    let current = directory.path().join("current");
    std::fs::create_dir(&old)?;
    std::fs::create_dir(&current)?;
    script(&old, "fido2-token", "printf '1.16.0\n' >&2")?;
    script(&current, "fido2-token", "printf '1.17.0\n' >&2")?;

    let resolve = |path: &Path| Ok(path.to_path_buf());
    assert!(matches!(
        Tools::discover_in([old.as_path()], resolve),
        Err(PlatformError::PasskeyUnsupported)
    ));
    let tools = Tools::discover_in([old.as_path(), current.as_path()], resolve)?;
    assert_eq!(tools.token, current.join("fido2-token"));
    assert_eq!(tools.cred, current.join("fido2-cred"));
    assert_eq!(tools.assert, current.join("fido2-assert"));
    Ok(())
}
