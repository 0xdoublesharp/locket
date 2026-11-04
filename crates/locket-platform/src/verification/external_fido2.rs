//! Terminal-only external USB FIDO2 integration with libfido2 1.17 tools.
//!
//! Protocol: Yubico/libfido2 1.17.0 credential, assertion, and token tools.
//! Cryptography and CTAP PIN exchange stay in libfido2.
//! The helper installation and host administrators are trusted. Attestation
//! signatures are checked, but manufacturer certificate trust is not asserted.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use data_encoding::BASE64;
use rustix::termios::{
    LocalModes, OptionalActions, QueueSelector, Termios, tcflush, tcgetattr, tcgetpgrp, tcsetattr,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::passkey::{PasskeyAssertionContext, PasskeyRegistration};
use crate::PlatformError;

const MAX_OUTPUT: usize = 64 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);
const CEREMONY_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) fn available() -> bool {
    terminal().is_ok() && Tools::discover().is_ok()
}

pub(super) fn register(
    _label: &str,
    relying_party_id: &str,
) -> Result<PasskeyRegistration, PlatformError> {
    validate_rp(relying_party_id)?;
    let mut terminal = terminal()?;
    let tools = Tools::discover()?;
    let device = tools.device()?;
    let challenge = random_bytes()?;
    let user_handle = random_bytes()?;
    let input = format!(
        "{}\n{relying_party_id}\nLocket\n{}\n",
        BASE64.encode(&challenge),
        BASE64.encode(&user_handle),
    );
    // pin=true (1.17+) requests PIN verification directly. -v here would
    // require built-in biometric UV and exclude ordinary PIN-only keys.
    terminal.prompt()?;
    let result = run(
        &tools.cred,
        &["-M", "-h", "-t", "pin=true", "--", &device, "es256"],
        input.as_bytes(),
        CEREMONY_TIMEOUT,
    )?;
    verify_registration(&tools, &result.stdout, &challenge, relying_party_id, user_handle)
}

pub(super) fn evaluate(
    credential: PasskeyAssertionContext<'_>,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
    validate_rp(credential.relying_party_id)?;
    if credential.credential_id.is_empty()
        || credential.credential_id.len() > 1024
        || credential.public_key.len() > 4096
        || salt.len() != 32
    {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    let mut terminal = terminal()?;
    let tools = Tools::discover()?;
    let device = tools.device()?;
    let challenge = random_bytes()?;
    // WebAuthn PRF maps its input to CTAP hmac-secret with this domain
    // separation. Stored salts are PRF inputs, never raw CTAP salts.
    let ctap_salt = prf_salt(salt);
    let input = format!(
        "{}\n{}\n{}\n{}\n",
        BASE64.encode(&challenge),
        credential.relying_party_id,
        BASE64.encode(credential.credential_id),
        BASE64.encode(&ctap_salt),
    );
    terminal.prompt()?;
    let result = run(
        &tools.assert,
        &["-G", "-h", "-p", "-v", "--", &device],
        input.as_bytes(),
        CEREMONY_TIMEOUT,
    )?;
    verify_assertion(&tools, &result.stdout, credential, &challenge)
}

fn prf_salt(input: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"WebAuthn PRF\0");
    hash.update(input);
    hash.finalize().into()
}

fn random_bytes() -> Result<[u8; 32], PlatformError> {
    locket_crypto::generate_passphrase_salt().map_err(|_| PlatformError::PasskeyAuthFailed)
}

fn validate_rp(rp: &str) -> Result<(), PlatformError> {
    if rp.is_empty()
        || rp.len() > 253
        || !rp.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    Ok(())
}

struct Terminal {
    file: File,
    settings: Termios,
}

impl Terminal {
    fn prompt(&mut self) -> Result<(), PlatformError> {
        self.file
            .write_all(b"Locket: enter your security key PIN when prompted, then touch the key.\n")
            .map_err(|_| PlatformError::PasskeyAuthFailed)
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // Also restores hidden PIN input if a timed-out helper was killed.
        // Discard an unfinished PIN still in the terminal's input queue before
        // returning control to a shell with echo enabled.
        if tcgetattr(&self.file)
            .is_ok_and(|current| !current.local_modes.contains(LocalModes::ECHO))
        {
            let _ = tcflush(&self.file, QueueSelector::IFlush);
        }
        let _ = tcsetattr(&self.file, OptionalActions::Now, &self.settings);
    }
}

fn terminal() -> Result<Terminal, PlatformError> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(PlatformError::PasskeyUnsupported);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| PlatformError::PasskeyUnsupported)?;
    if !file.is_terminal() || tcgetpgrp(&file).ok() != Some(rustix::process::getpgrp()) {
        return Err(PlatformError::PasskeyUnsupported);
    }
    let settings = tcgetattr(&file).map_err(|_| PlatformError::PasskeyUnsupported)?;
    Ok(Terminal { file, settings })
}

struct Tools {
    token: PathBuf,
    cred: PathBuf,
    assert: PathBuf,
}

impl Tools {
    fn discover() -> Result<Self, PlatformError> {
        for directory in ["/usr/bin", "/opt/homebrew/bin", "/usr/local/bin"] {
            if let Ok(tools) = Self::in_directory(Path::new(directory)) {
                return Ok(tools);
            }
        }
        Err(PlatformError::PasskeyUnsupported)
    }

    fn in_directory(directory: &Path) -> Result<Self, PlatformError> {
        let token = trusted_executable(&directory.join("fido2-token"))?;
        let cred = trusted_executable(&directory.join("fido2-cred"))?;
        let assert = trusted_executable(&directory.join("fido2-assert"))?;
        if token.parent() != cred.parent() || token.parent() != assert.parent() {
            return Err(PlatformError::PasskeyUnsupported);
        }
        let version = run(&token, &["-V"], &[], PROBE_TIMEOUT)?;
        // fido2-token writes its version to stderr; -V on the other tools
        // selects verification, so it must never be used as their version probe.
        if !version.stdout.is_empty() || !supported_version(&version.stderr) {
            return Err(PlatformError::PasskeyUnsupported);
        }
        Ok(Self { token, cred, assert })
    }

    fn device(&self) -> Result<String, PlatformError> {
        let listing = run(&self.token, &["-L"], &[], PROBE_TIMEOUT)?;
        let path = single_device(&listing.stdout)?;
        let info = run(&self.token, &["-I", "--", &path], &[], PROBE_TIMEOUT)?;
        let info =
            std::str::from_utf8(&info.stdout).map_err(|_| PlatformError::PasskeyAuthFailed)?;
        if !has_option(info, "extension strings: ", "hmac-secret")
            || !has_option(info, "options: ", "clientPin")
        {
            return Err(PlatformError::PasskeyAuthFailed);
        }
        Ok(path)
    }
}

fn supported_version(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else { return false };
    let Some(text) = text.strip_suffix('\n') else { return false };
    let parts: Vec<_> = text.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        && parts[0] == "1"
        && parts[1].parse::<u32>().is_ok_and(|minor| minor >= 17)
        && parts[2].parse::<u32>().is_ok()
}

fn has_option(info: &str, prefix: &str, option: &str) -> bool {
    info.lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .any(|options| options.split(", ").any(|value| value == option))
}

fn single_device(bytes: &[u8]) -> Result<String, PlatformError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PlatformError::PasskeyAuthFailed)?;
    let mut paths = Vec::new();
    for line in text.lines() {
        let Some((path, _)) = line.split_once(": vendor=") else {
            return Err(PlatformError::PasskeyAuthFailed);
        };
        if path.len() > 4096 || path.bytes().any(|b| b.is_ascii_control()) {
            return Err(PlatformError::PasskeyAuthFailed);
        }
        let usb = if cfg!(target_os = "macos") {
            path.starts_with("ioreg://")
        } else {
            path.strip_prefix("/dev/hidraw")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        };
        if usb {
            paths.push(path);
        }
    }
    match paths.as_slice() {
        [path] => Ok((*path).to_owned()),
        _ => Err(PlatformError::PasskeyAuthFailed),
    }
}

fn trusted_executable(path: &Path) -> Result<PathBuf, PlatformError> {
    let canonical = path.canonicalize().map_err(|_| PlatformError::PasskeyUnsupported)?;
    let uid = rustix::process::geteuid().as_raw();
    for target in [path, canonical.as_path()] {
        for (index, ancestor) in target.ancestors().enumerate() {
            let metadata = ancestor.metadata().map_err(|_| PlatformError::PasskeyUnsupported)?;
            let admin_ancestor = cfg!(target_os = "macos")
                && (index > 1 || (target != canonical && index > 0))
                && metadata.gid() == 80
                && (ancestor.starts_with("/opt/homebrew") || ancestor.starts_with("/usr/local"));
            if (metadata.uid() != 0 && metadata.uid() != uid)
                || metadata.mode() & 0o002 != 0
                || (metadata.mode() & 0o020 != 0 && !admin_ancestor)
                || (index == 0 && (!metadata.is_file() || metadata.mode() & 0o111 == 0))
                || (index != 0 && !metadata.is_dir())
            {
                return Err(PlatformError::PasskeyUnsupported);
            }
        }
    }
    Ok(canonical)
}

fn transcript_lines(bytes: &[u8]) -> Result<Vec<&str>, PlatformError> {
    if bytes.len() > MAX_OUTPUT || !bytes.ends_with(b"\n") {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| PlatformError::PasskeyAuthFailed)?;
    if text.bytes().any(|b| b.is_ascii_control() && b != b'\n') {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    Ok(text[..text.len() - 1].split('\n').collect())
}

fn verify_binding(lines: &[&str], challenge: &[u8; 32], rp: &str) -> Result<(), PlatformError> {
    if lines.len() < 2 || lines[0] != BASE64.encode(challenge) || lines[1] != rp {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    Ok(())
}

fn verify_registration(
    tools: &Tools,
    transcript: &[u8],
    challenge: &[u8; 32],
    rp: &str,
    user_handle: [u8; 32],
) -> Result<PasskeyRegistration, PlatformError> {
    let lines = transcript_lines(transcript)?;
    if !matches!(lines.len(), 6 | 7) {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    verify_binding(&lines, challenge, rp)?;
    let verified = run(&tools.cred, &["-V", "-h", "-v", "es256"], transcript, VERIFY_TIMEOUT)?;
    let text =
        std::str::from_utf8(&verified.stdout).map_err(|_| PlatformError::PasskeyAuthFailed)?;
    let (id, pem) = text.split_once('\n').ok_or(PlatformError::PasskeyAuthFailed)?;
    // cred_verify ignores the supplied ID and derives its result from signed
    // authenticator data. Bind that verified ID to the enrollment transcript.
    if id != lines[4]
        || !pem.starts_with("-----BEGIN PUBLIC KEY-----\n")
        || !pem.ends_with("-----END PUBLIC KEY-----\n")
        || pem.len() > 4096
    {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    let credential_id =
        BASE64.decode(id.as_bytes()).map_err(|_| PlatformError::PasskeyAuthFailed)?;
    if credential_id.is_empty() || credential_id.len() > 1024 {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    Ok(PasskeyRegistration {
        credential_id,
        public_key: pem.as_bytes().to_vec(),
        user_handle: user_handle.to_vec(),
        transports: vec!["usb".to_owned()],
        prf_capable: true,
        backup_eligible: None,
        backup_state: None,
    })
}

fn verify_assertion(
    tools: &Tools,
    transcript: &[u8],
    credential: PasskeyAssertionContext<'_>,
    challenge: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
    let lines = transcript_lines(transcript)?;
    if lines.len() != 5 {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    verify_binding(&lines, challenge, credential.relying_party_id)?;
    // Only the public key is written to a file. The PIN is read privately by
    // libfido2 from /dev/tty; the PRF is never placed in argv, files, or logs.
    let mut public_key =
        tempfile::NamedTempFile::new().map_err(|_| PlatformError::PasskeyAuthFailed)?;
    public_key.write_all(credential.public_key).map_err(|_| PlatformError::PasskeyAuthFailed)?;
    let verification_len = lines[..4].iter().map(|line| line.len() + 1).sum();
    run(
        &tools.assert,
        &[
            OsStr::new("-V"),
            OsStr::new("-h"),
            OsStr::new("-p"),
            OsStr::new("-v"),
            public_key.path().as_os_str(),
            OsStr::new("es256"),
        ],
        &transcript[..verification_len],
        VERIFY_TIMEOUT,
    )?;
    decode_prf(lines[4])
}

fn decode_prf(encoded: &str) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
    // The decoder reserves one byte for base64 padding before returning the
    // actual decoded length. Both allocations are erased on every exit.
    let mut decoded = Zeroizing::new([0_u8; 33]);
    // Decode directly into zeroizing storage; do not create a temporary Vec.
    if encoded.len() != BASE64.encode_len(32)
        || BASE64.decode_mut(encoded.as_bytes(), &mut *decoded) != Ok(32)
    {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    let mut secret = Zeroizing::new([0_u8; 32]);
    secret.copy_from_slice(&decoded[..32]);
    Ok(secret)
}

struct Output {
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn read_bounded(reader: impl Read) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
    // Fixed allocation: no reallocations can leave copies of PRF output behind.
    let mut reader = reader;
    let mut bytes = Zeroizing::new(vec![0; MAX_OUTPUT + 1]);
    let mut used = 0;
    while used <= MAX_OUTPUT {
        let count =
            reader.read(&mut bytes[used..]).map_err(|_| PlatformError::PasskeyAuthFailed)?;
        if count == 0 {
            break;
        }
        used += count;
    }
    if used > MAX_OUTPUT {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    bytes.truncate(used);
    Ok(bytes)
}

fn run(
    executable: &Path,
    args: &[impl AsRef<OsStr>],
    input: &[u8],
    timeout: Duration,
) -> Result<Output, PlatformError> {
    if input.len() > MAX_OUTPUT {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    let child = Command::new(executable)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .current_dir(executable.parent().ok_or(PlatformError::PasskeyAuthFailed)?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| PlatformError::PasskeyAuthFailed)?;
    let mut child = ChildGuard(child);
    let mut stdin = child.0.stdin.take().ok_or(PlatformError::PasskeyAuthFailed)?;
    let stdout = child.0.stdout.take().ok_or(PlatformError::PasskeyAuthFailed)?;
    let stderr = child.0.stderr.take().ok_or(PlatformError::PasskeyAuthFailed)?;
    std::thread::scope(|scope| {
        let write = scope.spawn(move || stdin.write_all(input));
        let out = scope.spawn(|| read_bounded(stdout));
        let err = scope.spawn(|| read_bounded(stderr));
        let started = Instant::now();
        let success = loop {
            match child.0.try_wait() {
                Ok(Some(status)) => break status.success(),
                Ok(None) if started.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => break false,
            }
        };
        // Close pipes before joining readers/writer, including timeout/errors.
        if !success {
            let _ = child.0.kill();
        }
        let _ = child.0.wait();
        let written = write.join();
        let stdout = out.join();
        let stderr = err.join();
        if !success || !matches!(written, Ok(Ok(()))) {
            return Err(PlatformError::PasskeyAuthFailed);
        }
        Ok(Output {
            stdout: stdout.map_err(|_| PlatformError::PasskeyAuthFailed)??,
            stderr: stderr.map_err(|_| PlatformError::PasskeyAuthFailed)??,
        })
    })
}

#[cfg(test)]
#[path = "external_fido2_tests.rs"]
mod tests;
