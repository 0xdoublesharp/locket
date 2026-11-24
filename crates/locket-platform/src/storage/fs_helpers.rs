//! Filesystem and base64 encoding helpers shared across platform modules.

use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use locket_crypto::{NONCE_LEN, NonceBytes, random_bytes};

use crate::error::PlatformError;

pub fn encode_bytes(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

pub fn decode_bytes(encoded: &str) -> Result<Vec<u8>, PlatformError> {
    BASE64URL_NOPAD.decode(encoded.as_bytes()).map_err(|_| PlatformError::InvalidPassphraseFallback)
}

pub fn decode_nonce(encoded: &str) -> Result<NonceBytes, PlatformError> {
    if encoded.len() != BASE64URL_NOPAD.encode_len(NONCE_LEN) {
        return Err(PlatformError::InvalidPassphraseFallback);
    }
    let mut nonce = [0; NONCE_LEN];
    BASE64URL_NOPAD
        .decode_mut(encoded.as_bytes(), &mut nonce)
        .map_err(|_| PlatformError::InvalidPassphraseFallback)?;
    Ok(nonce)
}

pub fn validate_path_component(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(PlatformError::InvalidProjectId);
    }
    Ok(())
}

/// Creates a directory tree and restricts it to the current user where supported.
///
/// # Errors
///
/// Returns [`PlatformError::Io`] when the directory cannot be created or hardened.
pub fn secure_directory(path: &Path) -> Result<(), PlatformError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Atomically writes a file with owner-only permissions where supported.
///
/// Refuses an existing destination symlink. Writes and syncs a new file in the
/// same directory before replacing the destination.
///
/// # Errors
///
/// Returns [`PlatformError::Io`] for symlinks or filesystem failures, and
/// [`PlatformError::Crypto`] if system randomness is unavailable.
pub fn write_user_only_file(path: &Path, contents: &[u8]) -> Result<(), PlatformError> {
    refuse_symlink(path)?;
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = format!(".locket-{}.tmp", HEXLOWER.encode(&random_bytes::<16>()?));
    // Named tempfiles use exclusive creation, start at mode 0600 on Unix,
    // and remove the temporary entry if writing or persisting fails.
    let mut temporary =
        tempfile::Builder::new().prefix(&name).rand_bytes(0).tempfile_in(directory)?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    refuse_symlink(path)?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

fn refuse_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_symlink() => {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "refusing to replace a symlink"))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
