//! Filesystem and base64 encoding helpers shared across platform modules.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use data_encoding::BASE64URL_NOPAD;
use locket_crypto::{NONCE_LEN, NonceBytes};

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

/// Writes a file with owner-only permissions where supported.
///
/// # Errors
///
/// Returns [`PlatformError::Io`] when the file cannot be created, written, or synced.
pub fn write_user_only_file(path: &Path, contents: &[u8]) -> Result<(), PlatformError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

pub fn replace_user_only_file(path: &Path, contents: &[u8]) -> Result<(), PlatformError> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}
