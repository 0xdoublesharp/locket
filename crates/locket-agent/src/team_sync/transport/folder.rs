use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use locket_core::team_package::digest;

use super::{ENTRY_LIMIT, PACKAGE_LIMIT, PutOutcome, Result, TeamTransport, TransportSummary};
use super::{reject, validate_filename};

pub(super) struct Folder {
    path: PathBuf,
    summary: TransportSummary,
}

fn verify_directory(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(reject("choose an existing regular shared folder"));
    }
    Ok(())
}

pub(super) fn canonicalize(path: &Path, key_root: &Path) -> Result<PathBuf> {
    verify_directory(path)?;
    let path = path.canonicalize()?;
    if key_root.starts_with(&path) || path.starts_with(key_root) {
        return Err(reject("shared folder must be separate from local vault/private-key storage"));
    }
    Ok(path)
}

fn validate_local_filename(filename: &str) -> Result<()> {
    validate_filename(filename)?;
    if Path::new(filename).file_name().and_then(|name| name.to_str()) != Some(filename) {
        return Err(reject("invalid shared folder package basename"));
    }
    #[cfg(windows)]
    if filename.contains([':', '<', '>', '|', '?', '*', '"']) {
        return Err(reject("invalid shared folder package basename"));
    }
    Ok(())
}

impl Folder {
    pub(super) fn new(path: PathBuf, summary: TransportSummary) -> Result<Self> {
        verify_directory(&path)?;
        Ok(Self { path, summary })
    }

    fn existing(&self, target: &Path, bytes: &[u8]) -> Result<Option<PutOutcome>> {
        match fs::symlink_metadata(target) {
            Ok(_) if read_package_file(target).is_ok_and(|existing| existing == bytes) => {
                #[cfg(unix)]
                fs::File::open(&self.path)?.sync_all()?;
                Ok(Some(PutOutcome::AlreadyPresent))
            }
            Ok(_) => Ok(Some(PutOutcome::Conflict)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

impl TeamTransport for Folder {
    fn list_packages(&self) -> Result<Vec<String>> {
        let mut files = Vec::new();
        for (index, entry) in fs::read_dir(&self.path)?.enumerate() {
            if index >= ENTRY_LIMIT {
                return Err(reject(
                    "shared folder has too many entries; choose a dedicated team folder",
                ));
            }
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str()
                && validate_local_filename(name).is_ok()
                && entry.file_type()?.is_file()
            {
                files.push(name.to_owned());
            }
        }
        files.sort_unstable();
        Ok(files)
    }

    fn get_package(&self, filename: &str) -> Result<Vec<u8>> {
        validate_local_filename(filename)?;
        read_package_file(&self.path.join(filename))
    }

    fn put_package(&self, filename: &str, bytes: &[u8]) -> Result<PutOutcome> {
        validate_local_filename(filename)?;
        if bytes.len() > PACKAGE_LIMIT {
            return Err(reject("oversized package"));
        }
        let target = self.path.join(filename);
        if let Some(outcome) = self.existing(&target, bytes)? {
            return Ok(outcome);
        }
        let temporary =
            self.path.join(format!(".{}.tmp", digest(&locket_crypto::random_bytes::<32>()?)));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        let written = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        // A hard link publishes a fully written file atomically and fails if a
        // concurrent writer already claimed the destination.
        let linked = written.and_then(|()| fs::hard_link(&temporary, &target));
        let cleaned = fs::remove_file(&temporary);
        match linked {
            Ok(()) => {
                cleaned?;
                #[cfg(unix)]
                fs::File::open(&self.path)?.sync_all()?;
                Ok(PutOutcome::Written)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                cleaned?;
                Ok(self.existing(&target, bytes)?.unwrap_or(PutOutcome::Conflict))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn summary(&self) -> TransportSummary {
        self.summary.clone()
    }
}

/// Read a bounded, regular encrypted package file without following symlinks.
/// # Errors
/// Returns an error if the file is unreadable, oversized, or not regular.
pub fn read_package_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > PACKAGE_LIMIT as u64 {
        return Err(reject("ignore nonregular or oversized package"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(0x0020_0000);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(reject("package is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take((PACKAGE_LIMIT + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > PACKAGE_LIMIT {
        return Err(reject("oversized package"));
    }
    Ok(bytes)
}
