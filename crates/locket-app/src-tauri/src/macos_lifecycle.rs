//! The Unix desktop instance socket and its show/acknowledgement protocol.

use std::fs;
use std::io::{self, ErrorKind, Read as _, Write as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const SOCKET_NAME: &str = "desktop-instance.sock";
const SHOW: &[u8; 5] = b"show\n";
const ACK: &[u8; 3] = b"ok\n";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) struct DesktopInstance {
    path: PathBuf,
    identity: (u64, u64),
    listener: Option<UnixListener>,
    server: Option<tauri::async_runtime::JoinHandle<()>>,
}

impl DesktopInstance {
    /// Returns the new owner, or `None` once the serving instance acknowledges a wake.
    pub(crate) fn acquire(directory: &Path) -> io::Result<Option<Self>> {
        fs::create_dir_all(directory)?;
        if !fs::symlink_metadata(directory)?.is_dir() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "Invalid desktop data directory"));
        }
        // Serialize probe/unlink/bind among simultaneous launches. The lock is
        // on the app directory itself, so there is no lockfile to recover.
        let directory_lock = fs::File::open(directory)?;
        directory_lock.lock()?;
        directory_lock.set_permissions(fs::Permissions::from_mode(0o700))?;

        let path = directory.join(SOCKET_NAME);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_socket() => match UnixStream::connect(&path) {
                Ok(stream) => {
                    drop(directory_lock);
                    request_show(stream)?;
                    return Ok(None);
                }
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                    fs::remove_file(&path)?;
                }
                Err(error) => return Err(error),
            },
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::AlreadyExists,
                    "Desktop instance path is occupied by a non-socket entry",
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let listener = UnixListener::bind(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        let instance = Self {
            path,
            identity: (metadata.dev(), metadata.ino()),
            listener: Some(listener),
            server: None,
        };
        // Drop the lock before any error can drop the instance and reacquire it.
        let result = fs::set_permissions(&instance.path, fs::Permissions::from_mode(0o600));
        drop(directory_lock);
        result?;
        Ok(Some(instance))
    }

    pub(crate) fn start(
        &mut self,
        show: impl Fn() -> bool + Send + Sync + 'static,
    ) -> io::Result<()> {
        let Some(listener) = self.listener.take() else {
            return Err(io::Error::other("Desktop instance listener already started"));
        };
        listener.set_nonblocking(true)?;
        let runtime = tauri::async_runtime::handle();
        let _entered = runtime.inner().enter();
        let listener = tokio::net::UnixListener::from_std(listener)?;
        self.server = Some(runtime.spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let _ = tokio::time::timeout(REQUEST_TIMEOUT, handle_request(stream, &show)).await;
            }
        }));
        Ok(())
    }
}

impl Drop for DesktopInstance {
    fn drop(&mut self) {
        // Inspect the inode while holding the same lock used for startup, so a
        // late cleanup can never unlink a succeeding owner's socket.
        if let Some(directory) = self.path.parent()
            && let Ok(lock) = fs::File::open(directory)
            && lock.lock().is_ok()
            && let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && (metadata.dev(), metadata.ino()) == self.identity
        {
            let _ = fs::remove_file(&self.path);
        }
        if let Some(server) = &self.server {
            server.abort();
        }
    }
}

fn request_show(mut stream: UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(STARTUP_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    stream.write_all(SHOW)?;
    let mut reply = [0; ACK.len()];
    stream.read_exact(&mut reply)?;
    if &reply != ACK {
        return Err(io::Error::new(ErrorKind::InvalidData, "Invalid desktop instance reply"));
    }
    Ok(())
}

async fn handle_request(
    mut stream: tokio::net::UnixStream,
    show: &(impl Fn() -> bool + Sync),
) -> io::Result<()> {
    let mut request = [0; SHOW.len()];
    stream.read_exact(&mut request).await?;
    if &request == SHOW && show() {
        stream.write_all(ACK).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn socket_directory() -> io::Result<tempfile::TempDir> {
        // Keep room for the production socket name under macOS's sockaddr_un
        // limit, even when Cargo uses a worktree-qualified temporary directory.
        tempfile::Builder::new().prefix("").tempdir()
    }

    #[test]
    fn second_instance_wakes_the_owner_and_quit_releases_the_socket() -> io::Result<()> {
        let directory = socket_directory()?;
        let path = directory.path().join(SOCKET_NAME);
        let mut owner = DesktopInstance::acquire(directory.path())?
            .ok_or_else(|| io::Error::other("Expected first instance to own the socket"))?;
        assert_eq!(fs::symlink_metadata(&path)?.mode() & 0o777, 0o600);
        let shows = Arc::new(AtomicUsize::new(0));
        let callback_count = Arc::clone(&shows);
        owner.start(move || {
            callback_count.fetch_add(1, Ordering::SeqCst);
            true
        })?;
        assert!(DesktopInstance::acquire(directory.path())?.is_none());
        assert_eq!(shows.load(Ordering::SeqCst), 1);
        drop(owner);
        assert!(!path.exists());
        assert!(DesktopInstance::acquire(directory.path())?.is_some());
        Ok(())
    }

    #[test]
    fn refused_socket_is_recovered_but_a_non_socket_entry_is_preserved() -> io::Result<()> {
        let directory = socket_directory()?;
        let path = directory.path().join(SOCKET_NAME);
        drop(UnixListener::bind(&path)?);
        let owner = DesktopInstance::acquire(directory.path())?
            .ok_or_else(|| io::Error::other("Expected to replace the stale socket"))?;
        drop(owner);
        fs::write(&path, b"keep")?;
        assert!(DesktopInstance::acquire(directory.path()).is_err());
        assert_eq!(fs::read(&path)?, b"keep");
        Ok(())
    }

    #[test]
    fn unknown_request_closes_without_waking_the_owner() -> io::Result<()> {
        let directory = socket_directory()?;
        let mut owner = DesktopInstance::acquire(directory.path())?
            .ok_or_else(|| io::Error::other("Expected a socket owner"))?;
        let shows = Arc::new(AtomicUsize::new(0));
        let callback_count = Arc::clone(&shows);
        owner.start(move || {
            callback_count.fetch_add(1, Ordering::SeqCst);
            true
        })?;
        let mut client = UnixStream::connect(directory.path().join(SOCKET_NAME))?;
        client.set_read_timeout(Some(REQUEST_TIMEOUT))?;
        client.write_all(b"quit\n")?;
        assert_eq!(client.read(&mut [0; 1])?, 0);
        assert_eq!(shows.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn invalid_acknowledgement_preserves_the_existing_socket_entry() -> io::Result<()> {
        let directory = socket_directory()?;
        let path = directory.path().join(SOCKET_NAME);
        let listener = UnixListener::bind(&path)?;
        let peer = std::thread::spawn(move || {
            let (mut client, _) = listener.accept()?;
            let mut request = [0; SHOW.len()];
            client.read_exact(&mut request)?;
            assert_eq!(&request, SHOW);
            client.write_all(b"no\n")
        });
        let result = DesktopInstance::acquire(directory.path());
        assert!(matches!(result, Err(error) if error.kind() == ErrorKind::InvalidData));
        peer.join().map_err(|_| io::Error::other("acknowledgement peer failed"))??;
        assert!(fs::symlink_metadata(path)?.file_type().is_socket());
        Ok(())
    }
}
