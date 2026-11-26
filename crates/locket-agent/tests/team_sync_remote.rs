//! Team sync over real loopback HTTP connections with untrusted storage.
#![allow(unused_crate_dependencies)]

use std::collections::BTreeMap;
use std::io::{self, BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use locket_agent::team_sync::{
    self, CredentialMode, TransportConfig, TransportSecretInput, WebDavAuthKind,
};
use locket_core::team_package::{DeviceIdentity, MAX_PACKAGE_BYTES, SignedStatement};
use locket_crypto::{KeyBytes, KeyPurpose, KeyWrapAad, KeyWrapPurpose, SecretBlobAad};
use locket_platform::{
    LocalDevicePrivateKeyStorage as _, MasterKeyStore as _, MemoryMasterKeyStore,
    WrappedLocalFileDevicePrivateKeyStorage,
};
use locket_store::{DeviceRecord, Store, TeamRecord};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const PROJECT: &str = "project";
const MASTER: KeyBytes = [22; 32];
const ACCESS_ID: &str = "DEMOACCESSKEY";
const S3_SECRET: &str = "s3-credential-do-not-log";
const S3_TOKEN: &str = "s3-session-do-not-log";
const DAV_SECRET: &str = "dav-secret-do-not-log";
const DAV_USER: &str = "example-user";

#[derive(Clone, Copy)]
enum Backend {
    S3,
    DavBasic,
    DavBearer,
}

impl Backend {
    const fn object_base(self) -> &'static str {
        match self {
            Self::S3 => "/bucket/exchange%20%26%20test/",
            Self::DavBasic | Self::DavBearer => "/team/",
        }
    }

    fn secret(self) -> TransportSecretInput {
        match self {
            Self::S3 => TransportSecretInput::S3 {
                access_key_id: ACCESS_ID.into(),
                secret_access_key: Zeroizing::new(S3_SECRET.into()),
                session_token: Some(Zeroizing::new(S3_TOKEN.into())),
            },
            Self::DavBasic => TransportSecretInput::WebDav {
                username: Some(DAV_USER.into()),
                secret: Zeroizing::new(DAV_SECRET.into()),
            },
            Self::DavBearer => TransportSecretInput::WebDav {
                username: None,
                secret: Zeroizing::new(DAV_SECRET.into()),
            },
        }
    }

    fn authorized(self, request: &Request) -> bool {
        let auth = request.header("authorization").unwrap_or_default();
        match self {
            Self::S3 => {
                auth.starts_with(&format!("AWS4-HMAC-SHA256 Credential={ACCESS_ID}/"))
                    && auth.contains("/us-east-1/s3/aws4_request")
                    && auth.contains("x-amz-security-token")
                    && request.header("x-amz-security-token") == Some(S3_TOKEN)
                    && request.header("x-amz-date").is_some_and(|value| value.len() == 16)
                    && request.header("x-amz-content-sha256").is_some_and(|value| {
                        use sha2::{Digest as _, Sha256};
                        value == data_encoding::HEXLOWER.encode(&Sha256::digest(&request.body))
                    })
            }
            Self::DavBasic => {
                auth == format!(
                    "Basic {}",
                    data_encoding::BASE64.encode(format!("{DAV_USER}:{DAV_SECRET}").as_bytes()),
                )
            }
            Self::DavBearer => auth == format!("Bearer {DAV_SECRET}"),
        }
    }
}

#[derive(Default)]
struct RemoteState {
    objects: BTreeMap<String, Vec<u8>>,
    extra_keys: Vec<String>,
    oversized: Option<String>,
    redirect: bool,
    refuse_auth: bool,
    conflict_next_put: bool,
    clashing_name: Option<String>,
    continued: usize,
    writes: usize,
    requests: usize,
}

struct MockRemote {
    addr: SocketAddr,
    backend: Backend,
    state: Arc<Mutex<RemoteState>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl MockRemote {
    fn start(backend: Backend) -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(RemoteState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let state_worker = Arc::clone(&state);
        let stop_worker = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_worker.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(mut stream) = stream else { break };
                let _ = serve(&mut stream, backend, &state_worker);
            }
        });
        Ok(Self { addr, backend, state, stop, worker: Some(worker) })
    }

    fn state(&self) -> TestResult<MutexGuard<'_, RemoteState>> {
        self.state.lock().map_err(|_| "mock storage lock poisoned".into())
    }

    fn config(&self, credential_mode: CredentialMode) -> TransportConfig {
        let url = format!("http://{}", self.addr);
        match self.backend {
            Backend::S3 => TransportConfig::S3 {
                bucket: "bucket".into(),
                region: "us-east-1".into(),
                prefix: "exchange & test".into(),
                endpoint: Some(url),
                path_style: true,
                credential_mode,
            },
            Backend::DavBasic | Backend::DavBearer => TransportConfig::WebDav {
                url: format!("{url}/team"),
                auth_kind: if matches!(self.backend, Backend::DavBasic) {
                    WebDavAuthKind::Basic
                } else {
                    WebDavAuthKind::Bearer
                },
                username: None,
                credential_mode,
            },
        }
    }
}

impl Drop for MockRemote {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct Request {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    fn read(stream: &mut TcpStream) -> io::Result<Self> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let mut parts = line.split_whitespace();
        let invalid = || io::Error::other("invalid test HTTP request");
        let method = parts.next().ok_or_else(invalid)?.to_owned();
        let target = parts.next().ok_or_else(invalid)?.to_owned();
        let mut headers = BTreeMap::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Err(invalid());
            }
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.split_once(':').ok_or_else(invalid)?;
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
        let length = headers
            .get("content-length")
            .ok_or_else(invalid)?
            .parse::<usize>()
            .map_err(|_| invalid())?;
        if length > MAX_PACKAGE_BYTES + 18 {
            return Err(invalid());
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        Ok(Self { method, target, headers, body })
    }
}

fn serve(stream: &mut TcpStream, backend: Backend, state: &Mutex<RemoteState>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let request = Request::read(stream)?;
    let mut state = state.lock().map_err(|_| io::Error::other("mock storage lock poisoned"))?;
    state.requests += 1;
    if state.redirect {
        return stream.write_all(
            b"HTTP/1.1 302 Found\r\nLocation: https://other.example/\r\nContent-Length: 0\r\n\r\n",
        );
    }
    if state.refuse_auth || !backend.authorized(&request) {
        return respond(
            stream,
            403,
            format!("{ACCESS_ID} {S3_SECRET} {S3_TOKEN} {DAV_SECRET}").as_bytes(),
        );
    }
    match (&backend, request.method.as_str()) {
        (Backend::S3, "GET") if request.target.starts_with("/bucket?") => {
            let Some(body) = s3_listing(&request.target, &mut state) else {
                return respond(stream, 400, b"malformed listing request");
            };
            return respond(stream, 200, body.as_bytes());
        }
        (Backend::DavBasic | Backend::DavBearer, "PROPFIND")
            if request.target == "/team/" && request.header("depth") == Some("1") =>
        {
            let body = dav_listing(&state);
            write!(stream, "HTTP/1.1 207 Multi-Status\r\nTransfer-Encoding: chunked\r\n\r\n")?;
            for chunk in body.as_bytes().chunks(29) {
                write!(stream, "{:x}\r\n", chunk.len())?;
                stream.write_all(chunk)?;
                stream.write_all(b"\r\n")?;
            }
            return stream.write_all(b"0\r\nTest-Trailer: complete\r\n\r\n");
        }
        _ => {}
    }
    let Some(object) = request.target.strip_prefix(backend.object_base()) else {
        return respond(stream, 404, &[]);
    };
    match request.method.as_str() {
        "HEAD" => {
            let status = if state.objects.contains_key(object) { 200 } else { 404 };
            respond(stream, status, &[])
        }
        "GET" if state.oversized.as_deref() == Some(object) => {
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_PACKAGE_BYTES + 19)
        }
        "GET" => {
            let (status, bytes) = state
                .objects
                .get(object)
                .map_or_else(|| (404, &[][..]), |bytes| (200, bytes.as_slice()));
            respond(stream, status, bytes)
        }
        "PUT"
            if request.header("if-none-match") == Some("*")
                && request.header("content-type") == Some("application/octet-stream") =>
        {
            if state.conflict_next_put {
                state.conflict_next_put = false;
                state.clashing_name = Some(object.into());
                state.objects.insert(object.into(), b"competing write".to_vec());
            }
            if state.objects.contains_key(object) {
                return respond(stream, 412, &[]);
            }
            state.objects.insert(object.into(), request.body);
            state.writes += 1;
            drop(state);
            respond(stream, 201, &[])
        }
        _ => respond(stream, 400, &[]),
    }
}

fn respond(stream: &mut TcpStream, status: u16, body: &[u8]) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n\r\n", body.len())?;
    stream.write_all(body)
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn s3_listing(target: &str, state: &mut RemoteState) -> Option<String> {
    use std::fmt::Write as _;
    const QUERY: &str = "list-type=2&prefix=exchange%20%26%20test%2F";
    let start = if target.strip_prefix("/bucket?")? == QUERY {
        0
    } else {
        let continuation = target.strip_prefix("/bucket?continuation-token=next%2B%2F")?;
        let (start, rest) = continuation.split_once("%3D%26&")?;
        if rest != QUERY {
            return None;
        }
        state.continued += 1;
        start.parse::<usize>().ok()?
    };
    let keys: Vec<_> =
        state.objects.keys().chain(state.extra_keys.iter()).map(String::as_str).collect();
    let page = keys.get(start..)?;
    let next = start + page.len().min(2);
    let is_truncated = next < keys.len();
    let mut body = format!("<ListBucketResult><IsTruncated>{is_truncated}</IsTruncated>");
    for key in page.iter().take(2) {
        write!(body, "<Contents><Key>exchange &amp; test/{}</Key></Contents>", xml_escape(key))
            .ok()?;
    }
    if is_truncated {
        write!(body, "<NextContinuationToken>next+/{next}=&amp;</NextContinuationToken>").ok()?;
    }
    body.push_str("</ListBucketResult>");
    Some(body)
}

fn dav_listing(state: &RemoteState) -> String {
    use std::fmt::Write as _;
    let mut body = String::from(
        "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>/team/</D:href></D:response>",
    );
    for key in state.objects.keys().chain(state.extra_keys.iter()) {
        let href = xml_escape(&format!("/team/{key}"));
        let _ = write!(body, "<D:response><href>{href}</href></D:response>");
    }
    body.push_str("</D:multistatus>");
    body
}

struct Device {
    identity: DeviceIdentity,
    signing: SigningKey,
    sealing: KeyBytes,
}

impl Device {
    fn new(id: &str, seed: u8) -> Self {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let sealing = [seed + 1; 32];
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(sealing));
        let identity =
            DeviceIdentity::new(id.into(), signing.verifying_key().to_bytes(), public.to_bytes());
        Self { identity, signing, sealing }
    }

    fn store(&self, dir: &Path) -> TestResult<Vault> {
        let root = dir.join(&self.identity.id);
        std::fs::create_dir(&root)?;
        let mut store = Store::open(root.join("vault.db"))?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT, "Team", 1)?;
        team_sync::store_key(&store, PROJECT, None, KeyPurpose::Audit, &MASTER, &[23; 32], 100)?;
        store.insert_device(&DeviceRecord {
            id: self.identity.id.clone(),
            project_id: PROJECT.into(),
            member_id: None,
            name: self.identity.id.clone(),
            label: "test".into(),
            signing_public_key: self.identity.signing_key.to_vec(),
            sealing_public_key: self.identity.sealing_key.to_vec(),
            fingerprint: self.identity.fingerprint.clone(),
            safety_words: vec![],
            local: true,
            created_at: 1,
            last_seen_at: None,
            revoked_at: None,
        })?;
        let master_keys = Arc::new(MemoryMasterKeyStore::default());
        master_keys.store_master_key(PROJECT, &MASTER)?;
        let storage = WrappedLocalFileDevicePrivateKeyStorage::new(&root, PROJECT, master_keys);
        storage.store(&self.identity.id, &self.sealing)?;
        storage.for_signing().store(&self.identity.fingerprint, &self.signing.to_bytes())?;
        Ok(Vault { store, root })
    }
}

struct Vault {
    store: Store,
    root: PathBuf,
}

impl Vault {
    fn owner(dir: &Path, owner: &Device, members: &[&Device], dangerous: bool) -> TestResult<Self> {
        let mut vault = owner.store(dir)?;
        vault.store.insert_team(&TeamRecord {
            id: "team".into(),
            project_id: PROJECT.into(),
            name: "Team".into(),
            created_at: 1,
            updated_at: 1,
        })?;
        vault.store.insert_team_member(
            "owner-member",
            "team",
            Some(&owner.identity.id),
            "owner",
            "owner",
            1,
        )?;
        vault.store.insert_profile_if_absent("profile", PROJECT, "dev", dangerous, 1)?;
        for (purpose, material) in
            [(KeyPurpose::ProfileSecret, [11; 32]), (KeyPurpose::ProfileFingerprint, [12; 32])]
        {
            team_sync::store_key(
                &vault.store,
                PROJECT,
                Some("profile"),
                purpose,
                &MASTER,
                &material,
                100,
            )?;
        }
        vault.store.connection().execute(
            "INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at)
             VALUES ('secret','project','profile','TOKEN','team-managed','manual',0,1,'active',1,1)",
            [],
        )?;
        write_value(&vault.store, 1, "initial")?;
        team_sync::initialize_owner(&mut vault.store, PROJECT, &owner.identity, 100)?;
        for member in members {
            team_sync::add_recipient(
                &mut vault.store,
                PROJECT,
                &member.identity,
                &member.identity.id,
                "developer",
                &["profile".into()],
                100,
            )?;
        }
        Ok(vault)
    }

    fn configure(&self, remote: &MockRemote, allow_dangerous: bool) -> TestResult {
        team_sync::configure_transport(
            &self.store,
            PROJECT,
            remote.config(CredentialMode::Vault),
            Some(remote.backend.secret()),
            &self.root,
            Some(&MASTER),
            allow_dangerous,
        )?;
        Ok(())
    }

    fn sync(&mut self, now: i64) -> team_sync::Result<team_sync::SyncStatus> {
        team_sync::sync_folder(&mut self.store, PROJECT, &MASTER, now)
    }

    fn join(
        &mut self,
        remote: &MockRemote,
        owner: &Device,
        member: &Device,
        now: i64,
        allow_dangerous: bool,
    ) -> TestResult {
        let config = remote.config(CredentialMode::Vault);
        let candidates =
            team_sync::list_and_read_join_packages(&config, Some(remote.backend.secret()))?;
        for item in candidates {
            let (_, bytes) = item?;
            if team_sync::join_package_checkpoint(
                &bytes,
                &member.sealing,
                &member.identity,
                PROJECT,
                &owner.identity.fingerprint,
                now,
            )
            .is_ok()
            {
                assert!(
                    team_sync::join_package_checkpoint(
                        &bytes,
                        &member.sealing,
                        &member.identity,
                        PROJECT,
                        &member.identity.fingerprint,
                        0,
                    )
                    .is_err()
                );
                team_sync::apply_package_with_consent_guarded(
                    &mut self.store,
                    &bytes,
                    &MASTER,
                    &member.sealing,
                    &member.identity,
                    PROJECT,
                    Some(&owner.identity.fingerprint),
                    now,
                    allow_dangerous,
                    None,
                )?;
                return Ok(());
            }
        }
        Err("no verified join package".into())
    }
}

fn write_value(store: &Store, version: u32, value: &str) -> TestResult {
    let aad = locket_crypto::secret_blob_aad_v1(&SecretBlobAad::new(
        PROJECT, "profile", "secret", "TOKEN", version,
    ))?;
    let wrap = locket_crypto::key_wrap_aad_v1(&KeyWrapAad::new(
        PROJECT,
        "secret",
        Some("profile"),
        version,
        KeyWrapPurpose::SecretDek,
    ))?;
    let blob = locket_crypto::encrypt_secret_value_v1(&[11; 32], value, &aad, &wrap)?;
    let db = store.connection();
    db.execute("UPDATE secret_versions SET state='deprecated' WHERE secret_id='secret'", [])?;
    db.execute("UPDATE secrets SET current_version=?1 WHERE id='secret'", [version])?;
    db.execute(
        "INSERT INTO secret_versions(secret_id,version,source,origin,state,created_at)
         VALUES ('secret',?1,'team-managed','manual','current',1)",
        [version],
    )?;
    db.execute(
        "INSERT INTO blobs VALUES ('secret',?1,?2,?3,?4,1,1)",
        rusqlite::params![
            version,
            blob.encrypted_dek,
            blob.ciphertext,
            blob.value_nonce.as_slice()
        ],
    )?;
    Ok(())
}

#[test]
fn s3_publication_join_update_conflict_revocation_and_fork() -> TestResult {
    let dir = tempfile::tempdir()?;
    let remote = MockRemote::start(Backend::S3)?;
    let owner = Device::new("owner", 7);
    let developer = Device::new("developer", 10);
    let revoked = Device::new("removed", 30);
    let mut publisher = Vault::owner(dir.path(), &owner, &[&developer, &revoked], false)?;
    publisher.configure(&remote, false)?;
    assert_eq!(publisher.sync(150)?.published, 2);

    let mut receiver = developer.store(dir.path())?;
    receiver.join(&remote, &owner, &developer, 150, false)?;
    receiver.configure(&remote, false)?;
    assert_eq!(receiver.sync(150)?.epoch, 1);

    // A local overlapping edit and a remote create race both preserve the
    // competing content, independently of each other.
    write_value(&publisher.store, 2, "owner update")?;
    write_value(&receiver.store, 2, "local update")?;
    remote.state()?.conflict_next_put = true;
    assert_eq!(publisher.sync(151)?.published, 2);
    {
        let state = remote.state()?;
        let clashing = state.clashing_name.as_ref().ok_or("upload race did not run")?;
        assert_eq!(
            state.objects.get(clashing).ok_or("clashing object missing")?,
            b"competing write"
        );
        let queued: bool = publisher.store.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM team_sync_outbox WHERE filename=?1)",
            [clashing],
            |row| row.get(0),
        )?;
        assert!(!queued);
    }
    let updated = receiver.sync(151)?;
    assert_eq!(updated.epoch, 2);
    assert_eq!(updated.conflict_ids, ["secret"]);
    assert_eq!(updated.transport_kind.as_deref(), Some("s3"));
    assert_eq!(updated.remote_region.as_deref(), Some("us-east-1"));
    assert!(remote.state()?.continued > 0);
    team_sync::resolve_conflict(
        &mut receiver.store,
        PROJECT,
        "TOKEN",
        false,
        &MASTER,
        &developer.sealing,
        &developer.identity,
        152,
    )?;

    let revoked_file = publisher.store.connection().query_row(
        "SELECT filename FROM team_sync_outbox WHERE recipient=?1 ORDER BY rowid DESC LIMIT 1",
        [&revoked.identity.fingerprint],
        |row| row.get::<_, String>(0),
    )?;
    remote.state()?.objects.remove(&revoked_file).ok_or("revoked developer's object missing")?;
    assert_eq!(
        team_sync::remove_member(&mut publisher.store, PROJECT, "removed", &MASTER, 153)?,
        ["TOKEN"]
    );
    assert_eq!(publisher.sync(153)?.published, 1);
    assert!(!remote.state()?.objects.contains_key(&revoked_file));
    assert_eq!(receiver.sync(153)?.epoch, 3);
    assert!(
        receiver
            .store
            .find_device(PROJECT, &revoked.identity.id)?
            .is_some_and(|device| device.revoked_at.is_some())
    );

    let latest = publisher.store.connection().query_row(
        "SELECT ciphertext FROM team_sync_outbox WHERE recipient=?1 ORDER BY rowid DESC LIMIT 1",
        [&developer.identity.fingerprint],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    assert!(SignedStatement::open(&latest, &revoked.sealing).is_err());
    let signed = SignedStatement::open(&latest, &developer.sealing)?;
    let mut statement = signed
        .verify_update(&owner.identity.fingerprint, PROJECT, &developer.identity, 153)?
        .statement;
    statement.nonce[0] ^= 1;
    let fork =
        SignedStatement::sign(&statement, &owner.signing)?.seal(&developer.identity.sealing_key)?;
    remote.state()?.objects.insert("fork.lkpkg".into(), fork);
    assert!(receiver.sync(154).is_err_and(|error| error.to_string().contains("fork or rollback")));
    let status = team_sync::status(&receiver.store, PROJECT)?;
    assert_eq!((status.epoch, status.state.as_str()), (3, "fork"));
    assert!(receiver.store.verify_audit_chain_read_only(PROJECT, &[23; 32])?.hmac_ok);
    Ok(())
}

#[test]
fn webdav_basic_and_bearer_deliver_and_gate_dangerous_profiles() -> TestResult {
    for backend in [Backend::DavBasic, Backend::DavBearer] {
        let dir = tempfile::tempdir()?;
        let remote = MockRemote::start(backend)?;
        let owner = Device::new("owner", 7);
        let developer = Device::new("developer", 10);
        let mut publisher = Vault::owner(dir.path(), &owner, &[&developer], true)?;
        publisher.configure(&remote, true)?;
        assert_eq!(publisher.sync(150)?.published, 1);
        let mut receiver = developer.store(dir.path())?;
        receiver.join(&remote, &owner, &developer, 150, true)?;
        receiver.configure(&remote, false)?;
        let no_writes =
            team_sync::test_configured_transport(&receiver.store, PROJECT, Some(&MASTER))?;
        assert!(no_writes.ok);
        assert_eq!(no_writes.package_count, 1);
        assert!(!no_writes.writable_checked);
        assert_eq!(remote.state()?.writes, 1);

        write_value(&publisher.store, 2, "second version")?;
        assert_eq!(publisher.sync(151)?.published, 1);
        let held = receiver.sync(151)?;
        assert_eq!(held.epoch, 2);
        assert_eq!(
            held.pending_profiles.get("profile").map(String::as_str),
            Some("consent-required")
        );
        assert!(receiver.store.get_blob("secret", 2)?.is_none());
        receiver.configure(&remote, true)?;
        let accepted = receiver.sync(152)?;
        assert_eq!(accepted.applied, 1);
        assert!(accepted.pending_profiles.is_empty());
        assert!(receiver.store.get_blob("secret", 2)?.is_some());
    }
    Ok(())
}

#[test]
fn vault_credentials_are_scoped_encrypted_redacted_and_deleted() -> TestResult {
    let dir = tempfile::tempdir()?;
    let remote = MockRemote::start(Backend::S3)?;
    let owner = Device::new("owner", 7);
    let vault = Vault::owner(dir.path(), &owner, &[], false)?;
    vault.configure(&remote, false)?;

    let metadata = serde_json::to_string(&team_sync::status(&vault.store, PROJECT)?)?;
    let (config, ciphertext, nonce): (String, Vec<u8>, Vec<u8>) = vault.store.connection().query_row(
        "SELECT transport_config_json,ciphertext,nonce FROM team_sync_folders JOIN team_sync_credentials USING(project_id)",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(nonce.len(), 24);
    let debug = format!("{:?}", Backend::S3.secret());
    for secret in [ACCESS_ID, S3_SECRET, S3_TOKEN] {
        assert!(!metadata.contains(secret));
        assert!(!config.contains(secret));
        assert!(!debug.contains(secret));
        assert!(!ciphertext.windows(secret.len()).any(|bytes| bytes == secret.as_bytes()));
    }

    assert!(team_sync::test_configured_transport(&vault.store, PROJECT, Some(&[99; 32])).is_err());
    assert!(team_sync::test_configured_transport(&vault.store, PROJECT, None).is_err());
    assert_eq!(remote.state()?.requests, 0);
    assert!(team_sync::test_configured_transport(&vault.store, PROJECT, Some(&MASTER))?.ok);
    assert!(
        team_sync::list_and_read_configured_join_packages(&vault.store, PROJECT, Some(&MASTER))?
            .next()
            .is_none()
    );

    let mut moved: TransportConfig = serde_json::from_str(&config)?;
    if let TransportConfig::S3 { prefix, .. } = &mut moved {
        "other-prefix".clone_into(prefix);
    }
    vault.store.connection().execute(
        "UPDATE team_sync_folders SET transport_config_json=?1",
        [serde_json::to_string(&moved)?],
    )?;
    let requests = remote.state()?.requests;
    assert!(team_sync::test_configured_transport(&vault.store, PROJECT, Some(&MASTER)).is_err());
    assert_eq!(remote.state()?.requests, requests);
    vault.configure(&remote, false)?;

    remote.state()?.refuse_auth = true;
    let error = team_sync::test_configured_transport(&vault.store, PROJECT, Some(&MASTER))
        .err()
        .ok_or("reflected error should be rejected")?
        .to_string();
    assert!(error.contains("HTTP 403"));
    for secret in [ACCESS_ID, S3_SECRET, S3_TOKEN, DAV_SECRET] {
        assert!(!error.contains(secret));
    }

    team_sync::configure_transport(
        &vault.store,
        PROJECT,
        remote.config(CredentialMode::Env),
        None,
        &vault.root,
        None,
        false,
    )?;
    assert_eq!(credential_rows(&vault.store)?, 0);
    vault.configure(&remote, false)?;
    let share = dir.path().join("share");
    std::fs::create_dir(&share)?;
    team_sync::configure_folder(&vault.store, PROJECT, &share, &vault.root, false)?;
    assert_eq!(credential_rows(&vault.store)?, 0);
    vault.configure(&remote, false)?;
    team_sync::clear_transport(&vault.store, PROJECT)?;
    assert_eq!(credential_rows(&vault.store)?, 0);
    assert!(team_sync::status(&vault.store, PROJECT)?.transport_kind.is_none());
    Ok(())
}

fn credential_rows(store: &Store) -> TestResult<i64> {
    Ok(store
        .connection()
        .query_row("SELECT count(*) FROM team_sync_credentials", [], |row| row.get(0))?)
}

#[test]
fn remote_urls_redirects_listing_traversal_and_oversized_downloads_are_rejected() -> TestResult {
    for url in [
        "http://example.com/team",
        "http://127.1/team",
        "https://key:secret@example.com/team",
        "https://example.com/team#fragment",
        "https://example.com/team\r\n",
    ] {
        let config = TransportConfig::WebDav {
            url: url.into(),
            auth_kind: WebDavAuthKind::None,
            username: None,
            credential_mode: CredentialMode::None,
        };
        assert!(
            team_sync::test_transport(&config, None)
                .is_err_and(|error| !error.to_string().contains(url))
        );
    }

    for backend in [Backend::S3, Backend::DavBearer] {
        let remote = MockRemote::start(backend)?;
        let config = remote.config(CredentialMode::Vault);
        remote.state()?.redirect = true;
        assert!(
            team_sync::test_transport(&config, Some(backend.secret()))
                .is_err_and(|error| error.to_string().contains("redirect"))
        );
        assert_eq!(remote.state()?.requests, 1);
        {
            let mut state = remote.state()?;
            state.redirect = false;
            for invalid in
                ["../escape.lkpkg", "subdir/child.lkpkg", "two..dots.lkpkg", "ignore.txt"]
            {
                state.extra_keys.push(invalid.into());
            }
            match backend {
                Backend::S3 => {
                    state
                        .extra_keys
                        .extend(["with\\slash.lkpkg".into(), "with\u{7f}control.lkpkg".into()]);
                }
                _ => {
                    state.extra_keys.extend([
                        "%2e%2e/escape.lkpkg".into(),
                        "%2fescape.lkpkg".into(),
                        "a%5cb.lkpkg".into(),
                    ]);
                }
            }
            state.oversized = Some("oversized.lkpkg".into());
            state.extra_keys.push("oversized.lkpkg".into());
            state.objects.insert("valid.lkpkg".into(), b"opaque".to_vec());
        }
        let tested = team_sync::test_transport(&config, Some(backend.secret()))?;
        assert_eq!(tested.package_count, 2);
        let mut packages = team_sync::list_and_read_join_packages(&config, Some(backend.secret()))?;
        assert!(matches!(packages.next(), Some(Err(team_sync::SyncError::RemoteBodyTooLarge))));
        assert_eq!(
            packages.next().ok_or("missing valid package")??,
            ("valid.lkpkg".into(), b"opaque".to_vec())
        );
        assert!(packages.next().is_none());
    }
    Ok(())
}
