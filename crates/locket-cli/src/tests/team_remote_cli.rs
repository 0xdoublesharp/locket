use super::*;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const CHILD_MODE: &str = "LOCKET_TEST_REMOTE_CREDENTIAL_MODE";
const ACCESS_ID: &str = "LOCKETMOCKACCESSKEY";
const ACCESS_SECRET: &str = "mock-s3-secret-canary";
const SESSION_TOKEN: &str = "mock-s3-session-canary";
const TEAM_VALUE: &str = "remote-team-value-canary";
const DAV_USER: &str = "mock-dav-user-canary";
const DAV_SECRET: &str = "mock-dav-secret-canary";

#[test]
fn s3_remote_cli_round_trip() -> TestResult {
    if let Ok(mode) = std::env::var(CHILD_MODE) {
        return round_trip(&mode);
    }
    for mode in ["env", "vault"] {
        let mut child = TestCommand::new(std::env::current_exe()?);
        child
            .args(["--exact", "tests::team_remote_cli::s3_remote_cli_round_trip", "--nocapture"])
            .env(CHILD_MODE, mode)
            .env_remove("LOCKET_S3_ACCESS_KEY_ID")
            .env_remove("LOCKET_S3_SECRET_ACCESS_KEY")
            .env_remove("LOCKET_S3_SESSION_TOKEN")
            .env_remove("AWS_ACCESS_KEY_ID")
            .env_remove("AWS_SECRET_ACCESS_KEY")
            .env_remove("AWS_SESSION_TOKEN");
        if mode == "env" {
            child
                .env("AWS_ACCESS_KEY_ID", ACCESS_ID)
                .env("AWS_SECRET_ACCESS_KEY", ACCESS_SECRET)
                .env("AWS_SESSION_TOKEN", SESSION_TOKEN);
        } else {
            child.env("LOCKET_S3_ACCESS_KEY_ID", ACCESS_ID);
        }
        let output = child.output()?;
        assert!(
            output.status.success(),
            "{mode} fixture failed\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let mixed = TestCommand::new(std::env::current_exe()?)
        .args(["--exact", "tests::team_remote_cli::s3_remote_cli_round_trip", "--nocapture"])
        .env(CHILD_MODE, "env")
        .env("LOCKET_S3_ACCESS_KEY_ID", ACCESS_ID)
        .env_remove("LOCKET_S3_SECRET_ACCESS_KEY")
        .env_remove("LOCKET_S3_SESSION_TOKEN")
        .env("AWS_SECRET_ACCESS_KEY", ACCESS_SECRET)
        .env("AWS_SESSION_TOKEN", SESSION_TOKEN)
        .output()?;
    assert!(
        !mixed.status.success(),
        "mixed LOCKET_S3_* and AWS_* credential families must fail closed"
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn round_trip(mode: &str) -> TestResult {
    let remote = MockRemote::start(MockBackend::S3 { with_session: mode == "env" })?;
    let endpoint = format!("http://{}", remote.addr);
    let owner = tempdir()?;
    let receiver = tempdir()?;
    let owner_context = test_context_with_secret_value(&owner, ACCESS_SECRET);
    let receiver_context = test_context_with_secret_value(&receiver, ACCESS_SECRET);

    run(&owner_context, &["init", "--no-passkey", "--name", "app"])?;
    run(&owner_context, &["team", "init", "Remote team"])?;
    let mut set = vec![
        "team",
        "remote",
        "set",
        "s3",
        "--bucket",
        "bucket",
        "--prefix",
        "exchange",
        "--endpoint",
        &endpoint,
        "--credentials",
        mode,
    ];
    if mode == "vault" {
        set.extend(["--access-key-id", ACCESS_ID]);
    }
    run(&owner_context, &set)?;
    assert_connection(&owner_context, 0)?;
    let initial = remote_status(&owner_context)?;
    assert_eq!(initial["transport_kind"], "s3");
    assert_eq!(initial["credential_mode"], mode);
    assert_eq!(initial["remote_target"], "s3://bucket/exchange/");
    assert_eq!(initial["remote_region"], "us-east-1");
    let owner_status = sync_status(&owner_context)?;
    let owner_device = owner_status["owner_fingerprint"].as_str().ok_or("missing owner pin")?;

    fs::copy(owner.path().join("locket.toml"), receiver.path().join("locket.toml"))?;
    run(&receiver_context, &["team", "join", "--request"])?;
    let resolved = crate::require_project(&owner_context)?;
    let project = resolved.config.project_id.as_str();
    let issuer = crate::open_store(&owner_context)?;
    let recipient = crate::open_store(&receiver_context)?;
    assert_eq!(credential_rows(&issuer)?, i64::from(mode == "vault"));
    let device = recipient.get_active_local_device(project)?.ok_or("recipient device missing")?;
    let descriptor = crate::encode_device_descriptor(&device)?;
    run(
        &owner_context,
        &[
            "team",
            "add",
            "Receiver",
            "--device",
            &descriptor,
            "--confirm-device-fingerprint",
            &device.fingerprint,
            "--profile",
            "dev",
        ],
    )?;
    assert!(run(&owner_context, &["team", "publish"])?.contains("delivered 1"));
    assert_connection(&owner_context, 1)?;
    let mut value_context = owner_context.clone();
    value_context.secret_value_reader = Arc::new(StaticSecretValueReader::new(TEAM_VALUE));
    run(&value_context, &["set", "INITIAL_TOKEN", "--source", "team-managed"])?;
    run(&owner_context, &["team", "publish"])?;
    assert_connection(&owner_context, 2)?;

    let join = |pin| {
        [
            "team",
            "join",
            "--owner",
            pin,
            "--s3-bucket",
            "bucket",
            "--s3-prefix",
            "exchange",
            "--s3-endpoint",
            &endpoint,
            "--credentials",
            mode,
        ]
    };
    let wrong_pin = "0".repeat(64);
    assert!(run(&receiver_context, &join(&wrong_pin)).is_err());
    assert!(remote_status(&receiver_context)?["transport_kind"].is_null());
    assert!(run(&receiver_context, &join(owner_device))?.contains("team package verified"));
    let joined = remote_status(&receiver_context)?;
    assert_eq!(joined["transport_kind"], "s3");
    assert_eq!(joined["credential_mode"], mode);
    let joined_status = sync_status(&receiver_context)?;
    assert_eq!(joined_status["owner_fingerprint"], owner_device);
    assert_eq!(joined_status["epoch"], 2);
    assert_eq!(credential_rows(&recipient)?, i64::from(mode == "vault"));
    assert!(
        run(&receiver_context, &["team", "join", "--owner", owner_device, "--remote"])?
            .contains("team package verified")
    );

    run(&value_context, &["set", "REMOTE_TOKEN", "--source", "team-managed"])?;
    run(&owner_context, &["team", "publish"])?;
    run(&receiver_context, &["team", "sync", "now"])?;
    let profile = recipient.get_profile_by_name(project, "dev")?.ok_or("joined profile missing")?;
    assert!(
        recipient
            .get_secret_by_source(project, &profile.id, "REMOTE_TOKEN", "team-managed")?
            .is_some()
    );

    let before_clear = sync_status(&receiver_context)?;
    assert!(before_clear["epoch"].as_u64() > joined_status["epoch"].as_u64());
    for (context, store) in [(&receiver_context, &recipient), (&owner_context, &issuer)] {
        assert!(run(context, &["team", "remote", "clear"])?.contains("authenticated history"));
        assert_eq!(credential_rows(store)?, 0);
        assert!(remote_status(context)?["transport_kind"].is_null());
    }
    let cleared = sync_status(&receiver_context)?;
    assert_eq!(cleared["owner_fingerprint"], owner_device);
    assert_eq!(cleared["epoch"], before_clear["epoch"]);
    Ok(())
}

#[test]
fn webdav_remote_cli_stores_basic_credentials_and_switches_to_folder() -> TestResult {
    let remote = MockRemote::start(MockBackend::WebDav)?;
    let url = format!("http://{}/team/", remote.addr);
    let directory = tempdir()?;
    let folder = tempdir()?;
    let context = test_context_with_secret_value(&directory, DAV_SECRET);
    run(&context, &["init", "--no-passkey", "--name", "app"])?;
    run(&context, &["team", "init", "Remote team"])?;
    run(
        &context,
        &[
            "team",
            "remote",
            "set",
            "webdav",
            "--url",
            &url,
            "--auth",
            "basic",
            "--username",
            DAV_USER,
        ],
    )?;
    assert_connection(&context, 0)?;
    let status = remote_status(&context)?;
    assert_eq!(status["transport_kind"], "webdav");
    assert_eq!(status["credential_mode"], "vault");
    let store = crate::open_store(&context)?;
    assert_eq!(credential_rows(&store)?, 1);
    let path = folder.path().to_str().ok_or("folder path must be UTF-8")?;
    run(&context, &["team", "remote", "set", "folder", path])?;
    let status = remote_status(&context)?;
    assert_eq!(status["transport_kind"], "folder");
    assert_eq!(status["credential_mode"], "none");
    assert_eq!(credential_rows(&store)?, 0);
    Ok(())
}

fn run(context: &RuntimeContext, args: &[&str]) -> TestResult<String> {
    let cli = Cli::try_parse_from(std::iter::once("locket").chain(args.iter().copied()))?;
    let mut output = Vec::new();
    assert_eq!(run_with_context(cli, context, &mut output)?, 0);
    let output = String::from_utf8(output)?;
    for secret in [ACCESS_ID, ACCESS_SECRET, SESSION_TOKEN, TEAM_VALUE, DAV_USER, DAV_SECRET] {
        assert!(!output.contains(secret), "command printed a credential or team value");
    }
    Ok(output)
}

fn remote_status(context: &RuntimeContext) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&run(context, &["team", "remote", "status"])?)?)
}

fn sync_status(context: &RuntimeContext) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&run(context, &["team", "sync", "status"])?)?)
}

fn assert_connection(context: &RuntimeContext, count: usize) -> TestResult {
    let result: serde_json::Value =
        serde_json::from_str(&run(context, &["team", "remote", "test"])?)?;
    assert_eq!(result["ok"], true);
    assert_eq!(result["package_count"], count);
    assert_eq!(result["writable_checked"], false);
    Ok(())
}

fn credential_rows(store: &locket_store::Store) -> TestResult<i64> {
    Ok(store
        .connection()
        .query_row("SELECT count(*) FROM team_sync_credentials", [], |row| row.get(0))?)
}

#[derive(Clone, Copy)]
enum MockBackend {
    S3 { with_session: bool },
    WebDav,
}

struct MockRemote {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl MockRemote {
    fn start(backend: MockBackend) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut objects = BTreeMap::new();
            for stream in listener.incoming() {
                if worker_stop.load(Ordering::Relaxed) {
                    break;
                }
                serve(&mut stream?, &mut objects, backend)?;
            }
            Ok(())
        });
        Ok(Self { addr, stop, worker: Some(worker) })
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

fn serve(
    stream: &mut TcpStream,
    objects: &mut BTreeMap<String, Vec<u8>>,
    backend: MockBackend,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut reader = BufReader::new(&mut *stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut fields = line.split_whitespace();
    let invalid = || io::Error::other("malformed mock storage request");
    let method = fields.next().ok_or_else(invalid)?.to_owned();
    let target = fields.next().ok_or_else(invalid)?.to_owned();
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
    if length > locket_core::team_package::MAX_PACKAGE_BYTES + 18 {
        return Err(invalid());
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let header = |key: &str| headers.get(key).map(String::as_str);
    let MockBackend::S3 { with_session } = backend else {
        let basic = data_encoding::BASE64.encode(format!("{DAV_USER}:{DAV_SECRET}").as_bytes());
        if header("authorization") != Some(&format!("Basic {basic}")) {
            return respond(stream, 403, &[]);
        }
        if method == "PROPFIND" && target == "/team/" && header("depth") == Some("1") {
            return respond(stream, 207, br#"<multistatus xmlns="DAV:"><response><href>/team/</href></response></multistatus>"#);
        }
        return respond(stream, 400, &[]);
    };
    if !header("authorization").is_some_and(|value| {
        value.starts_with(&format!("AWS4-HMAC-SHA256 Credential={ACCESS_ID}/"))
            && value.contains("/us-east-1/s3/aws4_request")
    }) || header("x-amz-security-token") != with_session.then_some(SESSION_TOKEN)
    {
        return respond(stream, 403, &[]);
    }
    if method == "GET" && target == "/bucket?list-type=2&prefix=exchange%2F" {
        let mut listing = String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
        for key in objects.keys() {
            write!(listing, "<Contents><Key>{key}</Key></Contents>").map_err(io::Error::other)?;
        }
        listing.push_str("</ListBucketResult>");
        return respond(stream, 200, listing.as_bytes());
    }
    let Some(key) = target.strip_prefix("/bucket/").filter(|key| key.starts_with("exchange/"))
    else {
        return respond(stream, 404, &[]);
    };
    match (method.as_str(), objects.get(key)) {
        ("HEAD", Some(_)) => respond(stream, 200, &[]),
        ("GET", Some(bytes)) => respond(stream, 200, bytes),
        ("HEAD" | "GET", None) => respond(stream, 404, &[]),
        ("PUT", _) if header("if-none-match") != Some("*") => respond(stream, 400, &[]),
        ("PUT", Some(_)) => respond(stream, 412, &[]),
        ("PUT", None) => {
            objects.insert(key.to_owned(), body);
            respond(stream, 201, &[])
        }
        _ => respond(stream, 400, &[]),
    }
}

fn respond(stream: &mut TcpStream, status: u16, body: &[u8]) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n\r\n", body.len())?;
    stream.write_all(body)
}
