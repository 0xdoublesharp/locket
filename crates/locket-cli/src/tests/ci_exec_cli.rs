use super::*;
use locket_core::team_package::{SignedStatement, TeamStatement};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Output;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use zeroize::Zeroizing;

#[test]
fn ci_cli_requires_backend_pin_and_explicit_secret_selection() {
    let shared = [
        "locket",
        "ci",
        "exec",
        "--owner",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--profile",
        "dev",
        "--folder",
        "packages",
    ];
    let parse =
        |tail: &[&str]| Cli::try_parse_from(shared.iter().copied().chain(tail.iter().copied()));
    assert!(parse(&["--secret", "TOKEN", "--", "tool", "--flag"]).is_ok());
    assert!(
        Cli::try_parse_from(
            shared[..shared.len() - 2].iter().copied().chain(["--secret", "TOKEN", "--", "tool"])
        )
        .is_err()
    );
    for tail in [
        &["--", "tool"][..],
        &["--secret", "TOKEN"],
        &["--secret", "TOKEN", "tool"],
        &["--secret", "TOKEN", "--all-profile-secrets", "--", "tool"],
        &["--all-profile-secrets", "--s3-bucket", "other", "--", "tool"],
        &["--all-profile-secrets", "--s3-region", "auto", "--", "tool"],
        &["--all-profile-secrets", "--webdav-auth", "bearer", "--", "tool"],
    ] {
        assert!(parse(tail).is_err(), "unexpectedly accepted {tail:?}");
    }
    assert!(
        Cli::try_parse_from([
            "locket",
            "ci",
            "verify",
            "--owner",
            "bad-pin",
            "--profile",
            "dev",
            "--folder",
            "packages",
        ])
        .is_err()
    );
}

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const DELIVERY_FIXTURE: &str = "LOCKET_TEST_CI_DELIVERY_FIXTURE";
const RUNNER_ARGS: &str = "LOCKET_TEST_CI_RUNNER_ARGS";
const CUSTOM_IDENTITY: &str = "PIPELINE_PRIVATE_IDENTITY";
const ACCESS_ID: &str = "CIACCESSKEY";
const ACCESS_KEY: &str = "ci-delivery-s3-key-canary";
const DAV_TOKEN: &str = "ci-delivery-webdav-token-canary";
const FIRST: &str = "ci-first-value-canary";
const SECOND: &str = "ci-second-value-canary";
const LOCAL: &str = "ci-local-value-canary";

#[test]
fn ci_init_device_secure_file_and_output() -> TestResult {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let path = directory.path().join("ci.key");
    let path_arg = path.to_str().ok_or("fixture path is not UTF-8")?;
    let args = ["ci", "init-device", "--label", "runner \"test\"", "--output-key-file", path_arg];
    let response = owner_command(&context, &args)?;
    assert!(!response.contains("lkci1_"));
    let metadata: serde_json::Value = serde_json::from_str(&response)?;
    assert_eq!(metadata["label"], "runner \"test\"");
    assert!(metadata["ci_identity"].is_null());
    let token = Zeroizing::new(fs::read_to_string(&path)?);
    assert!(token.starts_with("lkci1_"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    }
    assert!(owner_command(&context, &args).is_err());
    assert_eq!(Zeroizing::new(fs::read_to_string(&path)?), token);
    assert_eq!(fs::read_dir(directory.path())?.count(), 1);

    assert!(Cli::try_parse_from(["locket", "ci", "init-device"]).is_err());
    let stdout: serde_json::Value = serde_json::from_str(&owner_command(
        &context,
        &["ci", "init-device", "--print-private-identity"],
    )?)?;
    assert!(json_str(&stdout, "ci_identity")?.starts_with("lkci1_"));
    assert!(json_str(&stdout, "descriptor")?.starts_with("lkdev2_"));
    assert_eq!(stdout["label"], "ci-runner");
    assert_ne!(stdout["device_id"], metadata["device_id"]);
    assert!(json_str(&stdout, "warning")?.contains("CI Secrets"));
    Ok(())
}

#[test]
fn ci_rejects_malformed_enrollment_inputs_without_writing_files() -> TestResult {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let too_long = "x".repeat(81);
    for label in ["   ", "runner\nname", &too_long] {
        let args = ["ci", "init-device", "--label", label, "--print-private-identity"];
        let error = owner_command(&context, &args).err().ok_or("label must be rejected")?;
        assert!(error.to_string().contains("invalid CI device label"));
    }
    let args = [
        "locket",
        "ci",
        "verify",
        "--owner",
        &"A".repeat(64),
        "--profile",
        "dev",
        "--folder",
        "packages",
        "--identity-env",
        "NO=SUCH",
    ];
    let error = Cli::try_parse_from(args).err().ok_or("invalid env name must be rejected")?;
    assert!(error.to_string().contains("invalid CI identity environment variable name"));
    let cli = Cli::try_parse_from([
        "locket",
        "ci",
        "init-device",
        "--label",
        "private-label-canary",
        "--print-private-identity",
    ])?;
    let debug = format!("{:?}", cli.command);
    assert!(debug.contains("InitDeviceArgs"));
    assert!(!debug.contains("private-label-canary"));
    assert_eq!(fs::read_dir(directory.path())?.count(), 0);
    Ok(())
}

#[test]
fn ci_rejects_malformed_identity_tokens_without_echoing_them() -> TestResult {
    use data_encoding::BASE64URL_NOPAD;

    let directory = tempdir()?;
    let pin = "a".repeat(64);
    let args = [
        "verify",
        "--owner",
        &pin,
        "--project",
        "lk_proj_test",
        "--profile",
        "dev",
        "--folder",
        "packages",
    ];
    assert_denied(
        &invoke_ci_as(directory.path(), CUSTOM_IDENTITY, None, &args)?,
        "CI identity environment variable is missing or invalid",
    );
    let device = locket_core::DeviceId::generate()?;
    let encode = |v: u8, id: &str, key: &str| {
        format!(
            "lkci1_{}",
            BASE64URL_NOPAD.encode(
                json!({
                    "v": v,
                    "id": id,
                    "label": "fixture",
                    "signing_seed_b64": key,
                    "sealing_key_b64": key,
                })
                .to_string()
                .as_bytes()
            )
        )
    };
    let key = BASE64URL_NOPAD.encode(&[1; 32]);
    for token in [
        "unexpected-prefix-canary".to_owned(),
        "lkci1_A".to_owned(),
        "lkci1_!!!!".to_owned(),
        format!("lkci1_{}", BASE64URL_NOPAD.encode(b"plain text canary")),
        format!("lkci1_{}", BASE64URL_NOPAD.encode(&[0; 1025])),
        encode(2, device.as_str(), &key),
        encode(1, "", &key),
        encode(1, device.as_str(), "AA"),
        encode(1, device.as_str(), &"!".repeat(key.len())),
    ] {
        assert_denied(&invoke_ci(directory.path(), &token, &args)?, "invalid CI identity token");
    }
    Ok(())
}

#[test]
fn ci_delivery_round_trip() -> TestResult {
    if std::env::var_os(DELIVERY_FIXTURE).is_some() {
        for delivery in [Delivery::Folder, Delivery::S3, Delivery::WebDav] {
            round_trip(delivery)?;
        }
        return Ok(());
    }
    let output = TestCommand::new(std::env::current_exe()?)
        .args(["--exact", "tests::ci_exec_cli::ci_delivery_round_trip", "--nocapture"])
        .env(DELIVERY_FIXTURE, "1")
        .env("LOCKET_S3_ACCESS_KEY_ID", ACCESS_ID)
        .env("LOCKET_S3_SECRET_ACCESS_KEY", ACCESS_KEY)
        .env_remove("LOCKET_S3_SESSION_TOKEN")
        .env_remove("LOCKET_WEBDAV_SECRET")
        .env("LOCKET_WEBDAV_TOKEN", DAV_TOKEN)
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    Ok(())
}

// Cargo's bin unit-test target supplies the harness executable. Run the same
// standalone CI dispatcher in a subprocess with job-local environment variables.
#[test]
fn ci_runner_subprocess() -> TestResult {
    let Ok(args) = std::env::var(RUNNER_ARGS) else { return Ok(()) };
    let args: Vec<String> = serde_json::from_str(&args)?;
    let cli =
        Cli::try_parse_from(std::iter::once("locket").chain(args.iter().map(String::as_str)))?;
    let Some(crate::Command::Ci { command }) = cli.command else {
        return Err("expected CI command".into());
    };
    let code = match crate::commands::ci::run(&std::env::current_dir()?, &mut io::stdout(), command)
    {
        Ok(code) => code,
        Err(error) => {
            writeln!(io::stderr(), "locket: {error}")?;
            error.exit_code()
        }
    };
    std::process::exit(i32::from(code));
}

#[derive(Clone, Copy, Debug)]
enum Delivery {
    Folder,
    S3,
    WebDav,
}

#[allow(clippy::too_many_lines)]
fn round_trip(delivery: Delivery) -> TestResult {
    let owner = tempdir()?;
    let runner = tempdir()?;
    let folder = tempdir()?;
    let remote = match delivery {
        Delivery::Folder => None,
        Delivery::S3 | Delivery::WebDav => Some(MockRemote::start(delivery)?),
    };
    let endpoint =
        remote.as_ref().map_or_else(String::new, |remote| format!("http://{}", remote.addr));
    let dav_url = format!("{endpoint}/team/");
    let folder_arg = folder.path().to_str().ok_or("fixture path is not UTF-8")?;
    let context = test_context(&owner);
    owner_command(&context, &["init", "--no-passkey", "--name", "app"])?;
    owner_command(&context, &["team", "init", "CI team"])?;
    let setup: &[&str] = match delivery {
        Delivery::Folder => &["folder", folder_arg],
        Delivery::S3 => &[
            "s3",
            "--bucket",
            "bucket",
            "--prefix",
            "exchange",
            "--credentials",
            "env",
            "--endpoint",
            &endpoint,
            "--path-style",
        ],
        Delivery::WebDav => {
            &["webdav", "--url", &dav_url, "--auth", "bearer", "--credentials", "env"]
        }
    };
    let mut configure = vec!["team", "remote", "set"];
    configure.extend_from_slice(setup);
    owner_command(&context, &configure)?;

    let ci_key_file = owner.path().join("fixture-ci.key");
    let init: serde_json::Value = serde_json::from_str(&owner_command(
        &context,
        &[
            "ci",
            "init-device",
            "--output-key-file",
            ci_key_file.to_str().ok_or("missing key path")?,
        ],
    )?)?;
    let token = Zeroizing::new(fs::read_to_string(ci_key_file)?);
    let descriptor = json_str(&init, "descriptor")?;
    let fingerprint = json_str(&init, "fingerprint")?;
    owner_command(
        &context,
        &[
            "team",
            "add",
            "ci-bot",
            "--device",
            descriptor,
            "--confirm-device-fingerprint",
            fingerprint,
            "--profile",
            "dev",
            "--role",
            "read-only",
        ],
    )?;
    for (name, value, source) in [
        ("CI_FIRST", FIRST, "team-managed"),
        ("CI_SECOND", SECOND, "team-managed"),
        ("CI_LOCAL", LOCAL, "user-local"),
    ] {
        let mut context = context.clone();
        context.secret_value_reader = Arc::new(StaticSecretValueReader::new(value));
        owner_command(&context, &["set", name, "--source", source])?;
    }
    assert!(owner_command(&context, &["team", "publish"])?.contains("delivered 1"));

    let status: serde_json::Value =
        serde_json::from_str(&owner_command(&context, &["team", "sync", "status"])?)?;
    let pin = json_str(&status, "owner_fingerprint")?;
    let resolved = crate::require_project(&context)?;
    let project = resolved.config.project_id.as_str();
    let delivery_flags: &[&str] = match delivery {
        Delivery::Folder => &["--folder", folder_arg],
        Delivery::S3 => {
            &["--s3-bucket", "bucket", "--s3-prefix", "exchange", "--s3-endpoint", &endpoint]
        }
        Delivery::WebDav => &["--webdav-url", &dav_url, "--webdav-auth", "bearer"],
    };
    let call = |action: &str, pin: &str, flags: &[&str]| {
        let mut args = vec![action, "--owner", pin, "--project", project, "--profile", "dev"];
        args.extend_from_slice(delivery_flags);
        args.extend_from_slice(flags);
        invoke_ci(runner.path(), &token, &args)
    };
    let verified = call("verify", pin, &[])?;
    assert_eq!(
        checked_json(&verified)?,
        json!({
            "verified": true,
            "project_id": project,
            "profile": "dev",
            "epoch": 1,
            "owner_fingerprint": pin,
            "device_id": init["device_id"],
            "secret_names": ["CI_FIRST", "CI_SECOND"],
        }),
    );
    assert_denied(&call("verify", &"0".repeat(64), &[])?, "owner pin and project");
    assert_denied(&call("verify", pin, &["--min-epoch", "2"])?, "older than required --min-epoch");
    assert_eq!(checked_json(&call("verify", pin, &["--min-epoch", "1"])?)?["epoch"], 1);
    if matches!(delivery, Delivery::Folder) {
        test_runner_execution(&call, pin)?;
        test_signed_heads(&context, runner.path(), &token, project, pin, folder.path())?;
    }

    assert_eq!(fs::read_dir(runner.path())?.count(), 0, "{delivery:?} runner wrote files");
    let mut args = vec!["verify", "--owner", pin, "--profile", "dev"];
    args.extend_from_slice(delivery_flags);
    assert_denied(&invoke_ci(runner.path(), &token, &args)?, "--project is required");
    fs::copy(owner.path().join("locket.toml"), runner.path().join("locket.toml"))?;
    assert_eq!(checked_json(&invoke_ci(runner.path(), &token, &args)?)?["project_id"], project);

    let mut owner_confirmation = context;
    owner_confirmation.confirmation_reader = Arc::new(StaticConfirmationReader::new("dev\n"));
    owner_command(&owner_confirmation, &["profile", "mark-dangerous", "dev"])?;
    owner_confirmation.confirmation_reader =
        Arc::new(StaticConfirmationReader::new("team share dev\n"));
    assert!(owner_command(&owner_confirmation, &["team", "publish"])?.contains("delivered 1"));
    assert_denied(&call("verify", pin, &[])?, "requires --allow-dangerous");
    assert_eq!(checked_json(&call("verify", pin, &["--allow-dangerous"])?)?["epoch"], 2);

    owner_confirmation.confirmation_reader = Arc::new(StaticConfirmationReader::new("ci-bot\n"));
    owner_command(&owner_confirmation, &["team", "remove", "ci-bot"])?;
    assert!(owner_command(&owner_confirmation, &["team", "publish"])?.contains("delivered 0"));
    // Owner-side prune deletes all remote packages belonging to removed/revoked recipients.
    let pruned: serde_json::Value =
        serde_json::from_str(&owner_command(&owner_confirmation, &["team", "remote", "prune"])?)?;
    assert!(pruned["deleted"].as_u64().is_some_and(|deleted| deleted >= 2));
    if let Some(remote) = &remote {
        assert_eq!(remote.objects.lock().map_err(|_| "mock storage lock poisoned")?.len(), 0);
    }
    assert_denied(&call("verify", pin, &["--allow-dangerous"])?, "no CI package verified");

    assert_eq!(fs::read_dir(runner.path())?.count(), 1, "{delivery:?} runner wrote files");
    Ok(())
}

fn test_runner_execution(
    call: &impl Fn(&str, &str, &[&str]) -> TestResult<Output>,
    pin: &str,
) -> TestResult {
    let script = format!(
        "test \"$CI_FIRST\" = '{FIRST}' && test -z \"${{CI_SECOND+x}}\" &&
         test -z \"${{CI_LOCAL+x}}\" && test -n \"$PATH\" &&
         test -z \"${{LOCKET_CI_IDENTITY+x}}\" && test -z \"${{{CUSTOM_IDENTITY}+x}}\" &&
         test -z \"${{LOCKET_S3_SECRET_ACCESS_KEY+x}}\" &&
         test -z \"${{LOCKET_WEBDAV_TOKEN+x}}\" && exit 47; exit 91"
    );
    let output = call("exec", pin, &["--secret", "CI_FIRST", "--", test_shell(), "-c", &script])?;
    assert_eq!(output.status.code(), Some(47), "{:?}", output.status);
    #[cfg(unix)]
    {
        // On Unix, `ci exec` replaces locket via execve so $PPID is the caller test harness
        // itself rather than a surviving locket parent holding LOCKET_CI_IDENTITY in its env.
        let harness_pid = std::process::id();
        let ppid_script = format!(
            "test \"$PPID\" = '{harness_pid}' && ! (ps eww -p \"$PPID\" 2>/dev/null | grep -q 'lkci1_')"
        );
        let ppid_check =
            call("exec", pin, &["--secret", "CI_FIRST", "--", test_shell(), "-c", &ppid_script])?;
        assert!(
            ppid_check.status.success(),
            "parent process check failed: {}",
            String::from_utf8_lossy(&ppid_check.stderr)
        );
    }
    let script = format!("test \"$CI_FIRST\" = '{FIRST}' && test \"$CI_SECOND\" = '{SECOND}'");
    let output = call("exec", pin, &["--all-profile-secrets", "--", test_shell(), "-c", &script])?;
    assert!(output.status.success());
    assert_denied(
        &call("exec", pin, &["--secret", "CI_FIRST", "--secret", "CI_LOCAL", "--", test_true()])?,
        "requested CI secret CI_LOCAL is missing",
    );
    assert_denied(
        &call("exec", pin, &["--secret", "NODE_OPTIONS", "--", test_true()])?,
        "child startup variable",
    );
    Ok(())
}

fn test_signed_heads(
    context: &RuntimeContext,
    runner: &Path,
    token: &str,
    project: &str,
    pin: &str,
    published: &Path,
) -> TestResult {
    let fixture = tempdir()?;
    let path = fixture.path();
    let args = [
        "verify",
        "--owner",
        pin,
        "--project",
        project,
        "--profile",
        "dev",
        "--folder",
        path.to_str().ok_or("fixture path is not UTF-8")?,
    ];
    let encoded = token.strip_prefix("lkci1_").ok_or("invalid fixture token")?;
    let decoded = Zeroizing::new(data_encoding::BASE64URL_NOPAD.decode(encoded.as_bytes())?);
    let payload: serde_json::Value = serde_json::from_slice(&decoded)?;
    let sealing = Zeroizing::new(
        data_encoding::BASE64URL_NOPAD.decode(json_str(&payload, "sealing_key_b64")?.as_bytes())?,
    );
    let sealing: &[u8; 32] = sealing.as_slice().try_into()?;
    let package = fs::read(fs::read_dir(published)?.next().ok_or("no package")??.path())?;
    let signed = SignedStatement::open(&package, sealing)?;
    let mut statement: TeamStatement = serde_json::from_slice(&signed.statement)?;
    let missing_folder = path.join("missing");
    let mut unavailable = args;
    unavailable[8] = missing_folder.to_str().ok_or("fixture path is not UTF-8")?;
    assert_denied(&invoke_ci(runner, token, &unavailable)?, "team folder operation failed");
    let store = crate::open_store(context)?;
    let owner = store.get_active_local_device(project)?.ok_or("owner missing")?;
    let owner_key = crate::commands::team::device::load_device_signing_key(context, &owner)?;
    let write_package = |name: &str, statement: &TeamStatement| -> TestResult {
        let bytes =
            SignedStatement::sign(statement, &owner_key)?.seal(&statement.recipient.sealing_key)?;
        fs::write(path.join(name), bytes)?;
        Ok(())
    };

    fs::write(path.join("01.lkpkg"), &package)?;
    fs::write(path.join("02.lkpkg"), &package)?;
    fs::write(path.join("05.lkpkg"), signed.seal(&statement.publisher.sealing_key)?)?;
    assert_eq!(checked_json(&invoke_ci(runner, token, &args)?)?["epoch"], 1);
    let mut exec = args.to_vec();
    exec[0] = "exec";
    exec.extend(["--secret", "CI_FIRST", "--", test_true()]);
    assert_denied(
        &invoke_ci_as(runner, "CI_FIRST", Some(token), &exec)?,
        "CI secret name conflicts with the identity environment variable",
    );
    statement.nonce[0] ^= 1;
    write_package("03.lkpkg", &statement)?;
    assert_denied(&invoke_ci(runner, token, &args)?, "conflicting CI packages");
    statement.epoch += 1;
    write_package("04.lkpkg", &statement)?;
    assert_eq!(checked_json(&invoke_ci(runner, token, &args)?)?["epoch"], 2);
    statement.issued_at -= 60;
    write_package("04.lkpkg", &statement)?;
    let mut age_limited = args.to_vec();
    age_limited.extend(["--max-age-seconds", "30"]);
    assert_denied(
        &invoke_ci(runner, token, &age_limited)?,
        "latest CI package exceeds --max-age-seconds limit",
    );

    statement.profiles[0].secrets[0].blob.as_mut().ok_or("fixture blob missing")?.ciphertext[0] ^=
        1;
    write_package("04.lkpkg", &statement)?;
    assert_denied(&invoke_ci(runner, token, &args)?, "unable to decrypt");
    statement.issued_at -= 20;
    statement.expires_at = statement.issued_at + 1;
    write_package("04.lkpkg", &statement)?;
    assert_denied(&invoke_ci(runner, token, &args)?, "package has expired");

    statement.expires_at = statement.issued_at + 86400;
    statement.profiles.clear();
    let recipient = statement
        .members
        .iter_mut()
        .find(|member| member.device == statement.recipient)
        .ok_or("fixture recipient missing")?;
    recipient.profiles.clear();
    write_package("04.lkpkg", &statement)?;
    assert_denied(&invoke_ci(runner, token, &args)?, "not authorized for the requested profile");
    statement
        .members
        .iter_mut()
        .find(|member| member.device == statement.recipient)
        .ok_or("fixture recipient missing")?
        .removed = true;
    write_package("04.lkpkg", &statement)?;
    assert_denied(&invoke_ci(runner, token, &args)?, "not an active team member");
    Ok(())
}

fn owner_command(context: &RuntimeContext, args: &[&str]) -> TestResult<String> {
    let cli = Cli::try_parse_from(std::iter::once("locket").chain(args.iter().copied()))?;
    let mut output = Vec::new();
    assert_eq!(run_with_context(cli, context, &mut output)?, 0);
    Ok(String::from_utf8(output)?)
}

fn json_str<'a>(json: &'a serde_json::Value, field: &str) -> TestResult<&'a str> {
    json[field].as_str().ok_or_else(|| format!("missing JSON field {field}").into())
}

fn invoke_ci(cwd: &Path, token: &str, args: &[&str]) -> TestResult<Output> {
    invoke_ci_as(cwd, CUSTOM_IDENTITY, Some(token), args)
}

fn invoke_ci_as(
    cwd: &Path,
    identity_env: &str,
    token: Option<&str>,
    args: &[&str],
) -> TestResult<Output> {
    let mut runner_args = vec!["ci", args[0], "--identity-env", identity_env];
    runner_args.extend_from_slice(&args[1..]);
    let mut command = TestCommand::new(std::env::current_exe()?);
    command
        .args(["--exact", "tests::ci_exec_cli::ci_runner_subprocess", "--nocapture"])
        .env(RUNNER_ARGS, serde_json::to_string(&runner_args)?)
        .env_remove(identity_env)
        .env_remove("LOCKET_CI_IDENTITY")
        .env_remove("CI_FIRST")
        .env_remove("CI_SECOND")
        .env_remove("CI_LOCAL")
        .current_dir(cwd);
    if let Some(token) = token {
        command.env(identity_env, token).env("LOCKET_CI_IDENTITY", token);
    }
    let output = command.output()?;
    for stream in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(stream);
        for value in token.into_iter().chain([FIRST, SECOND, LOCAL, ACCESS_KEY, DAV_TOKEN]) {
            assert!(!text.contains(value), "CI command leaked private material");
        }
    }
    Ok(output)
}

fn checked_json(output: &Output) -> TestResult<serde_json::Value> {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let text = std::str::from_utf8(&output.stdout)?;
    Ok(serde_json::from_str(text.lines().find(|line| line.starts_with('{')).ok_or("no JSON")?)?)
}

fn assert_denied(output: &Output, reason: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success() && stderr.contains(reason), "{stderr}");
}

type RemoteObjects = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

struct MockRemote {
    addr: SocketAddr,
    objects: RemoteObjects,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl MockRemote {
    fn start(delivery: Delivery) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let objects = RemoteObjects::default();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_objects = Arc::clone(&objects);
        let worker = thread::spawn(move || {
            for stream in listener.incoming() {
                if worker_stop.load(Ordering::Relaxed) {
                    break;
                }
                serve(&mut stream?, &worker_objects, delivery)?;
            }
            Ok(())
        });
        Ok(Self { addr, objects, stop, worker: Some(worker) })
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

fn serve(stream: &mut TcpStream, objects: &RemoteObjects, delivery: Delivery) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut reader = BufReader::new(&mut *stream);
    let invalid = || io::Error::other("invalid CI mock storage request");
    let mut request = String::new();
    reader.read_line(&mut request)?;
    let mut fields = request.split_whitespace();
    let method = fields.next().ok_or_else(invalid)?;
    let path = fields.next().ok_or_else(invalid)?;
    let mut headers = BTreeMap::new();
    let mut line = String::new();
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
    let length: usize =
        headers.get("content-length").ok_or_else(invalid)?.parse().map_err(|_| invalid())?;
    if length > locket_core::team_package::MAX_PACKAGE_BYTES + 18 {
        return Err(invalid());
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let header = |name| headers.get(name).map(String::as_str);
    let mut objects = objects.lock().map_err(|_| io::Error::other("mock storage lock poisoned"))?;
    let prefix = match delivery {
        Delivery::S3 => {
            if !header("authorization").is_some_and(|value| {
                value.starts_with(&format!("AWS4-HMAC-SHA256 Credential={ACCESS_ID}/"))
                    && value.contains("/us-east-1/s3/aws4_request")
            }) {
                return respond(stream, 403, &[]);
            }
            if method == "GET" && path == "/bucket?list-type=2&prefix=exchange%2F" {
                let mut listing =
                    String::from("<ListBucketResult><IsTruncated>false</IsTruncated>");
                for key in objects.keys() {
                    write!(listing, "<Contents><Key>exchange/{key}</Key></Contents>")
                        .map_err(io::Error::other)?;
                }
                drop(objects);
                listing.push_str("</ListBucketResult>");
                return respond(stream, 200, listing.as_bytes());
            }
            "/bucket/exchange/"
        }
        Delivery::WebDav => {
            if header("authorization") != Some(&format!("Bearer {DAV_TOKEN}")) {
                return respond(stream, 403, &[]);
            }
            if method == "PROPFIND" && path == "/team/" && header("depth") == Some("1") {
                let mut listing = String::from("<multistatus xmlns=\"DAV:\">");
                for key in objects.keys() {
                    write!(listing, "<response><href>/team/{key}</href></response>")
                        .map_err(io::Error::other)?;
                }
                drop(objects);
                listing.push_str("</multistatus>");
                return respond(stream, 207, listing.as_bytes());
            }
            "/team/"
        }
        Delivery::Folder => return Err(invalid()),
    };
    let Some(key) = path.strip_prefix(prefix) else { return respond(stream, 404, &[]) };
    match (method, objects.get(key)) {
        ("HEAD", Some(_)) => respond(stream, 200, &[]),
        ("GET", Some(bytes)) => respond(stream, 200, bytes),
        ("HEAD" | "GET" | "DELETE", None) => respond(stream, 404, &[]),
        ("PUT", _) if header("if-none-match") != Some("*") => respond(stream, 400, &[]),
        ("PUT", Some(_)) => respond(stream, 412, &[]),
        ("PUT", None) => {
            objects.insert(key.to_owned(), body);
            drop(objects);
            respond(stream, 201, &[])
        }
        ("DELETE", Some(_)) => {
            objects.remove(key);
            drop(objects);
            respond(stream, 204, &[])
        }
        _ => respond(stream, 400, &[]),
    }
}

fn respond(stream: &mut TcpStream, status: u16, body: &[u8]) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\n\r\n", body.len())?;
    stream.write_all(body)
}
