//! In-process Tauri IPC dispatch with isolated paths and a real Unix transport.
#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use locket_agent::{
    AgentMethod, AgentSocketConfig, AgentSocketState, DEFAULT_MAX_MESSAGE_SIZE, ErrorEnvelope,
    RequestEnvelope, ResponseEnvelope, SuccessEnvelope, bind_socket_listener, encode_frame,
    handle_connection,
};
use locket_platform::{MasterKeyStore, PassphraseFallbackMasterKeyStore, PlatformError};
use locket_store::Store;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tauri::test::{MockRuntime, get_ipc_response, mock_builder, mock_context, noop_assets};
use tauri::{Listener as _, WebviewWindow, WebviewWindowBuilder};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

use super::*;

const CHILD_HOME: &str = "LOCKET_DESKTOP_IPC_TEST_HOME";
const PROJECT: &str = "lk_proj_ipc_test";
const PROFILE: &str = "lk_prof_ipc_test";
const SHARED: &str = "lk_proj_shared_ipc_test";
const SHARED_PROFILE: &str = "lk_prof_shared_ipc_test";
const TOKEN: &str = "test-only-secret-value";

#[test]
fn desktop_ipc_in_isolated_process() {
    if let Some(home) = std::env::var_os(CHILD_HOME) {
        exercise_desktop_ipc(&PathBuf::from(home));
        return;
    }
    // A separate process lets the production path and selection lookups run
    // normally, without mutating environment variables in the test runner.
    let home = tempfile::tempdir().expect("isolated desktop home");
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).expect("private test home");
    let mut child = Command::new(std::env::current_exe().expect("test executable"));
    child
        .args(["--exact", "command_tests::desktop_ipc_in_isolated_process", "--nocapture"])
        .env(CHILD_HOME, home.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_DATA_HOME", home.path().join("data"))
        .env("LOCKET_INSTANCE", "dev")
        .env("LOCKET_AGENT_SOCKET", home.path().join("a.sock"))
        .env_remove("LOCKET_SESSION_LOCKED");
    let result = child.output().expect("run isolated desktop tests");
    assert!(
        result.status.success(),
        "isolated desktop tests failed ({})\n{}\n{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );
}

struct Ipc {
    window: WebviewWindow<MockRuntime>,
    app: tauri::App<MockRuntime>,
}

impl Ipc {
    fn new(home: &Path) -> Self {
        #[cfg(target_os = "macos")]
        let picker_program = {
            let path = home.join("picker");
            fs::write(
                &path,
                "#!/bin/sh\ncase \"$6\" in\ndirectory) printf '/fixture/project folder\\n';;\nfile) printf 'user canceled (-128)\\n' >&2; exit 1;;\nsave) printf '/fixture/%s\\n' \"$8\";;\n*) exit 21;;\nesac\n",
            )
            .expect("fake picker");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("executable picker");
            path
        };
        #[cfg(not(target_os = "macos"))]
        let _ = home;
        let handoff = desktop_actions::DesktopHandoff {
            terminal: |cli, root, args| {
                let status = Command::new(cli)
                    .args(args)
                    .current_dir(root)
                    .status()
                    .map_err(|error| error.to_string())?;
                if !status.success() {
                    return Err(format!("test terminal failed: {status}"));
                }
                Ok(())
            },
            #[cfg(target_os = "macos")]
            picker_program,
            copy_text: |text| {
                if text == "refuse clipboard" {
                    return Err(ClipboardError::Backend("test refusal".into()));
                }
                assert_eq!(text, "plain fixture");
                Ok(())
            },
            copy_secret: |value, ttl| {
                Box::pin(async move {
                    assert_eq!(value, TOKEN);
                    match ttl.as_secs() {
                        0 | 7 | 300 => Ok(()),
                        _ => Err(ClipboardError::Backend("test refusal".into())),
                    }
                })
            },
        };
        let app = register_commands(mock_builder().manage(handoff))
            .build(mock_context(noop_assets()))
            .expect("mock desktop app");
        let window = WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .expect("mock desktop window");
        Self { window, app }
    }

    fn invoke(&self, command: &str, body: Value) -> Result<Value, Value> {
        get_ipc_response(
            &self.window,
            tauri::webview::InvokeRequest {
                cmd: command.into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: "tauri://localhost".parse().expect("IPC origin"),
                body: tauri::ipc::InvokeBody::Json(body),
                headers: Default::default(),
                invoke_key: tauri::test::INVOKE_KEY.into(),
            },
        )
        .map(|response| response.deserialize().expect("JSON IPC response"))
    }

    fn request(&self, command: &str, request: Value) -> Result<Value, Value> {
        self.invoke(command, json!({ "request": request }))
    }

    fn ok(&self, command: &str, request: Value) -> Value {
        self.request(command, request).unwrap_or_else(|error| panic!("{command} failed: {error}"))
    }

    fn rejected(&self, command: &str, request: Value, code: &str) -> Value {
        let error = self.request(command, request).expect_err(command);
        assert_eq!(error["kind"], "rejected", "{command}: {error}");
        assert_eq!(error["code"], code, "{command}: {error}");
        error
    }
}

struct Vault {
    root: PathBuf,
    store: PathBuf,
    id: String,
}

struct FixtureMasterKeys;

impl MasterKeyStore for FixtureMasterKeys {
    fn store_master_key(&self, _: &str, _: &[u8; 32]) -> Result<(), PlatformError> {
        unreachable!("the desktop cannot write this fixture's master keys")
    }

    fn load_master_key(&self, project: &str) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        match project {
            PROJECT => Ok(Zeroizing::new([42; 32])),
            SHARED => Ok(Zeroizing::new([91; 32])),
            _ => Err(PlatformError::MasterKeyNotFound),
        }
    }

    fn delete_master_key(&self, _: &str) -> Result<(), PlatformError> {
        unreachable!("the desktop cannot delete this fixture's master keys")
    }
}

impl Vault {
    fn new(home: &Path, store: PathBuf) -> Self {
        let root = home.join("project ' $(not-a-program)");
        fs::create_dir(&root).expect("project directory");
        let root = root.canonicalize().expect("canonical project root");
        let id = PROJECT.to_owned();
        fs::write(
            root.join("locket.toml"),
            format!(
                "schema_version = 1\nproject_id = '{id}'\nname = 'Fixture'\ndefault_profile = 'dev'\n[commands.test]\nargv = ['echo', 'test']\n"
            ),
        )
        .expect("write trusted project config");
        fs::write(
            root.join("package.json"),
            br#"{"scripts":{"test":"never execute me","build":"echo build"}}"#,
        )
        .expect("project manifest");
        fs::write(root.join(".env"), format!("TOKEN={TOKEN}\n")).expect("fixture env file");
        fs::create_dir_all(store.parent().expect("store directory")).expect("create store dir");
        let mut db = Store::open(&store).expect("test store");
        db.initialize_schema().expect("store schema");
        db.insert_project_if_absent(&id, "Fixture", 1).expect("project");
        db.insert_profile_if_absent(PROFILE, &id, "dev", false, 1).expect("dev profile");
        db.trust_project_root(
            &id,
            &Sha256::digest(root.to_string_lossy().as_bytes()).into(),
            root.to_str(),
            1,
        )
        .expect("trust test project root");
        seed_wrapped_keys(&db, PROJECT, PROFILE);
        Self { root, store, id }
    }

    fn add_shared(&self) {
        let db = Store::open(&self.store).expect("test store");
        db.insert_project_if_absent(SHARED, "@shared", 1).expect("Global Vault");
        db.insert_profile_if_absent(SHARED_PROFILE, SHARED, "default", false, 1)
            .expect("Global Vault profile");
        seed_wrapped_keys(&db, SHARED, SHARED_PROFILE);
    }

    fn dangerous(&self, enabled: bool) {
        Store::open(&self.store)
            .expect("test store")
            .set_profile_dangerous(&self.id, "dev", enabled)
            .expect("set dangerous marker");
    }

    fn start_live_agent(&self, socket: &Path, approve: bool) -> JoinHandle<()> {
        let config = AgentSocketConfig::new(socket.into(), "isolated-desktop-agent");
        let runtime = tauri::async_runtime::handle();
        let _entered = runtime.inner().enter();
        let listener = bind_socket_listener(&config).expect("bind real agent socket");
        let fallback = PassphraseFallbackMasterKeyStore::new(socket.with_file_name("fallback"));
        let uid = fs::metadata(socket).expect("agent socket").uid();
        let verifier = if approve {
            locket_platform::MemoryLocalUserVerifier::allowing()
        } else {
            locket_platform::MemoryLocalUserVerifier::denying()
        };
        let state = AgentSocketState::with_stores(
            &config.agent_version,
            uid,
            Arc::new(FixtureMasterKeys),
            Arc::new(fallback),
        )
        .with_canonical_store_path(self.store.clone())
        .with_user_config_path(default_config_path().expect("sandbox config"))
        .with_daemon_user_verification(approve)
        .with_user_verifier(Arc::new(verifier));
        runtime.inner().spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = state.clone();
                tokio::spawn(async move { handle_connection(stream, state).await });
            }
        })
    }
}

// Synthetic v1 fixtures for the constant IDs above. The ciphertexts were
// generated with derive_wrapping_key_v1, key_wrap_aad_v1 and wrap_key_material_v1.
// They wrap repeated-byte material [7; 32], [8; 32], and [9; 32] under the
// in-memory masters [42; 32] and [91; 32].
fn seed_wrapped_keys(store: &Store, project: &str, profile: &str) {
    let fixtures = [
        (
            PROJECT,
            "project-audit",
            "jITz8DJfGIlUj6wSeqdmVPCawPgXl8za",
            "TfrTMBSpg24KtNkg+ccjPsO4wgWJVy5z/TPpx4ZGYOpzZnb57GDELbmIGtKrTNS0",
        ),
        (
            PROJECT,
            "profile-secret",
            "7g51DnXFEa4Qz5oRcE/+gtSSjfHMXnzm",
            "zMP8Fpl0OGLwXKPywVj0TZWg8Ji/qMLLtcTSb1azFmUEdrM+7VM2uF+KeDc9bzIo",
        ),
        (
            PROJECT,
            "profile-fingerprint",
            "dKptyMgK0OvdQ4V0hOQITE7UCyG8pxqG",
            "+gkoLK2DGv8kbhLDjpR6xsUaU8ry14BjJuhYspG8tVCD9CaGGkDQcm/vbTkbawYQ",
        ),
        (
            SHARED,
            "project-audit",
            "IvgxlzkgT9jkG6PnEYvyH+qGFVloE44z",
            "8Fkva1jAGtquoUMoI9jXkFgwEAPHczRQczUr/lrv6MpEPkURvuj1HRLOLtQybhha",
        ),
        (
            SHARED,
            "profile-secret",
            "805y5s/tWz7evkq77eyEB2Oxdf0NwMPM",
            "XLh0q7++RrjKpx/NQey4c5vPkWzWryrU4K648gmlnT/akSJ3OFxuZgQxa2edyHCd",
        ),
        (
            SHARED,
            "profile-fingerprint",
            "95GUFfaaJiNerI/M+OEbALB0jlagUR7l",
            "Wi4r0Mo/Oe0FhT7YF+zdQym5k8kHCpm3HVOoj2A6gax78O4uOXuCvpjAMypPr4Nx",
        ),
    ];
    let decode =
        |data| base64::engine::general_purpose::STANDARD.decode(data).expect("wrapped key fixture");
    for (fixture_project, purpose, nonce, ciphertext) in fixtures {
        if fixture_project == project {
            store
                .insert_key(&locket_store::KeyRecord {
                    id: format!("lk_key_{project}_{purpose}"),
                    project_id: project.into(),
                    profile_id: (purpose != "project-audit").then(|| profile.into()),
                    purpose: purpose.into(),
                    wrapped_material: decode(ciphertext),
                    nonce: decode(nonce).try_into().expect("24-byte fixture nonce"),
                    created_at: 1,
                })
                .expect("insert wrapped fixture key");
        }
    }
}

fn exercise_desktop_ipc(home: &Path) {
    let socket = home.join("a.sock");
    assert_eq!(resolve_socket_path(), socket);
    let store = default_store_path().expect("isolated store path");
    assert!(store.starts_with(home), "store escaped test home: {store:?}");
    assert!(default_config_path().expect("isolated config").starts_with(home));

    let ipc = Ipc::new(home);
    assert_eq!(ipc.invoke("desktop_list_projects", json!({})), Ok(json!([])));
    assert_eq!(
        ipc.invoke("agent_status", json!({})).expect_err("offline agent")["kind"],
        "unavailable"
    );
    assert_eq!(
        ipc.request("agent_copy_secret", json!({"secret_name":"TOKEN","profile_id":PROFILE})),
        Err(
            json!({"kind":"protocol","reason":"Open a trusted project before requesting secret access."})
        ),
    );
    malformed_requests(&ipc);
    let vault = Vault::new(home, store);
    local_actions(&ipc, &vault, home);
    let status = subscribe_while_offline(&ipc);
    tray::start_tray_status_subscription(ipc.app.handle().clone());
    let server = vault.start_live_agent(&socket, true);
    let event = status.recv_timeout(Duration::from_secs(8)).expect("status after reconnect");
    assert_eq!(event.status.agent_version, "isolated-desktop-agent");
    assert_eq!(event.status.lock_state, locket_agent::LockState::Locked);
    live_agent_commands(&ipc, &vault);
    tray_menu_events(&ipc, &vault);
    crate::cancel_status_subscription();
    tauri::async_runtime::block_on(async {
        server.abort();
        let _ = server.await;
    });
    fs::remove_file(&socket).expect("remove stopped agent socket");
    wire_command_contracts(&ipc, &vault, &socket);
    let config = default_config_path().expect("sandbox config");
    fs::create_dir_all(config.parent().expect("sandbox config directory"))
        .expect("config directory");
    fs::write(config, "[user_verification_required_for]\ncopy = true\n")
        .expect("grant approval policy");
    let server = vault.start_live_agent(&socket, false);
    let copy = json!({"from_project_id":vault.id,"from_profile_id":PROFILE,"secret_name":"TOKEN"});
    ipc.ok(
        "agent_unlock",
        json!({"project_id":vault.id,"ttl_seconds":90,"source":{"kind":"os-keychain"}}),
    );
    ipc.rejected("desktop_copy_secret_to_shared", copy, "UserVerificationFailed");
    server.abort();
}

#[test]
fn mock_app_setup_wakes_owned_instance_and_shutdown_releases_its_socket() {
    let directory = tempfile::Builder::new().prefix("").tempdir().expect("short socket directory");
    let owner = macos_lifecycle::DesktopInstance::acquire(directory.path())
        .expect("acquire owner")
        .expect("first instance");
    let (ready, started) = std::sync::mpsc::channel();
    let app = desktop_builder(mock_builder(), move |app| {
        assert!(app.get_webview_window("main").is_some());
        ready.send(()).expect("start signal");
        Ok(())
    })
    .build(mock_context(noop_assets()))
    .expect("build app");
    let window =
        WebviewWindowBuilder::new(&app, "main", Default::default()).build().expect("mock window");
    let token = status_subscription_cancel_token();
    assert!(!token.is_cancelled());
    let path = directory.path().to_path_buf();
    let second_instance = std::thread::spawn(move || {
        let result = started
            .recv_timeout(Duration::from_secs(5))
            .map_err(std::io::Error::other)
            .and_then(|()| macos_lifecycle::DesktopInstance::acquire(&path));
        // Destroy the mock window even when the wake failed, so the mock
        // event loop always ends before the test reports the error.
        window.destroy().expect("exit the mock runtime");
        assert!(result.expect("wake the owner").is_none());
    });
    run_app(app, owner).expect("run mock app");
    second_instance.join().expect("second instance");
    assert!(token.is_cancelled(), "shutdown must cancel background subscribers");
    assert!(
        macos_lifecycle::DesktopInstance::acquire(directory.path())
            .expect("acquire after exit")
            .is_some()
    );
}

fn subscribe_while_offline(ipc: &Ipc) -> std::sync::mpsc::Receiver<locket_agent::StatusEvent> {
    let (events, status) = std::sync::mpsc::channel();
    ipc.app.listen(AGENT_STATUS_EVENT, move |event| {
        events
            .send(serde_json::from_str(event.payload()).expect("typed status event"))
            .expect("status receiver");
    });
    let (errors, error) = std::sync::mpsc::channel();
    ipc.app.once(AGENT_STATUS_ERROR_EVENT, move |event| {
        errors.send(event.payload().to_owned()).expect("error receiver");
    });
    let (disconnects, disconnected) = std::sync::mpsc::channel();
    ipc.app.once(AGENT_STATUS_DISCONNECTED_EVENT, move |_| {
        disconnects.send(()).expect("disconnect receiver");
    });
    assert_eq!(ipc.invoke("agent_subscribe_status", json!({})), Ok(Value::Null));
    assert_eq!(ipc.invoke("agent_subscribe_status", json!({})), Ok(Value::Null));
    let failure = error.recv_timeout(Duration::from_secs(5)).expect("offline error event");
    let failure: Value = serde_json::from_str(&failure).expect("decode connection error");
    assert_eq!(failure["kind"], "unavailable");
    disconnected.recv_timeout(Duration::from_secs(5)).expect("disconnected event");
    status
}

fn tray_menu_events(ipc: &Ipc, vault: &Vault) {
    let (send, receive) = std::sync::mpsc::channel();
    ipc.app.listen(TRAY_MENU_ACTION_EVENT, move |event| {
        send.send(serde_json::from_str::<TrayMenuAction>(event.payload()).expect("tray event"))
            .expect("event receiver");
    });
    let click = |id: &str| {
        tray::handle_tray_menu_event(ipc.app.handle(), &tauri::menu::MenuEvent { id: id.into() });
    };
    click("unregistered-tray-action");
    click(TrayMenuAction::RunPolicy.id());
    assert_eq!(receive.recv_timeout(Duration::from_secs(5)), Ok(TrayMenuAction::RunPolicy));

    ipc.ok(
        "agent_unlock",
        json!({
            "project_id":vault.id,"ttl_seconds":90,"source":{"kind":"os-keychain"},
        }),
    );
    click(TrayMenuAction::LockVault.id());
    assert_eq!(receive.recv_timeout(Duration::from_secs(5)), Ok(TrayMenuAction::LockVault));
    assert_eq!(
        ipc.invoke("agent_status", json!({})).expect("locked via tray")["lock_state"],
        "locked"
    );
}

fn malformed_requests(ipc: &Ipc) {
    for command in [
        "desktop_open_project",
        "desktop_open_shared_vault",
        "desktop_inspect_project_folder",
        "desktop_initialize_project",
        "desktop_import_env",
        "desktop_create_profile",
        "desktop_delete_secret",
        "desktop_copy_secret_to_shared",
        "desktop_detect_commands",
        "desktop_start_agent",
        "desktop_run_policy",
        "desktop_scan_project",
        "desktop_variable_readiness",
        "desktop_team_sync_status",
        "desktop_team_sync_configure",
        "desktop_team_sync_test_remote",
        "desktop_team_sync_clear",
        "desktop_team_sync_now",
        "desktop_team_sync_rename_profile",
        "desktop_team_sync_preserve_override",
        "agent_unlock",
        "agent_set_active_profile",
        "agent_reveal",
        "agent_scan",
        "agent_resolve",
        "agent_prepare_exec",
        "agent_policy_doctor",
        "agent_export_bundle",
        "agent_import_bundle",
        "agent_verify_bundle",
        "agent_recovery_rotate",
        "agent_list_runtime_sessions",
        "agent_list_policies",
        "agent_register_command_policies",
        "agent_list_device_members",
        "agent_list_secrets",
        "agent_discover_secrets",
        "agent_list_projects",
        "agent_set_secret",
        "agent_rotate_secret",
        "agent_read_config",
        "agent_write_config",
        "agent_list_audit",
        "agent_verify_audit",
        "agent_list_versions",
        "agent_copy_secret",
    ] {
        let error = ipc.request(command, json!(false)).expect_err(command);
        assert!(
            error.as_str().is_some_and(|message| message.contains("invalid args")),
            "{command}: {error}"
        );
    }
    for (command, body) in [
        ("desktop_pick_directory", json!({"title": 1})),
        ("desktop_pick_file", json!({"title": 1})),
        ("desktop_copy_text_plain", json!({"text": 1})),
        ("desktop_set_launch_at_login", json!({"enabled": 1})),
        ("tray_set_state", json!({"state": "invalid"})),
        ("tray_set_selection", json!({"selection": 1})),
        ("tray_set_privacy_context", json!({"context": 1})),
    ] {
        let error = ipc.invoke(command, body).expect_err(command);
        assert!(
            error.as_str().is_some_and(|message| message.contains("invalid args")),
            "{command}: {error}"
        );
    }
    assert!(ipc.invoke("not_a_desktop_command", json!({})).is_err());
}

fn local_actions(ipc: &Ipc, vault: &Vault, home: &Path) {
    let bin = home.join("bin");
    fs::create_dir(&bin).expect("fake CLI directory");
    let cli = bin.join("locket");
    // resolve_cli must prefer this verified resource over any installed binary.
    fs::write(
        &cli,
        format!(
            "#!/bin/sh\ncase \"$*\" in\n'--version') echo 'locket {}';;\n'init --no-passkey'|'agent start'|'run test'|'scan --require-known') printf '%s\\n' \"$*\" >> .cli-args;;\n'shared init --json') exit 19;;\n*) exit 20;;\nesac\n",
            env!("CARGO_PKG_VERSION")
        ),
    )
    .expect("fake CLI");
    fs::set_permissions(&cli, fs::Permissions::from_mode(0o700)).expect("executable fake CLI");
    desktop_actions::set_resource_root(bin);

    let snippet = ipc.invoke("desktop_mcp_config_snippet", json!({})).expect("MCP snippet");
    assert_eq!(snippet["command"], json!(cli.canonicalize().expect("resource CLI")));
    assert_eq!(snippet["args"], json!(["mcp"]));
    assert!(ipc.invoke("desktop_copy_text_plain", json!({"text":""})).is_err());
    assert_eq!(
        ipc.invoke("desktop_copy_text_plain", json!({"text":"plain fixture"})),
        Ok(Value::Null)
    );
    assert_eq!(
        ipc.invoke("desktop_copy_text_plain", json!({"text":"refuse clipboard"})),
        Err(json!("clipboard backend error: test refusal"))
    );

    assert!(ipc.request("desktop_open_shared_vault", json!({"project_id": SHARED})).is_err());
    let initialization_error =
        ipc.invoke("desktop_open_shared_vault", json!({})).expect_err("fake shared init fails");
    assert!(initialization_error.to_string().contains("Global Vault needs OS keychain access"));
    vault.add_shared();
    let shared = ipc.invoke("desktop_open_shared_vault", json!({})).expect("open Global Vault");
    assert_eq!(shared["project_id"], SHARED);
    assert!(
        ipc.request("desktop_create_profile", json!({"project_id":SHARED,"profile_name":"new"}))
            .expect_err("rootless profile creation")["reason"]
            .to_string()
            .contains("trusted project folder")
    );
    assert!(ipc.request("desktop_detect_commands", json!({"project_id":SHARED})).is_err());
    assert!(ipc.request("desktop_scan_project", json!({"project_id":SHARED})).is_err());
    assert!(
        ipc.request(
            "desktop_import_env",
            json!({
                "project_id":SHARED,"path":"relative.env","literal":false,"overwrite":false,
            })
        )
        .is_err()
    );

    let inspection = ipc.ok("desktop_inspect_project_folder", json!({"path":vault.root}));
    assert_eq!(inspection["has_config"], true);
    let context = ipc.ok("desktop_initialize_project", json!({"path":vault.root}));
    assert_eq!(context["project_id"], vault.id);
    assert_eq!(context["profile_id"], PROFILE);
    let rows = ipc.invoke("desktop_list_projects", json!({})).expect("registered projects");
    assert_eq!(rows[0]["project_id"], SHARED);
    assert_eq!(rows[1]["project_id"], vault.id);
    assert_eq!(ipc.ok("desktop_start_agent", json!({"project_id":vault.id})), Value::Null);
    assert_eq!(
        ipc.ok("desktop_run_policy", json!({"project_id":vault.id,"policy_name":"test"})),
        json!({"launched":true,"command":"locket run 'test'"})
    );
    assert_eq!(
        ipc.ok("desktop_scan_project", json!({"project_id":vault.id})),
        json!({"launched":true,"command":"locket scan --require-known"})
    );
    assert_eq!(
        fs::read_to_string(vault.root.join(".cli-args")).expect("CLI argv log"),
        "init --no-passkey\nagent start\nrun test\nscan --require-known\n"
    );
    assert!(ipc.request("desktop_open_project", json!({"path":home.join("missing")})).is_err());
    assert!(
        ipc.request("desktop_run_policy", json!({"project_id":vault.id,"policy_name":"-e"}))
            .is_err()
    );
    assert!(ipc.request("desktop_save_policy", json!({})).is_err());

    let results = ipc.ok("desktop_detect_commands", json!({"project_id":vault.id}));
    assert_eq!(results.as_array().expect("detected commands").len(), 2);
    assert!(results.to_string().contains("build"));
    assert!(!results.to_string().contains(TOKEN));
    let readiness = ipc.ok("desktop_variable_readiness", json!({"project_id":vault.id}));
    assert_eq!(readiness["policies"][0]["policy_name"], "test");
    assert_eq!(
        ipc.request(
            "desktop_variable_readiness",
            json!({"project_id":vault.id,"policy_name":"removed-command"})
        ),
        Err(json!("The selected command no longer exists. Refresh commands."))
    );
    assert_eq!(
        ipc.request("desktop_detect_commands", json!({"project_id":"lk_proj_previous"})),
        Err(json!("agent protocol error: The selected project changed. Refresh before retrying.")),
    );
    assert!(
        ipc.request(
            "desktop_copy_secret_to_shared",
            json!({
                "from_project_id":vault.id,"from_profile_id":"old-profile","secret_name":"TOKEN",
            })
        )
        .expect_err("stale profile")["reason"]
            .to_string()
            .contains("active profile changed")
    );

    #[cfg(target_os = "macos")]
    {
        assert_eq!(
            ipc.invoke("desktop_pick_directory", json!({"title":"Path ' \" ; -e"})),
            Ok(json!("/fixture/project folder"))
        );
        assert_eq!(ipc.invoke("desktop_pick_file", json!({"save":false})), Ok(Value::Null));
        assert_eq!(
            ipc.invoke("desktop_pick_file", json!({"save":true,"defaultName":"A B.env"})),
            Ok(json!("/fixture/A B.env"))
        );

        assert_eq!(ipc.invoke("desktop_get_launch_at_login", json!({})), Ok(json!(false)));
        let plist = home.join("Library/LaunchAgents/app.locket.desktop.dev.plist");
        fs::create_dir_all(&plist).expect("non-regular LaunchAgent path");
        for (command, body) in [
            ("desktop_get_launch_at_login", json!({})),
            ("desktop_set_launch_at_login", json!({"enabled":true})),
            ("desktop_set_launch_at_login", json!({"enabled":false})),
        ] {
            assert!(ipc.invoke(command, body).is_err(), "{command}");
        }
        fs::remove_dir(&plist).expect("remove invalid fixture");
        assert_eq!(
            ipc.invoke("desktop_set_launch_at_login", json!({"enabled":true})),
            Ok(json!(true))
        );
        assert!(plist.is_file());
        assert_eq!(ipc.invoke("desktop_get_launch_at_login", json!({})), Ok(json!(true)));
        assert_eq!(
            ipc.invoke("desktop_set_launch_at_login", json!({"enabled":false})),
            Ok(json!(false))
        );
        assert!(!plist.exists());
    }
}

fn live_agent_commands(ipc: &Ipc, vault: &Vault) {
    let project = json!({"project_id":vault.id});
    let request = json!({"project_id":vault.id,"profile_id":PROFILE});
    let status = ipc.invoke("agent_status", json!({})).expect("live locked status");
    assert_eq!(status["agent_version"], "isolated-desktop-agent");
    assert_eq!(status["lock_state"], "locked");
    assert_eq!(ipc.ok("desktop_open_project", json!({"path":vault.root}))["project_id"], vault.id);
    assert_eq!(ipc.ok("agent_list_secrets", request.clone())["rows"], json!([]));
    assert_eq!(
        ipc.ok(
            "agent_list_policies",
            json!({
                "project_id":vault.id, "privacy_redact_names":true,
            })
        )["rows"],
        json!([])
    );
    assert_eq!(
        ipc.ok(
            "agent_list_runtime_sessions",
            json!({
                "project_id":vault.id,"profile_id":PROFILE,"privacy_redact_names":true,
            })
        )["rows"],
        json!([])
    );
    assert_eq!(ipc.ok("agent_list_audit", project.clone())["rows"], json!([]));
    assert_eq!(
        ipc.ok(
            "agent_list_versions",
            json!({
                "project_id":vault.id,"profile_id":PROFILE,"now_unix_nanos":0,
            })
        )["rows"],
        json!([]),
    );
    assert_eq!(ipc.ok("agent_list_device_members", project.clone())["rows"], json!([]));
    assert_eq!(ipc.ok("agent_read_config", json!({}))["privacy_redact_names"], false);
    let projects = ipc.ok("agent_list_projects", json!({"redact_names":true}));
    assert_eq!(projects["projects"].as_array().expect("project summaries").len(), 2);
    assert!(!projects.to_string().contains("Fixture"));
    assert!(!projects.to_string().contains("not-a-program"));
    assert_eq!(
        ipc.ok("agent_discover_secrets", json!({"project":vault.id})),
        json!({"secrets":[]})
    );
    let fallback = ipc.rejected(
        "agent_unlock",
        json!({
            "project_id":"lk_proj_missing_passphrase","ttl_seconds":90,
            "source":{"kind":"passphrase","passphrase":TOKEN},
        }),
        "UnlockRequired",
    );
    assert_eq!(
        fallback["message"],
        "no passphrase fallback envelope is registered for this project"
    );
    assert!(!fallback.to_string().contains(TOKEN));

    let create = json!({"project_id":vault.id,"profile_name":"staging"});
    let delete = json!({"project_id":vault.id,"profile_id":PROFILE,"secret_name":"TOKEN","source":"user-local"});
    let copy = json!({"from_project_id":vault.id,"from_profile_id":PROFILE,"secret_name":"TOKEN"});
    ipc.rejected("desktop_create_profile", create.clone(), "UnlockRequired");
    ipc.rejected("desktop_delete_secret", delete.clone(), "UnlockRequired");
    let locked = ipc.rejected("desktop_copy_secret_to_shared", copy.clone(), "UnlockRequired");
    assert_eq!(locked["display_reason"], locked["message"]);
    assert!(ipc.request("desktop_team_sync_configure", project.clone()).is_err());
    ipc.rejected(
        "desktop_team_sync_test_remote",
        json!({"project_id":vault.id,"grant_id":"webview-supplied-grant"}),
        "UnlockRequired",
    );

    ipc.ok(
        "agent_unlock",
        json!({"project_id":vault.id,"ttl_seconds":90,"source":{"kind":"os-keychain"}}),
    );
    assert_eq!(
        ipc.invoke("agent_status", json!({})).expect("unlocked status")["lock_state"],
        "unlocked"
    );
    ipc.rejected(
        "desktop_create_profile",
        json!({"project_id":vault.id,"profile_name":"/bad"}),
        "InvalidProfileName",
    );
    assert_eq!(
        ipc.ok("agent_set_active_profile", json!({"project_id":vault.id,"profile_name":"dev"}))["profile_id"],
        PROFILE
    );

    live_crud(ipc, vault, &create, &delete, &copy);

    ipc.invoke("agent_lock", json!({})).expect("lock");
    assert_eq!(
        ipc.invoke("agent_status", json!({})).expect("locked via IPC")["lock_state"],
        "locked"
    );

    assert_eq!(ipc.invoke("tray_set_state", json!({"state":"agent-locked"})), Ok(Value::Null));
    for _ in 0..2 {
        assert_eq!(
            ipc.invoke(
                "tray_set_selection",
                json!({
                    "selection":{"vault_unlocked":true,"secret_selected":true},
                })
            ),
            Ok(Value::Null)
        );
        assert_eq!(ipc.invoke("tray_set_privacy_context", json!({
            "context":{"project_id":vault.id,"profile_name":"dev","privacy_redact_names":true},
        })), Ok(Value::Null));
    }
}

fn live_crud(ipc: &Ipc, vault: &Vault, create: &Value, delete: &Value, copy: &Value) {
    let original = fs::read(vault.root.join("locket.toml")).expect("original config");
    let created = ipc.ok("desktop_create_profile", create.clone());
    assert_eq!(created["created"], true);
    assert_eq!(created["profile_name"], "staging");
    assert_eq!(created["dangerous"], false);
    let db = Store::open(&vault.store).expect("test store");
    let profile = db
        .get_profile_by_name(&vault.id, "staging")
        .expect("get durable profile")
        .expect("staging profile");
    assert_eq!(created["profile_id"], profile.id);
    assert_eq!(fs::read(vault.root.join("locket.toml")).expect("config"), original);
    ipc.rejected("desktop_create_profile", create.clone(), "SecretAlreadyExists");

    let imported = ipc.ok(
        "desktop_import_env",
        json!({
            "project_id":vault.id,"path":".env","overwrite":false,"literal":true,
        }),
    );
    assert_eq!(
        imported["summary"],
        "Imported 1, overwritten 0, skipped 0. Original file preserved."
    );
    let inventory = ipc.ok(
        "agent_list_secrets",
        json!({"project_id":vault.id,"profile_id":PROFILE,"redact_names":true}),
    );
    let redacted_row = &inventory["rows"][0];
    assert_ne!(redacted_row["name"], "TOKEN");
    assert_eq!(
        ipc.ok(
            "agent_reveal",
            json!({
                "project_id":vault.id,"profile_id":PROFILE,
                "secret_id":redacted_row["id"],"secret_name":redacted_row["name"],
            })
        )["value"],
        TOKEN
    );
    let target_locked =
        ipc.rejected("desktop_copy_secret_to_shared", copy.clone(), "UnlockRequired");
    assert_eq!(
        target_locked["display_reason"],
        "unlock the Global Vault before copying the secret"
    );
    ipc.ok(
        "agent_unlock",
        json!({
            "project_id":SHARED,"ttl_seconds":90,"source":{"kind":"os-keychain"},
        }),
    );

    for (command, request) in
        [("desktop_delete_secret", delete), ("desktop_copy_secret_to_shared", copy)]
    {
        let mut invalid = request.clone();
        invalid["secret_name"] = json!("/invalid");
        ipc.rejected(command, invalid, "InvalidSecretName");
        let mut forged = request.clone();
        forged["binding"] = json!({"pid":0});
        assert!(
            ipc.request(command, forged)
                .expect_err("forged binding")
                .as_str()
                .is_some_and(|error| error.contains("unknown field"))
        );
    }

    vault.dangerous(true);
    for (command, request) in
        [("desktop_delete_secret", delete), ("desktop_copy_secret_to_shared", copy)]
    {
        let mut unconfirmed = request.clone();
        unconfirmed["confirmation"] = json!("DEV");
        ipc.rejected(command, unconfirmed, "ConfirmationFailed");
    }
    let safe_profile = ipc.ok(
        "desktop_create_profile",
        json!({
            "project_id":vault.id,"profile_name":"preview",
        }),
    );
    assert_eq!(safe_profile["dangerous"], false);

    let mut copy = copy.clone();
    copy["confirmation"] = json!("dev");
    let copied = ipc.ok("desktop_copy_secret_to_shared", copy.clone());
    assert_eq!(copied["target_project_id"], SHARED);
    assert_eq!(copied["target_profile_id"], SHARED_PROFILE);
    assert_eq!(copied["version"], 1);
    assert!(copied.get("value").is_none());
    ipc.rejected("desktop_copy_secret_to_shared", copy.clone(), "SecretAlreadyExists");
    copy["overwrite"] = json!(true);
    assert_eq!(ipc.ok("desktop_copy_secret_to_shared", copy)["version"], 2);

    let target = db
        .get_active_secret(SHARED, SHARED_PROFILE, "TOKEN", "user-local")
        .expect("destination lookup")
        .expect("copied secret");
    live_shared_links(ipc, vault, &db, &target.id);

    let mut delete = delete.clone();
    delete["confirmation"] = json!("dev");
    let deleted = ipc.ok("desktop_delete_secret", delete.clone());
    assert_eq!(
        deleted,
        json!({
            "secret_name":"TOKEN","source":"user-local","version":1,"deleted":true,
        })
    );
    ipc.rejected("desktop_delete_secret", delete, "SecretNotFound");
    for command in ["agent_reveal", "agent_copy_secret"] {
        assert_eq!(
            ipc.request(
                command,
                json!({
                    "project_id":vault.id,"profile_id":PROFILE,
                    "secret_id":redacted_row["id"],"secret_name":redacted_row["name"],
                })
            ),
            Err(json!({
                "kind":"protocol",
                "reason":"The selected secret changed. Refresh Secrets before retrying.",
            }))
        );
    }
    assert!(
        db.get_active_secret(&vault.id, PROFILE, "TOKEN", "user-local")
            .expect("source lookup")
            .is_none()
    );
    assert!(
        db.get_active_secret(SHARED, SHARED_PROFILE, "TOKEN", "user-local")
            .expect("destination lookup")
            .is_some()
    );
    assert!(
        db.verify_audit_chain_read_only(&vault.id, &[7; 32]).expect("source audit chain").hmac_ok
    );
    assert!(db.verify_audit_chain_read_only(SHARED, &[7; 32]).expect("target audit chain").hmac_ok);
    vault.dangerous(false);
}

fn live_shared_links(ipc: &Ipc, vault: &Vault, db: &Store, target_id: &str) {
    let local = json!({
        "project_id":vault.id,"profile_id":PROFILE,"local_name":"LINKED_TOKEN",
    });
    let mut link = local.clone();
    link["target_secret_name"] = json!("TOKEN");
    ipc.rejected("desktop_link_secret", link.clone(), "ConfirmationFailed");
    link["confirmation"] = json!("dev");
    let linked = ipc.ok("desktop_link_secret", link);
    assert_eq!(linked["target_secret_id"], target_id);
    assert_eq!(linked["local_name"], "LINKED_TOKEN");

    let request = json!({"target_secret_id":target_id,"redact_names":true});
    let usages = ipc.ok("desktop_list_shared_usages", request);
    assert_eq!(usages["usages"][0]["link_id"], linked["link_id"]);
    assert_ne!(usages["usages"][0]["local_name"], "LINKED_TOKEN");
    assert_ne!(usages["usages"][0]["target_secret_name"], "TOKEN");

    let source = db
        .get_active_secret(&vault.id, PROFILE, "TOKEN", "user-local")
        .expect("source lookup")
        .expect("source secret");
    // Cross-vault dedup indexing depends on a system keyring key. Seed the
    // two matching local indexes explicitly for this isolated store.
    db.upsert_local_value_fingerprint(&source.id, 1, &[10; 32], 1).expect("source fingerprint");
    db.upsert_local_value_fingerprint(target_id, 2, &[10; 32], 1).expect("target fingerprint");
    let duplicates = ipc.invoke("desktop_list_duplicates", json!({})).expect("duplicate groups");
    assert_eq!(duplicates["groups"][0]["members"].as_array().expect("duplicate members").len(), 2);
    let redacted = ipc.ok("desktop_list_duplicates", json!({"redact_names":true}));
    assert!(!redacted.to_string().contains("TOKEN"));

    let mut unlink = local.clone();
    unlink["confirmation"] = json!("dev");
    assert_eq!(ipc.ok("desktop_unlink_secret", unlink)["unlinked"], true);
    assert_eq!(
        ipc.ok("desktop_list_shared_usages", json!({"target_secret_id":target_id})),
        json!({"usages":[]})
    );
}

enum Reply {
    Success(Value),
    Error(&'static str, &'static str),
}

struct Exchange {
    method: AgentMethod,
    fields: Value,
    reply: Reply,
}

impl Exchange {
    fn success(method: AgentMethod, fields: Value, response: Value) -> Self {
        Self { method, fields, reply: Reply::Success(response) }
    }

    fn reject(method: AgentMethod, fields: Value, code: &'static str) -> Self {
        Self { method, fields, reply: Reply::Error(code, "fixture request rejected") }
    }
}

async fn read_request(stream: &mut UnixStream) -> RequestEnvelope {
    let len = stream.read_u32_le().await.expect("read request length") as usize;
    assert!(len <= DEFAULT_MAX_MESSAGE_SIZE);
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await.expect("read request body");
    serde_json::from_slice(&bytes).expect("decode request")
}

fn with_exchanges(socket: &Path, exchanges: Vec<Exchange>, run: impl FnOnce()) {
    let runtime = tauri::async_runtime::handle();
    let listener = {
        let _entered = runtime.inner().enter();
        UnixListener::bind(socket).expect("bind scripted agent")
    };
    let server = runtime.inner().spawn(async move {
        for expected in exchanges {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let request = read_request(&mut stream).await;
            assert_eq!(request.method().ok(), Some(expected.method));
            if matches!(
                expected.method,
                AgentMethod::TeamSyncConfigure | AgentMethod::TeamSyncTestRemote
            ) {
                assert_eq!(request.payload, expected.fields);
            } else {
                for (key, value) in expected.fields.as_object().expect("expected request fields") {
                    assert_eq!(
                        request.payload.get(key),
                        Some(value),
                        "{:?}.{key}",
                        expected.method
                    );
                }
            }
            let response = match expected.reply {
                Reply::Success(payload) => {
                    ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), payload))
                }
                Reply::Error(code, message) => ResponseEnvelope::Error(ErrorEnvelope::new(
                    request.id.clone(),
                    code,
                    message,
                    false,
                )),
            };
            stream
                .write_all(&encode_frame(&response, DEFAULT_MAX_MESSAGE_SIZE).expect("response"))
                .await
                .expect("write response");
        }
    });
    run();
    tauri::async_runtime::block_on(async {
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("all expected exchanges happened")
            .expect("server assertions");
    });
    fs::remove_file(socket).expect("remove fixture socket");
}

fn native_grant_exchanges(
    vault: &Vault,
    action: &str,
    profile: &str,
    confirm: bool,
    mut operation: Exchange,
) -> Vec<Exchange> {
    let binding = json!(desktop_actions::native_binding().expect("native binding"));
    let grant = "desktop-ipc-grant";
    operation.fields["project_id"] = json!(vault.id);
    operation.fields["grant_id"] = json!(grant);
    operation.fields["binding"] = binding.clone();
    vec![
        Exchange::success(
            AgentMethod::RequestGrant,
            json!({
                "project_id":vault.id,"profile_id":profile,"action":action,
                "binding":binding,"confirm_dangerous":confirm,"ttl_seconds":30,
            }),
            json!({"grant_id":grant}),
        ),
        operation,
        Exchange::success(AgentMethod::RevokeGrant, json!({"grant_id":grant}), Value::Null),
    ]
}

fn wire_command_contracts(ipc: &Ipc, vault: &Vault, socket: &Path) {
    let create = json!({"project_id":vault.id,"profile_name":"staging"});
    let delete = json!({
        "project_id":vault.id,"profile_id":PROFILE,"secret_name":"TOKEN","source":"user-local","confirmation":"dev",
    });
    let copy = json!({
        "from_project_id":vault.id,"from_profile_id":PROFILE,"secret_name":"TOKEN","overwrite":true,"confirmation":"dev",
    });
    for (command, request, method, action, fields, response, confirmed) in [
        (
            "desktop_create_profile",
            create,
            AgentMethod::CreateProfile,
            "CreateProfile",
            json!({"profile_name":"staging"}),
            json!({"profile_id":"lk_prof_staging","profile_name":"staging","dangerous":false,"created":true}),
            false,
        ),
        (
            "desktop_delete_secret",
            delete,
            AgentMethod::DeleteSecret,
            "DeleteSecret",
            json!({"secret_name":"TOKEN","source":"user-local","confirmation":"dev"}),
            json!({"secret_name":"TOKEN","source":"user-local","version":2,"deleted":true}),
            true,
        ),
        (
            "desktop_copy_secret_to_shared",
            copy,
            AgentMethod::CopySecretToShared,
            "CopySecretToShared",
            json!({"secret_name":"TOKEN","source":null,"overwrite":true,"confirmation":"dev"}),
            json!({"target_project_id":SHARED,"target_profile_id":SHARED_PROFILE,"secret_name":"TOKEN","version":3,"action":"rotate"}),
            true,
        ),
    ] {
        let mut fields = fields;
        fields["project_root"] = json!(vault.root);
        fields["store_path"] = json!(vault.store);
        fields["profile_id"] = json!(PROFILE);
        let operation = Exchange::success(method, fields, response.clone());
        with_exchanges(
            socket,
            native_grant_exchanges(vault, action, PROFILE, confirmed, operation),
            || {
                let value = ipc.ok(command, request);
                assert_eq!(value, response);
                assert!(!value.to_string().contains(TOKEN));
            },
        );
    }

    let policy = json!(super::tests::sample_policy());
    let scope = json!({"project_id":vault.id,"profile_id":PROFILE});
    with_exchanges(
        socket,
        vec![
            Exchange::reject(
                AgentMethod::ResolveReference,
                json!({"reference":"lk://dev/TOKEN"}),
                "GrantRequired",
            ),
            Exchange::reject(
                AgentMethod::ScanKnownValues,
                json!({"require_known":true}),
                "UnlockRequired",
            ),
            Exchange::reject(
                AgentMethod::PrepareExec,
                json!({"policy_name":"test","confirm_dangerous":false}),
                "GrantRequired",
            ),
            Exchange::reject(
                AgentMethod::WriteConfig,
                json!({"config_path":default_config_path().expect("config"), "store_path":vault.store}),
                "UnlockRequired",
            ),
            Exchange::success(
                AgentMethod::VerifyAudit,
                json!({"store_path":vault.store,"project_id":vault.id}),
                json!({"hmac_ok":null,"first_break_sequence":null,"first_break_reason":null,"rows_verified":0,"locked":true}),
            ),
            Exchange::reject(
                AgentMethod::PolicyDoctor,
                json!({"policy":policy,"store_path":vault.store}),
                "AccessDenied",
            ),
            Exchange::success(
                AgentMethod::RegisterCommandPolicies,
                json!({"policies":[],"store_path":vault.store}),
                Value::Null,
            ),
            Exchange::reject(
                AgentMethod::VerifyBundle,
                json!({"bundle_path":vault.root.join("absent.locket")}),
                "InvalidBundle",
            ),
            Exchange::reject(
                AgentMethod::RecoveryRotate,
                json!({"verification":"current-code","clear_after_display":true}),
                "UnlockRequired",
            ),
            Exchange::success(AgentMethod::TeamSyncStatus, scope, json!({"state":"waiting"})),
        ],
        || {
            ipc.rejected("agent_resolve", json!({"reference":"lk://dev/TOKEN"}), "GrantRequired");
            ipc.rejected("agent_scan", json!({"require_known":true}), "UnlockRequired");
            ipc.rejected(
                "agent_prepare_exec",
                json!({
                    "project_id":vault.id,"profile_id":PROFILE,"policy_name":"test",
                }),
                "GrantRequired",
            );
            ipc.rejected("agent_write_config", json!({"project_id":vault.id}), "UnlockRequired");
            assert_eq!(
                ipc.ok("agent_verify_audit", json!({"project_id":vault.id}))["locked"],
                true
            );
            ipc.rejected(
                "agent_policy_doctor",
                json!({
                    "project_id":vault.id,"profile_id":PROFILE,"policy":policy,
                }),
                "AccessDenied",
            );
            assert_eq!(
                ipc.ok(
                    "agent_register_command_policies",
                    json!({"project_id":vault.id,"policies":[]})
                ),
                Value::Null
            );
            ipc.rejected(
                "agent_verify_bundle",
                json!({"bundle_path":vault.root.join("absent.locket")}),
                "InvalidBundle",
            );
            ipc.rejected("agent_recovery_rotate", json!({
            "project_id":vault.id,"verification":"current-code","current_recovery_code":"fixture code",
            "acknowledged_one_time_display":true,"clear_after_display":true,
        }), "UnlockRequired");
            assert_eq!(
                ipc.ok("desktop_team_sync_status", json!({"project_id":vault.id}))["state"],
                "waiting"
            );
        },
    );

    wire_granted_actions(ipc, vault, socket, policy);
    wire_team_sync_delivery(ipc, vault, socket);
    dangerous_actions_require_typed_name(ipc, vault);
    clipboard_uses_agent_ttl(ipc, vault, socket);
}

fn wire_granted_actions(ipc: &Ipc, vault: &Vault, socket: &Path, policy: Value) {
    use locket_agent::BUNDLE_PROJECT_GRANT_SCOPE;
    let access =
        json!({"secret_name":"TOKEN","profile_id":PROFILE,"confirm_dangerous_profile":"dev"});
    let set = json!({
        "project_id":vault.id,"profile_id":PROFILE,"secret_name":"TOKEN","value":TOKEN,
        "confirm_dangerous_profile":"dev","source":"user-local","grace_until":7,
    });
    for (command, method, action, request, fields, response, confirm, profile) in [
        (
            "agent_reveal",
            AgentMethod::Reveal,
            "Reveal",
            access,
            json!({"store_path":vault.store,"secret_name":"TOKEN","profile_id":PROFILE}),
            json!({"value":TOKEN,"ttl_seconds":23}),
            true,
            PROFILE,
        ),
        (
            "agent_set_secret",
            AgentMethod::SetSecret,
            "SetSecret",
            set.clone(),
            json!({"secret_name":"TOKEN","value":TOKEN,"rotate":false,"profile_id":PROFILE}),
            json!({"action":"create","secret_id":"fixture-token","version":1,"source":"user-local"}),
            true,
            PROFILE,
        ),
        (
            "agent_rotate_secret",
            AgentMethod::SetSecret,
            "SetSecret",
            set,
            json!({"secret_name":"TOKEN","value":TOKEN,"rotate":true,"grace_until":7}),
            json!({"action":"rotate","secret_id":"fixture-token","version":2,"source":"user-local"}),
            true,
            PROFILE,
        ),
        (
            "agent_export_bundle",
            AgentMethod::ExportBundle,
            "Export",
            json!({
                "project_id":vault.id,"recipient_descriptor":"test","scope":"active-profile",
                "include_audit":false,"confirm_dangerous_profile":"dev",
            }),
            json!({"profile_id":PROFILE,"confirm_dangerous":true}),
            json!({"action":"export","status":"done","message":"sealed"}),
            true,
            PROFILE,
        ),
        (
            "agent_import_bundle",
            AgentMethod::ImportBundle,
            "ImportDotenv",
            json!({
                "project_id":vault.id,"bundle_path":vault.root.join("test.locket"),
                "include_audit":false,"conflict_mode":"review",
            }),
            json!({"conflict_mode":"review"}),
            json!({"action":"import","status":"review","message":"pending"}),
            false,
            BUNDLE_PROJECT_GRANT_SCOPE,
        ),
        (
            "desktop_save_policy",
            AgentMethod::ApplyPolicy,
            "ApplyPolicy",
            json!({
                "project_id":vault.id,"mode":"edit","original_name":"test","policy":policy,
            }),
            json!({"project_root":vault.root,"profile_id":PROFILE,"mode":"edit"}),
            json!({"policy_name":"test","operation":"edit"}),
            false,
            PROFILE,
        ),
        (
            "desktop_team_sync_configure",
            AgentMethod::TeamSyncConfigure,
            "TeamSync",
            json!({
                "project_id":vault.id,"folder":vault.root.join("shared"),"allow_dangerous":true,
                "confirm_dangerous_profile":"dev",
            }),
            json!({
                "profile_id":PROFILE,"store_path":vault.store,
                "folder":vault.root.join("shared"),"allow_dangerous":true,
            }),
            json!({"state":"configured"}),
            true,
            PROFILE,
        ),
        (
            "desktop_team_sync_now",
            AgentMethod::TeamSyncNow,
            "TeamSync",
            json!({"project_id":vault.id}),
            json!({"profile_id":PROFILE}),
            json!({"state":"synchronized"}),
            false,
            PROFILE,
        ),
    ] {
        vault.dangerous(confirm);
        let exchanges = native_grant_exchanges(
            vault,
            action,
            profile,
            confirm,
            Exchange::success(method, fields, response.clone()),
        );
        with_exchanges(socket, exchanges, || {
            assert_eq!(
                ipc.ok(command, request),
                if command == "desktop_save_policy" { Value::Null } else { response }
            );
        });
    }

    vault.dangerous(false);
    for warning in [None, Some("Refresh policy metadata.")] {
        let response = json!({
            "imported":1,"overwritten":2,"skipped":3,"original_preserved":true,
            "diagnostics":[],"maintenance_warning":warning,
        });
        let operation = Exchange::success(
            AgentMethod::ImportDotenv,
            json!({
                "env_path":".env","project_root":vault.root,"profile_id":PROFILE,
                "overwrite":false,"literal":true,"store_path":vault.store,
            }),
            response,
        );
        with_exchanges(
            socket,
            native_grant_exchanges(vault, "ImportDotenv", PROFILE, false, operation),
            || {
                let result = ipc.ok(
                    "desktop_import_env",
                    json!({
                        "project_id":vault.id,"path":".env","overwrite":false,"literal":true,
                    }),
                );
                let mut expected =
                    "Imported 1, overwritten 2, skipped 3. Original file preserved.".to_string();
                if let Some(warning) = warning {
                    expected.push(' ');
                    expected.push_str(warning);
                }
                assert_eq!(result["summary"], expected);
                assert_eq!(
                    fs::read_to_string(vault.root.join(".env")).expect("preserved dotenv"),
                    format!("TOKEN={TOKEN}\n")
                );
            },
        );
    }

    for (command, action_fields) in [
        (
            "desktop_team_sync_rename_profile",
            json!({"local_profile_id":PROFILE,"new_name":"test-next"}),
        ),
        ("desktop_team_sync_preserve_override", json!({"local_secret_id":"fixture-token"})),
    ] {
        let mut request = action_fields.clone();
        request["project_id"] = json!(vault.id);
        request["incoming_profile_id"] = json!("incoming");
        request["confirm_dangerous_profile"] = json!("dev");
        let mut action = action_fields;
        action["kind"] = json!(if command == "desktop_team_sync_rename_profile" {
            "rename_profile"
        } else {
            "preserve_override"
        });
        let operation = Exchange::reject(
            AgentMethod::TeamSyncReconcile,
            json!({
                "incoming_profile_id":"incoming","profile_id":PROFILE,"action":action,
            }),
            "AccessDenied",
        );
        with_exchanges(
            socket,
            native_grant_exchanges(vault, "TeamSync", PROFILE, true, operation),
            || {
                ipc.rejected(command, request, "AccessDenied");
            },
        );
    }
}

fn team_sync_remote_transports() -> [Value; 2] {
    [
        json!({
            "kind":"s3","bucket":"fixture","region":"auto","prefix":"team",
            "endpoint":"https://s3.example.test","path_style":true,"credential_mode":"vault",
            "access_key_id":"fixture-access-id","secret_access_key":TOKEN,
            "session_token":"fixture-session-token",
        }),
        json!({
            "kind":"webdav","url":"https://webdav.example.test/team","credential_mode":"vault",
            "auth_kind":"bearer","username":null,"secret":TOKEN,
        }),
    ]
}

fn wire_team_sync_delivery(ipc: &Ipc, vault: &Vault, socket: &Path) {
    vault.dangerous(false);
    let [s3, webdav] = team_sync_remote_transports();
    for (transport, allow_dangerous) in [(&s3, true), (&webdav, false)] {
        let mut request = json!({"project_id":vault.id,"transport":transport});
        if allow_dangerous {
            request["allow_dangerous"] = json!(true);
            request["confirm_dangerous_profile"] = json!("dev");
        }
        let response = json!({"state":"configured","transport_kind":transport["kind"]});
        let operation = Exchange::success(
            AgentMethod::TeamSyncConfigure,
            json!({
                "profile_id":PROFILE,"store_path":vault.store,"transport":transport,
                "allow_dangerous":allow_dangerous,
            }),
            response.clone(),
        );
        with_exchanges(
            socket,
            native_grant_exchanges(vault, "TeamSync", PROFILE, allow_dangerous, operation),
            || assert_eq!(ipc.ok("desktop_team_sync_configure", request), response),
        );
    }

    for (kind, transport) in [("s3", None), ("s3", Some(s3)), ("webdav", Some(webdav))] {
        let mut request = json!({"project_id":vault.id});
        let mut fields = json!({"profile_id":PROFILE,"store_path":vault.store});
        let confirmed = transport.is_some();
        vault.dangerous(confirmed);
        if let Some(transport) = transport {
            request["confirm_dangerous_profile"] = json!("dev");
            request["transport"] = transport.clone();
            fields["transport"] = transport;
        }
        let metadata = json!({
            "ok":true,"transport_kind":kind,"target":"fixture-target","package_count":3,
            "writable_checked":false,"message":"Package listing succeeded",
        });
        let mut agent_response = metadata.clone();
        agent_response["secret"] = json!(TOKEN);
        let operation = Exchange::success(AgentMethod::TeamSyncTestRemote, fields, agent_response);
        with_exchanges(
            socket,
            native_grant_exchanges(vault, "TeamSync", PROFILE, confirmed, operation),
            || assert_eq!(ipc.ok("desktop_team_sync_test_remote", request), metadata),
        );
    }

    vault.dangerous(false);
    let operation = Exchange::reject(
        AgentMethod::TeamSyncTestRemote,
        json!({"profile_id":PROFILE,"store_path":vault.store}),
        "GrantRequired",
    );
    with_exchanges(
        socket,
        native_grant_exchanges(vault, "TeamSync", PROFILE, false, operation),
        || {
            ipc.rejected(
                "desktop_team_sync_test_remote",
                json!({"project_id":vault.id}),
                "GrantRequired",
            );
        },
    );

    for dangerous in [false, true] {
        vault.dangerous(dangerous);
        let mut request = json!({"project_id":vault.id});
        if dangerous {
            request["confirm_dangerous_profile"] = json!("dev");
        }
        let response = json!({
            "state":"verified","epoch":3,"owner_fingerprint":"fixture-owner",
            "folder":null,"remote_target":null,
        });
        let operation = Exchange::success(
            AgentMethod::TeamSyncClear,
            json!({"profile_id":PROFILE,"store_path":vault.store}),
            response.clone(),
        );
        with_exchanges(
            socket,
            native_grant_exchanges(vault, "TeamSync", PROFILE, dangerous, operation),
            || assert_eq!(ipc.ok("desktop_team_sync_clear", request), response),
        );
    }
}

fn dangerous_actions_require_typed_name(ipc: &Ipc, vault: &Vault) {
    vault.dangerous(true);
    let access = json!({"project_id":vault.id,"profile_id":PROFILE,"secret_name":"TOKEN"});
    let mut set = access.clone();
    set["value"] = json!(TOKEN);
    for (command, request) in [
        ("agent_reveal", access.clone()),
        ("agent_copy_secret", access),
        ("agent_set_secret", set.clone()),
        ("agent_rotate_secret", set),
        (
            "agent_prepare_exec",
            json!({
                "project_id":vault.id,"profile_id":PROFILE,"policy_name":"test",
            }),
        ),
        ("desktop_team_sync_now", json!({"project_id":vault.id})),
        ("desktop_team_sync_test_remote", json!({"project_id":vault.id})),
        ("desktop_team_sync_clear", json!({"project_id":vault.id})),
        (
            "agent_export_bundle",
            json!({
                "project_id":vault.id,"recipient_descriptor":"test","scope":"active-profile",
                "include_audit":false,
            }),
        ),
        (
            "agent_import_bundle",
            json!({
                "project_id":vault.id,"bundle_path":vault.root.join("test.locket"),
                "include_audit":false,"conflict_mode":"review",
            }),
        ),
    ] {
        for confirmation in [None, Some(""), Some("DEV"), Some("dev ")] {
            let mut request = request.clone();
            request["confirm_dangerous"] = json!(true);
            if let Some(typed) = confirmation {
                request["confirm_dangerous_profile"] = json!(typed);
            }
            // The scripted agent is offline. Native denial must happen before any RPC.
            let error = ipc.rejected(command, request, "ConfirmationFailed");
            assert_eq!(
                error["message"],
                "Type the exact active profile name to confirm this action."
            );
        }
    }
    let [s3, webdav] = team_sync_remote_transports();
    for dangerous in [true, false] {
        vault.dangerous(dangerous);
        // Automatic dangerous-profile sync requires exact confirmation even on a safe active profile.
        for (field, value) in [
            ("folder", json!(vault.root.join("shared"))),
            ("transport", s3.clone()),
            ("transport", webdav.clone()),
        ] {
            for confirmation in [None, Some(""), Some("DEV"), Some("dev ")] {
                let mut request = json!({
                    "project_id":vault.id,"allow_dangerous":true,"confirm_dangerous":true,
                });
                request[field] = value.clone();
                if let Some(typed) = confirmation {
                    request["confirm_dangerous_profile"] = json!(typed);
                }
                let error =
                    ipc.rejected("desktop_team_sync_configure", request, "ConfirmationFailed");
                assert_eq!(
                    error["message"],
                    "Type the exact active profile name to confirm this action."
                );
            }
        }
    }
    for request in [
        json!({"project_id":vault.id}),
        json!({"project_id":vault.id,"folder":vault.root.join("shared"),"transport":s3}),
    ] {
        assert_eq!(
            ipc.request("desktop_team_sync_configure", request),
            Err(json!({"kind":"protocol","reason":"Choose exactly one team sync transport."})),
        );
    }
}

fn clipboard_uses_agent_ttl(ipc: &Ipc, vault: &Vault, socket: &Path) {
    vault.dangerous(true);
    for (requested, agent_ttl, expected_ttl, expected_error) in [
        (None, 0, 0, None),
        (Some(8), 7, 7, None),
        (Some(u32::MAX), 7, 7, None),
        (None, 600, 300, None),
        (None, 8, 8, Some("clipboard write failed: clipboard backend error: test refusal")),
    ] {
        let operation = Exchange::success(
            AgentMethod::Copy,
            json!({"secret_name":"TOKEN","store_path":vault.store,"profile_id":PROFILE}),
            json!({"value":TOKEN,"ttl_seconds":agent_ttl}),
        );
        with_exchanges(
            socket,
            native_grant_exchanges(vault, "Copy", PROFILE, true, operation),
            || {
                let result = ipc.request(
                    "agent_copy_secret",
                    json!({
                        "secret_name":"TOKEN","profile_id":PROFILE,"ttl_seconds":requested,
                        "confirm_dangerous_profile":"dev",
                    }),
                );
                if let Some(reason) = expected_error {
                    assert_eq!(result, Err(json!({"kind":"protocol","reason":reason})));
                } else {
                    assert_eq!(result, Ok(json!({"kind":"copied","ttl_seconds":expected_ttl})));
                }
            },
        );
    }
    vault.dangerous(false);
}
