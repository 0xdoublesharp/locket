//! Security-shape regressions for the Tauri 2 desktop shell.
//!
//! These tests pin the release Content-Security-Policy, the deny-by-default
//! capability set, and the scoped IPC surface against the load-bearing
//! `ReleaseWebviewPolicy::default()` descriptor in `locket-app`. A future
//! change to either the Tauri config or the descriptor breaks here, in CI,
//! before the release build can drift.
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

// Pull dev-deps into the integration test target so `unused_crate_dependencies`
// stays quiet for crates referenced only via path lookups below.
use arboard as _;
use base64 as _;
use directories as _;
use locket_agent as _;
use locket_core as _;
use locket_desktop_lib as _;
use locket_platform as _;
use locket_store as _;
use serde as _;
use sha2 as _;
use tauri as _;
use tempfile as _;
use thiserror as _;
use tokio as _;
use toml as _;
use zeroize as _;

use std::fs;
use std::path::{Path, PathBuf};

use locket_app::{CapabilityAccess, ReleaseWebviewPolicy};
use serde_json::Value;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(rel: &str) -> Value {
    let path: PathBuf = crate_root().join(rel);
    let raw = read_text_path(&path);
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("parse json {}: {err}", path.display()))
}

fn read_text(rel: &str) -> String {
    read_text_path(&crate_root().join(rel))
}

fn read_text_path(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn handler_command_names(source: &str) -> std::collections::BTreeSet<String> {
    let handler_marker = "tauri::generate_handler![";
    assert!(
        source.contains(handler_marker),
        "src/lib.rs must register commands via tauri::generate_handler!",
    );
    let occurrences = source.matches(handler_marker).count();
    assert_eq!(
        occurrences, 1,
        "src/lib.rs must register commands through exactly one generate_handler! call",
    );
    let handler_section = source
        .split_once(handler_marker)
        .and_then(|(_, after)| after.split_once(']'))
        .map(|(inside, _)| inside)
        .expect("could not isolate generate_handler! contents");
    handler_section
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|path| path.rsplit("::").next().unwrap_or(path).to_owned())
        .collect()
}

fn attributed_command_names(source: &str) -> std::collections::BTreeSet<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut commands = std::collections::BTreeSet::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || !trimmed.contains("#[tauri::command") {
            continue;
        }

        let function_line = lines
            .iter()
            .skip(idx + 1)
            .map(|line| line.trim_start().strip_prefix("pub(crate) ").unwrap_or(line.trim_start()))
            .find(|line| line.starts_with("async fn ") || line.starts_with("fn "))
            .unwrap_or_else(|| panic!("missing function after command attribute near line {idx}"));
        let name_start = function_line
            .find("fn ")
            .map(|pos| pos + "fn ".len())
            .expect("command function line must contain fn");
        let function_name = function_line[name_start..]
            .split_once('(')
            .map(|(name, _)| name.trim())
            .expect("command function line must include an argument list");
        assert!(
            commands.insert(function_name.to_owned()),
            "duplicate #[tauri::command] function {function_name}",
        );
    }

    commands
}

fn toml_string_array(raw: &str, key: &str) -> Vec<String> {
    let (_, after_key) =
        raw.split_once(key).unwrap_or_else(|| panic!("permission file missing {key}"));
    let (_, after_eq) =
        after_key.split_once('=').unwrap_or_else(|| panic!("permission {key} missing ="));
    let start = after_eq.find('[').unwrap_or_else(|| panic!("permission {key} missing ["));
    let end = after_eq[start + 1..]
        .find(']')
        .map(|end| start + 1 + end)
        .unwrap_or_else(|| panic!("permission {key} missing ]"));
    let inside = &after_eq[start + 1..end];
    inside
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .strip_prefix('"')
                .and_then(|entry| entry.strip_suffix('"'))
                .unwrap_or_else(|| panic!("permission {key} entries must be quoted strings"))
                .to_owned()
        })
        .collect()
}

fn csp_has_directive(csp: &str, expected: &str) -> bool {
    csp.split(';').map(str::trim).any(|directive| directive == expected)
}

#[test]
fn release_csp_matches_release_webview_policy_default() {
    let conf = read_json("tauri.conf.json");
    let csp = conf
        .get("app")
        .and_then(|app| app.get("security"))
        .and_then(|sec| sec.get("csp"))
        .and_then(Value::as_str)
        .expect("tauri.conf.json missing app.security.csp");

    let expected = ReleaseWebviewPolicy::default().content_security_policy;
    assert_eq!(
        csp, expected,
        "tauri.conf.json release CSP must equal ReleaseWebviewPolicy::default().content_security_policy"
    );
}

#[test]
fn release_csp_blocks_frames_objects_remote_fonts_and_inline_script() {
    let policy = ReleaseWebviewPolicy::default();
    let csp = policy.content_security_policy;

    assert!(csp_has_directive(csp, "default-src 'self'"));
    assert!(csp_has_directive(csp, "base-uri 'self'"));
    assert!(csp_has_directive(csp, "object-src 'none'"));
    assert!(csp_has_directive(csp, "frame-src 'none'"));
    assert!(csp_has_directive(csp, "font-src 'self'"));
    assert!(!csp.contains("'unsafe-inline'"));
    assert!(!csp.contains("https:"));
    assert!(!csp.contains("http:"));
}

#[test]
fn release_policy_denies_every_spec_broad_capability() {
    let policy = ReleaseWebviewPolicy::default();

    assert_eq!(policy.remote_content, CapabilityAccess::Denied);
    assert_eq!(policy.remote_fonts, CapabilityAccess::Denied);
    assert_eq!(policy.analytics, CapabilityAccess::Denied);
    assert_eq!(policy.third_party_iframes, CapabilityAccess::Denied);
    assert_eq!(policy.release_devtools, CapabilityAccess::Denied);
    assert_eq!(policy.broad_filesystem_access, CapabilityAccess::Denied);
    assert_eq!(policy.broad_shell_access, CapabilityAccess::Denied);
    assert_eq!(policy.broad_network_access, CapabilityAccess::Denied);
    assert_eq!(policy.broad_updater_access, CapabilityAccess::Denied);
    assert_eq!(policy.broad_clipboard_access, CapabilityAccess::Denied);
    assert_eq!(policy.broad_dialog_access, CapabilityAccess::Denied);
    assert_eq!(policy.broad_notification_access, CapabilityAccess::Denied);
}

#[test]
fn dev_csp_only_relaxes_localhost_hmr() {
    let conf = read_json("tauri.conf.json");
    let dev_csp = conf
        .get("app")
        .and_then(|app| app.get("security"))
        .and_then(|sec| sec.get("devCsp"))
        .and_then(Value::as_str)
        .expect("tauri.conf.json missing app.security.devCsp");

    // Vite HMR needs the dev server on localhost:1420; nothing else is allowed
    // beyond the release set.
    assert!(dev_csp.contains("ws://localhost:1420"));
    assert!(dev_csp.contains("http://localhost:1420"));
    // Dev relaxations beyond the localhost HMR socket would mean we drifted from
    // the release security posture without anyone noticing.
    assert!(!dev_csp.contains("https:"), "dev CSP must not allow remote https");
    assert!(!dev_csp.contains("http://*"), "dev CSP must not wildcard hosts");
    assert!(!dev_csp.contains("data: ws:"), "dev CSP must not allow arbitrary ws: connect-src",);
    assert!(csp_has_directive(dev_csp, "frame-src 'none'"));
    assert!(csp_has_directive(dev_csp, "object-src 'none'"));
}

#[test]
fn main_window_metadata_is_present() {
    let conf = read_json("tauri.conf.json");
    let windows = conf
        .get("app")
        .and_then(|app| app.get("windows"))
        .and_then(Value::as_array)
        .expect("tauri.conf.json missing app.windows array");
    assert_eq!(windows.len(), 1, "shell ships exactly one main window");

    let window = &windows[0];
    assert_eq!(window.get("label").and_then(Value::as_str), Some("main"));
    assert_eq!(window.get("title").and_then(Value::as_str), Some("Locket"));
}

#[test]
fn capability_file_denies_default_and_lists_no_broad_permissions() {
    let cap = read_json("capabilities/desktop.json");
    let permissions = cap
        .get("permissions")
        .and_then(Value::as_array)
        .expect("capabilities/desktop.json missing permissions array");
    let permission_names: Vec<&str> = permissions.iter().filter_map(Value::as_str).collect();
    assert_eq!(
        permission_names,
        ["desktop-commands", "core:event:allow-listen", "core:event:allow-unlisten"],
        "desktop capability must grant the local commands and receive-only event lifecycle",
    );

    let raw = read_text("capabilities/desktop.json");
    for forbidden in
        ["fs:", "shell:", "http:", "updater:", "clipboard:", "dialog:", "notification:"]
    {
        assert!(
            !raw.contains(forbidden),
            "capability file must not enable {forbidden} permissions",
        );
    }
}

#[test]
fn desktop_scan_action_is_registered_and_allowed() {
    let registered = handler_command_names(&read_text("src/lib.rs"));
    assert!(registered.contains("desktop_scan_project"));
    let allowed =
        toml_string_array(&read_text("permissions/desktop-commands.toml"), "commands.allow");
    assert!(allowed.iter().any(|name| name == "desktop_scan_project"));
}

#[test]
fn desktop_command_permission_matches_registered_handlers() {
    let source = read_text("src/lib.rs");
    let registered = handler_command_names(&source);
    let mut attributed = attributed_command_names(&source);
    attributed.extend(attributed_command_names(&read_text("src/desktop_actions.rs")));
    assert_eq!(
        attributed, registered,
        "every desktop #[tauri::command] must be listed exactly once in generate_handler!",
    );

    let permission = read_text("permissions/desktop-commands.toml");
    let allowed: std::collections::BTreeSet<String> =
        toml_string_array(&permission, "commands.allow").into_iter().collect();
    let denied = toml_string_array(&permission, "commands.deny");
    assert!(denied.is_empty(), "desktop command permission must not deny individual commands",);
    assert_eq!(
        allowed, registered,
        "permissions/desktop-commands.toml commands.allow must match the registered handlers",
    );
    assert!(
        allowed.iter().all(|command| command.starts_with("agent_")
            || command.starts_with("tray_")
            || command.starts_with("desktop_")),
        "desktop command permission must expose only scoped agent/tray/desktop handlers",
    );
}

#[test]
fn lib_opens_devtools_in_debug_only() {
    let source = read_text("src/lib.rs");

    // open_devtools may exist but must be gated behind cfg(debug_assertions).
    if source.contains("open_devtools") {
        assert!(
            source.contains("cfg(debug_assertions)") || source.contains("debug_assertions"),
            "open_devtools must be gated behind cfg(debug_assertions)",
        );
    }
}

#[test]
fn tauri_crate_does_not_enable_broad_access_plugins() {
    let manifest = read_text("Cargo.toml");
    for forbidden in [
        "tauri-plugin-fs",
        "tauri-plugin-shell",
        "tauri-plugin-http",
        "tauri-plugin-updater",
        "tauri-plugin-clipboard-manager",
        "tauri-plugin-dialog",
        "tauri-plugin-notification",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "desktop crate must not depend on broad access plugin {forbidden}",
        );
    }
}

#[test]
fn frontend_dist_points_at_ui_build_output() {
    let conf = read_json("tauri.conf.json");
    let dist = conf
        .get("build")
        .and_then(|b| b.get("frontendDist"))
        .and_then(Value::as_str)
        .expect("tauri.conf.json missing build.frontendDist");
    assert_eq!(dist, "../ui/dist");

    let dev_url = conf
        .get("build")
        .and_then(|b| b.get("devUrl"))
        .and_then(Value::as_str)
        .expect("tauri.conf.json missing build.devUrl");
    assert_eq!(dev_url, "http://localhost:1420");
}

#[test]
fn ui_project_layout_is_present_on_disk() {
    let ui = crate_root().join("../ui");
    for required in [
        "package.json",
        "index.html",
        "vite.config.ts",
        "tsconfig.json",
        "src/main.ts",
        "src/App.vue",
    ] {
        let path: PathBuf = ui.join(required);
        assert!(
            <Path as AsRef<Path>>::as_ref(&path).exists(),
            "ui project missing {}",
            path.display(),
        );
    }
}
