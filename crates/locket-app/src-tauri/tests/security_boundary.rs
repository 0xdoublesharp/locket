//! Regression tests for the desktop IPC allowlist and effective release configuration.
#![allow(unused_crate_dependencies)]

use std::{collections::BTreeSet, error::Error, path::Path};

use locket_app::ReleaseWebviewPolicy;
use tauri::utils::{
    config::{Config, Csp, WebviewUrl, parse::read_from},
    platform::Target,
};

// Existing config tests compare this permission file with the IPC handlers.
// Pin the reviewed commands independently so changing both still needs review.
const REVIEWED_COMMANDS: &str = "
desktop_list_projects
desktop_open_project
desktop_open_shared_vault
desktop_inspect_project_folder
desktop_initialize_project
desktop_import_env
desktop_create_profile
desktop_delete_secret
desktop_copy_secret_to_shared
desktop_link_secret
desktop_unlink_secret
desktop_list_shared_usages
desktop_list_duplicates
desktop_detect_commands
desktop_start_agent
desktop_run_policy
desktop_scan_project
desktop_save_policy
desktop_variable_readiness
desktop_team_sync_status
desktop_team_sync_configure
desktop_team_sync_test_remote
desktop_team_sync_clear
desktop_team_sync_now
desktop_team_sync_rename_profile
desktop_team_sync_preserve_override
desktop_get_launch_at_login
desktop_set_launch_at_login
desktop_pick_directory
desktop_pick_file
desktop_copy_text_plain
desktop_mcp_config_snippet
agent_status
agent_subscribe_status
agent_lock
agent_unlock
agent_set_active_profile
agent_reveal
agent_scan
agent_resolve
agent_prepare_exec
agent_policy_doctor
agent_export_bundle
agent_import_bundle
agent_verify_bundle
agent_recovery_rotate
agent_list_runtime_sessions
agent_list_policies
agent_register_command_policies
agent_list_device_members
agent_list_secrets
agent_discover_secrets
agent_list_projects
agent_set_secret
agent_rotate_secret
agent_read_config
agent_write_config
agent_list_audit
agent_verify_audit
agent_list_versions
agent_copy_secret
tray_set_state
tray_set_selection
tray_set_privacy_context
";

#[derive(serde::Deserialize)]
struct PermissionFile {
    permission: [Permission; 1],
}

#[derive(serde::Deserialize)]
struct Permission {
    identifier: String,
    commands: CommandPermissions,
}

#[derive(serde::Deserialize)]
struct CommandPermissions {
    allow: Vec<String>,
    deny: Vec<String>,
}

#[test]
fn desktop_permission_exposes_only_reviewed_commands() -> Result<(), Box<dyn Error>> {
    let manifest: PermissionFile =
        toml::from_str(include_str!("../permissions/desktop-commands.toml"))?;
    let [permission] = manifest.permission;
    assert_eq!(permission.identifier, "desktop-commands");
    assert!(permission.commands.deny.is_empty());
    let allowed: BTreeSet<_> = permission.commands.allow.iter().map(String::as_str).collect();
    assert_eq!(allowed.len(), permission.commands.allow.len(), "duplicate command permission");
    assert_eq!(allowed, REVIEWED_COMMANDS.split_whitespace().collect());
    Ok(())
}

#[test]
fn effective_release_config_preserves_the_local_webview_boundary() -> Result<(), Box<dyn Error>> {
    let (config, _) = read_from(Target::current(), Path::new(env!("CARGO_MANIFEST_DIR")))?;
    let config: Config = serde_json::from_value(config)?;
    let expected_csp = ReleaseWebviewPolicy::default().content_security_policy;
    assert_eq!(config.app.security.csp, Some(Csp::Policy(expected_csp.into())));
    assert!(!config.app.security.asset_protocol.enable);
    assert!(!config.app.with_global_tauri);
    assert!(config.app.windows.iter().all(|window| {
        matches!(window.url, WebviewUrl::App(_)) && window.devtools != Some(true)
    }));
    assert!(config.bundle.macos.hardened_runtime);
    assert_eq!(
        config.bundle.macos.entitlements.as_deref(),
        Some("../../../dist/installers/macos/entitlements.plist"),
    );
    Ok(())
}
