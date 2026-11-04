//! Integration coverage for the tray asset and tooltip mappings.
//!
//! We can't easily spin up a real Tauri runtime under cargo test on
//! every platform, so this suite only exercises the pure helpers
//! (`icon_bytes_for` / `tooltip_for`) — the same helpers `setup_tray`
//! and `update_tray_state` defer to. This pins the load-bearing
//! invariants without requiring a windowing system in CI.
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

// Pull dev-deps into this integration target so `unused_crate_dependencies`
// stays quiet for crates referenced only via path lookups in other tests
// or by the surrounding lib crate.
use arboard as _;
use base64 as _;
use directories as _;
use locket_agent as _;
use locket_core as _;
use locket_platform as _;
use locket_store as _;
use serde as _;
use serde_json as _;
use sha2 as _;
use tauri as _;
use tempfile as _;
use thiserror as _;
use tokio as _;
use toml as _;
use zeroize as _;

use locket_app::{TrayIconState, tray_icon_states};
use locket_desktop_lib::{LOCKET_TRAY_ID, icon_bytes_for, tooltip_for};

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n'];

#[test]
fn every_tray_icon_state_returns_a_valid_png() {
    for state in tray_icon_states() {
        let bytes = icon_bytes_for(*state);
        assert!(!bytes.is_empty(), "icon bytes for {state:?} must be non-empty");
        assert!(
            bytes.starts_with(&PNG_SIGNATURE),
            "icon bytes for {state:?} must start with the PNG signature",
        );
    }
}

#[test]
fn every_tray_icon_state_returns_a_non_empty_metadata_only_tooltip() {
    for state in tray_icon_states() {
        let tip = tooltip_for(*state);
        assert!(!tip.is_empty(), "tooltip for {state:?} must be non-empty");
        // Spec privacy rule: tooltip text must be metadata-only — no
        // exact secret, policy, or project names. The `descriptor`
        // labels the lib crate vends are stable strings, so we pin the
        // negative cases here as a tripwire.
        for forbidden in ["DATABASE_URL", "postgres://", "deploy-prod", "payments-api"] {
            assert!(!tip.contains(forbidden), "tooltip for {state:?} leaked {forbidden}",);
        }
    }
}

#[test]
fn tooltip_strings_are_distinct_per_state() {
    let mut tips = tray_icon_states().iter().map(|state| tooltip_for(*state)).collect::<Vec<_>>();
    tips.sort_unstable();
    let unique = tips.iter().copied().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        unique.len(),
        tray_icon_states().len(),
        "every tray state must surface a distinct tooltip; got {tips:?}",
    );
}

#[test]
fn agent_stopped_is_the_initial_setup_state() {
    // `setup_tray` boots with `AgentStopped`; assert that bytes for
    // that state are present and decode-shaped so the runtime call
    // can't bottom out on a missing asset.
    let bytes = icon_bytes_for(TrayIconState::AgentStopped);
    assert!(bytes.starts_with(&PNG_SIGNATURE));
    assert!(bytes.len() > PNG_SIGNATURE.len(), "PNG must contain at least one chunk");
}

#[test]
fn tray_id_constant_is_stable() {
    // The frontend and tests pin this id literally; surface a
    // regression here if it ever drifts.
    assert_eq!(LOCKET_TRAY_ID, "locket");
}
