//! Locket desktop binary entry point.
//!
//! Hides the console subprocess on Windows release builds and delegates to
//! the library `run` function. Startup errors propagate as a non-zero exit.

#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

// Runtime + test deps consumed only via the lib crate trip
// `unused_crate_dependencies` at the bin boundary; pull each in
// explicitly so the lint stays quiet without disabling it.
use arboard as _;
use base64 as _;
use directories as _;
use locket_agent as _;
use locket_app as _;
use locket_core as _;
use locket_platform as _;
use locket_store as _;
use serde as _;
use serde_json as _;
use sha2 as _;
#[cfg(any(target_os = "macos", test))]
use tempfile as _;
use thiserror as _;
use tokio as _;
use toml as _;
use zeroize as _;

fn main() -> tauri::Result<()> {
    locket_desktop_lib::run()
}
