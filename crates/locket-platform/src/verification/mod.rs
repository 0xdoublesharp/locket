#[cfg(any(target_os = "macos", target_os = "linux"))]
mod external_fido2;
#[cfg(target_os = "linux")]
pub mod linux_local_authentication;
#[cfg(target_os = "linux")]
pub mod linux_user_verifier;
#[cfg(target_os = "macos")]
pub mod macos_local_authentication;
#[cfg(target_os = "macos")]
pub mod macos_user_verifier;
pub mod passkey;
pub mod user_verification;
#[cfg(target_os = "windows")]
pub mod windows_local_authentication;
#[cfg(target_os = "windows")]
pub mod windows_user_verifier;
