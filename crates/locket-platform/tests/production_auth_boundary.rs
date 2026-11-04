//! Exercise the production-linked library without invoking native prompts.
#![allow(unused_crate_dependencies)]

use locket_platform::{
    KeyringPlatformPasskeyRegistrar, PasskeyAssertionContext, PlatformError,
    PlatformPasskeyRegistrar, default_platform_passkey_registrar,
};

#[test]
fn production_auth_ignores_test_environment() -> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "LOCKET_AUTH_BOUNDARY_CHILD";
    if std::env::var_os(CHILD).is_some() {
        assert!(!locket_platform::local_auth_test_overrides_enabled());
        return Ok(());
    }
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "production_auth_ignores_test_environment", "--nocapture"])
        .env(CHILD, "1")
        .env("LOCKET_TEST_LOCAL_AUTH", "allow")
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

#[test]
fn production_does_not_offer_software_keyring_seeds_as_passkeys() {
    let registrar = KeyringPlatformPasskeyRegistrar;
    assert!(!registrar.supports_registration());
    assert!(matches!(
        registrar.register_passkey("test", "locket.localhost"),
        Err(PlatformError::PasskeyUnsupported)
    ));
    assert!(matches!(
        registrar.evaluate_prf(
            PasskeyAssertionContext {
                credential_id: &[1; 32],
                relying_party_id: "locket.localhost",
                public_key: &[],
            },
            &[2; 32]
        ),
        Err(PlatformError::PasskeyUnsupported)
    ));
}

#[test]
fn production_passkey_nonterminal_fails_without_prompting() -> Result<(), Box<dyn std::error::Error>>
{
    const CHILD: &str = "LOCKET_PASSKEY_NONTERMINAL_CHILD";
    if std::env::var_os(CHILD).is_some() {
        let registrar = default_platform_passkey_registrar();
        assert!(!registrar.supports_registration());
        assert!(matches!(
            registrar.register_passkey("test", "locket.localhost"),
            Err(PlatformError::PasskeyUnsupported)
        ));
        assert!(matches!(
            registrar.evaluate_prf(
                PasskeyAssertionContext {
                    credential_id: &[1; 32],
                    relying_party_id: "locket.localhost",
                    public_key: &[],
                },
                &[2; 32]
            ),
            Err(PlatformError::PasskeyUnsupported)
        ));
        return Ok(());
    }
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "production_passkey_nonterminal_fails_without_prompting", "--nocapture"])
        .env(CHILD, "1")
        .stdin(std::process::Stdio::null())
        .output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::print_stderr)]
fn linux_missing_policy_fails_closed_without_prompting() {
    if std::path::Path::new("/usr/share/polkit-1/actions/app.locket.policy").exists() {
        // An installed desktop may legitimately prompt. Never launch an
        // interactive ceremony from the unattended suite; use the host harness.
        eprintln!("missing-policy probe skipped: Locket's polkit policy is installed");
        return;
    }
    assert!(matches!(
        locket_platform::linux_evaluate_local_user("Unlock vault"),
        Err(locket_platform::LinuxLocalAuthError::Unavailable(_))
    ));
}
