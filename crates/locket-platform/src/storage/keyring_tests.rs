use std::io;
use std::process::Command;

use keyring_core::{Entry, Error, mock};
use locket_crypto::KEY_LEN;

use crate::{
    AutomationClientKeyStore, KeyringAutomationClientKeyStore, KeyringMasterKeyStore,
    LocketInstance, MasterKeyStore, PlatformError,
};

const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];

#[test]
fn production_keyring_adapters_use_the_process_local_mock() -> Result<(), Box<dyn std::error::Error>>
{
    // The child owns keyring-core's process-global store. No other test sees
    // this mock or can install a host backend while these adapters are running.
    const CHILD: &str = "LOCKET_PLATFORM_MOCK_KEYRING_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe()?)
            .args(["production_keyring_adapters_use_the_process_local_mock", "--nocapture"])
            .env(CHILD, "1")
            .env_remove("LOCKET_KEYRING_HOST_TEST")
            .output()?;
        let transcript = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{transcript}");
        assert!(transcript.contains("1 passed"), "{transcript}");
        return Ok(());
    }

    keyring_core::unset_default_store();
    assert!(matches!(
        KeyringMasterKeyStore.load_master_key("missing-store"),
        Err(PlatformError::Keyring(Error::NoDefaultStore))
    ));
    keyring_core::set_default_store(mock::Store::new()?);
    exercise_master_adapter()?;
    exercise_automation_adapter()?;
    #[cfg(target_os = "macos")]
    {
        // Constructing the native store only configures the login domain.
        // No credential is opened once the child installs the native store.
        crate::init_platform_keyring()?;
        let first = keyring_core::get_default_store()
            .ok_or_else(|| io::Error::other("native backend was not installed"))?;
        assert!(first.as_any().is::<apple_native_keyring_store::keychain::Store>());
        crate::init_platform_keyring()?;
        let second = keyring_core::get_default_store()
            .ok_or_else(|| io::Error::other("native backend disappeared"))?;
        assert!(std::sync::Arc::ptr_eq(&first, &second));
    }
    Ok(())
}

fn exercise_master_adapter() -> Result<(), Box<dyn std::error::Error>> {
    let store = KeyringMasterKeyStore;
    let project = "lk_proj_mock_provider";
    let entry =
        Entry::new(LocketInstance::current().keyring_service(), "master:lk_proj_mock_provider")?;
    assert!(matches!(store.load_master_key(project), Err(PlatformError::MasterKeyNotFound)));

    store.store_master_key(project, &KEY)?;
    assert_eq!(*store.load_master_key(project)?, KEY);
    assert!(matches!(store.load_master_key("another"), Err(PlatformError::MasterKeyNotFound)));
    assert_eq!(entry.get_secret()?, data_encoding::BASE64URL_NOPAD.encode(&KEY).as_bytes());

    entry.set_secret(&[0xff; 43])?;
    assert!(matches!(store.load_master_key(project), Err(PlatformError::InvalidMasterKey)));
    inject_access_denial(&entry)?;
    assert!(matches!(
        store.load_master_key(project),
        Err(PlatformError::Keyring(Error::NoStorageAccess(_)))
    ));
    inject_access_denial(&entry)?;
    assert!(matches!(
        store.store_master_key(project, &KEY),
        Err(PlatformError::Keyring(Error::NoStorageAccess(_)))
    ));
    inject_access_denial(&entry)?;
    assert!(matches!(
        store.delete_master_key(project),
        Err(PlatformError::Keyring(Error::NoStorageAccess(_)))
    ));

    store.delete_master_key(project)?;
    assert!(matches!(store.load_master_key(project), Err(PlatformError::MasterKeyNotFound)));
    assert!(matches!(
        store.delete_master_key(project),
        Err(PlatformError::Keyring(Error::NoEntry))
    ));
    Ok(())
}

fn exercise_automation_adapter() -> Result<(), Box<dyn std::error::Error>> {
    let store = KeyringAutomationClientKeyStore;
    let client = "lk_client_mock_provider";
    let reference = store.store_client_key(client, &KEY)?;
    assert_eq!(reference.service, LocketInstance::current().keyring_service());
    assert_eq!(reference.account, "automation-client:lk_client_mock_provider");
    let entry = Entry::new(&reference.service, &reference.account)?;
    assert_eq!(entry.get_secret()?, data_encoding::BASE64URL_NOPAD.encode(&KEY).as_bytes());

    inject_access_denial(&entry)?;
    assert!(matches!(
        store.store_client_key(client, &[1; KEY_LEN]),
        Err(PlatformError::Keyring(Error::NoStorageAccess(_)))
    ));
    inject_access_denial(&entry)?;
    assert!(matches!(
        store.delete_client_key(client),
        Err(PlatformError::Keyring(Error::NoStorageAccess(_)))
    ));
    assert_eq!(entry.get_secret()?, data_encoding::BASE64URL_NOPAD.encode(&KEY).as_bytes());

    store.delete_client_key(client)?;
    assert!(matches!(entry.get_secret(), Err(Error::NoEntry)));
    store.delete_client_key(client)?;
    Ok(())
}

fn inject_access_denial(entry: &Entry) -> io::Result<()> {
    let credential = entry
        .as_any()
        .downcast_ref::<mock::Cred>()
        .ok_or_else(|| io::Error::other("expected mock credential"))?;
    credential.set_error(Error::NoStorageAccess(Box::new(io::Error::from(
        io::ErrorKind::PermissionDenied,
    ))));
    Ok(())
}
