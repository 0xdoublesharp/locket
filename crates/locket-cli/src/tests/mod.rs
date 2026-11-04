#![allow(clippy::redundant_pub_crate)]

pub(super) use clap::Parser;
pub(super) use locket_platform::{
    LocalUserVerifier, MasterKeyStore, MemoryAutomationClientKeyStore, MemoryLocalUserVerifier,
    MemoryMasterKeyStore, MockMasterKeyStore, MockMasterKeyStoreFailure,
    PassphraseFallbackMasterKeyStore, PlatformError, PlatformPasskeyRegistrar,
    UnavailablePlatformPasskeyRegistrar,
};
pub(super) use serde_json::json;
pub(super) use std::collections::BTreeSet;
pub(super) use std::ffi::OsStr;
pub(super) use std::fs;
pub(super) use std::io::{Read, Write};
pub(super) use std::path::{Path, PathBuf};
pub(super) use std::process::Command as TestCommand;
pub(super) use std::sync::Arc;
pub(super) use tempfile::{tempdir, tempdir_in};

pub(super) use super::{Cli, RuntimeContext, run_with_context};

#[derive(Debug)]
struct StaticPassphraseReader {
    passphrase: String,
}

impl StaticPassphraseReader {
    fn new(passphrase: &str) -> Self {
        Self { passphrase: passphrase.to_owned() }
    }
}

impl super::PassphraseReader for StaticPassphraseReader {
    fn existing_passphrase(&self) -> Result<zeroize::Zeroizing<String>, super::CliError> {
        Ok(zeroize::Zeroizing::new(self.passphrase.clone()))
    }

    fn new_passphrase(&self) -> Result<zeroize::Zeroizing<String>, super::CliError> {
        Ok(zeroize::Zeroizing::new(self.passphrase.clone()))
    }
}

#[derive(Debug)]
struct StaticRecoveryCodeReader {
    code: String,
}

impl StaticRecoveryCodeReader {
    fn new(code: &str) -> Self {
        Self { code: code.to_owned() }
    }
}

impl super::RecoveryCodeReader for StaticRecoveryCodeReader {
    fn read_recovery_code(
        &self,
        _prompt: &str,
    ) -> Result<zeroize::Zeroizing<String>, super::CliError> {
        Ok(zeroize::Zeroizing::new(self.code.clone()))
    }
}

#[derive(Debug)]
struct StaticConfirmationReader {
    confirmation: String,
    init_confirmation: Option<String>,
}

impl StaticConfirmationReader {
    fn new(confirmation: &str) -> Self {
        Self { confirmation: confirmation.to_owned(), init_confirmation: Some("app\n".to_owned()) }
    }
}

impl super::ConfirmationReader for StaticConfirmationReader {
    fn read_confirmation(&self, prompt: &str) -> Result<String, super::CliError> {
        if prompt == "init recovery code"
            && let Some(confirmation) = &self.init_confirmation
        {
            return Ok(confirmation.clone());
        }
        Ok(self.confirmation.clone())
    }
}

#[derive(Debug)]
struct StaticSecretValueReader {
    value: String,
}

impl StaticSecretValueReader {
    fn new(value: &str) -> Self {
        Self { value: value.to_owned() }
    }
}

impl super::SecretValueReader for StaticSecretValueReader {
    fn read_secret_value(
        &self,
        _prompt: &str,
    ) -> Result<zeroize::Zeroizing<String>, super::CliError> {
        super::validate_secret_value(zeroize::Zeroizing::new(self.value.clone()))
    }
}

#[derive(Debug)]
struct FailingSecretValueReader;

impl super::SecretValueReader for FailingSecretValueReader {
    fn read_secret_value(
        &self,
        _prompt: &str,
    ) -> Result<zeroize::Zeroizing<String>, super::CliError> {
        Err(super::invalid_reference_error("secret reader was called"))
    }
}

#[derive(Debug, Default)]
pub(super) struct UnavailableMasterKeyStore;

impl MasterKeyStore for UnavailableMasterKeyStore {
    fn store_master_key(
        &self,
        _project_id: &str,
        _master_key: &locket_crypto::KeyBytes,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::MasterKeyNotFound)
    }

    fn load_master_key(
        &self,
        _project_id: &str,
    ) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, PlatformError> {
        Err(PlatformError::MasterKeyNotFound)
    }

    fn delete_master_key(&self, _project_id: &str) -> Result<(), PlatformError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct StaleLoadingMasterKeyStore;

impl MasterKeyStore for StaleLoadingMasterKeyStore {
    fn store_master_key(
        &self,
        _project_id: &str,
        _master_key: &locket_crypto::KeyBytes,
    ) -> Result<(), PlatformError> {
        Ok(())
    }

    fn load_master_key(
        &self,
        _project_id: &str,
    ) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, PlatformError> {
        Ok(zeroize::Zeroizing::new([99; locket_crypto::KEY_LEN]))
    }

    fn delete_master_key(&self, _project_id: &str) -> Result<(), PlatformError> {
        Ok(())
    }
}

pub(super) fn test_context(directory: &tempfile::TempDir) -> RuntimeContext {
    test_context_with_key_store(directory, Arc::new(MemoryMasterKeyStore::default()))
}

pub(super) fn test_context_with_confirmation(
    directory: &tempfile::TempDir,
    confirmation: &str,
) -> RuntimeContext {
    test_context_with_key_store_and_confirmation(
        directory,
        Arc::new(MemoryMasterKeyStore::default()),
        confirmation,
    )
}

pub(super) fn test_context_with_key_store(
    directory: &tempfile::TempDir,
    key_store: Arc<dyn MasterKeyStore + Send + Sync>,
) -> RuntimeContext {
    test_context_with_key_store_confirmation_and_secret(directory, key_store, "app\n", "secret")
}

pub(super) fn test_context_with_key_store_and_confirmation(
    directory: &tempfile::TempDir,
    key_store: Arc<dyn MasterKeyStore + Send + Sync>,
    confirmation: &str,
) -> RuntimeContext {
    test_context_with_key_store_confirmation_and_secret(
        directory,
        key_store,
        confirmation,
        "secret",
    )
}

pub(super) fn test_context_with_secret_value(
    directory: &tempfile::TempDir,
    secret_value: &str,
) -> RuntimeContext {
    test_context_with_key_store_confirmation_and_secret(
        directory,
        Arc::new(MemoryMasterKeyStore::default()),
        "app\n",
        secret_value,
    )
}

pub(super) fn test_context_with_failing_secret_reader(
    directory: &tempfile::TempDir,
) -> RuntimeContext {
    let mut context = test_context(directory);
    context.secret_value_reader = Arc::new(FailingSecretValueReader);
    context
}

pub(super) fn test_context_with_key_store_confirmation_and_secret(
    directory: &tempfile::TempDir,
    key_store: Arc<dyn MasterKeyStore + Send + Sync>,
    confirmation: &str,
    secret_value: &str,
) -> RuntimeContext {
    RuntimeContext {
        cwd: directory.path().to_path_buf(),
        store_path: directory.path().join("store.db"),
        config_path: directory.path().join("config.toml"),
        template_dir: directory.path().join(".locket").join("templates"),
        agent_data_dir: None,
        key_store,
        automation_client_key_store: Arc::new(MemoryAutomationClientKeyStore::default()),
        passphrase_store: PassphraseFallbackMasterKeyStore::new(
            directory.path().join("passphrase-fallback"),
        ),
        passphrase_reader: Arc::new(StaticPassphraseReader::new("test fallback passphrase")),
        recovery_code_reader: Arc::new(StaticRecoveryCodeReader::new("")),
        confirmation_reader: Arc::new(StaticConfirmationReader::new(confirmation)),
        secret_value_reader: Arc::new(StaticSecretValueReader::new(secret_value)),
        user_verifier: Arc::new(MemoryLocalUserVerifier::allowing()),
        passkey_registrar: Arc::new(UnavailablePlatformPasskeyRegistrar),
        master_key_cache: crate::runtime::context::MasterKeyCache::new(),
    }
}

pub(super) fn context_with_passkey_registrar(
    context: &RuntimeContext,
    registrar: Arc<dyn PlatformPasskeyRegistrar + Send + Sync>,
) -> RuntimeContext {
    RuntimeContext { passkey_registrar: registrar, ..context.clone() }
}

pub(super) fn context_with_user_verifier(
    context: &RuntimeContext,
    verifier: Arc<dyn LocalUserVerifier + Send + Sync>,
) -> RuntimeContext {
    RuntimeContext { user_verifier: verifier, ..context.clone() }
}

pub(super) fn context_with_confirmation(
    context: &RuntimeContext,
    confirmation: &str,
) -> RuntimeContext {
    RuntimeContext {
        confirmation_reader: Arc::new(StaticConfirmationReader::new(confirmation)),
        ..context.clone()
    }
}

pub(super) fn context_with_recovery_code(context: &RuntimeContext, code: &str) -> RuntimeContext {
    RuntimeContext {
        recovery_code_reader: Arc::new(StaticRecoveryCodeReader::new(code)),
        ..context.clone()
    }
}

pub(super) fn test_secret_write_args(key: &str) -> super::SecretWriteArgs {
    super::SecretWriteArgs {
        key: key.to_owned(),
        source: super::SourceArg { source: Some(super::SecretSourceArg::UserLocal) },
        metadata: super::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
    }
}

pub(super) fn test_secret_write_args_for_source(
    key: &str,
    source: super::SecretSourceArg,
) -> super::SecretWriteArgs {
    let mut args = test_secret_write_args(key);
    args.source.source = Some(source);
    args
}

pub(super) fn test_rotate_args(key: &str, grace_ttl: Option<&str>) -> super::RotateArgs {
    super::RotateArgs {
        key: key.to_owned(),
        source: super::SourceArg { source: Some(super::SecretSourceArg::UserLocal) },
        metadata: super::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
        grace_ttl: grace_ttl.map(ToOwned::to_owned),
    }
}

pub(super) fn run_git(directory: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = TestCommand::new("git").arg("-C").arg(directory).args(args).output()?;
    assert!(output.status.success(), "git failed: {}", String::from_utf8_lossy(&output.stderr));
    Ok(())
}

pub(super) fn assert_lifecycle_audit_log(
    directory: &tempfile::TempDir,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let mut statement = store
        .connection()
        .prepare("SELECT action, metadata_json FROM audit_log ORDER BY sequence")?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let actions = rows.iter().map(|(action, _)| action.as_str()).collect::<Vec<_>>();
    assert_eq!(
        actions,
        ["INIT", "SET", "ROTATE", "REVEAL", "PURGE", "DELETE", "PURGE", "AUDIT_VERIFY"]
    );
    for (_, metadata) in rows {
        assert!(!metadata.contains("postgres://localhost/old"));
        assert!(!metadata.contains("postgres://localhost/new"));
    }
    Ok(())
}

pub(super) fn assert_error_contains<T>(result: Result<T, super::CliError>, expected: &str) {
    assert!(result.is_err(), "expected error containing {expected:?}");
    if let Err(error) = result {
        assert!(error.to_string().contains(expected), "{error}");
    }
}

pub(super) fn recovery_code_from_output(output: &str) -> Result<&str, Box<dyn std::error::Error>> {
    output
        .lines()
        .find(|line| {
            line.len() == 38
                && line.matches('-').count() == 4
                && locket_crypto::recovery_code_decode(line).is_ok()
        })
        .ok_or_else(|| format!("missing recovery code line in output: {output:?}").into())
}

pub(super) fn read_debug_bundle_json(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let file = fs::File::open(path)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == Path::new("bundle.json") {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            return Ok(contents);
        }
    }
    Err("bundle.json missing from debug bundle".into())
}
pub(super) fn test_project_id_and_master_key(
    context: &RuntimeContext,
) -> Result<(String, locket_crypto::KeyBytes), Box<dyn std::error::Error>> {
    let resolved = super::require_project(context)?;
    let project_id = resolved.config.project_id.as_str().to_owned();
    let master_key = *context.key_store.load_master_key(&project_id)?;
    Ok((project_id, master_key))
}

pub(super) fn setup_recovery_envelope(
    context: &RuntimeContext,
    project_id: &str,
    master_key: &locket_crypto::KeyBytes,
) -> Result<
    (super::RecoveryKdfToml, super::RecoveryEnvelope, [u8; locket_crypto::RECOVERY_CODE_BYTES]),
    Box<dyn std::error::Error>,
> {
    let code_bytes = locket_crypto::generate_recovery_code_bytes()?;
    let salt = locket_crypto::generate_recovery_salt()?;
    let kdf = super::RecoveryKdfToml::new_v1("lk_kdf_test".to_owned(), &salt, 1_000);
    let unwrap_root =
        locket_crypto::derive_recovery_key_v1(&code_bytes, &salt, kdf.to_crypto_params())?;
    let entry = super::seal_recovery_envelope_entry(
        &unwrap_root,
        &kdf.kdf_profile_id,
        "master_key",
        project_id,
        master_key,
    )?;
    let envelope = super::RecoveryEnvelope {
        kdf_profile_id: kdf.kdf_profile_id.clone(),
        created_at_unix_nanos: 1_000,
        entries: vec![entry],
    };
    let recovery_dir = context.cwd.join(".locket").join("recovery");
    super::save_recovery_kdf_toml(&recovery_dir, &kdf)?;
    locket_platform::save_recovery_state(&recovery_dir, &kdf, &envelope)?;
    Ok((kdf, envelope, code_bytes))
}

mod agent_lifecycle;
mod ai_safe;
mod cli_basics;
mod cli_errors;
mod config_passkey_lock;
mod dangerous_profile_gating;
mod diff_copy;
mod e2e_bundle_roundtrip;
mod e2e_policy_run;
mod exec;
mod grants_agent_diag;
mod history_purge_import;
mod ide_env_consumer;
mod init_template_device;
mod leak_canary;
mod mutation_expired_versions;
mod parsers;
mod passphrase_recovery_hooks;
mod policy_doctor;
mod policy_profile_project;
mod proptest_device_descriptor;
mod proptest_dotenv;
mod recovery;
mod scan_redact;
mod secrets_crud;
mod source_precedence;

mod variable_contract;

mod team_pending_cli;
