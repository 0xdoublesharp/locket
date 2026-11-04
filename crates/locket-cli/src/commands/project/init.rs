//! Implementation of the `locket init` command and its private helpers.
//!
//! Encapsulates project initialization, key material setup, recovery
//! envelope creation, and the rollback bookkeeping used to keep init
//! atomic on failure.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use locket_core::{ProfileName, ProjectConfig, ProjectId};
use locket_crypto::{
    KeyPurpose, derive_recovery_key_v1, generate_key, generate_recovery_code_bytes,
    generate_recovery_salt,
};
use locket_platform::{
    RecoveryEnvelope, RecoveryKdfToml, save_recovery_envelope, save_recovery_kdf_toml,
};
use locket_store::{AuditWrite, Store};
use serde_json::json;

use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, confirmation_failed_error, invalid_profile_name_error, metadata_invalid_error,
};
use crate::runtime::key_access::{
    MasterKeySource, default_profile, load_master_key_verified_by_project_key, load_project_key,
    store_master_key_with_fallback,
};
use crate::support::project_files::{
    EXAMPLE_FILE, GITIGNORE_FILE, ensure_example_file, ensure_gitignore,
};
use crate::support::style::{self, Tone};
use crate::{
    InitArgs, LOCKET_TOML, ensure_project_metadata, fallback_project_name, format_hex,
    formatted_recovery_code, insert_wrapped_key, now_unix_nanos, open_store, resolve_project,
    seal_recovery_envelope_entry, trust_root, write_project_config,
};

pub fn init(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: InitArgs,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    let timestamp = now_unix_nanos()?;

    if let Some(resolved) = resolve_project(&context.cwd)? {
        let state = inspect_init_state(&store, &resolved.config, &resolved.root)?;
        if state.is_complete(args.recovery_code) {
            if style::enabled() {
                style::write_banner(output, "project", "already initialized")?;
                style::write_kv(output, "project_id", resolved.config.project_id.as_str())?;
            } else {
                writeln!(
                    output,
                    "locket: project already initialized ({})",
                    resolved.config.project_id
                )?;
            }
            return Ok(());
        }

        let rollback = InitRollback::capture(
            &store,
            &resolved.root,
            resolved.config.project_id.as_str(),
            !state.project_present,
            !state.project_key_exists,
        )?;
        let result = complete_init(
            context,
            output,
            &mut store,
            &resolved.config,
            &resolved.root,
            timestamp,
            args.recovery_code,
            args.no_device,
            args.register_passkey,
            args.no_passkey,
        );
        let completion = match result {
            Ok(completion) => completion,
            Err(error) => {
                rollback.rollback(context, &store);
                return Err(error);
            }
        };
        write_init_summary(output, &resolved.config, completion.master_key_source, true)?;
        if io::stdin().is_terminal() {
            super::setup::offer_interactive_setup(context, output)?;
        }
        return Ok(());
    }

    let profile_name = match args.profile {
        Some(profile) => ProfileName::new(profile)
            .map_err(|_| invalid_profile_name_error("invalid profile name"))?,
        None => ProfileName::new("dev")
            .map_err(|_| invalid_profile_name_error("invalid profile name"))?,
    };
    let project_name = args.name.unwrap_or_else(|| fallback_project_name(&context.cwd));
    let config = ProjectConfig::new(
        ProjectId::generate().map_err(|_| CliError::Time)?,
        project_name,
        profile_name,
    );

    let config_path = context.cwd.join(LOCKET_TOML);
    if config_path.exists() {
        return Err(metadata_invalid_error("locket.toml already exists but could not be resolved"));
    }

    let rollback =
        InitRollback::capture(&store, &context.cwd, config.project_id.as_str(), true, true)?;
    write_project_config(&config_path, &config)?;
    let result = complete_init(
        context,
        output,
        &mut store,
        &config,
        &context.cwd,
        timestamp,
        args.recovery_code,
        args.no_device,
        args.register_passkey,
        args.no_passkey,
    );
    let completion = match result {
        Ok(completion) => completion,
        Err(error) => {
            rollback.rollback(context, &store);
            return Err(error);
        }
    };
    write_init_summary(output, &config, completion.master_key_source, false)?;
    if io::stdin().is_terminal() {
        super::setup::offer_interactive_setup(context, output)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct InitState {
    project_present: bool,
    profile_present: bool,
    project_key_exists: bool,
    project_keys_complete: bool,
    profile_keys_complete: bool,
    recovery_ready: bool,
}

impl InitState {
    const fn is_complete(self, recovery_required: bool) -> bool {
        self.project_present
            && self.profile_present
            && self.project_keys_complete
            && self.profile_keys_complete
            && (!recovery_required || self.recovery_ready)
    }
}

#[derive(Debug)]
struct InitCompletion {
    master_key_source: MasterKeySource,
}

#[derive(Debug)]
struct FileSnapshot {
    path: PathBuf,
    original: Option<Vec<u8>>,
}

impl FileSnapshot {
    fn capture(path: PathBuf) -> Result<Self, CliError> {
        let original = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        Ok(Self { path, original })
    }

    fn restore(&self) {
        match &self.original {
            Some(bytes) => {
                if let Some(parent) = self.path.parent() {
                    let _ignored = fs::create_dir_all(parent);
                }
                let _ignored = fs::write(&self.path, bytes);
            }
            None => {
                let _ignored = fs::remove_file(&self.path);
            }
        }
    }
}

#[derive(Debug)]
struct StoreSnapshot {
    profile_ids: BTreeSet<String>,
    key_ids: BTreeSet<String>,
    root_hashes: BTreeSet<Vec<u8>>,
}

impl StoreSnapshot {
    fn capture(store: &Store, project_id: &str) -> Result<Self, CliError> {
        Ok(Self {
            profile_ids: string_set(
                store,
                "SELECT id FROM profiles WHERE project_id = ?1",
                project_id,
            )?,
            key_ids: string_set(store, "SELECT id FROM keys WHERE project_id = ?1", project_id)?,
            root_hashes: bytes_set(
                store,
                "SELECT root_hash FROM project_roots WHERE project_id = ?1",
                project_id,
            )?,
        })
    }

    fn rollback_new_rows(&self, store: &Store, project_id: &str) {
        if let Ok(ids) = string_set(store, "SELECT id FROM keys WHERE project_id = ?1", project_id)
        {
            for id in ids.difference(&self.key_ids) {
                let _ignored = store.connection().execute("DELETE FROM keys WHERE id = ?1", [id]);
            }
        }
        if let Ok(ids) =
            string_set(store, "SELECT id FROM profiles WHERE project_id = ?1", project_id)
        {
            for id in ids.difference(&self.profile_ids) {
                let _ignored =
                    store.connection().execute("DELETE FROM profiles WHERE id = ?1", [id]);
            }
        }
        if let Ok(root_hashes) = bytes_set(
            store,
            "SELECT root_hash FROM project_roots WHERE project_id = ?1",
            project_id,
        ) {
            for root_hash in root_hashes.difference(&self.root_hashes) {
                let _ignored = store.connection().execute(
                    "DELETE FROM project_roots WHERE project_id = ?1 AND root_hash = ?2",
                    (project_id, root_hash.as_slice()),
                );
            }
        }
    }
}

#[derive(Debug)]
struct InitRollback {
    project_id: String,
    remove_store_project: bool,
    master_key_rollback: MasterKeyRollback,
    store_snapshot: StoreSnapshot,
    snapshots: Vec<FileSnapshot>,
    recovery_dir: PathBuf,
    recovery_dir_existed: bool,
    locket_dir: PathBuf,
    locket_dir_existed: bool,
}

impl InitRollback {
    fn capture(
        store: &Store,
        root: &Path,
        project_id: &str,
        remove_store_project: bool,
        delete_master_key: bool,
    ) -> Result<Self, CliError> {
        let recovery_dir = root.join(".locket").join("recovery");
        let locket_dir = root.join(".locket");
        let snapshots = vec![
            FileSnapshot::capture(root.join(LOCKET_TOML))?,
            FileSnapshot::capture(root.join(GITIGNORE_FILE))?,
            FileSnapshot::capture(root.join(EXAMPLE_FILE))?,
            FileSnapshot::capture(recovery_dir.join("kdf.toml"))?,
            FileSnapshot::capture(recovery_dir.join("envelope.bin"))?,
        ];
        Ok(Self {
            project_id: project_id.to_owned(),
            remove_store_project,
            master_key_rollback: MasterKeyRollback::from_delete(delete_master_key),
            store_snapshot: StoreSnapshot::capture(store, project_id)?,
            snapshots,
            recovery_dir_existed: recovery_dir.exists(),
            recovery_dir,
            locket_dir_existed: locket_dir.exists(),
            locket_dir,
        })
    }

    fn rollback(&self, context: &RuntimeContext, store: &Store) {
        if self.remove_store_project {
            let _ignored = store.delete_project(&self.project_id);
        } else {
            self.store_snapshot.rollback_new_rows(store, &self.project_id);
        }
        if self.master_key_rollback.should_delete() {
            let _ignored = context.key_store.delete_master_key(&self.project_id);
            let _ignored = context.passphrase_store.delete_master_key(&self.project_id);
        }
        for snapshot in self.snapshots.iter().rev() {
            snapshot.restore();
        }
        if !self.recovery_dir_existed {
            let _ignored = fs::remove_dir(&self.recovery_dir);
        }
        if !self.locket_dir_existed {
            let _ignored = fs::remove_dir(&self.locket_dir);
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MasterKeyRollback {
    Preserve,
    Delete,
}

impl MasterKeyRollback {
    const fn from_delete(delete: bool) -> Self {
        if delete { Self::Delete } else { Self::Preserve }
    }

    const fn should_delete(self) -> bool {
        matches!(self, Self::Delete)
    }
}

fn string_set(
    store: &Store,
    sql: &str,
    project_id: &str,
) -> Result<BTreeSet<String>, locket_store::StoreError> {
    let mut statement = store.connection().prepare(sql)?;
    let rows = statement
        .query_map([project_id], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(rows)
}

fn bytes_set(
    store: &Store,
    sql: &str,
    project_id: &str,
) -> Result<BTreeSet<Vec<u8>>, locket_store::StoreError> {
    let mut statement = store.connection().prepare(sql)?;
    let rows = statement
        .query_map([project_id], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(rows)
}

fn inspect_init_state(
    store: &Store,
    config: &ProjectConfig,
    root: &Path,
) -> Result<InitState, CliError> {
    let project_id = config.project_id.as_str();
    let project_present = store.get_project(project_id)?.is_some();
    let profile = store.get_profile_by_name(project_id, config.default_profile.as_str())?;
    let metadata_key_exists = key_exists(store, project_id, None, KeyPurpose::ProjectMetadata)?;
    let audit_key_exists = key_exists(store, project_id, None, KeyPurpose::Audit)?;
    let project_key_exists = metadata_key_exists || audit_key_exists;
    let project_keys_complete = metadata_key_exists && audit_key_exists;
    let profile_keys_complete = if let Some(profile) = &profile {
        key_exists(store, project_id, Some(&profile.id), KeyPurpose::ProfileSecret)?
            && key_exists(store, project_id, Some(&profile.id), KeyPurpose::ProfileFingerprint)?
    } else {
        false
    };
    Ok(InitState {
        project_present,
        profile_present: profile.is_some(),
        project_key_exists,
        project_keys_complete,
        profile_keys_complete,
        recovery_ready: init_recovery_files_ready(root),
    })
}

fn init_recovery_files_ready(root: &Path) -> bool {
    let recovery_dir = root.join(".locket").join("recovery");
    locket_platform::load_recovery_kdf_toml(&recovery_dir).is_ok()
        && locket_platform::load_recovery_envelope(&recovery_dir).is_ok()
}

#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
fn complete_init(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &mut Store,
    config: &ProjectConfig,
    root: &Path,
    timestamp: i64,
    recovery_code: bool,
    no_device: bool,
    register_passkey: bool,
    no_passkey: bool,
) -> Result<InitCompletion, CliError> {
    ensure_project_metadata(store, config, timestamp)?;
    let key_material = ensure_project_key_material(context, store, config, timestamp)?;
    trust_root(store, config, root, timestamp)?;
    maybe_init_device(context, output, no_device);
    let recovery_code_bytes = if recovery_code {
        ensure_initial_recovery_envelope(
            context,
            root,
            config,
            &key_material.master_key,
            timestamp,
        )?
    } else {
        None
    };
    maybe_register_passkey(context, output, register_passkey, no_passkey);
    ensure_gitignore(root)?;
    ensure_example_file(root)?;
    if let Some(code_bytes) = recovery_code_bytes {
        display_initial_recovery_code(context, output, config, &code_bytes)?;
    }
    write_init_audit(
        context,
        store,
        config,
        timestamp,
        recovery_code_bytes.is_some(),
        root.join(GITIGNORE_FILE).exists(),
        root.join(EXAMPLE_FILE).exists(),
    )?;
    Ok(InitCompletion { master_key_source: key_material.source })
}

/// Run `device init` automatically as part of `init`, swallowing any
/// failure with a stderr warning so the vault remains usable. Skipped
/// when the user passes `--no-device`.
fn maybe_init_device(context: &RuntimeContext, output: &mut impl Write, no_device: bool) {
    if no_device {
        return;
    }
    let device_args = crate::DeviceInitArgs { force: false };
    if let Err(error) =
        crate::commands::team::device::device_init_command(context, output, &device_args)
    {
        let mut stderr = std::io::stderr();
        let _ = writeln!(
            stderr,
            "locket: device init failed during init: {error}\n\
             locket: vault is usable; run `locket device init` later to retry."
        );
    }
}

/// Optionally register a passkey as part of `init`. Honors `--register-passkey`
/// to skip the prompt, `--no-passkey` to suppress the flow entirely, and
/// otherwise asks the user once on a TTY. Failures emit a stderr warning
/// rather than failing init.
fn maybe_register_passkey(
    context: &RuntimeContext,
    output: &mut impl Write,
    register_passkey: bool,
    no_passkey: bool,
) {
    if no_passkey {
        return;
    }
    let should_register = if register_passkey {
        true
    } else if io::stdin().is_terminal() && io::stderr().is_terminal() {
        context
            .confirmation_reader
            .read_confirmation("Register a passkey for this device? [y/N] ")
            .is_ok_and(|response| {
                let trimmed = response.trim().to_lowercase();
                matches!(trimmed.as_str(), "y" | "yes")
            })
    } else {
        false
    };
    if !should_register {
        return;
    }
    let label = std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "primary".to_owned());
    let args = crate::PasskeyRegisterArgs {
        label,
        relying_party_id: locket_store::DEFAULT_WEBAUTHN_RELYING_PARTY_ID.to_owned(),
    };
    if let Err(error) =
        crate::commands::vault::passkey::passkey_register_command(context, output, &args)
    {
        let mut stderr = std::io::stderr();
        let _ = writeln!(
            stderr,
            "locket: passkey registration failed during init: {error}\n\
             locket: vault is usable; run `locket passkey register --label <name>` later to retry."
        );
    }
}

fn write_init_summary(
    output: &mut impl Write,
    config: &ProjectConfig,
    master_key_source: MasterKeySource,
    resumed: bool,
) -> Result<(), CliError> {
    if style::enabled() {
        let status = if resumed { "resumed" } else { "initialized" };
        style::write_banner(output, "project", status)?;
        style::write_kv(output, "project_id", config.project_id.as_str())?;
        style::write_kv(output, "default_profile", config.default_profile.as_str())?;
        style::write_kv(output, "master_key_source", master_key_source.as_str())?;
        style::write_kv(output, "metadata_only", "yes")?;
    } else {
        if resumed {
            writeln!(output, "resumed locket project {}", config.project_id)?;
        } else {
            writeln!(output, "initialized locket project {}", config.project_id)?;
        }
        writeln!(output, "default_profile: {}", config.default_profile)?;
        writeln!(output, "master_key_source: {}", master_key_source.as_str())?;
    }
    Ok(())
}

fn key_exists(
    store: &Store,
    project_id: &str,
    profile_id: Option<&str>,
    purpose: KeyPurpose,
) -> Result<bool, CliError> {
    Ok(store.get_key_by_scope(project_id, profile_id, purpose.as_str())?.is_some())
}

struct InitKeyMaterial {
    master_key: zeroize::Zeroizing<locket_crypto::KeyBytes>,
    source: MasterKeySource,
}

fn ensure_project_key_material(
    context: &RuntimeContext,
    store: &Store,
    config: &ProjectConfig,
    timestamp: i64,
) -> Result<InitKeyMaterial, CliError> {
    let project_id = config.project_id.as_str();
    let metadata_key_exists = key_exists(store, project_id, None, KeyPurpose::ProjectMetadata)?;
    let audit_key_exists = key_exists(store, project_id, None, KeyPurpose::Audit)?;
    let (master_key, source) = if metadata_key_exists || audit_key_exists {
        let purpose =
            if metadata_key_exists { KeyPurpose::ProjectMetadata } else { KeyPurpose::Audit };
        load_master_key_verified_by_project_key(context, store, project_id, purpose)?
    } else {
        let master_key = generate_key()?;
        let source = store_master_key_with_fallback(context, project_id, &master_key, timestamp)?;
        (master_key, source)
    };

    ensure_wrapped_key(
        store,
        project_id,
        None,
        KeyPurpose::ProjectMetadata,
        &master_key,
        timestamp,
    )?;
    ensure_wrapped_key(store, project_id, None, KeyPurpose::Audit, &master_key, timestamp)?;
    let profile = default_profile(store, config)?;
    ensure_wrapped_key(
        store,
        project_id,
        Some(&profile.id),
        KeyPurpose::ProfileSecret,
        &master_key,
        timestamp,
    )?;
    ensure_wrapped_key(
        store,
        project_id,
        Some(&profile.id),
        KeyPurpose::ProfileFingerprint,
        &master_key,
        timestamp,
    )?;
    Ok(InitKeyMaterial { master_key, source })
}

fn ensure_wrapped_key(
    store: &Store,
    project_id: &str,
    profile_id: Option<&str>,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<(), CliError> {
    if key_exists(store, project_id, profile_id, purpose)? {
        return Ok(());
    }
    insert_wrapped_key(store, project_id, profile_id, purpose, master_key, timestamp)
}

fn ensure_initial_recovery_envelope(
    context: &RuntimeContext,
    root: &Path,
    config: &ProjectConfig,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<Option<[u8; locket_crypto::RECOVERY_CODE_BYTES]>, CliError> {
    let recovery_dir = root.join(".locket").join("recovery");
    if recovery_dir.join("envelope.bin").exists() {
        locket_platform::load_recovery_kdf_toml(&recovery_dir)?;
        locket_platform::load_recovery_envelope(&recovery_dir)?;
        return Ok(None);
    }

    let code_bytes = generate_recovery_code_bytes()?;
    let salt = generate_recovery_salt()?;
    let kdf_profile_id = format!("lk_kdf_{}", format_hex(&salt[..16]));
    let kdf = RecoveryKdfToml::new_v1(kdf_profile_id, &salt, timestamp);
    let recovery_root = derive_recovery_key_v1(&code_bytes, &salt, kdf.to_crypto_params())?;
    let entry = seal_recovery_envelope_entry(
        &recovery_root,
        &kdf.kdf_profile_id,
        "master_key",
        config.project_id.as_str(),
        master_key,
    )?;
    let mut entries = vec![entry];
    let resolved = crate::require_project(context)?;
    crate::commands::vault::recovery::replace_device_recovery_entries(
        context,
        &resolved,
        &kdf,
        &recovery_root,
        &mut entries,
    )?;
    let envelope = RecoveryEnvelope {
        kdf_profile_id: kdf.kdf_profile_id.clone(),
        created_at_unix_nanos: i128::from(timestamp),
        entries,
    };
    save_recovery_kdf_toml(&recovery_dir, &kdf)
        .map_err(|error| metadata_invalid_error(format!("save recovery kdf: {error}")))?;
    save_recovery_envelope(&recovery_dir, &envelope)
        .map_err(|error| metadata_invalid_error(format!("save recovery envelope: {error}")))?;
    Ok(Some(code_bytes))
}

fn display_initial_recovery_code(
    context: &RuntimeContext,
    output: &mut impl Write,
    config: &ProjectConfig,
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
) -> Result<(), CliError> {
    let code = formatted_recovery_code(code_bytes)?;
    if style::enabled() {
        style::write_banner(output, "recovery-code", "shown once")?;
        style::write_kv(output, "recovery_code_init", "success")?;
        writeln!(
            output,
            "  {} {}",
            style::paint(Tone::Warn, "warning"),
            style::paint(Tone::Value, "terminal scrollback may retain this code")
        )?;
        writeln!(output, "  {}", style::paint(Tone::Secret, &code))?;
        writeln!(
            output,
            "  {}",
            style::paint(
                Tone::Muted,
                format!("type project name '{}' after recording the recovery code", config.name)
            )
        )?;
    } else {
        writeln!(output, "recovery_code_init: success")?;
        writeln!(output, "recovery_code (shown once, store securely):")?;
        writeln!(output, "{code}")?;
        writeln!(output, "warning: terminal scrollback may retain this code")?;
        writeln!(output, "type project name '{}' after recording the recovery code", config.name)?;
    }
    let confirmation = context.confirmation_reader.read_confirmation("init recovery code")?;
    if confirmation.trim_end_matches(['\r', '\n']) != config.name {
        return Err(confirmation_failed_error("confirmation did not match project name"));
    }
    try_clear_screen();
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

/// Emits ANSI clear-screen codes to stdout when stdout is an interactive
/// terminal. No-op when stdout is piped, redirected, or in a test harness.
fn try_clear_screen() {
    if io::stdout().is_terminal() {
        let _ = io::stdout().write_all(b"\x1b[2J\x1b[H");
    }
}

fn write_init_audit(
    context: &RuntimeContext,
    store: &mut Store,
    config: &ProjectConfig,
    timestamp: i64,
    recovery_code_displayed: bool,
    gitignore_exists: bool,
    example_exists: bool,
) -> Result<(), CliError> {
    let audit_key =
        load_project_key(context, store, config.project_id.as_str(), KeyPurpose::Audit)?;
    let profile = default_profile(store, config)?;
    let mut generated_files = Vec::new();
    if gitignore_exists {
        generated_files.push(GITIGNORE_FILE);
    }
    if example_exists {
        generated_files.push(EXAMPLE_FILE);
    }
    let metadata = json!({
        "schema_version": 1,
        "action": "INIT",
        "status": "SUCCESS",
        "command": "init",
        "project_id": config.project_id.as_str(),
        "default_profile_id": profile.id,
        "generated_files": generated_files,
        "recovery_code_displayed": recovery_code_displayed,
    });
    let audit = AuditWrite {
        project_id: config.project_id.as_str(),
        profile_id: Some(&profile.id),
        action: "INIT",
        status: "SUCCESS",
        secret_name: None,
        command: Some("init"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
