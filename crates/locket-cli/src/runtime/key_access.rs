//! Master- and project-key loading helpers used by CLI commands.

use std::io::Write;

use locket_core::{LocketError, ProjectConfig};
use locket_crypto::{
    HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, WrappedKeyMaterial,
    derive_wrapping_key_v1, key_wrap_aad_v1, unwrap_key_material_v1, wrap_key_material_v1,
};
use locket_store::{ProfileRecord, Store};

use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, profile_not_found_error, project_not_found_error, typed_cli_error,
};

#[derive(Clone, Copy)]
enum PassphrasePromptReason {
    NewFallback,
    ExistingFallback,
}

fn explain_passphrase_prompt(reason: PassphrasePromptReason) {
    let mut stderr = std::io::stderr();
    let _ = match reason {
        PassphrasePromptReason::NewFallback => writeln!(
            stderr,
            "locket: OS keychain is unavailable; setting up a passphrase fallback for this project.\n\
             locket: you will need this passphrase to use this vault on this machine.\n\
             locket: run `locket recovery rotate` later if you want an offline recovery code."
        ),
        PassphrasePromptReason::ExistingFallback => writeln!(
            stderr,
            "locket: OS keychain entry not found for this project; using the passphrase fallback.\n\
             locket: enter the passphrase you set when this project was first initialized on this machine."
        ),
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MasterKeySource {
    OsKeyStore,
    PassphraseFallback,
}

impl MasterKeySource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OsKeyStore => "os-key-store",
            Self::PassphraseFallback => "passphrase-fallback",
        }
    }
}

pub fn store_master_key_with_fallback(
    context: &RuntimeContext,
    project_id: &str,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<MasterKeySource, CliError> {
    match context.key_store.store_master_key(project_id, master_key) {
        Ok(()) => Ok(MasterKeySource::OsKeyStore),
        Err(_primary_error) => {
            explain_passphrase_prompt(PassphrasePromptReason::NewFallback);
            let passphrase = context.passphrase_reader.new_passphrase()?;
            context.passphrase_store.store_master_key(
                project_id,
                master_key,
                passphrase.as_bytes(),
                timestamp,
            )?;
            Ok(MasterKeySource::PassphraseFallback)
        }
    }
}

pub fn load_master_key(
    context: &RuntimeContext,
    project_id: &str,
) -> Result<(zeroize::Zeroizing<locket_crypto::KeyBytes>, MasterKeySource), CliError> {
    if let Some(cached) = context.master_key_cache.get(project_id) {
        return Ok(cached);
    }
    let result = match context.key_store.load_master_key(project_id) {
        Ok(master_key) => (master_key, MasterKeySource::OsKeyStore),
        Err(primary_error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(primary_error.into());
            }
            (load_fallback_master_key(context, project_id)?, MasterKeySource::PassphraseFallback)
        }
    };
    context.master_key_cache.insert(project_id, result.0.clone(), result.1);
    Ok(result)
}

pub fn load_fallback_master_key(
    context: &RuntimeContext,
    project_id: &str,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    if let Some((key, MasterKeySource::PassphraseFallback)) =
        context.master_key_cache.get(project_id)
    {
        return Ok(key);
    }
    explain_passphrase_prompt(PassphrasePromptReason::ExistingFallback);
    let passphrase = context.passphrase_reader.existing_passphrase()?;
    let key = context.passphrase_store.load_master_key(project_id, passphrase.as_bytes())?;
    context.master_key_cache.insert(project_id, key.clone(), MasterKeySource::PassphraseFallback);
    Ok(key)
}

pub fn load_master_key_verified_by_project_key(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
) -> Result<(zeroize::Zeroizing<locket_crypto::KeyBytes>, MasterKeySource), CliError> {
    let (master_key, source) = load_master_key(context, project_id)?;
    match load_project_key_with_master(store, project_id, purpose, &master_key) {
        Ok(_) => Ok((master_key, source)),
        Err(error) if should_try_passphrase_fallback(source, &error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(error);
            }
            let fallback_master_key = load_fallback_master_key(context, project_id)?;
            load_project_key_with_master(store, project_id, purpose, &fallback_master_key)?;
            Ok((fallback_master_key, MasterKeySource::PassphraseFallback))
        }
        Err(error) => Err(error),
    }
}

pub fn should_try_passphrase_fallback(source: MasterKeySource, error: &CliError) -> bool {
    source == MasterKeySource::OsKeyStore
        && matches!(
            error,
            CliError::Crypto(
                locket_crypto::CryptoError::DecryptionFailed
                    | locket_crypto::CryptoError::InvalidWrappedKey
            )
        )
}

pub fn load_project_key(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    load_project_key_with_source(context, store, project_id, purpose).map(|(key, _)| key)
}

pub fn load_project_key_with_source(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
) -> Result<(zeroize::Zeroizing<locket_crypto::KeyBytes>, MasterKeySource), CliError> {
    let (master_key, source) = load_master_key(context, project_id)?;
    match load_project_key_with_master(store, project_id, purpose, &master_key) {
        Ok(key) => Ok((key, source)),
        Err(error) if should_try_passphrase_fallback(source, &error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(error);
            }
            let fallback_master_key = load_fallback_master_key(context, project_id)?;
            let key =
                load_project_key_with_master(store, project_id, purpose, &fallback_master_key)?;
            Ok((key, MasterKeySource::PassphraseFallback))
        }
        Err(error) => Err(error),
    }
}

pub fn load_project_key_with_master(
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let record = store.get_key_by_scope(project_id, None, purpose.as_str())?.ok_or_else(|| {
        typed_cli_error(
            LocketError::AuditIntegrityFailed,
            format!("project {} key is missing", purpose.as_str()),
        )
    })?;
    let wrapping_key =
        derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(project_id, None, purpose))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        None,
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    Ok(unwrap_key_material_v1(&wrapping_key, &wrapped, &aad)?)
}

pub fn load_profile_key(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    profile_id: &str,
    purpose: KeyPurpose,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let (master_key, source) = load_master_key(context, project_id)?;
    match load_profile_key_with_master(store, project_id, profile_id, purpose, &master_key) {
        Ok(key) => Ok(key),
        Err(error) if should_try_passphrase_fallback(source, &error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(error);
            }
            let fallback_master_key = load_fallback_master_key(context, project_id)?;
            load_profile_key_with_master(
                store,
                project_id,
                profile_id,
                purpose,
                &fallback_master_key,
            )
        }
        Err(error) => Err(error),
    }
}

pub fn load_profile_key_with_master(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let record = store
        .get_key_by_scope(project_id, Some(profile_id), purpose.as_str())?
        .ok_or_else(|| {
            typed_cli_error(
                LocketError::AuditIntegrityFailed,
                format!("profile {} key is missing", purpose.as_str()),
            )
        })?;
    let wrapping_key = derive_wrapping_key_v1(
        master_key,
        &HkdfWrapInfo::new(project_id, Some(profile_id), purpose),
    )?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        Some(profile_id),
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    Ok(unwrap_key_material_v1(&wrapping_key, &wrapped, &aad)?)
}

pub fn ensure_project_exists(store: &Store, project_id: &str) -> Result<(), CliError> {
    if store.get_project(project_id)?.is_some() {
        return Ok(());
    }
    Err(project_not_found_error())
}

pub fn default_profile(store: &Store, config: &ProjectConfig) -> Result<ProfileRecord, CliError> {
    store
        .get_profile_by_name(config.project_id.as_str(), config.default_profile.as_str())?
        .ok_or_else(|| profile_not_found_error("default profile is missing"))
}

/// Re-wraps a plaintext profile-key material under the receiver's
/// master-key-derived wrapping key for insertion into the local `keys`
/// table.
///
/// Sealed bundle payloads carry profile key material as plaintext
/// inside the age-encrypted payload (see
/// `crates/locket-cli/src/commands/team/bundle.rs::SealedBundleProfileKeyV1`).
/// On import, the receiver decrypts the age payload, extracts the
/// plaintext key bytes, and rewraps them under its own master-key-derived
/// wrapping key with the receiver's `(project_id, profile_id, purpose)`
/// HKDF info and a freshly bound key-wrap AAD covering the receiver-side
/// `key_id`. This isolates the local key wrap from any exporter-side
/// derivation and matches the
/// `docs/specs/team-sync-recovery.md` line 212 contract.
///
/// The caller supplies `receiver_key_id`, which becomes both the
/// `keys.id` value and a covered field in the wrap AAD. Callers that
/// have not yet generated a key id can use
/// [`locket_core::KeyId::generate`].
///
/// # Errors
///
/// Returns [`CliError`] if HKDF derivation, AAD construction, or
/// AEAD encryption fails.
pub fn rewrap_imported_profile_key(
    receiver_master_key: &locket_crypto::KeyBytes,
    receiver_project_id: &str,
    receiver_profile_id: &str,
    receiver_key_id: &str,
    purpose: KeyPurpose,
    plaintext_key_material: &locket_crypto::KeyBytes,
) -> Result<WrappedKeyMaterial, CliError> {
    let wrapping_key = derive_wrapping_key_v1(
        receiver_master_key,
        &HkdfWrapInfo::new(receiver_project_id, Some(receiver_profile_id), purpose),
    )?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        receiver_project_id,
        receiver_key_id,
        Some(receiver_profile_id),
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    Ok(wrap_key_material_v1(&wrapping_key, plaintext_key_material, &aad)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use locket_crypto::{KEY_LEN, KeyBytes};

    fn key_from_byte(byte: u8) -> KeyBytes {
        let mut key = [0_u8; KEY_LEN];
        for (index, slot) in key.iter_mut().enumerate() {
            *slot = byte ^ u8::try_from(index & 0xff).unwrap_or(0);
        }
        key
    }

    #[test]
    fn rewrap_round_trip_unwraps_with_receiver_master_key() {
        // Simulate the export side: a profile key wrapped under master_a.
        let master_a = key_from_byte(0xA1);
        let plaintext_profile_key = key_from_byte(0x42);
        let exporter_project_id = "lk_proj_alpha";
        let exporter_profile_id = "lk_prof_alpha";
        let exporter_key_id = "lk_key_alpha";
        let purpose = KeyPurpose::ProfileSecret;

        let wrapping_a = derive_wrapping_key_v1(
            &master_a,
            &HkdfWrapInfo::new(exporter_project_id, Some(exporter_profile_id), purpose),
        )
        .unwrap();
        let aad_a = key_wrap_aad_v1(&KeyWrapAad::new(
            exporter_project_id,
            exporter_key_id,
            Some(exporter_profile_id),
            0,
            KeyWrapPurpose::from(purpose),
        ))
        .unwrap();
        let wrapped_a = wrap_key_material_v1(&wrapping_a, &plaintext_profile_key, &aad_a).unwrap();

        // Transit reverse: unwrap with master_a to recover the plaintext.
        // Sealed bundle payloads ship plaintext key material directly,
        // so this step models the exporter's side of the wire.
        let recovered_plaintext = unwrap_key_material_v1(&wrapping_a, &wrapped_a, &aad_a).unwrap();
        assert_eq!(*recovered_plaintext, plaintext_profile_key);

        // Receiver rewraps under master_b with its own scope.
        let master_b = key_from_byte(0xB2);
        let receiver_project_id = "lk_proj_beta";
        let receiver_profile_id = "lk_prof_beta";
        let receiver_key_id = "lk_key_beta";
        let wrapped_b = rewrap_imported_profile_key(
            &master_b,
            receiver_project_id,
            receiver_profile_id,
            receiver_key_id,
            purpose,
            &recovered_plaintext,
        )
        .unwrap();

        // Receiver unwrap path: master_b derives the receiver wrapping
        // key with receiver-scoped HKDF info, then unwraps under
        // receiver-scoped AAD. The plaintext must equal the original.
        let wrapping_b = derive_wrapping_key_v1(
            &master_b,
            &HkdfWrapInfo::new(receiver_project_id, Some(receiver_profile_id), purpose),
        )
        .unwrap();
        let aad_b = key_wrap_aad_v1(&KeyWrapAad::new(
            receiver_project_id,
            receiver_key_id,
            Some(receiver_profile_id),
            0,
            KeyWrapPurpose::from(purpose),
        ))
        .unwrap();
        let final_plaintext = unwrap_key_material_v1(&wrapping_b, &wrapped_b, &aad_b).unwrap();
        assert_eq!(*final_plaintext, plaintext_profile_key);
    }

    #[test]
    fn rewrap_uses_independent_nonce_each_call() {
        // Two consecutive rewraps with identical inputs must produce
        // distinct nonces so XChaCha20-Poly1305 (key, nonce) pairs are
        // never reused. The wrapping key derivation is deterministic;
        // only the random nonce changes.
        let master = key_from_byte(0xC3);
        let plaintext = key_from_byte(0x10);
        let first = rewrap_imported_profile_key(
            &master,
            "lk_proj_x",
            "lk_prof_x",
            "lk_key_x",
            KeyPurpose::ProfileFingerprint,
            &plaintext,
        )
        .unwrap();
        let second = rewrap_imported_profile_key(
            &master,
            "lk_proj_x",
            "lk_prof_x",
            "lk_key_x",
            KeyPurpose::ProfileFingerprint,
            &plaintext,
        )
        .unwrap();
        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn rewrap_rejects_unwrap_with_different_master_key() {
        // Cross-master tamper: receiver-wrapped material must not unwrap
        // under a foreign master key. This protects against AEAD-tag
        // forgeries that swap exporter and receiver keys.
        let master_b = key_from_byte(0xB2);
        let plaintext = key_from_byte(0x77);
        let wrapped = rewrap_imported_profile_key(
            &master_b,
            "lk_proj_y",
            "lk_prof_y",
            "lk_key_y",
            KeyPurpose::ProfileSecret,
            &plaintext,
        )
        .unwrap();

        let wrong_master = key_from_byte(0xFE);
        let wrong_wrapping = derive_wrapping_key_v1(
            &wrong_master,
            &HkdfWrapInfo::new("lk_proj_y", Some("lk_prof_y"), KeyPurpose::ProfileSecret),
        )
        .unwrap();
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(
            "lk_proj_y",
            "lk_key_y",
            Some("lk_prof_y"),
            0,
            KeyWrapPurpose::from(KeyPurpose::ProfileSecret),
        ))
        .unwrap();
        let result = unwrap_key_material_v1(&wrong_wrapping, &wrapped, &aad);
        assert!(result.is_err(), "unwrap with wrong master key must fail");
    }
}
