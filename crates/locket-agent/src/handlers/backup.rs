//! Desktop backup/recovery RPC request and response types.

#![allow(
    clippy::manual_let_else,
    clippy::needless_pass_by_value,
    clippy::significant_drop_tightening,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use data_encoding::BASE64URL_NOPAD;
use locket_core::bundle::{
    BUNDLE_SCHEMA_V1, BundleContainer, BundleManifest, decrypt_bundle_payload_with_x25519_secret,
    encrypt_bundle_payload_for_age_recipients, verify_age_payload_structure,
};
use locket_core::{CommandPolicy, CommandSpec, ExternalEnvSource, KeyId, PolicyDocument};
use locket_crypto::{
    HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, WrappedKeyMaterial,
    derive_wrapping_key_v1, key_wrap_aad_v1, unwrap_key_material_v1, wrap_key_material_v1,
};
use locket_platform::{
    LocalDevicePrivateKeyStorage, PlatformError, WrappedLocalFileDevicePrivateKeyStorage,
};
use locket_store::{AuditWrite, KeyRecord, ProfileRecord, SecretBlobRecord, SecretRecord, Store};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::server::{AgentSocketState, current_unix_nanos};

/// Bundle export profile scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BundleExportScope {
    /// Export only the active profile.
    ActiveProfile,
    /// Export every profile in the project.
    AllProfiles,
}

/// Desktop request for sealed bundle export.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExportBundleRequest {
    /// Project id being exported.
    pub project_id: String,
    /// Active profile id/name supplied by desktop status.
    pub profile_id: Option<String>,
    /// Device descriptor for the recipient.
    pub recipient_descriptor: String,
    /// Profile selection.
    pub scope: BundleExportScope,
    /// Whether remote audit rows should be included.
    pub include_audit: bool,
    /// Include personal sources only for an explicit backup.
    #[serde(default)]
    pub include_personal: bool,
    /// Include historical versions only when explicitly requested.
    #[serde(default)]
    pub include_history: bool,
    /// Return selection metadata without writing a bundle.
    #[serde(default)]
    pub preview_only: bool,
    /// Optional output path.
    pub output_path: Option<PathBuf>,
}

/// Import conflict behavior.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BundleConflictMode {
    /// Review conflicts without applying divergent rows.
    Review,
    /// Prefer incoming bundle rows when conflicts occur.
    AcceptIncoming,
    /// Keep local rows when conflicts occur.
    AcceptLocal,
}

/// Desktop request for sealed bundle import.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportBundleRequest {
    /// Project id receiving the bundle.
    pub project_id: String,
    /// Bundle file path.
    pub bundle_path: PathBuf,
    /// Import remote audit rows when present.
    pub include_audit: bool,
    /// Conflict policy.
    pub conflict_mode: BundleConflictMode,
}

/// Desktop request for non-destructive bundle verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifyBundleRequest {
    /// Bundle file path.
    pub bundle_path: PathBuf,
    /// Whether the UI requires the bundle to be decryptable locally.
    #[serde(default)]
    pub require_decryptable: bool,
}

/// Recovery-rotation verification factor requested by the UI.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryVerification {
    /// Fresh platform prompt / hardware-backed verification.
    Platform,
    /// Current recovery-code prompt.
    CurrentCode,
}

/// Desktop request for recovery-code rotation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryRotateRequest {
    /// Project id whose recovery envelope would be rotated.
    pub project_id: String,
    /// Optional recovery directory. When omitted, the agent tries
    /// `<store-path-parent>/recovery`, matching test/local layouts.
    #[serde(default)]
    pub recovery_dir: Option<PathBuf>,
    /// Requested fresh verification factor.
    pub verification: RecoveryVerification,
    /// Current recovery code when `verification = current-code`.
    #[serde(default)]
    pub current_recovery_code: Option<String>,
    /// User confirmed one-time display semantics in the UI.
    pub acknowledged_one_time_display: bool,
    /// Whether the UI should clear the visible code after display.
    pub clear_after_display: bool,
}

/// Common metadata-only backup action response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupActionResponse {
    /// Stable action label.
    pub action: String,
    /// User-facing, metadata-only status.
    pub status: String,
    /// User-facing, metadata-only next step.
    pub message: String,
}

#[derive(Clone, Debug)]
struct UnlockedProject {
    store_path: PathBuf,
    profile_id: Option<String>,
    master_key: zeroize::Zeroizing<locket_crypto::KeyBytes>,
}

#[derive(Debug, Deserialize, Serialize)]
struct DeviceDescriptorV1 {
    v: u8,
    device_id: String,
    label: String,
    signing_public_key_ed25519: String,
    sealing_public_key_x25519: String,
    fingerprint_sha256: String,
    safety_words: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundlePayloadV1 {
    profiles: Vec<SealedBundleProfileV1>,
    command_policies: Vec<SealedBundleCommandPolicyV1>,
    secrets: Vec<SealedBundleSecretV1>,
    secret_versions: Vec<SealedBundleSecretVersionV1>,
    blobs: Vec<SealedBundleBlobV1>,
    profile_keys: Vec<SealedBundleProfileKeyV1>,
    profile_count: usize,
    command_policy_count: usize,
    secret_count: usize,
    secret_version_count: usize,
    blob_count: usize,
    profile_key_count: usize,
    active_secret_count: usize,
    audit_rows_included: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audit_chain: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleProfileV1 {
    profile_id: String,
    name: String,
    dangerous: bool,
    active_secret_count: usize,
    created_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleCommandPolicyV1 {
    name: String,
    command_kind: String,
    argv: Vec<String>,
    shell: Option<String>,
    allowed_secrets: Vec<String>,
    required_secrets: Vec<String>,
    optional_secrets: Vec<String>,
    inherit_env: Vec<String>,
    env_mode: String,
    override_mode: String,
    override_explicit: bool,
    external_env_sources: Vec<String>,
    allow_remote_docker: bool,
    confirm: bool,
    require_user_verification: bool,
    ttl_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleSecretV1 {
    id: String,
    profile_id: String,
    name: String,
    source: String,
    origin: String,
    current_version: u32,
    state: String,
    created_at: i64,
    updated_at: i64,
    last_rotated_at: Option<i64>,
    deleted_at: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleSecretVersionV1 {
    secret_id: String,
    version: u32,
    source: String,
    origin: String,
    state: String,
    created_at: i64,
    deprecated_at: Option<i64>,
    grace_until: Option<i64>,
    purged_at: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleBlobV1 {
    secret_id: String,
    version: u32,
    encrypted_dek_b64: String,
    ciphertext_b64: String,
    value_nonce_b64: String,
    aad_schema_version: u16,
    created_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleProfileKeyV1 {
    profile_id: String,
    purpose: String,
    key_material_b64: String,
}

struct BundleRecipientV1 {
    fingerprint: String,
    sealing_public_key: [u8; 32],
}

#[derive(Debug, Default)]
#[allow(clippy::struct_field_names)]
struct ImportedBundleCounts {
    profile_count: usize,
    secret_count: usize,
    secret_version_count: usize,
    blob_count: usize,
    command_policy_count: usize,
    profile_key_count: usize,
}

#[derive(Debug, Default, Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct AppliedBundleCounts {
    archived_local_profile_count: usize,
    profile_count: usize,
    secret_count: usize,
    secret_version_count: usize,
    blob_count: usize,
    command_policy_count: usize,
    profile_key_count: usize,
}

#[derive(Debug, Default, Clone, Copy)]
struct BundleConflictCounts {
    identical: usize,
    newer_incoming: usize,
    divergent: usize,
    deleted_vs_active: usize,
    applied: usize,
    rejected: usize,
}

enum ApplyOutcome {
    Applied { applied: AppliedBundleCounts, conflicts: BundleConflictCounts },
    ReviewRequired { divergent: Vec<String> },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ConflictResolution {
    AcceptIncoming,
    AcceptLocal,
    Review,
}

impl ConflictResolution {
    const fn from_mode(mode: &BundleConflictMode) -> Self {
        match mode {
            BundleConflictMode::AcceptIncoming => Self::AcceptIncoming,
            BundleConflictMode::AcceptLocal => Self::AcceptLocal,
            BundleConflictMode::Review => Self::Review,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::AcceptIncoming => "accept-incoming",
            Self::AcceptLocal => "accept-local",
            Self::Review => "review",
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DivergentDecision {
    Apply,
    Skip,
    Defer,
}

/// Non-destructive bundle verification response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifyBundleResponse {
    /// Whether the outer container and age payload are structurally valid.
    pub structural_valid: bool,
    /// Bundle schema version.
    pub schema_version: u16,
    /// Project id from the plaintext manifest.
    pub project_id: String,
    /// Profile count from the plaintext manifest.
    pub profile_count: u32,
    /// Recipient count from the plaintext manifest.
    pub recipient_count: u32,
    /// Payload digest from the plaintext manifest.
    pub payload_digest: String,
    /// Whether local decryptability was checked by this RPC.
    pub decryptable_by_this_device: Option<bool>,
    /// Metadata-only status.
    pub message: String,
}

/// Handle desktop bundle export.
pub async fn handle_export_bundle(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let request: ExportBundleRequest = match serde_json::from_value(envelope.payload.clone()) {
        Ok(request) => request,
        Err(_) => return error_response(envelope, "ProtocolError", "invalid ExportBundle payload"),
    };
    let unlocked = match unlocked_project(envelope, state, &request.project_id).await {
        Ok(unlocked) => unlocked,
        Err(response) => return response,
    };
    if request.include_audit {
        return error_response(
            envelope,
            "PolicyValidationIncomplete",
            "agent bundle export does not yet embed remote audit rows; retry without include_audit",
        );
    }
    if request.recipient_descriptor.trim().is_empty() {
        return error_response(envelope, "InvalidReference", "bundle export requires a recipient");
    }
    match export_bundle(&request, &unlocked) {
        Ok(response) => success_response(envelope, response),
        Err((code, message)) => error_response(envelope, code, &message),
    }
}

/// Handle desktop bundle import.
pub async fn handle_import_bundle(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let request: ImportBundleRequest = match serde_json::from_value(envelope.payload.clone()) {
        Ok(request) => request,
        Err(_) => return error_response(envelope, "ProtocolError", "invalid ImportBundle payload"),
    };
    if !request.bundle_path.exists() {
        return error_response(envelope, "BundleVerificationFailed", "bundle file was not found");
    }
    let unlocked = match unlocked_project(envelope, state, &request.project_id).await {
        Ok(unlocked) => unlocked,
        Err(response) => return response,
    };
    match import_bundle(&request, &unlocked, state) {
        Ok(response) => success_response(envelope, response),
        Err((code, message)) => error_response(envelope, code, &message),
    }
}

/// Handle desktop bundle verification.
pub fn handle_verify_bundle(envelope: &RequestEnvelope) -> ResponseEnvelope {
    let request: VerifyBundleRequest = match serde_json::from_value(envelope.payload.clone()) {
        Ok(request) => request,
        Err(_) => return error_response(envelope, "ProtocolError", "invalid VerifyBundle payload"),
    };
    let bytes = match std::fs::read(&request.bundle_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return error_response(
                envelope,
                "BundleVerificationFailed",
                "bundle file was not found",
            );
        }
    };
    let bundle = match BundleContainer::deserialize(&bytes) {
        Ok(bundle) => bundle,
        Err(error) => {
            return error_response(
                envelope,
                "BundleVerificationFailed",
                &format!("bundle verification failed: {error}"),
            );
        }
    };
    if let Err(error) = verify_age_payload_structure(&bundle.encrypted_payload) {
        return error_response(
            envelope,
            "BundleVerificationFailed",
            &format!("bundle verification failed: {error}"),
        );
    }
    let decryptable_by_this_device = request.require_decryptable.then_some(false);
    let response = VerifyBundleResponse {
        structural_valid: true,
        schema_version: bundle.manifest.schema_version,
        project_id: bundle.manifest.project_id,
        profile_count: bundle.manifest.profile_count,
        recipient_count: u32::try_from(bundle.manifest.recipient_fingerprints.len())
            .unwrap_or(u32::MAX),
        payload_digest: bundle.manifest.payload_digest,
        decryptable_by_this_device,
        message: if request.require_decryptable {
            "Bundle is structurally valid; local decryptability requires the CLI bundle core."
                .to_owned()
        } else {
            "Bundle is structurally valid.".to_owned()
        },
    };
    success_response(envelope, response)
}

/// Handle desktop recovery-code rotation.
pub async fn handle_recovery_rotate(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let request: RecoveryRotateRequest = match serde_json::from_value(envelope.payload.clone()) {
        Ok(request) => request,
        Err(_) => {
            return error_response(envelope, "ProtocolError", "invalid RecoveryRotate payload");
        }
    };
    if !request.acknowledged_one_time_display {
        return error_response(
            envelope,
            "ConfirmationFailed",
            "one-time recovery-code display must be acknowledged",
        );
    }
    if let Some(response) = require_unlocked(envelope, state, &request.project_id).await {
        return response;
    }
    not_implemented(
        envelope,
        "recovery-rotate",
        "Recovery rotation reached the typed agent path; fresh verification and envelope rewrite still require CLI-core extraction.",
    )
}

type BackupResult<T> = Result<T, (&'static str, String)>;

fn export_bundle(
    request: &ExportBundleRequest,
    unlocked: &UnlockedProject,
) -> BackupResult<BackupActionResponse> {
    let recipient = bundle_recipient(&request.recipient_descriptor)?;
    let mut store = Store::open(&unlocked.store_path)
        .map_err(|error| ("CorruptDb", format!("could not open store: {error}")))?;
    if store
        .get_project(&request.project_id)
        .map_err(|error| ("CorruptDb", format!("could not read project: {error}")))?
        .is_none()
    {
        return Err(("ProjectNotFound", "project not found".to_owned()));
    }
    if store
        .bundle_recipient_is_denied(&request.project_id, &recipient.sealing_public_key)
        .map_err(|error| ("CorruptDb", error.to_string()))?
    {
        return Err((
            "AccessDenied",
            "recipient device is revoked or its member was removed".to_owned(),
        ));
    }
    let profiles = selected_profiles(&store, &request.project_id, unlocked, &request.scope)?;
    let payload = bundle_payload_with_scope(
        &store,
        &request.project_id,
        &profiles,
        &unlocked.master_key,
        request.include_personal,
        request.include_history,
    )?;
    let selected = payload
        .secrets
        .iter()
        .map(|secret| {
            format!(
                "{} source={} current_version={}",
                secret.name, secret.source, secret.current_version
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    let preview = format!(
        "recipient={}; selected=[{}]; excluded personal={} history={}. {}",
        recipient.fingerprint,
        selected,
        !request.include_personal,
        !request.include_history,
        if payload.secret_count == 0 {
            "No team-managed values selected. For a deliberate personal backup enable include_personal; enable include_history for prior versions."
        } else {
            "Only selected values will be sealed."
        }
    );
    if request.preview_only {
        return Ok(BackupActionResponse {
            action: "export-bundle".to_owned(),
            status: "preview".to_owned(),
            message: preview,
        });
    }
    let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(&payload).map_err(json_error)?);
    let encrypted_payload =
        encrypt_bundle_payload_for_age_recipients(&plaintext, &[recipient.sealing_public_key])
            .map_err(|error| ("MetadataInvalid", format!("bundle encryption failed: {error}")))?;
    let timestamp = current_unix_nanos_i64();
    let manifest = BundleManifest {
        recipient_fingerprints: vec![recipient.fingerprint],
        project_id: request.project_id.clone(),
        schema_version: BUNDLE_SCHEMA_V1,
        created_at: timestamp,
        profile_count: u32::try_from(payload.profile_count).map_err(|_| {
            ("MetadataInvalid", "bundle profile count exceeds schema limit".to_owned())
        })?,
        payload_digest: bundle_encrypted_payload_digest(&encrypted_payload),
    };
    let container = BundleContainer::new(manifest.clone(), encrypted_payload)
        .map_err(|error| ("BundleVerificationFailed", format!("bundle build failed: {error}")))?;
    let output_path = request
        .output_path
        .clone()
        .unwrap_or_else(|| default_bundle_output_path(&unlocked.store_path, timestamp));
    write_bundle_file(&output_path, &container)?;
    write_export_audit(
        &mut store,
        &request.project_id,
        &unlocked.master_key,
        &manifest,
        &payload,
        output_path_kind(&output_path, &unlocked.store_path),
        timestamp,
    )?;
    Ok(BackupActionResponse {
        action: "export-bundle".to_owned(),
        status: "exported".to_owned(),
        message: format!(
            "sealed bundle written to {}; profiles={} secrets={} versions={} blobs={}. {preview}",
            output_path.display(),
            payload.profile_count,
            payload.secret_count,
            payload.secret_version_count,
            payload.blob_count,
        ),
    })
}

fn import_bundle(
    request: &ImportBundleRequest,
    unlocked: &UnlockedProject,
    state: &AgentSocketState,
) -> BackupResult<BackupActionResponse> {
    let bytes = fs::read(&request.bundle_path)
        .map_err(|error| ("BundleVerificationFailed", format!("could not read bundle: {error}")))?;
    let bundle = BundleContainer::deserialize(&bytes).map_err(|error| {
        ("BundleVerificationFailed", format!("bundle verification failed: {error}"))
    })?;
    if let Err(error) = verify_age_payload_structure(&bundle.encrypted_payload) {
        return Err(("BundleVerificationFailed", format!("bundle verification failed: {error}")));
    }
    if bundle.manifest.project_id != request.project_id {
        return Err((
            "BundleVerificationFailed",
            "bundle project id does not match requested project".to_owned(),
        ));
    }
    if bundle_encrypted_payload_digest(&bundle.encrypted_payload) != bundle.manifest.payload_digest
    {
        return Err((
            "BundleVerificationFailed",
            "bundle payload digest does not match manifest".to_owned(),
        ));
    }

    let mut store = Store::open(&unlocked.store_path)
        .map_err(|error| ("CorruptDb", format!("could not open store: {error}")))?;
    if store
        .get_project(&request.project_id)
        .map_err(|error| ("CorruptDb", format!("could not read project: {error}")))?
        .is_none()
    {
        return Err(("ProjectNotFound", "project not found".to_owned()));
    }
    let device = store
        .get_active_local_device(&request.project_id)
        .map_err(|error| ("CorruptDb", format!("could not read local device: {error}")))?
        .ok_or_else(|| {
            ("BundleVerificationFailed", "local device is not initialized".to_owned())
        })?;
    if !bundle
        .manifest
        .recipient_fingerprints
        .iter()
        .map(|fp| store.device_matches_bundle_recipient(&device, fp))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ("CorruptDb", error.to_string()))?
        .into_iter()
        .any(|matches| matches)
    {
        return Err((
            "BundleVerificationFailed",
            "bundle is not addressed to this device".to_owned(),
        ));
    }
    let storage = build_device_private_key_storage(unlocked, state, &request.project_id)?;
    let private_key = storage.load(&device.id).map_err(map_private_key_load_error)?;
    let plaintext =
        decrypt_bundle_payload_with_x25519_secret(&bundle.encrypted_payload, &private_key)
            .map_err(|error| {
                ("BundleVerificationFailed", format!("bundle verification failed: {error}"))
            })?;
    let payload: SealedBundlePayloadV1 = serde_json::from_slice(&plaintext).map_err(|error| {
        ("BundleVerificationFailed", format!("bundle verification failed: {error}"))
    })?;
    if payload.profile_count != payload.profiles.len()
        || payload.command_policy_count != payload.command_policies.len()
        || payload.secret_count != payload.secrets.len()
        || payload.secret_version_count != payload.secret_versions.len()
        || payload.blob_count != payload.blobs.len()
        || payload.profile_key_count != payload.profile_keys.len()
    {
        return Err((
            "BundleVerificationFailed",
            "bundle payload counts do not match row counts".to_owned(),
        ));
    }
    if request.include_audit && payload.audit_chain.is_some() {
        return Err((
            "PolicyValidationIncomplete",
            "agent bundle import does not yet append imported audit chains; retry without include_audit".to_owned(),
        ));
    }
    let counts = ImportedBundleCounts {
        profile_count: payload.profile_count,
        secret_count: payload.secret_count,
        secret_version_count: payload.secret_version_count,
        blob_count: payload.blob_count,
        command_policy_count: payload.command_policy_count,
        profile_key_count: payload.profile_key_count,
    };
    let resolution = ConflictResolution::from_mode(&request.conflict_mode);
    if request.conflict_mode == BundleConflictMode::Review {
        return Ok(BackupActionResponse {
            action: "import-bundle".to_owned(),
            status: "review".to_owned(),
            message: format!(
                "Issuer unauthenticated. Review {} profiles and {} secrets; select accept-incoming or accept-local to explicitly apply. {} command definitions remain proposed metadata and will not grant authority.",
                payload.profiles.len(),
                payload.secrets.len(),
                payload.command_policies.len()
            ),
        });
    }
    let timestamp = current_unix_nanos_i64();
    let outcome = apply_bundle_payload(
        &mut store,
        &request.project_id,
        &payload,
        resolution,
        &unlocked.master_key,
        timestamp,
    )?;
    let (applied, conflicts) = match outcome {
        ApplyOutcome::Applied { applied, conflicts } => (applied, conflicts),
        ApplyOutcome::ReviewRequired { divergent } => {
            return Err((
                "InvalidReference",
                format!(
                    "bundle conflicts require accept-incoming or accept-local: {}",
                    divergent.join(", ")
                ),
            ));
        }
    };
    write_import_audit(
        &mut store,
        &request.project_id,
        &unlocked.master_key,
        &bundle.manifest,
        &counts,
        &applied,
        &conflicts,
        resolution.label(),
        request.include_audit,
        timestamp,
    )?;
    Ok(BackupActionResponse {
        action: "import-bundle".to_owned(),
        status: "applied".to_owned(),
        message: format!(
            "Issuer unauthenticated; command definitions were not authorized. Bundle applied; archived_local_profiles={} profiles={} secrets={} versions={} blobs={} command_policies={} conflicts_applied={} conflicts_rejected={}",
            applied.archived_local_profile_count,
            applied.profile_count,
            applied.secret_count,
            applied.secret_version_count,
            applied.blob_count,
            applied.command_policy_count,
            conflicts.applied,
            conflicts.rejected,
        ),
    })
}

fn selected_profiles(
    store: &Store,
    project_id: &str,
    unlocked: &UnlockedProject,
    scope: &BundleExportScope,
) -> BackupResult<Vec<ProfileRecord>> {
    let profiles = store
        .list_profiles(project_id)
        .map_err(|error| ("CorruptDb", format!("could not list profiles: {error}")))?;
    match scope {
        BundleExportScope::AllProfiles => Ok(profiles),
        BundleExportScope::ActiveProfile => {
            let Some(profile_id) = unlocked.profile_id.as_deref() else {
                return Err((
                    "MetadataInvalid",
                    "active-profile export requires unlock audit profile context".to_owned(),
                ));
            };
            profiles
                .into_iter()
                .find(|profile| profile.id == profile_id || profile.name == profile_id)
                .map(|profile| vec![profile])
                .ok_or_else(|| ("ProfileNotFound", "active profile not found".to_owned()))
        }
    }
}

#[cfg(test)]
fn bundle_payload(
    store: &Store,
    project_id: &str,
    profiles: &[ProfileRecord],
    master_key: &locket_crypto::KeyBytes,
) -> BackupResult<SealedBundlePayloadV1> {
    bundle_payload_with_scope(store, project_id, profiles, master_key, false, false)
}

fn bundle_payload_with_scope(
    store: &Store,
    project_id: &str,
    profiles: &[ProfileRecord],
    master_key: &locket_crypto::KeyBytes,
    include_personal: bool,
    include_history: bool,
) -> BackupResult<SealedBundlePayloadV1> {
    let command_policies = bundle_command_policies(store)?;
    let mut profile_payloads = Vec::with_capacity(profiles.len());
    let mut secrets = Vec::new();
    let mut secret_versions = Vec::new();
    let mut blobs = Vec::new();
    let mut profile_keys = Vec::with_capacity(profiles.len().saturating_mul(2));
    let mut active_secret_count = 0_usize;
    for profile in profiles {
        let active_secrets = store
            .select_bundle_secrets(project_id, &profile.id, include_personal, include_history)
            .map_err(|error| ("CorruptDb", format!("could not list active secrets: {error}")))?;
        let active_count = active_secrets
            .iter()
            .filter(|(secret, _)| secret.state == "active" && secret.deleted_at.is_none())
            .count();
        active_secret_count = active_secret_count.saturating_add(active_count);
        profile_payloads.push(SealedBundleProfileV1 {
            profile_id: profile.id.clone(),
            name: profile.name.clone(),
            dangerous: profile.dangerous,
            active_secret_count: active_count,
            created_at: profile.created_at,
        });
        profile_keys.extend(bundle_profile_keys(store, project_id, &profile.id, master_key)?);
        for (secret, versions) in active_secrets {
            for version in versions {
                if let Some(blob) = store
                    .get_blob(&secret.id, version.version)
                    .map_err(|error| ("CorruptDb", format!("could not read blob: {error}")))?
                {
                    blobs.push(bundle_blob(blob));
                }
                secret_versions.push(SealedBundleSecretVersionV1 {
                    secret_id: version.secret_id,
                    version: version.version,
                    source: version.source,
                    origin: version.origin,
                    state: version.state,
                    created_at: version.created_at,
                    deprecated_at: version.deprecated_at,
                    grace_until: version.grace_until,
                    purged_at: version.purged_at,
                });
            }
            secrets.push(bundle_secret(secret));
        }
    }
    Ok(SealedBundlePayloadV1 {
        profile_count: profile_payloads.len(),
        command_policy_count: command_policies.len(),
        secret_count: secrets.len(),
        secret_version_count: secret_versions.len(),
        blob_count: blobs.len(),
        profile_key_count: profile_keys.len(),
        active_secret_count,
        audit_rows_included: false,
        profiles: profile_payloads,
        command_policies,
        secrets,
        secret_versions,
        blobs,
        profile_keys,
        audit_chain: None,
    })
}

fn bundle_command_policies(store: &Store) -> BackupResult<Vec<SealedBundleCommandPolicyV1>> {
    let Some(root) = project_root_from_store_path(store)? else {
        return Ok(Vec::new());
    };
    let policy_path = root.join("locket.toml");
    let text = match fs::read_to_string(&policy_path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(("MetadataInvalid", format!("could not read command policies: {error}")));
        }
    };
    let document = PolicyDocument::from_toml_str(&text)
        .map_err(|error| ("MetadataInvalid", format!("command policy parse failed: {error}")))?;
    Ok(document.commands.values().map(bundle_command_policy).collect())
}

fn project_root_from_store_path(store: &Store) -> BackupResult<Option<PathBuf>> {
    let path: String =
        match store.connection().query_row("PRAGMA database_list", [], |row| row.get(2)) {
            Ok(path) => path,
            Err(error) => {
                return Err(("CorruptDb", format!("could not resolve store path: {error}")));
            }
        };
    let path = PathBuf::from(path);
    Ok(path.parent().and_then(Path::parent).map(Path::to_path_buf))
}

fn bundle_command_policy(policy: &CommandPolicy) -> SealedBundleCommandPolicyV1 {
    let (argv, shell) = match &policy.command {
        CommandSpec::Argv(arguments) => (arguments.clone(), None),
        CommandSpec::Shell(script) => (Vec::new(), Some(script.clone())),
    };
    SealedBundleCommandPolicyV1 {
        name: policy.name.clone(),
        command_kind: command_type(&policy.command).to_owned(),
        argv,
        shell,
        allowed_secrets: policy
            .allowed_secrets
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
        required_secrets: policy
            .required_secrets
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
        optional_secrets: policy
            .optional_secrets
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
        inherit_env: policy.inherit_env.clone(),
        env_mode: policy.env_mode.as_str().to_owned(),
        override_mode: policy.override_behavior.as_str().to_owned(),
        override_explicit: policy.override_explicit(),
        external_env_sources: policy
            .external_env_sources
            .iter()
            .map(external_env_source_label)
            .collect(),
        allow_remote_docker: policy.allow_remote_docker,
        confirm: policy.confirm,
        require_user_verification: policy.require_user_verification,
        ttl_seconds: policy.ttl.as_secs(),
    }
}

const fn command_type(command: &CommandSpec) -> &'static str {
    match command {
        CommandSpec::Argv(_) => "argv",
        CommandSpec::Shell(_) => "shell",
    }
}

fn external_env_source_label(source: &ExternalEnvSource) -> String {
    match source {
        ExternalEnvSource::Parent => "parent".to_owned(),
        ExternalEnvSource::File(path) => format!("file:{}", path.display()),
        ExternalEnvSource::Compose => "compose".to_owned(),
        ExternalEnvSource::Ide => "ide".to_owned(),
    }
}

fn validate_bundle_project_scope(
    transaction: &rusqlite::Transaction<'_>,
    project_id: &str,
    payload: &SealedBundlePayloadV1,
) -> BackupResult<()> {
    use rusqlite::OptionalExtension as _;

    let incoming_profiles: BTreeSet<_> =
        payload.profiles.iter().map(|row| row.profile_id.as_str()).collect();
    let profiles: BTreeSet<_> = incoming_profiles
        .iter()
        .copied()
        .chain(payload.profile_keys.iter().map(|row| row.profile_id.as_str()))
        .chain(payload.secrets.iter().map(|row| row.profile_id.as_str()))
        .collect();
    for profile in profiles {
        let owner: Option<String> = transaction
            .query_row("SELECT project_id FROM profiles WHERE id = ?1", [profile], |row| row.get(0))
            .optional()
            .map_err(map_apply_sqlite_error)?;
        if owner.as_deref().is_some_and(|owner| owner != project_id)
            || (owner.is_none() && !incoming_profiles.contains(profile))
        {
            return Err((
                "BundleVerificationFailed",
                "bundle row is outside the requested project".to_owned(),
            ));
        }
    }

    let incoming_secrets: BTreeSet<_> = payload.secrets.iter().map(|row| row.id.as_str()).collect();
    let secrets: BTreeSet<_> = incoming_secrets
        .iter()
        .copied()
        .chain(payload.secret_versions.iter().map(|row| row.secret_id.as_str()))
        .chain(payload.blobs.iter().map(|row| row.secret_id.as_str()))
        .collect();
    for secret in secrets {
        let owner: Option<String> = transaction
            .query_row("SELECT project_id FROM secrets WHERE id = ?1", [secret], |row| row.get(0))
            .optional()
            .map_err(map_apply_sqlite_error)?;
        if owner.as_deref().is_some_and(|owner| owner != project_id)
            || (owner.is_none() && !incoming_secrets.contains(secret))
        {
            return Err((
                "BundleVerificationFailed",
                "bundle row is outside the requested project".to_owned(),
            ));
        }
    }
    Ok(())
}

fn apply_bundle_payload(
    store: &mut Store,
    project_id: &str,
    payload: &SealedBundlePayloadV1,
    resolution: ConflictResolution,
    receiver_master_key: &locket_crypto::KeyBytes,
    now: i64,
) -> BackupResult<ApplyOutcome> {
    for key in &payload.profile_keys {
        let purpose = parse_key_purpose(&key.purpose)?;
        if store
            .get_key_by_scope(project_id, Some(&key.profile_id), purpose.as_str())
            .map_err(|e| ("CorruptDb", e.to_string()))?
            .is_some()
        {
            let local = load_profile_key_with_master(
                store,
                project_id,
                &key.profile_id,
                purpose,
                receiver_master_key,
            )?;
            let incoming = decode_key_material(&key.key_material_b64, "profile key")?;
            if local.as_slice() != incoming.as_slice() {
                return Err(("MetadataInvalid", "bundle profile key conflicts with local keys; import into a separate store to preserve existing secrets".to_owned()));
            }
        }
    }
    let mut retained_secrets = BTreeSet::new();
    let mut rotated_versions = Vec::new();
    let mut applied = AppliedBundleCounts::default();
    let mut conflicts = BundleConflictCounts::default();
    let mut divergent = Vec::new();
    let transaction = store
        .connection_mut()
        .transaction()
        .map_err(|error| ("CorruptDb", format!("apply transaction begin failed: {error}")))?;

    validate_bundle_project_scope(&transaction, project_id, payload)?;

    for profile in &payload.profiles {
        use rusqlite::OptionalExtension as _;
        let same_name: Option<String> = transaction
            .query_row(
                "SELECT id FROM profiles WHERE project_id = ?1 AND name = ?2 AND id != ?3",
                params![project_id, profile.name, profile.profile_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_apply_sqlite_error)?;
        if let Some(local_id) = same_name {
            let count: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM secrets WHERE profile_id = ?1",
                    [&local_id],
                    |row| row.get(0),
                )
                .map_err(map_apply_sqlite_error)?;
            if count != 0 {
                return Err(("MetadataInvalid", "same-name local profile contains secrets with incompatible identity; import into a separate store".to_owned()));
            }
            locket_store::archive_empty_profile_for_import(&transaction, project_id, &local_id)
                .map_err(|error| ("CorruptDb", error.to_string()))?
                .ok_or_else(|| {
                    ("MetadataInvalid", "local profile is no longer empty".to_owned())
                })?;
            applied.archived_local_profile_count += 1;
        }
        match read_local_profile(&transaction, project_id, &profile.profile_id)? {
            None => {
                transaction
                    .execute(
                        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            profile.profile_id,
                            project_id,
                            profile.name,
                            profile.dangerous,
                            profile.created_at,
                        ],
                    )
                    .map_err(map_apply_sqlite_error)?;
                applied.profile_count = applied.profile_count.saturating_add(1);
                conflicts.applied = conflicts.applied.saturating_add(1);
            }
            Some(local) => {
                let identical = local.name == profile.name
                    && local.dangerous == profile.dangerous
                    && local.created_at == profile.created_at;
                if identical {
                    conflicts.identical = conflicts.identical.saturating_add(1);
                } else if resolve_divergent(
                    resolution,
                    &mut conflicts,
                    &mut divergent,
                    "profile",
                    &profile.profile_id,
                ) == DivergentDecision::Apply
                {
                    transaction
                        .execute(
                            "UPDATE profiles
                             SET name = ?2, dangerous = ?3, created_at = ?4
                             WHERE id = ?1 AND project_id = ?5",
                            params![
                                profile.profile_id,
                                profile.name,
                                profile.dangerous,
                                profile.created_at,
                                project_id,
                            ],
                        )
                        .map_err(map_apply_sqlite_error)?;
                    applied.profile_count = applied.profile_count.saturating_add(1);
                }
            }
        }
    }

    for profile_key in &payload.profile_keys {
        let purpose = parse_key_purpose(&profile_key.purpose)?;
        let exists = transaction
            .query_row(
                "SELECT 1 FROM keys
                 WHERE project_id = ?1 AND profile_id IS ?2 AND purpose = ?3",
                params![project_id, profile_key.profile_id, profile_key.purpose],
                |_| Ok(()),
            )
            .map(Some)
            .or_else(|error| {
                if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                    Ok(None)
                } else {
                    Err(error)
                }
            })
            .map_err(map_apply_sqlite_error)?
            .is_some();
        if exists {
            conflicts.identical = conflicts.identical.saturating_add(1);
            continue;
        }
        let plaintext = decode_key_material(&profile_key.key_material_b64, "profile key")?;
        let receiver_key_id = KeyId::generate()
            .map_err(|error| ("MetadataInvalid", format!("key id generation failed: {error}")))?;
        let wrapped = rewrap_imported_profile_key(
            receiver_master_key,
            project_id,
            &profile_key.profile_id,
            receiver_key_id.as_str(),
            purpose,
            &plaintext,
        )?;
        let key_record = KeyRecord {
            id: receiver_key_id.into_string(),
            project_id: project_id.to_owned(),
            profile_id: Some(profile_key.profile_id.clone()),
            purpose: purpose.as_str().to_owned(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: now,
        };
        transaction
            .execute(
                "INSERT INTO keys(id, project_id, profile_id, purpose, wrapped_material, nonce, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    key_record.id,
                    key_record.project_id,
                    key_record.profile_id,
                    key_record.purpose,
                    key_record.wrapped_material,
                    key_record.nonce,
                    key_record.created_at,
                ],
            )
            .map_err(map_apply_sqlite_error)?;
        applied.profile_key_count = applied.profile_key_count.saturating_add(1);
        conflicts.applied = conflicts.applied.saturating_add(1);
    }

    // Unsigned bundles carry proposed definitions only. Never mutate command authority.

    for secret in &payload.secrets {
        match read_local_secret(&transaction, &secret.id)? {
            None => {
                transaction
                    .execute(
                        "INSERT INTO secrets(
                           id, project_id, profile_id, name, source, origin, required,
                           current_version, state, created_at, updated_at, last_rotated_at, deleted_at
                         )
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, ?10, ?11, ?12)",
                        params![
                            secret.id,
                            project_id,
                            secret.profile_id,
                            secret.name,
                            secret.source,
                            secret.origin,
                            secret.current_version,
                            secret.state,
                            secret.created_at,
                            secret.updated_at,
                            secret.last_rotated_at,
                            secret.deleted_at,
                        ],
                    )
                    .map_err(map_apply_sqlite_error)?;
                applied.secret_count = applied.secret_count.saturating_add(1);
                conflicts.applied = conflicts.applied.saturating_add(1);
            }
            Some(local) => {
                let identical = local.profile_id == secret.profile_id
                    && local.name == secret.name
                    && local.source == secret.source
                    && local.origin == secret.origin
                    && local.current_version == secret.current_version
                    && local.state == secret.state
                    && local.created_at == secret.created_at
                    && local.updated_at == secret.updated_at
                    && local.last_rotated_at == secret.last_rotated_at
                    && local.deleted_at == secret.deleted_at;
                if identical {
                    conflicts.identical = conflicts.identical.saturating_add(1);
                    continue;
                }
                let deleted_vs_active = local.state != secret.state;
                if deleted_vs_active {
                    conflicts.deleted_vs_active = conflicts.deleted_vs_active.saturating_add(1);
                }
                let newer_incoming = secret.updated_at > local.updated_at
                    || secret.current_version > local.current_version;
                if newer_incoming && !deleted_vs_active {
                    conflicts.newer_incoming = conflicts.newer_incoming.saturating_add(1);
                }
                let decision = if deleted_vs_active || !newer_incoming {
                    resolve_divergent(
                        resolution,
                        &mut conflicts,
                        &mut divergent,
                        "secret",
                        &secret.id,
                    )
                } else {
                    resolve_newer_incoming(
                        resolution,
                        &mut conflicts,
                        &mut divergent,
                        "secret",
                        &secret.id,
                    )
                };
                if decision == DivergentDecision::Skip {
                    retained_secrets.insert(secret.id.as_str());
                }
                if decision == DivergentDecision::Apply {
                    if secret.current_version != local.current_version {
                        rotated_versions.push((secret.id.as_str(), local.current_version));
                    }
                    transaction
                        .execute(
                            "UPDATE secrets
                             SET profile_id = ?2, name = ?3, source = ?4, origin = ?5,
                                 current_version = ?6, state = ?7, created_at = ?8,
                                 updated_at = ?9, last_rotated_at = ?10, deleted_at = ?11
                             WHERE id = ?1",
                            params![
                                secret.id,
                                secret.profile_id,
                                secret.name,
                                secret.source,
                                secret.origin,
                                secret.current_version,
                                secret.state,
                                secret.created_at,
                                secret.updated_at,
                                now,
                                secret.deleted_at,
                            ],
                        )
                        .map_err(map_apply_sqlite_error)?;
                    applied.secret_count = applied.secret_count.saturating_add(1);
                }
            }
        }
    }

    for version in &payload.secret_versions {
        if retained_secrets.contains(version.secret_id.as_str()) {
            conflicts.rejected = conflicts.rejected.saturating_add(1);
            continue;
        }
        match read_local_secret_version(&transaction, &version.secret_id, version.version)? {
            None => {
                if version.state == "current" {
                    deprecate_local_current_version(&transaction, &version.secret_id, now)?;
                }
                insert_secret_version(&transaction, version)?;
                applied.secret_version_count = applied.secret_version_count.saturating_add(1);
                conflicts.applied = conflicts.applied.saturating_add(1);
            }
            Some(local) => {
                // An accepted import must not revive a locally expired grace window,
                // including when replaying the bundle that caused the local rotation.
                let preserve_expiry = local.state == "deprecated"
                    && version.state == "deprecated"
                    && local.grace_until.is_none_or(|until| until <= now);
                let deprecated_at =
                    if preserve_expiry { local.deprecated_at } else { version.deprecated_at };
                let grace_until =
                    if preserve_expiry { local.grace_until } else { version.grace_until };
                let identical = local.source == version.source
                    && local.origin == version.origin
                    && local.state == version.state
                    && local.created_at == version.created_at
                    && local.deprecated_at == deprecated_at
                    && local.grace_until == grace_until
                    && local.purged_at == version.purged_at;
                if identical {
                    conflicts.identical = conflicts.identical.saturating_add(1);
                    continue;
                }
                let deleted_vs_active = (local.state == "current") != (version.state == "current");
                if deleted_vs_active {
                    conflicts.deleted_vs_active = conflicts.deleted_vs_active.saturating_add(1);
                }
                let newer_incoming = !deleted_vs_active && version.created_at > local.created_at;
                if newer_incoming {
                    conflicts.newer_incoming = conflicts.newer_incoming.saturating_add(1);
                }
                let decision = if deleted_vs_active || !newer_incoming {
                    resolve_divergent(
                        resolution,
                        &mut conflicts,
                        &mut divergent,
                        "secret_version",
                        &format!("{}@{}", version.secret_id, version.version),
                    )
                } else {
                    resolve_newer_incoming(
                        resolution,
                        &mut conflicts,
                        &mut divergent,
                        "secret_version",
                        &format!("{}@{}", version.secret_id, version.version),
                    )
                };
                if decision == DivergentDecision::Apply {
                    transaction
                        .execute(
                            "UPDATE secret_versions
                             SET source = ?3, origin = ?4, state = ?5, created_at = ?6,
                                 deprecated_at = ?7, grace_until = ?8, purged_at = ?9
                             WHERE secret_id = ?1 AND version = ?2",
                            params![
                                version.secret_id,
                                version.version,
                                version.source,
                                version.origin,
                                version.state,
                                version.created_at,
                                deprecated_at,
                                grace_until,
                                version.purged_at,
                            ],
                        )
                        .map_err(map_apply_sqlite_error)?;
                    applied.secret_version_count = applied.secret_version_count.saturating_add(1);
                }
            }
        }
    }

    for (secret_id, version) in rotated_versions {
        transaction.execute(
            "UPDATE secret_versions SET state = 'deprecated', deprecated_at = ?3, grace_until = ?3
             WHERE secret_id = ?1 AND version = ?2 AND state != 'purged'",
            params![secret_id, version, now],
        ).map_err(map_apply_sqlite_error)?;
    }

    for blob in &payload.blobs {
        if retained_secrets.contains(blob.secret_id.as_str()) {
            conflicts.rejected = conflicts.rejected.saturating_add(1);
            continue;
        }
        match read_local_blob(&transaction, &blob.secret_id, blob.version)? {
            None => {
                let blob_record = decode_bundle_blob(blob)?;
                insert_blob(&transaction, &blob_record)?;
                applied.blob_count = applied.blob_count.saturating_add(1);
                conflicts.applied = conflicts.applied.saturating_add(1);
            }
            Some(local) => {
                let incoming = decode_bundle_blob(blob)?;
                let identical = local.encrypted_dek == incoming.encrypted_dek
                    && local.ciphertext == incoming.ciphertext
                    && local.value_nonce == incoming.value_nonce;
                if identical {
                    conflicts.identical = conflicts.identical.saturating_add(1);
                } else if resolve_divergent(
                    resolution,
                    &mut conflicts,
                    &mut divergent,
                    "blob",
                    &format!("{}@{}", blob.secret_id, blob.version),
                ) == DivergentDecision::Apply
                {
                    update_blob(&transaction, &incoming)?;
                    applied.blob_count = applied.blob_count.saturating_add(1);
                }
            }
        }
    }

    if !divergent.is_empty() && resolution == ConflictResolution::Review {
        transaction.rollback().map_err(|error| {
            ("CorruptDb", format!("apply transaction rollback failed: {error}"))
        })?;
        return Ok(ApplyOutcome::ReviewRequired { divergent });
    }

    transaction
        .commit()
        .map_err(|error| ("CorruptDb", format!("apply transaction commit failed: {error}")))?;
    Ok(ApplyOutcome::Applied { applied, conflicts })
}

fn resolve_newer_incoming(
    resolution: ConflictResolution,
    conflicts: &mut BundleConflictCounts,
    divergent: &mut Vec<String>,
    family: &str,
    identifier: &str,
) -> DivergentDecision {
    match resolution {
        ConflictResolution::AcceptIncoming => {
            conflicts.applied = conflicts.applied.saturating_add(1);
            DivergentDecision::Apply
        }
        ConflictResolution::AcceptLocal => {
            conflicts.rejected = conflicts.rejected.saturating_add(1);
            DivergentDecision::Skip
        }
        ConflictResolution::Review => {
            divergent.push(format!("{family}/{identifier}: newer-incoming"));
            DivergentDecision::Defer
        }
    }
}

fn resolve_divergent(
    resolution: ConflictResolution,
    conflicts: &mut BundleConflictCounts,
    divergent: &mut Vec<String>,
    family: &str,
    identifier: &str,
) -> DivergentDecision {
    conflicts.divergent = conflicts.divergent.saturating_add(1);
    match resolution {
        ConflictResolution::AcceptIncoming => {
            conflicts.applied = conflicts.applied.saturating_add(1);
            DivergentDecision::Apply
        }
        ConflictResolution::AcceptLocal => {
            conflicts.rejected = conflicts.rejected.saturating_add(1);
            DivergentDecision::Skip
        }
        ConflictResolution::Review => {
            divergent.push(format!("{family}/{identifier}: divergent"));
            DivergentDecision::Defer
        }
    }
}

#[derive(Debug)]
struct LocalProfileRow {
    name: String,
    dangerous: bool,
    created_at: i64,
}

fn read_local_profile(
    transaction: &rusqlite::Transaction<'_>,
    project_id: &str,
    profile_id: &str,
) -> BackupResult<Option<LocalProfileRow>> {
    use rusqlite::OptionalExtension;
    transaction
        .query_row(
            "SELECT name, dangerous, created_at
             FROM profiles
             WHERE id = ?1 AND project_id = ?2",
            params![profile_id, project_id],
            |row| {
                Ok(LocalProfileRow {
                    name: row.get(0)?,
                    dangerous: row.get(1)?,
                    created_at: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(map_apply_sqlite_error)
}

#[derive(Debug)]
struct LocalSecretRow {
    profile_id: String,
    name: String,
    source: String,
    origin: String,
    current_version: u32,
    state: String,
    created_at: i64,
    updated_at: i64,
    last_rotated_at: Option<i64>,
    deleted_at: Option<i64>,
}

fn read_local_secret(
    transaction: &rusqlite::Transaction<'_>,
    secret_id: &str,
) -> BackupResult<Option<LocalSecretRow>> {
    use rusqlite::OptionalExtension;
    transaction
        .query_row(
            "SELECT profile_id, name, source, origin, current_version, state,
                    created_at, updated_at, last_rotated_at, deleted_at
             FROM secrets
             WHERE id = ?1",
            params![secret_id],
            |row| {
                Ok(LocalSecretRow {
                    profile_id: row.get(0)?,
                    name: row.get(1)?,
                    source: row.get(2)?,
                    origin: row.get(3)?,
                    current_version: row.get(4)?,
                    state: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                    last_rotated_at: row.get(8)?,
                    deleted_at: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(map_apply_sqlite_error)
}

#[derive(Debug)]
struct LocalSecretVersionRow {
    source: String,
    origin: String,
    state: String,
    created_at: i64,
    deprecated_at: Option<i64>,
    grace_until: Option<i64>,
    purged_at: Option<i64>,
}

fn read_local_secret_version(
    transaction: &rusqlite::Transaction<'_>,
    secret_id: &str,
    version: u32,
) -> BackupResult<Option<LocalSecretVersionRow>> {
    use rusqlite::OptionalExtension;
    transaction
        .query_row(
            "SELECT source, origin, state, created_at, deprecated_at, grace_until, purged_at
             FROM secret_versions
             WHERE secret_id = ?1 AND version = ?2",
            params![secret_id, version],
            |row| {
                Ok(LocalSecretVersionRow {
                    source: row.get(0)?,
                    origin: row.get(1)?,
                    state: row.get(2)?,
                    created_at: row.get(3)?,
                    deprecated_at: row.get(4)?,
                    grace_until: row.get(5)?,
                    purged_at: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(map_apply_sqlite_error)
}

#[derive(Debug)]
struct LocalBlobRow {
    encrypted_dek: Vec<u8>,
    ciphertext: Vec<u8>,
    value_nonce: [u8; 24],
}

fn read_local_blob(
    transaction: &rusqlite::Transaction<'_>,
    secret_id: &str,
    version: u32,
) -> BackupResult<Option<LocalBlobRow>> {
    use rusqlite::OptionalExtension;
    transaction
        .query_row(
            "SELECT encrypted_dek, ciphertext, value_nonce
             FROM blobs
             WHERE secret_id = ?1 AND version = ?2",
            params![secret_id, version],
            |row| {
                let nonce_bytes: Vec<u8> = row.get(2)?;
                let mut nonce = [0_u8; 24];
                if nonce_bytes.len() != 24 {
                    return Err(rusqlite::Error::InvalidColumnType(
                        2,
                        "blobs.value_nonce".to_owned(),
                        rusqlite::types::Type::Blob,
                    ));
                }
                nonce.copy_from_slice(&nonce_bytes);
                Ok(LocalBlobRow {
                    encrypted_dek: row.get(0)?,
                    ciphertext: row.get(1)?,
                    value_nonce: nonce,
                })
            },
        )
        .optional()
        .map_err(map_apply_sqlite_error)
}

fn deprecate_local_current_version(
    transaction: &rusqlite::Transaction<'_>,
    secret_id: &str,
    now: i64,
) -> BackupResult<()> {
    transaction
        .execute(
            "UPDATE secret_versions
             SET state = 'deprecated', deprecated_at = ?2, grace_until = ?2
             WHERE secret_id = ?1 AND state = 'current'",
            params![secret_id, now],
        )
        .map_err(map_apply_sqlite_error)?;
    Ok(())
}

fn insert_secret_version(
    transaction: &rusqlite::Transaction<'_>,
    version: &SealedBundleSecretVersionV1,
) -> BackupResult<()> {
    transaction
        .execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                version.secret_id,
                version.version,
                version.source,
                version.origin,
                version.state,
                version.created_at,
                version.deprecated_at,
                version.grace_until,
                version.purged_at,
            ],
        )
        .map_err(map_apply_sqlite_error)?;
    Ok(())
}

fn insert_blob(
    transaction: &rusqlite::Transaction<'_>,
    blob: &SecretBlobRecord,
) -> BackupResult<()> {
    transaction
        .execute(
            "INSERT INTO blobs(
               secret_id, version, encrypted_dek, ciphertext, value_nonce,
               aad_schema_version, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                blob.secret_id,
                blob.version,
                blob.encrypted_dek,
                blob.ciphertext,
                blob.value_nonce.as_slice(),
                blob.aad_schema_version,
                blob.created_at,
            ],
        )
        .map_err(map_apply_sqlite_error)?;
    Ok(())
}

fn update_blob(
    transaction: &rusqlite::Transaction<'_>,
    blob: &SecretBlobRecord,
) -> BackupResult<()> {
    transaction
        .execute(
            "UPDATE blobs
             SET encrypted_dek = ?3, ciphertext = ?4, value_nonce = ?5,
                 aad_schema_version = ?6, created_at = ?7
             WHERE secret_id = ?1 AND version = ?2",
            params![
                blob.secret_id,
                blob.version,
                blob.encrypted_dek,
                blob.ciphertext,
                blob.value_nonce.as_slice(),
                blob.aad_schema_version,
                blob.created_at,
            ],
        )
        .map_err(map_apply_sqlite_error)?;
    Ok(())
}

fn decode_bundle_blob(blob: &SealedBundleBlobV1) -> BackupResult<SecretBlobRecord> {
    let encrypted_dek =
        BASE64URL_NOPAD.decode(blob.encrypted_dek_b64.as_bytes()).map_err(|_| {
            ("BundleVerificationFailed", "blob encrypted_dek_b64 is not valid base64url".to_owned())
        })?;
    let ciphertext = BASE64URL_NOPAD.decode(blob.ciphertext_b64.as_bytes()).map_err(|_| {
        ("BundleVerificationFailed", "blob ciphertext_b64 is not valid base64url".to_owned())
    })?;
    let nonce_bytes = BASE64URL_NOPAD.decode(blob.value_nonce_b64.as_bytes()).map_err(|_| {
        ("BundleVerificationFailed", "blob value_nonce_b64 is not valid base64url".to_owned())
    })?;
    if nonce_bytes.len() != 24 {
        return Err(("BundleVerificationFailed", "blob value_nonce must be 24 bytes".to_owned()));
    }
    let mut value_nonce = [0_u8; 24];
    value_nonce.copy_from_slice(&nonce_bytes);
    Ok(SecretBlobRecord {
        secret_id: blob.secret_id.clone(),
        version: blob.version,
        encrypted_dek,
        ciphertext,
        value_nonce,
        aad_schema_version: blob.aad_schema_version,
        created_at: blob.created_at,
    })
}

fn parse_key_purpose(value: &str) -> BackupResult<KeyPurpose> {
    match value {
        v if v == KeyPurpose::ProfileSecret.as_str() => Ok(KeyPurpose::ProfileSecret),
        v if v == KeyPurpose::ProfileFingerprint.as_str() => Ok(KeyPurpose::ProfileFingerprint),
        other => Err((
            "BundleVerificationFailed",
            format!("unknown profile key purpose in bundle: {other}"),
        )),
    }
}

fn decode_key_material(value: &str, label: &str) -> BackupResult<locket_crypto::KeyBytes> {
    let bytes = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| {
        ("BundleVerificationFailed", format!("{label} material is not valid base64url"))
    })?;
    let mut out = [0_u8; locket_crypto::KEY_LEN];
    if bytes.len() != out.len() {
        return Err(("BundleVerificationFailed", format!("{label} material has wrong length")));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn rewrap_imported_profile_key(
    receiver_master_key: &locket_crypto::KeyBytes,
    project_id: &str,
    profile_id: &str,
    key_id: &str,
    purpose: KeyPurpose,
    plaintext: &locket_crypto::KeyBytes,
) -> BackupResult<WrappedKeyMaterial> {
    let wrapping_key = derive_wrapping_key_v1(
        receiver_master_key,
        &HkdfWrapInfo::new(project_id, Some(profile_id), purpose),
    )
    .map_err(|error| ("MetadataInvalid", format!("profile key derivation failed: {error}")))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        key_id,
        Some(profile_id),
        0,
        KeyWrapPurpose::from(purpose),
    ))
    .map_err(|error| ("MetadataInvalid", format!("profile key aad failed: {error}")))?;
    wrap_key_material_v1(&wrapping_key, plaintext, &aad)
        .map_err(|error| ("MetadataInvalid", format!("profile key wrap failed: {error}")))
}

fn map_apply_sqlite_error(error: rusqlite::Error) -> (&'static str, String) {
    ("CorruptDb", format!("apply step failed: {error}"))
}

fn bundle_profile_keys(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    master_key: &locket_crypto::KeyBytes,
) -> BackupResult<Vec<SealedBundleProfileKeyV1>> {
    [KeyPurpose::ProfileSecret, KeyPurpose::ProfileFingerprint]
        .into_iter()
        .map(|purpose| {
            let key =
                load_profile_key_with_master(store, project_id, profile_id, purpose, master_key)?;
            Ok(SealedBundleProfileKeyV1 {
                profile_id: profile_id.to_owned(),
                purpose: purpose.as_str().to_owned(),
                key_material_b64: BASE64URL_NOPAD.encode(key.as_ref()),
            })
        })
        .collect()
}

fn load_profile_key_with_master(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
) -> BackupResult<zeroize::Zeroizing<locket_crypto::KeyBytes>> {
    let record = store
        .get_key_by_scope(project_id, Some(profile_id), purpose.as_str())
        .map_err(|error| ("CorruptDb", format!("could not read profile key: {error}")))?
        .ok_or_else(|| {
            ("AuditIntegrityFailed", format!("profile {} key is missing", purpose.as_str()))
        })?;
    let wrapping_key = derive_wrapping_key_v1(
        master_key,
        &HkdfWrapInfo::new(project_id, Some(profile_id), purpose),
    )
    .map_err(|error| ("MetadataInvalid", format!("profile key derivation failed: {error}")))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        Some(profile_id),
        0,
        KeyWrapPurpose::from(purpose),
    ))
    .map_err(|error| ("MetadataInvalid", format!("profile key aad failed: {error}")))?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    unwrap_key_material_v1(&wrapping_key, &wrapped, &aad)
        .map_err(|error| ("AuditIntegrityFailed", format!("profile key unwrap failed: {error}")))
}

fn bundle_secret(secret: SecretRecord) -> SealedBundleSecretV1 {
    SealedBundleSecretV1 {
        id: secret.id,
        profile_id: secret.profile_id,
        name: secret.name,
        source: secret.source,
        origin: secret.origin,
        current_version: secret.current_version,
        state: secret.state,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
        last_rotated_at: secret.last_rotated_at,
        deleted_at: secret.deleted_at,
    }
}

fn bundle_blob(blob: SecretBlobRecord) -> SealedBundleBlobV1 {
    SealedBundleBlobV1 {
        secret_id: blob.secret_id,
        version: blob.version,
        encrypted_dek_b64: BASE64URL_NOPAD.encode(&blob.encrypted_dek),
        ciphertext_b64: BASE64URL_NOPAD.encode(&blob.ciphertext),
        value_nonce_b64: BASE64URL_NOPAD.encode(&blob.value_nonce),
        aad_schema_version: blob.aad_schema_version,
        created_at: blob.created_at,
    }
}

fn bundle_recipient(value: &str) -> BackupResult<BundleRecipientV1> {
    let descriptor = decode_device_descriptor(value)?;
    let signing_public_key = decode_descriptor_key(&descriptor.signing_public_key_ed25519)?;
    let sealing_public_key = decode_descriptor_key(&descriptor.sealing_public_key_x25519)?;
    let fingerprint = device_fingerprint_hex(&signing_public_key, &sealing_public_key);
    if fingerprint != descriptor.fingerprint_sha256 {
        return Err((
            "MetadataInvalid",
            "recipient device descriptor fingerprint mismatch".to_owned(),
        ));
    }
    Ok(BundleRecipientV1 { fingerprint, sealing_public_key })
}

fn decode_device_descriptor(value: &str) -> BackupResult<DeviceDescriptorV1> {
    let (encoded, version) = if let Some(encoded) = value.strip_prefix("lkdev2_") {
        (encoded, 2)
    } else if let Some(encoded) = value.strip_prefix("lkdev1_") {
        (encoded, 1)
    } else {
        return Err((
            "MetadataInvalid",
            "device descriptor must start with lkdev2_ or legacy lkdev1_".to_owned(),
        ));
    };
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| ("MetadataInvalid", "device descriptor is not valid base64url".to_owned()))?;
    let descriptor: DeviceDescriptorV1 = serde_json::from_slice(&bytes)
        .map_err(|error| ("MetadataInvalid", format!("device descriptor is invalid: {error}")))?;
    if descriptor.v != version {
        return Err(("MetadataInvalid", "descriptor version mismatch".to_owned()));
    }
    Ok(descriptor)
}

fn decode_descriptor_key(value: &str) -> BackupResult<[u8; 32]> {
    let bytes = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| {
        ("MetadataInvalid", "device descriptor key is not valid base64url".to_owned())
    })?;
    bytes
        .try_into()
        .map_err(|_| ("MetadataInvalid", "device descriptor key must be 32 bytes".to_owned()))
}

fn device_fingerprint_hex(signing_public_key: &[u8; 32], sealing_public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"locket-device-v1");
    hasher.update(32_u16.to_le_bytes());
    hasher.update(signing_public_key);
    hasher.update(32_u16.to_le_bytes());
    hasher.update(sealing_public_key);
    format_hex(&hasher.finalize())
}

fn write_export_audit(
    store: &mut Store,
    project_id: &str,
    master_key: &locket_crypto::KeyBytes,
    manifest: &BundleManifest,
    payload: &SealedBundlePayloadV1,
    path_kind: &'static str,
    timestamp: i64,
) -> BackupResult<()> {
    let audit_key = load_project_key_with_master(store, project_id, KeyPurpose::Audit, master_key)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "BACKUP_EXPORT",
        "status": "SUCCESS",
        "command": "agent export-bundle",
        "project_id": project_id,
        "profile_count": manifest.profile_count,
        "recipient_fingerprints": manifest.recipient_fingerprints,
        "bundle_digest": manifest.payload_digest,
        "path_kind": path_kind,
        "active_secret_count": payload.active_secret_count,
        "command_policy_count": payload.command_policy_count,
        "secret_count": payload.secret_count,
        "secret_version_count": payload.secret_version_count,
        "blob_count": payload.blob_count,
        "profile_key_count": payload.profile_key_count,
        "include_audit": false,
        "metadata_only": true,
        "client_kind": "agent",
    });
    store
        .append_audit(
            audit_key.as_ref(),
            &AuditWrite {
                project_id,
                profile_id: None,
                action: "BACKUP_EXPORT",
                status: "SUCCESS",
                secret_name: None,
                command: Some("agent export-bundle"),
                metadata_json: &metadata,
                timestamp,
            },
        )
        .map_err(|error| ("CorruptDb", format!("could not append export audit: {error}")))
}

#[allow(clippy::too_many_arguments)]
fn write_import_audit(
    store: &mut Store,
    project_id: &str,
    master_key: &locket_crypto::KeyBytes,
    manifest: &BundleManifest,
    decrypted: &ImportedBundleCounts,
    applied: &AppliedBundleCounts,
    conflicts: &BundleConflictCounts,
    conflict_policy: &str,
    include_audit_requested: bool,
    timestamp: i64,
) -> BackupResult<()> {
    let audit_key = load_project_key_with_master(store, project_id, KeyPurpose::Audit, master_key)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "BACKUP_IMPORT",
        "status": "SUCCESS",
        "command": "agent import-bundle",
        "project_id": project_id,
        "bundle_digest": manifest.payload_digest,
        "profile_count": decrypted.profile_count,
        "secret_count": decrypted.secret_count,
        "secret_version_count": decrypted.secret_version_count,
        "blob_count": decrypted.blob_count,
        "command_policy_count": decrypted.command_policy_count,
        "profile_key_count": decrypted.profile_key_count,
        "applied_profile_count": applied.profile_count,
        "archived_local_profile_count": applied.archived_local_profile_count,
        "applied_secret_count": applied.secret_count,
        "applied_secret_version_count": applied.secret_version_count,
        "applied_blob_count": applied.blob_count,
        "applied_command_policy_count": applied.command_policy_count,
        "applied_profile_key_count": applied.profile_key_count,
        "conflict_policy": conflict_policy,
        "conflict_identical": conflicts.identical,
        "conflict_newer_incoming": conflicts.newer_incoming,
        "conflict_divergent": conflicts.divergent,
        "conflict_deleted_vs_active": conflicts.deleted_vs_active,
        "conflict_applied": conflicts.applied,
        "conflict_rejected": conflicts.rejected,
        "include_audit_requested": include_audit_requested,
        "metadata_only": true,
        "client_kind": "agent",
    });
    store
        .append_audit(
            audit_key.as_ref(),
            &AuditWrite {
                project_id,
                profile_id: None,
                action: "BACKUP_IMPORT",
                status: "SUCCESS",
                secret_name: None,
                command: Some("agent import-bundle"),
                metadata_json: &metadata,
                timestamp,
            },
        )
        .map_err(|error| ("CorruptDb", format!("could not append import audit: {error}")))
}

fn build_device_private_key_storage(
    unlocked: &UnlockedProject,
    state: &AgentSocketState,
    project_id: &str,
) -> BackupResult<WrappedLocalFileDevicePrivateKeyStorage> {
    let directory = unlocked
        .store_path
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| ("CorruptDb", "could not resolve device private key root".to_owned()))?;
    Ok(WrappedLocalFileDevicePrivateKeyStorage::new(
        directory,
        project_id.to_owned(),
        std::sync::Arc::clone(&state.master_key_store),
    ))
}

fn map_private_key_load_error(error: PlatformError) -> (&'static str, String) {
    match error {
        PlatformError::DevicePrivateKeyNotFound => {
            ("BundleVerificationFailed", "device private-key storage not initialized".to_owned())
        }
        other => ("MetadataInvalid", format!("device private-key load failed: {other}")),
    }
}

fn load_project_key_with_master(
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
) -> BackupResult<zeroize::Zeroizing<locket_crypto::KeyBytes>> {
    let record = store
        .get_key_by_scope(project_id, None, purpose.as_str())
        .map_err(|error| ("CorruptDb", format!("could not read project key: {error}")))?
        .ok_or_else(|| {
            ("AuditIntegrityFailed", format!("project {} key is missing", purpose.as_str()))
        })?;
    let wrapping_key =
        derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(project_id, None, purpose)).map_err(
            |error| ("MetadataInvalid", format!("project key derivation failed: {error}")),
        )?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        None,
        0,
        KeyWrapPurpose::from(purpose),
    ))
    .map_err(|error| ("MetadataInvalid", format!("project key aad failed: {error}")))?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    unwrap_key_material_v1(&wrapping_key, &wrapped, &aad)
        .map_err(|error| ("AuditIntegrityFailed", format!("project key unwrap failed: {error}")))
}

fn write_bundle_file(path: &Path, bundle: &BundleContainer) -> BackupResult<()> {
    let bytes = bundle.serialize().map_err(|error| {
        ("BundleVerificationFailed", format!("bundle serialize failed: {error}"))
    })?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            ("InvalidReference", "bundle output already exists".to_owned())
        } else {
            ("CorruptDb", format!("could not create bundle output: {error}"))
        }
    })?;
    file.write_all(&bytes)
        .map_err(|error| ("CorruptDb", format!("could not write bundle output: {error}")))?;
    set_user_only_file_permissions(path)
}

#[cfg(unix)]
fn set_user_only_file_permissions(path: &Path) -> BackupResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| ("CorruptDb", format!("could not set bundle permissions: {error}")))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)] // Keep the shared fallible interface; Windows inherits ACLs.
const fn set_user_only_file_permissions(_path: &Path) -> BackupResult<()> {
    Ok(())
}

fn default_bundle_output_path(store_path: &Path, timestamp: i64) -> PathBuf {
    store_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("locket-bundle-{timestamp}.locket-bundle"))
}

fn output_path_kind(path: &Path, store_path: &Path) -> &'static str {
    if path
        .parent()
        .zip(store_path.parent())
        .is_some_and(|(path_parent, store_parent)| path_parent == store_parent)
    {
        "store_directory"
    } else if path.is_absolute() {
        "absolute"
    } else {
        "relative"
    }
}

fn bundle_encrypted_payload_digest(encrypted_payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(encrypted_payload);
    format_hex(&hasher.finalize())
}

fn format_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn current_unix_nanos_i64() -> i64 {
    i64::try_from(current_unix_nanos()).unwrap_or(i64::MAX)
}

fn json_error(error: serde_json::Error) -> (&'static str, String) {
    ("MetadataInvalid", format!("bundle payload encode failed: {error}"))
}

async fn unlocked_project(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
    project_id: &str,
) -> Result<UnlockedProject, ResponseEnvelope> {
    let cache = state.unlock_cache.lock().await;
    let Some(entry) = cache.lookup(project_id, current_unix_nanos()) else {
        return Err(error_response(envelope, "UnlockRequired", "unlock the vault first"));
    };
    let Some(context) = entry.audit_context() else {
        return Err(error_response(
            envelope,
            "MetadataInvalid",
            "bundle export requires unlock audit context with store_path",
        ));
    };
    let master_key: locket_crypto::KeyBytes = entry.key_bytes().try_into().map_err(|_| {
        error_response(envelope, "MetadataInvalid", "cached master key has invalid length")
    })?;
    Ok(UnlockedProject {
        store_path: context.store_path.clone(),
        profile_id: context.profile_id.clone(),
        master_key: zeroize::Zeroizing::new(master_key),
    })
}

async fn require_unlocked(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
    project_id: &str,
) -> Option<ResponseEnvelope> {
    let unlocked = {
        let cache = state.unlock_cache.lock().await;
        cache.lookup(project_id, current_unix_nanos()).is_some()
    };
    (!unlocked).then(|| error_response(envelope, "UnlockRequired", "unlock the vault first"))
}

fn not_implemented(
    envelope: &RequestEnvelope,
    action: &'static str,
    message: impl Into<String>,
) -> ResponseEnvelope {
    success_response(
        envelope,
        BackupActionResponse {
            action: action.to_owned(),
            status: "not-implemented".to_owned(),
            message: message.into(),
        },
    )
}

fn success_response<T: Serialize>(envelope: &RequestEnvelope, payload: T) -> ResponseEnvelope {
    let payload = serde_json::to_value(payload).unwrap_or(serde_json::Value::Null);
    ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
}

fn error_response(envelope: &RequestEnvelope, error: &str, message: &str) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(envelope.id.clone(), error, message, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn import_apply(
        store: &mut Store,
        project: &str,
        payload: &SealedBundlePayloadV1,
        resolution: ConflictResolution,
    ) -> Result<ApplyOutcome, Box<dyn std::error::Error>> {
        apply_bundle_payload(store, project, payload, resolution, &[42; 32], 300)
            .map_err(|(_, message)| message.into())
    }

    #[test]
    fn import_archives_empty_same_name_profile_preserving_audit_and_references()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let mut store = Store::open(dir.path().join("store.db"))?;
        store.initialize_schema()?;
        store.insert_project_if_absent("project", "project", 1)?;
        store.connection().execute("INSERT INTO profiles(id,project_id,name,dangerous,created_at) VALUES ('local-profile','project','dev',0,1)", [])?;
        store.connection().execute("INSERT INTO keys(id,project_id,profile_id,purpose,wrapped_material,nonce,created_at) VALUES ('local-key','project','local-profile','profile-secret',x'1234',zeroblob(24),1)", [])?;
        store.connection().execute("INSERT INTO directory_grants(grant_id,project_id,profile_id,root_hash,directory_hash,grant_scope,created_at,updated_at) VALUES ('grant','project','local-profile',zeroblob(32),zeroblob(32),'project-root',1,1)", [])?;
        store.connection().execute("INSERT INTO runtime_sessions(id,project_id,profile_id,process_id,process_start_time,started_at) VALUES ('session','project','local-profile',1,1,1)", [])?;
        store.append_audit(&[9;32], &AuditWrite { project_id:"project", profile_id:Some("local-profile"), action:"BOOTSTRAP", status:"SUCCESS", secret_name:None, command:Some("locket init"), metadata_json:&json!({"schema_version":1,"action":"BOOTSTRAP","status":"SUCCESS","command":"locket init","project_id":"project","default_profile_id":"local-profile","recovery_code_displayed":false}), timestamp:1 })?;
        let payload = import_fixture("remote-profile", "secret", 1)?;
        import_apply(&mut store, "project", &payload, ConflictResolution::AcceptIncoming)?;
        assert_eq!(
            store.get_profile_by_name("project", "dev")?.ok_or("imported dev profile missing")?.id,
            "remote-profile"
        );
        assert_eq!(store.list_secrets_by_profile("project", "remote-profile")?.len(), 1);
        assert!(
            store.verify_audit_chain_read_only("project", &[9; 32])?.hmac_ok,
            "import must preserve audited profile references"
        );
        let archived = store
            .list_profiles("project")?
            .into_iter()
            .find(|p| p.id == "local-profile")
            .ok_or("original profile deleted")?;
        assert!(archived.name.starts_with("dev-local-"));
        for table in ["directory_grants", "runtime_sessions", "keys"] {
            let id: String = store.connection().query_row(
                &format!("SELECT profile_id FROM {table}"),
                [],
                |row| row.get(0),
            )?;
            assert_eq!(id, "local-profile");
        }
        let bytes: Vec<u8> = store.connection().query_row(
            "SELECT wrapped_material FROM keys WHERE id='local-key'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(bytes, [0x12, 0x34]);
        Ok(())
    }

    #[test]
    fn failed_import_restores_archived_profile_name_and_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let mut store = Store::open(dir.path().join("store.db"))?;
        store.initialize_schema()?;
        store.insert_project_if_absent("project", "project", 1)?;
        store.insert_profile_if_absent("local-profile", "project", "dev", false, 1)?;
        let mut payload = import_fixture("remote-profile", "secret", 1)?;
        payload.blobs[0].ciphertext_b64 = "%invalid".into();
        assert!(
            import_apply(&mut store, "project", &payload, ConflictResolution::AcceptIncoming)
                .is_err()
        );
        assert_eq!(
            store.get_profile_by_name("project", "dev")?.ok_or("original restored")?.id,
            "local-profile"
        );
        assert_eq!(store.list_profiles("project")?.len(), 1);
        assert_eq!(
            store.list_secrets_by_profile("project", "remote-profile")?,
            Vec::<locket_store::SecretRecord>::new()
        );
        Ok(())
    }

    #[test]
    fn same_name_populated_local_profile_is_not_replaced() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let mut store = Store::open(dir.path().join("store.db"))?;
        store.initialize_schema()?;
        store.insert_project_if_absent("project", "project", 1)?;
        import_apply(
            &mut store,
            "project",
            &import_fixture("local-profile", "local-secret", 1)?,
            ConflictResolution::AcceptIncoming,
        )?;
        assert!(
            import_apply(
                &mut store,
                "project",
                &import_fixture("remote-profile", "remote-secret", 1)?,
                ConflictResolution::AcceptIncoming
            )
            .is_err()
        );
        assert_eq!(
            store.get_profile_by_name("project", "dev")?.ok_or("original retained")?.id,
            "local-profile"
        );
        assert_eq!(store.list_profiles("project")?.len(), 1);
        assert_eq!(store.list_secrets_by_profile("project", "local-profile")?.len(), 1);
        Ok(())
    }

    #[test]
    fn unsigned_policy_cannot_widen_existing_command_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let mut store = Store::open(dir.path().join("store.db"))?;
        store.initialize_schema()?;
        store.insert_project_if_absent("project", "project", 1)?;
        let restricted = r#"{"allowed_secrets":["SAFE"],"confirm":true}"#;
        store.connection().execute("INSERT INTO command_policies(project_id,name,policy_json,normalized_json,created_at,updated_at) VALUES ('project','deploy',?1,?1,1,1)", [restricted])?;
        let mut payload = import_fixture("profile", "secret", 1)?;
        payload.command_policies.push(serde_json::from_value(serde_json::json!({
            "name":"deploy","command_kind":"argv","argv":["sh","-c","evil"],"shell":null,
            "allowed_secrets":["*"],"required_secrets":[],"optional_secrets":[],"inherit_env":[],
            "env_mode":"inherit","override_mode":"allow","override_explicit":true,"external_env_sources":[],
            "allow_remote_docker":true,"confirm":false,"require_user_verification":false,"ttl_seconds":999_999
        }))?);
        payload.command_policy_count = 1;
        import_apply(&mut store, "project", &payload, ConflictResolution::AcceptIncoming)?;
        let actual: String = store.connection().query_row("SELECT policy_json FROM command_policies WHERE project_id = 'project' AND name = 'deploy'", [], |row| row.get(0))?;
        assert_eq!(actual, restricted);
        Ok(())
    }

    fn import_fixture(
        profile: &str,
        id: &str,
        version: u32,
    ) -> Result<SealedBundlePayloadV1, serde_json::Error> {
        serde_json::from_value(serde_json::json!({
            "profiles": [{"profile_id": profile, "name": "dev", "dangerous": false,
                "active_secret_count": 1, "created_at": 100}],
            "command_policies": [], "profile_keys": [],
            "secrets": [{"id": id, "profile_id": profile, "name": id, "source": "machine-local",
                "origin": "manual", "current_version": version, "state": "active",
                "created_at": 100, "updated_at": version * 100, "last_rotated_at": null, "deleted_at": null}],
            "secret_versions": [{"secret_id": id, "version": version, "source": "machine-local",
                "origin": "manual", "state": "current", "created_at": version * 100,
                "deprecated_at": null, "grace_until": null, "purged_at": null}],
            "blobs": [{"secret_id": id, "version": version, "encrypted_dek_b64": "AQ",
                "ciphertext_b64": BASE64URL_NOPAD.encode(&version.to_le_bytes()),
                "value_nonce_b64": BASE64URL_NOPAD.encode(&[0; 24]),
                "aad_schema_version": 1, "created_at": version * 100}],
            "profile_count": 1, "command_policy_count": 0, "profile_key_count": 0,
            "secret_count": 1, "secret_version_count": 1, "blob_count": 1,
            "active_secret_count": 1, "audit_rows_included": false, "audit_chain": null
        }))
    }

    #[test]
    fn import_rotation_does_not_restore_exporter_grace() -> Result<(), Box<dyn std::error::Error>> {
        for reverse in [false, true] {
            let directory = tempfile::tempdir()?;
            let mut store = Store::open(directory.path().join("store.db"))?;
            store.initialize_schema()?;
            store.insert_project_if_absent("project", "project", 100)?;
            import_apply(
                &mut store,
                "project",
                &import_fixture("profile", "secret", 1)?,
                ConflictResolution::AcceptIncoming,
            )?;
            let mut incoming = import_fixture("profile", "secret", 2)?;
            let mut historical = import_fixture("profile", "secret", 1)?;
            historical.secret_versions[0].state = "deprecated".to_owned();
            historical.secret_versions[0].deprecated_at = Some(200);
            historical.secret_versions[0].grace_until = Some(999);
            incoming.secret_versions.extend(historical.secret_versions);
            if reverse {
                incoming.secret_versions.reverse();
            }
            refresh_fixture_counts(&mut incoming);
            import_apply(&mut store, "project", &incoming, ConflictResolution::AcceptIncoming)?;
            // Replaying an accepted bundle must not revive the prior version.
            import_apply(&mut store, "project", &incoming, ConflictResolution::AcceptIncoming)?;
            let old = store.get_secret_version("secret", 1)?.ok_or("missing old version")?;
            assert_eq!(old.state, "deprecated");
            assert_eq!(old.deprecated_at, Some(300));
            store.connection().execute("UPDATE secret_versions SET grace_until = NULL WHERE secret_id = 'secret' AND version = 1", [])?;
            import_apply(&mut store, "project", &incoming, ConflictResolution::AcceptIncoming)?;
            assert_eq!(
                store.get_secret_version("secret", 1)?.ok_or("missing old version")?.grace_until,
                None
            );

            assert_eq!(
                old.grace_until,
                Some(300),
                "import rotation must expire the previous version immediately"
            );
        }
        Ok(())
    }

    fn refresh_fixture_counts(payload: &mut SealedBundlePayloadV1) {
        payload.profile_count = payload.profiles.len();
        payload.secret_count = payload.secrets.len();
        payload.secret_version_count = payload.secret_versions.len();
        payload.blob_count = payload.blobs.len();
        payload.profile_key_count = payload.profile_keys.len();
        payload.active_secret_count =
            payload.secrets.iter().filter(|row| row.state == "active").count();
    }

    #[test]
    fn import_profile_keys_are_rewrapped_for_receiver_and_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut store = Store::open(directory.path().join("store.db"))?;
        store.initialize_schema()?;
        store.insert_project_if_absent("project", "project", 100)?;
        let mut payload = import_fixture("profile", "secret", 1)?;
        for purpose in [KeyPurpose::ProfileSecret, KeyPurpose::ProfileFingerprint] {
            payload.profile_keys.push(SealedBundleProfileKeyV1 {
                profile_id: "profile".to_owned(),
                purpose: purpose.as_str().to_owned(),
                key_material_b64: BASE64URL_NOPAD.encode(&[7; 32]),
            });
        }
        refresh_fixture_counts(&mut payload);
        for _ in 0..2 {
            import_apply(&mut store, "project", &payload, ConflictResolution::AcceptIncoming)?;
            for purpose in [KeyPurpose::ProfileSecret, KeyPurpose::ProfileFingerprint] {
                let recovered =
                    load_profile_key_with_master(&store, "project", "profile", purpose, &[42; 32])
                        .map_err(|(_, message)| message)?;
                assert_eq!(*recovered, [7; 32]);
                assert!(
                    load_profile_key_with_master(&store, "project", "profile", purpose, &[43; 32],)
                        .is_err()
                );
            }
            let count: u32 = store.connection().query_row(
                "SELECT COUNT(*) FROM keys WHERE project_id = 'project'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(count, 2);
        }
        Ok(())
    }

    #[test]
    fn import_conflict_choice_keeps_version_pointer_and_blob_consistent()
    -> Result<(), Box<dyn std::error::Error>> {
        for resolution in [
            ConflictResolution::Review,
            ConflictResolution::AcceptLocal,
            ConflictResolution::AcceptIncoming,
        ] {
            let directory = tempfile::tempdir()?;
            let mut store = Store::open(directory.path().join("store.db"))?;
            store.initialize_schema()?;
            store.insert_project_if_absent("project", "project", 100)?;
            let original = import_fixture("profile", "secret", 1)?;
            import_apply(&mut store, "project", &original, ConflictResolution::Review)?;
            let mut incoming = import_fixture("profile", "secret", 2)?;
            let mut historical = import_fixture("profile", "secret", 1)?;
            historical.secret_versions[0].state = "deprecated".to_owned();
            historical.secret_versions[0].deprecated_at = Some(200);
            historical.secret_versions[0].grace_until = Some(999);
            incoming.secret_versions.extend(historical.secret_versions);
            let unrelated = import_fixture("profile", "unrelated", 1)?;
            incoming.secrets.extend(unrelated.secrets);
            incoming.secret_versions.extend(unrelated.secret_versions);
            incoming.blobs.extend(unrelated.blobs);
            refresh_fixture_counts(&mut incoming);
            let outcome = import_apply(&mut store, "project", &incoming, resolution)?;
            let expected_version =
                if resolution == ConflictResolution::AcceptIncoming { 2 } else { 1 };
            let pointer: u32 = store.connection().query_row(
                "SELECT current_version FROM secrets WHERE id = 'secret'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(pointer, expected_version);
            let active =
                store.get_secret_version("secret", pointer)?.ok_or("missing pointed version")?;
            assert_eq!(
                active.state, "current",
                "conflict choice must keep its selected version usable"
            );
            let blob = store.get_blob("secret", pointer)?.ok_or("missing pointed blob")?;
            assert_eq!(blob.ciphertext, expected_version.to_le_bytes());
            if resolution != ConflictResolution::AcceptIncoming {
                assert!(store.get_secret_version("secret", 2)?.is_none());
                assert!(store.get_blob("secret", 2)?.is_none());
            }
            let unrelated_count: u32 = store.connection().query_row(
                "SELECT COUNT(*) FROM secrets WHERE id = 'unrelated'",
                [],
                |row| row.get(0),
            )?;
            if resolution == ConflictResolution::Review {
                assert!(matches!(outcome, ApplyOutcome::ReviewRequired { .. }));
                assert_eq!(unrelated_count, 0, "review must roll back the whole import");
            } else {
                assert!(matches!(outcome, ApplyOutcome::Applied { .. }));
                assert_eq!(unrelated_count, 1, "nonconflicting new secrets still import");
            }
        }
        Ok(())
    }

    #[test]
    fn import_rejects_cross_project_rows_and_rolls_back() -> Result<(), Box<dyn std::error::Error>>
    {
        for attack in [
            "secret",
            "version",
            "blob",
            "profile",
            "profile-key",
            "missing-profile",
            "missing-secret",
            "missing-key-profile",
        ] {
            let directory = tempfile::tempdir()?;
            let mut store = Store::open(directory.path().join("store.db"))?;
            store.initialize_schema()?;
            for project in ["project-a", "project-b"] {
                store.insert_project_if_absent(project, project, 100)?;
            }
            let original = import_fixture("profile-b", "secret-b", 1)?;
            import_apply(&mut store, "project-b", &original, ConflictResolution::Review)?;
            let mut incoming = import_fixture("profile-a", "new-secret", 2)?;
            match attack {
                "secret" => {
                    incoming.secrets[0].id = "secret-b".to_owned();
                    incoming.secret_versions[0].secret_id = "secret-b".to_owned();
                    incoming.blobs[0].secret_id = "secret-b".to_owned();
                }
                "version" => incoming.secret_versions[0].secret_id = "secret-b".to_owned(),
                "blob" => {
                    incoming.blobs[0].secret_id = "secret-b".to_owned();
                    incoming.blobs[0].version = 1;
                }
                "profile" => incoming.secrets[0].profile_id = "profile-b".to_owned(),
                "missing-profile" => incoming.secrets[0].profile_id = "missing-profile".to_owned(),
                "missing-secret" => {
                    incoming.secret_versions[0].secret_id = "missing-secret".to_owned();
                }
                _ => incoming.profile_keys.push(SealedBundleProfileKeyV1 {
                    profile_id: if attack == "missing-key-profile" {
                        "missing-profile"
                    } else {
                        "profile-b"
                    }
                    .to_owned(),
                    purpose: KeyPurpose::ProfileSecret.as_str().to_owned(),
                    key_material_b64: BASE64URL_NOPAD.encode(&[42; 32]),
                }),
            }
            refresh_fixture_counts(&mut incoming);
            assert!(
                import_apply(
                    &mut store,
                    "project-a",
                    &incoming,
                    ConflictResolution::AcceptIncoming
                )
                .is_err(),
                "{attack} must reject a foreign project reference"
            );
            let retained: (String, String, u32) = store.connection().query_row(
                "SELECT project_id, profile_id, current_version FROM secrets WHERE id = 'secret-b'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(retained, ("project-b".to_owned(), "profile-b".to_owned(), 1));
            assert_eq!(
                store.get_secret_version("secret-b", 1)?.ok_or("missing original version")?.state,
                "current"
            );
            assert_eq!(
                store.get_blob("secret-b", 1)?.ok_or("missing original blob")?.ciphertext,
                1_u32.to_le_bytes()
            );
            assert!(store.get_secret_version("secret-b", 2)?.is_none());
            assert!(
                store.list_profiles("project-a")?.is_empty(),
                "rejected import must roll back profile insertion"
            );
        }
        Ok(())
    }

    use locket_crypto::{
        HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, generate_key, wrap_key_material_v1,
    };
    use locket_store::KeyRecord;

    const PROJECT_ID: &str = "lk_proj_backup_export";
    const PROFILE_ID: &str = "lk_prof_backup_export";

    #[test]
    fn export_bundle_writes_sealed_container_and_audit_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempfile::tempdir()?;
        let store_path = tempdir.path().join("store.sqlite3");
        let output_path = tempdir.path().join("export.locket-bundle");
        let mut store = Store::open(&store_path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT_ID, "backup export", 100)?;
        store.insert_profile_if_absent(PROFILE_ID, PROJECT_ID, "dev", false, 100)?;

        let master_key = *generate_key()?;
        insert_wrapped_key(
            &store,
            "lk_key_audit_export",
            None,
            KeyPurpose::Audit,
            &master_key,
            &*generate_key()?,
        )?;
        insert_wrapped_key(
            &store,
            "lk_key_profile_secret_export",
            Some(PROFILE_ID),
            KeyPurpose::ProfileSecret,
            &master_key,
            &*generate_key()?,
        )?;
        insert_wrapped_key(
            &store,
            "lk_key_profile_fingerprint_export",
            Some(PROFILE_ID),
            KeyPurpose::ProfileFingerprint,
            &master_key,
            &*generate_key()?,
        )?;
        drop(store);

        let request = ExportBundleRequest {
            project_id: PROJECT_ID.to_owned(),
            profile_id: Some(PROFILE_ID.to_owned()),
            recipient_descriptor: test_device_descriptor()?,
            scope: BundleExportScope::ActiveProfile,
            include_audit: false,
            include_personal: false,
            include_history: false,
            preview_only: false,
            output_path: Some(output_path.clone()),
        };
        let unlocked = UnlockedProject {
            store_path: store_path.clone(),
            profile_id: Some(PROFILE_ID.to_owned()),
            master_key: zeroize::Zeroizing::new(master_key),
        };

        let mut preview_request = request.clone();
        preview_request.preview_only = true;
        let preview = export_bundle(&preview_request, &unlocked).map_err(|(_, message)| message)?;
        assert_eq!(preview.status, "preview");
        assert!(preview.message.contains("No team-managed values"));
        assert!(!output_path.exists());
        let response = export_bundle(&request, &unlocked).map_err(|(_, message)| message)?;
        assert_eq!(response.status, "exported");
        let bytes = fs::read(&output_path)?;
        let bundle = BundleContainer::deserialize(&bytes)?;
        assert_eq!(bundle.manifest.project_id, PROJECT_ID);
        assert_eq!(bundle.manifest.profile_count, 1);
        assert_eq!(bundle.manifest.recipient_fingerprints.len(), 1);

        let store = Store::open(&store_path)?;
        let audit_count: u32 = store.connection().query_row(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'BACKUP_EXPORT'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(audit_count, 1);
        Ok(())
    }

    #[test]
    fn bundle_payload_includes_project_command_policies() -> Result<(), Box<dyn std::error::Error>>
    {
        let tempdir = tempfile::tempdir()?;
        let root = tempdir.path();
        fs::create_dir(root.join(".locket"))?;
        fs::write(
            root.join("locket.toml"),
            r#"
schema_version = 1

[commands.deploy]
argv = ["deploy", "--check"]
required_secrets = ["DATABASE_URL"]
ttl = "30s"
"#,
        )?;
        let store_path = root.join(".locket").join("store.sqlite3");
        let mut store = Store::open(&store_path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT_ID, "backup export", 100)?;
        store.insert_profile_if_absent(PROFILE_ID, PROJECT_ID, "dev", false, 100)?;
        let master_key = *generate_key()?;
        insert_wrapped_key(
            &store,
            "lk_key_profile_secret_export",
            Some(PROFILE_ID),
            KeyPurpose::ProfileSecret,
            &master_key,
            &*generate_key()?,
        )?;
        insert_wrapped_key(
            &store,
            "lk_key_profile_fingerprint_export",
            Some(PROFILE_ID),
            KeyPurpose::ProfileFingerprint,
            &master_key,
            &*generate_key()?,
        )?;
        let profiles = store.list_profiles(PROJECT_ID)?;

        let payload = bundle_payload(&store, PROJECT_ID, &profiles, &master_key)
            .map_err(|(_, message)| message)?;

        assert_eq!(payload.command_policy_count, 1);
        assert_eq!(payload.command_policies[0].name, "deploy");
        assert_eq!(payload.command_policies[0].required_secrets, vec!["DATABASE_URL"]);
        assert_eq!(payload.command_policies[0].ttl_seconds, 30);
        Ok(())
    }

    #[test]
    fn unsigned_bundle_cannot_grant_policy_and_rolls_back_review_conflict()
    -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempfile::tempdir()?;
        let store_path = tempdir.path().join("store.sqlite3");
        let mut store = Store::open(&store_path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT_ID, "backup import", 100)?;
        let master_key = *generate_key()?;
        let payload = minimal_import_payload("dev", "deploy");

        let outcome = apply_bundle_payload(
            &mut store,
            PROJECT_ID,
            &payload,
            ConflictResolution::Review,
            &master_key,
            200,
        )
        .map_err(|(_, message)| message)?;
        assert!(matches!(outcome, ApplyOutcome::Applied { .. }));
        let policy_count: u32 = store.connection().query_row(
            "SELECT COUNT(*) FROM command_policies WHERE project_id = ?1",
            params![PROJECT_ID],
            |row| row.get(0),
        )?;
        assert_eq!(policy_count, 0);

        let conflicting = minimal_import_payload("prod", "ship");
        let outcome = apply_bundle_payload(
            &mut store,
            PROJECT_ID,
            &conflicting,
            ConflictResolution::Review,
            &master_key,
            300,
        )
        .map_err(|(_, message)| message)?;
        assert!(matches!(outcome, ApplyOutcome::ReviewRequired { .. }));
        let profile_name: String = store.connection().query_row(
            "SELECT name FROM profiles WHERE id = ?1",
            params![PROFILE_ID],
            |row| row.get(0),
        )?;
        assert_eq!(profile_name, "dev");
        assert_eq!(
            store.connection().query_row("SELECT COUNT(*) FROM command_policies", [], |row| row
                .get::<_, u32>(0))?,
            0
        );
        Ok(())
    }

    fn minimal_import_payload(profile_name: &str, policy_name: &str) -> SealedBundlePayloadV1 {
        SealedBundlePayloadV1 {
            profiles: vec![SealedBundleProfileV1 {
                profile_id: PROFILE_ID.to_owned(),
                name: profile_name.to_owned(),
                dangerous: false,
                active_secret_count: 0,
                created_at: 100,
            }],
            command_policies: vec![SealedBundleCommandPolicyV1 {
                name: policy_name.to_owned(),
                command_kind: "argv".to_owned(),
                argv: vec!["deploy".to_owned()],
                shell: None,
                allowed_secrets: Vec::new(),
                required_secrets: Vec::new(),
                optional_secrets: Vec::new(),
                inherit_env: Vec::new(),
                env_mode: "minimal".to_owned(),
                override_mode: "deny".to_owned(),
                override_explicit: false,
                external_env_sources: Vec::new(),
                allow_remote_docker: false,
                confirm: false,
                require_user_verification: false,
                ttl_seconds: 900,
            }],
            secrets: Vec::new(),
            secret_versions: Vec::new(),
            blobs: Vec::new(),
            profile_keys: Vec::new(),
            profile_count: 1,
            command_policy_count: 1,
            secret_count: 0,
            secret_version_count: 0,
            blob_count: 0,
            profile_key_count: 0,
            active_secret_count: 0,
            audit_rows_included: false,
            audit_chain: None,
        }
    }

    fn insert_wrapped_key(
        store: &Store,
        key_id: &str,
        profile_id: Option<&str>,
        purpose: KeyPurpose,
        master_key: &locket_crypto::KeyBytes,
        key_material: &locket_crypto::KeyBytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wrapping_key = derive_wrapping_key_v1(
            master_key,
            &HkdfWrapInfo::new(PROJECT_ID, profile_id, purpose),
        )?;
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            key_id,
            profile_id,
            0,
            KeyWrapPurpose::from(purpose),
        ))?;
        let wrapped = wrap_key_material_v1(&wrapping_key, key_material, &aad)?;
        store.insert_key(&KeyRecord {
            id: key_id.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: profile_id.map(ToOwned::to_owned),
            purpose: purpose.as_str().to_owned(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: 100,
        })?;
        Ok(())
    }

    fn test_device_descriptor() -> Result<String, serde_json::Error> {
        let signing = [3_u8; 32];
        let sealing = [4_u8; 32];
        let descriptor = DeviceDescriptorV1 {
            v: 1,
            device_id: "lk_dev_export".to_owned(),
            label: "export".to_owned(),
            signing_public_key_ed25519: BASE64URL_NOPAD.encode(&signing),
            sealing_public_key_x25519: BASE64URL_NOPAD.encode(&sealing),
            fingerprint_sha256: device_fingerprint_hex(&signing, &sealing),
            safety_words: Vec::new(),
        };
        serde_json::to_vec(&descriptor)
            .map(|bytes| format!("lkdev1_{}", BASE64URL_NOPAD.encode(&bytes)))
    }
}
