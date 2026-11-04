//! Core policy and validation primitives for Locket.

// age 0.11 transitively carries older versions of a few crates that
// are also present elsewhere in the workspace. This is acceptable for
// the sealed-bundle crypto boundary and cannot be resolved locally.
#![allow(clippy::multiple_crate_versions)]

mod configuration;
mod formats;
mod identity;

pub mod error;
pub mod policy;

pub use configuration::{env, metadata, privacy, project, time};
pub use formats::{audit, bundle, dotenv, invite, pgp_word_list, update_manifest};
pub use identity::{id, profile_name, reference_uri, secret_name};

pub use audit::{
    AUDIT_CHECKPOINT_MAX_BYTES, AUDIT_HMAC_LEN, AuditCanonicalizationError, AuditCheckpoint,
    AuditHmacInput, audit_checkpoint_v1_bytes, audit_hmac_v1_bytes, bytes, canonical_json,
    canonical_json_bytes, canonical_json_string, field, insert_convenience_metadata,
};
pub use bundle::{
    BUNDLE_MAGIC, BUNDLE_MANIFEST_ALLOWED_FIELDS, BUNDLE_MAX_MANIFEST_LEN, BUNDLE_MAX_PAYLOAD_LEN,
    BUNDLE_SCHEMA_V1, BundleContainer, BundleContainerError, BundleContainerResult,
    BundleEncryptionError, BundleEncryptionResult, BundleManifest,
    decrypt_bundle_payload_with_age_identity, decrypt_bundle_payload_with_x25519_secret,
    encrypt_bundle_payload_for_age_recipients, verify_age_payload_structure,
};
pub use env::{
    EnvMap, EnvMergeError, EnvMode, EnvOverrideMode, EnvValue, InvalidEnvMode,
    InvalidEnvOverrideMode, env_value, merge_environment,
};
pub use error::{ErrorDisplayCopy, ExitCode, LocketError};
pub use id::{
    ClientId, DeviceId, IdGenerationError, InvalidId, InviteId, KdfProfileId, KeyId, MemberId,
    PasskeyId, ProfileId, ProjectId, SecretId, SessionId, TeamId,
};
pub use invite::{
    INVITE_PREFIX, InviteDecodeError, InviteEncodeError, InvitePayload, InviteVerifyError,
    SealedInvitePayloadV1, SealedInvitePlaintextCounts, SignedInvite, TeamRole,
    device_fingerprint_v1, fingerprint_hex,
};
pub use metadata::{MetadataPrivacyFinding, MetadataValidationError, validate_metadata_field};
pub use pgp_word_list::{
    EVEN_SYLLABLE_WORDS, ODD_SYLLABLE_WORDS, SAFETY_WORD_COUNT, safety_words_from_fingerprint_hex,
};
pub use policy::{
    CommandPolicy, CommandSpec, ExternalEnvSource, MAX_COMMAND_POLICY_TTL_SECONDS, PathEnvSet,
    PolicyDocument, PolicyFieldSource, PolicyParseError, SecretAccessPolicy,
    VariableClassification, VariableContract, VariableReadinessRow, VariableReadinessState,
    VariableType, variable_exposure_warning,
};
pub use privacy::privacy_alias;
pub use profile_name::{InvalidProfileName, MAX_PROFILE_NAME_LEN, ProfileName};
pub use project::{PROJECT_CONFIG_SCHEMA_VERSION, ProjectConfig};
pub use reference_uri::{
    InvalidReferenceUri, InvalidSecretSource, LkReferenceUri, SecretSource, SecretVersion,
};
pub use secret_name::{InvalidSecretName, SecretName};
pub use time::{Duration, InvalidDuration, Timestamp};
pub use update_manifest::{
    ReleaseKey, UpdateArtifact, UpdateChannel, UpdateManifestError, UpdateManifestFetchRequest,
    UpdateManifestPayload, UpdateManifestSignature, VerifiedUpdateManifest,
    build_update_manifest_fetch_request, verify_update_manifest,
    verify_update_manifest_key_rotation,
};

pub use formats::team_package;
