//! Offline validation for signed update manifests.

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{LocketError, canonical_json};

const MANIFEST_SCHEMA_VERSION: u8 = 1;
const SIGNATURE_ALGORITHM: &str = "Ed25519";
const SIGNATURE_DOMAIN: &[u8] = b"locket-update-manifest-v1\0";
const SHA256_HEX_LEN: usize = 64;
const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;

/// A signed update manifest envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedUpdateManifest {
    /// Manifest schema version. v1 signs only the `signed` payload.
    pub v: u8,
    /// Privacy-safe update metadata covered by the release signature.
    pub signed: UpdateManifestPayload,
    /// Detached signatures over the canonical v1 payload.
    pub signatures: Vec<UpdateManifestSignature>,
}

/// Update metadata covered by the offline release signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateManifestPayload {
    /// Release channel this manifest applies to.
    pub channel: UpdateChannel,
    /// Release version string.
    pub version: String,
    /// UTC publication timestamp supplied by release tooling.
    pub published_at: String,
    /// Per-platform artifacts.
    pub artifacts: Vec<UpdateArtifact>,
}

/// Supported update channels for signed manifests.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateChannel {
    /// Stable public release channel.
    Stable,
    /// Beta prerelease channel.
    Beta,
}

impl UpdateChannel {
    /// Stable wire token used in update-manifest fetch paths.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
        }
    }
}

/// Public release key material pinned by the binary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseKey {
    /// Stable release-key identifier.
    pub key_id: String,
    /// Unpadded base64url Ed25519 verifying key.
    pub public_key_base64url: String,
}

/// Privacy-preserving update-manifest fetch request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateManifestFetchRequest {
    /// HTTPS URL keyed only by channel, platform, architecture, and current app version.
    pub url: String,
}

/// Metadata for one downloadable release artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateArtifact {
    /// Operating-system target, for example `macos`, `windows`, or `linux`.
    pub platform: String,
    /// CPU architecture target, for example `aarch64` or `x86_64`.
    pub arch: String,
    /// HTTPS download URL for the artifact.
    pub url: String,
    /// Lowercase hex SHA-256 digest of the artifact bytes.
    pub sha256: String,
    /// Artifact length in bytes.
    pub size_bytes: u64,
}

/// A detached signature entry for a signed manifest payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateManifestSignature {
    /// Stable release-key identifier.
    pub key_id: String,
    /// Signature algorithm. v1 accepts only `Ed25519`.
    pub algorithm: String,
    /// Unpadded base64url Ed25519 signature.
    pub signature: String,
}

/// A manifest whose schema, metadata, and release signature have been verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedUpdateManifest {
    /// Verified metadata payload.
    pub payload: UpdateManifestPayload,
    /// Key id of the pinned release key that verified the payload.
    pub key_id: String,
}

/// Failure reasons for update manifest validation.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum UpdateManifestError {
    /// Manifest JSON could not be parsed.
    #[error("manifest JSON is invalid")]
    InvalidJson,
    /// Manifest schema version is unsupported.
    #[error("manifest schema version is unsupported")]
    UnsupportedSchema,
    /// Required signed metadata is missing or malformed.
    #[error("manifest metadata is invalid")]
    InvalidMetadata,
    /// Pinned release public key is malformed.
    #[error("release public key is invalid")]
    InvalidPublicKey,
    /// No signature matches the pinned release key id.
    #[error("manifest signature is missing")]
    MissingSignature,
    /// Manifest signature is malformed.
    #[error("manifest signature is invalid")]
    InvalidSignature,
    /// Manifest signature does not verify against the pinned key.
    #[error("manifest signature verification failed")]
    SignatureVerificationFailed,
}

impl From<UpdateManifestError> for LocketError {
    fn from(_: UpdateManifestError) -> Self {
        Self::UpdateManifestInvalid
    }
}

/// Parses and verifies a signed update manifest with a pinned Ed25519 release key.
///
/// The verifier performs no network I/O. Callers fetch the manifest only after
/// the user opts into update checks, then pass the bytes here with the pinned
/// release key compiled into the binary.
///
/// # Errors
///
/// Returns [`UpdateManifestError`] when JSON parsing, schema validation,
/// privacy-safe URL validation, or Ed25519 verification fails.
pub fn verify_update_manifest(
    manifest_bytes: &[u8],
    pinned_key_id: &str,
    pinned_public_key_base64url: &str,
) -> Result<VerifiedUpdateManifest, UpdateManifestError> {
    let manifest: SignedUpdateManifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| UpdateManifestError::InvalidJson)?;
    if manifest.v != MANIFEST_SCHEMA_VERSION {
        return Err(UpdateManifestError::UnsupportedSchema);
    }
    validate_payload(&manifest.signed)?;
    verify_manifest_signature(&manifest, pinned_key_id, pinned_public_key_base64url)?;
    Ok(VerifiedUpdateManifest { payload: manifest.signed, key_id: pinned_key_id.to_owned() })
}

/// Parses and verifies a release-key rotation manifest signed by both keys.
///
/// Rotation succeeds only when the same signed payload verifies with the
/// currently pinned key and the next pinned key. Callers can then persist or
/// ship the next key knowing the rotation manifest was authorized by both.
///
/// # Errors
///
/// Returns [`UpdateManifestError`] when the manifest is malformed, either
/// release key is invalid, either required signature is missing, or either
/// signature does not verify the signed payload.
pub fn verify_update_manifest_key_rotation(
    manifest_bytes: &[u8],
    current_key: &ReleaseKey,
    next_key: &ReleaseKey,
) -> Result<VerifiedUpdateManifest, UpdateManifestError> {
    if current_key.key_id == next_key.key_id {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    let manifest: SignedUpdateManifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| UpdateManifestError::InvalidJson)?;
    if manifest.v != MANIFEST_SCHEMA_VERSION {
        return Err(UpdateManifestError::UnsupportedSchema);
    }
    validate_payload(&manifest.signed)?;
    verify_manifest_signature(&manifest, &current_key.key_id, &current_key.public_key_base64url)?;
    verify_manifest_signature(&manifest, &next_key.key_id, &next_key.public_key_base64url)?;
    Ok(VerifiedUpdateManifest { payload: manifest.signed, key_id: next_key.key_id.clone() })
}

/// Builds the opt-in manifest fetch request without accepting private identifiers.
///
/// The returned request has no dynamic headers and the URL path contains only
/// update channel, platform, architecture, and current app version. The
/// configured base URL must be HTTPS and static: no query string, fragment,
/// userinfo, or explicit port.
///
/// # Errors
///
/// Returns [`UpdateManifestError::InvalidMetadata`] when the configured base
/// URL is not static HTTPS metadata or any path token contains characters that
/// would allow extra path/query/header data.
pub fn build_update_manifest_fetch_request(
    manifest_base_url: &str,
    channel: UpdateChannel,
    platform: &str,
    arch: &str,
    current_version: &str,
) -> Result<UpdateManifestFetchRequest, UpdateManifestError> {
    validate_https_static_url(manifest_base_url)?;
    validate_fetch_token(platform)?;
    validate_fetch_token(arch)?;
    validate_fetch_token(current_version)?;
    let base = manifest_base_url.trim_end_matches('/');
    Ok(UpdateManifestFetchRequest {
        url: format!(
            "{}/{}/{}/{}/{}/manifest.json",
            base,
            channel.as_str(),
            platform,
            arch,
            current_version
        ),
    })
}

fn validate_payload(payload: &UpdateManifestPayload) -> Result<(), UpdateManifestError> {
    validate_nonempty_token(&payload.version)?;
    validate_nonempty_token(&payload.published_at)?;
    if payload.artifacts.is_empty() {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    for artifact in &payload.artifacts {
        validate_nonempty_token(&artifact.platform)?;
        validate_nonempty_token(&artifact.arch)?;
        validate_https_static_url(&artifact.url)?;
        validate_sha256_hex(&artifact.sha256)?;
        if artifact.size_bytes == 0 {
            return Err(UpdateManifestError::InvalidMetadata);
        }
    }
    Ok(())
}

fn validate_nonempty_token(value: &str) -> Result<(), UpdateManifestError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    Ok(())
}

fn validate_fetch_token(value: &str) -> Result<(), UpdateManifestError> {
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
    {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    Ok(())
}

fn validate_https_static_url(url: &str) -> Result<(), UpdateManifestError> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(UpdateManifestError::InvalidMetadata);
    };
    if url.chars().any(|character| character.is_control() || character.is_whitespace())
        || url.contains(['?', '#', '\\'])
    {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    let host = rest.split('/').next().unwrap_or_default();
    // The URL parser normalizes explicit default ports, so check the raw authority too.
    if host.is_empty() || host.contains(['@', ':']) || url::Url::parse(url).is_err() {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    Ok(())
}

fn verify_manifest_signature(
    manifest: &SignedUpdateManifest,
    key_id: &str,
    public_key_base64url: &str,
) -> Result<(), UpdateManifestError> {
    let verifying_key = decode_verifying_key(public_key_base64url)?;
    let signature = manifest
        .signatures
        .iter()
        .find(|signature| signature.key_id == key_id && signature.algorithm == SIGNATURE_ALGORITHM)
        .ok_or(UpdateManifestError::MissingSignature)?;
    let signature = decode_signature(&signature.signature)?;
    verifying_key
        .verify(&signed_payload_bytes(&manifest.signed)?, &signature)
        .map_err(|_| UpdateManifestError::SignatureVerificationFailed)
}

fn validate_sha256_hex(value: &str) -> Result<(), UpdateManifestError> {
    if value.len() != SHA256_HEX_LEN
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    Ok(())
}

fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, UpdateManifestError> {
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| UpdateManifestError::InvalidPublicKey)?;
    let key_bytes: [u8; ED25519_PUBLIC_KEY_LEN] =
        bytes.try_into().map_err(|_| UpdateManifestError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| UpdateManifestError::InvalidPublicKey)
}

fn decode_signature(encoded: &str) -> Result<Signature, UpdateManifestError> {
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| UpdateManifestError::InvalidSignature)?;
    let signature_bytes: [u8; ED25519_SIGNATURE_LEN] =
        bytes.try_into().map_err(|_| UpdateManifestError::InvalidSignature)?;
    Ok(Signature::from_bytes(&signature_bytes))
}

fn signed_payload_bytes(payload: &UpdateManifestPayload) -> Result<Vec<u8>, UpdateManifestError> {
    let value: Value =
        serde_json::to_value(payload).map_err(|_| UpdateManifestError::InvalidMetadata)?;
    let mut bytes = Vec::from(SIGNATURE_DOMAIN);
    bytes.extend_from_slice(canonical_json(&value).as_bytes());
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use ed25519_dalek::{Signer, SigningKey};
    use proptest::prelude::*;
    use serde_json::json;

    use super::{
        ReleaseKey, SignedUpdateManifest, UpdateArtifact, UpdateChannel, UpdateManifestError,
        UpdateManifestPayload, UpdateManifestSignature, build_update_manifest_fetch_request,
        verify_update_manifest, verify_update_manifest_key_rotation,
    };
    use crate::LocketError;

    #[test]
    fn verifies_signed_manifest_and_returns_payload() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest()?;

        let verified = verify_update_manifest(&manifest, &key_id, &public_key)?;

        assert_eq!(verified.key_id, key_id);
        assert_eq!(verified.payload.version, "0.2.0");
        assert_eq!(verified.payload.artifacts[0].platform, "macos");
        Ok(())
    }

    #[test]
    fn rejects_unsigned_or_mismatched_key_id() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, _, public_key) = signed_manifest()?;

        let Err(error) = verify_update_manifest(&manifest, "release-key-other", &public_key) else {
            return Err("manifest should require the pinned key id".into());
        };

        assert_eq!(error, UpdateManifestError::MissingSignature);
        assert_eq!(LocketError::from(error).exit_code(), 89);
        Ok(())
    }

    #[test]
    fn rejects_invalid_json() -> Result<(), Box<dyn std::error::Error>> {
        let Err(error) = verify_update_manifest(b"{not json", "release-key-v1", "not-a-key") else {
            return Err("invalid JSON should fail before key parsing".into());
        };

        assert_eq!(error, UpdateManifestError::InvalidJson);
        Ok(())
    }

    #[test]
    fn rejects_unsupported_schema() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest()?;
        let mut manifest: serde_json::Value = serde_json::from_slice(&manifest)?;
        manifest["v"] = json!(2);
        let manifest = serde_json::to_vec(&manifest)?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, &public_key) else {
            return Err("unsupported schema should fail before trusting manifest".into());
        };

        assert_eq!(error, UpdateManifestError::UnsupportedSchema);
        Ok(())
    }

    #[test]
    fn rejects_invalid_pinned_release_key() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, _) = signed_manifest()?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, "not-a-release-key") else {
            return Err("invalid pinned release key should fail".into());
        };

        assert_eq!(error, UpdateManifestError::InvalidPublicKey);
        Ok(())
    }

    #[test]
    fn rejects_malformed_signature() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest()?;
        let mut manifest: serde_json::Value = serde_json::from_slice(&manifest)?;
        manifest["signatures"][0]["signature"] = json!("not-a-signature");
        let manifest = serde_json::to_vec(&manifest)?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, &public_key) else {
            return Err("malformed signature should fail".into());
        };

        assert_eq!(error, UpdateManifestError::InvalidSignature);
        Ok(())
    }

    #[test]
    fn rejects_tampered_signed_payload() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest()?;
        let mut manifest: serde_json::Value = serde_json::from_slice(&manifest)?;
        manifest["signed"]["version"] = json!("0.2.1");
        let manifest = serde_json::to_vec(&manifest)?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, &public_key) else {
            return Err("tampered manifest should not verify".into());
        };

        assert_eq!(error, UpdateManifestError::SignatureVerificationFailed);
        Ok(())
    }

    #[test]
    fn rejects_non_static_or_non_https_urls() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest_with_url(
            "https://updates.example.test/locket.pkg?project_id=lk_proj_secret",
        )?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, &public_key) else {
            return Err("tracking query strings should be rejected".into());
        };

        assert_eq!(error, UpdateManifestError::InvalidMetadata);
        Ok(())
    }

    #[test]
    fn rejects_invalid_artifact_digest_shape() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest_with_digest("ABC")?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, &public_key) else {
            return Err("invalid digest should be rejected before trusting manifest".into());
        };

        assert_eq!(error, UpdateManifestError::InvalidMetadata);
        Ok(())
    }

    #[test]
    fn builds_privacy_preserving_manifest_fetch_request() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = build_update_manifest_fetch_request(
            "https://updates.example.test/locket",
            UpdateChannel::Stable,
            "macos",
            "aarch64",
            "0.2.0",
        )?;

        assert_eq!(
            request.url,
            "https://updates.example.test/locket/stable/macos/aarch64/0.2.0/manifest.json"
        );
        for forbidden in [
            "project", "profile", "secret", "policy", "device", "member", "hostname", "username",
            "install", "token", "?", "#",
        ] {
            assert!(!request.url.contains(forbidden));
        }
        Ok(())
    }

    #[test]
    fn validates_beta_fetch_paths_and_rejects_ambiguous_authorities()
    -> Result<(), UpdateManifestError> {
        let channel = UpdateChannel::Beta;
        let request = build_update_manifest_fetch_request(
            "https://updates.example.test/locket/",
            channel,
            "linux",
            "x86_64",
            "1.0.0-beta+1",
        )?;
        assert_eq!(
            request.url,
            "https://updates.example.test/locket/beta/linux/x86_64/1.0.0-beta+1/manifest.json"
        );
        for url in [
            "http://updates.example.test",
            "https:///missing-host",
            "https://user@updates.example.test",
            "https://updates.example.test:443",
        ] {
            assert_eq!(
                build_update_manifest_fetch_request(url, channel, "linux", "x86_64", "1.0"),
                Err(UpdateManifestError::InvalidMetadata)
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_invalid_signed_metadata_before_signature_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let (valid, id, key) = signed_manifest()?;
        let manifest: SignedUpdateManifest = serde_json::from_slice(&valid)?;
        let mut no_artifacts = manifest.clone();
        no_artifacts.signed.artifacts.clear();
        let mut zero_size = manifest.clone();
        zero_size.signed.artifacts[0].size_bytes = 0;
        let mut invalid_version = manifest.clone();
        invalid_version.signed.version = "1.0\n".into();
        for invalid in [no_artifacts, zero_size, invalid_version] {
            assert_eq!(
                verify_update_manifest(&serde_json::to_vec(&invalid)?, &id, &key),
                Err(UpdateManifestError::InvalidMetadata)
            );
        }
        let current = ReleaseKey { key_id: id, public_key_base64url: key };
        assert_eq!(
            verify_update_manifest_key_rotation(&valid, &current, &current),
            Err(UpdateManifestError::InvalidMetadata)
        );
        let next = ReleaseKey { key_id: "next".into(), ..current.clone() };
        let mut wrong_schema = manifest;
        wrong_schema.v += 1;
        assert_eq!(
            verify_update_manifest_key_rotation(
                &serde_json::to_vec(&wrong_schema)?,
                &current,
                &next
            ),
            Err(UpdateManifestError::UnsupportedSchema)
        );
        Ok(())
    }

    #[test]
    fn rejects_non_static_or_private_manifest_fetch_inputs() {
        let query = build_update_manifest_fetch_request(
            "https://updates.example.test/manifest.json?install_id=abc",
            UpdateChannel::Stable,
            "macos",
            "aarch64",
            "0.2.0",
        );
        assert_eq!(query, Err(UpdateManifestError::InvalidMetadata));

        let path_escape = build_update_manifest_fetch_request(
            "https://updates.example.test/manifest.json",
            UpdateChannel::Stable,
            "macos/lk_proj_secret",
            "aarch64",
            "0.2.0",
        );
        assert_eq!(path_escape, Err(UpdateManifestError::InvalidMetadata));
    }

    #[test]
    fn rejects_fetch_components_that_change_when_parsed_as_a_url() {
        let base = "https://updates.example.test/locket";
        for (base, platform, arch, version) in [
            (base, "..", "aarch64", "1.0"),
            (base, "macos", ".", "1.0"),
            (base, "macos", "aarch64", ".."),
            ("https://updates.example.test\\releases", "macos", "aarch64", "1.0"),
            ("https://bad host.example.test", "macos", "aarch64", "1.0"),
            ("https://bad%zz.example.test", "macos", "aarch64", "1.0"),
        ] {
            assert_eq!(
                build_update_manifest_fetch_request(
                    base,
                    UpdateChannel::Stable,
                    platform,
                    arch,
                    version
                ),
                Err(UpdateManifestError::InvalidMetadata)
            );
        }
    }

    #[test]
    fn key_rotation_requires_old_and_new_signatures() -> Result<(), Box<dyn std::error::Error>> {
        let current_key_id = "release-key-v1".to_owned();
        let next_key_id = "release-key-v2".to_owned();
        let current_signing_key = SigningKey::from_bytes(&[7; 32]);
        let next_signing_key = SigningKey::from_bytes(&[8; 32]);
        let current_release_key = ReleaseKey {
            key_id: current_key_id.clone(),
            public_key_base64url: BASE64URL_NOPAD
                .encode(current_signing_key.verifying_key().as_bytes()),
        };
        let next_release_key = ReleaseKey {
            key_id: next_key_id.clone(),
            public_key_base64url: BASE64URL_NOPAD
                .encode(next_signing_key.verifying_key().as_bytes()),
        };
        let manifest = signed_manifest_with_artifact_and_keys(
            release_artifact(),
            vec![
                (current_key_id.clone(), current_signing_key.clone()),
                (next_key_id.clone(), next_signing_key),
            ],
        )?;

        let verified = verify_update_manifest_key_rotation(
            &manifest,
            &current_release_key,
            &next_release_key,
        )?;

        assert_eq!(verified.key_id, next_key_id);

        let missing_next = signed_manifest_with_artifact_and_keys(
            release_artifact(),
            vec![(current_key_id, current_signing_key)],
        )?;
        let Err(error) = verify_update_manifest_key_rotation(
            &missing_next,
            &current_release_key,
            &next_release_key,
        ) else {
            return Err("rotation manifest should require both signatures".into());
        };
        assert_eq!(error, UpdateManifestError::MissingSignature);
        Ok(())
    }

    proptest! {
        #[test]
        fn valid_signed_manifest_payloads_verify(
            artifact in release_artifact_strategy(),
            version in "[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}",
            published_day in 1u8..=28,
        ) {
            let payload = UpdateManifestPayload {
                channel: UpdateChannel::Stable,
                version,
                published_at: format!("2026-04-{published_day:02}T00:00:00Z"),
                artifacts: vec![artifact],
            };
            let (manifest, key_id, public_key) = signed_manifest_with_payload(payload.clone())
                .expect("generated valid manifest should sign");

            let verified = verify_update_manifest(&manifest, &key_id, &public_key)
                .expect("generated valid manifest should verify");

            prop_assert_eq!(verified.key_id, key_id);
            prop_assert_eq!(verified.payload, payload);
        }

        #[test]
        fn signed_manifest_rejects_valid_metadata_changed_after_signing(
            artifact in release_artifact_strategy(),
            changed_sha256 in lowercase_sha256_strategy(),
        ) {
            prop_assume!(changed_sha256 != artifact.sha256);
            let payload = UpdateManifestPayload {
                channel: UpdateChannel::Stable,
                version: "0.2.0".to_owned(),
                published_at: "2026-04-29T00:00:00Z".to_owned(),
                artifacts: vec![artifact],
            };
            let (manifest, key_id, public_key) = signed_manifest_with_payload(payload)
                .expect("generated valid manifest should sign");
            let mut envelope: SignedUpdateManifest = serde_json::from_slice(&manifest).unwrap();
            envelope.signed.artifacts[0].sha256 = changed_sha256;
            let changed_manifest = serde_json::to_vec(&envelope).unwrap();

            let error = verify_update_manifest(&changed_manifest, &key_id, &public_key)
                .expect_err("valid metadata changed after signing must not verify");

            prop_assert_eq!(error, UpdateManifestError::SignatureVerificationFailed);
        }
    }

    fn release_artifact_strategy() -> impl Strategy<Value = UpdateArtifact> {
        (
            prop_oneof![
                Just("macos".to_owned()),
                Just("windows".to_owned()),
                Just("linux".to_owned()),
            ],
            prop_oneof![Just("aarch64".to_owned()), Just("x86_64".to_owned())],
            prop::collection::vec("[a-z0-9][a-z0-9._+-]{0,12}", 1..4),
            lowercase_sha256_strategy(),
            1_u64..=100_000_000,
        )
            .prop_map(|(platform, arch, path, sha256, size_bytes)| UpdateArtifact {
                platform,
                arch,
                url: format!("https://updates.example.test/{}", path.join("/")),
                sha256,
                size_bytes,
            })
    }

    fn lowercase_sha256_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop_oneof![b'0'..=b'9', b'a'..=b'f'], 64)
            .prop_map(|bytes| String::from_utf8(bytes).expect("hex bytes are utf8"))
    }

    fn signed_manifest() -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
        signed_manifest_with_url("https://updates.example.test/releases/locket-0.2.0-aarch64.pkg")
    }

    fn signed_manifest_with_url(
        url: &str,
    ) -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
        signed_manifest_with_artifact(UpdateArtifact {
            platform: "macos".to_owned(),
            arch: "aarch64".to_owned(),
            url: url.to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            size_bytes: 42,
        })
    }

    fn signed_manifest_with_digest(
        sha256: &str,
    ) -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
        signed_manifest_with_artifact(UpdateArtifact {
            platform: "macos".to_owned(),
            arch: "aarch64".to_owned(),
            url: "https://updates.example.test/releases/locket-0.2.0-aarch64.pkg".to_owned(),
            sha256: sha256.to_owned(),
            size_bytes: 42,
        })
    }

    fn signed_manifest_with_artifact(
        artifact: UpdateArtifact,
    ) -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
        signed_manifest_with_payload(UpdateManifestPayload {
            channel: UpdateChannel::Stable,
            version: "0.2.0".to_owned(),
            published_at: "2026-04-29T00:00:00Z".to_owned(),
            artifacts: vec![artifact],
        })
    }

    fn signed_manifest_with_payload(
        payload: UpdateManifestPayload,
    ) -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
        let key_id = "release-key-v1".to_owned();
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let public_key = BASE64URL_NOPAD.encode(signing_key.verifying_key().as_bytes());
        let manifest =
            signed_manifest_with_payload_and_keys(payload, vec![(key_id.clone(), signing_key)])?;
        Ok((manifest, key_id, public_key))
    }

    fn signed_manifest_with_artifact_and_keys(
        artifact: UpdateArtifact,
        signers: Vec<(String, SigningKey)>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let payload = UpdateManifestPayload {
            channel: UpdateChannel::Stable,
            version: "0.2.0".to_owned(),
            published_at: "2026-04-29T00:00:00Z".to_owned(),
            artifacts: vec![artifact],
        };
        signed_manifest_with_payload_and_keys(payload, signers)
    }

    fn signed_manifest_with_payload_and_keys(
        payload: UpdateManifestPayload,
        signers: Vec<(String, SigningKey)>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let signed_payload = super::signed_payload_bytes(&payload)?;
        let envelope = SignedUpdateManifest {
            v: 1,
            signed: payload,
            signatures: signers
                .into_iter()
                .map(|(key_id, signing_key)| {
                    let signature = signing_key.sign(&signed_payload);
                    UpdateManifestSignature {
                        key_id,
                        algorithm: "Ed25519".to_owned(),
                        signature: BASE64URL_NOPAD.encode(&signature.to_bytes()),
                    }
                })
                .collect(),
        };
        Ok(serde_json::to_vec(&envelope)?)
    }

    fn release_artifact() -> UpdateArtifact {
        UpdateArtifact {
            platform: "macos".to_owned(),
            arch: "aarch64".to_owned(),
            url: "https://updates.example.test/releases/locket-0.2.0-aarch64.pkg".to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            size_bytes: 42,
        }
    }
}
