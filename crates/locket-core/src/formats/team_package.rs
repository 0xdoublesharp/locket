//! Authenticated team snapshots. Sign exact statement bytes inside recipient encryption.
#![allow(missing_docs)]
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const MAX_PACKAGE_BYTES: usize = 16 * 1024 * 1024;
const DOMAIN: &[u8] = b"locket-team-state-v1\0";

#[derive(Debug, thiserror::Error)]
#[error("team package rejected: {0}")]
pub struct PackageError(pub String);
impl From<serde_json::Error> for PackageError {
    fn from(_: serde_json::Error) -> Self {
        Self("invalid statement schema".into())
    }
}
pub type PackageResult<T> = Result<T, PackageError>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentity {
    pub id: String,
    pub signing_key: [u8; 32],
    pub sealing_key: [u8; 32],
    pub fingerprint: String,
}
impl DeviceIdentity {
    #[must_use]
    pub fn new(id: String, signing_key: [u8; 32], sealing_key: [u8; 32]) -> Self {
        let fingerprint =
            crate::fingerprint_hex(&crate::device_fingerprint_v1(&signing_key, &sealing_key));
        Self { id, signing_key, sealing_key, fingerprint }
    }
    #[must_use]
    pub fn valid(&self) -> bool {
        self.fingerprint
            == Self::new(self.id.clone(), self.signing_key, self.sealing_key).fingerprint
            && !self.id.is_empty()
            && self.sealing_key != [0; 32]
            && VerifyingKey::from_bytes(&self.signing_key).is_ok()
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamMember {
    pub id: String,
    pub name: String,
    pub role: String,
    pub profiles: Vec<String>,
    pub device: DeviceIdentity,
    pub removed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamBlob {
    pub encrypted_dek: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub value_nonce: [u8; 24],
    pub aad_schema_version: u16,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamSecret {
    pub id: String,
    pub name: String,
    pub version: u32,
    pub deleted: bool,
    pub created_at: i64,
    pub blob: Option<TeamBlob>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamProfile {
    pub id: String,
    pub name: String,
    pub dangerous: bool,
    pub created_at: i64,
    pub key_epoch: u32,
    pub secret_key: [u8; 32],
    pub fingerprint_key: [u8; 32],
    pub secrets: Vec<TeamSecret>,
}
impl Drop for TeamProfile {
    fn drop(&mut self) {
        self.secret_key.zeroize();
        self.fingerprint_key.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamStatement {
    pub v: u8,
    pub team_id: String,
    pub project_id: String,
    pub epoch: u64,
    pub previous_digest: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: [u8; 24],
    pub publisher: DeviceIdentity,
    pub recipient: DeviceIdentity,
    pub members: Vec<TeamMember>,
    pub profiles: Vec<TeamProfile>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedStatement {
    pub statement: Vec<u8>,
    pub signing_key: [u8; 32],
    pub signature: String,
}
impl Drop for SignedStatement {
    fn drop(&mut self) {
        self.statement.zeroize();
    }
}
pub struct VerifiedStatement {
    pub statement: TeamStatement,
    pub digest: String,
}
impl SignedStatement {
    /// # Errors
    /// Rejects statements that cannot be serialized.
    pub fn sign(statement: &TeamStatement, key: &SigningKey) -> PackageResult<Self> {
        let bytes = serde_json::to_vec(statement)?;
        let mut message = zeroize::Zeroizing::new(DOMAIN.to_vec());
        message.extend_from_slice(&bytes);
        Ok(Self {
            statement: bytes,
            signing_key: key.verifying_key().to_bytes(),
            signature: BASE64URL_NOPAD.encode(&key.sign(&message).to_bytes()),
        })
    }
    /// # Errors
    /// Rejects invalid signatures, external pins, recipients, scope, epochs or expiry.
    pub fn verify(
        &self,
        pin: &str,
        project: &str,
        recipient: &DeviceIdentity,
        now: i64,
    ) -> PackageResult<VerifiedStatement> {
        self.verify_inner(pin, project, recipient, now, true)
    }
    /// Verifies an established pinned stream; callers must enforce its saved predecessor.
    /// # Errors
    /// Rejects invalid signatures, pins, scope or future-issued statements.
    pub fn verify_update(
        &self,
        pin: &str,
        project: &str,
        recipient: &DeviceIdentity,
        now: i64,
    ) -> PackageResult<VerifiedStatement> {
        self.verify_inner(pin, project, recipient, now, false)
    }
    fn verify_inner(
        &self,
        pin: &str,
        project: &str,
        recipient: &DeviceIdentity,
        now: i64,
        first_join: bool,
    ) -> PackageResult<VerifiedStatement> {
        if self.statement.len() > MAX_PACKAGE_BYTES {
            return Err(PackageError("statement too large".into()));
        }
        let key = VerifyingKey::from_bytes(&self.signing_key)
            .map_err(|_| PackageError("invalid signer".into()))?;
        let signature = BASE64URL_NOPAD
            .decode(self.signature.as_bytes())
            .map_err(|_| PackageError("invalid signature".into()))?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| PackageError("invalid signature".into()))?;
        let mut message = zeroize::Zeroizing::new(DOMAIN.to_vec());
        message.extend_from_slice(&self.statement);
        key.verify_strict(&message, &signature)
            .map_err(|_| PackageError("invalid signature".into()))?;
        let statement: TeamStatement = serde_json::from_slice(&self.statement)?;
        if statement.v != 1
            || statement.epoch == 0
            || statement.epoch > i64::MAX as u64
            || statement.project_id != project
            || statement.team_id.is_empty()
            || statement.publisher.signing_key != self.signing_key
            || !statement.publisher.valid()
            || statement.publisher.fingerprint != pin
            || pin.len() != 64
            || !recipient.valid()
            || statement.recipient != *recipient
            || statement.expires_at <= statement.issued_at
            || statement.expires_at.saturating_sub(statement.issued_at) > 30 * 86400
            || now.saturating_add(300) < statement.issued_at
            || (first_join && now.saturating_sub(300) > statement.expires_at)
        {
            return Err(PackageError("pin, scope, recipient, version or expiry mismatch".into()));
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut devices = std::collections::BTreeSet::new();
        for member in &statement.members {
            if !member.device.valid()
                || member.id.is_empty()
                || !ids.insert(&member.id)
                || !devices.insert(&member.device.fingerprint)
                || !["owner", "maintainer", "developer", "read-only"]
                    .contains(&member.role.as_str())
            {
                return Err(PackageError("invalid membership".into()));
            }
        }
        if !statement
            .members
            .iter()
            .any(|m| !m.removed && m.role == "owner" && m.device == statement.publisher)
        {
            return Err(PackageError("publisher is not active owner".into()));
        }
        let member = statement
            .members
            .iter()
            .find(|m| m.device == *recipient)
            .ok_or_else(|| PackageError("recipient is not a member".into()))?;
        let mut profiles = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        let mut secrets = std::collections::BTreeSet::new();
        for profile in &statement.profiles {
            if member.removed
                || !member.profiles.contains(&profile.id)
                || profile.key_epoch == 0
                || !profiles.insert(&profile.id)
                || !names.insert(&profile.name)
            {
                return Err(PackageError("profile outside recipient grant".into()));
            }
            let mut secret_names = std::collections::BTreeSet::new();
            for secret in &profile.secrets {
                if secret.version == 0
                    || !secrets.insert(&secret.id)
                    || !secret_names.insert(&secret.name)
                    || secret.deleted == secret.blob.is_some()
                {
                    return Err(PackageError("invalid secret snapshot".into()));
                }
            }
        }
        if !member.removed && profiles != member.profiles.iter().collect() {
            return Err(PackageError("incomplete profile scope".into()));
        }
        Ok(VerifiedStatement { statement, digest: digest(&self.statement) })
    }
    /// # Errors
    /// Rejects invalid recipients, excessive payloads or encryption failures.
    pub fn seal(&self, recipient: &[u8; 32]) -> PackageResult<Vec<u8>> {
        let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(self)?);
        let encrypted = crate::encrypt_bundle_payload_for_age_recipients(&plaintext, &[*recipient])
            .map_err(|_| PackageError("encryption failed".into()))?;
        if encrypted.len() > MAX_PACKAGE_BYTES {
            return Err(PackageError("package too large".into()));
        }
        let mut bytes = crate::BUNDLE_MAGIC.to_vec();
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&(encrypted.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&encrypted);
        Ok(bytes)
    }
    /// # Errors
    /// Rejects malformed, oversized or undecryptable v2 containers.
    pub fn open(bytes: &[u8], secret: &[u8; 32]) -> PackageResult<Self> {
        if bytes.len() < 18
            || bytes.len() > MAX_PACKAGE_BYTES + 18
            || &bytes[..8] != crate::BUNDLE_MAGIC
            || bytes[8..10] != 2_u16.to_le_bytes()
        {
            return Err(PackageError("invalid v2 container".into()));
        }
        let len = u64::from_le_bytes(
            bytes[10..18].try_into().map_err(|_| PackageError("invalid length".into()))?,
        );
        if len != (bytes.len() - 18) as u64 {
            return Err(PackageError("incomplete container".into()));
        }
        let plaintext =
            crate::decrypt_bundle_payload_with_x25519_secret_zeroizing(&bytes[18..], secret)
                .map_err(|_| PackageError("not decryptable".into()))?;
        Ok(serde_json::from_slice(&plaintext)?)
    }
}
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    crate::fingerprint_hex(&Sha256::digest(bytes).into())
}
