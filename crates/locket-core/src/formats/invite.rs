//! Signed invite codec for the team trust ceremony.
//!
//! Spec: `docs/specs/team-sync-recovery.md`, "Team invite trust ceremony".

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::id::{InviteId, MemberId, ProjectId};

/// Serialization prefix for encoded invite strings.
pub const INVITE_PREFIX: &str = "lkinvite1_";

/// Domain separator for invite payload signatures.
const INVITE_DOMAIN: &[u8] = b"locket-invite-v1\0";

/// Collaboration role granted by this invite.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamRole {
    /// Full administrative control over team, members, devices, and profiles.
    Owner,
    /// Invite developers, manage non-dangerous profiles, rotate shared secrets.
    Maintainer,
    /// Accept invites, use granted profiles, run policies.
    Developer,
    /// Inspect metadata, run scans, use explicitly granted read-only workflows.
    ReadOnly,
}

/// The signed payload embedded in every invite.
///
/// All fields here are covered by the Ed25519 signature over the canonical
/// JSON representation (domain-prefixed). Callers must not trust any field
/// before calling [`SignedInvite::verify`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvitePayload {
    /// Schema version, always `1` for this type.
    pub v: u8,
    /// Unique invite identifier; recorded by `team accept` to prevent replay.
    pub invite_id: InviteId,
    /// Project the invite is scoped to.
    pub project_id: ProjectId,
    /// `MemberId` of the inviting team member.
    pub issuer_member_id: MemberId,
    /// Ed25519 signing public key of the issuer device (32 bytes, base64url).
    pub issuer_signing_public_key: String,
    /// X25519 sealing public key of the issuer device (32 bytes, base64url).
    pub issuer_sealing_public_key: String,
    /// SHA-256 device identity fingerprint of the issuer device (hex).
    pub issuer_device_fingerprint: String,
    /// SHA-256 device identity fingerprint of the intended recipient (hex).
    pub recipient_device_fingerprint: String,
    /// X25519 sealing public key of the recipient device (32 bytes, base64url).
    pub recipient_sealing_public_key: String,
    /// Role granted to the recipient on acceptance.
    pub role: TeamRole,
    /// Profile names included in this invite.
    pub profiles: Vec<String>,
    /// UTC expiry as Unix seconds.
    pub expires_at: i64,
    /// 24-byte random nonce (base64url) to ensure uniqueness even across
    /// identical metadata.
    pub nonce: String,
    /// Age-encrypted inner payload that lets `team accept` import profile
    /// keys and command policies into the recipient's store as part of
    /// the trust ceremony.
    ///
    /// The whole field is signature-covered (Ed25519 over canonical
    /// JSON of `InvitePayload`), so a man-in-the-middle cannot strip
    /// or substitute the sealed section without invalidating
    /// [`SignedInvite::verify`].
    pub sealed_payload: SealedInvitePayloadV1,
}

/// Age-encrypted inner section of an [`InvitePayload`].
///
/// Carries the recipient-keyed age ciphertext for the smaller invite
/// import surface: profile keys + command policies + an optional list
/// of canonicalized secret metadata (no values).
///
/// Encryption envelope is age, recipient-keyed by the invite's
/// `recipient_sealing_public_key` so only the intended device can
/// decrypt. The outer signature on [`InvitePayload`] still covers this
/// field structurally (the encrypted blob is part of the canonical
/// JSON), preventing a man-in-the-middle from stripping or swapping
/// the sealed section.
///
/// All `_b64` fields are base64url-unpadded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedInvitePayloadV1 {
    /// Schema version of the sealed payload itself; always `1` here.
    /// Bumped independently of the outer invite schema so future
    /// versions can extend the inner format without forcing every
    /// invite consumer to upgrade in lockstep.
    pub v: u8,
    /// Age-encrypted ciphertext of the canonical-JSON inner payload
    /// (profile keys + command policies + optional secret metadata),
    /// base64url-unpadded.
    pub ciphertext_b64: String,
    /// X25519 recipient public key the ciphertext was sealed for,
    /// base64url-unpadded. Must equal `recipient_sealing_public_key`
    /// on the enclosing [`InvitePayload`]; mirrored here to make
    /// receiver-side key selection self-contained when the recipient
    /// rotates devices and needs to look up the matching private key.
    pub recipient_sealing_public_key_b64: String,
    /// AAD schema version covering the encryption parameters. Mirrors
    /// `locket_crypto::AAD_SCHEMA_V1` so the recipient can bind the
    /// decrypt step to a known canonical AAD layout.
    pub aad_schema_version: u16,
    /// Plaintext counts emitted by the issuer for receiver-side audit
    /// rows. Counts only; never names. `secret_metadata_count` covers
    /// the optional canonicalized-metadata list (no values, no
    /// ciphertext). Useful for the `TEAM_ACCEPT` audit row to report
    /// per-family counts without decrypting first.
    pub plaintext_counts: SealedInvitePlaintextCounts,
}

/// Per-family plaintext counts carried alongside the encrypted inner
/// invite payload.
///
/// Counts only; never names or values. The recipient uses these to
/// shape the `TEAM_ACCEPT` audit row when an invite carries a sealed
/// payload but the recipient declines (or fails) to apply it.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedInvitePlaintextCounts {
    /// Number of `(profile_id, purpose)` profile-key pairs in the
    /// encrypted inner payload.
    pub profile_key_count: u32,
    /// Number of command-policy rows in the encrypted inner payload.
    pub command_policy_count: u32,
    /// Number of canonicalized secret-metadata entries (names + flags;
    /// no ciphertext, no DEKs) in the encrypted inner payload.
    pub secret_metadata_count: u32,
}

/// A signed invite envelope: payload + detached Ed25519 signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedInvite {
    /// The fields covered by the signature.
    pub payload: InvitePayload,
    /// Detached Ed25519 signature over
    /// `INVITE_DOMAIN || canonical_json(payload)`.
    pub signature: String,
}

/// Error from [`SignedInvite::encode`].
#[derive(Debug, Error)]
pub enum InviteEncodeError {
    /// JSON serialization of the invite struct failed.
    #[error("invite serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Error from [`SignedInvite::decode`].
#[derive(Debug, Error)]
pub enum InviteDecodeError {
    /// The input string does not start with [`INVITE_PREFIX`].
    #[error("invite string has wrong prefix")]
    WrongPrefix,
    /// The base64url payload could not be decoded.
    #[error("invite base64url decode failed")]
    Base64,
    /// The decoded bytes are not valid invite JSON.
    #[error("invite JSON decode failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Error from [`SignedInvite::verify`].
#[derive(Debug, Error)]
pub enum InviteVerifyError {
    /// The issuer signing public key is not a valid 32-byte Ed25519 key.
    #[error("issuer public key is invalid")]
    InvalidIssuerKey,
    /// The signature does not verify against the payload and issuer key.
    #[error("invite signature is invalid")]
    InvalidSignature,
}

/// Maximum clock-skew tolerance applied to [`SignedInvite::check_expiry`].
///
/// Spec: `docs/specs/team-sync-recovery.md` — invite expiry comparisons
/// honor up to 5 minutes of clock drift between issuer and accepter.
pub const INVITE_CLOCK_SKEW_SECONDS: i64 = 5 * 60;

/// Error from [`SignedInvite::check_expiry`].
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InviteExpiryError {
    /// `now` is more than [`INVITE_CLOCK_SKEW_SECONDS`] past
    /// `payload.expires_at`.
    #[error(
        "invite expired: expires_at {expires_at} is {expired_seconds}s before now (skew tolerance {skew_seconds}s)"
    )]
    Expired {
        /// `expires_at` field copied from the invite payload.
        expires_at: i64,
        /// `now - expires_at` in seconds (always positive when this
        /// variant fires).
        expired_seconds: i64,
        /// Tolerance applied; matches [`INVITE_CLOCK_SKEW_SECONDS`].
        skew_seconds: i64,
    },
}

/// Compute the v1 device identity fingerprint.
///
/// `SHA-256("locket-device-v1" || u16_le(signing_key_len) || signing_key
///           || u16_le(sealing_key_len) || sealing_key)`
#[must_use]
pub fn device_fingerprint_v1(
    signing_public_key: &[u8; 32],
    sealing_public_key: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"locket-device-v1");
    hasher.update(u16::try_from(signing_public_key.len()).unwrap_or(32).to_le_bytes());
    hasher.update(signing_public_key);
    hasher.update(u16::try_from(sealing_public_key.len()).unwrap_or(32).to_le_bytes());
    hasher.update(sealing_public_key);
    hasher.finalize().into()
}

/// Format a fingerprint as lowercase hex.
#[must_use]
pub fn fingerprint_hex(fingerprint: &[u8; 32]) -> String {
    fingerprint.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

impl SignedInvite {
    /// Sign an invite payload with the issuer device signing key.
    ///
    /// # Errors
    ///
    /// Returns [`InviteEncodeError::Serialize`] if payload serialization fails.
    pub fn sign(
        signing_key: &SigningKey,
        payload: InvitePayload,
    ) -> Result<Self, InviteEncodeError> {
        let payload_json = serde_json::to_vec(&payload)?;
        let mut message = Vec::with_capacity(INVITE_DOMAIN.len() + payload_json.len());
        message.extend_from_slice(INVITE_DOMAIN);
        message.extend_from_slice(&payload_json);
        let signature: Signature = signing_key.sign(&message);
        Ok(Self { payload, signature: BASE64URL_NOPAD.encode(&signature.to_bytes()) })
    }

    /// Encode to `lkinvite1_<base64url-json>`.
    ///
    /// # Errors
    ///
    /// Returns [`InviteEncodeError::Serialize`] if JSON serialization fails.
    pub fn encode(&self) -> Result<String, InviteEncodeError> {
        let json = serde_json::to_vec(self)?;
        let mut out = String::with_capacity(INVITE_PREFIX.len() + json.len() * 4 / 3 + 4);
        out.push_str(INVITE_PREFIX);
        out.push_str(&BASE64URL_NOPAD.encode(&json));
        Ok(out)
    }

    /// Decode from `lkinvite1_<base64url-json>`.
    ///
    /// # Errors
    ///
    /// Returns [`InviteDecodeError`] on prefix mismatch, base64 error, or JSON
    /// error.
    pub fn decode(s: &str) -> Result<Self, InviteDecodeError> {
        let encoded = s.strip_prefix(INVITE_PREFIX).ok_or(InviteDecodeError::WrongPrefix)?;
        let bytes =
            BASE64URL_NOPAD.decode(encoded.as_bytes()).map_err(|_| InviteDecodeError::Base64)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Verify the detached signature against the claimed issuer signing key.
    ///
    /// Reconstructs `INVITE_DOMAIN || canonical_json(payload)` and checks the
    /// Ed25519 signature. Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns [`InviteVerifyError`] when the issuer public key is malformed or
    /// the signature does not verify.
    pub fn verify(&self) -> Result<(), InviteVerifyError> {
        let key_bytes = BASE64URL_NOPAD
            .decode(self.payload.issuer_signing_public_key.as_bytes())
            .map_err(|_| InviteVerifyError::InvalidIssuerKey)?;
        let key_array: [u8; 32] =
            key_bytes.try_into().map_err(|_| InviteVerifyError::InvalidIssuerKey)?;
        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|_| InviteVerifyError::InvalidIssuerKey)?;

        let sig_bytes = BASE64URL_NOPAD
            .decode(self.signature.as_bytes())
            .map_err(|_| InviteVerifyError::InvalidSignature)?;
        let sig_array: [u8; 64] =
            sig_bytes.try_into().map_err(|_| InviteVerifyError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_array);

        let payload_json =
            serde_json::to_vec(&self.payload).map_err(|_| InviteVerifyError::InvalidSignature)?;
        let mut message = Vec::with_capacity(INVITE_DOMAIN.len() + payload_json.len());
        message.extend_from_slice(INVITE_DOMAIN);
        message.extend_from_slice(&payload_json);

        verifying_key.verify(&message, &signature).map_err(|_| InviteVerifyError::InvalidSignature)
    }

    /// Reject invites whose `expires_at` is more than 5 minutes in the
    /// past relative to `now_unix_seconds`.
    ///
    /// `now <= expires_at + INVITE_CLOCK_SKEW_SECONDS` succeeds. This
    /// matches the spec's bidirectional clock-skew tolerance: clients
    /// whose clocks are slow by up to 5 minutes still accept invites
    /// that just expired, and clients whose clocks are fast still
    /// accept invites the issuer claims are within the window.
    ///
    /// # Errors
    ///
    /// Returns [`InviteExpiryError::Expired`] when the invite is past
    /// the tolerance window.
    pub const fn check_expiry(&self, now_unix_seconds: i64) -> Result<(), InviteExpiryError> {
        let expires_at = self.payload.expires_at;
        let expired_seconds = now_unix_seconds.saturating_sub(expires_at);
        if expired_seconds > INVITE_CLOCK_SKEW_SECONDS {
            return Err(InviteExpiryError::Expired {
                expires_at,
                expired_seconds,
                skew_seconds: INVITE_CLOCK_SKEW_SECONDS,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::id::{InviteId, MemberId, ProjectId};

    fn make_signing_key() -> ed25519_dalek::SigningKey {
        let seed = [0x42_u8; 32];
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    fn make_payload(
        signing_key: &ed25519_dalek::SigningKey,
        sealing_pub: &[u8; 32],
    ) -> InvitePayload {
        let signing_pub: [u8; 32] = signing_key.verifying_key().to_bytes();
        let fp = device_fingerprint_v1(&signing_pub, sealing_pub);

        InvitePayload {
            v: 1,
            invite_id: InviteId::new("lk_invite_test01").unwrap(),
            project_id: ProjectId::new("lk_proj_test01").unwrap(),
            issuer_member_id: MemberId::new("lk_member_alice").unwrap(),
            issuer_signing_public_key: BASE64URL_NOPAD.encode(&signing_pub),
            issuer_sealing_public_key: BASE64URL_NOPAD.encode(sealing_pub),
            issuer_device_fingerprint: fingerprint_hex(&fp),
            recipient_device_fingerprint: fingerprint_hex(&fp),
            recipient_sealing_public_key: BASE64URL_NOPAD.encode(sealing_pub),
            role: TeamRole::Developer,
            profiles: vec!["dev".to_owned()],
            expires_at: 9_999_999_999,
            nonce: BASE64URL_NOPAD.encode(&[0_u8; 24]),
            sealed_payload: SealedInvitePayloadV1 {
                v: 1,
                ciphertext_b64: BASE64URL_NOPAD.encode(b"ciphertext"),
                recipient_sealing_public_key_b64: BASE64URL_NOPAD.encode(sealing_pub),
                aad_schema_version: 1,
                plaintext_counts: SealedInvitePlaintextCounts::default(),
            },
        }
    }

    fn sign_payload(
        signing_key: &ed25519_dalek::SigningKey,
        payload: &InvitePayload,
    ) -> SignedInvite {
        use ed25519_dalek::Signer;

        let payload_json = serde_json::to_vec(payload).unwrap();
        let mut message = INVITE_DOMAIN.to_vec();
        message.extend_from_slice(&payload_json);
        let sig: ed25519_dalek::Signature = signing_key.sign(&message);

        SignedInvite {
            payload: payload.clone(),
            signature: BASE64URL_NOPAD.encode(&sig.to_bytes()),
        }
    }

    #[test]
    fn device_fingerprint_v1_is_deterministic() {
        let signing = [0x11_u8; 32];
        let sealing = [0x22_u8; 32];
        let fp1 = device_fingerprint_v1(&signing, &sealing);
        let fp2 = device_fingerprint_v1(&signing, &sealing);
        assert_eq!(fp1, fp2);
        assert_ne!(fp1, [0_u8; 32]);
    }

    #[test]
    fn device_fingerprint_v1_differs_across_key_pairs() {
        let fp_a = device_fingerprint_v1(&[0x11_u8; 32], &[0x22_u8; 32]);
        let fp_b = device_fingerprint_v1(&[0x33_u8; 32], &[0x44_u8; 32]);
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn fingerprint_hex_is_lowercase_64_chars() {
        let bytes = [0xab_u8; 32];
        let hex = fingerprint_hex(&bytes);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn encode_decode_round_trips() {
        let sk = make_signing_key();
        let sealing = [0x77_u8; 32];
        let payload = make_payload(&sk, &sealing);
        let invite = sign_payload(&sk, &payload);

        let encoded = invite.encode().unwrap();
        assert!(encoded.starts_with(INVITE_PREFIX));

        let decoded = SignedInvite::decode(&encoded).unwrap();
        assert_eq!(decoded, invite);
    }

    #[test]
    fn decode_rejects_wrong_prefix() {
        let err = SignedInvite::decode("lkinvite2_AAAA").unwrap_err();
        assert!(matches!(err, InviteDecodeError::WrongPrefix));
    }

    #[test]
    fn decode_rejects_invalid_base64() {
        let err = SignedInvite::decode("lkinvite1_!!!!").unwrap_err();
        assert!(matches!(err, InviteDecodeError::Base64));
    }

    #[test]
    fn verify_accepts_correctly_signed_invite() {
        let sk = make_signing_key();
        let sealing = [0x77_u8; 32];
        let payload = make_payload(&sk, &sealing);
        let invite = sign_payload(&sk, &payload);
        assert!(invite.verify().is_ok());
    }

    #[test]
    fn verify_rejects_wrong_signing_key() {
        let sk = make_signing_key();
        let sk2 = ed25519_dalek::SigningKey::from_bytes(&[0x99_u8; 32]);
        let sealing = [0x77_u8; 32];
        let payload = make_payload(&sk, &sealing);
        let mut invite = sign_payload(&sk, &payload);
        // Replace issuer signing key with a different key (payload still signed by sk)
        invite.payload.issuer_signing_public_key =
            BASE64URL_NOPAD.encode(&sk2.verifying_key().to_bytes());
        assert!(matches!(invite.verify(), Err(InviteVerifyError::InvalidSignature)));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let sk = make_signing_key();
        let sealing = [0x77_u8; 32];
        let payload = make_payload(&sk, &sealing);
        let mut invite = sign_payload(&sk, &payload);
        // Flip one byte in the signature base64
        let mut sig_bytes = BASE64URL_NOPAD.decode(invite.signature.as_bytes()).unwrap();
        sig_bytes[0] ^= 0xFF;
        invite.signature = BASE64URL_NOPAD.encode(&sig_bytes);
        assert!(matches!(invite.verify(), Err(InviteVerifyError::InvalidSignature)));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let sk = make_signing_key();
        let sealing = [0x77_u8; 32];
        let payload = make_payload(&sk, &sealing);
        let mut invite = sign_payload(&sk, &payload);
        // Change role after signing
        invite.payload.role = TeamRole::Owner;
        assert!(matches!(invite.verify(), Err(InviteVerifyError::InvalidSignature)));
    }

    #[test]
    fn team_role_serde_uses_snake_case() {
        assert_eq!(serde_json::to_string(&TeamRole::ReadOnly).unwrap(), "\"read_only\"");
        assert_eq!(serde_json::from_str::<TeamRole>("\"read_only\"").unwrap(), TeamRole::ReadOnly);
    }

    fn invite_with_expiry(expires_at: i64) -> SignedInvite {
        let sk = make_signing_key();
        let sealing = [0x77_u8; 32];
        let mut payload = make_payload(&sk, &sealing);
        payload.expires_at = expires_at;
        sign_payload(&sk, &payload)
    }

    #[test]
    fn check_expiry_accepts_now_before_expires_at() {
        let invite = invite_with_expiry(2_000);
        assert!(invite.check_expiry(1_500).is_ok());
    }

    #[test]
    fn check_expiry_accepts_now_at_expires_at() {
        let invite = invite_with_expiry(2_000);
        assert!(invite.check_expiry(2_000).is_ok());
    }

    #[test]
    fn check_expiry_accepts_full_skew_window() {
        let invite = invite_with_expiry(2_000);
        assert!(invite.check_expiry(2_000 + INVITE_CLOCK_SKEW_SECONDS).is_ok());
    }

    #[test]
    fn check_expiry_rejects_one_second_past_skew_window() -> Result<(), &'static str> {
        let invite = invite_with_expiry(2_000);
        let outside = 2_000 + INVITE_CLOCK_SKEW_SECONDS + 1;
        let Err(InviteExpiryError::Expired { expires_at, expired_seconds, skew_seconds }) =
            invite.check_expiry(outside)
        else {
            return Err("expected Expired");
        };
        assert_eq!(expires_at, 2_000);
        assert_eq!(expired_seconds, INVITE_CLOCK_SKEW_SECONDS + 1);
        assert_eq!(skew_seconds, INVITE_CLOCK_SKEW_SECONDS);
        Ok(())
    }

    #[test]
    fn invite_clock_skew_seconds_matches_spec_5_minutes() {
        assert_eq!(INVITE_CLOCK_SKEW_SECONDS, 300);
    }

    #[test]
    fn check_expiry_handles_now_far_in_the_future_without_overflow() {
        let invite = invite_with_expiry(0);
        assert!(matches!(invite.check_expiry(i64::MAX), Err(InviteExpiryError::Expired { .. })));
    }

    fn make_sealed_payload() -> SealedInvitePayloadV1 {
        // Counts-only smoke-test fixture; no real ciphertext is bound
        // here because the apply path lands in a follow-up. The sole
        // contract under test today is that the field round-trips
        // through serde and is covered by the outer signature.
        SealedInvitePayloadV1 {
            v: 1,
            ciphertext_b64: BASE64URL_NOPAD.encode(b"dummy-ciphertext"),
            recipient_sealing_public_key_b64: BASE64URL_NOPAD.encode(&[0x77_u8; 32]),
            aad_schema_version: 1,
            plaintext_counts: SealedInvitePlaintextCounts {
                profile_key_count: 2,
                command_policy_count: 3,
                secret_metadata_count: 5,
            },
        }
    }

    #[test]
    fn invite_without_sealed_payload_is_rejected() {
        let sk = make_signing_key();
        let mut encoded = serde_json::to_value(make_payload(&sk, &[0x77_u8; 32])).unwrap();
        encoded.as_object_mut().unwrap().remove("sealed_payload");
        assert!(serde_json::from_value::<InvitePayload>(encoded).is_err());
    }

    #[test]
    fn invite_with_sealed_payload_round_trips_and_is_signature_covered() {
        // When the issuer populates sealed_payload, the field MUST be
        // covered by the outer Ed25519 signature: tampering with any
        // sealed_payload field after signing flips verify() to error.
        let sk = make_signing_key();
        let sealing = [0x77_u8; 32];
        let mut payload = make_payload(&sk, &sealing);
        payload.sealed_payload = make_sealed_payload();
        let invite = sign_payload(&sk, &payload);

        assert!(invite.verify().is_ok());

        // Encode/decode round-trip preserves the sealed payload bytes.
        let encoded = invite.encode().unwrap();
        let decoded = SignedInvite::decode(&encoded).unwrap();
        assert_eq!(decoded, invite);
        assert_eq!(decoded.payload.sealed_payload, payload.sealed_payload);

        // Tamper test: flip a byte in the inner ciphertext after
        // signing; the outer signature must reject it.
        let mut tampered = invite.clone();
        let inner = &mut tampered.payload.sealed_payload;
        let mut ct = BASE64URL_NOPAD.decode(inner.ciphertext_b64.as_bytes()).unwrap();
        ct[0] ^= 0xFF;
        inner.ciphertext_b64 = BASE64URL_NOPAD.encode(&ct);
        assert!(matches!(tampered.verify(), Err(InviteVerifyError::InvalidSignature)));

        // Swapping in a different sealed payload after signing must also fail.
        let mut swapped = invite;
        swapped.payload.sealed_payload.plaintext_counts.profile_key_count += 1;
        assert!(matches!(swapped.verify(), Err(InviteVerifyError::InvalidSignature)));
    }
}
