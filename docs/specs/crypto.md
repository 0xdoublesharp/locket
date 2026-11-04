# Crypto, Key Management & User Verification

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Crypto & Key Management

Algorithms:

- AEAD: `XChaCha20-Poly1305`
- KDF: `Argon2id`
- RNG: `rand::rngs::OsRng`
- Key derivation: HKDF where subkeys are needed
- Fingerprints: profile-scoped HMAC-SHA256 of secret values
- Audit integrity: HMAC chain with a separate audit key
- Memory handling: `zeroize` and `secrecy`
- Device identity: Ed25519 for invite/export signatures and age-compatible X25519 recipients for sealing bundles
- Local user verification: platform biometric/presence APIs plus optional FIDO2/CTAP2 hardware-key presence

Cryptographic choices must use maintained RustCrypto, dalek, age/rage, or similarly reviewed implementations. The app must not introduce custom cryptographic primitives, custom KEMs, custom password hashing, or bespoke authenticated-encryption compositions.

Key hierarchy:

```text
Local Project Master Key (OS protected or recovered, project scoped)
  -> HKDF key-wrap keys by project id and key purpose
    -> Wrapped random Project Metadata Key
    -> Wrapped random Project Audit Key
    -> Wrapped random Profile Secret Key per profile
    -> Wrapped random Profile Fingerprint Key per profile
  -> HKDF key-wrap keys by global secret path and secret key id
    -> Wrapped random Secret/Data Encryption Key per secret version
  -> Profile Secret Key
    -> Secret/Data Encryption Key
  -> Profile Fingerprint Key
  -> Project Audit Key
```

Each project currently has its own local master key and device identity. `locket init` creates a new master key for a new project and reuses the existing key when completing that same project. Recovery is also per project: back up each project's encrypted `.locket/recovery/envelope.bin` and its recovery code. A code for one project does not recover another project. Project metadata, project audit, profile secret, and profile fingerprint keys are random 32-byte keys stored only as wrapped material in the `keys` table. They are not deterministically derived from the master key. HKDF is used to derive purpose-separated wrapping keys from the master key, so wrapped keys can be independently rotated and audited without making one project/profile key substitutable for another.

Global reusable secrets are addressed by canonical absolute secret paths such as `/work/acme/aws/dev/db-password`. A global secret has its own random secret key id and per-version DEK; projects consume that secret through links/aliases and policy grants rather than by copying private key material or duplicating encrypted values. Project-local secrets remain supported for values that should not leave a project boundary.

HKDF wrap info v1:

```text
hkdf_wrap_info_v1 =
  "locket-wrap-v1" ASCII bytes
  u16_le(wrap_info_schema_version = 1)
  field("scope", "project" or "secret")
  field("project_id", project_id or "")
  field("secret_path", canonical_secret_path or "")
  field("secret_key_id", secret_key_id or "")
  field("profile_id", profile_id or "")
  field("purpose", key_purpose)
```

`profile_id` is the empty string only for project-scoped keys. `project_id` is empty only for identity-scoped global secret wraps. `secret_path` and `secret_key_id` are empty for project/profile keys and set for global reusable secret keys. `key_purpose` is one of the canonical persisted purpose strings used by `keys.purpose`: `project-metadata`, `project-audit`, `profile-secret`, `profile-fingerprint`, or `global-secret`. The Rust `KeyPurpose::Audit` variant serializes as `project-audit`. The `field(name, value)` helper uses the length-prefixed UTF-8 encoding defined for canonical AAD v1. HKDF info construction must never use raw concatenation, delimiters, JSON, TOML, or locale-sensitive encoding.

Profile key boundary:

- Secret values are encrypted under per-version DEKs; each DEK is wrapped by the active profile's `ProfileSecret` key, not by a project-wide secret key.
- Known-value scan fingerprints use the active profile's `ProfileFingerprint` key, not a project-wide fingerprint key.
- The project audit key signs the local audit chain and is not sufficient to decrypt secret values.
- Profile-scoped team invites and sealed bundles include only the selected profiles' `ProfileSecret` and `ProfileFingerprint` keys inside the encrypted bundle payload. Granting `dev` must not provide cryptographic access to `prod`.

Secret value encoding:

- v1 secret values are UTF-8 strings for environment-variable compatibility.
- NUL bytes are forbidden because OS environment variables cannot safely carry them.
- Multiline values are rejected by default in `set` and `import`; a future explicit multiline delivery mode may support them without changing the default env-injection contract.
- Docker, Compose, `exec`, `redact`, and scan paths must treat values as bytes after UTF-8 validation and must never perform locale-dependent normalization.

Encryption flow:

```text
secret value
  -> generate random DEK
  -> encrypt secret with DEK
  -> encrypt DEK with profile secret key
  -> store encrypted blob and encrypted DEK metadata
  -> store keyed fingerprint for the version
  -> append audit row with chained HMAC
```

AAD must bind ciphertext to at least project id, profile id, secret id, secret name, and version. AAD is re-derived deterministically from canonical metadata and the blob's AAD schema version; it is not read from a mutable database field. Renaming or moving a blob across projects/profiles must fail decryption.

AEAD nonce layout:

- `SecretBlob.value_nonce` is used only for encrypting the UTF-8 secret value with the per-version DEK.
- The DEK wrap uses a separate 24-byte nonce embedded as the first bytes of `SecretBlob.encrypted_dek`: `wrap_nonce || wrap_ciphertext`.
- Decryption code must split `encrypted_dek` before unwrapping the DEK. Reusing `value_nonce` for the DEK wrap is forbidden.

Key wrap v1:

```text
key_wrap_v1 =
  wrap_nonce: 24 random bytes
  wrap_ciphertext: XChaCha20-Poly1305(
    key = profile_secret_key or HKDF-derived wrapping key,
    nonce = wrap_nonce,
    plaintext = key material,
    aad = key_wrap_aad_v1
  )

key_wrap_aad_v1 =
  "locket-key-wrap-v1" ASCII bytes
  field("project_id", project_id)
  field("key_id", key_id or secret_id)
  field("profile_id", profile_id or "")
  u32_le(version or 0)
  field("purpose", key purpose or "secret-dek")
  u16_le(wrap_schema_version = 1)
```

Stored key-wrap layouts are intentionally different:

- `SecretBlob.encrypted_dek = wrap_nonce || wrap_ciphertext` because there is no separate nonce column for per-version DEK wraps.
- `keys.wrapped_material = wrap_ciphertext` and `keys.nonce = wrap_nonce` for wrapped project/profile keys.

The `field(name, value)` helper uses the same length-prefixed UTF-8 encoding defined for canonical AAD v1 below.

KDF parameters:

- Recovery envelope Argon2id parameters: memory `m=65536 KiB`, iterations `t=3`, parallelism `p=4`.
- Passphrase fallback Argon2id parameters: memory `m=32768 KiB`, iterations `t=2`, parallelism `p=4`.
- Recovery KDF metadata uses the following canonical TOML key names (embedded in the atomic envelope container, or stored in `recovery/kdf.toml` for legacy backups): `kdf_profile_id` (string, `lk_kdf_*` prefix), `algorithm` (string, `"argon2id"` for v1), `version` (integer, schema version of this file, `1` for v1), `salt` (string, unpadded base64url), `m_cost` (integer, memory in KiB), `t_cost` (integer, iterations), `p_cost` (integer, parallelism), `output_len` (integer, derived key length in bytes, `32` for v1), and `created_at` (integer, UTC Unix nanoseconds as `i64`). These names are normative; implementations must use them exactly for recovery interoperability. `kdf_profile_id` is an opaque random 128-bit id with prefix `lk_kdf_`, generated for each recovery envelope creation or recovery-code rotation. It is not derived from the recovery code, salt, device id, or project id. `kdf_profile_id` must match the id stored in `recovery/envelope.bin`; mismatch means the KDF metadata and envelope are not a valid pair and recovery fails closed.
- Recovery envelope re-wraps may upgrade KDF parameters but must never silently downgrade them. If the running binary cannot meet stored parameters, recovery fails closed with a typed error rather than using weaker parameters.
- Stored KDF parameters are authoritative for future recovery; the binary default is used only for new envelopes or explicit upgrades.

Canonical AAD v1:

```text
aad_v1 =
  "locket-aad-v1" ASCII bytes
  u16_le(aad_schema_version = 1)
  field("project_id", project_id)
  field("profile_id", profile_id)
  field("secret_id", secret_id)
  field("secret_name", secret_name)
  u32_le(version)

field(name, value) =
  u16_le(byte_len(name)) || UTF-8(name) ||
  u32_le(byte_len(value)) || UTF-8(value)
```

Opaque IDs are encoded as their canonical prefixed UTF-8 string form. `secret_name` is encoded exactly after validation and before any display transformation. Integers are little-endian. No JSON, TOML, locale-aware case folding, path normalization, or map ordering is involved in AAD. Any future field or encoding change must increment `aad_schema_version`.

OS key integration:

| OS | Backend |
| --- | --- |
| macOS | Keychain |
| Windows | Credential Manager / DPAPI-backed keyring |
| Linux | Secret Service |

Use a cross-platform `keyring` crate initially, wrapped behind a `locket-platform` trait. Provide an Argon2 passphrase fallback where OS key storage is unavailable.

Passphrase fallback must store only salt and KDF parameters, never a reusable verifier that can reveal the master key. KDF parameters must be recorded so they can be upgraded over time.

Recovery code model:

- Locket has one recovery secret: the recovery code.
- The recovery code is displayed once during initialization as exactly 160 random bits encoded as 32 Crockford Base32 data characters plus 2 checksum characters, grouped for paper entry. The checksum detects transcription errors; it does not add security entropy.
- The recovery code derives a recovery unwrap key with Argon2id and stored salt/KDF parameters.
- The local recovery envelope contains wrapped master key material and the local device private key material needed to import bundles addressed to that device.
- `locket recover` restores the OS keychain entry for the master key and the OS keychain-backed local device private key material from the recovery envelope.
- Sealed bundles require the recipient device private key to import. If that private key is lost, the recovery code can restore it only when the local recovery envelope is present; otherwise the user needs another trusted device or a fresh team invite.

Recovery envelope v1:

- New `recovery/envelope.bin` files contain the ASCII magic `LOCKET-RECOVERY-STATE-V1` followed by a NUL byte, a `u32` little-endian TOML byte length, that many bytes of KDF TOML, then the recovery envelope described below. Both parts are replaced through one synced temporary file and atomic rename. Embedded KDF metadata is authoritative; a remaining legacy `kdf.toml` is ignored by readers. Legacy raw envelopes plus `kdf.toml` remain readable.
- The inner recovery envelope is a versioned binary container. All integers are little-endian and all strings are UTF-8 length-prefixed.
- Header: magic bytes `LOCKET-RECOVERY\0`, `u16 schema_version = 1`, `field("kdf_profile_id", id)`, `i128 created_at_unix_nanos_utc`, `u32 entry_count`.
- Entry: `field("entry_kind", kind)`, `field("entry_id", id)`, `u16 algorithm_id`, `u16 nonce_len = 24`, `nonce`, `u32 ciphertext_len`, `ciphertext`.
- `algorithm_id = 1` means XChaCha20-Poly1305.
- The recovery unwrap root is `Argon2id(recovery_code, stored KDF salt, stored params)`.
- Each entry encryption key is `HKDF-SHA256(recovery_unwrap_root, info = "locket-recovery-entry-v1" || field("entry_kind", entry_kind) || field("entry_id", entry_id) || field("kdf_profile_id", kdf_profile_id))`.
- Each entry AAD is `locket-recovery-envelope-v1 || u16_le(schema_version) || field("kdf_profile_id", kdf_profile_id) || field("entry_kind", entry_kind) || field("entry_id", entry_id)`.
- Required wrapped entries are `master_key`, `device_signing_private_key`, and `device_sealing_private_key`; Locket-managed automation client private keys may be included as `automation_client_private_key:<client_id>` entries.
- `locket client create` with `--storage os-keychain` or `--storage wrapped-local-file` writes the client private key wrap into the recovery envelope during creation. `locket recovery rotate` re-wraps all active managed client private keys under the new recovery code in the same atomic replacement as the master and device key wraps; revoked clients are omitted from the new envelope.
- Externally managed automation client keys are not represented in the recovery envelope and are never recovered by Locket.

Passkey and local user-verification model:

- General user-presence gates use macOS LocalAuthentication.framework and Windows Hello user-consent APIs. Linux gates currently fail closed: access to an unlocked Secret Service collection does not prove fresh consent. Ordinary keyring storage and passphrase vault unlock remain supported.
- CTAP2/FIDO2 user-presence/user-verification approval gates require a real authenticator integration; the current Linux hardware-key feature does not provide one.
- Browser-style WebAuthn/passkey ceremonies are not the default path for local CLI/UI user presence because they add browser/RP ceremony without improving the local approval primitive.
- WebAuthn PRF/hmac-secret is allowed only as an optional key-wrapping factor when a hardware token or platform authenticator supports it. Recovery code support remains mandatory because PRF availability and synced-passkey behavior vary by platform.
- Local user-verification gates can protect unlock, reveal/copy, dangerous-profile switching, team invite acceptance, device registration, and recovery operations.
- Genuine authenticators must keep their private material outside Locket. Legacy `platform-keyring` credentials instead use software seeds held in the OS keyring; they are explicitly identified as legacy software recovery factors.
- Local user verification does not replace peer-credential checks for the local agent and does not bypass policy, grants, audit, or team roles.
- Registration, removal, and authentication write audit rows when project context is available.

Component checks:

- Decryption fails with wrong key, nonce, AAD, project, profile, secret id, secret name, or version.
- Fingerprints are keyed HMACs, not raw hashes.
- Audit verification detects breaks, insertion, reordering, or mutation in the retained chain. A valid prefix remains valid: tail truncation or whole-database rollback requires an independently retained checkpoint to detect.

## Local User Verification And Passkeys

Local user verification is the default approval layer for sensitive Locket actions. It must use platform presence APIs, not browser-style WebAuthn ceremonies.

Default approval paths:

- macOS: LocalAuthentication.framework.
- Windows: Windows Hello user-consent APIs.
- Linux: fresh current-user polkit authentication with the packaged non-caching policy; Secret Service access alone is not accepted.
- Hardware keys: optional PRF key wrapping through the terminal FIDO2 backend below. Ordinary approval gates continue to use the OS verifier.

Protected use cases:

- Unlocking the vault with local user verification.
- Requiring presence/verification before reveal, copy, recovery, dangerous-profile switch, team invite acceptance, or device registration.
- Strengthening team trust ceremonies by requiring local presence at invite acceptance or device registration.
- Optionally using WebAuthn PRF/hmac-secret as an additional key-wrapping factor when a supported authenticator is explicitly registered.

Rules:

- Local user verification never replaces recovery codes.
- Local user verification never bypasses project/profile policy, grants, team roles, or audit logging.
- Production binaries ignore `LOCKET_TEST_LOCAL_AUTH`; test overrides are compiled only into unit tests.
- New external-key registration uses libfido2 1.17+ tools on macOS/Linux terminals, requiring a PIN, user presence, and hmac-secret support. Desktop/non-terminal and Windows ceremonies fail explicitly. It must not generate software keyring seeds and describe them as WebAuthn PRF credentials.
- Credential attestation and assertion signatures must verify before accepting credential metadata or PRF output. Assertions bind a fresh challenge, the stored RP ID, and the stored public key, with both UP and UV required. Optional key wrapping uses the WebAuthn PRF salt transformation `SHA-256("WebAuthn PRF" || 0x00 || input)` before requesting CTAP hmac-secret output.
- Registration completes the PRF ceremony before atomically storing the credential, master-key wrap, and successful audit row. Cancellation, verification failure, or a failed database write must not leave a partially enrolled credential.
- Existing `platform-keyring` records remain readable through an explicitly labeled legacy recovery path after fresh local verification. Their seed derivation remains compatible; key material is zeroized after use. These credentials are not an independent hardware factor or an RP-bound WebAuthn ceremony.
- Genuine biometric and authenticator private material must never be stored by Locket.
- Browser-style WebAuthn/passkey ceremonies are not used for ordinary reveal/copy/unlock approvals. They may be used only for optional PRF/hmac-secret key-wrapping flows that require a WebAuthn-compatible authenticator.
- For optional WebAuthn PRF credentials, the relying party id must be recorded in `PasskeyCredential.webauthn_relying_party_id` and must never change silently. The default RP ID for that optional path is `locket.localhost`; official signed distributions may define a controlled RP ID only as an explicit migration requiring credential re-registration.
- Synced passkeys are not accepted as a sole recovery or trust root. If a platform exposes backup eligibility/state, Locket must display it so teams can decide whether synced credentials are acceptable as an extra approval factor under current NIST syncable-authenticator guidance.
- Authenticator metadata is safe metadata, but credential ids and public keys should not be printed unless explicitly requested.
