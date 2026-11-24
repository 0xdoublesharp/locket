# Data Model

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Data Model

All IDs are opaque and prefix-based:

```text
lk_proj_*
lk_sec_*
lk_prof_*
lk_key_*
lk_dev_*
lk_grant_*
lk_team_*
lk_member_*
lk_invite_*
lk_passkey_*
lk_client_*
lk_session_*
lk_kdf_*
```

`Timestamp` is an `i64` of UTC Unix nanoseconds (signed; negative values represent pre-epoch instants). SQLite stores it as `INTEGER`. The audit HMAC canonical bytes encode the same value as `i128_le` — the upper 64 bits are the sign extension of the `i64` — so the wire format is forward-compatible if precision is ever extended without changing v1 row semantics.

`Duration` is `std::time::Duration` in Rust, serialized in TOML/config/CLI as a quoted duration string matching `^[1-9][0-9]*(s|m|h|d|w)$`. Units are seconds, minutes, hours, days, and weeks. Compound values (`1h30m`), fractional values (`1.5h`), zero (`0s`), negative values, uppercase units, and whitespace are invalid. SQLite stores normalized durations as unsigned integer seconds. Rendering back to TOML should preserve the user's original string when available; otherwise render the largest exact unit. Field-specific caps such as `rotation.max_grace_ttl` are enforced after parsing.

Primary domain types:

```rust
struct Project {
    id: ProjectId,
    name: String,
    trusted_root_hashes: Vec<[u8; 32]>,
    key_ids: ProjectKeySet,
    user_verification_policy: UserVerificationPolicy,
    created_at: Timestamp,
    profiles: Vec<ProfileId>,
}

struct ProjectKeySet {
    project_metadata_key_id: KeyId,
    audit_key_id: KeyId,
}

// In-memory model for the KDF metadata embedded in recovery/envelope.bin;
// KDF profiles are not persisted in SQLite.
struct KdfProfile {
    id: KdfProfileId,
    algorithm: String, // "argon2id" for v1
    salt: Vec<u8>,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: u32,
    created_at: Timestamp,
}

struct ProfileKeySet {
    secret_key_id: KeyId,
    fingerprint_key_id: KeyId,
}

struct Profile {
    id: ProfileId,
    project_id: ProjectId,
    name: String,
    key_ids: ProfileKeySet,
    dangerous: bool,
    created_at: Timestamp,
}

struct SecretMeta {
    id: SecretId,
    project_id: ProjectId,
    profile_id: ProfileId,
    name: String,
    description: Option<String>,
    owner: Option<String>,
    source: SecretSource,
    origin: SecretOrigin,
    tags: Vec<String>,
    required: bool,
    current_version: u32,
    state: SecretState,
    created_at: Timestamp,
    updated_at: Timestamp,
    last_rotated_at: Option<Timestamp>,
    deleted_at: Option<Timestamp>,
}

enum SecretSource {
    TeamManaged,
    UserLocal,
    MachineLocal,
}

enum SecretOrigin {
    Manual,
    Imported,
    TeamAccept,
    ProfileCopy,
}

enum SecretState {
    Active,
    Deleted,
}

struct SecretVersion {
    secret_id: SecretId,
    version: u32,
    source: SecretSource,
    origin: SecretOrigin,
    state: SecretVersionState,
    created_at: Timestamp,
    deprecated_at: Option<Timestamp>,
    grace_until: Option<Timestamp>,
    purged_at: Option<Timestamp>,
}

enum SecretVersionState {
    Current,
    Deprecated,
    Purged,
}

struct SecretBlob {
    secret_id: SecretId,
    version: u32,
    encrypted_dek: Vec<u8>, // wrap_nonce || wrap_ciphertext, using key_wrap_v1
    ciphertext: Vec<u8>,
    value_nonce: [u8; 24],
    aad_schema_version: u16,
    created_at: Timestamp,
}

struct CommandPolicy {
    name: String, // derived from the [commands.<name>] table key; not serialized in the table body
    command: CommandSpec,
    allowed_secrets: Vec<String>,
    required_secrets: Vec<String>,
    optional_secrets: Vec<String>,
    inherit_env: Vec<String>,
    env_mode: EnvMode,
    override_behavior: EnvOverrideMode, // serde field name is "override"
    external_env_sources: Vec<ExternalEnvSource>,
    allow_remote_docker: bool,
    confirm: bool,
    require_user_verification: bool,
    require_agent: bool,
    ttl: Option<Duration>,
}

struct SecretAccessPolicy {
    name: String, // derived from the [secrets.<NAME>] table key; not serialized in the table body
    allow_commands: Vec<String>, // command identity globs, e.g. "dev" or "npm:*"
    allow_argv: Vec<Vec<String>>, // structured argv token patterns; "*" is token-local, "**" matches argv tail
    allow_paths: Vec<String>, // project-relative path or subtree patterns
}

struct UserVerificationPolicy {
    unlock: bool,
    reveal: bool,
    copy: bool,
    dangerous_profile_switch: bool,
    recovery: bool,
    team_accept: bool,
    device_register: bool,
}

enum CommandSpec {
    Argv(Vec<String>),
    Shell(String),
}

enum EnvMode {
    Strict,
    Minimal,
    Merge,
    Passthrough,
}

enum EnvOverrideMode {
    Locket,
    Preserve,
    Error,
}

enum ExternalEnvSource {
    Parent,
    File(PathBuf),
    Compose,
    Ide, // resolved by a VS Code terminal session id published through LOCKET_IDE_ENV_SESSION
}

// In-memory agent type only. Never serialized to SQLite, written to
// config.toml, stored in shell hook files, or persisted as a token.
struct Grant {
    id: GrantId,
    project_id: ProjectId,
    profile_id: ProfileId,
    directory_hash: Option<[u8; 32]>,
    process_id: Option<u32>,
    process_start_time: Option<Timestamp>,
    shell_session_id: Option<String>,
    allowed_actions: Vec<GrantAction>,
    issued_at: Timestamp,
    expires_at: Timestamp,
}

struct AgentEnvelope<T> {
    v: u16,
    id: String,
    kind: String,
    payload: T,
}

struct AgentErrorEnvelope {
    v: u16,
    id: String,
    error: String,
    message: String,
    retryable: bool,
}

struct DirectoryGrant {
    project_id: ProjectId,
    profile_id: ProfileId,
    directory_hash: [u8; 32],
    granted_by: Option<MemberId>,
    created_at: Timestamp,
    revoked_at: Option<Timestamp>,
}

struct Team {
    id: TeamId,
    project_id: ProjectId,
    name: String,
    created_at: Timestamp,
}

struct TeamMember {
    id: MemberId,
    team_id: TeamId,
    display_name: String,
    role: TeamRole,
    trusted_devices: Vec<DeviceId>,
    created_at: Timestamp,
    removed_at: Option<Timestamp>,
}

enum TeamRole {
    Owner,
    Maintainer,
    Developer,
    ReadOnly,
}

struct Device {
    id: DeviceId,
    member_id: Option<MemberId>,
    name: String,
    signing_public_key: Vec<u8>,    // Ed25519, used for invite and export signatures
    sealing_public_key: Vec<u8>,    // X25519, used as the recipient key for sealed bundles
    fingerprint: String,            // SHA-256 over the canonical concatenation of both public keys, hex-encoded
    label: String,
    created_at: Timestamp,
    last_seen_at: Option<Timestamp>,
    revoked_at: Option<Timestamp>,
}

struct PasskeyCredential {
    id: PasskeyCredentialId,
    device_id: DeviceId,
    member_id: Option<MemberId>,
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    webauthn_relying_party_id: Option<String>, // present only for optional WebAuthn PRF/hmac-secret credentials
    // Random 32-byte opaque handle generated at registration time for
    // WebAuthn-compatible credentials. It is stable for this credential,
    // never derived from member_id/device_id/email, and not printed by default.
    user_handle: Vec<u8>,
    label: String,
    transports: Vec<String>,
    backup_eligible: bool,
    backup_state: bool,
    created_at: Timestamp,
    last_used_at: Option<Timestamp>,
    revoked_at: Option<Timestamp>,
}

// user_handle is never shown through CLI, UI, debug bundles, logs, or
// audit metadata. v1 intentionally provides no flag to reveal it; it
// exists only for authenticator protocol compatibility and local lookup.

struct AutomationClient {
    id: ClientId,
    project_id: ProjectId,
    name: String,
    public_key: Vec<u8>, // Ed25519 signing public key for challenge-response authentication
    fingerprint: String,
    // v1 automation clients may contain only RunPolicy, ResolveReference,
    // ScanKnownValues, and Redact. PrepareExec is agent-internal through
    // RunPolicy; SetSecret, Reveal, Copy, and Export are human-gated in v1. Client
    // registration, bundle import, and policy-index refresh must reject
    // excluded variants.
    allowed_actions: Vec<GrantAction>,
    allowed_policies: Vec<String>,
    created_at: Timestamp,
    last_used_at: Option<Timestamp>,
    revoked_at: Option<Timestamp>,
}

struct AutomationClientNonce {
    client_id: ClientId,
    nonce: [u8; 24], // agent-issued challenge nonce, not a client-generated nonce
    request_timestamp: Timestamp,
    seen_at: Timestamp,
    expires_at: Timestamp,
}

struct AutomationClientPrivateKeyRef {
    client_id: ClientId,
    storage: ClientPrivateKeyStorage,
    created_at: Timestamp,
}

enum ClientPrivateKeyStorage {
    External,
    OsKeychain,
    WrappedLocalFile(PathBuf),
}

struct TeamInvite {
    id: InviteId,
    team_id: TeamId,
    project_id: ProjectId,
    recipient_device_sealing_public_key: Vec<u8>,
    issuer_member_id: MemberId,
    issuer_device_id: DeviceId,
    issuer_signature: Vec<u8>,
    nonce: [u8; 24],
    profiles: Vec<ProfileId>,
    role: TeamRole,
    expires_at: Timestamp,
    accepted_at: Option<Timestamp>,
    revoked_at: Option<Timestamp>,
}

struct SecretFingerprint {
    secret_id: SecretId,
    version: u32,
    hmac: [u8; 32],
    created_at: Timestamp,
}

struct Key {
    id: KeyId,
    project_id: ProjectId,
    profile_id: Option<ProfileId>,
    purpose: KeyPurpose,
    wrapped_material: Vec<u8>,
    nonce: [u8; 24],
    created_at: Timestamp,
}

enum KeyPurpose {
    ProjectMetadata,
    ProfileSecret,
    ProfileFingerprint,
    Audit,
}

// KeyPurpose serializes to the persisted/wire strings
// project-metadata, profile-secret, profile-fingerprint, and project-audit.
// The Rust variant remains Audit, but the canonical string is project-audit
// everywhere it appears in storage, HKDF info, manifests, and audit metadata.

struct RuntimeSession {
    id: SessionId,
    project_id: ProjectId,
    profile_id: ProfileId,
    policy_name: Option<String>,
    process_id: u32,
    process_start_time: Timestamp,
    started_at: Timestamp,
    ended_at: Option<Timestamp>,
    exit_status: Option<i32>,
    secret_names: Vec<String>, // sensitive metadata; pruned according to runtime.session_secret_name_retention
}

enum GrantAction {
    RunPolicy,
    PrepareExec,
    ResolveReference,
    ScanKnownValues,
    Reveal,
    Copy,
    Redact,
    Export,
    SetSecret,
}
```

All `*Id` types (`ProjectId`, `ProfileId`, `SecretId`, `KeyId`, `DeviceId`, `MemberId`, `TeamId`, `InviteId`, `GrantId`, `SessionId`, `PasskeyCredentialId`, `ClientId`, `KdfProfileId`) are newtype wrappers around the opaque prefixed strings listed above. They are validated on construction and not interchangeable with raw `String` in public APIs.

`Action` and `AuditStatus` are Rust enums whose variants are exactly the text-listed values below. The `metadata_json` field on `AuditLog` is a serialized JSON document (stored as `TEXT` in SQLite) with a documented per-action shape, parsed into typed structures in memory. The shape must never include plaintext secret values, and a single audit row's serialized metadata must not exceed 64 KiB.

Audit model:

```rust
struct AuditLog {
    sequence: u64,
    hmac_schema_version: u16, // audit HMAC algorithm version; v1 rows always write 1
    timestamp: Timestamp,
    project_id: Option<ProjectId>,
    profile_id: Option<ProfileId>,
    action: Action,
    status: AuditStatus,
    secret_name: Option<String>,
    command: Option<String>,
    metadata_json: Option<serde_json::Value>,
    prev_hmac: [u8; 32],
    hmac: [u8; 32],
}

struct ImportedAuditChain {
    id: String,
    project_id: ProjectId,
    source_device_fingerprint: String,
    bundle_digest: Vec<u8>,
    checkpoint_sequence: u64,
    checkpoint_hmac: [u8; 32],
    encrypted_rows_nonce: [u8; 24],
    encrypted_rows: Vec<u8>,
    aad_schema_version: u16,
    imported_at: Timestamp,
}
```

Audit metadata must never contain plaintext secret values.

Audit actions:

```text
SET
GET
EXEC
RUN
DELETE
PURGE
SECRET_META_UPDATE
IMPORT
ROTATE
REVEAL
COPY
SECRET_COPY
SCAN
REDACT
PROFILE_CREATE
PROFILE_CHANGE
TRUST_ROOT
ALLOW_DIRECTORY
DENY_DIRECTORY
AGENT_GRANT
BACKUP_EXPORT
BACKUP_IMPORT
RECOVER
RECOVERY_ROTATE
TEAM_INIT
TEAM_INVITE
TEAM_ACCEPT
TEAM_REMOVE
DEVICE_ADD
DEVICE_REVOKE
PASSKEY_REGISTER
PASSKEY_REMOVE
PASSKEY_AUTH
CLIENT_ADD
CLIENT_REVOKE
CLIENT_AUTH
CONFIG_UPDATE
BOOTSTRAP
DOCTOR
LOCK
UNLOCK
AUDIT_VERIFY
HOOK_INSTALL
AGENT_REVOKE
GRANT_EXPIRED
BUNDLE_VERIFY
POLICY_UPDATE
EXAMPLE_EMIT
```

Audit status:

```text
SUCCESS
DENIED
FAILED
```

Typed errors:

```rust
enum LocketError {
    ProjectNotFound,
    ProjectRootNotTrusted,
    ProfileNotFound,
    SecretNotFound,
    SecretAlreadyExists,
    SecretDeleted,
    SecretConflict,
    InvalidSecretName,
    UnlockRequired,
    GrantRequired,
    AccessDenied,
    DecryptionFailed,
    StorageError,
    CryptoError,
    KeychainUnavailable,
    KeychainEntryMissing,
    RecoveryCodeUnavailable,
    LocalVaultUnrecoverable,
    AgentUnavailable,
    AgentSocketInUse,
    ConfigError,
    InvalidPolicy,
    InvalidReferenceUri,
    AuditIntegrityFailed,
    BackupRecoveryFailed,
    BundleConflict,
    BundleVerificationFailed,
    InviteExpired,
    DeviceNotTrusted,
    LocalUserVerificationRequired,
    LocalUserVerificationFailed,
    ClientNotTrusted,
    ClientReplayDetected,
    MemberNotFound,
    TeamPolicyViolation,
    UnsafeReveal,
    SecretVersionExpired,
}
```

## Secret Metadata And Ownership

Secrets must be understandable without revealing values.

Metadata fields:

- Description.
- Owner or responsible team/person.
- Source: team-managed, user-local, or machine-local.
- Origin: manual entry, `.env` import, team accept, or profile copy.
- Required/optional flag.
- Tags.
- Created/updated timestamps.
- Last rotated timestamp.
- Current version and state.

Secret metadata is not protected like secret values. Names, descriptions, owners, tags, sources, origins, profile names, and policy names can appear in local metadata surfaces and must not contain plaintext secret values, recovery codes, private keys, access tokens, or credential material. Metadata input paths (`set`, `rotate`, `meta`, import reports, policy editing, templates, team/member/device labels, and UI edits) must apply provider-token and high-entropy detection. Exact known-secret metadata matches are refused when the vault is unlocked and known-value matching is available; provider-shaped or high-entropy metadata is refused by default unless an explicit typed confirmation acknowledges that the field is metadata and may be visible locally. Control characters, NUL bytes, and terminal escape sequences are invalid in display metadata.

`SecretMeta.origin` is set once at creation and never updated. It records how the logical secret first entered the project: `Manual` (created by `locket set`), `Imported` (created by `locket import`), `TeamAccept` (created by `locket team accept` or `locket import-bundle`), or `ProfileCopy` (created by `locket copy`). `SecretVersion.origin` records how each individual version was created: `locket set` writes `Manual`; `locket import` and `--overwrite` rotation write `Imported`; `locket team accept` and `locket import-bundle` write `TeamAccept`; `locket copy` writes `ProfileCopy`.

List, history, diff, UI, and `.env.example` generation may show this metadata. Values remain hidden unless reveal/copy rules are satisfied.
