# Storage

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Storage

Default local layout:

```text
~/.locket/
  config.toml
  store.db
  agent.sock           (Unix; on Windows: \\.\pipe\locket-agent-<sid>)
  agent.pid
```

Use SQLite through `rusqlite`. Encrypted secret blobs live in the SQLite `blobs` table so metadata and ciphertext updates can be transactional. External blob directories are out of scope for this spec.

Each project stores recovery material under `<project>/.locket/recovery/`, outside the shared user store. Its `envelope.bin` contains the KDF metadata plus the encrypted master, device and managed automation-client keys. Keep an independent backup of this encrypted file and its recovery code. The directory must never contain plaintext keys, plaintext secrets, or the recovery code itself.

New recovery state embeds KDF TOML and the inner encrypted envelope in one `envelope.bin`, using the container specified in [crypto.md](crypto.md). Rotation syncs a new file, then atomically replaces the prior file. A crash cannot commit only one half of a pair. Legacy backups with separate `kdf.toml` and raw `envelope.bin` remain readable; for those backups both files are required. Any legacy `kdf.toml` beside a modern container is non-authoritative. KDF and inner envelope profile IDs must match or recovery fails closed. SQLite stores no recovery-code salt, recovery-code verifier, or recovery unwrap key.

Required tables:

```text
projects
project_roots
profiles
secrets
secret_versions
blobs
keys
devices
passkey_credentials
automation_clients
automation_client_private_key_refs
automation_client_nonces
teams
team_members
team_invites
command_policies
directory_grants
audit_log
imported_audit_chains
fingerprints
runtime_sessions
schema_migrations
```

Plaintext secret values must never be stored in SQLite, `config.toml`, generated files, app state, VS Code state, shell hook files, crash logs, or debug logs.

Minimum SQLite column definitions for security-critical tables:

```sql
CREATE TABLE project_roots (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  root_hash BLOB NOT NULL CHECK (length(root_hash) = 32),
  display_path TEXT,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  PRIMARY KEY (project_id, root_hash)
);

CREATE TABLE secret_versions (
  secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version >= 1 AND version <= 4294967295),
  source TEXT NOT NULL CHECK (source IN ('team-managed', 'user-local', 'machine-local')),
  origin TEXT NOT NULL CHECK (origin IN ('manual', 'imported', 'team-accept', 'profile-copy')),
  state TEXT NOT NULL CHECK (state IN ('current', 'deprecated', 'purged')),
  created_at INTEGER NOT NULL,
  deprecated_at INTEGER,
  grace_until INTEGER,
  purged_at INTEGER,
  PRIMARY KEY (secret_id, version)
);

CREATE TABLE blobs (
  secret_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  encrypted_dek BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  value_nonce BLOB NOT NULL CHECK (length(value_nonce) = 24),
  aad_schema_version INTEGER NOT NULL CHECK (aad_schema_version >= 1),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (secret_id, version),
  FOREIGN KEY (secret_id, version)
    REFERENCES secret_versions(secret_id, version)
    ON DELETE CASCADE
);

CREATE TABLE keys (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK (purpose IN ('project-metadata', 'project-audit', 'profile-secret', 'profile-fingerprint')),
  wrapped_material BLOB NOT NULL,
  nonce BLOB NOT NULL CHECK (length(nonce) = 24),
  created_at INTEGER NOT NULL,
  CHECK (
    (profile_id IS NULL AND purpose IN ('project-metadata', 'project-audit'))
    OR
    (profile_id IS NOT NULL AND purpose IN ('profile-secret', 'profile-fingerprint'))
  )
);

CREATE UNIQUE INDEX keys_project_scope_unique
  ON keys(project_id, purpose)
  WHERE profile_id IS NULL;

CREATE UNIQUE INDEX keys_profile_scope_unique
  ON keys(project_id, profile_id, purpose)
  WHERE profile_id IS NOT NULL;

CREATE TABLE automation_client_nonces (
  client_id TEXT NOT NULL REFERENCES automation_clients(id) ON DELETE CASCADE,
  nonce BLOB NOT NULL CHECK (length(nonce) = 24), -- agent-issued challenge nonce echoed in payload.auth.nonce
  request_timestamp INTEGER NOT NULL,
  seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (client_id, nonce)
);
```

`Vec<u8>` fields use SQLite `BLOB`; opaque ids and enum values use `TEXT`; `Timestamp` uses `INTEGER` UTC Unix nanoseconds; version numbers use `INTEGER` with the u32 range check above. Full migrations may add indexes, triggers, and additional tables, but they must preserve these column meanings and constraints.

Rules:

- Use explicit transactions for operations that update metadata, encrypted blobs, fingerprints, and audit rows together.
- Version schema migrations from the first implementation.
- Secret version numbers are 1-indexed. The initial version is `1`; every rotation increments by exactly one. Version `0` is invalid in CLI flags, `lk://...@vN` references, storage APIs, and import/export manifests.
- Secret updates create a new version. The current version pointer advances atomically with the encrypted blob write.
- Prior versions may remain for rotation/history, but their values are never displayed by `history`.
- `fingerprints` stores keyed fingerprints by secret id and version. It is not sufficient for leak scanning by itself and must update in the same transaction as secret metadata and blob writes.
- Denied and failed sensitive actions must also write audit rows when enough project context is available.
- `directory_grants` stores durable directory consent created by `locket allow`; live TTL grants remain in agent memory only.
- `runtime_sessions` stores non-secret execution/session metadata. Rows are inserted at spawn with `started_at`, `process_id`, and `process_start_time`; updated at exit with `ended_at` and `exit_status`. Crashed processes leave incomplete rows that `locket doctor` reports. `secret_names` are sensitive metadata and have a default 90-day retention window. `locket doctor` reports rows whose `secret_names` retention window has expired and offers to prune only the `secret_names` field, preserving session timing, policy name, pid/start-time, exit status, and audit linkage. The retention window is controlled by `runtime.session_secret_name_retention`; setting it to `off` disables storing `secret_names` in new rows rather than retaining them forever.
- `keys` stores randomly generated wrapped key material. Project-scoped rows are keyed by `(project_id, null profile_id, purpose)` for `ProjectMetadata` and `Audit`; profile-scoped rows are keyed by `(project_id, profile_id, purpose)` for `ProfileSecret` and `ProfileFingerprint`. The persisted purpose strings are `project-metadata`, `project-audit`, `profile-secret`, and `profile-fingerprint`; `KeyPurpose::Audit` serializes as `project-audit`. The master key is held by the OS keychain or recovered through the recovery envelope and is never stored in this table.
- `secrets` stores per-secret metadata including the current version pointer, source, whole-secret state (`Active` or `Deleted`), and delete timestamp where applicable. `secret_versions` stores per-version metadata keyed by `(secret_id, version)` with columns `secret_id`, `version` (u32), `source` (SecretSource), `origin` (SecretOrigin), `state` (SecretVersionState), `created_at`, `deprecated_at` (nullable), `grace_until` (nullable), and `purged_at` (nullable); `blobs` stores ciphertext keyed by `(secret_id, version)`. `secret_versions.source` is denormalized for history, diff, bundle manifest, and source-precedence workflows and must match the immutable parent `secrets.source`; writes that would make them differ fail with `StorageError`. The three tables update inside one transaction on every write. Rotation marks the prior version `SecretVersionState::Deprecated`, sets `deprecated_at = now`, and sets `grace_until = now + --grace-ttl` when a grace window is requested. `grace_until` controls how long a pinned `lk://...@vN` reference may resolve and how long scans include that deprecated value. Omitting `--grace-ttl` leaves `grace_until` null, making the deprecated version unavailable for pinned resolution and known-value scanning immediately after rotation. Purge never hard-deletes `secret_versions`; it deletes `blobs` and keyed fingerprints for the selected versions, sets those version rows to `SecretVersionState::Purged`, clears `grace_until`, and sets `purged_at = now`. Whole-secret deprecation is not a v1 lifecycle state; retiring a key uses `rm` or `purge`.
- AAD bytes are never stored as trusted data. The `blobs.aad_schema_version` field records which deterministic AAD derivation function to use; AAD is re-derived from canonical project/profile/secret/version metadata at encryption and decryption time.
- Secret rows are unique by `(project_id, profile_id, name, source)`. Runtime resolution treats `name` as the logical environment variable and applies the source precedence rules to select one active source. This permits machine-local and user-local overrides without overloading one `SecretMeta` row.
- `fingerprints` is keyed by `(secret_id, version)`. `SecretFingerprint` does not store `profile_id`; profile is obtained through the immutable `SecretMeta.secret_id -> profile_id` relationship.
- `automation_client_private_key_refs` stores `AutomationClientPrivateKeyRef` rows for Locket-managed client private keys. The table stores storage mode and local path/keychain reference metadata only, never plaintext private keys.
- `automation_client_nonces` stores recently seen signed-client challenge nonces with a unique `(client_id, nonce)` constraint so replay protection survives agent restarts. The stored nonce is the 24-byte agent-issued challenge nonce echoed in `payload.auth.nonce`, not a separate client-generated value.
- `imported_audit_chains` stores metadata for remote audit checkpoints imported from sealed bundles. When `--include-audit` is used, full remote audit rows are stored encrypted with the local project metadata key in this table as a separate chain and are never merged into the local `audit_log`. The AAD binds project id, source device fingerprint, bundle digest, checkpoint sequence, checkpoint HMAC, and `aad_schema_version`.
- SQLite must enable foreign keys, use WAL mode where available, configure a 5000 ms busy timeout by default, and run integrity checks through `locket doctor`.
- Required indexes include project/profile/name lookups for secrets, secret/version lookups for blobs and fingerprints, audit sequence ordering, trusted root hash lookup, and bundle/import conflict lookup by profile/name/version.

Schema migrations:

- Each migration writes a `SCHEMA_MIGRATE` audit row when project context is available.
- Before any migration that mutates schema or persistent data, Locket creates a local pre-migration backup of `store.db` and recovery metadata with user-only permissions, or requires explicit user confirmation if a safe backup cannot be created.
- Failed migrations must roll back completely or leave the store read-only with a clear failure mode.
- Migrations must be idempotent, transactional where SQLite permits it, and declare the minimum and maximum schema versions they can read.
- `locket doctor` reports pending, failed, or backup-skipped migrations and the path of the latest pre-migration backup when one exists.
- Downgrades are not supported against a mutable store; older binaries must fail closed when the schema is newer.

Component checks:

- Plaintext does not appear in SQLite rows, generated files, logs, shell hook files, or editor state.
- Concurrent writes are serialized or fail with a typed storage error.
- A schema newer than the current binary fails closed with a clear upgrade message.

Storage paths and permissions:

- `~/.locket/` is illustrative; actual platform paths come from the `directories` crate.
- Local store directories must be user-only where the platform supports it: `0700` directories and `0600` files on Unix-like systems.
- Agent sockets, recovery metadata, sealed bundles created locally, and hook files must be created with the narrowest practical permissions.
- `config.toml` may store preferences such as theme, default editor, agent autostart, update channel, reveal TTL, shell integration preferences, and UI density. It must not store secret values, wrapped keys, grant tokens, recovery material, or device private keys.

Config schema:

All duration strings in `config.toml`, `locket.toml`, and policy TOML use the canonical `Duration` grammar defined in [data-model.md](data-model.md) and are normalized to unsigned integer seconds in SQLite caches.

- `schema_version`: integer config schema version.
- `ui.theme`: `system | light | dark`.
- `ui.density`: `comfortable | compact`.
- `privacy.redact_names`: boolean, default `false`. When true, status-oriented surfaces replace project, profile, policy, member, device, and secret names with stable local aliases where exact names are not required for correctness. This affects tray, shell prompt, VS Code status, `locket status`, `locket context --redact-names`, redaction labels, and debug bundles. It does not alter audit rows, policy files, `.env.example`, storage keys, command execution, or local authorization decisions.
- `editor.default`: command name or absolute path, never shell-expanded.
- `agent.autostart`: boolean.
- `agent.unlock_ttl`: duration string, capped by project policy.
- `runtime.session_secret_name_retention`: duration string or `off`, default `90d`. This controls how long `runtime_sessions.secret_names` are retained for local troubleshooting and audit correlation. It does not delete audit rows and does not affect whether execution audit metadata is written.
- `reveal.ttl`: duration string, default 60 seconds, capped at 5 minutes.
- `rotation.max_grace_ttl`: duration string, default 7 days, capped at 30 days by the binary. Project config may lower this cap but may not raise it above the binary maximum.
- `shell.integration`: `off | prompt-only | hook`.
- `updates.channel`: `off | stable | beta`.
- `updates.manifest_url`: HTTPS URL for signed manifests; ignored unless update checks are enabled.
- `example.auto_refresh`: boolean, default `true`. When `false`, `set`, `rotate`, `rm`, `purge`, `import`, `copy`, and `team accept` do not automatically refresh `.env.example`; use `locket emit-example` to regenerate on demand. Version-level deprecation created by `rotate --grace-ttl` does not change `.env.example` membership because the current version remains active. May be set in `config.toml` (user default) or `locket.toml` (project override); project-level wins.
- `user_verification_required_for.unlock`, `user_verification_required_for.reveal`, `user_verification_required_for.copy`, `user_verification_required_for.dangerous_profile_switch`, `user_verification_required_for.recovery`, `user_verification_required_for.team_accept`, and `user_verification_required_for.device_register`: booleans controlling non-command local user-verification gates. These settings are project-scoped when stored in `locket.toml` and user defaults when stored in `config.toml`; project policy wins over user defaults. At startup, Locket reads `[user_verification_required_for]` from `locket.toml` and writes the parsed values into `Project.user_verification_policy` in SQLite alongside the policy index refresh; `locket.toml` is the canonical source and SQLite is the working cache.
