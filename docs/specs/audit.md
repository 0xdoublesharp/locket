# Audit & Integrity

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Audit & Integrity

Audit-log integrity is required from day 1.

Design:

- Every audit row includes a sequence number, previous-row HMAC, and current-row HMAC.
- Project audit/metadata keys and profile secret/fingerprint keys are random keys stored only as wrapped material. The master key derives purpose-separated wrapping keys via HKDF; it does not directly derive project or profile keys. No project/profile key may be derivable from, or substitutable with, another, and none may be derivable from any device key.
- The HMAC covers sequence, timestamp, project/profile ids, action, status, safe metadata, previous HMAC, and the schema version recorded on the row at write time.
- Verification recomputes each row's HMAC using the schema version stored on that row, not the current binary's schema version, so a `SCHEMA_MIGRATE` does not break the chain.
- Audit append must run inside the same SQLite transaction as the metadata/blob change it records. Sequence numbers are assigned at commit so a rolled-back transaction never produces a gap or a phantom row.
- Audit verification detects gaps, insertion, mutation, and reordering within the retained chain. It cannot detect deletion of a valid suffix, an emptied chain, or whole-database rollback without an independently retained checkpoint. Local audit verification establishes integrity of the rows present, not completeness against an external history.
- Audit metadata never includes plaintext secret values.
- The top-level `AuditLog.secret_name` and `AuditLog.command` columns are query/index conveniences only. When present, the same values must also be encoded inside `metadata_json` as `secret_name` and `command` fields so they are covered by `bytes("metadata_json", ...)` in the HMAC chain. When either convenience field is absent, the corresponding key must be omitted from `metadata_json`; implementations must never encode `"secret_name": null` or `"command": null`. Implementations must not treat the convenience columns as authoritative if they disagree with HMAC-covered metadata.

Audit HMAC v1 canonical bytes:

```text
audit_hmac_v1 =
  "locket-audit-v1" ASCII bytes
  u16_le(schema_version)
  u64_le(sequence)
  i128_le(timestamp_unix_nanos_utc)
  field("project_id", project_id or "")
  field("profile_id", profile_id or "")
  field("action", action)
  field("status", status)
  bytes("metadata_json", canonical_json(metadata_json))
  bytes("previous_hmac", previous_hmac or 32 zero bytes)
```

`field(name, value)` uses the length-prefixed UTF-8 encoding defined in [crypto.md](crypto.md): `u16_le(byte_len(name)) || UTF-8(name) || u32_le(byte_len(value)) || UTF-8(value)`. `bytes(name, value)` uses the same name encoding but treats the value as a raw byte sequence: `u16_le(byte_len(name)) || UTF-8(name) || u32_le(byte_len(value)) || value_bytes`. `bytes` is used for `metadata_json` (the UTF-8 byte representation of the canonical JSON string) and `previous_hmac` (32 raw bytes). If a legacy or failed-row path represents `metadata_json` as `None`, `canonical_json(metadata_json)` is exactly the four ASCII bytes `null`; it is never encoded as zero-length bytes and the `metadata_json` field is never omitted from `audit_hmac_v1`.

`canonical_json` uses UTF-8, sorted object keys, no insignificant whitespace, decimal integer encoding, and JSON string escaping. Any future timestamp, metadata, or field encoding change must increment the audit schema version. Implementations must never compute HMAC over database row serialization, TOML, pretty JSON, or platform-local timestamp formats.

## Audit Metadata Shapes

Every audit row stores a typed JSON object in `metadata_json`. The object must include `schema_version: 1`, `action`, and `status`, plus the fields below when applicable. Unknown fields are allowed only after a schema version bump or when the typed metadata parser explicitly preserves and re-HMACs them.

| Action family | Required metadata fields |
| --- | --- |
| Secret value lifecycle: `SET`, `ROTATE`, `DELETE`, `PURGE`, `IMPORT`, `SECRET_COPY`, `SECRET_META_UPDATE` | `secret_name`, `profile_id`, `source`, `version` or `target_version`; rotation/copy additionally include `prior_version`, `deprecated_at`, and `grace_until` when present; metadata updates include updated field names/counts, required-state changes when present, status, and failure reason when applicable, but never description, owner, tag text, or secret values |
| Secret value access: `GET`, `REVEAL`, `COPY` | `secret_name`, `profile_id`, `source`, `access_mode`; clipboard copy additionally includes `ttl_seconds` |
| Execution: `EXEC`, `RUN` | `command` or `policy_name`, `argv0`, `arg_count`, `profile_id`, `env_mode`, `override`, `secret_names`, `exit_status` when available, and `delivery_mode` for Docker/Compose/ephemeral-file paths |
| Scan/redaction: `SCAN`, `REDACT` | `scope`, `known_value_coverage`, `finding_counts`, `redacted_secret_names` when known, `pattern_only`, and child `argv0`/`arg_count` for `ai-safe` |
| Project/profile/policy/config/bootstrap: `PROFILE_CREATE`, `PROFILE_CHANGE`, `TRUST_ROOT`, `POLICY_UPDATE`, `CONFIG_UPDATE`, `EXAMPLE_EMIT`, `BOOTSTRAP` | `profile_id`/`profile_name` for profile creation; `profile_id`/`profile_name` plus prior/new active profile or prior/new flags for profile changes; `root_hash` and trust operation for roots; `policy_name` and `change_kind` for policies; config key path plus redacted prior/new metadata for config; example path kind/hash and secret-name count for example emission; project id, default profile id, generated file list, and `recovery_code_displayed` for bootstrap |
| Directory grants: `ALLOW_DIRECTORY`, `DENY_DIRECTORY` | `grant_id` when present, `project_id`, `profile_id`, `root_hash`, `directory_hash`, `grant_scope`, prior grant metadata when replacing or removing, and resulting grant state |
| Agent/grants: `UNLOCK`, `LOCK`, `AGENT_GRANT`, `AGENT_REVOKE`, `GRANT_EXPIRED` | `client_kind`, `grant_actions`, `ttl_seconds`, `directory_hash` where relevant, `process_id` and `process_start_time` where relevant |
| Passkeys/automation clients: `PASSKEY_REGISTER`, `PASSKEY_REMOVE`, `PASSKEY_AUTH`, `CLIENT_ADD`, `CLIENT_REVOKE`, `CLIENT_AUTH` | `passkey_id` or `client_id`; credential id prefix or public-key fingerprint; capabilities/transports and backup state for passkeys; storage mode, allowed actions, and allowed policies for clients; `revoked_at` for removals; request id, requested action/policy, nonce freshness result, and authentication result for client/passkey auth |
| Team/device/recovery/bundle: `TEAM_INIT`, `TEAM_INVITE`, `TEAM_ACCEPT`, `TEAM_REMOVE`, `DEVICE_ADD`, `DEVICE_REVOKE`, `BACKUP_EXPORT`, `BACKUP_IMPORT`, `RECOVER`, `RECOVERY_ROTATE`, `BUNDLE_VERIFY` | `team_id`/`member_id`/`device_id` or fingerprints where relevant, selected profile ids, role, expiry, bundle digest/checkpoint, and result summary |
| Diagnostics/integrity/schema: `DOCTOR`, `AUDIT_VERIFY`, `SCHEMA_MIGRATE`, `HOOK_INSTALL` | check names, pass/warn/fail/skip counts, first failure location where relevant, schema versions, and hook path kind/hash |

HMAC-covered audit metadata stores exact canonical names and ids, never privacy aliases. Privacy aliases may be applied only when rendering audit output, status views, debug bundles, or redacted transcripts. `secret_names` and `redacted_secret_names` never contain values. Large collections must be capped and summarized before reaching the 64 KiB audit metadata limit.

Command:

```bash
locket audit verify
```

Behavior:

- Exit success when the chain verifies.
- Exit with `AuditIntegrityFailed` when the chain is broken.
- Record an `AUDIT_VERIFY` row only when the entire chain verifies successfully and the SQLite write succeeds in the same transaction.
- On verification failure, report the first break location and do not attempt to append a row.

### Independently retained checkpoints

```bash
locket audit checkpoint --output /independent/location/project-checkpoint.json
locket audit verify --checkpoint /independent/location/project-checkpoint.json
```

Checkpoint export verifies the nonempty chain and authenticates its project,
sequence, and final row HMAC with a domain-separated HMAC. It creates a new
file (mode `0600` on Unix) and refuses to overwrite an existing output. Checkpoint
verification authenticates the checkpoint, verifies the current chain, and
requires the exact anchored row before appending a successful `AUDIT_VERIFY`
row in the same transaction. Missing anchored rows, including an emptied or
truncated chain, fail verification.

Keep the newest trusted checkpoint independently of the vault and its backups.
Restoring both the database and an older authentic checkpoint remains
undetectable. Checkpoints are explicitly supplied to verification; creating one
does not automatically enforce it on later secret operations.
