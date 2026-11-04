# Team, Recovery & Sync

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Team Local Development Bootstrap

Locket must make secure team setup as easy as copying a `.env` file, without ever copying plaintext secrets.

Target teammate experience:

```bash
git clone <repo>
cd <repo>
locket device init
locket team accept ./alice.locket-invite
locket bootstrap
locket run dev
```

Maintainer invite flow:

1. Maintainer runs `locket team init` once for the project. `locket team init` requires a resolved project from a trusted root, an unlocked vault, and an initialized local device key. If no local device key exists, it fails with `KeychainEntryMissing` and directs the user to run `locket device init`. When no `Team` record exists, any authenticated local user who can unlock the local vault for that project may run `locket team init`; the first successful caller becomes Owner. This deliberately relies on OS-level user account isolation and the local vault unlock boundary. On the first invocation for the current user-local store, it creates a `Team` record for the current project, registers the running user's local device as the first `TeamMember` with `Owner` role, writes a `TEAM_INIT` audit row, and is idempotent: if a `Team` record already exists for this project it exits successfully with a notice rather than creating a duplicate or changing ownership. Because the store is user-scoped, "first Owner" means first owner in this OS user's local Locket store; shared-machine safety still depends on per-user store permissions.
2. New teammate runs `locket device init` and sends their device descriptor to a maintainer through any existing trusted communication channel. v1 uses device descriptors as the only invite request artifact.
3. Maintainer runs `locket team invite <name> --device <device-descriptor> --profile dev --role developer [--output <path>]`.
4. Locket creates a sealed invite encrypted to the teammate's device sealing key. The invite file is written to `locket-invite-<utc-timestamp>.locket-invite` in the current working directory by default so human names are not leaked through filenames; `--output <path>` overrides the destination.
5. Maintainer sends the invite file through any existing channel.
6. Teammate runs `locket team accept <invite.locket>`.
7. Locket imports only the profiles, profile secret/fingerprint keys, and command policies included in the invite, rewraps imported profile keys into the local `keys` table, and records audit events. `team accept` must run inside a directory containing a `locket.toml` whose `project_id` matches the invite. When that project is not yet present in the local store, `team accept` creates the local `Project`, `Profile`, `Team`, and `TeamMember` records, registers the issuer device as a trusted member device, and adds the current canonicalized root path to the project's trusted roots. When the current directory has no `locket.toml`, has a mismatched `project_id`, or already maps to a different local project, `team accept` fails closed with a typed error rather than silently creating or overwriting state. If no local device key exists in the OS keychain, `team accept` fails with `KeychainEntryMissing` and directs the user to run `locket device init` first.
8. Teammate runs `locket bootstrap` to validate the environment and run setup checks.

Agent invite handoff uses the same primitive with paste-friendly command wrappers:

```bash
locket setup agent
locket agent invite request
locket agent invite create <label> --device <descriptor> --profile dev --role developer [--expires-in 7d]
cat <<'LOCKET_INVITE' | locket agent invite accept -
<sealed invite block>
LOCKET_INVITE
```

`locket setup agent` prints the receiver, maintainer, and accept commands in the order they should be used. `locket setup share` lists the agent invite, team invite, and sealed bundle paths for users who are not sure which sharing flow they need. `locket agent invite request` uses the active local device descriptor, or a supplied `--device <descriptor>`, to print a request block containing the descriptor, fingerprint, safety words, and a ready-to-run maintainer command. If no local descriptor exists, it directs the user to run `locket device init`; it does not silently initialize a device because that flow may display recovery material. `locket agent invite create` is a CLI and desktop handoff wrapper for `locket team invite`: it accepts the same device descriptor, profile, role, expiry, issuer authorization, dangerous-profile confirmation, and audit requirements, writes the standard signed invite file, then prints a heredoc accept block suitable for copying through chat, issue comments, or another user-mediated channel. `locket agent invite accept -` reads that block from stdin and applies the same verification, replay protection, user-verification policy, import, and audit behavior as `locket team accept`. These commands do not define a new cryptographic protocol, trust root, role model, or unattended grant path; they only package the existing team invite/accept flow for agent and desktop handoff surfaces.

`locket bootstrap` must:

- Verify `locket.toml` and trusted root state.
- Verify the local agent is running or startable.
- Verify the active profile is available.
- Verify required command policies exist.
- Verify referenced tools are present where possible.
- Offer to install shell hooks and Git hooks.
- Generate or refresh `.env.example`.
- Run a smoke command if one is configured. The smoke command is the name of an existing command policy, specified as `smoke_policy = "<name>"` under a `[bootstrap]` table in `locket.toml`. The named policy is run exactly as `locket run <name>` would run it, including all policy gates, confirmation prompts, and audit logging. If `smoke_policy` is not set, this step is skipped silently.
- Print missing setup steps without printing secret values.
- Run safely on solo-developer projects with no team configured: team-membership, invite, and device-revocation checks are skipped when no `Team` record exists for the project.

`locket device init` is idempotent. When no local master key exists yet (the typical teammate path: `git clone` then `device init` without ever running `locket init`), the first invocation also creates the local master key, the recovery envelope, and the recovery code, and displays the recovery code under the same one-time-display rules as `locket init`. The first invocation then generates the local device key and places its private key wrap in the keychain and in the recovery envelope. Subsequent invocations refuse to overwrite the existing device key unless `--force` is supplied. `--force` requires an unlocked vault plus fresh local user verification through the configured platform prompt, hardware-key presence, or passphrase fallback; it writes `DEVICE_REVOKE` for the prior local device key and `DEVICE_ADD` for the replacement key, atomically updates the recovery envelope with the new device private-key wraps, and breaks any existing sealed exports addressed to the prior device sealing public key, which the user must rotate. If the recovery-envelope update fails, the entire forced rekey rolls back and the prior device key remains active.

`locket init` triggers the same master-key bootstrap the first time it runs on a machine and additionally creates the project records. On a machine that already has a master key (e.g., the user has another Locket project), `locket init` reuses the existing master key and only creates new project/profile-scoped keys. Re-running `locket init` in an already initialized project is idempotent as defined in [project-cli.md](project-cli.md): it must not create new keys or re-display the recovery code.

Team invite trust ceremony:

- Every device has a public-key fingerprint and a short safety-words representation.
- `locket device pubkey` prints a device descriptor containing both the Ed25519 signing public key and X25519 sealing public key, plus the combined fingerprint and safety words.
- Device descriptors are encoded as `lkdev1_` followed by unpadded base64url JSON. The decoded JSON must contain `v`, `device_id`, `label`, `signing_public_key_ed25519`, `sealing_public_key_x25519`, `fingerprint_sha256`, and `safety_words`. Public keys are unpadded base64url byte strings.
- Device identity fingerprint v1 is lowercase hex `SHA-256("locket-device-v1" || u16_le(signing_key_len) || signing_public_key_ed25519 || u16_le(sealing_key_len) || sealing_public_key_x25519)`. `device_id` and `label` are descriptor metadata and must not affect the fingerprint, so relabeling a device does not create a new identity.
- Safety words are 4 words derived from the fingerprint by splitting the first 8 bytes of the SHA-256 fingerprint into four 2-byte windows and indexing the PGP word list (alternating even/odd columns per byte position), producing a fixed-length human-pronounceable phrase suitable for out-of-band verification.
- `locket device add`, `locket team invite`, and `locket export --sealed --recipient` all accept the same `<device-descriptor>` format. The CLI flag name for accepting a descriptor is `--device` except export, where `--recipient` names the recipient role.
- Maintainers must verify the recipient device fingerprint or safety words out of band before creating an invite.
- Invite files are signed by the issuing maintainer device and include issuer member id, issuer device id, issuer signing public key, issuer sealing public key, issuer device fingerprint, recipient device fingerprint, recipient sealing public key, expiry, nonce, role, profiles, and project id. The issuer's public keys are carried in the unsealed envelope so a first-time acceptor with no prior project state can verify the signature and record the trusted device.
- `locket team accept` shows the issuer member name, project id, profiles, role, expiry, recipient fingerprint, and the issuer device's fingerprint and safety words. The teammate must confirm the issuer fingerprint matches the value the maintainer published out of band before import. After acceptance the issuer device is recorded as a trusted member device, so subsequent invites verify against the locally stored key without re-prompting.
- Accepted invite ids are recorded to prevent replay. Clock-skew tolerance for `expires_at` is 5 minutes. Expired, revoked, already accepted, unsigned, incorrectly signed, or fingerprint-mismatched invites fail closed.
- `locket team revoke-invite <invite-id>` sets `TeamInvite.revoked_at = now` in the local `team_invites` table and writes a `TEAM_INVITE` audit row with revocation metadata. The invite id is printed at invite creation time, included in `locket team members` pending-invite output, and stored inside the invite payload; it is not embedded in the default invite filename, which remains `locket-invite-<utc-timestamp>.locket-invite`. Future `locket team accept` of a revoked invite fails closed because the issuer's local store records it as revoked. Revocation is local-first: it does not prevent acceptance on a machine that has not yet synced the revocation. Owners may revoke any invite; Maintainers may revoke invites they issued or invites for non-owner roles.
- `locket team members` lists all `TeamMember` records for the current project: member id, display name, role, trusted-device count, join date, and removal date where applicable. Pending invites (not yet accepted, not expired, not revoked) are shown with an invitation status indicator. Output is metadata-only and never includes secret values, device private keys, or wrapped key material.
- `locket team remove <member>` accepts a member display name or member id. Owners may remove any member except the last remaining Owner. Maintainers may remove only Developer and ReadOnly members. The command shows a metadata-only summary of the profiles the member's trusted devices could access and the secrets associated with those profiles. It requires typing the member's display name exactly as confirmation. It sets `TeamMember.removed_at = now`, writes a `TEAM_REMOVE` audit row, and produces a rotation checklist for every profile and secret the member's trusted devices could decrypt. It does not retroactively revoke secrets from environments the member has already received.
- `locket team revoke-device <device>` accepts a device name, device id, or fingerprint. Requires Owner role for all devices; Maintainers may revoke non-owner member devices. Sets `Device.revoked_at = now`, writes a `DEVICE_REVOKE` audit row, refuses future invites and sealed exports to the revoked device, and produces a rotation checklist for every profile and secret that device could decrypt. Does not retroactively revoke secrets from already-distributed bundles. This is the team action for revoking a member's device. `locket device remove` (in the personal device management section of the CLI) is the corresponding action for removing one of your own additional registered devices.

Team security rules:

- Signed `team add` and manual `team publish` require typed `team share <profile names>` confirmation before granting or delivering dangerous profiles. Automatic publication separately requires the owner's explicit dangerous-profile folder consent. Recipient-side holds are not a substitute for sender consent: an encrypted package already grants cryptographic access to its recipient.

- Invites are sealed to recipient device sealing public keys; invite files never contain plaintext secret values outside the age-encrypted payload. Profile secret and fingerprint keys are included as plaintext key material inside the age-sealed payload so the recipient can rewrap them into their local `keys` table; the recipient device private key is the cryptographic protection for that payload.
- Invites are profile-scoped and role-scoped.
- Default teammate role is `Developer`, limited to non-dangerous profiles unless explicitly granted.
- Production or dangerous profiles require owner/maintainer role and typed confirmation.
- Removing a member or revoking a device prevents future sealed exports to that device and must prompt rotation of secrets the member/device could access.
- Team sharing is local-first: no hosted service, no account system, and no remote calls are required.
- Audit rows record invite creation, acceptance, member removal, device revocation, bootstrap checks, and denied team actions.

Collaboration roles:

| Role | Capabilities |
| --- | --- |
| Owner | Manage team, members, devices, all profiles, sealed exports, and dangerous profile grants |
| Maintainer | Invite developers, manage non-dangerous profiles, rotate shared development secrets |
| Developer | Accept invites, use granted profiles, run policies, rotate own local-only secrets |
| ReadOnly | Inspect metadata, run scans, and use explicitly granted non-reveal workflows |

Authorization matrix for team-managed state:

| Action | Owner | Maintainer | Developer | ReadOnly |
| --- | --- | --- | --- | --- |
| Invite or remove members | yes | invite/remove Developers and ReadOnly only | no | no |
| Register or revoke team devices | yes | non-owner devices only | own device only through invite/accept | no |
| Read metadata for granted profiles | yes | yes | granted profiles | granted profiles |
| Run command policies for granted profiles | yes | yes | yes | only policies explicitly marked read-only-safe |
| Set/rotate team-managed secrets | yes | non-dangerous profiles by default | no unless policy grants per-secret rotation | no |
| Copy into team-managed profile | yes | non-dangerous profiles by default | no | no |
| Purge team-managed secrets | yes | yes for non-dangerous profiles with typed confirmation | no | no |
| Export sealed bundles | yes | non-dangerous profiles and trusted devices | no unless explicitly granted | no |
| Delete policies or change policy gates | yes | non-dangerous profiles by default | no | no |
| Add/revoke automation clients | yes | non-dangerous policies by default | no | no |
| Change security config, recovery, or dangerous profile flags | yes | no | no | no |

Solo-developer projects with no `Team` record treat the local user as Owner for authorization, but still enforce typed confirmations, local user verification, audit logging, and source-selection rules.

Team collaboration intentionally avoids live cloud state. For team sync, Locket uses repeated sealed bundles and explicit imports. Conflicts are detected by secret version and audit timestamp, then resolved by the bundle conflict policy; plaintext values are never used for conflict display.

Team local-development UX:

- `locket bootstrap` must present a checklist with status, fix command, and safe explanation for each item.
- The happy path must end with the exact command the developer can run next, usually `locket run dev`.
- Missing secrets, missing tools, untrusted roots, stopped agents, expired invites, and revoked devices must produce actionable messages without values.
- A failed bootstrap must be safe to rerun.

## Backup, Recovery & Multi-Machine Sync

Backup and recovery are required for a tool that owns local secrets. Current recovery is project scoped: each project has its own local master key, device identity, recovery envelope and recovery code. Back up the encrypted `<project>/.locket/recovery/envelope.bin` for every project separately from its code. Legacy backups also require their matching `kdf.toml`. Project vault data must be backed up separately; the recovery envelope restores keys, not a lost database.

Initialization:

- `locket init --recovery-code` emits a recovery code for the project. Plain `locket init` leaves recovery creation to a later `locket recovery rotate`.
- Initialization includes the current device keys when a device is created, so the initial backup can restore both vault access and bundle decryption.
- The recovery code is the only recovery secret. It derives the unwrap key for the local recovery envelope with Argon2id and stored salt/KDF parameters.
- Locket must clearly tell the user that the recovery code is shown once and is required if the OS keychain entry is lost.
- The display flow must require a typed acknowledgement that the user has recorded the code before continuing, warn that terminal scrollback may persist the code, and offer to clear the visible screen after acknowledgement. The recovery code is never written to a Locket-managed file, log, or audit row in plaintext form.

Recovery:

```bash
locket recover [--force]
```

Behavior:

- Prompt for the recovery code using a secure interactive password prompt (equivalent to `rpassword`) before performing any other action. The recovery code must not be accepted as a command-line argument, positional parameter, or environment variable. Reading from stdin is allowed only when stdin is not a TTY. The prompt is displayed on stderr so it does not interfere with scripted output.
- Rebuild the OS keychain entry (master key) and the OS keychain entry for the local device private key from the recovery code and the recovery envelope. Both the master key and device private key wrap are restored to the OS keychain, mirroring the state created by `locket device init`. The on-disk recovery envelope is not modified by `locket recover`.
- Restore Locket-managed automation client private keys: for every `automation_client_private_key:<client_id>` entry found in the recovery envelope, restore the `OsKeychain` or `WrappedLocalFile` key material to the same storage destination recorded in `AutomationClientPrivateKeyRef`. Externally managed client keys are never restored by Locket. If a client key entry cannot be restored because the client record has been deleted or revoked, skip it with a metadata-only warning rather than failing the overall recovery.
- Record a recovery audit event.
- Never write recovered master key material, device private key material, or client private key material to disk outside their designated OS keychain or wrapped-local-file destinations.
- Refuse to run when the OS keychain entry is already valid unless `--force` is supplied; `--force` rotates the keychain entry and is audited as `RECOVER` with metadata indicating an intact-keychain override.
- Refuse to run when the recovery envelope is missing or its KDF parameters cannot be parsed, returning `BackupRecoveryFailed`.

Recovery error mapping:

| Condition | Error |
| --- | --- |
| Recovery code checksum or format is invalid | `BackupRecoveryFailed` |
| Recovery code is well-formed but cannot decrypt the envelope | `BackupRecoveryFailed` |
| embedded KDF metadata (or legacy `recovery/kdf.toml`) is missing, unparsable, unsupported, or mismatches the inner envelope | `BackupRecoveryFailed` |
| `recovery/envelope.bin` has a schema version newer than this binary understands | `ConfigError` with upgrade-required guidance |
| `recovery/envelope.bin` is missing, corrupt, truncated, or fails AAD/authentication checks | `BackupRecoveryFailed` |
| Required `master_key`, `device_signing_private_key`, or `device_sealing_private_key` entry is missing after successful envelope parse | `LocalVaultUnrecoverable` |
| OS keychain write fails after successful decrypt | `KeychainUnavailable` or `StorageError`, depending on backend failure |
| Recovery succeeds for master/device keys but optional managed automation-client key restore fails | metadata-only warning; overall recovery succeeds |

Recovery code rotation:

```bash
locket recovery rotate
```

Behavior:

- Requires an unlocked vault plus fresh local user verification through the configured platform prompt, hardware-key presence, or passphrase fallback.
- Generates a fresh recovery code with the same entropy and encoding rules as `locket init`.
- Re-wraps the recovery envelope under a new Argon2id-derived key from the new code. Displays the code and requires typed acknowledgment before replacing recovery state. Then writes KDF metadata and the encrypted envelope as one atomic container; the old envelope is not retained as a fallback. A legacy loose KDF file may remain, but cannot recover keys without its old envelope.
- The one-time display uses typed acknowledgment and a scrollback warning, and clears the terminal only after acknowledgment. Rejected acknowledgment or audit-write failure leaves the previous backup intact. If an error occurs after the atomic replacement, the user already has the acknowledged new code; retain both codes until verifying the committed backup.
- Writes a `RECOVERY_ROTATE` audit row. The prior code is invalidated immediately on commit; an in-progress recovery using the prior code will fail with `BackupRecoveryFailed`.
- Refuses to run from a merely unlocked agent session without fresh user verification. If the current recovery code is available, the user may provide it as the verification factor; otherwise fresh platform/hardware-key/passphrase verification is required so a briefly unattended unlocked session cannot silently rotate the user out of recovery.
- When the current recovery code is used as the verification factor, `locket recovery rotate` prompts for it through the same no-echo secure TTY input path as `locket recover`. The current code must not be accepted through argv, environment variables, shell history, or ordinary stdin in v1. Non-interactive recovery-code rotation is refused.

One-user, multi-machine sync:

```bash
locket export --sealed --recipient <device-descriptor> --profile <name> [--include-audit] [--output <path>]
locket export --sealed --recipient <device-descriptor> --all-profiles [--include-audit] [--output <path>]
locket import-bundle <bundle> [--include-audit] [--accept-incoming | --accept-local]
```

Team bundle sharing uses the same primitive:

```bash
locket export --sealed --recipient <alice-device-descriptor> --recipient <bob-device-descriptor> --profile dev [--include-audit] [--output <path>]
locket import-bundle <bundle> [--include-audit] [--accept-incoming | --accept-local]
```

Export selection rules:

- `--profile <name>` selects exactly one profile and may be repeated.
- `--all-profiles` exports every profile the local device is authorized to read.
- A bundle contains only the secrets, policies, and metadata the local device can decrypt. Items the local device cannot decrypt are omitted with a metadata-only summary, never written as ciphertext-passthrough.
- For each selected profile, the age-encrypted bundle payload includes that profile's `ProfileSecret` and `ProfileFingerprint` keys as plaintext key material inside the encrypted payload plus the selected encrypted secret blobs and metadata. Non-selected profile keys are never included. Exporting the master key, project audit key, device private keys, recovery material, or keychain wraps is forbidden.
- Project audit key material is never exported in sealed bundles. Bundles carry audit checkpoints and optionally remote audit rows, but imports append local audit rows under the receiving device's local audit key.
- Default: the active profile only.
- Exporting a dangerous profile requires Owner role and typed confirmation of the dangerous profile name, even when `--all-profiles` is used.
- Export output defaults to `locket-bundle-<utc-timestamp>.locket-bundle` in the current working directory so project names are not leaked through filenames. `--output <path>` overrides the destination. If the output path already exists, the command fails with a descriptive error; v1 has no overwrite flag for bundle export.
- Full audit rows are excluded by default. `--include-audit` includes full remote audit rows inside the encrypted payload; without it, bundles include only an audit checkpoint.
- Successful bundle export writes `BACKUP_EXPORT` with selected profile ids, recipient fingerprints, bundle digest, output path kind, `include_audit`, and counts only. It never records secret values, wrapped key material, or the full output path by default.

A user can sync sealed bundles through any folder service because each bundle is encrypted to the recipient device key or keys. No hosted sync service is part of this spec.

Team sealed sharing:

- Owners and maintainers can create sealed bundles for trusted member devices.
- Bundles can contain only selected profiles, policies, metadata, encrypted blobs, and audit checkpoints.
- Importing a team bundle never overwrites newer local versions without showing a metadata-only conflict summary.
- Removing a team member or revoking a device does not erase secrets already received by that device; Locket must make this explicit and offer rotation for affected secrets.
- Team sharing relies on cryptographic recipient control, auditability, and rotation, not remote revocation magic.

Sealed bundle format:

- Bundles are versioned Locket containers with a magic header, schema version, plaintext metadata manifest, and an encrypted payload.
- The encrypted payload uses the age v1 file encryption format in binary mode, implemented through the Rust age/rage library. Locket does not define a custom X25519 KEM.
- Multi-recipient support is delegated to age recipients: one encrypted payload is addressed to one or more age-compatible X25519 recipients. All recipients of a bundle receive the same content; per-recipient subsets require separate bundles.
- The plaintext manifest is intentionally minimal because sealed bundles are commonly stored in sync folders. It may include recipient fingerprints, project id, schema version, created_at, profile count, and payload digest. It must not include profile names, secret names, policy names, member names, device labels, secret values, wrapped project/profile keys, recovery material, or device private keys. Exact names belong inside the encrypted payload.
- The encrypted payload contains a canonical JSON manifest plus binary payload sections: selected profiles, selected command policies, selected secret metadata, selected `secret_versions`, selected blobs, selected profile key material, and audit checkpoint/rows according to `--include-audit`.
- Imported profile keys are rewrapped into the receiver's local `keys` table with the receiver's master-key-derived wrapping key. Imported blobs remain encrypted under their per-version DEKs, and those DEKs remain wrapped by the imported profile secret key.
- `locket bundle verify <bundle>` performs a non-destructive check and never imports rows or writes secret material. Structural checks validate magic header, schema version support, manifest length bounds, required manifest fields, payload digest shape, age recipient stanza presence, and that plaintext manifest fields obey the minimization rules above. Cryptographic checks verify the age payload authentication tag by attempting decryption when the current device has a matching recipient key. If no matching recipient exists, verification reports "structurally valid but not decryptable by this device" and exits `0` because v1 verification is allowed to be structural-only for bundles addressed to other devices. When decryption succeeds, Locket parses the encrypted manifest, validates selected profile/key/blob references, checks bundle checkpoint consistency, reports counts only, and exits `0`. Malformed containers return `BundleVerificationFailed` with exit `110`; unsupported schema returns `ConfigError`; missing local device key returns a metadata-only non-decryptable result with exit `0`. `BUNDLE_VERIFY` audit rows contain bundle digest, schema version, decryptability, and counts only.

Bundle import conflict policy:

- Different secret names import without conflict.
- Same profile/name/version with identical fingerprint is treated as already present.
- Same profile/name with a newer incoming version imports only after showing a metadata-only summary.
- Same profile/name with divergent local and incoming versions requires interactive resolution or explicit `--accept-incoming` / `--accept-local`.
- Deleted locally but active incoming, or active locally but deleted incoming, requires interactive resolution.
- Full audit rows imported with `--include-audit` remain a separate remote audit chain in `imported_audit_chains`. Locket structurally verifies the remote chain against the bundle checkpoint: sequence numbers must be monotonically increasing, each row's `prev_hmac` must match the prior row's stored `hmac`, and the final row's `hmac` must match the plaintext bundle checkpoint `hmac`. HMAC recomputation against the project audit key is not performed because audit key material is never exported in sealed bundles; structural and checkpoint consistency is the sole verification mechanism for remote chains. The encrypted remote rows are stored as imported evidence, and a local import row is appended with the bundle checkpoint rather than merging chains. `locket team accept` writes `TEAM_ACCEPT`; `locket import-bundle` always writes `BACKUP_IMPORT`, including when the bundle came from another team member.

When `import-bundle` or `team accept` imports a newer version over an existing active target, it applies the same target lifecycle as `locket rotate` with no grace window: the prior local version is marked `Deprecated`, the incoming version becomes current, and `SecretMeta.last_rotated_at` is set to the import timestamp. Importing version `1` into a missing target leaves `last_rotated_at = None`.

Import validates project ownership for every referenced profile, profile key,
secret, version, and blob before applying rows. References must resolve within
the requested project or to new rows declared by that bundle. Foreign or
missing references reject the entire transaction. Accepting a local secret
also retains its versions and ciphertext; unrelated new secrets may still
import. Historical rows and repeated imports must not extend a locally expired
deprecated-version grace period.
