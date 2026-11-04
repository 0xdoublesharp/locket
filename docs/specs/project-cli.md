# Project Resolution, CLI & Onboarding

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Project Resolution

Resolution algorithm:

1. Find `locket.toml` by walking upward from the current directory.
2. If not found, return `ProjectNotFound`.
3. Read `project_id` from `locket.toml`.
4. Canonicalize and hash the project root path.
5. Match `project_id` to a stored project.
6. Verify the current root hash is in the project's trusted root hashes.
7. Resolve active profile from CLI flag, environment override, project config, live shell grant, or stored default.

Default relocation policy is `fail`: a copied or moved `locket.toml` must not silently access an existing local vault. Users can intentionally trust the new path with `locket project trust-root`, which adds the current root hash to the project's trusted root set and records an audit event.

Minimal project file:

```toml
schema_version = 1
project_id = "lk_proj_..."
name = "my-app"
default_profile = "dev"
```

The project file must not contain secret values, encrypted secret blobs, wrapped keys, grant tokens, or machine-local unlock state.

Projects may also declare metadata-only path scopes for monorepos:

```toml
[commands.dev]
argv = ["pnpm", "dev"]

[paths."apps/api"]
profile = "dev"
required_secrets = ["DATABASE_URL"]
optional_secrets = ["STRIPE_SECRET_KEY"]
```

Path scopes are project-relative env sets, not secret stores. The deepest matching `[paths."..."]` entry extends the selected `[commands.<policy>]` entry for `locket run`, `locket env inspect`, Docker, and Compose execution from that subtree. A path scope may add `required_secrets`, add `optional_secrets`, and select a profile; normal policy validation, source precedence, conflict handling, and audit rules still apply.

The upward search for `locket.toml` stops at the filesystem root, at the first parent that cannot be read, or when canonicalization fails. In nested projects, the nearest `locket.toml` wins.

Directory hashes used by trusted roots, directory grants, and shell grants are `SHA-256` of the canonicalized absolute path bytes after Unicode NFC normalization. Symlinks are followed during canonicalization. On case-insensitive filesystems the on-disk casing is preserved; Locket does not lowercase paths. Two `locket.toml` files at paths that canonicalize to the same bytes hash identically.

`locket allow` operates on the project root directory, not the current working subdirectory. Running `allow` from any descendant of the project root grants the root, and any later `cd` within the same project root retains the grant. `locket allow` requires the current root hash to be trusted; if it is not, the command fails with `ProjectRootNotTrusted` before any grant is created.

## CLI Contract

This section describes the full CLI surface.

Secret names must use portable environment variable syntax by default: `^[A-Z_][A-Z0-9_]*$`. Non-portable names are rejected.

Profile names must match `^[a-z][a-z0-9_-]{0,63}$` so they appear unambiguously in `lk://profile/KEY` references and on every surface. Reserved profile names: `_default` (reserved for tool internals).

Secret paths provide a reusable, SSM-like namespace above project scope. A canonical secret path starts with `/`, contains slash-separated portable path segments, and identifies one logical secret independently of any project that consumes it. Examples: `/personal/github/token`, `/work/acme/aws/dev/db-password`, and `/shared/npm/publish-token`. The underlying secret value and per-version DEK live once under that path; projects attach links/aliases to consume it as local environment variable names. Project-local secrets continue to use portable `KEY` names and remain private to the current project/profile.

Core commands:

```bash
locket init [--name <name>] [--profile <name>] [--recovery-code]
locket identity init
locket set <KEY> [--source user-local|machine-local|team-managed] [--description <text>] [--owner <name>] [--tag <tag>] [--required]
locket secret put <PATH> [--description <text>] [--owner <name>] [--tag <tag>]
locket link <PATH> <KEY> [--profile <name>] [--source user-local|machine-local|team-managed]
locket get <KEY>
locket get <KEY> --reveal
locket get <KEY> --copy
locket rm <KEY> [--source user-local|machine-local|team-managed]
locket purge <KEY> [--source user-local|machine-local|team-managed] [--version N | --all-versions]
locket list [--all]
locket lock
locket unlock [--verify-user]
locket passkey register
locket passkey list [--all]
locket passkey remove <passkey>
```

`locket identity init` creates or verifies the machine/user-scoped local identity: OS keychain master key, local device private keys, passphrase fallback when needed, and the local recovery envelope. It displays the recovery code only when creating a new local identity. Re-running it on a machine with a valid identity is idempotent and never creates project records.

`locket init` is atomic: either `locket.toml`, local store project records, trusted root, default profile, project/profile keys, local identity bootstrap when needed, `.gitignore` changes, `.env.example` block, and audit row all succeed, or the operation rolls back every Locket-owned change it can safely remove. Default init does not force an offline recovery-code ceremony for every new project; pass `--recovery-code` to create and display one during setup, or run `locket recovery rotate` later while the vault is still accessible. If a local identity already exists, `init` reuses it and must not create a project-specific master key or project-specific recovery code. If `locket.toml` already exists and its `project_id` matches an existing local project, `init` exits successfully with a notice, writes no new rows, and never re-displays the recovery code. If a prior failed init left `locket.toml` without a matching local store project record, the next `locket init` treats that file as resumable partial state: it validates the file, completes missing store/key/profile setup, and either commits the full init or leaves the file unchanged with a typed error.

`locket secret put <PATH>` creates or rotates a reusable global secret under the canonical path. The value is stored once with its own per-version DEK and path-bound metadata. `locket link <PATH> <KEY>` records that the current project/profile may consume the global secret as local secret name `KEY`; links may have project-specific source, profile, policy, and env-mapping metadata. Linking never copies plaintext values, private device keys, or local identity master key material into the project directory. `locket get <KEY>` resolves local project secrets first according to source precedence, then resolves linked global paths only when the active policy/profile grants that link.

`locket set <KEY>` creates version `1` for a selected source and fails with `SecretAlreadyExists` if that `(profile, key, source)` already exists with `SecretState::Active`. If the row exists with `SecretState::Deleted`, `set` fails with `SecretDeleted`; it must not silently reactivate tombstoned history. Reactivation requires an explicit future restore command, not v1 `set`. Secret values are collected only through a secure no-echo TTY prompt, an explicitly configured secure editor flow, or piped stdin when stdin is not a TTY. v1 has no `--value` flag and does not accept secret values through argv, environment variables, shell history-friendly prompts, or logs. If stdin is not a TTY, exactly one UTF-8 secret value is read from stdin; empty input, multiple NUL-separated values, or no input fails with `ConfigError`. If stdin is a TTY and no secure prompt/editor is available, `set` fails closed. Metadata flags populate `SecretMeta` at creation time; `--tag` may be repeated. Updating an existing active source requires `locket rotate <KEY> --source <source>`. Without `--source`, `set` targets `user-local` but refuses to proceed when the same logical key already exists in another source, forcing the user to choose an explicit override source. `team-managed` writes require an appropriate team role.

`locket get <KEY>` resolves the active source by the source precedence rules. `locket list` shows active secrets and all active sources for each logical key so overrides are visible. `locket list --all` also includes deleted sources and deprecated version counts with state labels; tombstoned secrets are hidden from the default list and from `.env.example`.

`locket rm <KEY>` tombstones the selected source in the target profile by setting `SecretState::Deleted`, setting `SecretMeta.deleted_at = now`, and preserving encrypted history. `locket purge <KEY>` is the destructive operation: it permanently removes selected encrypted value versions and keyed fingerprints for the selected source after typed confirmation of the profile, source, secret name, and version scope. `purge --version N` on an active source may target only versions already in `SecretVersionState::Deprecated`; it must not purge the current version of an active source. `purge --version N` on a deleted source may target `Current` or `Deprecated` versions because the source is already retired. Targeting an already `Purged` version is an idempotent metadata-only no-op: it exits successfully, prints an already-purged notice, and writes no new `PURGE` row. `purge --all-versions` requires the source to already be `SecretState::Deleted`; it purges every encrypted version for the selected source and keeps metadata tombstones for audit/history. The `secrets` row remains `Deleted`; `secret_versions` rows remain present with `state = Purged` and `purged_at` set, while blobs and keyed fingerprints are removed. Purge requires Owner or Maintainer role for team-managed secrets and local ownership for user/machine-local secrets. If more than one source exists for a key, `rm` and `purge` require `--source`; they do not silently delete whichever source currently wins precedence. Audit rows remain metadata-only and record `PURGE`; no purge flow prints or logs the value.

`locket lock` and `locket unlock` operate on the local agent if it is running and on the direct CLI process otherwise. `locket unlock` performs OS keychain unlock or passphrase fallback; with the agent running it caches the unwrapped keys for the configured TTL, and without the agent it unwraps only for the current CLI invocation. `locket unlock --verify-user` additionally requires local user verification through the configured platform prompt, hardware key, or passphrase fallback before unwrapping keys. `locket lock` clears agent-held keys and live grants; without the agent it is a no-op that exits successfully and writes a `LOCK` audit row only when keys were actually cleared.

`locket passkey register` registers a platform authenticator or hardware authenticator only for optional CTAP2/WebAuthn PRF key-wrapping or explicit authenticator identity flows. It requires fresh local user verification before registration, verifies the platform supports the requested PRF/hmac-secret or identity capability, stores only public credential metadata in `passkey_credentials`, records backup eligibility/state when the platform exposes it, and writes a `PASSKEY_REGISTER` audit row. If the platform cannot provide the required PRF/hmac-secret capability, registration fails with `ConfigError`; if the verification ceremony fails, registration fails with `LocalUserVerificationFailed`. Locket must not silently register a weaker approval-only credential for a key-wrapping request.

`locket passkey list` displays active registered authenticators: label, credential id prefix, transports, PRF/key-wrapping capability, backup eligibility, backup state, creation date, and last-used date. `locket passkey list --all` also includes revoked credentials with `revoked_at`. Listing never displays private key material, biometric data, raw credential payloads, or full credential ids by default.

`locket passkey remove <passkey>` accepts a passkey label or credential id prefix. It requires fresh local user verification through the configured platform prompt, hardware key, or passphrase fallback, shows the credential metadata that will be revoked, and requires typed confirmation of the label or credential id prefix. Removal is revocation, not hard deletion: Locket sets `PasskeyCredential.revoked_at = now`, excludes the credential from future approval/key-wrapping flows, preserves metadata for audit/history, and writes a `PASSKEY_REMOVE` audit row. Removing a PRF key-wrapping credential must not delete or rewrite existing recovery envelopes; recovery-code support remains mandatory. Locket refuses removal when it would leave a policy-required gate with no usable verification method and no configured recovery/passphrase fallback.

Profiles:

```bash
locket profile create dev
locket profile list
locket use dev
locket profile mark-dangerous prod
locket profile clear-dangerous prod
```

`locket profile create <name>` creates a new profile for the current project. The name must match `^[a-z][a-z0-9_-]{0,63}$` and must not already exist; attempting to create a duplicate name fails with `ConfigError`. Locket generates a new random `ProfileSecret` key and `ProfileFingerprint` key, wraps them under the master-key-derived HKDF wrapping keys, stores the wrapped material in the `keys` table, creates the `Profile` row with `dangerous = false`, and appends the profile id to the owning `Project.profiles`. It writes a `PROFILE_CHANGE` audit row with operation `create`. It does not switch the active profile unless the project has no active/default profile yet; in that first-profile case it also sets the default profile and records that in the same audit metadata.

`locket profile list` displays all profiles for the current project: name, profile id, dangerous flag, active/default indicator, creation date where available, and secret-name counts only. It does not require unlock and does not decrypt or display secret values.

Switching the active profile to a dangerous profile requires typed confirmation of the profile name on every surface, including CLI, UI, tray, shell, and VS Code. `locket use <profile>` does not require unlock; it only updates the persistent default and emits a `PROFILE_CHANGE` audit row. Switching back from a dangerous profile to a non-dangerous profile is allowed without confirmation.

`locket profile mark-dangerous <name>` requires Owner role in team projects and treats solo projects as Owner. It shows the profile name and requires typing that exact profile name before changing the flag. `locket profile clear-dangerous <name>` requires the same Owner role. It is stricter: it first shows a metadata-only summary of policies, command grants, and saved tray actions that will lose dangerous-profile gating, then requires typing `clear <profile-name>` exactly. Both commands write `PROFILE_CHANGE` audit rows with prior and new flag values.

Project maintenance:

```bash
locket
locket status
locket setup [status|agent|share]
locket new --from-template <name>
locket project trust-root
locket project list-roots
locket project untrust-root <root-hash>
locket emit-example
locket completion <shell>
```

Bare `locket` behaves as `locket status`. It shows active project, active profile, lock state, agent state, running session count, scan warning count, trusted-root state, and one next suggested action if setup is incomplete. `locket setup` is a metadata-only guided entry point for local development: without a project it prints the exact `init`, `import`, policy, and agent setup commands to run; inside a project it prints the active project/profile, policy count, and next safe setup commands. `locket setup agent` prints the receiver/maintainer/accept command sequence for paste-friendly agent onboarding, and `locket setup share` points users to the agent invite, team invite, and sealed bundle paths. Setup guidance must not create files, start agents, modify project state, or print secret values. When `privacy.redact_names = true`, status output uses stable local aliases for project, profile, policy, and secret names while preserving counts and next-action guidance. `locket new --from-template <name>` initializes a new project from a local template at `~/.locket/templates/<name>.toml` or a packaged built-in template. Templates may define profiles, expected secret names, metadata, and command policies, but never secret values. v1 templates are local or bundled only; any future remote/community template channel must define signing, provenance, and review rules before it is enabled.

`locket project trust-root` records the current resolved project root hash for the active project after showing the canonical path and requiring confirmation. If the current root is already trusted, it exits successfully with a notice and updates `last_seen_at` without creating a duplicate root row. `locket project list-roots` prints trusted root hashes, display paths where known, creation timestamps, and last-seen timestamps; it never prints secret values. `locket project untrust-root <root-hash>` requires typed confirmation of the root hash, removes durable trust for that root, revokes live grants bound to that root, invalidates shell/editor grants for that root, writes a `TRUST_ROOT` audit row with removal metadata, and prevents new secret access from that path. It does not terminate already spawned child processes because their environments are already outside Locket's control.

`locket emit-example` regenerates `.env.example` from active secret names across profiles and sources using the same rules as automatic refresh. It does not require unlock because it reads metadata only. The Locket-managed block markers are exactly `# --- BEGIN LOCKET MANAGED ---` and `# --- END LOCKET MANAGED ---`. If `.env.example` already exists, Locket rewrites only the content between those marker lines when they are present; otherwise it shows a metadata-only summary and requires confirmation before replacing the file. v1 has no `--force` flag for this command and no silent overwrite. Successful emission writes an `EXAMPLE_EMIT` audit row when project context is available. Store or project-resolution failures return the normal typed error and leave the existing file unchanged.

Configuration:

```bash
locket config list
locket config get <key>
locket config set <key> <value>
locket config unset <key>
```

`locket config` manages non-secret preferences stored in `config.toml`. It refuses to write values that match known secret fingerprints or provider-token patterns, rejects keys outside the documented config schema, and writes `CONFIG_UPDATE` audit rows for security-relevant settings such as agent autostart, reveal TTL, update channel, and shell integration.

Execution:

```bash
locket exec --secret DATABASE_URL -- <cmd>
locket exec --all -- <cmd>
locket run api
locket run npm dev
locket env inspect --policy api
locket env docker --policy api -- docker run ...
locket compose run --policy api -- docker compose up
```

`locket run <policy>`, `locket env inspect --policy <policy>`, `locket env docker --policy <policy>`, and `locket compose run --policy <policy>` first resolve the project from the current directory, then merge the deepest matching path scope into the named command policy. This lets a monorepo reuse one policy name, such as `dev`, while exposing package-specific env names only inside `apps/api`, `apps/web`, or another configured subtree. Scope keys are relative to the project root and must not be absolute or contain `..`.

`locket run <runner> <target...>` is a convenience path for common project runners. `npm`, `pnpm`, `yarn`, and `bun` insert `run` when omitted, so `locket run npm dev` executes `npm run dev`; `cargo`, `make`, `just`, `task`, and `python` pass the target directly; `poetry` and `uv` insert `run` when omitted. Runner invocations create an ephemeral command policy with a stable identity such as `npm:dev`, `cargo:test`, or `make:deploy`, then apply the same path-scope and secret-ACL rules as a saved policy.

Secret ACLs under `[secrets.<KEY>]` narrow where named secrets may be delivered. `allow_commands` matches saved policy names and runner identities. `allow_argv` matches structured argv token patterns, where `*` matches inside one token and `**` as a whole token matches the remaining argv tail. `allow_paths` matches project-relative directories or subtrees. If multiple ACL fields are present, all configured dimensions must match; otherwise execution fails closed with `InvalidPolicy` before secret resolution.

`locket env inspect` is metadata-only. It shows the names, sources, conflicts, and policy decisions that would apply to an execution, but it never prints secret values and never emits shell `export` statements. Locket must not support `eval "$(locket ...)"` as a normal delivery path because that would create a global shell export and violate process-scoped injection.

`locket env docker --policy` and `locket compose run --policy` write `RUN` audit rows because they execute a named policy through Docker/Compose delivery. v1 has no ad-hoc Docker helper without a named policy; any later ad-hoc Docker execution path must write `EXEC` using the same metadata rules as `locket exec`. Audit metadata includes delivery mode, Docker context class (`local`, `remote-tcp`, `remote-ssh`, or `unknown`), policy name, argv program, argument count, and injected secret names only.

`locket exec --secret KEY -- <cmd>` is an ad-hoc execution path, not a named policy. It requires an unlocked vault or valid execution grant for the active project/profile, injects only the named key after source resolution, writes an `EXEC` audit row with the key name and source, and fails with `SecretNotFound`, `UnlockRequired`, or `GrantRequired` as appropriate. It does not require a saved command policy.

`locket exec --all` requires an interactive summary of every active-profile secret name that will be injected, then typed confirmation of the active profile name. Dangerous profiles still require the dangerous-profile confirmation path, and policy may additionally require local user verification. Non-interactive `--all` is refused unless a saved command policy explicitly allows equivalent access; the preferred non-interactive surface is `locket run <policy>`.

Agent and shell:

```bash
locket agent start
locket agent status
locket agent stop
locket agent logs
locket shellenv
locket hook
locket allow
locket deny
```

`locket agent start` is idempotent. If a trusted agent for the current user is already running, it exits successfully after printing metadata-only status. If an agent socket or pid file exists but no live trusted process owns it, Locket removes the stale endpoint and starts a fresh agent. If another live or untrusted process owns the endpoint, it fails with `AgentSocketInUse`. Starting the agent does not unlock the vault by itself.

`locket agent status` prints metadata only: running state, agent version, pid, socket or pipe path, lock state, unlock TTL remaining when available, live grant count, active project/profile when a project context is resolved, degraded hardening flags, and last error summary. `locket agent stop` asks the running trusted agent to clear unwrapped keys, revoke live grants, close subscriptions, remove its socket/pipe and pid file, and exit. It writes `LOCK` if key material was held and `AGENT_REVOKE` audit rows for grants revoked because of stop when project context is available. `locket agent logs` prints local redacted agent logs and does not require unlock; detailed log flags and retention live in [operations.md](operations.md).

Import and scanning:

```bash
locket import .env [--profile <name>] [--source user-local|machine-local|team-managed] [--overwrite]
locket scan [path] [--no-gitignore] [--require-known]
locket scan --staged [--require-known]
locket redact file.log [--redact-names]
locket redact --stdin [--redact-names]
locket context [--redact-names]
locket ai-safe [--pattern-only] [--redact-names] -- <cmd>
locket ai-safe --output redacted.log [--redact-names] [--force] -- <cmd>
locket install-hooks
```

`locket import .env` imports into the active profile by default. `--profile <name>` overrides the target profile. Imported secrets are stored as `user-local` by default with `origin = Imported`; `--source <source>` overrides the target runtime source. Duplicate keys are skipped by default with a metadata-only warning. `--overwrite` rotates each duplicate key in the target source, marks the prior version `Deprecated` with no grace window, updates `SecretMeta.last_rotated_at`, and writes `ROTATE` audit rows. When `--overwrite` targets a dangerous profile, import requires typed confirmation of the dangerous profile name before any rotation begins; failure aborts the entire import before decrypting or writing values. Multiline values are rejected by default unless a future explicit multiline mode is added. Invalid names, duplicate keys, `export` prefixes, quoted values, comments, and conflicts must be handled explicitly in the import report without printing values.

Secret values for `set`, `rotate`, and import overwrite prompts must be entered through secure prompt, editor, or non-echo stdin flows only. v1 must not accept secret values as positional arguments, CLI flags, environment variables, shell history-friendly prompts, or debug logs. Metadata flags are allowed on the command line because they are metadata, but they are still validated by the metadata privacy rules in [data-model.md](data-model.md).

Rotation and history:

```bash
locket rotate <KEY> [--source user-local|machine-local|team-managed] [--description <text>] [--owner <name>] [--tag <tag>] [--required|--optional] [--grace-ttl <duration>]
locket meta <KEY> [--source user-local|machine-local|team-managed] [--description <text>] [--owner <name>] [--tag <tag>] [--required|--optional]
locket history <KEY>
locket history <KEY> --profile <profile>
locket diff <profileA> <profileB>
locket diff --since <date-or-rev>
locket copy <KEY> --from <profileA> --to <profileB> [--from-source <source>] [--to-source <source>]
```

`locket rotate <KEY>` updates the selected source by writing a new current version and marking the prior version `SecretVersionState::Deprecated`. Metadata flags update `SecretMeta` in the same transaction as the new encrypted version; omitted metadata fields keep their prior values. `--grace-ttl <duration>` sets `secret_versions.grace_until = now + duration` on the deprecated prior version. Omitting `--grace-ttl` leaves `grace_until` null, so the deprecated version is unavailable for pinned `lk://...@vN` resolution and known-value scan matching immediately after rotation. `rotation.max_grace_ttl` caps the accepted duration; rotation fails with `ConfigError` if the requested TTL exceeds the effective cap. `ROTATE` audit metadata records key name, source, prior version, new version, deprecated prior version, `deprecated_at`, `grace_until`, and metadata changes, never values. If multiple sources exist and `--source` is omitted, rotation fails with a source-selection error before prompting for a value. `locket history <KEY>` is scoped to the active profile unless `--profile` is provided and shows versions grouped by source. If the key exists but has no displayable versions after filters, history prints a metadata-only "no versions" notice and exits `0`; a missing key still fails with `SecretNotFound`. `locket diff <profileA> <profileB>` compares profiles within the same project and reports names, sources, presence/absence, version numbers, and states only. Empty profile-to-profile diffs and `diff --since` ranges with no changes print a metadata-only "no differences" notice and exit `0`. `locket diff --since <date-or-rev>` uses audit log and version history to show metadata-only changes in the active profile since an ISO 8601 date/time or a Git revision; when the argument is not a parseable ISO date, Locket resolves it as a Git revision by invoking `git log -1 --format=%ct <rev>` from the project root using a direct subprocess call with `<rev>` as a separate argument (e.g., `Command::new("git").args(["-1", "--format=%ct", rev])`); Locket must not construct a shell command string from user-provided input to prevent command injection. If not inside a Git repository or the revision cannot be resolved, the command fails with a descriptive error rather than silently using epoch zero.

`locket meta <KEY>` updates description, owner, tags, or required/optional on the selected source's `SecretMeta` without writing a new encrypted blob or `SecretVersion` row. If multiple sources exist and `--source` is omitted, it fails with a source-selection error. It applies the metadata privacy rules from [data-model.md](data-model.md) before writing and refuses control characters, terminal escapes, known secret values when known-value matching is available, and provider-shaped or high-entropy metadata unless a future typed-confirmation override is implemented. It writes a `SECRET_META_UPDATE` audit row with field names, field counts, source, profile, secret name, version, status, and failure reason when applicable; it never stores the description, owner, or tag text in audit metadata. `locket meta` does not update `updated_at` on `SecretMeta`; only `set` and `rotate` do that, since they change the encrypted content. This command exists to avoid forcing a value re-entry just to correct a description or tag.

Audit, backup, and recovery:

```bash
locket audit verify
locket export --sealed --recipient <device-descriptor> [--profile <name> | --all-profiles] [--include-audit] [--output <path>]
locket import-bundle <bundle> [--include-audit] [--accept-incoming | --accept-local]
locket bundle verify <bundle>
locket recover [--force]
locket recovery rotate
```

Diagnostics:

```bash
locket doctor
locket agent logs [--lines N] [--since <timestamp>] [--follow]
locket debug bundle --redacted
```

Team local development:

```bash
locket device init
locket device init --force
locket device pubkey
locket device add <name> --device <device-descriptor>
locket device list
locket device remove <device>
locket team init
locket setup share
locket team invite <name> --device <device-descriptor> --profile dev --role developer [--expires-in <duration>] [--output <path>]
locket team accept <invite.locket>
locket team revoke-invite <invite-id>
locket team members
locket team remove <member>
locket team revoke-device <device>
locket bootstrap
locket doctor
```

`locket device add <name> --device <device-descriptor>` registers a new trusted device for the current user's own identity: it decodes the device descriptor, verifies the combined fingerprint, creates a `Device` record with the given name, and writes a `DEVICE_ADD` audit row. The name must be unique among the member's devices. Owner and Maintainer roles are required for team projects. `locket device add` does not distribute secrets; use `locket team invite` or `locket export --sealed --recipient` to grant the new device profile access.

`locket device remove <device>` removes one of the current user's own registered devices (for example, decommissioning a personal machine). It accepts a device name, device id, or fingerprint, sets `Device.revoked_at = now`, writes a `DEVICE_REVOKE` audit row, and warns that sealed exports addressed to the revoked device sealing public key are no longer safe to distribute. Removing the currently active device of the local machine requires `--force` and re-running `locket device init` on that machine to obtain a fresh device key. For revoking a team member's device, use `locket team revoke-device`.

`locket team invite` sets `TeamInvite.expires_at` from `--expires-in` when provided, otherwise from the default 7-day TTL. The accepted range is 5 minutes through 30 days; project policy may lower the maximum but may not raise it above 30 days. Invite creation fails with `ConfigError` if the requested expiry is outside the effective range. The default invite output path is `locket-invite-<utc-timestamp>.locket-invite`; it intentionally omits the teammate name and invite id. `--output <path>` overrides the destination but Locket must warn before writing a filename that contains obvious email addresses, access tokens, or provider-token-shaped strings.

Local user-verification behavior:

- Passkey CLI behavior is defined in the core command section. Ordinary approval gates use platform local user-verification APIs; passkey registration is only for optional CTAP2/WebAuthn PRF key-wrapping or explicit authenticator identity flows.
- `locket unlock --verify-user` requires local user verification through the configured platform prompt, hardware key, or passphrase fallback before unwrapping local keys.
- Dangerous-profile actions, team invite acceptance, recovery, reveal/copy, and device registration can require local user verification by policy.
- If local user verification fails or is unavailable, Locket falls back only to explicitly configured recovery or passphrase flows; it must not silently downgrade protected actions.

Automation clients:

```bash
locket client create <name> [--storage os-keychain|wrapped-local-file] --action <action> --policy <policy>
locket client add <name> --pubkey <pubkey> --action <action> --policy <policy>
locket client list
locket client revoke <client>
```

Automation clients are optional local identities for tools that need to ask the agent for scoped actions without acting as a human shell. `client create` generates a local Ed25519 keypair and stores the private key according to the selected Locket-managed private-key storage mode; when `--storage` is omitted, the default is `os-keychain` on supported platforms and `wrapped-local-file` only after explicit confirmation. `client create` does not support external storage because Locket would have to print or write a private key outside its managed recovery rules. Tools that own their own private-key storage must generate the keypair themselves and use `client add` to register the public key. Requests use Ed25519 challenge-response over the local agent socket and still require local transport authentication, project context, policy authorization, TTL limits, and audit logging. Client identities are not API keys, do not work against a hosted service, and do not get unrestricted `get secret` access.

Client private key storage:

- `External`: produced only by `client add`; Locket stores only the public key, and the calling tool owns private-key storage and backup.
- `OsKeychain`: Locket stores the client private key in the OS keychain for user-session-local automation.
- `WrappedLocalFile`: Locket stores an encrypted private-key file under the Locket data directory, wrapped by a local keychain key. The wrapped file is not exported in ordinary sealed bundles.
- Recovery restores Locket-managed `OsKeychain` and `WrappedLocalFile` client private keys only when their wraps are included in the local recovery envelope. Externally managed client keys are never recoverable by Locket.
- A `WrappedLocalFile` or `OsKeychain` client key created after the last `locket recovery rotate` will not be present in the recovery envelope and will be silently unrecoverable from that envelope. Locket warns at `client create` time when the local recovery envelope predates the new key; running `locket recovery rotate` after creating a new Locket-managed client key is required to keep the recovery envelope current.

Automation-client action strings are kebab-case and map to `GrantAction` as follows:

| CLI action | GrantAction | v1 client support |
| --- | --- | --- |
| `run-policy` | `RunPolicy` | Allowed; requires at least one `--policy` |
| `resolve-reference` | `ResolveReference` | Allowed only for references authorized by the stored policy scope |
| `scan-known-values` | `ScanKnownValues` | Allowed for scanner integrations that never receive plaintext values |
| `redact` | `Redact` | Allowed for redaction integrations with known-value coverage |
| `prepare-exec` | `PrepareExec` | Not directly grantable; internal to `run-policy` |
| `reveal` | `Reveal` | Not grantable to automation clients in v1 |
| `copy` | `Copy` | Not grantable to automation clients in v1 |
| `export` | `Export` | Not grantable to automation clients in v1 |

For every supported v1 automation-client action, at least one `--policy` flag is required and stored in `AutomationClient.allowed_policies`. Additional `--policy` flags may be repeated; wildcard policy access is not supported. `run-policy` may invoke only the named policies. `resolve-reference`, `scan-known-values`, and `redact` may operate only inside the named command-policy scopes and still must pass the normal core policy checks for requested names. Unsupported action strings fail validation with `InvalidPolicy`.

`locket client list` displays registered automation clients: name, fingerprint (truncated), allowed actions, allowed policies, creation date, last-used date, and revocation date where applicable. Never displays private keys or secret values.

`locket client revoke <client>` accepts a client name or client id. Sets `AutomationClient.revoked_at = now`, writes a `CLIENT_REVOKE` audit row, and rejects any in-flight agent requests from that client. If the client private key was Locket-managed (`OsKeychain` or `WrappedLocalFile`), removes that key material from its live storage location where possible. It does not rewrite the recovery envelope during revoke; revoked-client entries are skipped by `locket recover` and omitted on the next `locket recovery rotate`, which is the atomic recovery-envelope rewrite operation.

Policy authoring:

```bash
locket policy add dev -- pnpm dev
locket policy allow dev DATABASE_URL
locket policy require dev DATABASE_URL
locket policy edit dev
locket policy refresh dev
locket policy delete dev
locket policy doctor
```

Command policy shape:

```toml
[commands.api]
argv = ["pnpm", "dev"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["OPENAI_API_KEY"]
env_mode = "minimal"
override = "locket"

[commands.release]
shell = "pnpm build && pnpm publish"
required_secrets = ["NPM_TOKEN"]
confirm = true
require_user_verification = true
ttl = "30m"
allow_remote_docker = false
```

The TOML table key is the policy name. The body must not contain a second `name` field; if present, it is rejected as ambiguous. In the normalized Rust model, `CommandPolicy.name` is populated from the `[commands.<name>]` key after deserialization.

Secret list semantics:

- `required_secrets = [...]` marks a subset of allowed secrets that must exist before spawn.
- `optional_secrets = [...]` marks authorized secrets that are injected only when present.
- `secrets = [...]` is not part of the v1 policy schema. Locket is a new app, so there is no shorthand compatibility form to preserve; policy files using `secrets` fail validation with `InvalidPolicy`.
- The normalized `allowed_secrets` set is `required_secrets ∪ optional_secrets`.
- A name may not appear in both required and optional sets after normalization.

Serde mapping must make the reserved TOML key explicit: the Rust field `override_behavior` serializes and deserializes as `override`, not as `override_behavior` or `override_mode`.

Policy TTL and gates:

- `allow_remote_docker` defaults to `false` when omitted. It only affects Docker/Compose helpers; ordinary `locket run` and `locket exec` ignore it. When true, Docker/Compose policies still require typed confirmation before delivering secrets to a remote Docker context.
- `ttl` controls the live agent grant duration for this policy's `RunPolicy`, `PrepareExec`, and `ResolveReference` operations. It does not change the agent unlock-cache TTL, clipboard/reveal TTL, or deprecated-version grace windows.
- If omitted, the default policy grant TTL is 15 minutes. The maximum policy TTL is 8 hours unless a project config lowers it.
- `confirm = true` requires typed confirmation of the policy name after showing a metadata-only execution summary.
- `require_user_verification = true` requires local user verification after typed confirmation and before any secret values are resolved.
- When both `confirm` and `require_user_verification` are true, both gates are required; local user verification does not satisfy typed confirmation.
- If either gate fails, execution stops before decryption, no child process is spawned, and a denied `RUN` or `EXEC` audit row is written when project context is available.

Command parsing must avoid shell expansion unless the policy explicitly uses `shell`.

## Onboarding Flows

Greenfield flow:

1. User runs `locket init`.
2. Locket creates `locket.toml` with a `name` defaulting to the current directory name (or the value supplied with `--name`), initializes the encrypted store, creates the default profile named `dev` (or the name supplied with `--profile`), writes safe `.gitignore` entries, and skips the recovery-code ceremony unless `--recovery-code` was requested.
3. User runs `locket set DATABASE_URL`.
4. Locket prompts securely, encrypts the value, stores the keyed fingerprint, writes an audit row, and updates `.env.example`.
5. User runs `locket exec --secret DATABASE_URL -- pnpm dev` or creates a policy and runs `locket run dev`.
6. Locket injects only the authorized secret into the child process.

Dotenv migration flow:

1. User runs `locket init`.
2. User runs `locket import .env`.
3. Locket parses the file, encrypts values, stores keyed fingerprints, writes audit rows, updates `.env.example`, and ensures `.env` is ignored.
4. Locket offers a name-level parity check comparing names in `.env` to names in the active profile. It must not run the user's application automatically because application commands can have side effects.
5. If parity is acceptable, Locket prompts the user to delete `.env`.
6. Locket never deletes `.env` without explicit confirmation.
