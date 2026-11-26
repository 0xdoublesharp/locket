# Runtime, References & Secret Lifecycle

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Runtime Execution

Locket must support process environment injection for ordinary apps, Docker, and Docker Compose without requiring Locket to become the only source of local configuration.

Default argv injection mode:

```rust
Command::new(argv[0])
    .args(&argv[1..])
    .env_clear() // strict mode
    .envs(allowed_safe_env)
    .envs(resolved_secrets)
```

Rules:

- Default command policies use `env_mode = "minimal"`: inherit only the safe allowlist and inject resolved Locket secrets.
- `env_mode = "strict"` uses `env_clear()` and injects only explicitly inherited variables plus Locket secrets.
- `env_mode = "merge"` inherits the parent environment, then overlays authorized Locket secrets according to the precedence rules below.
- `env_mode = "passthrough"` inherits parent environment and resolves only explicit `lk://` references; it is useful when another tool owns most configuration.
- Inject only into the child process.
- Never mutate the parent process environment.
- Zeroize decrypted secret material after spawn setup.
- Record an audit event for execution.
- Refuse command execution if policy resolution fails.
- Treat environment variables as a compatibility transport, not a perfect isolation boundary.
- Never globally export secrets into the user's shell.

Environment-variable injection can expose secrets to the child process, subprocesses it spawns, crash dumps, debug tooling, or platform-specific process inspection. This is acceptable for compatibility but must be documented. Higher-security delivery modes should use stdin, ephemeral file, or socket/agent delivery where the target tool supports it.

Conservative env allowlist:

```text
PATH
HOME
USER
SHELL
TMPDIR
LANG
LC_*
TERM
CI
```

Command policies must support:

```toml
[commands.migrate]
argv = ["pnpm", "prisma", "migrate", "deploy"]
required_secrets = ["DATABASE_URL"]
inherit_env = ["PATH", "HOME", "NODE_ENV"]
confirm = true
ttl = "30m"
env_mode = "minimal"
override = "locket"
allow_remote_docker = false
```

Environment precedence:

1. Base environment from `env_mode`.
2. Explicit `inherit_env` allowlist.
3. External env sources declared in policy, if any.
4. Locket secrets authorized for the command.

Default conflict behavior is `override = "locket"`: authorized Locket secrets override existing variables with the same name inside the child process only. Policies may set `override = "preserve"` to keep existing variables and inject only missing Locket names, or `override = "error"` to fail when a name conflict exists. Conflict metadata must include names only, never values.

External env compatibility:

- Locket may coexist with `.env`, shell exports, Docker Compose `environment`, Docker Compose `env_file`, IDE-provided env, direnv, language-specific env loaders, and platform-specific local config.
- Locket must not edit, delete, or rewrite external env files except `.env.example` and explicit migration flows.
- `locket run` must print a metadata-only warning when a Locket secret name conflicts with an existing env var and the policy does not explicitly choose an override mode.
- `locket env inspect --policy <name>` prints names, sources, conflicts, and final injection decisions only. It is a diagnostic command, not an export mechanism.
- Secret ACLs are evaluated after command policy and path-scope merging but before external env resolution, agent grants, or value decryption. If a requested secret has a `[secrets.<NAME>]` ACL and the active command identity, structured argv, or project-relative path does not satisfy every configured ACL dimension, execution fails with `InvalidPolicy` and no secret values are read. ACL denial metadata must name only the command identity and denied secret names.

Docker and Compose:

- `locket env docker --policy <name> -- docker run ...` injects authorized secrets into the `docker run` process environment and adds `--env KEY` or equivalent safe arguments so Docker reads values from its own environment without placing secret values on the command line.
- `locket compose run --policy <name> -- docker compose up` injects authorized secrets into the Compose invocation environment so Compose variable interpolation and service `environment` entries can consume them.
- Locket must not write plaintext `.env` files for Compose by default.
- Docker and Compose are not isolation boundaries. Injected environment variables may be visible to the Docker daemon, container metadata, `docker inspect`, process listings inside the container, crash dumps, and any process with Docker daemon access. Locket must show this warning in policy doctor output for Docker/Compose policies and record only metadata in audit rows.
- Locket must detect the active Docker context where practical. Remote Docker contexts, TCP Docker hosts, and SSH Docker hosts are refused by default for secret injection because they deliver local secrets to another machine; a policy must explicitly set `allow_remote_docker = true` and require typed confirmation before remote Docker injection is allowed.
- Docker/Compose helper invocations with a named policy write `RUN` audit rows. v1 has no ad-hoc Docker/Compose execution path without a named policy; any later ad-hoc Docker/Compose execution path must write `EXEC`. Audit metadata includes delivery mode, Docker context class, policy name when present, argv program, argument count, and injected secret names only.
- If a tool requires an env file, Locket may create an ephemeral env file in a secure temp directory with a randomized filename, `0700` parent permissions, and `0600` file permissions; pass it to the child process; delete it immediately after startup/exit according to policy; and audit the file delivery mode. The path must never be inside the project tree by default. Ephemeral env files are compatibility fallbacks, not the default, and Locket must warn that normal filesystem deletion is not a cryptographic secure erase guarantee.
- Docker/Compose support must preserve non-Locket variables supplied by the user, shell, Compose file, or `env_file` according to the selected `env_mode` and `override` policy.
- `locket compose run` must support `--project-directory`, `--profile`, and pass-through Compose arguments after `--`.

Secret precedence:

1. Machine-local secret in the active profile.
2. User-local secret in the active profile.
3. Shared link in the active profile, resolved from the local Global Vault.
4. Team-managed secret in the active profile.

Precedence applies when the same secret name exists in the same profile with different sources. Both `locket run` and `locket exec` deliver a selected shared link under its local alias. The consuming project and the Global Vault must each be unlocked in the agent before delivery. A locked vault causes `UnlockRequired` with the unlock command for that vault. Team bundles default to team-managed values and can include user-local and machine-local values when explicitly requested. Global Vault links stay local.

Required secrets:

- A policy can mark secrets as required or optional.
- Missing required secrets fail before process spawn and list missing names only.
- `locket bootstrap` and `locket policy doctor` validate required secrets for configured commands.
- Optional secrets are injected only when present and authorized.

Component checks:

- `locket exec -- <cmd>` injects no secrets by default.
- `--secret KEY` injects only that key.
- `--all` injects active-profile secrets only after audit and required confirmation.
- Policy `argv` commands execute without shell expansion.
- Policy `shell` commands are explicit and audited as shell execution.
- `override = "preserve"` never overwrites an existing environment variable.
- `override = "error"` fails before spawn when a conflict exists.
- Docker and Compose helpers do not print plaintext values and do not write persistent env files.
- `inherit_env` augments the `env_mode` base allowlist; it never replaces or shrinks the base. To run with no inherited environment, set `env_mode = "strict"` and leave `inherit_env` empty.
- `ExternalEnvSource::Parent` lets a policy explicitly consume the calling process's environment as a named layer for diagnostic and override logic. It re-injects only names within the policy's normalized `allowed_secrets` set and must not expose names outside that set to the child process or to audit metadata. `ExternalEnvSource::File(path)` reads variable names from a `.env`-style file and passes the values through unchanged; Locket never imports, logs, audits, fingerprints, or persists those values unless the user separately runs `locket import`. The path must be canonical, must reside within the project root or a Locket-managed directory, and must not be a symlink that resolves outside those boundaries; paths failing validation cause policy execution to fail with `InvalidPolicy`. Because file sources reintroduce plaintext file dependency, `locket policy doctor` must warn on every `ExternalEnvSource::File` use and recommend migration into Locket-managed secrets. `ExternalEnvSource::Compose` resolves variables by shelling out to `docker compose config --format json` from the project root (or from `--project-directory` when that flag is present), parsing the top-level `environment` map from the resulting JSON, and using those name/value pairs as the Compose layer; if `docker compose` is not in `PATH` or the command fails, the policy execution fails with a descriptive error rather than silently skipping the source. Note that `docker compose config` expands env-file contents and interpolated variables, so the Compose layer may include values from `.env` files read by Compose; Locket records only names in audit metadata for this source. `ExternalEnvSource::Ide` accepts variables published by the VS Code extension's terminal integration.
- `ExternalEnvSource::Ide` uses a non-secret `LOCKET_IDE_ENV_SESSION=<uuid>` environment variable injected into integrated terminals. The VS Code extension publishes that terminal session's name/value environment map to the agent over the local socket with the same TTL as the terminal grant. The agent uses it only for the matching project/profile/session, never persists the values, and records only names and source labels in audit metadata.
- Path-scoped environment sets from `[paths."<relative-path>"]` are resolved before external sources and Locket secret lookup. They do not provide values themselves; they extend the command policy's allowed/required name set, optionally select a profile, and then normal policy source precedence applies. The matching path name may be rendered in diagnostics, but audit metadata remains names-only and value-free.
- Each external source layers between `inherit_env` and Locket secrets per the precedence list and is recorded as a metadata-only audit entry.

Exec audit metadata must include the command policy name where present, the argv program (`argv[0]`) and argument count for ad-hoc `locket exec` invocations (the full argv is never stored because it may contain user-pasted literal values), profile id, exit status where available, and the list of secret names injected or resolved. It must never include secret values.

### Child output

`locket run` and `locket exec` default to `run.redact_output = "auto"`. In this mode, both output streams go through a streaming filter when either stdout or stderr is redirected or captured. When both streams are terminals, the child inherits them directly. Set `run.redact_output` to `"always"` to filter all output or `"never"` to inherit the streams.

Set the user default with `locket config set run.redact_output <auto|always|never>`. A project's `[run]` table in `locket.toml` overrides that setting. `LOCKET_REDACT_OUTPUT` overrides both and also accepts `1` and `true` for `always`, or `0` and `false` for `never`. The mutually exclusive `--redact-output` and `--no-redact-output` flags take precedence over the environment. For `locket run`, `--egress-host` always enables strict redaction. See [scan-redaction.md](scan-redaction.md) for what each mode filters.

CLI agent requests for execution use a 15-second deadline for ordinary requests and a 120-second deadline for unlock. During interactive unlock the CLI prints a notice while it waits.

## Reference URIs (`lk://`)

Locket must support first-class local reference URIs:

```text
lk://profile/KEY
lk://profile/KEY@v3
lk://profile/KEY?source=user-local
lk://profile/KEY@v3?source=team-managed
lk://dev/DATABASE_URL
lk://prod/STRIPE_SECRET_KEY@v12
```

Purpose:

- Allow third-party tools to carry secret references in ordinary string fields without storing secret values.
- Support `.env.example`, package scripts, config files, `tauri.conf.json`, JSON/TOML/YAML files, and editor completions.
- Resolve references at execution time through the agent, not by writing plaintext files.

Rules:

- `lk://profile/KEY` resolves to the current version of `KEY` in `profile`.
- When multiple sources exist for the same logical key, source precedence selects the source unless the URI includes `?source=user-local`, `?source=machine-local`, or `?source=team-managed`.
- `?source=imported` is not valid in `lk://` URIs. Import is provenance (`origin = Imported`), not a runtime source; imported values resolve through their stored runtime source.
- `@vN` pins a specific version for controlled compatibility windows after source resolution. For stable long-lived references in projects that use source overlays, include both source and version.
- Pinned `@vN` references resolve current versions normally. They resolve deprecated versions only when `secret_versions.grace_until` is set and still in the future, and resolution emits metadata-only warning/audit fields containing the key name, source, pinned version, and grace expiry. Expired, ungraced, purged, deleted, or unauthorized pinned versions fail closed with `SecretVersionExpired`, `SecretNotFound`, or `AccessDenied` as appropriate.
- Resolution requires project context, profile access, active unlock/grant, and policy authorization.
- Reference strings are safe to commit because they contain names and versions only, never values.
- Invalid or unauthorized references fail closed.
- `lk://` resolution requires the local agent. In agent-less invocations, references are not silently passed through as literal strings; resolution fails with `AgentUnavailable` so a placeholder never reaches the child process. Direct CLI execution paths that require resolved values (e.g., `locket exec --secret KEY`) start the agent on demand or fall back to a single-shot direct unlock when policy permits. `locket run <policy>` also starts the agent on demand when none is running, using the same on-demand startup path; if on-demand startup fails, `locket run` fails with `AgentUnavailable`.

This borrows the ergonomics of `op://` references while remaining local-only and project-policy aware.

## Reveal/Copy

Secret values are hidden by default.

Reveal/copy requires:

1. Active project and profile resolution.
2. OS unlock, passphrase verification, or valid agent TTL grant.
3. Authorization through the core policy layer.
4. Short TTL grant, default 60 seconds.
5. Audit event recording.
6. Frontend, terminal, clipboard, or webview cleanup after TTL expiration.

`locket get <KEY>` returns metadata only. `--reveal` prints the value to stdout after unlock and audit, and requires a TTY unless `--force` is provided. `--copy` writes to the clipboard after unlock and audit, then clears the clipboard after TTL where supported.

Clipboard behavior:

- Clipboard copy must audit the secret name, profile, and TTL, never the value.
- Where supported, Locket must clear the clipboard after TTL only if the clipboard still contains the copied secret value.
- If the platform cannot clear the clipboard reliably, Locket must warn before copying.
- Locket must not persist or attempt to restore the user's prior clipboard contents.
- UI, tray, and VS Code clipboard flows must keep the plaintext only in the smallest possible local scope needed to write the clipboard and verify TTL cleanup. Clipboard values must not enter Redux-like stores, persisted webview state, app telemetry, system notifications, accessibility labels, or structured logs.

Reveal/copy must not:

- Persist plaintext in frontend stores.
- Persist plaintext in VS Code settings or state.
- Write plaintext to logs.
- Place plaintext in long-lived app state.
- Include plaintext in audit rows.
- Include plaintext in crash reports.

## Rotation & History

Commands:

```bash
locket rotate <KEY> [--source user-local|machine-local|team-managed] [--description <text>] [--owner <name>] [--tag <tag>] [--required|--optional] [--grace-ttl <duration>]
locket history <KEY>
locket diff <profileA> <profileB>
locket diff --since <date-or-rev>
locket copy <KEY> --from <profileA> --to <profileB> [--from-source <source>] [--to-source <source>]
```

Behavior:

- `locket rotate <KEY>` writes a new encrypted version for the selected source, updates that source's current version pointer, sets `SecretMeta.last_rotated_at = now`, marks the prior version `Deprecated`, and optionally sets a grace TTL via `--grace-ttl <duration>` (e.g. `--grace-ttl 24h`). `--grace-ttl` sets `secret_versions.grace_until` on the deprecated version, allowing pinned `lk://...@vN` references to keep resolving and scans to keep checking that version until the window expires. Omitting `--grace-ttl` leaves `grace_until` null, expiring the deprecated version immediately for resolution and scan purposes. `rotation.max_grace_ttl` caps accepted grace windows. Metadata flags update `SecretMeta` in the same transaction as the new encrypted version. If multiple sources exist and no `--source` is provided, it fails before prompting.
- `SET` audit events record version `1` for a key. `ROTATE` audit events record every subsequent version. `set` is forbidden after the first active version and also forbidden for a tombstoned `(profile, key, source)` row.
- `locket history <KEY>` shows versions, sources, timestamps, state, `deprecated_at`, `grace_until`, `purged_at`, and audit metadata. It never shows values.
- `locket diff <profileA> <profileB>` shows secret names, sources, presence/absence, current version numbers, current states, and deprecated-version grace differences only. `locket diff --since <date-or-rev>` uses audit log and version history to show metadata-only changes in the active profile since an ISO 8601 date/time or a Git revision. When the argument is not a parseable ISO date, Locket resolves it as a Git revision by shelling out to `git log -1 --format=%ct <rev>` from the project root and using the returned Unix timestamp; if not inside a Git repository or the revision cannot be resolved, the command fails with a descriptive error rather than silently using epoch zero.
- Pinned `lk://profile/KEY@vN` references can continue resolving during a configured grace period if policy allows it.
- Rotation writes one `ROTATE` audit row containing the new version, deprecated prior version, `deprecated_at`, and `grace_until`. It does not emit separate whole-secret deprecation actions.
- `locket copy <KEY> --from <profileA> --to <profileB>` creates version `1` in the target profile/source when the logical key does not exist there, leaving `last_rotated_at = None`. When the target profile/source already exists and is active, copy behaves like a rotation with no grace window: it creates the next version, marks the prior target version `Deprecated`, sets `grace_until = None`, advances the target current pointer, and sets `SecretMeta.last_rotated_at = now`. Copy to a deleted target source fails with `SecretDeleted`. It writes `SECRET_COPY` for the cross-profile copy operation and includes source/target profile names, source/target sources, prior target version when present, and target version in audit metadata. It does not reuse clipboard `COPY`, which is reserved for user clipboard access. When `--from-source` is omitted and profileA has multiple sources for KEY, copy uses the highest-precedence source (machine-local > user-local > team-managed); if multiple sources exist and their precedence is ambiguous, copy fails with a source-selection error requiring an explicit `--from-source`. When `--to-source` is omitted, copy targets the same source as the selected from-source, falling back to `user-local` if that source does not exist in the target profile. Copying within the same profile and same source is rejected; use `locket rotate` instead.
- `locket rm <KEY>` tombstones the selected source in the target profile, sets `SecretMeta.deleted_at = now`, writes an audit row, removes active policy access to that source, and leaves historical metadata/value versions encrypted for audit/history.
- `locket purge <KEY>` permanently deletes selected encrypted value versions and keyed fingerprints for the selected source, but keeps metadata tombstones. It requires typed confirmation of profile, source, key, and version scope, writes a `PURGE` audit row when material is actually purged, and is not reversible. `purge --version N` cannot target the current version of an active source; already-purged versions are successful no-ops with no new `PURGE` row. `purge --all-versions` requires `SecretState::Deleted`.

Component checks:

- History and diff output never contain plaintext.
- Rotated secrets cannot be silently rolled back without an explicit audited operation.
- Expired pinned references fail closed.

## Public defaults and value validation

After existing environment layers and override handling, a permitted
`[variables.<NAME>].default` fills an authorized name only if the final child
environment lacks that name. Defaults never broaden a policy's name set or
bypass path/command/argv ACLs. This fallback applies to ordinary execution and
Docker/Compose injection. The existing unsupported Docker-policy gates still
apply. Values selected from any source are validated against a declared
variable type before spawn; errors name the variable and failed requirement
without printing the value. Missing required names include commit-safe setup
guidance and an explicit `locket set <NAME>` next step.

Metadata-only readiness reports contain names, classification, required state,
source labels, descriptions, setup hints, and warnings. They contain neither
resolved values nor public default strings. Deferred source availability must
remain distinct from a proven ready state. A names-only CI validation result
never proves that a live credential exists or that its value is valid.

Ad-hoc `locket exec` validates the types of its explicitly selected existing
vault values and shows the same browser-prefix warnings. It does not discover
or inject extra variables from contracts or apply saved-command defaults. Use
`locket run <policy>` for a declared command's requirements and public defaults.
