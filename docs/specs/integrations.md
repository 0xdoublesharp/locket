# Shell, Editor & Git Integrations

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Shell Integration

Shell integration is required for Locket to replace dotenv workflows rather than merely wrap commands.

Commands:

```bash
locket shellenv
locket hook
locket allow
locket deny
```

Behavior:

- `locket shellenv` emits an rc snippet for bash, zsh, and fish. Shell detection uses `$SHELL` first, then the running process name from `$0`, then falls back to bash. An explicit `--shell <bash|zsh|fish>` flag overrides auto-detection. The emitted snippet is idempotent when sourced multiple times and contains no secret values, grant tokens, or lock-state information.
- The prompt indicator shows project, profile, and lock state, for example `my-app · dev · 🔒` or `my-app · dev · 🔓`.
- When `privacy.redact_names = true`, the prompt indicator uses stable local aliases instead of project and profile names, for example `project-1 · profile-1 · 🔒`.
- `locket hook` installs a direnv-style directory hook that detects `locket.toml` and asks the agent for a per-shell grant.
- `locket allow` records durable directory consent for the project-root directory plus active profile in `directory_grants` after unlock. The live shell grant remains in agent memory, is TTL-bound, and can be recreated from durable consent only after the agent revalidates peer credentials and project context.
- `locket allow` requires the current root hash to be trusted; running it from an untrusted root fails with `ProjectRootNotTrusted` before any grant is created or written.
- Directory grants are profile-scoped. After `locket use <profile>` changes the active profile, the shell hook requests a new live grant for the now-active profile. If no `directory_grants` row exists for that profile and project root, the hook enters `GrantRequired` and prompts the user to run `locket allow` again. Grants for prior profiles remain valid only when that prior profile is active again; they are never reused across profiles.
- `locket deny` revokes the directory grant for the project root nearest the current directory and the active profile; it does not operate on arbitrary subdirectories. `locket deny --all` revokes every directory grant for that project across all profiles.
- No plaintext secret values are written to disk by shell integration.
- Shell grants are TTL-bound and tied to peer credentials, process ancestry where available, project id, profile id, and directory hash.

The shell hook must never silently inject all secrets into the shell. It may expose status and allow `lk://` resolution or `locket run` without repeated unlock prompts.

Component checks:

- Shell rc snippets contain no secret values or grant tokens.
- Directory changes do not auto-grant secrets without prior `allow`.
- Revoked or expired shell grants prevent subsequent secret resolution.

## VS Code Extension

The VS Code extension is a first-class local developer surface backed by the agent.

Features:

- Status-bar item showing project, profile, lock state, and scan warnings.
- When `privacy.redact_names = true`, the status-bar item and notifications show local aliases/counts rather than exact project, profile, policy, or secret names.
- Command palette actions for unlock, lock, switch profile, run policy, scan workspace, reveal/copy with gating, and open audit view.
- Reference completion for `lk://` URIs in `.env.example`, JSON, TOML, YAML, shell scripts, and source files.
- Diagnostics for `process.env.KEY` and similar references when `KEY` is missing from the active profile, and diagnostics for pinned `lk://...@vN` references that target deprecated versions near grace expiry or past grace expiry.
- Integrated terminal auto-binds to the agent and current workspace grant.
- Gated reveal through a webview that uses short-lived data and does not persist plaintext.

Explicit non-goals:

- No secret values in extension settings.
- No secret values in `globalState`, `workspaceState`, mementos, logs, telemetry, or workspace files.
- No project-specific remote calls, marketplace telemetry enrichment, or language-service requests containing secret names, policy names, `lk://` references, workspace paths, or scan findings.
- No standalone extension vault implementation. The extension is a thin client over the agent.

Component checks:

- Extension state contains only project/profile/status metadata.
- Gated reveal expires and clears webview state.
- Diagnostics never require decrypting secret values; deprecated-version warnings are derived only from metadata.

## Git Integration & Pre-Commit

`locket init`, `locket import`, and `locket team accept` must ensure `.gitignore` contains:

```text
.env
.env.*
.locket.local
.locketignore
```

Locket generates empty placeholders in `.env.example` for the union of active names across project profiles, including active shared-link aliases.

- Locket updates the block delimited by `# --- BEGIN LOCKET MANAGED ---` and `# --- END LOCKET MANAGED ---`. It preserves the surrounding bytes and line endings. Assignments outside the block count as documentation, including `export NAME=` and `# NAME=`.
- `set`, `rotate`, `rm`, `purge`, `import`, `copy`, `generate`, `link`, `unlink`, `promote`, and `team accept` refresh the managed block, unless `example.auto_refresh = false` is set. `locket.toml` overrides `config.toml`. An unmanaged file stays untouched. If refresh fails after a vault mutation commits, the command reports a metadata-only warning on stderr and the mutation succeeds.
- A tombstoned secret stops contributing its name. The name remains if another active source, profile, or link still provides it.
- `locket emit-example` creates or refreshes the managed block on demand. For an unmanaged template it appends the block. Use `--replace` with typed confirmation to replace the whole unmanaged file.
- Generated entries contain names and empty placeholders. Keep project documentation and sample settings outside the managed block.


Pre-commit integration:

```bash
locket install-hooks
```

`locket install-hooks` installs a pre-commit hook that runs:

```bash
locket scan --staged
```

Hook policy:

- Block commits on known-secret matches.
- Warn on high-entropy strings and common provider-token patterns.
- When the vault or agent is locked, the default hook still runs pattern, entropy, provider-token, and `.env` checks, warns that known-value matching was skipped, and exits according to those available checks.
- Projects that require known-value coverage may install or configure the hook to run `locket scan --staged --require-known`; in that mode developers must keep the agent unlocked before committing, and a locked vault fails the commit with `UnlockRequired`.
- Never print secret values in hook output.
- Allow explicit bypass only through normal Git hook bypass mechanisms, not a Locket-specific hidden override.
- Hook installation and replacement write a `HOOK_INSTALL` audit row when project context is available.
- The pre-commit hook block markers are exactly `# --- BEGIN LOCKET PRE-COMMIT ---` and `# --- END LOCKET PRE-COMMIT ---`. When `.git/hooks/pre-commit` does not exist, `locket install-hooks` creates it with that marked Locket block. When a Locket-managed block already exists, installation is idempotent and rewrites only that block without confirmation. When a non-Locket hook exists and no Locket block is present, Locket shows a preview, requires typed confirmation of the project name, and prepends its marked block while preserving the existing hook content. It must not silently replace or discard an existing user hook.

Scanner ignore behavior:

- Scanner respects `.gitignore` for repository scans unless `--no-gitignore` is provided.
- `.locketignore` can suppress paths or patterns for Locket scans.
- Inline suppression comments are allowed for high-entropy findings only, not known-secret matches.
- Inline suppression markers are case-sensitive comment fragments anywhere on a line. The canonical marker family is the `locket-suppress*` directives defined in `scan-redaction.md` (line-level `locket-suppress: <reason>`, block-level `locket-suppress-block-start: <reason>` ... `locket-suppress-block-end`, and file-level `locket-suppress-file: <reason>` within the first five lines). See `scan-redaction.md` lines 80-100 for the full directive grammar, reason-length bounds, and audit semantics. Provider-token, `.env` file, and known-secret matches always pass through.
- Suppressed findings are recorded as metadata-only `SCAN` audit rows with status `SUPPRESSED` when project context is available. Each row includes path label, line, column, rule id, reason, and scope (`tree` or `staged`); it never includes the matched value.

Scan scope:

- `locket scan` with no path scans the project working tree rooted at the nearest `locket.toml`.
- `locket scan <path>` scans an arbitrary file or directory and still uses project context when run inside a Locket project. When run outside any project (no `locket.toml` found in any parent directory), only pattern, entropy, provider-token, and `.env` detection run; known-value detection is skipped with an explicit notice. `--require-known` fails with `ProjectNotFound` when no project context is available.
- `locket scan --staged` scans staged Git content only and requires a Git worktree. If no `.git` directory or Git worktree marker is found in any ancestor of the project root/current directory, it fails with `ConfigError` and exit code `64`.
- Pattern, entropy, provider-token, and `.env` detection run while locked. Known-value detection checks active secret versions, deleted-source current versions that still have blobs, and deprecated versions whose grace TTL has not expired; expired deprecated and purged versions are excluded by default.
- `--require-known` fails with `UnlockRequired` when known-value coverage cannot run because the vault is locked or unavailable.
