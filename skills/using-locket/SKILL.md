---
name: using-locket
description: Use when working in a repository that manages secrets with Locket, or when onboarding, importing .env files, linking shared Global Vault credentials, configuring policies, or running commands with Locket-injected secrets.
---

# Using Locket

Locket stores project and Global Vault (`@shared`) secrets locally and injects them into approved commands without placing secret values in agent context, shell history, or tracked files.

## Core rules

- Keep secret values out of prompts, tool output, shell arguments, and logs. Never run `locket get --reveal`, `locket get --copy`, `cat .env`, `env`, `printenv`, `echo $VAR`, or `set -x` on secret-bearing files or shells.
- Use metadata-only commands to inspect state: `locket --version`, `locket context`, `locket status`, `locket list`, `locket env keys <FILE>`, `locket env scan`, `locket parity`, `locket duplicates`, `locket shared usages <KEY>`, and `locket policy doctor`.
- After updating Locket, check `locket agent status` for an agent version mismatch. If the running version differs, `locket agent restart` starts the daemon from the current CLI and clears unlocks and live grants.
- Prefer Locket's MCP tools when the host exposes them (`locket_list_projects`, `locket_discover_secrets`, `locket_get_secret_metadata`, `locket_inspect_env_keys`, `locket_scan_env_files`, `locket_detect_commands`, `locket_import_env`, `locket_find_duplicates`, `locket_list_shared_usages`, `locket_link_secret`, `locket_unlink_secret`, `locket_list_project_policies`, and `locket_generate_secret`). Run `locket mcp config` to print host configuration snippets for Claude, Codex, or generic stdio clients.
- Export `LOCKET_NO_PROMPT=1` in agent shells so interactive passphrase or confirmation prompts fail immediately instead of hanging on a PTY.

## Onboarding a repository

1. Check the installed binary and repository context first:

```sh
locket --version
locket context
locket env scan
```

2. Initialize the repository with `locket init`. If `.env.example` already exists without Locket markers, `locket init` preserves it byte-for-byte, and automatic refreshes leave unmarked templates untouched.
3. To adopt an existing `.env.example` later without duplicating documented keys, run `locket emit-example`. Locket appends a managed block containing only undocumented active keys and live `shared-link` aliases. Pass `--replace` only when the user explicitly asks to overwrite the file.
4. Do not run `locket init --recovery-code` inside an agent transcript; recovery codes belong directly in the user's terminal or desktop app.

## Importing `.env` files and linking `@shared` secrets

- Pass `--link-shared` to link exact matches already stored in `@shared`, or `--promote-duplicates` to promote repeated values across projects into `@shared` and link them back. Both flags fail closed if `@shared` is unavailable or locked.
- `--dry-run` uses the same classification planner as real execution and reports `would_link`, `would_promote`, `linked_names`, `promoted_names`, and `duplicate_matches`.
- To promote, link, or unlink individual secrets after import:

```sh
locket promote RPC_URL --as ALCHEMY_MAINNET_RPC --consolidate-duplicates
locket link RPC_URL ALCHEMY_MAINNET_RPC
locket unlink RPC_URL
locket duplicates --reindex
locket shared usages ALCHEMY_MAINNET_RPC
```

- Shared links stay local in SQLite and never modify `locket.toml`, Team Sync packages, or CI bundles. Before removing a linked `@shared` secret, inspect `locket shared usages <KEY>` and confirm with the user before passing `--unlink-all`.

### Staged cutover

1. Preview with `locket import .env --dry-run --link-shared --json`. If the preview returns `UnlockRequired`, follow the unlock instructions below before retrying.
2. Import and keep the source with `locket import .env --link-shared --keep`.
3. Ask the user to run `locket unlock` once from a desktop terminal, adding `--shared` if the app uses shared links. They can also unlock the vaults in Locket Desktop. Complete verification and archiving within the default 15-minute unlock window.
4. Verify the target app or command with `locket run <POLICY>` or a scoped `locket exec` invocation.
5. When the user chooses to archive, run `locket import .env --archive <PRIVATE_DIR> --archive-if-matching --dry-run --json`. Review `archive_consumer_warnings`, and check Makefiles and framework configuration for direct reads of `.env`. Once the preview reports `delete_env: would-archive` and you've addressed file consumers, repeat the command without `--dry-run`. Use a private directory outside the project or ignored by Git for the plaintext backup.

`--archive-if-matching` compares skipped values with the values the app receives under runtime precedence. Filtered keys block archiving. If the preview reports `delete_env: kept`, check `archive_blocked_reason`.

## Running commands safely

- Prefer a narrow saved command policy in `locket.toml` via `locket run <POLICY>`. Use `locket exec` only when an ad-hoc scoped command is appropriate; both `run` and `exec` resolve `shared-link` aliases under the project's local variable name.
- Check `--help`, `--version`, config dumps, and startup diagnostics without secret injection (or with dummy values). CLI frameworks such as Clap can print `[env: KEY=<value>]` in help or usage errors.
- Output redaction defaults to `run.redact_output = "auto"`, which redacts known delivered secrets (8 bytes or longer and encoded variants) when stdout or stderr is captured. Pass `--redact-output` (or `LOCKET_REDACT_OUTPUT=1`) for strict pattern scanning and shorter values, or wrap external commands with `locket ai-safe -- <CMD>`. Use `--no-redact-output` only when the user explicitly needs raw non-secret pipeline output and no `--egress-host` policy is active.

## Handling unlock and human consent boundaries

Stop and ask the user whenever any of these are required:

- **On `UnlockRequired`**, stop and ask the user to unlock once from a desktop terminal or Locket Desktop. Give the command for the locked vault, `locket unlock` for the project or `locket unlock --shared` for `@shared`. Agents must never run an unlock command. Never bypass the lock by stopping the daemon, passing `--overwrite`, or moving `.env` manually.
- **Dangerous or privileged flags**: Policy approval, `--confirm-dangerous`, `--use-dangerous`, `--force`, `--allow-insecure-argv`, `--allow-uncontained-egress`, `--unlink-all`, `--replace`, and deleting `.env` files.
- **Interactive prompts**: Passphrases, Touch ID, OS keychain dialogs, and recovery codes.
