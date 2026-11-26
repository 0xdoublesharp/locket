---
name: using-locket
description: Use when working in a repository that manages secrets with Locket, or when onboarding, importing .env files, linking shared Global Vault credentials, configuring policies, or running commands with Locket-injected secrets.
---

# Using Locket

Locket stores project and Global Vault (`@shared`) secrets locally and injects them into approved commands without placing secret values in agent context, shell history, or tracked files.

## Core rules

- Keep secret values out of prompts, tool output, shell arguments, and logs. Never run `locket get --reveal`, `locket get --copy`, `cat .env`, `env`, `printenv`, `echo $VAR`, or `set -x` on secret-bearing files or shells.
- Use metadata-only commands to inspect state: `locket --version`, `locket context`, `locket status`, `locket list`, `locket env keys <FILE>`, `locket env scan`, `locket parity`, `locket duplicates`, `locket shared usages <KEY>`, and `locket policy doctor`.
- After updating Locket, check `locket agent status` for an agent version mismatch. If the running version differs, ask the user to run `locket agent restart` from their terminal. Restarting clears unlocks and live grants.
- Prefer Locket's MCP tools when the host exposes them (`locket_list_projects`, `locket_discover_secrets`, `locket_get_secret_metadata`, `locket_inspect_env_keys`, `locket_scan_env_files`, `locket_detect_commands`, `locket_import_env`, `locket_find_duplicates`, `locket_list_shared_usages`, `locket_link_secret`, `locket_unlink_secret`, `locket_list_project_policies`, and `locket_generate_secret`). Run `locket mcp config` to print host configuration snippets for Claude, Codex, or generic stdio clients.
- Export `LOCKET_NO_PROMPT=1` in agent shells so interactive passphrase or confirmation prompts fail immediately instead of hanging on a PTY.

## Onboarding a repository

0. Before `locket init`, preview key names with `locket env keys .env` or list workspace dotenv files with `locket env scan`. The scan skips templates and non-dotenv suffixes and prints `locket=yes` or `locket=no`. Use `locket env scan --remaining` for a migration work queue. It lists `staged_project_roots` and `uninitialized_project_roots` and keeps the counts for `migrated`, `staged`, and `uninitialized` projects. `locket import --dry-run` requires an initialized `locket.toml`.
1. Check the installed binary and repository context.

```sh
locket --version
locket context
```

2. Initialize the repository with `locket init`. If `.env.example` already exists without Locket markers, `locket init` preserves it byte-for-byte, and automatic refreshes leave unmarked templates untouched.
3. To adopt an existing `.env.example` later without duplicating documented keys, run `locket emit-example`. Locket appends a managed block containing only undocumented active keys and live `shared-link` aliases. Pass `--replace` only when the user explicitly asks to overwrite the file.
4. Do not run `locket init --recovery-code` inside an agent transcript; recovery codes belong directly in the user's terminal or desktop app.

## Importing `.env` files and linking `@shared` secrets

- Use a local import by default. `--link-shared` links exact matches already stored in `@shared`, and `--promote-duplicates` promotes repeated values across projects into `@shared` and links them back. Run `locket shared list` first to confirm `@shared` is set up. Both flags return `SharedVaultNotInitialized` when `@shared` needs initialization. If a shared import returns `UnlockRequired`, ask the user to unlock the vault. Never silently retry a failed shared import as a local import.
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

1. Preview the local import with `locket import .env --dry-run --json`. If it returns `UnlockRequired`, follow the unlock instructions below before retrying.
2. Import and keep the source with `locket import .env --keep`.
3. Run `locket policy detect` for suggested `locket policy add <name> -- <argv>` commands. Detection uses `packageManager` and parent lockfiles in monorepos and `foundry.toml` in Foundry projects. Give the user the suggested commands and the unlock command for review. Use `locket policy require <name> <KEY>...` to grant each new policy only the secrets its command needs, then have the user approve the policy.
4. Verify the target app or command with `locket run <POLICY>` or a scoped `locket exec` invocation.
5. When the user chooses to archive, run `locket import .env --archive <PRIVATE_DIR> --archive-if-matching --dry-run --json`. Review `archive_consumer_warnings` for Compose files (including shallow subdirectories), Makefiles, `package.json` scripts and `dotenv` dependencies, `Cargo.toml` `dotenvy`/`dotenv` dependencies, and directly invoked local scripts. Compose interpolation warnings name up to 12 overlapping `.env` keys and show how many more matched. A Compose file with no matching keys produces no interpolation warning. Check framework loaders such as Vite, Next.js, and Prisma, and confirm `archive_directory`. Use a private directory outside any Git worktree or ignored by Git for the plaintext backup.
6. Once the preview reports `delete_env: would-archive` and file consumers are addressed, repeat the command without `--dry-run`. To require verification immediately before archiving, run `locket import .env --archive <DIR> --archive-if-matching --verify-policy <POLICY>` with an existing, human-approved policy. Choose a finite check such as `test`, `typecheck`, `build`, or a config check. A long-running server policy like `dev` will hit the verification deadline. Set the deadline with `--verify-timeout <SECONDS>` (60 seconds by default, up to 600). Locket runs the check with vault values and keeps `.env` in place if verification fails or times out. If archiving fails after the import commits, Locket keeps the source in place, exits nonzero, and reports `archive_error` alongside the import summary.

`--archive-if-matching` compares skipped values with the values the app receives under runtime precedence. Filtered keys block archiving. If the preview reports `delete_env: kept`, check `archive_blocked_reason`.

## Running commands safely

- Prefer a narrow saved command policy in `locket.toml` via `locket run <POLICY>`. Use `locket exec` only when an ad-hoc scoped command is appropriate; both `run` and `exec` resolve `shared-link` aliases under the project's local variable name.
- Check `--help`, `--version`, config dumps, and startup diagnostics without secret injection (or with dummy values). CLI frameworks such as Clap can print `[env: KEY=<value>]` in help or usage errors.
- Output redaction defaults to `run.redact_output = "auto"`, which redacts known delivered secrets (8 bytes or longer and encoded variants) when stdout or stderr is captured. Pass `--redact-output` (or `LOCKET_REDACT_OUTPUT=1`) for strict pattern scanning and shorter values, or wrap external commands with `locket ai-safe -- <CMD>`. Use `--no-redact-output` only when the user explicitly needs raw non-secret pipeline output and no `--egress-host` policy is active.

## Handling unlock and human consent boundaries

Agents must never run unlock, auto-approve policies, or stop the daemon. Never pass `--overwrite` or move `.env` manually to bypass a lock.

Stop and ask the user whenever any of these are required:

- **On `UnlockRequired`**, stop and ask the user to unlock from a desktop terminal or Locket Desktop. Give them `locket unlock` for the current project, `locket unlock --project @shared` for the Global Vault alone, or `locket unlock --shared` to include it with the current project. For several projects, give them one command such as `locket unlock --project <p1> --project <p2> --ttl 3600`. On macOS, one Touch ID prompt names all selected vaults, up to eight distinct vaults. Each vault keeps its own unlock TTL and audit entry. `--ttl` accepts 1 to 86400 seconds and overrides `agent.unlock_ttl`, which defaults to 15 minutes. Complete verification and archiving within the unlock window.
- **Dangerous or privileged flags**: Policy approval, `--confirm-dangerous`, `--use-dangerous`, `--force`, `--allow-insecure-argv`, `--allow-uncontained-egress`, `--unlink-all`, `--replace`, and deleting `.env` files.
- **Interactive prompts**: Passphrases, Touch ID, OS keychain dialogs, and recovery codes.
