---
name: using-locket
description: Use when working in a repository that manages secrets with Locket, or when onboarding, importing .env files, linking shared Global Vault credentials, configuring policies, or running commands with Locket-injected secrets.
---

# Using Locket

Locket stores project and Global Vault (`@shared`) secrets locally and injects them into approved commands without placing secret values in agent context, shell history, or tracked files.

## Core rules

- Keep secret values out of prompts, tool output, shell arguments, and logs. Never run `locket get --reveal`, `locket get --copy`, `cat .env`, `env`, `printenv`, `echo $VAR`, or `set -x` on secret-bearing files or shells.
- Use metadata-only commands to inspect state: `locket --version`, `locket context`, `locket status`, `locket list`, `locket env keys <FILE>`, `locket env scan`, `locket parity`, `locket duplicates`, `locket shared usages <KEY>`, and `locket policy doctor`.
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

Always preview imports before writing, keep the source `.env` file until the user chooses to archive or delete it, and reuse `@shared` for repeated credentials such as RPC URLs or provider keys:

```sh
locket env keys .env
locket import .env --dry-run --link-shared --json
locket import .env --link-shared --keep
locket parity
```

- Pass `--link-shared` to link exact matches already stored in `@shared`, or `--promote-duplicates` to promote repeated values across projects into `@shared` and link them back. Both flags fail closed if `@shared` is unavailable or locked.
- `--dry-run` uses the same classification planner as real execution and reports `would_link`, `would_promote`, `linked_names`, `promoted_names`, and `duplicate_matches`.
- When the user chooses to archive the source, use `locket import .env --archive <DIR>` in place of `--keep`. Locket writes a private plaintext backup and removes the source after a complete import with no skipped or filtered keys. Use a directory outside the project or one ignored by Git. Add `--dry-run` to preview without creating a backup.
- To promote, link, or unlink individual secrets after import:

```sh
locket promote RPC_URL --as ALCHEMY_MAINNET_RPC --consolidate-duplicates
locket link RPC_URL ALCHEMY_MAINNET_RPC
locket unlink RPC_URL
locket duplicates --reindex
locket shared usages ALCHEMY_MAINNET_RPC
```

- Shared links stay local in SQLite and never modify `locket.toml`, Team Sync packages, or CI bundles. Before removing a linked `@shared` secret, inspect `locket shared usages <KEY>` and confirm with the user before passing `--unlink-all`.

## Running commands safely

- Prefer a narrow saved command policy in `locket.toml` via `locket run <POLICY>`. Use `locket exec` only when an ad-hoc scoped command is appropriate; both `run` and `exec` resolve `shared-link` aliases under the project's local variable name.
- Check `--help`, `--version`, config dumps, and startup diagnostics without secret injection (or with dummy values). CLI frameworks such as Clap can print `[env: KEY=<value>]` in help or usage errors.
- Output redaction defaults to `run.redact_output = "auto"`, which redacts known delivered secrets (8 bytes or longer and encoded variants) when stdout or stderr is captured. Pass `--redact-output` (or `LOCKET_REDACT_OUTPUT=1`) for strict pattern scanning and shorter values, or wrap external commands with `locket ai-safe -- <CMD>`. Use `--no-redact-output` only when the user explicitly needs raw non-secret pipeline output and no `--egress-host` policy is active.

## Handling unlock and human consent boundaries

Stop and ask the user whenever any of these are required:

- **Vault unlock**: If a command returns `UnlockRequired`, report the locked vault and exact command (`locket unlock` for the project vault, `locket unlock --shared` or `locket shared unlock` for `@shared`, or the Locket desktop app). Never pipe passphrases or loop on unlock.
- **Dangerous or privileged flags**: Policy approval, `--confirm-dangerous`, `--use-dangerous`, `--force`, `--allow-insecure-argv`, `--allow-uncontained-egress`, `--unlink-all`, `--replace`, and deleting `.env` files.
- **Interactive prompts**: Passphrases, Touch ID, OS keychain dialogs, and recovery codes.
