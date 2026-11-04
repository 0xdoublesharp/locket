# Policy Authoring

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Policy Authoring

Policy authoring must be usable from CLI and UI without hand-editing TOML for common cases.

Commands:

```bash
locket policy add dev -- pnpm dev
locket policy allow dev DATABASE_URL
locket policy require dev DATABASE_URL
locket policy edit dev
locket policy refresh dev
locket policy delete dev
locket policy doctor
```

Behavior:

- `policy add` creates a structured `argv` command by default.
- `policy allow` permits optional secret access.
- `policy require` marks a secret as required before spawn.
- `policy edit` opens the configured editor on the policy file or launches the UI editor.
- `policy refresh <name>` approves the current local command, path scopes, and secret ACLs for agent reference resolution after review and typed confirmation of the policy name. It refreshes the audited SQLite index without changing `locket.toml`, and refuses a source change during confirmation.
- `policy delete <name>` shows a metadata-only summary of affected shell hooks, tray actions, automation clients, and VS Code tasks, requires typed confirmation of the policy name, removes the saved policy, revokes live grants for that policy, and writes a `POLICY_UPDATE` audit row with deletion metadata.
- `policy doctor` validates command existence, required secrets, profile availability, dangerous-profile confirmations, and `lk://` references. If the agent is unavailable, it warns that `lk://` reference validation was skipped, lists unvalidated references, and exits with a distinct non-zero status separate from ordinary policy validation failure.
- `policy doctor` reports existing indexes with missing or stale source approval and prints the affected `locket policy refresh <name>` commands. It never approves or refreshes a policy implicitly. Agent availability and unlock failures include the next commands to run.
- UI policy editing must expose argv vs shell mode clearly and warn when shell mode is selected.
- Docker/Compose policy editing must expose `allow_remote_docker` clearly. The default is `false`; enabling it requires typed confirmation because remote Docker contexts deliver local secrets to another machine.
- Monorepos may define path-scoped environment sets under `[paths."<project-relative-directory>"]`. The current working directory is resolved under the project root, the deepest matching path scope wins, and its `required_secrets` / `optional_secrets` are merged into the selected command policy before policy execution, external-env resolution, `env inspect`, Docker, or Compose preparation. A scope may set `profile = "<profile>"` to use that profile for executions from the matching subtree. Path keys must be project-relative and must not contain `..` or absolute roots.
- Projects may define secret-level ACLs under `[secrets.<SECRET_NAME>]`. ACLs never grant access by themselves; they only narrow access already requested by `required_secrets` or `optional_secrets`. Supported fields are `allow_commands`, `allow_argv`, and `allow_paths`. If more than one field is present, every configured dimension must match before the secret can be delivered.

Example:

```toml
[commands.dev]
argv = ["pnpm", "dev"]

[paths."apps/api"]
profile = "dev"
required_secrets = ["DATABASE_URL"]
optional_secrets = ["STRIPE_SECRET_KEY"]

[paths."apps/web"]
required_secrets = ["NEXT_PUBLIC_API_URL"]

[secrets.DATABASE_URL]
allow_commands = ["dev", "npm:dev"]
allow_argv = [["pnpm", "dev"], ["npm", "run", "dev"]]
allow_paths = ["apps/api/**"]
```

Command ACL semantics:

- `allow_commands` matches the saved policy name for `locket run <policy>` and the generated runner identity for adapter invocations such as `npm:dev`, `pnpm:test`, `cargo:test`, or `make:deploy`.
- Explicit `locket exec` uses command identity `exec` and evaluates `allow_argv` against its actual arguments and `allow_paths` against its working directory, including when `--all --force` selects the names.
- `allow_argv` matches structured argv tokens only. `*` matches within one token, so `release:*` matches `release:prod`; `**` may appear as a whole token to match the remaining argv tail, such as `["cargo", "test", "**"]`.
- `allow_argv` does not match `shell = "..."` policies because shell strings are not parsed into trusted argv tokens. Use `allow_commands` for shell policies, and keep high-risk secrets behind `confirm` or `require_user_verification`.
- `allow_paths` entries are project-relative. A plain entry such as `apps/api` matches that directory and descendants; `apps/api/**` is accepted as the explicit subtree form. Absolute paths and `..` are rejected.
- A `[secrets.<NAME>]` table with no ACL fields is invalid. Omitting the table means the secret has no extra command/path ACL beyond the selected policy and path scope.

Policy source of truth:

- Project command policies are canonical in `locket.toml` under `[commands.<name>]` so they can be reviewed in Git and shared with teammates without exporting secret values.
- Project path scopes are canonical in `locket.toml` under `[paths.<relative-path>]` so subproject env boundaries are reviewable without exporting secret values.
- Project secret ACLs are canonical in `locket.toml` under `[secrets.<SECRET_NAME>]` so per-secret command and path limits are reviewable without exporting secret values.
- The SQLite `command_policies` table stores a normalized local index/cache used by the agent, UI, tray, VS Code, and policy doctor.
- Agent reference resolution requires both a durable `source_path` and a matching `source_digest`; legacy allow-list-only indexes fail closed. The source is read and validated on every resolution, including current command, path, profile, and secret ACL rules. After upgrading, review `locket.toml` and use `locket policy refresh <name>` for any legacy policy reported by doctor.
- `policy add`, `policy allow`, `policy require`, `policy edit`, and `policy delete` update `locket.toml` first, then refresh the SQLite index in the same user-visible operation.
- If `locket.toml` and SQLite disagree, `locket.toml` wins after a successful parse; invalid TOML fails closed and leaves the prior SQLite index read-only for diagnostics only.

## Variable contracts

Projects may add commit-safe descriptions, setup guidance, classification, and
literal public defaults under `[variables.<NAME>]`. These tables are separate
from `[secrets.<NAME>]`, which continues to contain only access restrictions.

```toml
[variables.DATABASE_URL]
classification = "secret"
type = "url"
description = "Database connection for the API."
setup_hint = "Ask a teammate for a local development database."

[variables.NEXT_PUBLIC_API_URL]
classification = "public"
type = "url"
default = "http://localhost:3001"
description = "API endpoint included in browser code."
```

Classification defaults to `secret`. Type defaults to `string`; `integer`
requires a signed 64-bit integer, `boolean` requires exactly `true` or `false`,
and `url` requires an absolute URL accepted by the URL parser. URL syntax
validation does not verify an endpoint or its trustworthiness. NUL characters
are invalid. Descriptions and setup hints must be safe to commit and contain
no credentials.

Only explicitly public variables may have a default. Defaults are literal
strings: Locket performs no shell expansion, interpolation, or reference
resolution, and rejects `lk://` references in defaults. Unknown contract fields
and invalid defaults fail validation with value-free diagnostics.

A contract never grants access. Existing `required_secrets`, `optional_secrets`,
path scopes, and secret ACLs determine which names a command can receive. Public
defaults fill only those authorized names that have no value after existing
source and override rules. They do not overwrite inherited, external, or vault
values, and do not hide source conflicts. Resolved values are checked against
the declared type before the child process starts.

Secret-classified or unclassified `VITE_` and `NEXT_PUBLIC_` names produce a
browser-exposure warning before launch. A public classification describes
intent; it does not bypass encrypted-store access, reveal, copy, or ACL rules.

For CI without a local vault, agent, or credentials:

```sh
locket env validate --policy dev --provided-name DATABASE_URL --json
```

This offline command reads project contracts and supplied names only. It applies
the current directory's path scope and ACLs, checks required-name coverage, and
reports metadata with `mode = "names-only"` and `values_checked = false`. It
never starts a process, reads external env files or process environment values,
opens the local vault, contacts the agent, or resolves Compose/IDE sources.
Exit status is 0 for complete coverage, 1 for missing required names, and 2 for
an invalid contract, policy, input, or authorization. Provided names establish
coverage only, not valid values or access to a real credential.

`env inspect` shows source labels and missing-value setup guidance without
values. Its existing external-source resolution may invoke Compose, so use
`env validate` for the offline check. Older Locket binaries reject the new
`variables` root key; use matching CLI, desktop, and editor release versions.
