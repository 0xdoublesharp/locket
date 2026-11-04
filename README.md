<div align="center">

<img src="docs/Locket.png" alt="Locket" width="160" />

# Locket

### Your development variables, encrypted locally and ready to run.

<p>
  <img alt="local-first" src="https://img.shields.io/badge/local--first-✓-3b82f6?style=flat-square" />
  <img alt="no telemetry" src="https://img.shields.io/badge/no_telemetry-✓-10b981?style=flat-square" />
  <img alt="encrypted vault" src="https://img.shields.io/badge/encrypted_vault-✓-8b5cf6?style=flat-square" />
  <img alt="rust" src="https://img.shields.io/badge/built_with-Rust-orange?style=flat-square&logo=rust&logoColor=white" />
  <img alt="platforms" src="https://img.shields.io/badge/macOS_·_Linux_·_Windows-grey?style=flat-square" />
</p>

<em>Replace plaintext <code>.env</code> files with an encrypted vault, explicit policy,<br/>and delivery to the commands you approve.</em>

<br/>

<sub>
  🔐&nbsp;Encrypted&nbsp;&nbsp;·&nbsp;&nbsp;🎯&nbsp;Capability-scoped&nbsp;&nbsp;·&nbsp;&nbsp;🧭&nbsp;Project&nbsp;+&nbsp;Profile&nbsp;&nbsp;·&nbsp;&nbsp;🤖&nbsp;AI-safe&nbsp;local&nbsp;context&nbsp;&nbsp;·&nbsp;&nbsp;🚫&nbsp;No&nbsp;Telemetry
</sub>

</div>

<br/>

> Import your `.env`, approve which variables a command can use, and run it with Locket. Values are encrypted in your local vault. Project configuration and variable names can go in Git; values stay out of it. Locket collects no telemetry.

---

## Why Locket

- 🔐 **Encrypted local vault** — your secrets, sealed at rest, unlocked only when you ask.
- 🎯 **Capability-scoped delivery** — `locket run`, `locket exec`, Docker, and Compose helpers inject secrets into one child process and nowhere else.
- 📋 **Explicit command policies** — declare which secrets a command may receive, and Locket enforces it.
- 🧭 **Project + profile workflows** — keep `dev`, `staging`, and per-machine secrets cleanly separated.
- 🛠️ **Shell, editor, desktop, and tray integrations** — local status, approvals, metadata history, and `lk://` reference resolution.
- 🔄 **Rotation, history, and diffs** — change values safely; compare profiles without revealing them.
- 🧹 **Scanner, pre-commit, redaction, AI-safe tools** — keep secrets out of code, logs, and prompts before sharing context with local AI agents.
- 🪪 **Recovery and device trust** — local verification, recovery rotation, and sealed export/import without a hosted service.
- 👥 **Team updates** — signed encrypted shared-folder delivery, verified device onboarding, and personal overrides; no hosted service required.
- 🧾 **Metadata-only audit and diagnostics** — report what happened, never the values.
- 🚫 **No telemetry, no analytics** — only opt-in update checks or explicit sealed sync/export/import.

## Project Files

- `locket.toml` lives in the project and contains shareable configuration, policies, and metadata.
- Monorepos can add `[paths."<relative/path>"]` env sets to make package-specific secret names available only when commands run from that subtree.
- Secret values stay in the local encrypted vault, **not** in Git-tracked project files.
- `.env.example` is maintained as a names-only contract for expected variables.
- `.gitignore` is updated to keep plaintext local env files out of Git.

> Locket is intentionally local-first. CI and production should use their platform-native secret stores; Locket is for local development workflows.

## Current Scope

Locket targets local development. The desktop connects project folders, unlocks the vault, imports env files, edits durable commands, and opens approved commands in a terminal. Imports and policy edits use the unlocked agent cache, including passphrase-only vaults. Native packages bundle a matching CLI; the editor version matches the app and CLI.

Teams can [join a fresh machine and receive signed encrypted updates](docs/team-updates.md) through an existing shared folder. First join requires the owner's full fingerprint from a separate trusted channel. One owner publishes shared values, while personal overrides remain local. The unlocked agent publishes changed shared values and applies verified updates automatically. Status shows the last verified update; an offline or malicious folder provider can withhold newer files. Owner handover and real sync-provider/clean-OS acceptance remain separate qualification work.

Manual version 1 export/import remains available. These older bundles encrypt for recipients but do **not** authenticate the issuer. Imported command proposals never grant local execution permission. Exports default to current shared values; personal overrides and history require explicit opt-in. Read [package validation](docs/distribution-validation.md) before preparing installers; unsigned local artifacts do not establish signing or notarization.

For an older local signing identity, run `locket device rotate-signing` before enabling signed team delivery, then refresh your recovery backup. This preserves the sealing key needed to open earlier bundles. Once a team owner is pinned, identity replacement is refused; authenticated owner handover is not supported yet.

Scanners and redaction help prepare output before sharing it. They do not isolate code or intercept an AI application's outbound requests. Programs receiving a variable can read and transmit it. Original `.env` files stay plaintext until you explicitly remove them; keep a verified recovery path before doing so.

## Install From Source

```bash
cargo install --path crates/locket-cli
```

For repository development, run the CLI without installing it:

```bash
cargo run -p locket-cli -- <command>
```

## Quick Start

In your application folder, initialize Locket and migrate your variables:

```bash
locket init --name my-app --profile dev
locket import .env
locket run -- npm run dev
```

The first new command asks you to approve its exact arguments, working directory, and variable names. Approval saves a command in `locket.toml`. Later runs can use its saved name, for example `locket run dev`. Interactive setup can detect common package scripts; `locket setup` shows the next action for your project.

Import validates the whole file before writing any values. It supports quoted multiline values, empty strings, comments, and `export KEY=...`; duplicate names use the last assignment with a warning. Variable expansion is rejected by default. Use `locket import .env --literal` only when dollar expressions should remain literal text. Nothing in the file is executed. Review skipped entries before replacing values with `--overwrite`. Removal of the original requires a separate confirmation after a complete successful import; desktop imports keep it.

To approve only specific variables instead:

```bash
locket policy add dev -- npm run dev
locket policy require dev DATABASE_URL
locket run dev
```

Inspect names and state without printing values:

```bash
locket list
locket status
locket status --scan
```

Use the desktop's **Project** page for the same connect → unlock → import → command workflow. The names **Shared**, **My override**, and **This machine** describe where a value comes from. Environments such as `dev` and `staging` retain the compatible `profile` CLI syntax.

## Core Workflows

### Project Setup

```bash
locket init [--name <name>] [--profile <profile>] [--recovery-code]
locket new --from-template <name>
locket setup [status|agent|share]
locket bootstrap
locket status
locket emit-example
```

`locket setup` shows the next missing action. In an interactive terminal it can offer to import an existing `.env` and approve a detected development command. It never starts a project script during setup. `locket init` creates the project configuration, prepares the local vault, updates `.gitignore`, and creates a managed `.env.example` block. Each project has its own master key and device identity. Pass `--recovery-code` when you want an offline backup code during setup; otherwise you can add or rotate one later with `locket recovery rotate`.

### Secrets And Profiles

```bash
locket set <KEY> [--source user-local|machine-local|team-managed]
locket import .env [--overwrite] [--literal]
locket list [--all]
locket get <KEY>
locket get <KEY> --reveal
locket rotate <KEY> [--grace-ttl <duration>]
locket history <KEY>
locket diff <profileA> <profileB>
locket profile create staging
locket use staging
```

Secret names use portable environment-variable syntax, such as `DATABASE_URL` or `STRIPE_SECRET_KEY`. Secret values are not accepted as command-line arguments; use stdin for writes so values do not land in shell history or process listings.

### Policies And Execution

```bash
locket policy add dev -- pnpm dev
locket policy allow dev DATABASE_URL
locket policy require dev API_TOKEN
locket policy doctor
```

If doctor reports an old or changed policy approval, review `locket.toml` and run
`locket policy refresh dev`. Type the policy name to approve the current command,
path scopes, and secret access rules. This updates local approval without editing
the project file.

Run a saved policy or inject explicit secrets into one child process:

```bash
locket run dev
locket run npm dev
locket run -- npm run dev
locket env inspect --policy dev
locket exec --secret DATABASE_URL -- <command> [args...]
locket env docker --policy dev -- docker run ...
locket compose run --policy dev -- docker compose up
```

`locket run` accepts a saved policy name, a supported runner adapter, or explicit arguments after `--`. New command access requires interactive approval; noninteractive execution uses saved authorization. For example, `locket run npm dev` expands to `npm run dev`, validates the `dev` script when `package.json` is present, and uses the command identity `npm:dev` for ACL checks and audit metadata. Other adapters include `pnpm`, `yarn`, `bun`, `cargo`, `make`, `just`, `task`, `poetry`, `uv`, and `python`.

In monorepos, path scopes extend the selected command policy by current directory:

```toml
[commands.dev]
argv = ["pnpm", "dev"]

[paths."apps/api"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["STRIPE_SECRET_KEY"]

[paths."apps/web"]
required_secrets = ["NEXT_PUBLIC_API_URL"]
```

The deepest matching `[paths."..."]` entry wins. A path scope can add `required_secrets`, add `optional_secrets`, and optionally set `profile = "dev"` for commands run from that subtree. It never stores values; it only names what the selected policy may receive. Run `locket env inspect --policy dev` from a package directory to see the active `path_scope` and final metadata-only injection plan.

Secret ACLs can further limit where an authorized secret may be delivered:

```toml
[secrets.DATABASE_URL]
allow_commands = ["dev", "npm:dev"]
allow_argv = [["npm", "run", "dev"], ["cargo", "test", "**"]]
allow_paths = ["apps/api/**"]
```

When a secret has an ACL, every configured dimension must match: command identity, structured argv pattern, and project-relative path. `*` matches inside one command or argv token; `**` is supported as a full argv token to match the remaining arguments. Plain `allow_paths` entries match that directory and its descendants, while `apps/api/**` is the explicit subtree form.

Execution commands prepare the child process environment for that invocation only. They do not export secrets into the parent shell.

### Configuration contracts

Describe required setup in `locket.toml` without committing secret values:

```toml
[variables.DATABASE_URL]
classification = "secret"
type = "url"
setup_hint = "Ask a teammate for a local development database."

[variables.NEXT_PUBLIC_API_URL]
classification = "public"
type = "url"
default = "http://localhost:3001"
```

Keep each command's approved names in its existing `required_secrets` and
`optional_secrets` lists. Contracts do not grant access. Only public variables
can have defaults, which fill missing authorized names after existing sources
and conflict rules. Types are checked before launch; errors show names, never
values. Secret `VITE_` and `NEXT_PUBLIC_` names produce a browser exposure warning.
The desktop's configuration panel shows missing names, setup guidance, source
labels and unverified sources without showing values or default strings.

For CI coverage without opening a vault, reading env values or starting scripts:

```sh
locket env validate --policy dev --provided-name DATABASE_URL --json
```

The report is names-only and sets `values_checked` to `false`. Exit codes are 0
for complete coverage, 1 for missing required names and 2 for invalid input or
access rules. It does not verify a live credential. See the
[contract specification](docs/specs/policy.md#variable-contracts) for all fields.

### Agent And Integrations

```bash
locket agent start
locket agent status
locket setup agent
locket agent invite request
locket agent invite create <label> --device <descriptor> --profile dev --role developer [--expires-in 7d]
locket agent invite accept -
locket shellenv
locket hook
locket allow
locket deny
locket install-hooks
```

The local agent backs unlock caching, live grants, shell prompts, editor status, `lk://` reference resolution, and desktop/tray workflows. `locket setup agent` prints the copy/paste handoff in the order both sides need to run it.

For paste-friendly agent onboarding, the receiving machine runs `locket agent invite request` and sends the printed request block to a maintainer. The block includes the device descriptor plus the exact maintainer command to run. The maintainer creates a profile- and role-scoped invite with `locket agent invite create <label> --device <descriptor> --profile dev --role developer [--expires-in 7d]`, then sends the sealed invite text back. The receiver accepts it without saving an intermediate file:

```bash
cat <<'LOCKET_INVITE' | locket agent invite accept -
<sealed invite block>
LOCKET_INVITE
```

### Scan And Redact

```bash
locket scan [path]
locket scan --staged
locket scan --require-known [path]
locket redact file.log
some-command | locket redact --stdin
locket context
locket ai-safe -- <command> [args...]
```

`scan` reports provider-token patterns, high-entropy strings, env-file markers, and, with `--require-known`, values already stored in the local vault. `redact` and `context` help prepare logs or project metadata before sharing them.

### Access And Recovery

```bash
locket unlock [--verify-user]
locket lock
locket recover
locket recovery rotate
```

Recovery and verification flows are local-first. Keep each project's recovery code separately from its encrypted recovery files in `.locket/recovery` and back up both the recovery files and local vault. The encrypted files are excluded from Git; one project's recovery code does not recover other projects.

Fresh user verification uses macOS LocalAuthentication, Windows Hello, or Linux polkit. Linux requires the packaged `app.locket.verify` policy, polkit, and an active user session with an authentication agent; missing prerequisites fail closed. Each verification requires current-user authentication without authorization caching. Reading an unlocked Secret Service keyring is not proof of fresh consent.

Use `locket agent start --require-session-monitoring` to require an available native session observer. Linux uses logind; Windows uses session and power notifications. Lock and suspend events clear cached keys and live grants. See [OS host validation](docs/operations/os-host-validation.md) for installation and native acceptance checks.

New passkey registration is unavailable until a genuine WebAuthn/FIDO2 backend is integrated. Earlier `platform-keyring` credentials are software recovery factors stored in the OS keyring, not hardware passkeys. `locket passkey list` identifies them; `locket passkey unlock` preserves their recovery path and requires fresh local verification. Keep your recovery code available.

The macOS agent observes sleep and screen lock and clears cached keys and grants. `locket agent status` reports whether monitoring is active. When monitoring is unavailable, lock the vault explicitly before leaving the device; TTL expiry still applies.

### Team And Sync

Receiving device:

```bash
locket team join --request
# Give the descriptor to the owner and compare fingerprints separately.
locket team join --folder /path/to/shared-folder --owner '<verified full owner fingerprint>'
locket team sync status
```

Owner:

```bash
locket device init
locket team init 'Our team'
locket team add Alex --device '<descriptor>' --confirm-device-fingerprint '<verified full device fingerprint>' --profile dev
locket team folder /path/to/shared-folder
locket team publish
```

The unlocked agent delivers signed encrypted updates automatically. Held values are shown by `locket team sync pending`; the desktop provides explicit collision resolution. Follow the [team onboarding and recovery guide](docs/team-updates.md) for the complete flow.

Manual `export --sealed` / `import-bundle` and older invite commands remain available for compatibility. Version 1 bundles do not authenticate the issuer; use the signed team workflow for ongoing delivery.

### Audit And Diagnostics

```bash
locket audit verify
locket doctor
locket agent logs
locket debug bundle --redacted
```

Diagnostics are designed to report project, vault, hook, agent, policy, and bundle state without exposing secret values.

## Development

The workspace uses the repository-pinned Rust toolchain.

```bash
make ci-local
make fmt-check
make clippy
make test
make coverage
make coverage-html  # doublcov via npx (primary); set COVERAGE_HTML_TOOL=llvm-cov for the cargo llvm-cov --html fallback
make dependency-hygiene
make vet
make bench-fixtures
make perf-passphrase-unlock
make perf-recovery-envelope-unlock
make slsa-provenance
```

`make ci-local` is the default local quality gate. It uses `OFFLINE=1` by
default, runs with `CARGO_JOBS=12`, and skips optional tools with explicit
warnings instead of fetching network state.

Additional quality gates are available through the `Makefile`:

```bash
make nextest
make coverage-branch
make mutation
make leak-canary
make bench-ci
make bench-report
make supply-chain-local
make deny
make audit
make unsafe-inventory
make sbom
make third-party-notices
make supply-chain-exceptions
make fuzz-smoke
```

Release-style checks should be run explicitly when the required tools and
network-backed advisory data are available. `make ci-strict` includes the
unsafe inventory and SBOM release artifacts under `target/quality/`.

For release candidates, run the local gate plus the surfaces used by AI-agent
development:

```bash
make docs-check
make supply-chain-local
pnpm --dir extensions/vscode run test
pnpm --dir crates/locket-app/ui run test
pnpm --dir crates/locket-app/ui run build
make leak-canary
```

```bash
make ci-strict OFFLINE=0 STRICT=1
make fuzz-nightly STRICT=1
```

Quality gate scripts live in `scripts/` and are intentionally metadata-only:
they must not print, snapshot, or persist secret values. Generated reports are
written under `target/quality/` or `coverage/` and are ignored by Git. RustSec
advisory policy output is written to `target/quality/rustsec-policy.md`.
Supply-chain exceptions are tracked in `supply-chain-exceptions.json` and
validated by `make supply-chain-exceptions`. Third-party notices for MPL-2.0
covered Rust crates are generated from locked Cargo metadata at
`target/quality/THIRD_PARTY_NOTICES.md`; release artifacts must include that
file or an equivalent notice/source-availability document.

Full design specs live in [`docs/specs/index.md`](docs/specs/index.md).
