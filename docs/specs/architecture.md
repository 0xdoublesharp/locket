# Architecture & Scope

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Architecture

Planned Rust workspace layout:

```text
crates/
  locket-cli/
  locket-core/
  locket-store/
  locket-crypto/
  locket-platform/
  locket-exec/
  locket-docker/
  locket-scan/
  locket-agent/
  locket-app/
```

Component responsibilities:

| Component | Responsibility |
| --- | --- |
| CLI | Command-line surface and thin client for the agent when available |
| Core | Project resolution, profile resolution, policy evaluation, typed errors, shared models |
| Store | SQLite persistence, encrypted blobs, schema migrations, audit log |
| Crypto | Encryption, key derivation, key wrapping, keyed fingerprints, audit chain HMACs |
| Platform | OS keychain integration, passphrase fallback, peer credential helpers |
| Exec | Process spawning, environment isolation, reference resolution, shell/argv handling |
| Docker | Docker and Compose env injection helpers built on the exec/policy layer |
| Scan | Known-secret, high-entropy, `.env`, staged-file, and AI-leak scanning |
| Agent | Local broker, socket/pipe server, TTL grants, unlock cache, automation identities, thin-client API |
| App | Tauri v2 desktop UI and tray/status panel backed by the same core and agent APIs |

Per-component acceptance checks may live with crate implementation plans, but the normative cross-cutting quality requirements live in [testing.md](testing.md) and [fuzzing.md](fuzzing.md).

## Functional Scope

This spec describes the intended v1 product surface for Locket. A conforming implementation must eventually include:

- Workspace scaffolding for the Rust crates listed in Architecture.
- Encrypted SQLite store with schema migrations.
- OS key integration, passphrase fallback, recovery code generation, and `locket recover`.
- Project resolution, trusted roots, profiles, dangerous-profile policy, and `locket project trust-root`.
- Project template initialization through `locket new --from-template` using bundled or local templates only.
- Platform local user verification for unlock, dangerous actions, team/device trust, and recovery gates. Genuine passkey/PRF registration is unavailable in the default backend; legacy software keyring recovery remains explicitly labeled and requires fresh verification.
- Team setup, device identity, sealed invites, member/device revocation, and `locket bootstrap`.
- Core secret lifecycle: `init`, `set`, `get`, `rm`, `purge`, `list`, `rotate`, rotation grace/deprecated-version handling, `history`, and `diff`.
- CLI reveal/copy gates with TTY and `--force` semantics.
- Local agent/daemon with authenticated local transport and TTL grants.
- Signed automation-client identities for scoped local agent requests.
- Shell integration through `shellenv`, `hook`, `allow`, and `deny`.
- VS Code extension backed by the local agent.
- Command policies, secret ACLs, path-scoped env sets for monorepos, and `locket run`.
- Config management through `locket config`.
- `lk://` reference URI resolution through the agent.
- `locket exec` with explicit `--secret`, `--all`, conservative env isolation, argv commands, explicit shell commands, and policy enforcement.
- Unobtrusive env layering for existing local environments, including Docker and Docker Compose helpers.
- `.env` import, `.env.example` generation, `.gitignore` updates, and scripted migration flow.
- Scanner, staged scanner, pre-commit hook installation, redactor, AI context output, and `ai-safe` command output capture.
- Tauri v2 desktop UI and system tray/status panel.
- Audit HMAC chain, `locket audit verify`, and audit coverage for sensitive success, denial, and failure events.
- Sealed export/import for one-user multi-machine sync and multi-recipient team bundles.
- Recovery code rotation through `locket recovery rotate`.
- Local diagnostics: `locket doctor`, `locket agent logs`, and `locket debug bundle --redacted`.
- Signed distribution packages, release provenance, and opt-in update checks.
- Stable typed errors and failure-mode behavior.

## Delivery Shape

The v1 surface is organized by dependency boundary:

1. Foundation: typed core models, validation, error taxonomy, project resolution, storage migrations, crypto envelopes, and audit chain.
2. Local CLI MVP: `init`, `set`, metadata-only `get`, `list`, `rotate`, `rm`, `purge`, `.env` import, `.env.example`, and scan/redact basics.
3. Agent and runtime: authenticated local agent, grants, `lk://` resolution, command policies, path-scoped env sets, `locket run`, and Docker/Compose helpers.
4. Desktop and integrations: Tauri v2 app/tray, shell hook, VS Code extension, status streams, and local user-verification gates.
5. Team and distribution: sealed bundles, invite flows, signed packages, update manifests, and release provenance.

Each supported surface may ship only when its behaviors meet the corresponding specs, tests, and failure modes. Public release readiness requires the full v1 surface or an explicitly documented reduced edition.
