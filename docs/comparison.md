# Choosing Locket

Locket is a Rust local-first secrets manager for developers who want encrypted local storage, explicit command and path policies, zero-knowledge AI-agent workflows, and offline execution without running a server.

## Scored feature matrix (Rust v0.2+)

Scores reflect **shipped behavior** on a 0–2 scale:

- **2**: Native, shipped, and core to the workflow
- **1**: Partial, conditional, server-dependent, or requires manual/add-on steps
- **0**: Out of scope or unavailable

| Capability | Locket (Rust) | Doppler | Infisical | 1Password CLI (`op`) | Bitwarden SM | dotenvx | SOPS | pass / gopass |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Zero-server local-first & native offline | **2** | 1¹ | 1¹ | 1¹ | 1¹ | **2** | **2** | **2** |
| Zero-knowledge encrypted vault at rest | **2** | 0 | 1² | **2** | **2** | **2** | **2** | **2** |
| Global (`@shared`) + project/profile vaults | **2** | **2** | **2** | 1 | 1 | 1 | 1 | 1 |
| Capability-scoped command, argv & monorepo path ACLs | **2** | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Zero-knowledge AI-agent MCP, `.env` scan/import & redaction | **2** | 0 | 0 | 0 | 0 | 1³ | 0 | 0 |
| Native Desktop companion + IDE + shell workflow | **2** | 1⁴ | 1⁴ | **2** | 1⁴ | 1⁴ | 0 | 1 |
| Local HMAC audit, grace-window rotation & offline recovery | **2** | 1⁵ | 1⁵ | 1⁵ | 1⁵ | 0 | 0 | 0 |
| Formal verification (TLA+ / Lean 4 / live trace replay) | **2** | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **Local-Dev & Security Subtotal (max 16)** | **16 / 16** | **5 / 16** | **6 / 16** | **7 / 16** | **6 / 16** | **7 / 16** | **5 / 16** | **6 / 16** |
| Multi-admin team sync & RBAC | 1⁶ | **2** | **2** | **2** | **2** | 1 | 1 | 1 |
| Cloud CI/CD, SSO/SCIM & dynamic production secrets | 0⁷ | **2** | **2** | 1 | 1 | 1 | 1 | 0 |
| **Overall Total (max 20)** | **17 / 20** | **9 / 20** | **10 / 20** | **10 / 20** | **9 / 20** | **9 / 20** | **7 / 20** | **7 / 20** |

### Scoring notes

1. **Offline & zero-server**: Doppler documents encrypted offline fallback snapshots and fallback-only mode ([Doppler fallback documentation](https://docs.doppler.com/docs/automatic-fallbacks)), Infisical and Bitwarden SM cache against a required server, and 1Password desktop supports offline viewing while `op` CLI relies on cloud/Connect or desktop integration. Locket, dotenvx, SOPS, and pass/gopass operate natively with no server.
2. **Zero-knowledge**: Infisical offers end-to-end encryption, but server-side features such as dynamic secrets and managed rotation require server access to plaintext. Doppler decrypts secrets server-side.
3. **AI-agent & known-value redaction**: Dotenvx documents runtime redaction of loaded values in `dotenvx run` ([Dotenvx official CLI documentation](https://github.com/dotenvx/dotenvx)). Locket pairs known-value scanning (`locket scan --require-known`), output redaction (`locket redact`, `locket ai-safe`), a streaming HTTP egress proxy, projection-first privacy mode, and a zero-knowledge MCP server (`locket mcp` with `locket_inspect_env_keys`, `locket_scan_env_files`, `locket_import_env`, and `locket_detect_commands`).
4. **Desktop, IDE & shell**: Doppler, Infisical, and Bitwarden SM provide web consoles, while 1Password pairs a native desktop app with `op`. Locket ships a native Tauri v2 desktop companion (Global Vault, 1-click Keychain unlock, Day-2 CRUD, detected commands, MCP/agent setup, and tray), a VS Code extension, and shell hooks.
5. **Audit, rotation & recovery**: Hosted tools keep audit logs and rotation on their servers. Locket keeps a local tamper-evident HMAC audit chain with external witness receipts, pinned `lk://...@vN` grace windows, and offline recovery envelopes.
6. **Team sync & RBAC**: Locket ships signed, device-encrypted shared-folder updates with personal overrides, collision holding, and fingerprint-verified onboarding, but currently supports a single pinned owner without owner handover, and live cloud-folder provider qualification remains open. Hosted platforms score 2 for multi-admin hosted RBAC.
7. **Cloud CI/CD, SSO/SCIM & dynamic secrets**: Out of scope for Locket. Production and CI pipelines should use platform-native secret stores or hosted platforms like Doppler, Infisical, or HashiCorp Vault.

## What sets the Rust version apart

- **Local capability boundaries**: Saved command policies in `locket.toml`, deepest-subtree monorepo `[paths."..."]` scopes, per-secret `allow_commands` / `allow_argv` / `allow_paths` ACLs, process-bound agent grants (PID + start time), and explicit `@shared` injection via `shared_secrets` or `locket exec --project @shared`.
- **Built for AI coding agents**: Zero-knowledge `.env` discovery and migration over `locket mcp`, read-only `locket policy detect`, machine-readable `locket status --json`, known-value redaction, and projection-first privacy mode that hides raw names even from discovery queries.
- **Formally checked security core**: 10 exhaustive TLC/TLA+ models (over 10M generated states), live Rust-to-TLC trace validation, and 11 Lean 4 proof modules with zero placeholders or axioms ([formal verification summary](../formal/README.md)).

## Compare the workflow

| Question | Current Locket behavior |
| --- | --- |
| Where do values live? | An encrypted local SQLite vault (personal Global Vault `@shared` and per-project vaults); shareable project metadata stays in `locket.toml`. |
| How does an application receive values? | A saved command policy (plus optional monorepo path scope and `shared_secrets`) declares permitted names; Locket injects values into that child process only. |
| Does routine execution require a hosted service? | No. Local keys, project configuration, and values must be available. |
| How do AI agents work with secrets safely? | `locket mcp` exposes metadata-only `.env` key inspection, workspace scanning, filtered import, and command detection without ever returning plaintext values. |
| How are teammates updated? | One owner publishes signed, device-encrypted updates through an existing shared folder. Unlocked agents deliver and apply verified updates. Real provider behavior still needs acceptance testing. |
| What is shared by default? | Current shared values. Personal/machine overrides and history require opt-in. |
| Are imported commands trusted? | Approve command access locally. Signed team updates never install command approvals or project configuration; manual sealed bundles do not authenticate their issuer. |
| How does a fresh machine join? | Prepare device keys, compare full fingerprints independently with the owner, then join an owner-signed package. Owner handover and trust-fork recovery remain unsupported. |
| What works in the desktop? | Global Vault (`@shared`) and auto-detecting project setup, 1-click Keychain or passphrase unlock, Secret CRUD + Copy to Global Vault, Environment creation, Detected Commands, 1-click MCP & AI migration prompt copy, readiness checks, terminal launch, and explicit team conflict controls. |
| Is this a production secret-management service? | No. Use infrastructure designed for your production and CI requirements. |

## Claims to avoid

Offline execution is not unique to Locket. Doppler documents encrypted fallback snapshots and a fallback-only mode for offline access ([Doppler fallback documentation](https://docs.doppler.com/docs/automatic-fallbacks)).

Actual-value redaction is not unique either. Dotenvx documents redaction of loaded values with its run command, as well as encrypted env files ([Dotenvx official CLI documentation](https://github.com/dotenvx/dotenvx)).

Locket's scanners and redaction are explicit tools for preparing files or output. They do not intercept arbitrary AI requests or make untrusted code safe. A process receiving a variable can disclose it.

Do not market unfinished SSO, compliance programs, hosted tiers, owner handover, or future pricing as shipped features. Signed folder delivery is implemented; observed team usability and real provider qualification remain open. Vendor prices and plan limits change, so check their primary pricing pages when evaluating a purchase.

The remaining adoption test is practical: can an unfamiliar developer import and run their app without coaching, then help a teammate do the same without losing data or sharing extra values? The [team guide](team-updates.md) and [distribution checks](distribution-validation.md) describe the current workflows and acceptance boundaries.

External claims checked against the linked primary documentation on 2026-11-24. Product behavior is based on this repository; live multi-device usability has not been measured.
