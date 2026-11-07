# Locket v1 Specification

This spec defines the Locket v1 product contract. Normative terms such as `must`, `should`, and `may` describe required behavior for supported release surfaces and local development workflows.

The Locket spec is split by implementation boundary. These files are normative as a set; do not duplicate rules across files. When behavior crosses boundaries, the owning file should hold the rule and other files should link to it.

## Freshness Baseline

Last reviewed: 2026-06-26.

Release builds should use current stable foundations, not legacy defaults:

- Rust 2024 edition with the repository-pinned toolchain in `rust-toolchain.toml` (`1.99.1`). The pre-1.0 minimum supported Rust version is 1.99.
- Tauri v2 for the desktop app and tray surface; start from the latest stable v2 minor at scaffolding time (`2.10.x` at this review), not legacy v1 or beta/RC APIs. Reference: [Tauri v2 releases](https://tauri.app/release/tauri/v2.10.1/).
- SLSA v1.2-style provenance expectations for release artifacts. Reference: [SLSA v1.2 build requirements](https://slsa.dev/spec/v1.2/build-requirements).
- OWASP secrets-management guidance for lifecycle, rotation, audit, redaction, and CI boundaries. Reference: [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
- NIST SP 800-63-4 guidance for local user verification and syncable authenticator/passkey tradeoffs. Reference: [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html).

Before cutting a public artifact, refresh this section against primary sources and update dependency versions, release signing, and platform-authenticator assumptions. Prefer current stable releases over release candidates unless a written design note explains the risk and migration plan.

## Reading Order

- [Product & Positioning](product.md)
- [Invariants & Threat Model](invariants.md)
- [Architecture & Scope](architecture.md)
- [Data Model](data-model.md)
- [Storage](storage.md)
- [Crypto, Key Management & User Verification](crypto.md)
- [Project Resolution, CLI & Onboarding](project-cli.md)
- [Policy Authoring](policy.md)
- [Runtime, References & Secret Lifecycle](runtime.md)
- [Local Agent / Daemon](agent.md)
- [Shell, Editor & Git Integrations](integrations.md)
- [Scan, Redaction & AI Safety](scan-redaction.md)
- [Desktop UI & Tray](desktop.md)
- [Audit & Integrity](audit.md)
- [Team, Recovery & Sync](team-sync-recovery.md)
- [Diagnostics & Distribution](operations.md)
- [Performance Budgets](performance.md)
- [Performance Reference Runner](performance-reference-runner.md)
- [Errors & Failure Modes](errors.md)
- [Engineering Standards & Dependencies](engineering.md)
- [Testing Strategy](testing.md)
- [Fuzzing](fuzzing.md)

## Ownership Guide

- Product, invariants, architecture, and data model define system-wide constraints.
- Storage, crypto, audit, errors, and agent specs define security-critical implementation contracts.
- CLI, policy, runtime, integrations, desktop, and scan specs define user-facing behavior.
- Engineering, testing, fuzzing, performance, diagnostics, and distribution specs define implementation quality gates and operational behavior.
