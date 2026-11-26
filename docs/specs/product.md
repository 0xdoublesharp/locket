# Product & Positioning

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Summary

Locket will be a local-first secrets control plane. It is intended to replace `.env`-centered local-development workflows with an encrypted local vault, explicit access policy, process-scoped secret delivery, an AI-aware scanner, a local agent, shell/editor integrations, and a modern desktop status surface.

The core product decision is simple: secrets are not files. Secrets are capabilities granted to specific projects, profiles, commands, directories, editors, shells, and runtime sessions.

The product is designed around two priorities at the same time:

- Ease of use: `locket init`, `locket import .env`, `locket run dev`, shell status, editor hints, and no repeated prompts during normal local work.
- Security: no plaintext source of truth, deny-by-default policy, scoped grants, audit integrity, and no secret values in logs, settings, workspace state, generated files, or telemetry.

Normative language:

- Must means required for conformance to this spec.
- Should means required by default unless a documented platform limitation prevents it.
- May means optional behavior.

## Positioning Vs Alternatives

- dotenv: Locket should preserve the developer-friendly environment variable interface, but reject plaintext files as the source of truth.
- dotenvx: Locket should treat local encrypted configuration as a stepping stone, but reject encrypted `.env` files as the runtime control plane.
- SOPS: Locket should borrow file encryption discipline, but reject Git-tracked encrypted secret files as the primary local workflow.
- pass/passage: Locket should borrow local-first key ownership, but add project/profile policy, process injection, editor integration, and audit trails.
- 1Password CLI (`op`): Locket should borrow reference-style resolution, but keep the vault local-first and project-policy aware.
- Infisical and Doppler: Locket should borrow polished DX and environment management, but reject a hosted service as the default dependency.
- Vault: Locket should borrow brokered secret access and TTL thinking, but target local development workflows instead of distributed infrastructure.
- AWS SSM, GitHub Actions secrets, and other platform-native stores can hold CI bootstrap credentials and production secrets.

## CI Position

CI runners can read an authorized team profile with `locket ci`. Store the machine identity and delivery credentials in the platform's protected secret store, such as GitHub Actions secrets, an AWS, GCP, or Azure secret manager, or the deployment platform's secret facility. Locket verifies packages and decrypts profile values in memory. It can emit `.env.example` and policy metadata for CI parity, and it must not export plaintext profile values in normal workflows. See the [CI/CD guide](../ci-cd.md) for enrollment and execution.

## Telemetry

Locket collects no telemetry or analytics. Network calls are limited to opt-in update checks and user-directed delivery of encrypted packages, including automatic team sync after a user configures a backend.

Opt-in update checks must not send project metadata, secret metadata, device identifiers, stable installation identifiers, local paths, hostnames, usernames, or unique tracking tokens. Team sync exchanges encrypted packages through user-configured storage. Membership and revocation travel in owner-signed updates. Diagnostics stay local.
