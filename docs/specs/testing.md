# Testing Strategy

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

Testing should be driven from the threat model and user-facing guarantees. Security-sensitive behavior needs regression tests, including negative-path and error-path coverage.

## Test Pyramid

- Unit tests: type validation, parsers, policy evaluation, path-scope matching, env merge, crypto AAD construction, key-wrap canonicalization, audit HMAC canonicalization, recovery envelope parsing, device descriptor parsing, scanner rules, and typed error mapping.
- Integration tests: CLI commands against temp stores, agent RPC calls, import/export bundles, scan and redact flows, recovery flows, and Docker/Compose helpers.
- End-to-end tests: representative local-dev flows such as greenfield init, dotenv migration, team invite accept, Docker/Compose injection, and VS Code/agent smoke paths where practical.
- Property tests: `.env` parsing, policy TOML normalization, `lk://` parsing, canonical JSON, device descriptors, and bundle manifest parsing.
- Fuzz tests: malformed, random, and adversarial inputs for parsers and protocol boundaries. Fuzzing requirements are defined in [fuzzing.md](fuzzing.md).

## TDD Expectations

For new behavior:

1. Add a failing test that captures the required behavior or regression.
2. Implement the smallest production change that passes it.
3. Add edge-case and error-path tests before widening the API.
4. Add a fuzz target when the behavior accepts structured external input.

Implementation should use TDD for parser, policy, crypto envelope, store schema checks, scanner, and agent protocol behavior where the expected behavior is known from this spec.

## Coverage Commands

```bash
make test
make coverage
make coverage-html
make coverage-branch
make mutation
```

Coverage failures must be handled by adding meaningful tests, not by lowering thresholds.

## Coverage Bar

- Aim for full practical coverage on `locket-core`, `locket-crypto`, `locket-store`, `locket-agent`, `locket-exec`, and parsers.
- The repository coverage gate starts at 90% line coverage and should ratchet upward as real code lands.
- Security-critical crates (`locket-core`, `locket-crypto`, `locket-store`, `locket-agent`, and `locket-exec`) start with a 90% branch coverage gate once branch reporting is wired. Authorization, deny-by-default policy, key unwrap/wrap, AAD validation, audit verification, grant validation, and env merge code must have explicit negative-path tests for every typed failure branch even if global branch tooling cannot attribute them perfectly.
- Mutation testing must cover policy evaluation, env merge, typed error mapping, and authorization boundaries before public release. Surviving mutants in those areas are treated as missing tests unless the mutant is demonstrably equivalent and documented inline in the mutation report.
- Coverage exclusions require an inline reason and should be rare.

Coverage tooling:

- Use `cargo llvm-cov` as the canonical line and branch coverage tool for Rust.
- Use `cargo nextest` for fast integration and workspace test execution.
- Use platform mocks/fakes instead of real keychain, biometric, Docker, desktop, or network dependencies in normal CI.
- Slow end-to-end tests may be split into a scheduled or release-blocking job, but security-critical unit and integration tests must run on every pull request.
- Real OS prompt and packaged-artifact checks are driven by
  `docs/operations/os-host-validation.md`; CI must at least dry-run those
  harnesses so command drift is caught before release-host execution.

## Required Test Coverage

- Unit tests for project resolution, source precedence, policy normalization, path-scope matching and merge precedence, AAD/key-wrap canonicalization, audit HMAC canonicalization, recovery envelope parsing, device descriptor parsing, scanner rules, and typed error mapping.
- Integration tests for `init`, `profile create`, `profile list`, `agent start/status/stop`, `set`, `get`, `rm`, `purge`, `rotate`, `rotate --grace-ttl`, pinned `lk://...@vN` resolution during grace, pinned reference failure after grace, known-value scan inclusion during grace, known-value scan exclusion after grace expiry, rotation audit metadata for `deprecated_at`/`grace_until`, `import`, `exec --secret`, `run`, `scan`, `audit verify`, `export --sealed`, `import-bundle`, and recovery flows.
- Cross-platform tests or platform-specific mocks for OS keychain, local user verification, peer credentials, memory-lock failure handling, sockets/named pipes, clipboard clearing, and Docker/Compose helpers.
- Mutation or negative-path tests for deny-by-default policy, malformed ciphertext/AAD/nonces, replayed automation-client nonces, audit tampering, locked-vault scans, expired deprecated-version references, and dangerous-profile confirmations.

## Required Scenarios

- Secret values never appear in errors, logs, audit metadata, generated files, debug bundles, snapshots, or UI payloads.
- `profile create` generates profile-scoped secret/fingerprint keys, rejects duplicate names, records `PROFILE_CHANGE`, and switches default only for the first profile.
- `agent start/status/stop` is idempotent, handles stale endpoints, refuses untrusted socket owners, clears keys/grants on stop, and reports metadata only.
- `set` fails on an existing active key and fails with `SecretDeleted` for tombstoned sources.
- `rotate` creates subsequent versions, marks the prior version deprecated, and updates `last_rotated_at`.
- `rotate --grace-ttl` allows pinned references and known-value scan matching only until `grace_until`; after expiry, pinned resolution fails with `SecretVersionExpired` and scan excludes the deprecated value by default.
- `purge --version N` never purges the current version of an active source.
- Env injection honors `strict`, `minimal`, `merge`, and `passthrough` modes.
- Path-scoped env sets merge only from the deepest matching project-relative subtree, reject absolute or parent-traversal keys, and never add values outside the normal policy/source-resolution path.
- `override = "preserve"` never overwrites existing env vars.
- `override = "error"` fails before process spawn.
- Docker/Compose helpers do not write persistent plaintext env files.
- Docker/Compose helpers refuse remote Docker contexts unless policy explicitly enables remote delivery with confirmation.
- Agent grants bind to process identity and process start time where available.
- Expired, revoked, or replayed team invites fail closed.
- Automation-client replayed nonces fail closed across agent restarts.
- Bundle conflicts show metadata-only resolution.
- Recovery restores both local master key access and local device private key wrap.
- Privacy display mode aliases project, profile, policy, device, member, and secret names on status/debug/context/redaction surfaces without changing policy evaluation, audit rows, `.env.example`, or command execution.
- Metadata input validation rejects exact known-secret metadata when known-value matching is available and blocks provider-shaped or high-entropy metadata without explicit typed confirmation.

## Secret-Leak Canary Harness

The test suite must include a reusable canary helper that generates unique, high-entropy secret values and inserts them through normal Locket APIs. Representative CLI, agent, scan, redaction, audit, debug bundle, UI, tray, VS Code, Docker, and recovery flows must run with those canaries and then assert that the exact values do not appear in:

- stdout, stderr, panic messages, and typed error displays.
- structured logs, tracing spans, local agent logs, and debug bundles.
- SQLite audit metadata, generated `.env.example`, config files, shell hook output, status payloads, and serialized app or extension state.
- test snapshots, frontend fixtures, and browser/devtools-visible payloads.

The helper should scan both text and binary artifacts where feasible. A canary leak is a release blocker, even if the leaked value appears only in a test artifact.

The canary suite must also seed sensitive-looking metadata values to prove metadata validation works: exact secret-value copies are refused when known-value matching is available, provider-token-shaped metadata is blocked without typed confirmation, and privacy display mode suppresses exact metadata names in status-oriented outputs.
