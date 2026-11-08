# Isolated CI Runners for Release Builds

`docs/specs/operations.md:39` requires that public release artifacts be built
by CI on hosted, **isolated** runners — not from a maintainer laptop and not
on the same shared runners that build pull-request and branch CI. This
document defines what "isolated" means here, how the GitHub Actions
configuration is split, and how `scripts/release-build.sh` enforces the
boundary at runtime.

Companion docs: [`release-key-offline.md`](./release-key-offline.md) for the
signing flow that consumes the release-build output, and
[`vscode-vsix-signing.md`](./vscode-vsix-signing.md) for the VSIX-specific
case.

## 1. The "isolated runner" requirement

An *isolated* runner, for the purposes of release builds, satisfies all of:

- **Single-tenant per job.** No PR or branch CI workload runs concurrently or
  in series in the same runtime as a release build. Either ephemeral hosted
  runners (`ubuntu-24.04` GitHub-hosted, fresh VM per job) **provisioned only
  for the release pool**, or self-hosted runners labelled `isolated` and
  provisioned exclusively for tag releases.
- **Ephemeral filesystem.** No state survives between jobs. Any cache that is
  permitted is cryptographically scoped to the release pool and cannot be
  poisoned from PR CI.
- **Restricted network egress.** Egress allow-list excludes Marketplace
  publishing endpoints, code-signing oracles, and the offline signing host.
  CI never holds signing keys (see `release-key-offline.md`).
- **Pinned, attested base image.** The runner image identity is recorded in
  SLSA provenance and validated by `scripts/slsa-provenance-policy.pl
  --require-build-l3`.
- **Workflow-level separation.** Release jobs live in a dedicated workflow
  file that cannot be triggered by `pull_request` or `push` to non-release
  branches.

## 2. Why CI runner reuse is a supply-chain risk

If the same runner pool builds PRs and releases, an attacker who lands a
PR-time foothold (malicious test, dependency post-install script, build cache
poisoning) can:

- Plant a binary or shared library that a later release job picks up.
- Corrupt a self-hosted runner's filesystem or environment such that the next
  release inherits the corruption.
- Read secrets that are nominally scoped to release jobs but were briefly
  exposed in a shared environment.

The PR threat model is intentionally permissive (anyone can open a PR and
trigger CI). The release threat model must be the opposite. Sharing runners
between them collapses both into the permissive case.

## 3. GitHub Actions configuration

### Release workflow (`.github/workflows/release.yml`)

```yaml
name: release
on:
  push:
    tags:
      - "v*"
permissions:
  contents: write
  id-token: write    # for SLSA provenance attestation
  attestations: write
jobs:
  build:
    runs-on: [self-hosted, isolated, locked-down]
    # Or, if self-hosted is not yet provisioned:
    # runs-on: ubuntu-24.04   # GitHub-hosted, ephemeral, but pool-isolated
    #                          # by virtue of this workflow only running on tags
    env:
      LOCKET_RELEASE_RUNNER_ATTESTED: ${{ vars.LOCKET_RELEASE_RUNNER_ID }}
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - run: scripts/release-build.sh
      - uses: actions/attest-build-provenance@v2
        with:
          subject-path: target/release/dist/**
```

### Standard CI workflow (`.github/workflows/ci.yml`)

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-24.04   # standard GitHub-hosted pool
    steps:
      - uses: actions/checkout@v4
      - run: cargo test --workspace
```

### Trigger matrix

| Trigger                          | Workflow      | Runner pool                                   |
|----------------------------------|---------------|-----------------------------------------------|
| Tag push matching `v*`           | `release.yml` | `[self-hosted, isolated, locked-down]`        |
| `pull_request` (any branch)      | `ci.yml`      | `ubuntu-24.04` (GitHub-hosted)                |
| `push` to `main`                 | `ci.yml`      | `ubuntu-24.04` (GitHub-hosted)                |
| `workflow_dispatch` on `release.yml` | `release.yml` | release pool, restricted to maintainer role |

Release workflows must **not** run on `pull_request` or feature-branch push.
PR jobs must **not** target the release runner pool. Both directions are
enforced by branch-protection rules on workflow file paths.

## 4. SLSA provenance

Every release artifact carries an SLSA v1.2 build-provenance attestation
generated via `actions/attest-build-provenance@v2`. The attestation is then
validated by `scripts/slsa-provenance-policy.pl` against:

- The expected source repository (`0xdoublesharp/locket`).
- The expected workflow ref (`.github/workflows/release.yml@refs/tags/v*`).
- The expected builder identity (GitHub-hosted Actions runner or the pinned
  isolated self-hosted builder).
- The expected build type
  (`https://actions.github.io/buildtypes/workflow/v1`).
- `--require-signature` (the DSSE envelope must be signed).
- `--require-build-l3` (builder identity must match a hosted/isolated CI
  builder, not a workstation).

A release that fails provenance validation must not be signed by the offline
release key (`release-key-offline.md`) and must not be published.

## 5. Runtime guard in `scripts/release-build.sh`

`scripts/release-build.sh` refuses to run unless the environment variable
`LOCKET_RELEASE_RUNNER_ATTESTED` is set. The release workflow sets this from
a repository variable that names the isolated runner (e.g.
`LOCKET_RELEASE_RUNNER_ID = "locket-release-isolated-01"`). PR CI does not
have access to that variable, so a release build accidentally triggered from
PR CI fails fast.

For local development, set `LOCKET_RELEASE_RUNNER_ATTESTED=local-dev`. This
opt-out is intentional, narrowly scoped, and documented at the top of the
script. A `local-dev` build is not a release build: artifacts produced this
way must not be signed by the release key, must not be uploaded to the
release bucket, and the script tags its output directory accordingly.
