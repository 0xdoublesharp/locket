# Homebrew formula for Locket

This directory holds the working-draft Homebrew formula for the Locket CLI.
It is checked into the source tree so that the formula can evolve alongside
the codebase, and so the eventual tap can be regenerated mechanically from a
signed release tag rather than authored by hand at release time.

## Status

The formula is a build-from-source draft. It is not yet published to a tap
because the offline release-signing ceremony is incomplete. See the
`release-key-offline` item in `docs/agents/progress.md` for the gating work.

While the draft is in this directory:

- It can be linted with `brew audit --strict --new-formula dist/homebrew/locket.rb`.
- It can be installed locally for testing with
  `brew install --build-from-source dist/homebrew/locket.rb`.
- The `sha256` and `url` fields contain placeholders; do not publish the
  formula in this state.

The publishable formula is generated from `dist/homebrew/locket.rb.in` using
the signed source-tarball URL and SHA-256 recorded by the release ceremony:

```sh
scripts/render-homebrew-formula.sh \
  --version 0.1.0 \
  --url https://github.com/0xdoublesharp/locket/releases/download/v0.1.0/locket-0.1.0-src.tar.gz \
  --sha256 <64 lowercase hex>
```

The unified package gate also renders a syntax-checked formula into
`target/package/homebrew/locket.rb`:

```sh
scripts/validate-distribution.sh
```

Set `LOCKET_HOMEBREW_AUDIT=1` when rendering on a host with Homebrew to run
`brew audit --strict --new-formula` on the generated formula.

The release operator checklist makes the final tap update deterministic:

```sh
scripts/release-operator-runbook.sh \
  --task homebrew-tap-publish-operator \
  --signed-source-url https://github.com/0xdoublesharp/locket/releases/download/v0.1.0/locket-0.1.0-src.tar.gz \
  --signed-source-sha256 <64 lowercase hex>
```

The command is dry-run by default. On the credentialed release host, set
`LOCKET_HOMEBREW_TAP_DIR` to a checkout of `doublesharp/homebrew-locket` and
add `--execute --confirm publish-v0.1.0`.

## Intended tap path

Once `release-key-offline` ships, the formula will live at:

- Tap repository: `doublesharp/homebrew-locket`
- Formula path: `Formula/locket.rb`
- User install command: `brew tap doublesharp/locket && brew install locket`

## Release-tag to formula update flow

1. Cut a signed release tag in `0xdoublesharp/locket` (for example, `v0.1.0`).
   This step depends on the offline release key ceremony and signed source
   tarball production.
2. The release pipeline publishes a signed source tarball as a GitHub
   release asset and records its SHA256.
3. A formula-update job copies `dist/homebrew/locket.rb` from the source
   tree, renders `dist/homebrew/locket.rb.in` with the version, `sha256`,
   and signed source-tarball URL, and opens a pull request against the
   `doublesharp/homebrew-locket` tap repository.
4. The tap PR runs `brew audit --strict --new-formula` and the formula's
   `test do` block in CI before merging.
5. Users `brew upgrade locket` after the tap PR merges; no client-side
   action is required between releases.

## Why a tap instead of homebrew-core

A personal tap is the right initial home for Locket because:

- Locket is a security-sensitive tool whose distribution chain we want to
  control end to end during the early-release period.
- homebrew-core requires a stable release cadence and an established user
  base before accepting a new formula.
- The tap repository can mirror the same signed-tarball verification flow
  the binary release pipeline uses, without depending on homebrew-core
  release scheduling.

## Dependencies on other roadmap items

- Signed source tarball (credential-only): the formula cannot be published
  until the release tarball is signed by the offline release key and the
  SHA256 is recorded for that signed tarball.
- `auditable-builds` (parallel): once cargo-auditable is wired into the
  release flow, the brew-installed binary will inherit the embedded SBOM
  and downstream `cargo audit bin` checks will work against the
  brew-installed binary too.
- `cargo-install-path` (parallel): the formula depends on
  `cargo install --locked --path crates/locket-cli`. Any required
  `crates/locket-cli/Cargo.toml` metadata fields are tracked under that
  item.
