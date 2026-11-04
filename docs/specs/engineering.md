# Engineering Standards & Dependencies

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Engineering Standards

Locket will handle secret material, so the default engineering posture is stricter than a normal CLI from the first commit.

- Prefer small crates with explicit ownership boundaries.
- Keep public APIs typed; avoid stringly typed policy, crypto, storage, and IPC boundaries.
- Use `thiserror` for typed library errors and `anyhow` only at executable edges.
- Do not log, print, serialize, snapshot, or persist secret values.
- Do not use `unwrap`, `expect`, `panic`, `todo`, `unimplemented`, or `dbg` in production code.
- Do not introduce `unsafe` without a documented design review and a narrow exception.
- Add tests before or alongside behavior changes. Security-sensitive behavior needs regression tests.
- Add fuzz coverage for parsers, protocol decoders, scanners, redactors, bundle readers, and env merge logic.
- Keep dependencies minimal and justify new dependencies that touch crypto, IPC, parsing, persistence, local user verification, or desktop integration.
- Rust code must pass `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace --all-targets --all-features` before merge.
- Production crates must deny `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic`, `clippy::todo`, `clippy::unimplemented`, `clippy::dbg_macro`, `clippy::print_stdout`, and `clippy::print_stderr`. Test modules and fuzz harnesses may allow these lints locally only when the exception is narrow and does not hide production behavior.
- Security-critical crates (`locket-core`, `locket-crypto`, `locket-store`, `locket-agent`, and `locket-exec`) must deny undocumented `unsafe`; any required `unsafe` must be isolated behind platform modules with tests and a safety comment.
- Documented `unsafe` inventory (audit before each release; cross-check against `cargo geiger` output in `target/quality/unsafe-inventory.md`):
  - `locket-platform::macos_local_authentication` — wraps `LAContext::evaluatePolicy:localizedReason:reply:` for the macOS user-verification backend (`docs/specs/crypto.md:192-218`). The `unsafe` is confined to that module via a `SAFETY-AUDIT` comment; the rest of `locket-platform` keeps `unsafe_code = "deny"` and `MacosLocalUserVerifier` itself has zero `unsafe`.
  - `locket-platform::session::macos` — owns Core Foundation notification/run-loop and IOKit power registrations on the main thread, with daemon work on a separate thread. Callback contexts outlive registration and carry no keys. Only retained run-loop wakeup/source signaling crosses threads. Sleep acknowledgement is bound to its notification and follows key erasure; timeout or event-queue overflow terminates the daemon. Shutdown wakes pending acknowledgements, removes observers, and joins the worker before releasing contexts. Direct `objc2-core-foundation` and `objc2-io-kit` dependencies match the existing objc2 native binding family with narrow features; they provide the existing OS APIs without an AppKit dependency. The main CFRunLoop satisfies [Apple's notification delivery requirement](https://developer.apple.com/documentation/corefoundation/cfnotificationcenteraddobserver(_:_:_:_:_:_:)). Regression coverage exercises OS notification delivery, callback acknowledgement, and cleanup without locking or sleeping the host.
- Public APIs must use typed ids and typed errors, not raw strings, for project/profile/secret/key/device/member/client identifiers.
- The Windows storage FFI boundaries are `storage::windows_directory`, which creates and verifies protected current-user directory ACLs and checks ancestor replacement rights, and `storage::windows_file_identity`, which reads volume and 128-bit file identifiers from borrowed handles. File identity checks let policy updates read through their lock-owning handle while detecting pathname replacement. Both modules keep unsafe calls isolated and document handle/buffer lifetimes.
- Logging must be structured and metadata-only. Tests must include assertions that known secret values do not appear in logs, audit rows, generated files, debug bundles, or error messages.

## Required Quality Tooling

The implementation should expose these checks through `make` targets so local development and CI use the same commands:

- Formatting: `cargo fmt --all -- --check`; frontend code uses Prettier through `pnpm format:check` once the Tauri app exists.
- Rust lints: `cargo clippy --workspace --all-targets --all-features -- -D warnings` plus the production panic/printing bans listed above.
- Rust tests: `cargo nextest run --workspace --all-features` is the preferred default runner; `cargo test --workspace --all-targets --all-features` remains required for doctests and compatibility.
- Coverage: `cargo llvm-cov` is the canonical coverage backend because it reports line and branch coverage consistently across the workspace.
- Mutation checks: `cargo mutants` or an equivalent mutation-testing tool must run on policy evaluation, env merge, typed error mapping, and authorization boundaries before public release and whenever those areas receive risky changes.
- Dependency hygiene: `cargo machete` or `cargo udeps` should run regularly to remove unused dependencies; unused dependencies in security-critical crates are review blockers.
- Unsafe inventory: `cargo geiger` or equivalent must run before public releases and after any dependency change that touches crypto, IPC, platform verification, or storage.
- Frontend quality once `locket-app` exists: `pnpm lint`, `pnpm typecheck`, `pnpm test`, and `pnpm build` must pass before merging app changes. UI tests that exercise reveal/copy/tray flows must assert that secret values never enter persistent app state.
- Documentation quality: Markdown specs should pass a link check and a basic markdown linter before release branches are cut.

## Commit Discipline

- Commit coherent, reviewable changes.
- Do not include coauthor trailers.
- Keep generated output, formatting churn, and unrelated edits out of feature commits.
- Every commit that changes behavior should include tests or document why tests are not applicable.

## Review Bar

A change is not ready if it:

- Can print or persist a secret value through an error, trace, test snapshot, debug bundle, or UI state.
- Weakens deny-by-default behavior.
- Adds a new secret delivery path without policy and audit coverage.
- Adds a parser or binary decoder without malformed-input tests and a fuzz target.
- Adds a new storage migration without rollback/fail-closed behavior.
- Adds a CLI command without failure-mode documentation.
- Adds a network call, remote resource load, telemetry-like event, or support artifact path without an explicit privacy review and data-minimization note.
- Adds a new metadata field or display surface without deciding whether `privacy.redact_names` applies.
- Adds or changes dependencies that touch crypto, IPC, parsing, persistence, local user verification, or desktop integration without explicit review notes.

Testing and fuzzing requirements are normative in [testing.md](testing.md) and [fuzzing.md](fuzzing.md).

## Dependency Baseline

The first implementation should target Rust 2024 on the stable toolchain pinned in `rust-toolchain.toml`. The MSRV may be the pinned stable release while the app is pre-1.0; once public releases begin, MSRV changes must be deliberate and documented.

Required dependency direction:

```toml
anyhow = "1"
age = { version = "0.11.5", default-features = false }
argon2 = { version = "0.6", default-features = false, features = ["alloc", "zeroize"] }
arboard = "3"
chacha20poly1305 = { version = "0.11", default-features = false, features = ["alloc", "zeroize"] }
clap = { version = "4", features = ["derive", "env"] }
data-encoding = "2"
directories = "6"
dotenvy = "0.15"
ed25519-dalek = "3"
hkdf = "0.13"
hmac = "0.13"
ignore = "0.4"
keyring = "3"
libc = "0.2"
rand = "0.10"
regex = "1"
rpassword = "7"
rusqlite = { version = "0.41", default-features = false, features = ["bundled", "cache"] }
secrecy = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.11"
tempfile = "3"
thiserror = "2"
time = { version = "0.3", features = ["serde", "formatting"] }
tokio = { version = "1", features = ["macros", "net", "rt-multi-thread", "sync", "time"] }
toml = "1"
tracing = "0.1"
x25519-dalek = { version = "3", features = ["static_secrets"] }
zeroize = "1"
```

Required development/test dependencies:

```toml
assert_cmd = "2"
predicates = "3"
proptest = "1"
tempfile = "3"
```

Version numbers are a starting baseline, not permission to pin stale releases indefinitely. Before adding each crate, check its current release, maintenance status, advisories, license, feature flags, and whether the standard library or an existing dependency now covers the need. Security-sensitive crates require an implementation note explaining why that crate is acceptable. If a newer stable major is available, prefer migrating the spec and code to that major before first public release rather than carrying compatibility debt from the scaffold.

Desktop dependency direction:

- Use the latest stable Tauri v2 minor at app scaffolding time.
- Keep Tauri dependencies isolated to `locket-app` and its frontend workspace.
- Use Tauri capabilities, permissions, and scopes for desktop command access control; do not expose unrestricted filesystem, shell, clipboard, updater, or network capabilities to the webview.
- Tauri updater support must remain opt-in and must verify the signed Locket update manifest described in [operations.md](operations.md).

Release and supply-chain tooling:

- Project-owned scripts should use Bash for orchestration and Node `.mjs` for JSON parsing, report generation, and release metadata validation. Do not add new Perl tooling.
- Use `cargo deny` for license/advisory/source policy.
- Use `cargo audit` or the RustSec advisory database in CI.
- Use `cargo vet` or an equivalent third-party crate review record before public release; all direct dependencies in security-sensitive crates need an explicit trust/review entry or a documented temporary exception.
- Generate SBOMs for public release artifacts.
- Generate third-party notices from locked dependency metadata; release artifacts that contain MPL-2.0 covered crates must include `target/quality/THIRD_PARTY_NOTICES.md` or an equivalent notice/source-availability document.
- Build release binaries with dependency metadata embedded through `cargo auditable` or an equivalent mechanism where supported.
- Sign release artifacts and update manifests.
- Generate and verify SLSA v1.2-compatible provenance for release builds where the package ecosystem supports it; target Build L3 controls for public release artifacts where hosted isolated runners make that practical.
- Prefer keyless signing with transparency logs for CI-produced public artifacts where practical; offline release keys remain required for update-manifest trust roots.
- Run OpenSSF Scorecard or equivalent repository security checks once the public repository and CI exist.

Supply-chain checks are blocking:

- Pull requests must pass formatting, linting, test, coverage-threshold, `cargo deny`, and RustSec advisory checks before merge.
- Pull requests that add or change dependencies in crypto, IPC, parsing, persistence, platform verification, desktop integration, update, or release code must include review notes covering maintenance status, license, feature flags, transitive dependency risk, and why an existing dependency or the standard library is insufficient.
- `cargo deny` must fail on yanked crates, unknown registries, git dependencies without an explicit exception, duplicate security-sensitive crates where one version can be removed, licenses outside the project allowlist, and denied advisories.
- High and critical RustSec advisories fail CI. Medium advisories fail CI for runtime dependencies and require an issue-linked exception for dev-only dependencies. Low advisories require triage before release.
- Supply-chain exceptions must name the package, version, reason, compensating controls, owner, and expiration date. Exceptions without expiration are invalid.
- Release builds must additionally generate SBOMs and third-party notices, verify provenance, run unsafe inventory checks, run the public artifact signing flow, and verify the signed update manifest before publishing.

Fuzz targets should use `cargo-fuzz`/`libFuzzer` where available. Fuzz harnesses live outside release crates and must not require real keychain, biometric, Docker, or desktop services.

The agent transport uses Tokio-native Unix sockets and Windows named pipes (`tokio::net::UnixListener` and `tokio::net::windows::named_pipe`) with `#[cfg(unix)]` and `#[cfg(windows)]`; do not add a separate IPC abstraction crate unless Tokio lacks a required platform feature.

Platform user-verification dependencies belong in `locket-platform` behind target-specific feature flags. macOS should use LocalAuthentication.framework bindings; Windows should use Windows Hello user-consent APIs through the `windows` crate; Linux uses the packaged polkit action. The optional external-key wrapping backend uses libfido2's verified command-line ceremonies from trusted absolute installation paths, with bounded output and timeouts. This avoids another cryptography implementation or application FFI boundary. Do not use a browser-oriented `passkey` crate for general local user-presence gates. WebAuthn/PRF dependencies may be added only for the optional authenticator key-wrapping path.

Tauri-specific dependencies belong only in `locket-app`. VS Code extension dependencies belong outside the Rust crate graph.
