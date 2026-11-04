# Library update review

The Rust workspace and separate fuzz lockfile use current compatible releases
on the existing Rust 1.99 toolchain. Direct migrations include Argon2 0.6,
ChaCha20-Poly1305 0.11, Ed25519/X25519 Dalek 3, rusqlite 0.41, Bech32 0.12,
and base64 0.23. Tauri updates to 2.12 and Tokio to 1.54.

## Security-sensitive dependencies

These maintained upstream packages provide cryptography, SQLite, OS integration,
and serialization that the standard library cannot replace. Their MIT,
Apache-2.0, and BSD-3-Clause licenses remain within the dependency policy;
existing transitive license exceptions still apply. Registry dependencies stay
checksum-locked, with no new git sources or advisory exceptions.

- Argon2 enables only allocation and zeroization. Its raw Argon2id v0x13 API
  and stored KDF parameters remain unchanged. ChaCha20-Poly1305 explicitly
  enables zeroization, which became optional in 0.11, and allocation without
  adding its RNG interface. Dalek retains its zeroizing defaults and X25519
  static-secret support. See the upstream [Argon2 changelog](https://github.com/RustCrypto/password-hashes/blob/master/argon2/CHANGELOG.md)
  and [ChaCha changelog](https://github.com/RustCrypto/AEADs/blob/master/chacha20poly1305/CHANGELOG.md).
- Synthetic fixtures generated with Argon2 0.5.3, ChaCha20-Poly1305 0.10.1,
  age 0.11.5, and Bech32 0.11.1 check existing derived keys, ciphertext,
  wrapped keys, and raw X25519 bundle identities. Authentication failures
  remain covered; the update does not change stored formats.
- rusqlite keeps bundled SQLite and statement caching, with the new default
  WebAssembly backend disabled. No application schema migration is introduced.
- base64's direct dependency enables only `std`; desktop dependencies still
  enable its default SIMD implementation through Cargo feature unification.
  Tauri and the native bindings keep existing capabilities and permission scopes.
- age stays at 0.11.5. Version 0.12.1 unconditionally adds HPKE/P-256 and
  `crypto-bigint` 0.5.5, affected by [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
  Resume that upgrade when upstream accepts a patched arithmetic dependency.
  The older transitive ChaCha/X25519 generations and the
  `proc-macro-error2` future-compatibility warning therefore remain; forcing
  incompatible transitive versions would bypass upstream compatibility bounds.

RustSec's informational warnings also remain for `basic-toml` and the macro
crates used by age/GTK, and for `zvariant`, `zvariant_derive`, and `zbus_names`
through the Linux keyring backend. The latter have [moved into zbus 6](https://rustsec.org/advisories/RUSTSEC-2026-0370.html),
which requires an upstream keyring migration. Tauri's Linux GTK stack still
requires glib 0.18.5 with [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html);
the fixed glib 0.20 is outside its dependency bounds. These are existing
upstream constraints, not resolved by refreshing lockfiles. Track their removal
through compatible upstream releases; a passing advisory policy does not mean
the graph has no informational warnings.

## Native session and authentication additions

Native Linux session observation adds zbus 6 with only Tokio/proxy features and
futures-util with `std`. D-Bus is required to use logind's session state and
suspend inhibitor; the observer connects to the fixed system socket, validates
the root-owned service's unique sender, and stops on ownership loss. This direct
dependency does not replace the older keyring dependency graph described above.
Both lockfiles retain registry checksums and the existing license policy.

Windows enables additional `windows-sys` window, WTS, module, and graphics
bindings. The new unsafe boundary is confined to `session/windows.rs`: a single
thread owns the hidden window, notification registration, callback context, and
teardown. Callback state is thread-local, never taken from message pointers;
WTS buffers are checked and freed with the matching OS allocator. Callbacks
carry session metadata and wait for bounded key-erasure acknowledgement.
Windows token queries now allocate pointer-aligned storage before reading
`TOKEN_USER`; session queries copy returned bytes into aligned local storage
before interpreting `WTSINFOEXW`.
Temporary env-file creation on Windows uses an isolated filesystem boundary in
`locket-platform`. It creates a protected inheritable ACL for the current SID
before writing, verifies the resulting descriptor, and rejects parent paths
that another unprivileged account could replace. Descriptor/ACL pointers remain
owned by Windows allocations through each synchronous call and are freed with
the matching allocator. `locket-exec` reuses this boundary through a Windows-only
dependency rather than adding unsafe code to its execution logic.
Linux authentication uses a fixed polkit executable and policy rather than a
new native FFI dependency; child environment and timeout are bounded.

CLI checkpoint files reuse tempfile and rustix's `fs` feature for atomic export
and no-follow, nonblocking reads on Unix. Checkpoint authentication uses the
existing HMAC implementation with a separate domain and constant-time tag
verification. No encryption format or key derivation changes are introduced.

## External FIDO2 tools

The optional terminal passkey backend uses separately installed libfido2 tools
(BSD-2-Clause), requiring version 1.17 or newer for forced-PIN registration.
Version 1.17 also fixes the Windows library search issue and removes the tools
from Windows SDK packaging; the terminal adapter remains macOS/Linux-only.
See the upstream [release notes](https://developers.yubico.com/libfido2/Release_Notes.html)
and [assertion tool contract](https://developers.yubico.com/libfido2/Manuals/fido2-assert.html).

Locket verifies signatures using those tools, with fresh challenge/RP binding
and the stored public key. Executables come from checked absolute installation
paths with a cleared child environment. PIN input stays on the controlling
terminal; PRF output stays in bounded, zeroizing memory. Only the public key PEM
is written temporarily for signature verification. The existing rustix
dependency enables `termios` to restore terminal settings when a helper is
cancelled or times out. No new application unsafe code or Rust cryptographic
dependency is required.

## JavaScript tooling

Desktop and extension dependencies are updated independently in their pnpm
lockfiles. The extension keeps its existing minimum VS Code API while migrating
its lint configuration and TypeScript module resolution to current tooling.
VS Code typings are pinned to 1.80.0, matching that minimum. Development and
packaging use Node 24, matching CI; the extension's runtime requirement stays
unchanged. The new direct lint dependencies, `@eslint/js` and `globals`, are
MIT licensed.

Both packages retain TypeScript 6.0.3 because the current TypeScript ESLint
parser supports versions below 6.1. TypeScript 7 needs compatible lint tooling
before migration. Vite moves to 8.3, Vitest to 5.1, and the extension to ESLint 10
and vsce 4.

Both pnpm workspaces override only `minimatch@>=7.0.0 <11.0.1` to 11.0.4 for
[GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249).
Current upstream lint tooling still requests the affected versions. Remove
the override when upstream requirements include the fix. The lint, build,
test, and packaging checks exercise the override with the consuming tools.
