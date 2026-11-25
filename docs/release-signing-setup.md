# Release signing setup

Status reviewed on 2026-10-18. Signing is not set up yet. This run created no
developer account, certificate, private key, notarization credential, or signed
release.

The inspected Mac has zero valid code-signing identities. The five Apple inputs
listed below are absent from its environment. Repository-level GitHub Actions
variable and secret name listings are empty. These checks do not establish
whether an Apple membership or credentials exist elsewhere. No signing host has
been chosen. Unsigned installer tests and hosted CI can proceed independently;
they do not establish signing or Gatekeeper acceptance.

## Get the Mac signing identity

1. Choose the legal publisher and its Account Holder. Reuse an existing Apple
   Developer Program membership if the intended publisher already has one.
   Otherwise enroll as an individual or organization using an Apple Account with
   two-factor authentication. Organization enrollment requires a legal entity,
   binding authority, a domain-associated work email and website, and normally a
   D-U-N-S number. Apple lists the annual fee as USD 99, with regional pricing
   and possible taxes. Complete Apple's verification and membership activation
   before proceeding. See [Apple's enrollment requirements](https://developer.apple.com/help/account/membership/program-enrollment/).
2. Choose a controlled Mac for native signing and a custodian for its Keychain.
   Install Xcode and confirm `xcrun notarytool --help` works. Resolve the build and
   signing boundary described below before importing keys onto a runner.
3. On that Mac, use Keychain Access, Certificate Assistant, Request a Certificate
   from a Certificate Authority. Supply the publisher's email and a recognizable
   key name, leave the CA email empty, and save the CSR to disk. Keep the private
   key in the chosen Keychain. Follow [Apple's CSR instructions](https://developer.apple.com/help/account/certificates/create-a-certificate-signing-request/).
4. Have the Account Holder create **Developer ID Application** and **Developer
   ID Installer** certificates in Certificates, Identifiers & Profiles, Software,
   Developer ID. Application signs Locket.app and its CLI; Installer signs the
   `.pkg`. Upload the CSR and install each downloaded `.cer` on the Mac holding
   its matching private key. These certificates support distribution outside the
   Mac App Store, so no App Store listing is needed. Cloud-managed Developer ID
   access for eligible admins is a separate option; the current shell packaging
   path expects usable local identities. See [Apple's Developer ID instructions](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/).
5. In Keychain Access, My Certificates, confirm that each certificate has its
   private key. A downloaded `.cer` alone cannot sign. Record the exact identity
   names, Team ID, fingerprints, expiration dates, custodian, and recovery owner
   in the private operations inventory. The following inspection commands expose
   public certificate metadata, not private keys:

   ```sh
   security find-identity -v -p codesigning
   security find-identity -v
   ```

   The first command checks application signing identities. Inspect the Installer
   identity separately with the second command and Keychain Access.

If a second Mac needs the identity, export the certificate with its private key
as a password-protected `.p12`, import it into that Mac's dedicated signing
Keychain, and verify it there. Apple's [certificate export instructions](https://help.apple.com/xcode/mac/current/en.lproj/dev154b28f09.html)
describe this format. Keep any encrypted backup in the approved private vault,
with its password held separately. Never put `.p12`, private keys, passwords, or
Keychain files in Git, build artifacts, shared caches, or run evidence. Remove
temporary transfer copies after confirming import and recovery. The ordinary
build workflow must not receive these keys.

## Configure notarization

The existing packager supports an Apple Account plus an app-specific password.
Create a dedicated password at account.apple.com, Sign-In and Security,
App-Specific Passwords, after enabling two-factor authentication. Do not use the
primary account password. Password resets revoke existing app-specific passwords;
replace the release credential when that happens. See [Apple's password guide](https://support.apple.com/en-us/102654).

Apple also supports App Store Connect API authentication with a private `.p8`
key, key ID, and issuer ID. This authenticates notarization; it does not replace
the Developer ID private keys. Use a team key created by an App Store Connect
Admin; Apple's current API-key documentation excludes individual keys from
`notaryTool`. See [Apple's API-key requirements](https://developer.apple.com/documentation/appstoreconnectapi/creating-api-keys-for-app-store-connect-api).
The current packager has no API-key or Keychain
profile option. Choosing either requires a packaging change and verification
before a signed release. See [Apple's notarytool credential options](https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool).

For a manual credential check, this command prompts for the app-specific password
and stores it in Keychain. Replace the placeholders; do not paste a password into
the command or enable shell tracing:

```sh
xcrun notarytool store-credentials 'locket-notary' \
  --apple-id '<APPLE_ACCOUNT_EMAIL>' --team-id '<TEAM_ID>'
xcrun notarytool history --keychain-profile 'locket-notary'
```

The profile test confirms service access only. `package-native-installers.sh`
still requires `APPLE_APP_SPECIFIC_PASSWORD` supplied through the controlled
signing environment until profile support is implemented. Apple describes
submission, checking the notarization log, and attaching tickets in its
[custom notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).

## Wire the existing packaging inputs

[`scripts/package-native-installers.sh`](../scripts/package-native-installers.sh)
currently reads these exact inputs:

| Input | Supply on the controlled signing host |
| --- | --- |
| `APPLE_DEVELOPER_ID_APPLICATION` | Exact `Developer ID Application: <publisher> (<TEAM_ID>)` identity name |
| `APPLE_DEVELOPER_ID_INSTALLER` | Exact `Developer ID Installer: <publisher> (<TEAM_ID>)` identity name |
| `APPLE_ID` | Apple Account email authorized for the selected team |
| `APPLE_APP_SPECIFIC_PASSWORD` | Dedicated notarization password, injected privately |
| `APPLE_TEAM_ID` | Team ID from the active membership |
| `LOCKET_RELEASE_RUNNER_ATTESTED` | Verified isolated release runner identity; `local-dev` is rejected for signed packaging |
| `CARGO_TARGET_DIR`, `LOCKET_BUILD_ROOT` | Task-owned paths under `/Volumes/Scratch/locket/build/<task>` on local Macs |
| `NATIVE_INSTALLER_OUT_DIR`, `TMPDIR` | Task-owned Scratch output and temporary directories |

Identity names and Team ID are configuration, not private keys. Environment
variables alone do not install certificates, unlock a Keychain, or grant signing
access. No certificate-import or private credential-injection setup exists in the
release workflow. Its repository variables `LOCKET_RELEASE_RUNNER_ID` and
`LOCKET_RELEASE_RUNNER_LABELS` select and identify a runner; setting a string does
not prove isolation.

Before the first signed build, reconcile the existing policies. The
[runner policy](../dist/release-ci-runners.md) keeps signing keys out of CI and
excludes signing services from build-runner egress. The native packager currently
builds and signs in one invocation on an attested isolated runner. Choose and
document a controlled native signing stage, its custody and network permissions,
and any needed separation of build from signing. Do not solve this by copying
private keys into ordinary hosted validation jobs.

Then qualify the chosen Mac with `cargo-auditable`, `cargo-audit`, Tauri and UI
dependencies, an accessible signing Keychain, and notarization network access.
The signed path audits embedded Rust binaries, signs the CLI and app, signs the
package, submits it to Apple, and staples its ticket. Retain the notarization
submission ID, status, and log privately under Scratch reports.

Before publication, require an accepted notarization result, successful
`codesign --verify --deep --strict '<Locket.app>'`,
`pkgutil --check-signature '<Locket.pkg>'`, and
`xcrun stapler validate '<Locket.pkg>'`. Assess the downloaded installer with
`spctl --assess --type install --verbose=4 '<Locket.pkg>'`, then install and launch
it on a clean Mac under normal Gatekeeper settings. Verify the installed app and
bundled CLI. A successful unsigned installation does not satisfy these gates.

## Renewal and compromise

Calendar membership renewal and each certificate's actual expiration, with an
owner and advance reminders. Issue replacements before the next signed release
needs them. Existing apps may continue after certificate expiry; revocation can
prevent signed apps from installing or launching. Treat Installer certificate
expiry as a package re-signing and requalification gate rather than relying on
old downloads remaining usable. See
[Apple's expiry guidance](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/).

If a private key may be compromised, stop releases, isolate the signing host, and
have the Account Holder request Developer ID revocation through
`product-security@apple.com`, as directed by Apple's [compromised-certificate
guidance](https://developer.apple.com/help/account/certificates/certificates-overview#Compromised-certificates).
Rotate exposed notarization credentials separately, replace identities, and
requalify rebuilt packages before publication. Deleting a local Keychain item
does not revoke its certificate.

## Windows, Linux, and VSIX

| Artifact | Remaining setup |
| --- | --- |
| Windows MSI | Obtain a trusted publisher code-signing certificate and choose its hardware or managed private-key custody. The current path expects an accessible Windows certificate-store identity via `WINDOWS_EV_CERT_SHA1` and an RFC 3161 service via `WINDOWS_TIMESTAMP_URL`. Its name reflects the repository's EV expectation; a cloud service needing a different signing interface requires code changes. Install the Windows SDK SignTool, verify the chosen provider works with this invocation, then qualify the signed MSI on Windows. |
| Linux DEB | Provision the intended GPG signing identity and custody, supply `LOCKET_DEB_GPG_KEY`, and qualify the current `debsign` invocation against the produced package. Decide repository metadata signing and public-key distribution separately. |
| Linux RPM | Provision the intended GPG signing identity and custody, supply `LOCKET_RPM_GPG_NAME`, then verify the signed RPM and its key distribution on Linux. |
| Direct-download VSIX and release manifests | Confirm possession and operation of the offline release quorum described in the existing release-key documents. Apple and Windows certificates do not satisfy that trust requirement. |

Microsoft documents SignTool's certificate selection, SHA-256 signing,
timestamping and verification in its [SignTool reference](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool).
The current script signs the MSI container; separately verify the signature
coverage required for its installed executables before calling Windows signing
complete.

Follow [`dist/release-key-offline.md`](../dist/release-key-offline.md) and
[`dist/vscode-vsix-signing.md`](../dist/vscode-vsix-signing.md) for the independent
release-key ceremony. Checked-in public keys do not prove current private-key
custody. The VSIX hook expects `LOCKET_MINISIGN_SECRET_KEY` as a private-key file
path and a matching public key ID. Its single detached signature must not be
mistaken for proof of the documented 3-of-5 release quorum. Verify that full
ceremony and downstream quorum checks before a public release, and keep its
private material off build runners.

## Verify reproducible CLI builds

From the release commit, run `make reproducible-check` with the pinned Rust
toolchain, the native compiler and SDK used for the target, and the locked Cargo
dependencies already cached. The release workflow runs this check on Linux and
macOS after fetching the locked dependencies. On a local Mac, use the shared
compute broker.

```sh
TMPDIR=/Volumes/Scratch/locket/t compute run --class heavy --where local --sync "$PWD" -- make reproducible-check
```

The check builds the release-profile `locket` CLI offline in two fresh build
directories. It uses the current commit timestamp as `SOURCE_DATE_EPOCH`, remaps
compiler paths, disables incremental compilation, and requires identical SHA-256
digests. Local build directories live under `/Volumes/Scratch/locket/tmp`. CI
places them under `TMPDIR`. To diagnose a mismatch, rerun with
`LOCKET_KEEP_REPRO_BUILDS=1` and compare the two retained binaries.

The digests apply to the CLI produced by this command on the same host and
toolchain. Verify the provenance of the separately built auditable release
binaries, and verify native signatures and notarization on the packaged artifacts.

## Set up Cargo Vet

Run `cargo vet init` once at the workspace root and review the generated
`supply-chain/` files alongside `Cargo.lock`. Initialization creates exemptions
for the current dependency graph. Replace those exemptions with review records
as audits are completed. Use `safe-to-deploy` for shipped dependencies and
`safe-to-run` for test-only dependencies. For the dependencies below, require
`safe-to-deploy` coverage for every version used by a shipped target before
approving the release. [Cargo Vet setup](https://mozilla.github.io/cargo-vet/setup.html).

| Dependency | Review scope |
| --- | --- |
| `aws-lc-sys` | Bundled AWS-LC source provenance, native build and linking, and the Rust FFI boundary. |
| `rusqlite` | Rust bindings and bundled SQLite provenance, with a corresponding review of `libsqlite3-sys`. |
| `objc2` | Objective-C runtime calls, ownership and lifetime assumptions, and enabled Apple framework bindings. |
| `windows-sys` | Generated bindings, enabled Win32 API families, and every locked version in a shipped Windows target. |

Record a versioned audit with `cargo vet certify <crate> <version> --criteria
safe-to-deploy` after reviewing the published source. Review the diff from the
last audited version when upgrading. Import third-party audits only after
verifying the audit publisher, review criteria, and version coverage. Require
version-specific audits for the four dependencies above and keep any other
temporary exemptions scoped to a version with an owner, reason, and expiry.
[Cargo Vet audit commands](https://mozilla.github.io/cargo-vet/commands.html#cargo-vet-certify).

Commit the vetted `supply-chain/` records with the lockfile and run
`cargo vet --locked --frozen` against the cached graph and recorded audits.
Continue running `make supply-chain-local` for the separate RustSec, license,
and source checks.
