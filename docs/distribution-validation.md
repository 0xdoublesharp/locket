# Build matching Locket packages

The workspace, desktop, UI, and VS Code extension use the same version. `node scripts/distribution.mjs versions` rejects a mismatch. Releases also set `LOCKET_RELEASE_TAG=v<version>` so a wrong tag fails before building.

For local validation on macOS:

```sh
export TMPDIR=/Volumes/Scratch/locket/tmp/package-check
export CARGO_TARGET_DIR=/Volumes/Scratch/locket/cargo/package-check
export LOCKET_BUILD_ROOT=/Volumes/Scratch/locket/build/package-check
export RUSTC_WRAPPER=sccache
mkdir -p "$TMPDIR" "$CARGO_TARGET_DIR" "$LOCKET_BUILD_ROOT"
scripts/package-native-installers.sh --target host --unsigned
scripts/package-vscode-extension.sh
scripts/validate-packaged-os-canaries.sh --artifact-root "$LOCKET_BUILD_ROOT/package"
```

Install the pinned `tauri-cli` 2.10.1 build tool and the existing locked UI/editor dependencies first. The scripts compile frontend/editor output in a staging directory under `LOCKET_BUILD_ROOT`. Native packaging builds and embeds the exact matching CLI. The desktop resolves the installed resource directory and checks CLI version before using it. VSIX validation opens the compressed archive and checks its identity, version, entry point, and excluded development files.

The package-validation workflow downloads and installs the unsigned native package on a separate fresh GitHub-hosted runner. The acceptance job does not install build dependencies; hosted images still contain preinstalled software and are not minimal consumer OS installations. It checks installed package metadata and the desktop executable, runs the installed bundled CLI version check, and scans the installed payload for canaries. Linux also checks the desktop executable for unresolved runtime libraries. `scripts/validate-installed-native.py` refuses local and self-hosted installation. These checks do not exercise the desktop GUI or native authentication.

For a real installed-extension host check with your existing VS Code binary, run:

```sh
scripts/validate-packaged-os-canaries.sh --artifact-root "$LOCKET_BUILD_ROOT/package" --editor-smoke
```

This installs the VSIX into temporary user-data and extension directories, activates its actual compiled entry point, and checks all nine commands. It uses an absent synthetic agent socket and opens only a temporary workspace. Keep `TMPDIR` on Scratch. The `--editor-smoke` option does not invoke a native installer or require release signatures.

Unsigned packages are for local validation. They have no notarization or release-signing claim. Signed macOS packaging requires both Developer ID Application and Installer identities, plus notarization credentials. Signed packaging also requires an attested isolated release runner and cargo-auditable/cargo-audit. Both binaries are built through the auditable runner and checked before signing; macOS checks the exact nested app binaries as well. The nested CLI is signed before bundling. Windows and Linux signed paths retain their certificate/GPG requirements. Publication remains a separate authorized release operation.

Optional `--install-smoke` additionally checks the host package's release signature and runs the editor host check. Its signature requirements do not apply to `--editor-smoke` alone. Neither check establishes a human's complete editor workflow.

Use the [release signing setup report](release-signing-setup.md) to provision identities and notarization before attempting the signed path.

The package-validation workflow builds unsigned host packages for macOS, Windows, and Linux. A local check does not establish that those CI jobs passed or that an installer works on a clean OS. Retain only needed artifacts; stop their processes before removing task-owned Scratch output. Shared compiler caches and dependency directories are reusable.
