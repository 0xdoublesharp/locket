#!/usr/bin/env bash
set -euo pipefail

# Build and install the local macOS CLI (/Users/<user>/.cargo/bin/locket) and
# Desktop app (/Applications/Locket.app), preferring a persistent local code
# signing certificate so macOS Keychain keeps trusting rebuilt binaries.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="${TMPDIR:-/Volumes/Scratch/locket/t}"
export TMPDIR
mkdir -p "$TMPDIR"

RESTART_AGENT="auto"
SIGN_IDENTITY="${LOCKET_SIGN_IDENTITY:-}"

usage() {
    cat <<'EOF'
Usage: scripts/install-local.sh [--restart | --no-restart] [--identity <NAME>]

Options:
  --restart          Restart the running agent after install (clears active unlocks).
  --no-restart       Install binaries without restarting the running agent.
  --identity <NAME>  Use a specific macOS code-signing identity (default: auto-detect
                     "Locket Local Dev" or "Developer ID Application", else ad-hoc).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --restart) RESTART_AGENT="yes"; shift ;;
        --no-restart) RESTART_AGENT="no"; shift ;;
        --identity) SIGN_IDENTITY="${2:?missing identity}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

cd "$ROOT"

VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')"

if [[ -z "$SIGN_IDENTITY" ]] && command -v security >/dev/null 2>&1; then
    IDENTITIES="$(security find-identity -v -p codesigning 2>/dev/null || true)"
    if grep -q '"Locket Local Dev"' <<<"$IDENTITIES"; then
        SIGN_IDENTITY="Locket Local Dev"
    else
        SIGN_IDENTITY="$(sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' <<<"$IDENTITIES" | head -n 1)"
    fi
fi

if [[ -z "$SIGN_IDENTITY" ]]; then
    SIGN_IDENTITY="-"
    echo "install-local: signing with ad-hoc identity (-). Create a self-signed 'Locket Local Dev' Code Signing cert in Keychain Access to avoid Keychain prompts on rebuilds."
else
    echo "install-local: signing with persistent identity: $SIGN_IDENTITY"
fi

echo "install-local: building release locket-cli and locket-desktop ($VERSION)..."
cargo build --release --locked --offline -p locket-cli -p locket-desktop

TARGET_DIR="$(cargo metadata --offline --format-version 1 --no-deps | python3 -c 'import sys, json; print(json.load(sys.stdin)["target_directory"])')"
CLI_BIN="$TARGET_DIR/release/locket"
DESKTOP_BIN="$TARGET_DIR/release/locket-desktop"
INSTALL_CLI="$HOME/.cargo/bin/locket"

echo "install-local: installing signed CLI to $INSTALL_CLI..."
CLI_STAGE="$TMPDIR/locket.cli.stage"
install -m 0755 "$CLI_BIN" "$CLI_STAGE"
codesign --force --sign "$SIGN_IDENTITY" --identifier "dev.0xdoublesharp.locket.cli" "$CLI_STAGE"
codesign --verify --strict "$CLI_STAGE"
mv -f "$CLI_STAGE" "$INSTALL_CLI"

if [[ -d "/Applications/Locket.app" ]]; then
    echo "install-local: staging, signing, and installing /Applications/Locket.app ($VERSION)..."
    STAGE_APP="$TMPDIR/Locket.app.stage"
    BACKUP_APP="$TMPDIR/Locket.app.prev"
    rm -rf "$STAGE_APP" "$BACKUP_APP"
    cp -R /Applications/Locket.app "$STAGE_APP"
    install -m 0755 "$DESKTOP_BIN" "$STAGE_APP/Contents/MacOS/locket-desktop"
    install -m 0755 "$CLI_BIN" "$STAGE_APP/Contents/Resources/locket"
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$STAGE_APP/Contents/Info.plist"
    /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$STAGE_APP/Contents/Info.plist"
    codesign --force --deep --sign "$SIGN_IDENTITY" "$STAGE_APP"
    codesign --verify --deep --strict "$STAGE_APP"
    python3 scripts/check-package-contents.py --app "$STAGE_APP" --version "$VERSION"
    mv /Applications/Locket.app "$BACKUP_APP"
    mv "$STAGE_APP" /Applications/Locket.app
    rm -rf "$BACKUP_APP"
    codesign --verify --deep --strict /Applications/Locket.app
    python3 scripts/check-package-contents.py --app /Applications/Locket.app --version "$VERSION"
else
    echo "install-local: /Applications/Locket.app not found; skipped Desktop app bundle update."
fi

if [[ "$RESTART_AGENT" == "auto" ]]; then
    if "$INSTALL_CLI" agent status 2>/dev/null | grep -q '^lock_state: unlocked$'; then
        echo "install-local: active unlocked vaults detected; skipping agent restart (run 'locket agent restart' when ready)."
        RESTART_AGENT="no"
    else
        RESTART_AGENT="yes"
    fi
fi

if [[ "$RESTART_AGENT" == "yes" ]]; then
    "$INSTALL_CLI" agent restart
fi

"$INSTALL_CLI" --version
"$INSTALL_CLI" agent status
