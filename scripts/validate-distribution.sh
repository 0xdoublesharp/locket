#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${repo_root}"

check() {
  echo "==> $*"
  "$@"
}

skip_or_check() {
  local tool="$1"
  shift
  if command -v "${tool}" >/dev/null 2>&1; then
    check "$@"
  else
    echo "skip: ${tool} not on PATH"
  fi
}

check node scripts/distribution.mjs versions
check node --test scripts/distribution.test.mjs
check python3 scripts/package_contents_test.py
check bash -n scripts/package-vscode-extension.sh
check bash -n scripts/package-native-installers.sh
check bash -n scripts/package-cargo-auditable.sh
check bash -n scripts/render-homebrew-formula.sh
check bash -n scripts/release-operator-runbook.sh
check bash -n scripts/validate-local-user-auth-real-host.sh
check bash -n scripts/validate-packaged-os-canaries.sh
check bash -n tools/vsix-sign.sh

check node -e '
const fs = require("fs");
for (const file of [
  "dist/installers/package-matrix.json",
  "dist/keys/locket-release-quorum-v1.json",
  "crates/locket-app/src-tauri/tauri.conf.json",
  "extensions/vscode/package.json"
]) {
  JSON.parse(fs.readFileSync(file, "utf8"));
}
const matrix = JSON.parse(fs.readFileSync("dist/installers/package-matrix.json", "utf8"));
const required = new Set(["homebrew-formula", "cargo-install", "macos-pkg", "windows-msi", "linux-deb", "linux-rpm", "vscode-vsix"]);
for (const target of matrix.targets || []) required.delete(target.id);
if (required.size) throw new Error(`missing package targets: ${[...required].join(", ")}`);
const runbook = fs.readFileSync("scripts/release-operator-runbook.sh", "utf8");
for (const task of [
  "homebrew-tap-publish-operator",
  "cargo-install-publish-operator",
  "macos-pkg-sign-notarize-operator",
  "windows-msi-sign-operator",
  "linux-deb-rpm-sign-operator",
  "vsix-release-sign-operator",
]) {
  if (!runbook.includes(task)) throw new Error(`release operator runbook missing task: ${task}`);
}
const tauri = JSON.parse(fs.readFileSync("crates/locket-app/src-tauri/tauri.conf.json", "utf8"));
if (!tauri.bundle || tauri.bundle.active !== true) throw new Error("Tauri bundle.active must be true");
const vsix = JSON.parse(fs.readFileSync("extensions/vscode/package.json", "utf8"));
if (vsix.private !== false) throw new Error("VSIX package must be publishable: private=false");
if (!vsix.publisher || !vsix.repository) throw new Error("VSIX package metadata is incomplete");
const publishCrates = new Set(["locket-exec", "locket-docker", "locket-store", "locket-platform", "locket-agent", "locket-cli"]);
for (const dir of fs.readdirSync("crates")) {
  const manifest = `crates/${dir}/Cargo.toml`;
  if (!fs.existsSync(manifest)) continue;
  const text = fs.readFileSync(manifest, "utf8");
  const name = text.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
  if (!publishCrates.has(name)) continue;
  const depPattern = /^locket-[a-z-]+\s*=\s*\{([^}]+)\}/gm;
  let match;
  while ((match = depPattern.exec(text)) !== null) {
    const body = match[1];
    if (body.includes("path =") && !body.includes("version =")) {
      throw new Error(`${manifest}: ${match[0]} must include version for crates.io publication`);
    }
  }
}
'

skip_or_check ruby ruby -c dist/homebrew/locket.rb
skip_or_check ruby ruby -c dist/homebrew/locket.rb.in
check scripts/render-homebrew-formula.sh --version 0.1.0 --url https://github.com/0xdoublesharp/locket/releases/download/v0.1.0/locket-0.1.0-src.tar.gz --sha256 1111111111111111111111111111111111111111111111111111111111111111 --out "${LOCKET_BUILD_ROOT:-${CARGO_TARGET_DIR:-target}}/package/homebrew/locket.rb"
skip_or_check plutil plutil -lint dist/installers/macos/entitlements.plist
skip_or_check xmllint xmllint --noout dist/installers/macos/distribution.xml
skip_or_check actionlint actionlint .github/workflows/ci.yml .github/workflows/release.yml .github/workflows/fuzz-nightly.yml .github/workflows/package-validation.yml

check scripts/package-native-installers.sh --target all --dry-run

if command -v cargo >/dev/null 2>&1; then
  echo "==> cargo metadata --no-deps --locked --format-version 1"
  cargo metadata --no-deps --locked --format-version 1 >/dev/null
  if [[ "${LOCKET_VALIDATE_CARGO_PACKAGE:-0}" == "1" ]]; then
    for package in locket-core locket-crypto locket-scan locket-exec locket-docker locket-store locket-platform locket-agent locket-cli; do
      check cargo package -p "${package}" --locked --allow-dirty --list
    done
  else
    echo "skip: set LOCKET_VALIDATE_CARGO_PACKAGE=1 to run cargo package --list for publish crates"
  fi
else
  echo "skip: cargo not on PATH"
fi

if command -v pnpm >/dev/null 2>&1; then
  if [[ -d extensions/vscode/node_modules ]]; then
    (cd extensions/vscode && check node_modules/.bin/vsce ls --no-dependencies)
  else
    echo "skip: extensions/vscode/node_modules missing; run pnpm --dir extensions/vscode install --frozen-lockfile for VSIX packaging checks"
  fi
else
  echo "skip: pnpm not on PATH"
fi

echo "validate-distribution.sh: done"
