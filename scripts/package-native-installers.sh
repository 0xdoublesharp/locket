#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tauri_dir="${repo_root}/crates/locket-app/src-tauri"
ui_dir="${repo_root}/crates/locket-app/ui"
build_root="${LOCKET_BUILD_ROOT:-${CARGO_TARGET_DIR:-${repo_root}/target}}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${build_root}}"
out_root="${NATIVE_INSTALLER_OUT_DIR:-${build_root}/package/installers}"
stage="${out_root}/stage"
profile_root="${CARGO_TARGET_DIR}${CARGO_BUILD_TARGET:+/${CARGO_BUILD_TARGET}}/release"
target="host"
dry_run=0
unsigned=0

usage() {
  sed -n '1,120p' <<'USAGE'
Usage:
  scripts/package-native-installers.sh --target <all|macos-pkg|windows-msi|linux-deb|linux-rpm> [--dry-run] [--unsigned]

Builds native desktop installers with a matching bundled CLI. --unsigned creates
local validation artifacts without signing or notarization. Default target is host.
Builds and signs native desktop installers. --dry-run validates repository
manifests, command shape, and signing inputs without requiring credentials.

Required signing environment:
  macos-pkg:   APPLE_DEVELOPER_ID_APPLICATION, APPLE_DEVELOPER_ID_INSTALLER, APPLE_ID,
               APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID
  windows-msi: WINDOWS_EV_CERT_SHA1, WINDOWS_TIMESTAMP_URL
  linux-deb:   LOCKET_DEB_GPG_KEY
  linux-rpm:   LOCKET_RPM_GPG_NAME
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      target="${2:-}"
      shift 2
      ;;
    --unsigned)
      unsigned=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

require_tool() {
  local tool="$1"
  if command -v "${tool}" >/dev/null 2>&1; then
    return 0
  fi
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: missing optional tool ${tool}"
    return 0
  fi
  echo "required tool not found: ${tool}" >&2
  exit 127
}

require_env() {
  local name="$1"
  [[ "${unsigned}" == "1" ]] && return 0
  if [[ -n "${!name:-}" ]]; then
    return 0
  fi
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: required signing env ${name} is unset"
    return 0
  fi
  echo "required signing env is unset: ${name}" >&2
  exit 64
}

version() {
  node -e 'const fs=require("fs"); const t=fs.readFileSync(process.argv[1],"utf8"); const m=t.match(/\[workspace\.package\][\s\S]*?\nversion\s*=\s*"([^"]+)"/); if(!m) process.exit(1); process.stdout.write(m[1]);' "${repo_root}/Cargo.toml"
}

macos_target_arch() {
  case "${CARGO_BUILD_TARGET:-}" in
    x86_64-apple-darwin) echo "x86_64" ;;
    aarch64-apple-darwin) echo "arm64" ;;
    *) uname -m ;;
  esac
}

build_tauri_bundle() {
  local bundles="$1"
  require_tool pnpm
  require_tool cargo
  if ! command -v cargo-tauri >/dev/null 2>&1 && ! cargo tauri --version >/dev/null 2>&1; then
    if [[ "${dry_run}" == "1" ]]; then
      echo "dry-run: missing cargo-tauri"
      return 0
    fi
    echo "cargo-tauri is required; install with: cargo install tauri-cli --locked" >&2
    exit 127
  fi
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: would build Tauri bundles: ${bundles}"
    return 0
  fi
  mkdir -p "${stage}/ui"
  node "${repo_root}/scripts/distribution.mjs" versions >/dev/null
  if [[ "${unsigned}" == "1" ]]; then
    cargo build --locked --release -p locket-cli
  else
    if [[ -z "${LOCKET_RELEASE_RUNNER_ATTESTED:-}" || "${LOCKET_RELEASE_RUNNER_ATTESTED}" == "local-dev" ]]; then
      echo "Signed packaging requires an attested isolated release runner; local-dev artifacts cannot be signed." >&2
      exit 64
    fi
    require_tool cargo-auditable
    require_tool cargo-audit
    "${repo_root}/scripts/package-cargo-auditable.sh" build --locked --release -p locket-cli
  fi
  node "${ui_dir}/node_modules/vue-tsc/bin/vue-tsc.js" --project "${ui_dir}/tsconfig.json" --noEmit
  (cd "${ui_dir}" && node node_modules/vite/bin/vite.js build --outDir "${stage}/ui")
  cp "${profile_root}/locket${LOCKET_EXE_SUFFIX:-}" "${stage}/locket${LOCKET_EXE_SUFFIX:-}"
  if [[ "${unsigned}" != "1" ]]; then
    cargo audit bin "${stage}/locket${LOCKET_EXE_SUFFIX:-}"
  fi
  if [[ "$(uname -s)" == "Darwin" && "${unsigned}" != "1" ]]; then
    codesign --force --options runtime --timestamp --sign "${APPLE_DEVELOPER_ID_APPLICATION}" "${stage}/locket"
  fi
  node "${repo_root}/scripts/distribution.mjs" overlay "${stage}/locket${LOCKET_EXE_SUFFIX:-}" "${stage}/ui" "${stage}/tauri-bundle.json"
  local tauri_target_args=()
  if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    tauri_target_args=(--target "${CARGO_BUILD_TARGET}")
  fi
  if [[ "${unsigned}" == "1" ]]; then
    (cd "${tauri_dir}" && APPLE_SIGNING_IDENTITY=- cargo tauri build ${tauri_target_args[@]+"${tauri_target_args[@]}"} --config "${stage}/tauri-bundle.json" --bundles "${bundles}")
  else
    (cd "${tauri_dir}" && APPLE_SIGNING_IDENTITY="${APPLE_DEVELOPER_ID_APPLICATION:-}" cargo tauri build ${tauri_target_args[@]+"${tauri_target_args[@]}"} --runner "${repo_root}/scripts/package-cargo-auditable.sh" --config "${stage}/tauri-bundle.json" --bundles "${bundles}")
    cargo audit bin "${profile_root}/locket-desktop${LOCKET_EXE_SUFFIX:-}"
  fi
}

copy_exact_match() {
  local pattern="$1"
  local destination="$2"
  local match=""
  match="$(python3 - "${profile_root}/bundle" "${pattern}" <<'PYMATCH'
import pathlib, sys
matches = [p for p in pathlib.Path(sys.argv[1]).rglob('*') if p.is_file() and p.match(sys.argv[2])]
if len(matches) != 1:
    sys.exit(f'expected exactly one fresh bundle for {sys.argv[2]}, found {len(matches)}; clear stale bundle outputs')
print(matches[0])
PYMATCH
)"
  if [[ -z "${match}" ]]; then
    echo "expected bundle output not found: ${pattern}" >&2
    exit 1
  fi
  mkdir -p "$(dirname "${destination}")"
  cp "${match}" "${destination}"
}

macos_pkg() {
  require_tool node
  require_tool pkgbuild
  require_env APPLE_DEVELOPER_ID_APPLICATION
  require_tool productbuild
  [[ "${unsigned}" == "1" ]] || require_tool xcrun
  require_env APPLE_DEVELOPER_ID_INSTALLER
  require_env APPLE_ID
  require_env APPLE_APP_SPECIFIC_PASSWORD
  require_env APPLE_TEAM_ID
  build_tauri_bundle app
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: would pkgbuild/productbuild/sign/notarize macOS pkg"
    return 0
  fi
  local v arch component distribution pkg app_bundle
  local arch_check_args=()
  v="$(version)"
  arch="$(macos_target_arch)"
  if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
    arch_check_args=(--expected-arch "${arch}")
  fi
  app_bundle="${profile_root}/bundle/macos/Locket.app"
  python3 "${repo_root}/scripts/check-package-contents.py" --app "${app_bundle}" --version "${v}" ${arch_check_args[@]+"${arch_check_args[@]}"}
  component="${out_root}/macos/locket-component.pkg"
  distribution="${out_root}/macos/distribution.xml"
  pkg="${out_root}/macos/Locket-${v}-${arch}.pkg"
  mkdir -p "${out_root}/macos"
  sed "s#__LOCKET_VERSION__#${v}#g" "${repo_root}/dist/installers/macos/distribution.xml" > "${distribution}"
  if [[ "${unsigned}" == "1" ]]; then
    pkg="${out_root}/macos/Locket-${v}-${arch}-unsigned.pkg"
    pkgbuild --component "${app_bundle}" --identifier app.locket.desktop.pkg --version "${v}" --install-location /Applications "${component}"
    productbuild --distribution "${distribution}" --package-path "${out_root}/macos" "${pkg}"
    python3 "${repo_root}/scripts/check-package-contents.py" --pkg "${pkg}" --scratch-root "${stage}" --version "${v}" ${arch_check_args[@]+"${arch_check_args[@]}"}
    echo "Unsigned macOS validation pkg: ${pkg}"
    return 0
  fi
  cargo audit bin "${app_bundle}/Contents/MacOS/locket-desktop"
  cargo audit bin "${app_bundle}/Contents/Resources/locket"
  codesign --verify --deep --strict "${app_bundle}"
  codesign --verify --strict "${app_bundle}/Contents/Resources/locket"
  pkgbuild --component "${app_bundle}" --identifier app.locket.desktop.pkg --version "${v}" --install-location /Applications --sign "${APPLE_DEVELOPER_ID_INSTALLER}" "${component}"
  productbuild --distribution "${distribution}" --package-path "${out_root}/macos" --sign "${APPLE_DEVELOPER_ID_INSTALLER}" "${pkg}"
  xcrun notarytool submit "${pkg}" --apple-id "${APPLE_ID}" --password "${APPLE_APP_SPECIFIC_PASSWORD}" --team-id "${APPLE_TEAM_ID}" --wait
  xcrun stapler staple "${pkg}"
  pkgutil --check-signature "${pkg}"
  xcrun stapler validate "${pkg}"
  python3 "${repo_root}/scripts/check-package-contents.py" --pkg "${pkg}" --scratch-root "${stage}" --version "${v}"
  echo "macOS pkg: ${pkg}"
}

windows_msi() {
  export LOCKET_EXE_SUFFIX=.exe
  require_tool node
  [[ "${unsigned}" == "1" ]] || require_tool signtool
  require_env WINDOWS_EV_CERT_SHA1
  require_env WINDOWS_TIMESTAMP_URL
  build_tauri_bundle msi
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: would signtool sign and verify MSI"
    return 0
  fi
  local v out
  v="$(version)"
  out="${out_root}/windows/Locket-${v}-${PROCESSOR_ARCHITECTURE:-x64}.msi"
  copy_exact_match "*/msi/*.msi" "${out}"
  [[ "${unsigned}" == "1" ]] && { echo "Unsigned Windows validation MSI: ${out}"; return 0; }
  signtool sign /fd SHA256 /tr "${WINDOWS_TIMESTAMP_URL}" /td SHA256 /sha1 "${WINDOWS_EV_CERT_SHA1}" "${out}"
  signtool verify /pa /v "${out}"
  echo "Windows MSI: ${out}"
}

linux_deb() {
  require_tool node
  [[ "${unsigned}" == "1" ]] || require_tool debsign
  require_env LOCKET_DEB_GPG_KEY
  build_tauri_bundle deb
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: would debsign generated deb"
    return 0
  fi
  local v out
  v="$(version)"
  out="${out_root}/linux/locket_${v}_$(uname -m).deb"
  copy_exact_match "*/deb/*.deb" "${out}"
  [[ "${unsigned}" == "1" ]] && { echo "Unsigned Linux validation deb: ${out}"; return 0; }
  debsign -k"${LOCKET_DEB_GPG_KEY}" "${out}"
  echo "Linux deb: ${out}"
}

linux_rpm() {
  require_tool node
  [[ "${unsigned}" == "1" ]] || require_tool rpmsign
  require_env LOCKET_RPM_GPG_NAME
  build_tauri_bundle rpm
  if [[ "${dry_run}" == "1" ]]; then
    echo "dry-run: would rpmsign generated rpm"
    return 0
  fi
  local v out
  v="$(version)"
  out="${out_root}/linux/locket-${v}-1.$(uname -m).rpm"
  copy_exact_match "*/rpm/*.rpm" "${out}"
  [[ "${unsigned}" == "1" ]] && { echo "Unsigned Linux validation rpm: ${out}"; return 0; }
  rpmsign --define "_gpg_name ${LOCKET_RPM_GPG_NAME}" --addsign "${out}"
  rpm --checksig "${out}"
  echo "Linux rpm: ${out}"
}

run_target() {
  case "$1" in
    host)
      case "$(uname -s)" in
        Darwin*) macos_pkg ;;
        Linux*) linux_deb ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT) export LOCKET_EXE_SUFFIX=.exe; windows_msi ;;
        *) echo "unsupported packaging host" >&2; exit 64 ;;
      esac ;;
    macos-pkg) macos_pkg ;;
    windows-msi) windows_msi ;;
    linux-deb) linux_deb ;;
    linux-rpm) linux_rpm ;;
    all)
      macos_pkg
      windows_msi
      linux_deb
      linux_rpm
      ;;
    *)
      echo "unknown target: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
}

run_target "${target}"
