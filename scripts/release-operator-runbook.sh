#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${LOCKET_RELEASE_ARTIFACT_ROOT:-${repo_root}/target/package}"
task="all"
execute=0
confirm=""
version=""
release_tag=""
signed_source_url="${LOCKET_SIGNED_SOURCE_URL:-}"
signed_source_sha256="${LOCKET_SIGNED_SOURCE_SHA256:-}"
homebrew_tap_dir="${LOCKET_HOMEBREW_TAP_DIR:-}"
vsix_key_id="${LOCKET_RELEASE_KEY_ID:-}"

tasks=(
  homebrew-tap-publish-operator
  cargo-install-publish-operator
  macos-pkg-sign-notarize-operator
  windows-msi-sign-operator
  linux-deb-rpm-sign-operator
  vsix-release-sign-operator
)

publish_crates=(
  locket-core
  locket-crypto
  locket-scan
  locket-exec
  locket-docker
  locket-store
  locket-platform
  locket-agent
  locket-cli
)

usage() {
  cat <<'USAGE'
Usage:
  scripts/release-operator-runbook.sh [--task <task|all>] [options]

Default mode is a non-publishing dry-run. Use --execute only on the
credentialed release host, paired with --confirm publish-<tag>.

Tasks:
  homebrew-tap-publish-operator
  cargo-install-publish-operator
  macos-pkg-sign-notarize-operator
  windows-msi-sign-operator
  linux-deb-rpm-sign-operator
  vsix-release-sign-operator
  all

Options:
  --version <semver>             Defaults to workspace.package.version.
  --release-tag <tag>            Defaults to v<version>.
  --signed-source-url <url>      Or LOCKET_SIGNED_SOURCE_URL.
  --signed-source-sha256 <hex>   Or LOCKET_SIGNED_SOURCE_SHA256.
  --homebrew-tap-dir <path>      Or LOCKET_HOMEBREW_TAP_DIR.
  --vsix-key-id <key-id>         Or LOCKET_RELEASE_KEY_ID.
  --artifact-root <path>         Defaults to target/package.
  --execute                      Run credentialed publish/sign commands.
  --confirm <publish-tag>        Required with --execute.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --task) task="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --release-tag) release_tag="${2:-}"; shift 2 ;;
    --signed-source-url) signed_source_url="${2:-}"; shift 2 ;;
    --signed-source-sha256) signed_source_sha256="${2:-}"; shift 2 ;;
    --homebrew-tap-dir) homebrew_tap_dir="${2:-}"; shift 2 ;;
    --vsix-key-id) vsix_key_id="${2:-}"; shift 2 ;;
    --artifact-root) artifact_root="${2:-}"; shift 2 ;;
    --execute) execute=1; shift ;;
    --confirm) confirm="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 64 ;;
  esac
done

workspace_version() {
  node -e 'const fs=require("fs"); const t=fs.readFileSync(process.argv[1],"utf8"); const m=t.match(/\[workspace\.package\][\s\S]*?\nversion\s*=\s*"([^"]+)"/); if(!m) process.exit(1); process.stdout.write(m[1]);' "${repo_root}/Cargo.toml"
}

version="${version:-$(workspace_version)}"
release_tag="${release_tag:-v${version}}"

if [[ ! "${version}" =~ ^[0-9]+[.][0-9]+[.][0-9]+([-.+][A-Za-z0-9.-]+)?$ ]]; then
  echo "version must be semver-like without a leading v: ${version}" >&2
  exit 64
fi
if [[ "${release_tag}" != "v${version}" ]]; then
  echo "release tag must match version: expected v${version}, got ${release_tag}" >&2
  exit 64
fi

task_known() {
  local candidate="$1"
  local known
  for known in "${tasks[@]}"; do
    [[ "${candidate}" == "${known}" ]] && return 0
  done
  return 1
}

if [[ "${task}" != "all" ]] && ! task_known "${task}"; then
  echo "unknown task: ${task}" >&2
  usage >&2
  exit 64
fi

run() {
  local arg
  printf '+'
  for arg in "$@"; do
    printf ' %q' "${arg}"
  done
  printf '\n'
  "$@"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 && return 0
  echo "required tool not found: $1" >&2
  exit 127
}

require_execute_env() {
  [[ -n "${!1:-}" ]] && return 0
  echo "required credential env is unset: $1" >&2
  exit 64
}

require_execute_value() {
  [[ -n "$2" ]] && return 0
  echo "required release input is unset: $1" >&2
  exit 64
}

ensure_execute_confirmed() {
  [[ "${execute}" == "1" ]] || return 0
  local expected="publish-${release_tag}"
  if [[ "${confirm}" != "${expected}" ]]; then
    echo "--execute requires --confirm ${expected}" >&2
    exit 64
  fi
  if ! git -C "${repo_root}" diff --quiet || ! git -C "${repo_root}" diff --cached --quiet; then
    echo "release execution requires a clean checkout" >&2
    exit 65
  fi
  git -C "${repo_root}" rev-parse "${release_tag}^{tag}" >/dev/null
  git -C "${repo_root}" tag -v "${release_tag}" >/dev/null
}

heading() {
  printf '\n==> %s\n' "$1"
}

source_url_or_placeholder() {
  [[ -n "${signed_source_url}" ]] && printf '%s' "${signed_source_url}" && return
  printf 'https://github.com/0xdoublesharp/locket/releases/download/%s/locket-%s-src.tar.gz' "${release_tag}" "${version}"
}

source_sha_or_placeholder() {
  [[ -n "${signed_source_sha256}" ]] && printf '%s' "${signed_source_sha256}" && return
  printf '1111111111111111111111111111111111111111111111111111111111111111'
}

homebrew_task() {
  heading "homebrew-tap-publish-operator"
  require_tool node
  local formula="${artifact_root}/operator/homebrew/locket.rb"
  run "${repo_root}/scripts/render-homebrew-formula.sh" \
    --version "${version}" \
    --url "$(source_url_or_placeholder)" \
    --sha256 "$(source_sha_or_placeholder)" \
    --out "${formula}"
  if command -v brew >/dev/null 2>&1; then
    run brew audit --strict --new-formula "${formula}"
  else
    echo "skip: brew not on PATH"
  fi
  if [[ "${execute}" == "1" ]]; then
    require_execute_value LOCKET_SIGNED_SOURCE_URL "${signed_source_url}"
    require_execute_value LOCKET_SIGNED_SOURCE_SHA256 "${signed_source_sha256}"
    require_execute_value LOCKET_HOMEBREW_TAP_DIR "${homebrew_tap_dir}"
    mkdir -p "${homebrew_tap_dir}/Formula"
    cp "${formula}" "${homebrew_tap_dir}/Formula/locket.rb"
    run git -C "${homebrew_tap_dir}" diff -- Formula/locket.rb
    run git -C "${homebrew_tap_dir}" status --short
  else
    echo "dry-run residual: signed source URL/SHA, tap checkout, tap PR push/merge credentials"
  fi
}

cargo_task() {
  heading "cargo-install-publish-operator"
  require_tool cargo
  local package
  for package in "${publish_crates[@]}"; do
    run cargo package -p "${package}" --locked --allow-dirty --list
  done
  if [[ "${execute}" == "1" ]]; then
    require_execute_env CARGO_REGISTRY_TOKEN
    for package in "${publish_crates[@]}"; do
      run cargo publish -p "${package}" --locked
    done
  else
    echo "dry-run residual: CARGO_REGISTRY_TOKEN"
  fi
}

macos_task() {
  heading "macos-pkg-sign-notarize-operator"
  if [[ "${execute}" == "1" ]]; then
    require_execute_env APPLE_DEVELOPER_ID_INSTALLER
    require_execute_env APPLE_ID
    require_execute_env APPLE_APP_SPECIFIC_PASSWORD
    require_execute_env APPLE_TEAM_ID
    run "${repo_root}/scripts/package-native-installers.sh" --target macos-pkg
  else
    run "${repo_root}/scripts/package-native-installers.sh" --target macos-pkg --dry-run
    echo "dry-run residual: Apple Developer ID Installer and notarization credentials"
  fi
}

windows_task() {
  heading "windows-msi-sign-operator"
  if [[ "${execute}" == "1" ]]; then
    require_execute_env WINDOWS_EV_CERT_SHA1
    require_execute_env WINDOWS_TIMESTAMP_URL
    run "${repo_root}/scripts/package-native-installers.sh" --target windows-msi
  else
    run "${repo_root}/scripts/package-native-installers.sh" --target windows-msi --dry-run
    echo "dry-run residual: Windows EV certificate and timestamp URL on Windows"
  fi
}

linux_task() {
  heading "linux-deb-rpm-sign-operator"
  if [[ "${execute}" == "1" ]]; then
    require_execute_env LOCKET_DEB_GPG_KEY
    require_execute_env LOCKET_RPM_GPG_NAME
    run "${repo_root}/scripts/package-native-installers.sh" --target linux-deb
    run "${repo_root}/scripts/package-native-installers.sh" --target linux-rpm
  else
    run "${repo_root}/scripts/package-native-installers.sh" --target linux-deb --dry-run
    run "${repo_root}/scripts/package-native-installers.sh" --target linux-rpm --dry-run
    echo "dry-run residual: Linux deb/rpm GPG identities on Linux"
  fi
}

vsix_task() {
  heading "vsix-release-sign-operator"
  run bash -n "${repo_root}/scripts/package-vscode-extension.sh"
  run bash -n "${repo_root}/tools/vsix-sign.sh"
  if [[ "${execute}" == "1" ]]; then
    require_execute_value LOCKET_RELEASE_KEY_ID "${vsix_key_id}"
    require_execute_env LOCKET_MINISIGN_SECRET_KEY
    run "${repo_root}/scripts/package-vscode-extension.sh" --sign "${vsix_key_id}"
  else
    echo "dry-run residual: LOCKET_RELEASE_KEY_ID and LOCKET_MINISIGN_SECRET_KEY on the signing host"
  fi
}

run_task() {
  case "$1" in
    homebrew-tap-publish-operator) homebrew_task ;;
    cargo-install-publish-operator) cargo_task ;;
    macos-pkg-sign-notarize-operator) macos_task ;;
    windows-msi-sign-operator) windows_task ;;
    linux-deb-rpm-sign-operator) linux_task ;;
    vsix-release-sign-operator) vsix_task ;;
  esac
}

ensure_execute_confirmed

echo "release operator runbook: task=${task} version=${version} tag=${release_tag} mode=$([[ "${execute}" == "1" ]] && echo execute || echo dry-run)"
if [[ "${task}" == "all" ]]; then
  for t in "${tasks[@]}"; do
    run_task "${t}"
  done
else
  run_task "${task}"
fi

echo
echo "release-operator-runbook.sh: done"
