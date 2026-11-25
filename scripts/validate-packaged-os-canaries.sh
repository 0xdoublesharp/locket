#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${LOCKET_PACKAGE_ARTIFACT_ROOT:-${LOCKET_BUILD_ROOT:-${CARGO_TARGET_DIR:-${repo_root}/target}}/package}"
dry_run=0
install_smoke=0
editor_smoke=0
vsix_path="${LOCKET_VSIX_PATH:-}"

usage() {
  sed -n '1,120p' <<'USAGE'
Usage:
  scripts/validate-packaged-os-canaries.sh [--artifact-root PATH] [--vsix PATH] [--install-smoke] [--editor-smoke] [--dry-run]

Validates packaged OS canary surfaces that normal CI cannot fully exercise:
signed desktop installer artifacts, packaged VSIX execution, and artifact
scanning for known canary markers.

--install-smoke runs host-specific installer/extension smoke commands when the
required tools and artifacts are available.
--editor-smoke installs and activates the VSIX in disposable editor directories
without invoking native installer or signing checks. It does not open a real vault.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-root)
      artifact_root="${2:-}"
      shift 2
      ;;
    --vsix)
      vsix_path="${2:-}"
      shift 2
      ;;
    --editor-smoke)
      editor_smoke=1
      shift
      ;;
    --install-smoke)
      install_smoke=1
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
  echo "required tool not found: ${tool}" >&2
  exit 127
}

scan_artifacts_for_canaries() {
  if [[ ! -d "${artifact_root}" ]]; then
    echo "artifact root not found: ${artifact_root}" >&2
    exit 66
  fi
  if rg --no-config --hidden --no-ignore -a -l "lk-canary|LOCKET_CANARY|DATABASE_URL_CANARY" "${artifact_root}"; then
    echo "known canary marker leaked into packaged artifacts" >&2
    exit 1
  else
    local result=$?
    [[ "$result" == "1" ]] || { echo "artifact scan could not complete" >&2; exit "$result"; }
  fi
  echo "artifact scan passed: no known canary markers under ${artifact_root}"
}

validate_host_package() {
  case "$(uname -s)" in
    Darwin*)
      local pkg
      pkg="$(find "${artifact_root}" -name '*.pkg' -type f | sort || true)"
      [[ "${pkg}" != *$'\n'* ]] || { echo "multiple pkg artifacts; use a clean artifact root" >&2; exit 64; }
      [[ -n "${pkg}" ]] || { echo "no macOS pkg under ${artifact_root}" >&2; exit 66; }
      require_tool pkgutil
      require_tool spctl
      pkgutil --check-signature "${pkg}"
      spctl -a -vv -t install "${pkg}"
      ;;
    Linux*)
      local deb rpm
      deb="$(find "${artifact_root}" -name '*.deb' -type f | sort || true)"
      rpm="$(find "${artifact_root}" -name '*.rpm' -type f | sort || true)"
      if [[ -n "${deb}" ]]; then
        require_tool dpkg-deb
        dpkg-deb --info "${deb}" >/dev/null
      fi
      if [[ -n "${rpm}" ]]; then
        require_tool rpm
        rpm --checksig "${rpm}"
      fi
      if [[ -z "${deb}${rpm}" ]]; then
        echo "no Linux deb/rpm under ${artifact_root}" >&2
        exit 66
      fi
      ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      local msi
      msi="$(find "${artifact_root}" -name '*.msi' -type f | sort || true)"
      [[ "${msi}" != *$'\n'* ]] || { echo "multiple msi artifacts; use a clean artifact root" >&2; exit 64; }
      [[ -n "${msi}" ]] || { echo "no Windows MSI under ${artifact_root}" >&2; exit 66; }
      require_tool signtool
      signtool verify /pa /v "${msi}"
      ;;
    *)
      echo "unsupported host for package install smoke: $(uname -s)" >&2
      exit 64
      ;;
  esac
}

validate_vsix() {
  if [[ -z "${vsix_path}" ]]; then
    vsix_path="$(find "${artifact_root}" -name '*.vsix' -type f | sort || true)"
  fi
  [[ -n "${vsix_path}" ]] || { echo "no VSIX artifact found" >&2; exit 66; }
  [[ "${vsix_path}" != *$'\n'* ]] || { echo "multiple VSIX artifacts; pass --vsix" >&2; exit 64; }
  require_tool code
  local version editor_id smoke_root
  version="$(node "${repo_root}/scripts/distribution.mjs" versions)"
  python3 "${repo_root}/scripts/check-package-contents.py" --vsix "${vsix_path}" --version "${version}"
  editor_id="$(node -e 'const p=require(process.argv[1]);process.stdout.write(p.publisher+"."+p.name)' "${repo_root}/extensions/vscode/package.json")"
  : "${TMPDIR:?set TMPDIR to disposable smoke storage}"
  smoke_root="$(mktemp -d "${TMPDIR%/}/locket-editor-smoke.XXXXXX")"
  code --user-data-dir "${smoke_root}/user" --extensions-dir "${smoke_root}/extensions" --install-extension "${vsix_path}" --force
  code --user-data-dir "${smoke_root}/user" --extensions-dir "${smoke_root}/extensions" --list-extensions | rg -F -x "${editor_id}" >/dev/null
  mkdir -p "${smoke_root}/workspace" "${smoke_root}/user/User"
  printf '%s\n' '{"telemetry.telemetryLevel":"off","extensions.autoUpdate":false,"extensions.autoCheckUpdates":false,"workbench.startupEditor":"none"}' > "${smoke_root}/user/User/settings.json"
  local installed
  installed="$(python3 - "${smoke_root}/extensions" "${editor_id}" "${version}" <<'PYEDITOR'
import json, pathlib, sys
matches = []
for manifest in pathlib.Path(sys.argv[1]).glob('*/package.json'):
    package = json.loads(manifest.read_text())
    if package.get('publisher', '') + '.' + package.get('name', '') == sys.argv[2] and package.get('version') == sys.argv[3]:
        matches.append(manifest.parent)
if len(matches) != 1:
    sys.exit(f'expected exactly one installed matching extension, found {len(matches)}')
print(matches[0])
PYEDITOR
)"
  LOCKET_AGENT_SOCKET="${smoke_root}/absent-test-agent.sock" \
  LOCKET_EXPECTED_EDITOR_ID="${editor_id}" \
  LOCKET_EXPECTED_EDITOR_VERSION="${version}" \
  LOCKET_EDITOR_ACCEPTANCE_REPORT="${smoke_root}/activation.json" \
    code --user-data-dir "${smoke_root}/user" --extensions-dir "${smoke_root}/extensions" \
      --extensionDevelopmentPath="${installed}" \
      --extensionTestsPath="${repo_root}/extensions/vscode/integration/packaged-host.cjs" \
      --disable-workspace-trust --skip-welcome --skip-release-notes --new-window --wait "${smoke_root}/workspace"
  python3 - "${smoke_root}/activation.json" "${editor_id}" "${version}" <<'PYRESULT'
import json, pathlib, sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text())
if result.get('id') != sys.argv[2] or result.get('version') != sys.argv[3] or result.get('isActive') is not True or len(result.get('registeredCommands', [])) != 9:
    sys.exit('installed extension activation did not complete')
PYRESULT
  echo "Isolated editor installation and activation verified; report: ${smoke_root}/activation.json"
}

if [[ "${dry_run}" == "1" ]]; then
  echo "dry-run: would scan packaged artifacts under ${artifact_root}"
  if [[ "${install_smoke}" == "1" ]]; then
    echo "dry-run: would run host installer and VSIX smoke checks when artifacts exist"
  fi
  exit 0
fi

require_tool rg
scan_artifacts_for_canaries
version="$(node "${repo_root}/scripts/distribution.mjs" versions)"
while IFS= read -r -d '' vsix; do
  python3 "${repo_root}/scripts/check-package-contents.py" --vsix "${vsix}" --version "${version}"
done < <(find "${artifact_root}" -name '*.vsix' -type f -print0)

if [[ "${install_smoke}" == "1" ]]; then
  validate_host_package
fi
if [[ "${install_smoke}" == "1" || "${editor_smoke}" == "1" ]]; then
  validate_vsix
fi
