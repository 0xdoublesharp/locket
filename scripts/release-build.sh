#!/usr/bin/env bash
# release-build.sh — build release binaries with embedded dependency metadata.
#
# Why this script exists:
#
#   docs/specs/engineering.md:125 requires release binaries to embed dependency
#   metadata so that downstream advisory checks can be performed against an
#   already-shipped artifact, without needing access to the original Cargo.lock.
#
# Two related but distinct tools collaborate here:
#
#   - `cargo auditable` is a *build-time* wrapper. It runs `cargo build` with an
#     extra step that embeds a compressed copy of the resolved dependency graph
#     (a CycloneDX-shaped SBOM) into a dedicated section of the final binary.
#     The embedded data describes exactly which crate versions were linked into
#     the artifact that ships.
#
#   - `cargo audit` is a *runtime* advisory checker against the RustSec
#     advisory database. With the `bin` subcommand it reads the embedded SBOM
#     out of an auditable-built binary and reports advisories without needing
#     a Cargo.lock or source tree. This means a downstream user (or a CI job
#     that only sees the built artifact) can independently verify the supply
#     chain on the same binary that gets distributed.
#
# Install requirements (offline-friendly, run once per host):
#
#   cargo install --locked cargo-auditable cargo-audit rust-audit-info
#
# These tools are installed in the user's cargo bin directory; this script does
# not auto-install them. If a tool is missing, the script reports the
# install command and exits non-zero unless invoked with --skip-missing.
#
# Usage:
#   scripts/release-build.sh                 # build all shipped binaries
#   scripts/release-build.sh --print-deps    # build, then print embedded SBOM
#   scripts/release-build.sh --skip-missing  # skip steps whose tool is absent
#
# CI release builds must set LOCKET_RELEASE_RUNNER_ATTESTED to the configured
# variable that identifies the isolated runner pool. For local release-build
# debugging only, set LOCKET_RELEASE_RUNNER_ATTESTED=local-dev; artifacts built
# that way must not be signed or published.

set -euo pipefail

cargo_auditable_cmd="${CARGO_AUDITABLE:-cargo auditable}"
cargo_audit_cmd="${CARGO_AUDIT:-cargo audit}"
source "$(dirname "${BASH_SOURCE[0]}")/cargo-jobs.sh"
jobs="$(cargo_jobs)"
target_dir="${CARGO_TARGET_DIR:-target}"
release_dir="${target_dir}/release"
runner_attested="${LOCKET_RELEASE_RUNNER_ATTESTED:-}"
print_deps=0
skip_missing=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --print-deps)
      print_deps=1
      shift
      ;;
    --skip-missing)
      skip_missing=1
      shift
      ;;
    -h|--help)
      sed -n '1,40p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${runner_attested}" ]]; then
  echo "LOCKET_RELEASE_RUNNER_ATTESTED is required for auditable release builds" >&2
  echo "set it from the isolated release runner identity, or use local-dev for local debugging only" >&2
  exit 2
fi

if [[ "${runner_attested}" == "local-dev" ]]; then
  echo "warning: local-dev release build guard bypass; do not sign or publish these artifacts" >&2
else
  echo "release runner attested: ${runner_attested}"
fi

# Shipped binaries. Keep this list in sync with [[bin]] entries in
# crates/*/Cargo.toml that are part of the public release.
#
# Format: <crate>:<binary-name>
shipped_binaries=(
  "locket-cli:locket"
  "locket-desktop:locket-desktop"
)

require_tool() {
  local label="$1"
  shift
  if "$@" --version >/dev/null 2>&1; then
    return 0
  fi
  if [[ "${skip_missing}" == "1" ]]; then
    echo "${label} is not installed; skipping (run: cargo install ${label})" >&2
    return 1
  fi
  echo "${label} is not installed; install with: cargo install ${label}" >&2
  exit 127
}

build_auditable() {
  local crate="$1"
  shift
  echo "==> cargo auditable build --release --locked -p ${crate} -j ${jobs} $*"
  # shellcheck disable=SC2086
  ${cargo_auditable_cmd} build --release --locked -p "${crate}" -j "${jobs}" "$@"
}

audit_binary() {
  local binary_path="$1"
  if [[ ! -x "${binary_path}" ]]; then
    echo "binary not found: ${binary_path}" >&2
    exit 1
  fi
  echo "==> cargo audit bin ${binary_path}"
  # shellcheck disable=SC2086
  ${cargo_audit_cmd} bin "${binary_path}"
}

print_embedded_deps() {
  local binary_path="$1"
  echo "==> embedded dependencies in ${binary_path}"
  rust-audit-info "${binary_path}" \
    | node -e '
        let input = "";
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", chunk => { input += chunk; });
        process.stdin.on("end", () => {
          const report = JSON.parse(input);
          const packages = report.packages
            .sort((a, b) => String(a.name).localeCompare(String(b.name)) || String(a.version).localeCompare(String(b.version)));
          for (const pkg of packages) console.log(`${pkg.name} ${pkg.version}`);
          console.log(`# total: ${packages.length} packages`);
        });
      '
}

if ! require_tool "cargo-auditable" ${cargo_auditable_cmd}; then
  exit 0
fi

for entry in "${shipped_binaries[@]}"; do
  crate="${entry%%:*}"
  if [[ "${crate}" == locket-desktop ]]; then
    # Tauri's production protocol embeds frontendDist and uses the release CSP.
    build_auditable "${crate}" --features tauri/custom-protocol
  else
    build_auditable "${crate}"
  fi
done

# The audit step is best-effort under --skip-missing: a host without
# cargo-audit can still produce auditable binaries, but cannot verify them.
if require_tool "cargo-audit" ${cargo_audit_cmd}; then
  if ! command -v rust-audit-info >/dev/null 2>&1; then
    echo "rust-audit-info is required to verify embedded dependencies; install with: cargo install --locked rust-audit-info" >&2
    if [[ "${skip_missing}" == "0" ]]; then
      exit 127
    fi
  fi
  for entry in "${shipped_binaries[@]}"; do
    binary_name="${entry##*:}"
    binary_path="${release_dir}/${binary_name}"
    if command -v rust-audit-info >/dev/null 2>&1; then
      # cargo audit bin can fall back to a partial scan when the SBOM is absent.
      if [[ "${print_deps}" == "1" ]]; then
        print_embedded_deps "${binary_path}"
      else
        rust-audit-info "${binary_path}" >/dev/null
      fi
    fi
    audit_binary "${binary_path}"
  done
fi

echo "release-build.sh: done"
