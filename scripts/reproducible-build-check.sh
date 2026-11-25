#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
workspace="$(pwd -P)"
cargo_bin="${CARGO:-cargo}"
cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
rustup_home="${RUSTUP_HOME:-${HOME}/.rustup}"

if [[ "${CI:-}" == "true" ]]; then
  build_root="${TMPDIR:?Set TMPDIR to disposable build storage in CI}"
else
  scratch=/Volumes/Scratch
  if ! df -P "${scratch}" | awk -v mount="${scratch}" 'END { exit ($NF != mount) }'; then
    echo "Scratch volume is not mounted at ${scratch}" >&2
    exit 1
  fi
  build_root="${scratch}/locket/tmp"
  if [[ "${TMPDIR:-}" != "${scratch}/"* ]]; then
    export TMPDIR="${build_root}"
  fi
fi
mkdir -p "${build_root}"
build_root="$(cd "${build_root}" && pwd -P)"
run_dir="$(mktemp -d "${build_root}/reproducible-build.XXXXXXXX")"

cleanup() {
  if [[ "${LOCKET_KEEP_REPRO_BUILDS:-0}" == "1" ]]; then
    echo "Build directories retained at ${run_dir}" >&2
  else
    rm -rf -- "${run_dir}"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export SOURCE_DATE_EPOCH
export CARGO_INCREMENTAL=0
jobs="${COMPUTE_JOBS:-$(scripts/cargo-jobs.sh)}"

build() {
  local build_dir="$1"
  local flags=(
    "--remap-path-prefix=${workspace}=/locket"
    "--remap-path-prefix=${cargo_home}=/cargo"
    "--remap-path-prefix=${rustup_home}=/rustup"
    "--remap-path-prefix=${build_dir}=/build"
  )

  mkdir -p "${build_dir}"
  local encoded_flags
  encoded_flags="$(IFS=$'\x1f'; printf '%s' "${flags[*]}")"
  CARGO_ENCODED_RUSTFLAGS="${encoded_flags}" CARGO_BUILD_BUILD_DIR="${build_dir}/intermediate" \
    "${cargo_bin}" build --release --locked --offline -p locket-cli --bin locket \
      --target-dir "${build_dir}/target" --jobs "${jobs}"
}

sha256() {
  local digest
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum < "$1")"
  else
    digest="$(shasum -a 256 < "$1")"
  fi
  printf '%s\n' "${digest%% *}"
}

echo "Building locket twice with SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
build "${run_dir}/first"
build "${run_dir}/second"

first="$(sha256 "${run_dir}/first/target/release/locket")"
second="$(sha256 "${run_dir}/second/target/release/locket")"
printf 'First build:  %s\nSecond build: %s\n' "${first}" "${second}"
if [[ "${first}" != "${second}" ]]; then
  echo "locket builds differ. Rerun with LOCKET_KEEP_REPRO_BUILDS=1 to inspect both binaries." >&2
  exit 1
fi
echo "locket builds are bit-for-bit identical."
