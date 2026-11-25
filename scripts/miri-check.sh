#!/usr/bin/env bash
set -euo pipefail

components=$(rustup component list --installed --toolchain nightly 2>/dev/null || true)
if ! printf '%s\n' "$components" | grep -Eq '^miri($|-)'; then
    printf '%s\n' 'Nightly Miri is unavailable. Install it with rustup component add miri --toolchain nightly.' >&2
    [[ ${STRICT:-0} != 1 ]]
    exit
fi

if [[ -z ${MIRI_LIB_SRC:-} ]] && ! printf '%s\n' "$components" | grep -Eq '^rust-src($|-)'; then
    printf '%s\n' 'Install nightly Rust sources with rustup component add rust-src --toolchain nightly.' >&2
    exit 1
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch=/Volumes/Scratch
if ! mount | awk -v path="$scratch" '$2 == "on" && $3 == path { found = 1 } END { exit !found }'; then
    printf 'miri-check: %s is not mounted\n' "$scratch" >&2
    exit 1
fi
export TMPDIR="$scratch/locket/t"
export CARGO_NET_OFFLINE=true
mkdir -p -- "$TMPDIR"
work=$(mktemp -d "$TMPDIR/miri.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export MIRI_SYSROOT="$work/sysroot"

cd -- "$root"
args=(--locked --offline -p locket-crypto -p locket-core -p locket-scan --target-dir "$work/target")
if [[ -n ${COMPUTE_JOBS:-} ]]; then
    export CARGO_BUILD_JOBS="$COMPUTE_JOBS"
    args+=(-j "$COMPUTE_JOBS")
fi
cargo +nightly miri setup
cargo +nightly miri test "${args[@]}"
