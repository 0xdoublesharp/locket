#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-kani >/dev/null; then
    printf '%s\n' 'Kani is unavailable. Install it with cargo install --locked kani-verifier and run cargo kani setup.' >&2
    [[ ${STRICT:-0} != 1 ]]
    exit
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch=/Volumes/Scratch
if ! mount | awk -v path="$scratch" '$2 == "on" && $3 == path { found = 1 } END { exit !found }'; then
    printf 'kani-check: %s is not mounted\n' "$scratch" >&2
    exit 1
fi
export TMPDIR="$scratch/locket/t"
export CARGO_NET_OFFLINE=true
mkdir -p -- "$TMPDIR"
work=$(mktemp -d "$TMPDIR/kani.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd -- "$root"
# Kani's Cargo invocations inherit offline mode. Check the resolved lockfile
# first because cargo kani does not forward Cargo's --locked flag.
cargo metadata --offline --locked --format-version 1 >/dev/null
if [[ -n ${COMPUTE_JOBS:-} ]]; then
    export CARGO_BUILD_JOBS="$COMPUTE_JOBS"
fi
cargo kani -p locket-crypto -p locket-core --lib --target-dir "$work" -j "${COMPUTE_JOBS:-2}"
