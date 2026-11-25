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
if mount | awk -v path="$scratch" '$2 == "on" && $3 == path { found = 1 } END { exit !found }'; then
    export TMPDIR="$scratch/locket/tmp"
elif [[ ${CI:-} == true ]] || [[ $(uname -s) == Linux && -n ${RUNNER_TEMP:-${TMPDIR:-}} ]]; then
    export TMPDIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/locket-check"
else
    printf 'miri-check: %s is not mounted\n' "$scratch" >&2
    exit 1
fi
mkdir -p -- "$TMPDIR"
work=$(mktemp -d "$TMPDIR/miri.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export MIRI_SYSROOT="${MIRI_SYSROOT:-$work/sysroot}"

cd -- "$root"
# Embed age's localization files so its error paths can run with Miri isolation.
args=(
    --locked --config 'profile.test.package.age.debug-assertions=false'
    --config 'profile.test.package.rust-embed.debug-assertions=false'
    -p locket-crypto -p locket-core -p locket-scan --target-dir "$work/target"
)
if [[ ${OFFLINE:-1} == 0 ]]; then
    export CARGO_NET_OFFLINE=false
else
    export CARGO_NET_OFFLINE=true
    args+=(--offline)
fi
if [[ -n ${COMPUTE_JOBS:-} ]]; then
    export CARGO_BUILD_JOBS="$COMPUTE_JOBS"
    args+=(-j "$COMPUTE_JOBS")
fi
cargo +nightly miri setup
# Proptest's failure persistence needs filesystem access that Miri isolates.
PROPTEST_DISABLE_FAILURE_PERSISTENCE=1 \
    MIRIFLAGS="${MIRIFLAGS:+$MIRIFLAGS }-Zmiri-env-forward=PROPTEST_DISABLE_FAILURE_PERSISTENCE" \
    cargo +nightly miri test "${args[@]}"
