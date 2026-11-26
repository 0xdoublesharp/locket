#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-kani >/dev/null; then
    printf '%s\n' 'Kani is unavailable. Install it with cargo install --locked kani-verifier and run cargo kani setup.' >&2
    [[ ${STRICT:-0} != 1 ]]
    exit
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch=/Volumes/Scratch
if mount | awk -v path="$scratch" '$2 == "on" && $3 == path { found = 1 } END { exit !found }'; then
    export TMPDIR="$scratch/locket/tmp"
elif [[ ${CI:-} == true ]] || [[ $(uname -s) == Linux && -n ${RUNNER_TEMP:-${TMPDIR:-}} ]]; then
    export TMPDIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/locket-check"
else
    printf 'kani-check: %s is not mounted\n' "$scratch" >&2
    exit 1
fi
mkdir -p -- "$TMPDIR"
work=$(mktemp -d "$TMPDIR/kani.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd -- "$root"
# Kani's Cargo invocations inherit offline mode. Check the resolved lockfile
# first because cargo kani does not forward Cargo's --locked flag.
if [[ ${OFFLINE:-1} == 0 ]]; then
    export CARGO_NET_OFFLINE=false
else
    export CARGO_NET_OFFLINE=true
fi
cargo metadata --locked --format-version 1 >/dev/null
if [[ -n ${COMPUTE_JOBS:-} ]]; then
    export CARGO_BUILD_JOBS="$COMPUTE_JOBS"
fi
# Kani cannot verify the inline assembly used for CPU feature detection or
# all of the accelerated crypto intrinsics. Check the portable Rust backends.
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--cfg=chacha20_backend=\"soft\" --cfg=poly1305_backend=\"soft\""
# Run each harness individually with a bounded per-harness timeout so CI logs
# always record per-harness timing and never silently lose logs to runner kills.
harness_timeout="${KANI_HARNESS_TIMEOUT:-300}"
failures=0
run_harness() {
    local pkg="$1"
    local harness="$2"
    printf '==> Kani %s::%s (timeout %ss)\n' "$pkg" "$harness" "$harness_timeout"
    if command -v timeout >/dev/null 2>&1; then
        timeout --foreground "${harness_timeout}s" \
            cargo kani -Z stubbing -p "$pkg" --lib --target-dir "$work" \
                --harness "$harness" --exact --output-format terse -j 1 || failures=$((failures + 1))
    else
        cargo kani -Z stubbing -p "$pkg" --lib --target-dir "$work" \
            --harness "$harness" --exact --output-format terse -j 1 || failures=$((failures + 1))
    fi
}

run_harness locket-crypto kani_proofs::embedded_nonce_and_ciphertext_require_exact_lengths
run_harness locket-crypto kani_proofs::canonical_field_preserves_utf8_boundaries
run_harness locket-crypto kani_proofs::fixed_wrap_round_trips_and_rejects_a_flipped_tag_bit

run_harness locket-core kani_proofs::a_single_acl_mismatch_denies_an_explicitly_selected_secret
run_harness locket-core kani_proofs::bounded_secret_names_match_the_ascii_grammar
run_harness locket-core kani_proofs::bounded_reference_suffixes_parse_without_panics
run_harness locket-core kani_proofs::bounded_acl_matching_is_panic_free

if (( failures > 0 )); then
    printf 'kani-check: %d harness(es) failed\n' "$failures" >&2
    exit 1
fi
