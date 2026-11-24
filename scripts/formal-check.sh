#!/usr/bin/env bash
set -euo pipefail

die() {
    printf 'formal-check: %s\n' "$*" >&2
    exit 1
}

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch=/Volumes/Scratch
[[ -d "$scratch" ]] || die "$scratch is unavailable"
scratch_tmp="$scratch/locket/tmp"
mkdir -p -- "$scratch_tmp"
work=$(mktemp -d "$scratch_tmp/formal-check.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export TMPDIR="$work"

jar=${TLA2TOOLS_JAR:-"$HOME/.local/share/tla2tools/tla2tools.jar"}
[[ -f "$jar" && -r "$jar" ]] || die "TLA+ tools jar unavailable at $jar"
jar=$(cd -- "$(dirname -- "$jar")" && pwd -P)/$(basename -- "$jar")

java_bin=
if [[ -n "${JAVA:-}" ]]; then
    java_bin=$(command -v "$JAVA") || die "JAVA executable unavailable at $JAVA"
    "$java_bin" -version >/dev/null 2>&1 || die "JAVA does not start a JVM at $java_bin"
else
    for candidate in java /opt/homebrew/opt/openjdk/bin/java /opt/homebrew/opt/openjdk@21/bin/java; do
        if java_bin=$(command -v "$candidate") && "$java_bin" -version >/dev/null 2>&1; then
            break
        fi
        java_bin=
    done
    [[ -n "$java_bin" ]] || die "Java unavailable. Set JAVA to an installed JVM."
fi
java_bin=$(cd -- "$(dirname -- "$java_bin")" && pwd -P)/$(basename -- "$java_bin")

if [[ -d "$HOME/.elan/bin" ]]; then
    export PATH="$HOME/.elan/bin:$PATH"
fi
command -v lake >/dev/null || die "Lake unavailable. Install the pinned Lean toolchain."

scan_status=0
LC_ALL=C grep -RnE --include='*.lean' --exclude-dir=.lake \
    '(^|[^[:alnum:]_])(sorry|admit|axiom|axioms)([^[:alnum:]_]|$)' \
    "$root/formal/lean" >&2 || scan_status=$?
case "$scan_status" in
    0) die "found a forbidden Lean proof placeholder or axiom declaration" ;;
    1) ;;
    *) die "could not scan Lean sources" ;;
esac

check_model() {
    local model=$1
    local log="$work/$model.log"
    local workers=${COMPUTE_JOBS:-2}
    printf 'Checking %s with TLC\n' "$model"
    cp -- "$root/formal/tla/$model.tla" "$root/formal/tla/$model.cfg" "$work/"
    if ! (
        cd -- "$work"
        "$java_bin" -Xmx512m -XX:+UseParallelGC -Djava.io.tmpdir="$work" \
            -cp "$jar" tlc2.TLC -deadlock -workers "$workers" -metadir "$work/$model-states" \
            -config "$model.cfg" "$model.tla"
    ) >"$log" 2>&1; then
        cat -- "$log" >&2
        die "$model failed"
    fi
    local counts
    counts=$(awk '/states generated, .*distinct states found, 0 states left on queue/ {
        print $1 " generated, " $4 " distinct"
    }' "$log")
    if [[ -z "$counts" ]] || ! grep -Fq 'No error has been found' "$log"; then
        cat -- "$log" >&2
        die "$model did not report an exhaustive pass"
    fi
    printf '  %s states, 0 errors\n' "$counts"
}

check_model AgentUnlockGrantLifecycle
check_model SecretLifecycleAuditChain
check_model EgressProxyAndRedaction
check_model TeamSyncAndAuditWitness

# Build the exact sources in a Scratch copy so Lake's artifacts stay off Data.
lean_project="$work/formal/lean"
mkdir -p -- "$lean_project"
cp -R -- "$root/formal/lean/"{lean-toolchain,lakefile.toml,LocketProofs.lean,LocketProofs} "$lean_project/"
printf 'Building Lean proofs\n'
(
    cd -- "$lean_project"
    lake --no-cache --wfail build
)
printf 'Formal checks passed for all four TLC models and all Lean modules.\n'
