#!/usr/bin/env bash
set -euo pipefail

die() {
    printf 'formal-trace-check: %s\n' "$*" >&2
    exit 1
}

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
scratch=/Volumes/Scratch
if mount | awk -v path="$scratch" '$2 == "on" && $3 == path { found = 1 } END { exit !found }'; then
    check_tmp="$scratch/locket/tmp"
elif [[ ${CI:-} == true ]] || [[ $(uname -s) == Linux && -n ${RUNNER_TEMP:-${TMPDIR:-}} ]]; then
    check_tmp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/locket-check"
else
    die "$scratch is not mounted"
fi
mkdir -p -- "$check_tmp"
work=$(mktemp -d "$check_tmp/formal-trace-check.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ ${TMPDIR:-} != "$scratch/locket/"* ]]; then
    export TMPDIR="$check_tmp"
fi

jar=${TLA2TOOLS_JAR:-"$HOME/.local/share/tla2tools/tla2tools.jar"}
[[ -f "$jar" && -r "$jar" ]] || die "TLA+ tools jar unavailable at $jar"
jar=$(cd -- "$(dirname -- "$jar")" && pwd -P)/$(basename -- "$jar")
java_bin=$(command -v "${JAVA:-java}") || die "Java unavailable. Set JAVA to an installed JVM."
java_bin=$(cd -- "$(dirname -- "$java_bin")" && pwd -P)/$(basename -- "$java_bin")

command -v python3 >/dev/null || die "Python 3 is required to read Cargo artifact metadata"
cd -- "$root"
build_args=(build -p locket-cli --bin locket --offline --locked --message-format=json-render-diagnostics)
cargo_args=(test -p locket-agent --test tla_trace_conformance --offline --locked)
if [[ -n "${COMPUTE_JOBS:-}" ]]; then
    build_args+=(-j "$COMPUTE_JOBS")
    cargo_args+=(-j "$COMPUTE_JOBS")
fi
# Cargo reports the executable location even when a wrapper routes its build directory.
cargo "${build_args[@]}" >"$work/cli-build.jsonl"
cli=$(python3 -c '
import json
import sys

for line in sys.stdin:
    event = json.loads(line)
    if event["reason"] == "compiler-artifact" and event.get("executable") and event["target"]["name"] == "locket":
        print(event["executable"])
' <"$work/cli-build.jsonl")
[[ -x "$cli" ]] || die "Cargo did not report an executable Locket CLI"

LOCKET_TLA_CLI="$cli" LOCKET_TLA_TRACE_DIR="$work/traces" LOCKET_TLA_TMPDIR="$check_tmp" \
    cargo "${cargo_args[@]}"

run_tlc() (
    local dir=$1 model=$2
    cd -- "$dir"
    # Keep deadlock checking enabled. The wrappers loop only after all
    # observations match and separately check the TraceCompletion property.
    "$java_bin" -Xmx512m -XX:+UseParallelGC -Djava.io.tmpdir="$work" \
        -cp "$jar" tlc2.TLC -workers 1 -metadir "$dir/states" \
        -config "${model}Trace.cfg" "${model}Trace.tla"
)

check_model() {
    local model=$1 dir="$work/$1" log="$work/$1.log"
    local base="$root/formal/tla" data="$work/traces/${1}TraceData.tla"
    [[ -s "$data" ]] || die "Rust did not emit $model trace data"
    mkdir -- "$dir"
    cp -- "$base/$model.tla" "$base/traces/${model}Trace.tla" \
        "$base/traces/${model}Trace.cfg" "$data" "$dir/"
    local expected_initial
    expected_initial=$(awk '/^(Recorded|Rejected)Trace == <</ { n++ } END { print n + 0 }' "$data")
    if ! run_tlc "$dir" "$model" >"$log" 2>&1 ||
        [[ "$expected_initial" -eq 0 ]] ||
        ! grep -Eq "^Finished computing initial states: $expected_initial distinct states? generated" "$log" ||
        ! grep -Fq 'Finished checking temporal properties' "$log" ||
        ! grep -Fq 'No error has been found' "$log" ||
        ! grep -Eq '^[0-9]+ states generated, [1-9][0-9]* distinct states found, 0 states left on queue' "$log" ||
        grep -Eiq '(^|[[:space:]])(warning|error):' "$log"; then
        cat -- "$log" >&2
        die "$model did not complete a clean replay"
    fi
    local lengths
    lengths=$(awk '
        /^(Recorded|Rejected)Trace == <</ { active = 1; n = 0 }
        active && /^    \[action / { n++ }
        active && /^>>$/ {
            printf "%s%d", separator, n
            separator = " and "
            active = 0
        }
        END { print "" }
    ' "$data")
    printf '%s: %s observations, reached traceIdx = Len(Trace) + 1, 0 errors, 0 warnings\n' \
        "$model" "$lengths"
}

check_model AgentUnlockGrantLifecycle
check_model AgentAuthzProtocol
check_model AutomationClientAuth
check_model SecretLifecycleAuditChain
check_model BackupAndRecoveryLifecycle
check_model SharedVaultIsolation
check_model SharedSecretLinks
check_model TeamSyncAndAuditWitness
check_model EgressProxyAndRedaction
check_model AgentDaemonLifecycle
check_model McpAndDesktopBoundary

# Keep the actual first create's after-state and strip only its audit event.
# TLC must report deadlock at the initial observation. Parse failures, failed
# invariants, and a replay that advances beyond this step do not count.
model=SecretLifecycleAuditChain
canary="$work/canary"
mkdir -- "$canary"
cp -- "$work/$model/$model.tla" "$work/$model/${model}Trace.tla" \
    "$work/$model/${model}Trace.cfg" "$canary/"
data="${model}TraceData.tla"
sed 's/^Trace == RecordedTrace$/Trace == [i \\in DOMAIN RecordedTrace |-> IF i = 2 THEN [RecordedTrace[i] EXCEPT !.state.events = <<>>] ELSE RecordedTrace[i]]/' \
    "$work/traces/$data" >"$canary/$data"
log="$canary/tlc.log"
if run_tlc "$canary" "$model" >"$log" 2>&1 ||
    ! grep -Fxq 'Error: Deadlock reached.' "$log" ||
    ! grep -Fxq '/\ traceIdx = 1' "$log" ||
    grep -Eq '^State 2:' "$log"; then
    cat -- "$log" >&2
    die "illegal unaudited mutation did not fail at the first transition"
fi
printf '%s\n' 'Negative canary: TLC rejected a secret mutation without an audit row at traceIdx = 1.'
