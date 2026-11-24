#!/usr/bin/env bash
# perf-cli-cold-start.sh — measure CLI cold-start latency with hyperfine.
#
# Builds locket --release and uses hyperfine to record three cold-start
# scenarios:
#
#   1. `locket --help`            — zero-context cold start.
#   2. `locket status`            — fresh LOCKET_HOME, no project bound.
#   3. `locket get FOO`           — project pre-seeded with one secret.
#
# JSON results are written to target/perf/cli-cold-start.json. The script does
# not bundle hyperfine; install with `brew install hyperfine`,
# `apt install hyperfine`, or `cargo install hyperfine`. Missing hyperfine is
# treated as a soft skip so CI can run this conditionally.
#
# Budgets:
#   metadata_p95_ms = 100   (per docs/specs/performance.md, metadata-only CLIs)
# `locket get FOO` is currently routed through the agent path; this harness
# emits raw mean and p95 data until the named reference runner publishes a
# calibrated `lk://` resolution number.

set -euo pipefail

# Release binaries here must use the development instance; the OS keychain
# ignores the temporary HOME these scripts set.
export LOCKET_INSTANCE=dev

cargo_bin="${CARGO:-cargo}"
source "$(dirname "${BASH_SOURCE[0]}")/cargo-jobs.sh"
jobs="$(cargo_jobs)"
offline="${OFFLINE:-1}"
warmup="${PERF_CLI_WARMUP:-3}"
runs="${PERF_CLI_RUNS:-20}"
output_dir="${PERF_CLI_OUTPUT_DIR:-target/perf}"
output_json="${output_dir}/cli-cold-start.json"
metadata_budget_ms="${PERF_CLI_METADATA_BUDGET_MS:-100}"

if ! command -v hyperfine >/dev/null 2>&1; then
  echo "perf-cli-cold-start: skip — hyperfine not installed" >&2
  echo "perf-cli-cold-start: install via 'brew install hyperfine', 'apt install hyperfine', or 'cargo install hyperfine'" >&2
  exit 0
fi

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

mkdir -p "${output_dir}"

repo_root="$(pwd)"
binary="${repo_root}/target/release/locket"

echo "perf-cli-cold-start: building locket-cli --release"
"${cargo_bin}" build -p locket-cli --release "${offline_args[@]}" -j "${jobs}" >/dev/null

if [[ ! -x "${binary}" ]]; then
  echo "perf-cli-cold-start: expected release binary at ${binary}" >&2
  exit 2
fi

# Scenario 1 (--help) and 2 (status) need separate LOCKET_HOME directories so
# the second scenario truly measures a fresh init path. Scenario 3 binds the
# CLI to a temporary working directory that contains a single seeded secret.
help_home="$(mktemp -d -t locket-perf-cli-help.XXXXXX)"
status_home="$(mktemp -d -t locket-perf-cli-status.XXXXXX)"
get_home="$(mktemp -d -t locket-perf-cli-get.XXXXXX)"
get_project_dir="$(mktemp -d -t locket-perf-cli-get-proj.XXXXXX)"

cleanup() {
  rm -rf "${help_home}" "${status_home}" "${get_home}" "${get_project_dir}"
}
trap cleanup EXIT

# Scenario 3 fixture: initialize a project and add one secret. We swallow
# stderr/stdout because we only care about the cold-start measurement that
# follows. If init fails, we still record the --help/status scenarios.
get_setup_ok=1
(
  cd "${get_project_dir}"
  LOCKET_HOME="${get_home}" "${binary}" init >/dev/null 2>&1 || exit 11
  printf 'value-foo\n' | LOCKET_HOME="${get_home}" "${binary}" set FOO --stdin >/dev/null 2>&1 || exit 12
) || get_setup_ok=0

if [[ "${get_setup_ok}" -ne 1 ]]; then
  echo "perf-cli-cold-start: warning — could not seed get FOO fixture; scenario will be skipped" >&2
fi

cmd_help="LOCKET_HOME=${help_home} ${binary} --help"
cmd_status="LOCKET_HOME=${status_home} ${binary} status"
cmd_get="cd ${get_project_dir} && LOCKET_HOME=${get_home} ${binary} get FOO"

hyperfine_args=(
  --warmup "${warmup}"
  --runs "${runs}"
  --shell /bin/bash
  --export-json "${output_json}"
  --command-name "locket --help" "${cmd_help}"
  --command-name "locket status" "${cmd_status}"
)
if [[ "${get_setup_ok}" -eq 1 ]]; then
  hyperfine_args+=(--command-name "locket get FOO" "${cmd_get}")
fi

hyperfine "${hyperfine_args[@]}"

# Parse mean/stddev from the JSON for a quick pass/fail on the metadata
# budgets. p95 from a 20-run sample is wide; the bench-smoke harness owns the
# full p95 calculation. This script just emits the per-scenario mean and a
# soft warning if it exceeds the documented metadata budget.
node_summary() {
  node - "$@" <<'JS'
const fs = require("node:fs");

const [path, budgetArg] = process.argv.slice(2);
const budgetMs = Number(budgetArg);
const data = JSON.parse(fs.readFileSync(path, "utf8"));

console.log();
console.log("perf-cli-cold-start summary (mean ± stddev, seconds):");
const metadataNames = new Set(["locket --help", "locket status"]);
let exitCode = 0;
for (const entry of data.results ?? []) {
  const name = entry.command ?? "?";
  const meanS = entry.mean ?? 0.0;
  const stddevS = entry.stddev ?? 0.0;
  console.log(`  ${name}: ${(meanS * 1000).toFixed(2)} ms ± ${(stddevS * 1000).toFixed(2)} ms`);
  if (metadataNames.has(name) && meanS * 1000.0 > budgetMs) {
    console.log(`    FAIL: exceeds metadata budget ${budgetMs.toFixed(0)} ms`);
    exitCode = 1;
  }
}

console.log();
console.log("# reference-runner calibration pending for `locket get FOO`");
console.log("# lk:// resolution numbers are recorded per docs/specs/performance.md.");
process.exit(exitCode);
JS
}

node_summary "${output_json}" "${metadata_budget_ms}"
