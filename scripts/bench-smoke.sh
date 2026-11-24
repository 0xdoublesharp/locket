#!/usr/bin/env bash
set -euo pipefail

# Release binaries here must use the development instance; the OS keychain
# ignores the temporary HOME these scripts set.
export LOCKET_INSTANCE=dev

mode="${1:-ci}"
repo_root="$(pwd)"
cargo_bin="${CARGO:-cargo}"
source "$(dirname "${BASH_SOURCE[0]}")/cargo-jobs.sh"
jobs="$(cargo_jobs)"
offline="${OFFLINE:-1}"
quality_dir="${repo_root}/target/quality"
jsonl="${quality_dir}/bench-smoke.jsonl"
summary="${quality_dir}/bench-summary.json"
report="${quality_dir}/bench-report.md"
reference_setup="${REFERENCE_RUNNER_SETUP_FINGERPRINT:-${quality_dir}/reference-runner-setup.json}"
bench_fixture_out="${BENCH_FIXTURE_OUT:-${repo_root}/target/bench-fixtures}"
staged_scan_repo="${bench_fixture_out}/staged-scan/repo"
min_warmups="${BENCH_WARMUPS:-5}"
min_samples="${BENCH_SAMPLES:-50}"
build_profile="${BENCH_BUILD_PROFILE:-debug}"
policy_mode="${BENCH_POLICY_MODE:-}"
baseline_summary="${BENCH_BASELINE_SUMMARY:-}"
accepted_regression_note="${BENCH_ACCEPTED_REGRESSION_NOTE:-}"

if [[ "${mode}" == "full" ]]; then
  build_profile="${BENCH_BUILD_PROFILE:-release}"
fi

if [[ -z "${policy_mode}" ]]; then
  if [[ "${mode}" == "full" ]]; then
    policy_mode="release"
  else
    policy_mode="pr"
  fi
fi

cargo_profile_args=()
binary="${repo_root}/target/debug/locket"
if [[ "${build_profile}" == "release" ]]; then
  cargo_profile_args=(--release)
  binary="${repo_root}/target/release/locket"
fi

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

mkdir -p "${quality_dir}"

metadata_value() {
  local command="$1"
  shift
  "$command" "$@" 2>/dev/null | head -n 1 || printf 'unknown\n'
}

cpu_model() {
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n machdep.cpu.brand_string 2>/dev/null && return
  fi
  if [[ -r /proc/cpuinfo ]]; then
    awk -F: '/model name/ { sub(/^ /, "", $2); print $2; exit }' /proc/cpuinfo && return
  fi
  printf 'unknown\n'
}

memory_bytes() {
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.memsize 2>/dev/null && return
  fi
  if [[ -r /proc/meminfo ]]; then
    awk '/MemTotal/ { print $2 * 1024; exit }' /proc/meminfo && return
  fi
  printf 'unknown\n'
}

filesystem_type() {
  local device
  device="$(df . 2>/dev/null | awk 'NR == 2 { print $1 }')"
  if [[ -n "${device}" ]] && mount >/dev/null 2>&1; then
    mount | awk -v device="${device}" '
      $1 == device {
        sub(/^.*\(/, "", $0);
        sub(/[,)].*$/, "", $0);
        print $0;
        found = 1;
        exit;
      }
      END { if (!found) exit 1 }
    ' && return
  fi
  if stat -f %T . >/dev/null 2>&1; then
    stat -f %T .
    return
  fi
  if df -T . >/dev/null 2>&1; then
    df -T . | awk 'NR == 2 { print $2 }'
    return
  fi
  printf 'unknown\n'
}

power_mode() {
  if command -v pmset >/dev/null 2>&1; then
    pmset -g batt 2>/dev/null | awk 'NR == 1 { print $0; exit }' && return
  fi
  printf 'unknown\n'
}

reference_setup_field() {
  local field="$1"
  local default_value="${2:-unknown}"
  if [[ ! -f "${reference_setup}" ]]; then
    printf '%s\n' "${default_value}"
    return
  fi
  node -e '
    const fs = require("node:fs");
    const [path, field] = process.argv.slice(1);
    const doc = JSON.parse(fs.readFileSync(path, "utf8"));
    process.stdout.write(String(doc[field] ?? "unknown"));
  ' "${reference_setup}" "${field}"
}

reference_setup_sha256() {
  if [[ ! -f "${reference_setup}" ]]; then
    printf 'none\n'
    return
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${reference_setup}" | awk '{ print $1 }'
  else
    shasum -a 256 "${reference_setup}" | awk '{ print $1 }'
  fi
}

now_seconds() {
  node -e 'console.log((Date.now() / 1000).toFixed(6))'
}

elapsed_ms() {
  local start="$1"
  local end="$2"
  awk -v start="${start}" -v end="${end}" 'BEGIN { printf "%.3f", (end - start) * 1000 }'
}

percentile_95() {
  awk '
    { values[NR] = $1 }
    END {
      if (NR == 0) {
        print "0.000";
        exit;
      }
      for (i = 1; i <= NR; i++) {
        for (j = i + 1; j <= NR; j++) {
          if (values[i] > values[j]) {
            tmp = values[i];
            values[i] = values[j];
            values[j] = tmp;
          }
        }
      }
      idx = int(0.95 * NR);
      if (0.95 * NR > idx) {
        idx++;
      }
      if (idx < 1) {
        idx = 1;
      }
      printf "%.3f\n", values[idx];
    }
  '
}

run_sample() {
  local name="$1"
  shift
  local start end elapsed
  start="$(now_seconds)"
  "$@" >/dev/null
  end="$(now_seconds)"
  elapsed="$(elapsed_ms "${start}" "${end}")"
  printf '%s\n' "${elapsed}" >> "${quality_dir}/${name}.samples"
  printf '{"name":"%s","elapsed_ms":%s}\n' "${name}" "${elapsed}" >> "${jsonl}"
}

run_sample_in_dir() {
  local name="$1"
  local directory="$2"
  shift 2
  (
    cd "${directory}"
    run_sample "${name}" "$@"
  )
}

sample_count() {
  local name="$1"
  wc -l < "${quality_dir}/${name}.samples" | tr -d ' '
}

prepare_staged_scan_fixture() {
  if [[ ! -d "${staged_scan_repo}" ]]; then
    echo "staged scan fixture missing at ${staged_scan_repo}; run make bench-fixtures first" >&2
    exit 2
  fi
  git -C "${staged_scan_repo}" init -q
  git -C "${staged_scan_repo}" add -A
}

write_report() {
  local cli_p95 agent_p95 scan_p95 cli_samples agent_samples scan_samples p95_index
  local processed_bytes elapsed_seconds throughput
  local reference_runner reference_setup_hash reference_setup_mode
  cli_p95="$(percentile_95 < "${quality_dir}/cli_help.samples")"
  agent_p95="$(percentile_95 < "${quality_dir}/agent_status.samples")"
  scan_p95="$(percentile_95 < "${quality_dir}/scan_staged.samples")"
  cli_samples="$(sample_count cli_help)"
  agent_samples="$(sample_count agent_status)"
  scan_samples="$(sample_count scan_staged)"
  p95_index="$(awk -v n="${min_samples}" 'BEGIN { idx = int(0.95 * n); if (0.95 * n > idx) idx++; if (idx < 1) idx = 1; print idx }')"
  processed_bytes="0"
  elapsed_seconds="0"
  throughput="not-measured"
  reference_runner="$(reference_setup_field setup_class local-smoke)"
  reference_setup_hash="$(reference_setup_sha256)"
  reference_setup_mode="$(reference_setup_field apply_mode none)"
  {
    echo "# Locket Benchmark Smoke Report"
    echo
    echo "- mode: ${mode}"
    echo "- policy_mode: ${policy_mode}"
    echo "- reference_runner: ${reference_runner}"
    echo "- reference_runner_setup_path: ${reference_setup}"
    echo "- reference_runner_setup_sha256: ${reference_setup_hash}"
    echo "- reference_runner_setup_mode: ${reference_setup_mode}"
    echo "- cpu_model: $(cpu_model)"
    echo "- core_count: $(metadata_value getconf _NPROCESSORS_ONLN)"
    echo "- memory_bytes: $(memory_bytes)"
    echo "- os: $(uname -srmo 2>/dev/null || uname -srm)"
    echo "- filesystem_type: $(filesystem_type)"
    echo "- power_mode: $(power_mode)"
    echo "- commit_sha: $(git rev-parse HEAD)"
    echo "- build_profile: ${build_profile}"
    echo "- rust_version: $(rustc -V)"
    echo "- agent_running_unlocked: no"
    echo "- cargo_jobs: ${jobs}"
    echo "- offline: ${offline}"
    echo "- warmup_iterations: ${min_warmups}"
    echo "- cli_help_samples: ${cli_samples}"
    echo "- cli_help_p95_ms: ${cli_p95}"
    echo "- cli_help_budget_ms: 100"
    echo "- agent_status_samples: ${agent_samples}"
    echo "- agent_status_p95_ms: ${agent_p95}"
    echo "- agent_status_budget_ms: 100"
    echo "- scan_staged_samples: ${scan_samples}"
    echo "- scan_staged_p95_ms: ${scan_p95}"
    echo "- scan_staged_budget_ms: 500"
    echo "- p95_index_formula: ceil(0.95 * n) - 1 zero-based / report index ${p95_index} one-based for ${min_samples} samples"
    echo "- throughput_processed_bytes: ${processed_bytes}"
    echo "- throughput_elapsed_seconds: ${elapsed_seconds}"
    echo "- throughput_bytes_per_second: ${throughput}"
    echo
    echo "This report records the reference-runner fields and sampling rules required"
    echo "by docs/specs/performance.md and includes the PR smoke surfaces for"
    echo "metadata commands and staged scans."
  } > "${report}"
  node -e '
    const fs = require("node:fs");
    const [
      path, mode, policyMode, profile, cliSamples, cliP95,
      agentSamples, agentP95, scanSamples, scanP95,
      setupPath, setupSha, setupClass, setupMode
    ] = process.argv.slice(1);
    const doc = {
      mode,
      policy_mode: policyMode,
      build_profile: profile,
      reference_runner_setup: {
        path: setupPath,
        sha256: setupSha,
        setup_class: setupClass,
        apply_mode: setupMode,
      },
      benchmarks: [
        { name: "cli_help", kind: "latency_ms", budget_ms: 100, samples: Number(cliSamples), p95_ms: Number(cliP95) },
        { name: "agent_status", kind: "latency_ms", budget_ms: 100, samples: Number(agentSamples), p95_ms: Number(agentP95) },
        { name: "scan_staged", kind: "latency_ms", budget_ms: 500, samples: Number(scanSamples), p95_ms: Number(scanP95) },
      ],
    };
    fs.writeFileSync(path, `${JSON.stringify(doc, null, 2)}\n`);
  ' "${summary}" "${mode}" "${policy_mode}" "${build_profile}" \
    "${cli_samples}" "${cli_p95}" \
    "${agent_samples}" "${agent_p95}" \
    "${scan_samples}" "${scan_p95}" \
    "${reference_setup}" "${reference_setup_hash}" "${reference_runner}" "${reference_setup_mode}"
}

if [[ "${mode}" == "report" ]]; then
  # docs/specs/performance.md:31 lists `make bench-report` alongside
  # `make bench` and `make bench-ci`. If a producer has not yet been run,
  # auto-produce the smoke report so the command is self-sufficient. Set
  # BENCH_REPORT_AUTORUN=0 to disable the fallback and require a prior
  # `make bench-ci` run.
  if [[ ! -f "${report}" ]]; then
    if [[ "${BENCH_REPORT_AUTORUN:-1}" == "1" ]]; then
      echo "no benchmark report at ${report}; running bench-smoke.sh ci to produce one" >&2
      if ! "${BASH:-bash}" "${BASH_SOURCE[0]}" ci; then
        echo "auto bench-ci run failed; run 'make bench-ci' manually then re-run 'make bench-report'" >&2
        exit 2
      fi
      if [[ ! -f "${report}" ]]; then
        echo "bench-ci finished but ${report} is still missing; run 'make bench-ci' manually" >&2
        exit 2
      fi
    else
      echo "no benchmark report at ${report}; run 'make bench-ci' first (or unset BENCH_REPORT_AUTORUN)" >&2
      exit 2
    fi
  fi
  cat "${report}"
  if [[ -f "${quality_dir}/bench-policy.md" ]]; then
    echo
    cat "${quality_dir}/bench-policy.md"
  fi
  exit 0
fi

: > "${jsonl}"
: > "${quality_dir}/cli_help.samples"
: > "${quality_dir}/agent_status.samples"
: > "${quality_dir}/scan_staged.samples"

"${cargo_bin}" build -p locket-cli "${offline_args[@]}" "${cargo_profile_args[@]}" -j "${jobs}" >/dev/null
prepare_staged_scan_fixture

for _ in $(seq 1 "${min_warmups}"); do
  "${binary}" --help >/dev/null
  "${binary}" agent status >/dev/null
  (cd "${staged_scan_repo}" && "${binary}" scan --staged >/dev/null)
done

for _ in $(seq 1 "${min_samples}"); do
  run_sample cli_help "${binary}" --help
  run_sample agent_status "${binary}" agent status
  run_sample_in_dir scan_staged "${staged_scan_repo}" "${binary}" scan --staged
done

write_report
policy_args=(--current "${summary}" --mode "${policy_mode}" --report "${quality_dir}/bench-policy.md")
if [[ -n "${baseline_summary}" ]]; then
  policy_args+=(--baseline "${baseline_summary}")
fi
if [[ -n "${accepted_regression_note}" ]]; then
  policy_args+=(--accepted-regression-note "${accepted_regression_note}")
fi
scripts/bench-policy.mjs "${policy_args[@]}"
cat "${report}"
