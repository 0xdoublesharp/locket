#!/usr/bin/env bash
set -euo pipefail

# Release binaries here must use the development instance; the OS keychain
# ignores the temporary HOME these scripts set.
export LOCKET_INSTANCE=dev
umask 0077

cargo_bin="${CARGO:-cargo}"
source "$(dirname "${BASH_SOURCE[0]}")/cargo-jobs.sh"
jobs="$(cargo_jobs)"
offline="${OFFLINE:-1}"
build_profile="${PERF_AGENT_IDLE_BUILD_PROFILE:-release}"
samples="${PERF_AGENT_IDLE_SAMPLES:-5}"
warmups="${PERF_AGENT_IDLE_WARMUPS:-5}"
warmup_seconds="${PERF_AGENT_IDLE_WARMUP_SECONDS:-1}"
budget_mb="${PERF_AGENT_IDLE_BUDGET_MB:-50}"
report="${PERF_AGENT_IDLE_REPORT:-target/quality/perf-agent-idle-memory.md}"

cargo_profile_args=()
binary="target/debug/locket"
if [[ "${build_profile}" == "release" ]]; then
  cargo_profile_args=(--release)
  binary="target/release/locket"
elif [[ "${build_profile}" != "debug" ]]; then
  echo "PERF_AGENT_IDLE_BUILD_PROFILE must be release or debug" >&2
  exit 2
fi

offline_args=()
if [[ "${offline}" == "1" ]]; then
  offline_args=(--offline)
fi

tmpdir="$(mktemp -d "/tmp/lai.XXXXXX")"
home_dir="${tmpdir}/h"
mkdir -p "${home_dir}"

cleanup() {
  HOME="${home_dir}" XDG_DATA_HOME="${home_dir}/.local/share" XDG_CONFIG_HOME="${home_dir}/.config" \
    "${binary}" agent stop >/dev/null 2>&1 || true
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

metadata_value() {
  local command="$1"
  shift
  "$command" "$@" 2>/dev/null | head -n 1 || printf 'unknown\n'
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

rss_kib() {
  local pid="$1"
  local value
  value="$(ps -o rss= -p "${pid}" | tr -d ' ')"
  if [[ -z "${value}" ]]; then
    echo "could not read RSS for agent pid ${pid}" >&2
    exit 1
  fi
  printf '%s\n' "${value}"
}

"${cargo_bin}" build -p locket-cli "${offline_args[@]}" "${cargo_profile_args[@]}" -j "${jobs}" >/dev/null

start_output="$(
  HOME="${home_dir}" XDG_DATA_HOME="${home_dir}/.local/share" XDG_CONFIG_HOME="${home_dir}/.config" \
    "${binary}" agent start
)"
agent_pid="$(awk '/^pid:/ { print $2 }' <<< "${start_output}")"
if [[ ! "${agent_pid}" =~ ^[0-9]+$ ]]; then
  echo "agent start did not report a numeric pid" >&2
  echo "${start_output}" >&2
  exit 1
fi

sleep "${warmup_seconds}"
for _ in $(seq 1 "${warmups}"); do
  HOME="${home_dir}" XDG_DATA_HOME="${home_dir}/.local/share" XDG_CONFIG_HOME="${home_dir}/.config" \
    "${binary}" agent status >/dev/null
done

mkdir -p "$(dirname "${report}")"
samples_path="${report%.md}.samples"
: > "${samples_path}"

peak_kib=0
for _ in $(seq 1 "${samples}"); do
  current_kib="$(rss_kib "${agent_pid}")"
  printf '%s\n' "${current_kib}" >> "${samples_path}"
  if (( current_kib > peak_kib )); then
    peak_kib="${current_kib}"
  fi
  sleep 0.2
done

peak_mb="$(awk -v kib="${peak_kib}" 'BEGIN { printf "%.3f", kib / 1024 }')"
budget_kib="$(awk -v mb="${budget_mb}" 'BEGIN { printf "%d", mb * 1024 }')"
result="passed"
if (( peak_kib > budget_kib )); then
  result="failed"
fi

cat > "${report}" <<EOF
# Agent Idle Memory

- benchmark: perf-agent-idle-memory
- result: ${result}
- budget_mb: ${budget_mb}
- peak_rss_mb: ${peak_mb}
- samples: ${samples}
- warmup_status_calls: ${warmups}
- warmup_seconds: ${warmup_seconds}
- build_profile: ${build_profile}
- cargo_jobs: ${jobs}
- offline: ${offline}
- agent_pid: ${agent_pid}
- os: $(uname -srmo 2>/dev/null || uname -srm)
- memory_bytes: $(memory_bytes)
- rust_version: $(rustc -V)
- commit_sha: $(git rev-parse HEAD)
- samples_path: ${samples_path}
EOF

if [[ "${result}" != "passed" ]]; then
  echo "perf-agent-idle-memory failed: peak ${peak_mb} MB > budget ${budget_mb} MB" >&2
  exit 1
fi

echo "perf-agent-idle-memory passed: peak ${peak_mb} MB <= budget ${budget_mb} MB; report=${report}"
