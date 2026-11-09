#!/usr/bin/env bash
set -euo pipefail

# --require-build-l3 accepts GitHub-hosted builders and this repository's own
# workflows, and refuses workflows from any other repository or owner.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/locket-slsa-policy-test.XXXXXX")"
trap 'rm -rf "${tmpdir}"' EXIT

artifact="${tmpdir}/locket"
printf 'locket release binary fixture\n' >"${artifact}"
digest="$(node -e 'const { createHash } = require("node:crypto");
process.stdout.write(createHash("sha256").update(require("node:fs").readFileSync(process.argv[1])).digest("hex"));' "${artifact}")"

repository="https://github.com/0xdoublesharp/locket"
workflow=".github/workflows/release.yml@refs/tags/v0.2.0"
build_type="https://actions.github.io/buildtypes/workflow/v1"

check_builder() {
  local want="$1" builder="$2"
  local provenance="${tmpdir}/provenance.json" report="${tmpdir}/report.md"
  cat >"${provenance}" <<JSON
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "locket", "digest": { "sha256": "${digest}" } }],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "${build_type}",
      "externalParameters": { "repository": "${repository}", "workflow": "${workflow}" }
    },
    "runDetails": { "builder": { "id": "${builder}" } }
  }
}
JSON

  set +e
  node "${repo_root}/scripts/slsa-provenance-policy.mjs" \
    --artifact "${artifact}" \
    --provenance "${provenance}" \
    --expected-repository "${repository}" \
    --expected-builder "${builder}" \
    --expected-build-type "${build_type}" \
    --expected-workflow "${workflow}" \
    --require-build-l3 \
    --report "${report}" >/dev/null 2>&1
  local status=$?
  set -e

  if ! grep -Fq "| Build L3 hosted-runner target | ${want} |" "${report}" \
    || { [[ "${want}" == "passed" ]] && [[ "${status}" -ne 0 ]]; } \
    || { [[ "${want}" == "failed" ]] && [[ "${status}" -eq 0 ]]; }; then
    echo "Build L3 check for ${builder}: expected ${want}, policy exited ${status}" >&2
    cat "${report}" >&2
    exit 1
  fi
}

check_builder passed "https://github.com/0xdoublesharp/locket/${workflow}"
check_builder passed "https://github.com/actions/runner/github-hosted"
check_builder failed "https://github.com/someone-else/locket/${workflow}"
check_builder failed "https://github.com/0xdoublesharp/locket-fork/${workflow}"

echo "slsa-provenance-policy-test: passed"
