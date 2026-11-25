#!/usr/bin/env bash
set -euo pipefail

mode="${1:-local}"
cargo_bin="${CARGO:-cargo}"
cargo_deny="${CARGO_DENY:-cargo deny}"
cargo_audit="${CARGO_AUDIT:-cargo audit}"
cargo_geiger="${CARGO_GEIGER:-cargo geiger}"
cargo_vet="${CARGO_VET:-cargo vet}"
strict="${STRICT:-0}"
quality_dir="target/quality"

mkdir -p "${quality_dir}"

require_tool() {
  local name="$1"
  local command="$2"

  if ${command} --version >/dev/null 2>&1; then
    return 0
  fi

  if [[ "${strict}" == "1" ]]; then
    echo "${name} is required for strict supply-chain checks" >&2
    exit 127
  fi

  echo "${name} is not installed; skipping ${name} check" >&2
  return 1
}

metadata() {
  "${cargo_bin}" metadata --offline --locked --format-version=1 > "${quality_dir}/cargo-metadata.json"
}

exception_ledger() {
  scripts/supply-chain-exceptions.mjs \
    supply-chain-exceptions.json \
    "${quality_dir}/supply-chain-exceptions.md"
}

third_party_notices() {
  scripts/third-party-notices.mjs \
    "${quality_dir}/cargo-metadata.json" \
    "${quality_dir}/THIRD_PARTY_NOTICES.md"
}

deny_local() {
  if require_tool "cargo-deny" "${cargo_deny}"; then
    ${cargo_deny} check licenses bans sources
  fi
}

deny_strict() {
  if require_tool "cargo-deny" "${cargo_deny}"; then
    ${cargo_deny} check
  fi
}

audit_local() {
  if ! require_tool "cargo-audit" "${cargo_audit}"; then
    return 0
  fi

  metadata

  if ${cargo_audit} --help 2>/dev/null | grep -q -- '--no-fetch'; then
    audit_with_policy --no-fetch --stale --json
    return 0
  fi

  if [[ "${strict}" == "1" ]]; then
    echo "cargo-audit does not support --no-fetch; refusing strict offline audit" >&2
    exit 127
  fi

  echo "cargo-audit lacks --no-fetch; skipping to avoid network access" >&2
}

audit_strict() {
  if require_tool "cargo-audit" "${cargo_audit}"; then
    metadata
    audit_with_policy --json
  fi
}

vet() {
  if require_tool "cargo-vet" "${cargo_vet}"; then
    ${cargo_vet} --locked
  fi
}

audit_with_policy() {
  local audit_json="${quality_dir}/rustsec-audit.json"
  local report="${quality_dir}/rustsec-policy.md"
  local status

  set +e
  ${cargo_audit} "$@" > "${audit_json}"
  status=$?
  set -e

  if [[ "${status}" -gt 1 ]]; then
    echo "cargo-audit failed before policy evaluation; see ${audit_json}" >&2
    exit "${status}"
  fi

  if [[ ! -s "${audit_json}" ]]; then
    echo "cargo-audit did not write a JSON report" >&2
    exit 1
  fi

  scripts/rustsec-policy.mjs \
    "${audit_json}" \
    "${quality_dir}/cargo-metadata.json" \
    supply-chain-exceptions.json \
    "${report}"
}

unsafe_inventory() {
  local report="${quality_dir}/unsafe-inventory.md"
  local geiger_report="${quality_dir}/unsafe-inventory.geiger.md"

  metadata

  if require_tool "cargo-geiger" "${cargo_geiger}"; then
    if ${cargo_geiger} --all-features --output-format GitHubMarkdown > "${geiger_report}"; then
      {
        echo "# Unsafe Inventory"
        echo
        echo "- Tool: cargo-geiger"
        echo "- Scope: workspace, all features"
        echo "- Metadata: ${quality_dir}/cargo-metadata.json"
        echo
        cat "${geiger_report}"
      } > "${report}"
      rm -f "${geiger_report}"
      echo "wrote ${report}"
      return 0
    fi

    if [[ "${strict}" == "1" ]]; then
      echo "cargo-geiger failed during strict unsafe inventory" >&2
      exit 1
    fi

    echo "cargo-geiger failed; writing lexical unsafe inventory fallback" >&2
  else
    echo "cargo-geiger is not installed; writing lexical unsafe inventory fallback" >&2
  fi

  unsafe_inventory_fallback "${report}"
}

unsafe_inventory_fallback() {
  local report="$1"

  scripts/unsafe-inventory-fallback.mjs "${quality_dir}/cargo-metadata.json" "${report}"
}

sbom() {
  if command -v cargo-cyclonedx >/dev/null 2>&1; then
    metadata
    CARGO_NET_OFFLINE=true "${cargo_bin}" cyclonedx --format json --target all
    # cargo-cyclonedx writes one BOM next to each workspace member's manifest.
    node --input-type=module - "${quality_dir}" <<'NODE'
import { copyFileSync, readFileSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";

const output = process.argv[2];
const { packages, workspace_members } = JSON.parse(readFileSync(join(output, "cargo-metadata.json"), "utf8"));
for (const pkg of packages.filter(({ id }) => workspace_members.includes(id))) {
  const name = `${pkg.name}.cdx.json`;
  const source = join(dirname(pkg.manifest_path), name);
  copyFileSync(source, join(output, name));
  unlinkSync(source);
}
NODE
    return 0
  fi

  if [[ "${strict}" == "1" ]]; then
    echo "cargo-cyclonedx is required for strict SBOM generation" >&2
    exit 127
  fi

  echo "cargo-cyclonedx is not installed; writing metadata fallback only" >&2
  metadata
  cat > "${quality_dir}/SBOM-FALLBACK.md" <<EOF
# SBOM Fallback Metadata

- Tool: cargo metadata
- File: ${quality_dir}/cargo-metadata.json
- Reason: cargo-cyclonedx is not installed, so a CycloneDX SBOM was not generated.

Release consumers must treat this as fallback dependency metadata, not as a CycloneDX SBOM.
EOF
}

case "${mode}" in
  local)
    exception_ledger
    metadata
    third_party_notices
    deny_local
    audit_local
    ;;
  deny)
    metadata
    if [[ "${strict}" == "1" ]]; then
      deny_strict
    else
      deny_local
    fi
    ;;
  audit)
    exception_ledger
    if [[ "${strict}" == "1" ]]; then
      audit_strict
    else
      audit_local
    fi
    ;;
  vet)
    vet
    ;;
  unsafe)
    unsafe_inventory
    ;;
  sbom)
    sbom
    ;;
  notices)
    metadata
    third_party_notices
    ;;
  exceptions)
    exception_ledger
    ;;
  strict)
    exception_ledger
    metadata
    third_party_notices
    deny_strict
    audit_strict
    vet
    unsafe_inventory
    sbom
    ;;
  *)
    echo "unknown supply-chain mode: ${mode}" >&2
    exit 2
    ;;
esac
