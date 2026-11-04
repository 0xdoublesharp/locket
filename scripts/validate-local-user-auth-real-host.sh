#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-cargo}"
source "$(dirname "${BASH_SOURCE[0]}")/cargo-jobs.sh"
jobs="$(cargo_jobs)"
target="auto"
dry_run=0
require_fido2=0

usage() {
  sed -n '1,120p' <<'USAGE'
Usage:
  scripts/validate-local-user-auth-real-host.sh [--target auto|linux-polkit|windows-hello] [--require-fido2] [--dry-run]

Runs the LocalUserVerifier against real host OS user-presence APIs.

Targets:
  linux-polkit          Exercises fresh current-user polkit authentication.
  windows-hello         Exercises Windows Hello UserConsentVerifier.
  auto                  Selects a target from uname.

--require-fido2 verifies that a Linux FIDO2 token is visible to the host and
prints the terminal passkey acceptance commands. Inventory does not prove a
successful PIN/touch or PRF ceremony.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      target="${2:-}"
      shift 2
      ;;
    --require-fido2)
      require_fido2=1
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

detect_target() {
  case "$(uname -s)" in
    Linux*) echo "linux-polkit" ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT) echo "windows-hello" ;;
    *)
      echo "unsupported"
      ;;
  esac
}

require_tool() {
  local tool="$1"
  if command -v "${tool}" >/dev/null 2>&1; then
    return 0
  fi
  echo "required tool not found: ${tool}" >&2
  exit 127
}

write_harness() {
  local harness_dir="$1"
  mkdir -p "${harness_dir}/src"
  cat > "${harness_dir}/Cargo.toml" <<EOF
[package]
name = "locket-local-auth-real-host"
version = "0.0.0"
edition = "2024"
publish = false

[dependencies]
locket-platform = { path = "${repo_root}/crates/locket-platform" }
EOF
  cat > "${harness_dir}/src/main.rs" <<'EOF'
use locket_platform::{LocalUserVerificationRequest, default_local_user_verifier};

fn main() {
    let verifier = default_local_user_verifier();
    let request = LocalUserVerificationRequest::new(
        "real_host_validation",
        "Validate Locket local user verification",
    );

    match verifier.verify_user(&request) {
        Ok(result) => {
            println!(
                "local user verification succeeded: method={:?} platform={}",
                result.method, result.platform
            );
        }
        Err(error) => {
            eprintln!("local user verification failed: {error}");
            std::process::exit(1);
        }
    }
}
EOF
}

run_harness() (
  local harness_dir
  : "${TMPDIR:?Set TMPDIR to disposable storage before running the host harness}"
  harness_dir="$(mktemp -d "${TMPDIR%/}/locket-local-auth.XXXXXX")"
  trap 'rm -rf "${harness_dir}"' EXIT
  write_harness "${harness_dir}"
  # Preserve the workspace versions while adding only this temporary harness.
  # The new package is absent from the workspace lock, so --locked cannot be
  # used until Cargo records it. Offline resolution uses the installed cache.
  cp "${repo_root}/Cargo.lock" "${harness_dir}/Cargo.lock"
  "${cargo_bin}" run --manifest-path "${harness_dir}/Cargo.toml" --offline -j "${jobs}"
)

validate_linux_prereqs() {
  if [[ ! -x /usr/bin/pkcheck || ! -f /usr/share/polkit-1/actions/app.locket.policy ]]; then
    echo "install polkit and Locket's packaged policy before validating fresh authentication" >&2
    exit 65
  fi
  if [[ ! -S /run/dbus/system_bus_socket ]]; then
    echo "system D-Bus unavailable; run from an active Linux desktop session" >&2
    exit 65
  fi
  if [[ "${require_fido2}" == "1" ]]; then
    require_tool fido2-token
    local devices
    devices="$(fido2-token -L)"
    if [[ -z "${devices}" ]]; then
      echo "no FIDO2 key is visible; connect a supported key before this check" >&2
      exit 65
    fi
    printf '%s\n' "${devices}"
    cat <<'EOF'
Manual follow-up in a disposable Locket project, from an interactive terminal:
  locket passkey register --label validation-key
  locket lock
  locket passkey unlock validation-key
Complete the PIN/touch prompts and the acceptance checks documented in
docs/operations/os-host-validation.md. The local-auth harness below tests polkit.
EOF
  fi
}

if [[ "${target}" == "auto" ]]; then
  target="$(detect_target)"
fi

case "${target}" in
  linux-secret-service)
    # Retain the old invocation as an alias; Secret Service is not a consent gate.
    target="linux-polkit"
    ;;
  linux-polkit|windows-hello)
    ;;
  unsupported)
    if [[ "${dry_run}" == "1" ]]; then
      echo "dry-run: current host has no real-host local-auth target"
      exit 0
    fi
    echo "unsupported host for real local-auth validation: $(uname -s)" >&2
    exit 64
    ;;
  *)
    echo "unknown target: ${target}" >&2
    usage >&2
    exit 64
    ;;
esac

if [[ "${dry_run}" == "1" ]]; then
  echo "dry-run: would run ${target} LocalUserVerifier harness via ${cargo_bin}"
  if [[ "${require_fido2}" == "1" ]]; then
    echo "dry-run: would require a visible FIDO2 key and print manual passkey acceptance commands"
  fi
  exit 0
fi

require_tool "${cargo_bin}"
cd "${repo_root}"

case "${target}" in
  linux-polkit)
    validate_linux_prereqs
    run_harness
    ;;
  windows-hello)
    run_harness
    ;;
esac
