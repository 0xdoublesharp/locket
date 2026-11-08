# frozen_string_literal: true

# Homebrew formula draft for the Locket CLI.
#
# This is a build-from-source formula. Until the offline release-signing
# ceremony (see docs/agents/progress.md, release-key-offline) ships, the
# tap is not production-ready and the SHA256 below is a placeholder.
#
# See dist/homebrew/README.md for the intended tap path and the release-tag
# to formula update flow.
class Locket < Formula
  desc "Local-first secrets control plane for development environments"
  homepage "https://github.com/0xdoublesharp/locket"
  # TODO(release-key-offline): replace with the signed release-tarball URL
  # produced by the offline signing ceremony. The pattern below mirrors the
  # GitHub source-tarball convention and will become a release-asset URL once
  # the signed tarball pipeline lands.
  url "https://github.com/0xdoublesharp/locket/archive/refs/tags/v#{version}.tar.gz"
  # TODO(release-key-offline): replace with actual release-tarball SHA256
  # from offline signing ceremony.
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"
  version "0.1.1"

  depends_on "rust" => :build

  def install
    # Build via cargo and install the resulting binary into the formula's
    # prefix. `--locked` ensures the resolved Cargo.lock is honored so the
    # build is bit-reproducible from the same source tarball.
    system "cargo", "install", "--locked", "--path", "crates/locket-cli", "--root", prefix
  end

  test do
    # Smoke test: `locket --version` must produce non-empty output.
    output = shell_output("#{bin}/locket --version").strip
    assert !output.empty?, "expected non-empty --version output"
  end

  def caveats
    <<~CAVEATS
      Locket Homebrew packaging is a working draft.

      Until the offline release-signing ceremony ships, this formula is
      published from a personal tap rather than homebrew-core. Production
      tap status depends on the release-key-offline roadmap item.

      Locket is local-first: it stores secrets in an encrypted vault on this
      machine. CI and production secrets should use platform-native stores.
    CAVEATS
  end
end
