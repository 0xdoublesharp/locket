# OS Host Validation

These checks cover behavior that repository CI can only probe, not fully prove,
because the final signal requires real OS prompts, signed installers, desktop
session state, or physical hardware.

## Local User Verification

Dry-run probe for CI and non-target hosts:

```sh
scripts/validate-local-user-auth-real-host.sh --dry-run
```

Linux fresh-authentication validation (from an active desktop session):

```sh
scripts/validate-local-user-auth-real-host.sh --target linux-polkit
```

Set `TMPDIR` and `CARGO_TARGET_DIR` to disposable storage before running the
harness. Install Locket's Debian/RPM package, or install
`crates/locket-platform/resources/app.locket.policy` as root at
`/usr/share/polkit-1/actions/app.locket.policy` with mode `0644`, alongside
polkit's `/usr/bin/pkcheck`. A graphical polkit agent or the terminal's internal
agent must be available. Root sessions are rejected.

Run twice consecutively: each request must require the current user's
authentication, even when the Secret Service collection is unlocked. Repeat
with cancellation and an unavailable authentication agent; both must fail.
The action uses `auth_self` without caching and denies inactive sessions.
The helper uses the fixed system bus and verifies the root-owned policy's
contents. Administrative polkit rules remain part of the trusted host and can
override polkit decisions; do not install a rule that automatically authorizes
`app.locket.verify`.

Windows Hello real-host validation:

```sh
scripts/validate-local-user-auth-real-host.sh --target windows-hello
```

Run on an enrolled Windows user with an interactive desktop.

## External FIDO2 Key

Use an interactive macOS or Linux terminal with libfido2 1.17 or newer and one
USB FIDO2 key supporting PIN verification and hmac-secret. On macOS, install
the tools with `brew install libfido2`. Linux needs the same tool version in a
trusted system installation directory. Configure the key's PIN using its
vendor's supported tool before enrollment. Enter the PIN only in the hidden
terminal prompt, never in a command argument or environment variable.

In a disposable Locket project with its recovery code retained separately:

```sh
locket passkey register --label validation-key
locket passkey list
locket lock
locket passkey unlock validation-key
```

- Confirm registration requires local OS verification and the key's PIN/touch,
  and reports a successful PRF wrap.
- Lock and unlock twice with the same key; both must recover the same project.
- Unplug the key and repeat unlock; it must fail without falling back to a
  software keyring credential.
- Cancel a new enrollment and confirm it leaves no credential or successful
  registration audit row. Interrupt or time out a PIN prompt and verify terminal
  echo is restored.
- Verify ordinary recovery-code recovery remains usable independently.

Desktop PIN entry and Windows external-key ceremonies are not implemented by
this terminal backend. Do not run Locket elevated to obtain Windows HID access;
that platform needs a native WebAuthn integration.

The local-auth harness can additionally require that a key is visible on Linux:

```sh
scripts/validate-local-user-auth-real-host.sh --target linux-polkit --require-fido2
```

This option checks device inventory and prints the manual follow-up; it does not
replace the registration/unlock ceremonies above or prove hardware user presence.

## Session Lock and Suspend

Start a fresh agent with `locket agent start --require-session-monitoring` and
check `locket agent status`. Startup must fail when native monitoring is
unavailable, including headless Linux hosts without a graphical logind session.
An already-running daemon is accepted only if it reports active monitoring.

Linux uses the root-owned logind service on the system bus, an initial
`LockedHint`/`Active` snapshot, and a delay inhibitor for suspend. Windows uses
WTS session notifications, an initial session snapshot, and a top-level window
for power broadcasts. Both bound the time allowed for key erasure before
suspend. macOS uses native notifications; its observer does not yet query the
screen's lock state at startup.

On each interactive OS, unlock a test project and obtain a grant, then lock the
screen, switch users, suspend, and resume. Check that cached keys and old grants
are cleared, requests are denied while locked, and fresh authorization is
required after resuming. Repeat observer disconnection where supported; the
agent must stop. Verify no stale keys survive agent shutdown.

The Windows CI job executes workspace tests on a `windows-2025` VM. Docker can
exercise Linux code and service-unavailable failures, but neither that container
nor an unattended Windows runner proves real authentication prompts or physical
lock/sleep delivery. Those checks require an interactive host.

## Packaged Canary Validation

Dry-run probe for CI:

```sh
scripts/validate-packaged-os-canaries.sh --dry-run
```

Release-host validation after installer and VSIX artifacts are produced:

```sh
LOCKET_PACKAGE_ARTIFACT_ROOT=target/package \
  scripts/validate-packaged-os-canaries.sh --install-smoke
```

The script scans package artifacts for known canary markers, verifies the host
installer signature or package metadata, and installs the packaged VSIX through
the `code` CLI when available.

Manual release follow-ups:

- [ ] Run signed desktop webview smoke on macOS, Windows, and Linux release
  hosts after installing the packaged desktop app.
- [ ] Exercise OS clipboard and tray integration on each installed desktop app.
- [ ] Run a full recovery restore e2e from the packaged CLI/app and scan the
  produced artifacts with the packaged-canary script.
