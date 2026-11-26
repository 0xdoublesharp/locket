# Desktop UI & Tray

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Desktop UI

Build a modern Tauri v2 desktop app as a first-class control surface. The UI shares the same core, store, crypto, scan, exec, policy, and agent APIs as the CLI.

Primary views:

- First-run Welcome view offering one-click Global Vault (`@shared`) creation and auto-detecting project folder connection when no vault or project is selected.
- Unified sidebar vault and project switcher covering `@shared`, connected projects, environment switching, and project overview.
- Secret metadata list (default landing view once a vault or project is connected) with Discover, Add or import, and variable history tabs.
- Secret editor with gated set/update flow and `.env` import (requiring an absolute file path in `@shared`).
- Secret version history showing current, deprecated, and purged version metadata, including `deprecated_at`, `grace_until`, and pinned-reference eligibility.
- Command policy editor with variable readiness checks and terminal handoff (project folders with `locket.toml`).
- Activity views covering execution/session monitor, audit log and verification, and terminal scan handoff.
- Settings views covering preferences, environment switching, team sharing, people and devices, backup/recovery, and project overview.

Design direction:

- Modern, restrained, dense operational interface.
- Primary navigation stays focused on four destinations (**Secrets**, **Commands**, **Activity**, and **Settings**) paired with the unified vault switcher and `⌘K` command palette.
- Connected project overviews surface prioritized local next actions derived from verifiable metadata such as lock state, missing secrets, missing policies, scan status, audit health, failed runs, and share readiness.
- Keyboard-friendly flows.
- Clear locked/unlocked state.
- No marketing-style landing page.
- No secret values in frontend state unless a reveal/copy grant is active.
- Release webviews must not load remote content, remote fonts, analytics scripts, or third-party iframes. The app must use a restrictive Content Security Policy, disable release devtools where supported, and expose only scoped Tauri commands required by the current view.
- Tauri capabilities must deny broad filesystem, shell, network, updater, and clipboard access by default. Any capability that can reveal, copy, execute, import, export, or inspect local files must call the same Rust core authorization path as the CLI and agent.
- No decorative UI that obscures state, warnings, grants, or policy decisions.
- Search and filtering for projects, profiles, secrets, policies, audit events, scan findings, devices, and members.
- Secret rows must surface version-level deprecation warnings when a current policy, command preview, or `lk://...@vN` reference depends on a deprecated version whose grace window is active or expired.
- Version history must show current, deprecated, and purged states; grace expiry timestamps; whether pinned references remain eligible; scan inclusion while grace is active; and the audit metadata associated with the rotation that created the deprecated version.
- Accessible keyboard navigation, visible focus states, screen-reader labels, sufficient contrast, reduced-motion support, and reveal/copy flows that do not expose values through accessibility metadata after TTL expiry.
- When `privacy.redact_names = true`, dashboard, tray, shell-status mirrored UI, and notification surfaces must use local aliases for project, profile, secret, policy, device, and member names unless the user explicitly opens a detail view that requires exact names for editing.

### Global Vault links

In **Secrets**, choose a project and environment. Promote a local value to the Global Vault, or link an existing Global Vault entry under the name the project expects. A linked variable appears with its Global Vault target. Unlink it from the project to remove that mapping. In **Global Vault**, inspect usages before rotating or removing an entry. Rotation supplies the new value on subsequent runs of approved commands in the linked projects.

## UX Requirements

Every user-facing surface must make the secure path obvious and the unsafe path deliberate.

Error UX:

- CLI errors must include a short reason, stable exit code, and one safe next command when possible.
- UI, tray, shell, and VS Code errors must show the same reason and next action as the CLI.
- Error messages must not include secret values, wrapped key material, recovery material, grant tokens, raw public keys unless explicitly requested, or clipboard contents.
- Denied actions must distinguish locked vault, missing grant, explicit policy denial, dangerous-profile confirmation, revoked device, and expired invite.

Empty states:

- No project: explain `locket init` or `locket team accept`.
- No profile: offer `locket profile create dev`.
- No secrets: offer `locket set <KEY>` or `locket import .env`.
- No policy: offer `locket policy add dev -- <cmd>`.
- No agent: offer `locket agent start`.
- No team device: offer `locket device init`.

Confirmation UX:

- Dangerous-profile actions require typing the profile name.
- `--all`, shell grants, tray reveal/copy, member removal, device revocation, destructive import conflict resolution, and recovery must show what will happen using names and metadata only.
- Confirmations must be auditable and must not include values.

## Tray

The system tray or app bar status panel is a compact control surface over the agent.

It must show:

- Vault locked/unlocked state.
- Active project, or a local alias when privacy display mode is enabled.
- Active profile, or a local alias when privacy display mode is enabled.
- Running sessions.
- Recent scan warning count.
- Recent audit status.
- Count of active warnings for expiring or expired pinned references; exact names or aliases appear only in the opened app detail view, never in passive notifications.
- Agent status.

It must allow:

- Open app.
- Lock vault.
- Unlock vault through OS prompt.
- Switch profile.
- Run saved command policies.
- Start scan.
- Copy or reveal selected secret only after OS unlock and TTL grant.

The tray must never bypass core policy. It may launch only saved command policies, not arbitrary typed commands, because tray actions are easy to trigger accidentally.

Tray and notification privacy:

- No secret values are ever shown in tray menus, notifications, badges, accessibility labels, or hover text.
- Notifications must not include secret names by default for reveal/copy, denied access, scan findings, or execution failures; they should say "secret", "policy", or "project" unless the user opens the app. Exact names may appear inside the app when privacy display mode is off.
- Recent activity shown in the tray is bounded to metadata counts and safe statuses. Detailed audit rows stay in the app audit view.

Tray icon set: icons use the [Lucide](https://lucide.dev) icon set. The tray icon reflects agent and vault state:

| State | Icon | Description |
| --- | --- | --- |
| Agent running, vault unlocked | `lock-open` (filled) | Normal operating state |
| Agent running, vault locked | `lock` (filled) | Vault locked, agent available |
| Agent stopped | `lock` (outline) | No agent, no active session |
| Scan warning | `shield-alert` | One or more unresolved scan warnings |
| Error / degraded | `alert-triangle` | Agent error or degraded state |

On macOS the tray icon is a template image (black only, alpha mask) so the OS applies the correct appearance in light and dark menu bar modes. On Windows and Linux a full-color icon is used with explicit light/dark variants.
