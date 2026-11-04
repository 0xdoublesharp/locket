# Local Agent / Daemon

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Local Agent / Daemon

The agent will be the substrate for good local DX. CLI, UI, tray, shell hook, and VS Code extension must be thin clients when the agent is running.

Transport:

- Linux/macOS: Unix domain socket.
- Linux/macOS client authentication: peer credential check where available (`SO_PEERCRED`, `getpeereid`, or platform equivalent).
- Windows: named pipe with ACL restricted to the current user.
- Socket/pipe path must be user-scoped and protected from other users.

Socket and pipe locations:

- Linux: `$XDG_RUNTIME_DIR/locket/agent.sock` when `XDG_RUNTIME_DIR` is set, falling back to `~/.locket/agent.sock` with `0700` parent-directory permissions and `0600` socket permissions.
- macOS: `~/Library/Application Support/locket/agent.sock` with the same permission posture; the directory is created on first run.
- Windows: `\\.\pipe\locket-agent-<sid>` where `<sid>` is the current user's SID. The pipe DACL grants the current user only.
- Locket resolves these paths via the `directories` crate and rejects any path that is world- or group-accessible.

Responsibilities:

- Hold unwrapped keys in memory after unlock.
- Serve project/profile status.
- Issue TTL-bound grants.
- Resolve authorized `lk://` references.
- Verify signed requests from registered automation clients after local peer authentication.
- Launch approved command policies or return scoped secret material to trusted CLI execution paths.
- Feed tray, UI, shell, and VS Code status without exposing secret values.
- Clear keys on lock, timeout, process exit, or explicit user action.

Grant model:

- Grants are scoped to project id, profile id, directory hash, peer identity, process id or shell session where available, action set, and expiration.
- Grants can authorize actions such as run policy, resolve reference, scan known values, reveal, or copy.
- Grants never contain secret values.
- Expired or revoked grants fail closed.

Agent checks:

- Unauthorized peer credentials are rejected.
- Agent socket/pipe collision fails closed with a typed error.
- Agent restart drops all in-memory grants and keys.
- Thin clients can fall back to direct unlock only for commands that do not require long-lived shell/editor state.

Lifecycle and hardening:

- The agent can start on demand, from the tray app, or at login when the user enables autostart.
- The agent locks on explicit `locket lock`, idle timeout, process exit, system sleep, screen lock where detectable, and user-session switch where detectable.
- macOS implements native sleep/wake and screen lock/unlock notifications. Sleep is acknowledged after key erasure and grant revocation; if this cannot finish within five seconds, the daemon exits. Losing an active observer also clears keys and grants and stops the daemon. User-session changes can be signaled with `SIGHUP`; there is no separate native switch observer. Linux and Windows currently report native session monitoring as unavailable; users must lock explicitly when leaving those sessions. `Status.session_monitoring`, `agent start`, `agent status`, and the desktop warning expose this capability.
- An empty unlock cache has no polling timer. Inserts wake the expiry worker, which uses the earliest deadline with a 100 ms maximum wait while keys exist so forward wall-clock changes still cause prompt physical erasure and grant revocation.
- Stale sockets or pipes are cleaned up only after verifying that no live trusted agent owns them.
- Linux agents must call `prctl(PR_SET_DUMPABLE, 0)` and set `RLIMIT_CORE = 0` where available.
- macOS and Windows agents must use the closest platform-supported core-dump suppression and process hardening available to a user-space app.
- The agent must use best-effort memory locking for master keys, project/profile keys, DEKs, and in-flight plaintext secret values: `mlock`/`mlockall` and `MADV_DONTDUMP` where available on Unix-like systems, and `VirtualLock` on Windows. If memory locking is unavailable or denied, Locket must either warn and continue under the documented local-machine threat model or fail closed when project policy requires locked memory.
- Agent-held key material and plaintext buffers must be zeroized before unlock TTL expiry, lock, process exit, grant revocation, and after each execution/reveal/copy/scan preparation path.
- Agent logs are local, redacted, metadata-only, and accessible through `locket agent logs`; log format, retention, and CLI flags are defined in [operations.md](operations.md).

Agent protocol:

- Requests and responses use a 4-byte little-endian length prefix followed by a UTF-8 JSON payload. The length excludes the 4-byte prefix. JSON is required for v1 so redacted debug bundles can include envelope metadata without bespoke decoders.
- Every request envelope has shape `{ "v": 1, "id": "<request-id>", "kind": "<method>", "payload": { ... } }`.
- Every success response envelope has shape `{ "v": 1, "id": "<request-id>", "ok": true, "payload": { ... } }`.
- Every error response envelope has shape `{ "v": 1, "id": "<request-id>", "ok": false, "error": "<TypedError>", "message": "<redacted safe message>", "retryable": false }`.
- Streaming methods use the same length-prefixed JSON framing. `SubscribeStatus` returns an initial success envelope, then sends a sequence of `StatusEvent` success envelopes on the same persistent connection until the client sends `CancelSubscription` or closes the connection. The agent sends a metadata-only heartbeat at least every 30 seconds so clients can detect broken streams. Heartbeats are `StatusEvent` envelopes with `kind = "heartbeat"` in the payload alongside the current `lock_state` and a monotonically increasing `sequence` counter; clients must not treat a heartbeat as a meaningful state change and must not act on the `lock_state` field differently from a normal `StatusEvent`.
- Unknown top-level envelope fields are ignored only when `v` is supported. Unknown required payload fields for a specific method fail with `ConfigError` or the relevant typed protocol error.
- Every request includes protocol version, request id, client kind inside payload, project context if known, requested action, and safe metadata.
- The agent authenticates the local peer before evaluating the request.
- Automation-client authentication uses Ed25519 challenge-response. The client sends `ClientHello { client_id }`; the agent returns a 24-byte random challenge nonce and a `challenge_id` (a random 16-byte value encoded as unpadded base64url, unique per challenge, used to bind the response to a specific challenge instance and prevent cross-challenge replay); the client signs `locket-client-auth-v1 || client_id || challenge_id || nonce || request_timestamp || request_id || canonical_request_hash` using its Ed25519 private key and sends the signature with the request. The `payload.auth.nonce` field in the signed request must equal the agent-issued challenge nonce byte-for-byte; v1 has no separate client-generated auth nonce. All byte string fields in the signed message are encoded as raw bytes without delimiters; `client_id` and `challenge_id` are encoded as their UTF-8 bytes. The agent verifies against `AutomationClient.public_key` before policy evaluation. Replayed, expired, revoked, or policy-mismatched client requests fail closed and write `CLIENT_AUTH` audit rows when project context is available.
- `canonical_request_hash` is `SHA-256` over canonical JSON for the intended request envelope with authentication fields omitted. Canonical JSON means UTF-8, sorted object keys, no insignificant whitespace, integers in decimal form, and strings escaped per JSON rules. The request `id`, `kind`, `v`, and `payload` are included, so a signature cannot be replayed across methods or payloads.
- Authentication fields are exactly `payload.auth.client_id`, `payload.auth.challenge_id`, `payload.auth.nonce`, `payload.auth.request_timestamp`, `payload.auth.signature`, and `payload.auth.public_key_hint` when present. No other fields are omitted from `canonical_request_hash`. The signed request must still include `client_id`, `challenge_id`, `nonce`, `request_timestamp`, and `signature` under `payload.auth` so the agent can verify the signature and freshness after recomputing the hash.
- Automation-client request timestamps have a default freshness window of 5 minutes. Accepted agent-issued challenge nonces are persisted in `automation_client_nonces.nonce` with `expires_at = request_timestamp + 10 minutes`; the `(client_id, nonce)` uniqueness constraint prevents replay across agent restarts. The persisted nonce is the challenge nonce returned by the agent and echoed in `payload.auth.nonce`, not any additional request payload field. The 10-minute retention window intentionally exceeds the 5-minute freshness window so nonce rows remain available during cleanup lag. Expired nonce rows are pruned opportunistically during client authentication and by `locket doctor`.
- The agent rejects oversized messages, malformed messages, unknown protocol versions, and requests missing required context. Default maximum message size is 1 MiB, configurable upward only when explicitly required by scan or bundle flows.
- Default request timeout is 5 seconds for metadata/status calls and 30 seconds for unlock, scan, import, export, and execution preparation calls.
- Decrypted secret values may cross the socket only for explicitly authorized CLI execution, reveal, copy, redaction, or scan flows. UI, tray, shell prompt, VS Code status, diagnostics, and metadata calls receive no secret values.
- Status and subscription payloads must honor `privacy.redact_names` for tray, shell, notifications, and VS Code status clients by returning stable aliases or counts where exact names are not required. Detail views may request exact metadata only after declaring a UI/detail client kind; the response is still metadata-only and never contains values.
- Grant validation checks project id, profile id, action, directory hash, peer identity, process id, process start time where available, shell session id where available, and expiration.
- Policy execution bindings carry `execution = { policy_name, cwd }`. The agent binds that context to the live grant and reloads the durable command, deepest path scope, and secret ACLs before reference delivery. A changed command or directory requires another grant. Older reference clients without an execution context are evaluated at the project root.
- Policy preparation may request `Unlock` with `reuse_cached = true`; this reuses a live project key without extending its original TTL. Explicit unlock requests still authenticate through the configured key store. Daemon-owned expiry clears elapsed keys and their project grants independently of status clients.
- PIDs are never trusted alone. Process-bound grants must bind to `(pid, process_start_time)` using `/proc/<pid>/stat` on Linux, platform process creation time on Windows, and the closest available macOS process start metadata.
- Agent restart drops all live TTL grants. Durable directory consent remains in `directory_grants`, but a fresh live TTL grant is still required before resolution or execution.

Required agent RPC methods:

- `Status`: returns lock state, active project/profile metadata, grant summary, and agent version.
- `Unlock`: performs OS keychain or passphrase-fallback unlock and starts the in-memory key TTL.
- `Lock`: clears unwrapped keys and live TTL grants.
- `RegisterClient`: stores a scoped automation-client public key and writes `CLIENT_ADD`.
- `RevokeClient`: revokes an automation client and writes `CLIENT_REVOKE`.
- `RequestGrant`: evaluates policy and returns a grant id without secret values.
- `RevokeGrant`: revokes a live grant and writes an `AGENT_REVOKE` audit row.
- `ExpireGrant`: records `GRANT_EXPIRED` lazily when an expired grant is observed during use, explicit cleanup, or status refresh. The agent must not run a background sweeper that writes `GRANT_EXPIRED` rows solely because time passed; that would add audit noise and make expiration logs depend on daemon scheduling.
- `ResolveReference`: resolves authorized `lk://` references for an execution/reveal/copy/redaction context.
- `PrepareExec`: resolves a command policy into allowed env names, command kind, TTL, and a process-bound `PrepareExec` grant id; secret values are resolved only by follow-up `ResolveReference` calls.
- `ScanKnownValues`: provides in-memory known-secret matching for scanner calls without persisting values.
- `Reveal` and `Copy`: perform gated value access for CLI/UI/tray/VS Code flows.
- `SubscribeStatus`: streams metadata-only status updates to UI, tray, shell, and VS Code.
- `CancelSubscription`: closes a status stream by request id; closing the socket is also a valid cancellation path.

CLI agent commands:

`locket agent start` starts the local agent daemon and is idempotent. If a trusted agent for the current user already owns the socket or pipe path, `agent start` prints metadata-only status and exits successfully rather than competing for the socket. If a socket, pipe, or pid file exists but no live trusted process owns it, Locket removes the stale endpoint and starts a fresh agent. If another live or untrusted process owns the endpoint, startup fails with `AgentSocketInUse`. On successful start the agent acquires the socket or pipe, writes its PID to `agent.pid`, and begins serving requests. Starting the agent does not unlock the vault by itself.

`locket agent stop` sends a graceful shutdown request only to a trusted current-user agent. The agent clears all in-memory keys, revokes live TTL grants, closes subscriptions, removes the socket or pipe and pid file, then exits. It writes a `LOCK` audit row when project context is available and keys were held, and `AGENT_REVOKE` audit rows for grants revoked because of stop. If no agent is running (`agent.pid` absent or process not live), the command exits successfully with a notice after removing any stale endpoint it can verify as unowned. `locket agent stop` waits up to 5 seconds for a clean exit; if the process does not exit within that window, it fails with an error and reports the PID so the user can investigate.

`locket agent status` contacts the agent over the local socket or pipe and prints metadata only: running or stopped state, agent version, pid, socket or pipe path, lock state, unlock TTL remaining when available, live grant count, active project/profile when a project context is resolved, degraded hardening flags, and last error summary. When the agent is unreachable, it reports stopped and includes the last known PID from `agent.pid` if that file is present.

`locket agent invite request` prints a paste-friendly setup request for the current machine or for a supplied `--device <descriptor>`. When no descriptor is supplied, the command uses the active local device descriptor; if none exists, it fails with actionable guidance to run `locket device init` explicitly. It then prints a bounded text block containing the device descriptor, fingerprint, safety words, optional project metadata, and an issuer command of the form `locket agent invite create <label> --device <descriptor> --profile dev --role developer [--expires-in 7d]`. The request block is metadata-only and contains no secret values, wrapped key material, recovery material, or device private keys.

`locket agent invite create <label> --device <descriptor> --profile <profile> --role <role> [--expires-in <duration>]` is an agent-oriented wrapper for the team invite creation flow defined in [team-sync-recovery.md](team-sync-recovery.md). It uses the same device descriptor parsing, safety-word verification requirement, issuer authorization, expiry bounds, profile scoping, dangerous-profile confirmation, sealed payload format, and audit behavior as `locket team invite`. Its output keeps the standard signed invite file for retry and auditability, then prints a heredoc accept block designed for copy/paste or desktop command handoff. It must not introduce an alternate invite format or bypass team role checks.

`locket agent invite accept -` reads a signed sealed invite block from stdin and applies the team accept flow defined in [team-sync-recovery.md](team-sync-recovery.md). It must show the same issuer, recipient, project, profile, role, expiry, fingerprint, and safety-word summary as `locket team accept`; enforce the same local user-verification policy; record the same replay-prevention and audit rows; and fail closed for expired, revoked, unsigned, incorrectly signed, fingerprint-mismatched, or project-mismatched invites. The `-` stdin form is intended for heredocs emitted by desktop or chat handoff surfaces and must not log or persist the raw invite text except as the accepted invite record required by the team spec.

Agent-to-agent setup proposal:

- The immediate next step is a user-mediated signed setup request. A local agent can emit a signed request block containing its device descriptor, requested project/profile metadata, timestamp, nonce, and intended role. Another local user or maintainer can paste that block into `locket agent invite create`, inspect the metadata-only summary, and explicitly approve creation of the sealed team invite. The receiver then consumes the sealed invite through `locket agent invite accept -`. This keeps transport out of scope while allowing agents to prepare and validate handoff text for humans.
- The request signature should authenticate the requesting device descriptor and freshness, but it should not grant access by itself. Authorization remains entirely with the issuing maintainer's local approval, team role, and profile policy. A valid request only reduces transcription errors and gives the issuer confidence that the descriptor and requested metadata were generated by one local Locket identity.
- A later same-host coordination path may add an authenticated Unix-socket or named-pipe exchange between local agents owned by the same OS user. That path can move the same signed setup request and sealed invite blocks without clipboard steps, but it must still surface a local approval prompt before any secret-bearing team invite is created or accepted.
- No mode may grant secrets, import profile keys, register a durable automation client, or accept a team invite without explicit local user approval and the existing user-verification policy where configured. Unattended agent-to-agent bootstrap is out of scope for v1 because local agent authentication proves process identity, not project authorization or human intent.

`ResolveReference`, `PrepareExec`, and `ScanKnownValues` must enforce deprecated-version grace windows consistently. A deprecated version with a future `grace_until` may be resolved only through an explicit pinned `lk://...@vN` reference or scan matching path. It is never selected by unpinned secret resolution. Expired, ungraced, purged, or deleted versions return typed metadata-only failures without exposing values.
