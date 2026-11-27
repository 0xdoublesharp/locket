# Locket formal verification

Run from the repository root.

```sh
./scripts/formal-check.sh
./scripts/formal-trace-check.sh
```

The runner uses an installed JVM, the TLC jar, and the Lean version pinned in
[lean-toolchain](lean/lean-toolchain). Set `JAVA` or `TLA2TOOLS_JAR` to override
JVM or jar discovery. The default jar path is
`~/.local/share/tla2tools/tla2tools.jar`. The runner finds Lake on `PATH` or under
`~/.elan/bin`. The Lean package builds offline once the pinned toolchain is
installed and uses only the bundled standard library.

`./scripts/formal-trace-check.sh` runs live Rust tests in
[tla_trace_conformance.rs](../crates/locket-agent/tests/tla_trace_conformance.rs)
to emit concrete transition traces and replays observations against all eleven
models. The runner builds the CLI offline for the Unix process-level tests and
uses Python 3 to locate the built executable.
The negative canary removes the audit row from a real secret mutation and
requires TLC to reject the first transition.

| Trace model | Observed behavior |
| --- | --- |
| AgentUnlockGrantLifecycle | Project unlock, grant scope and revocation, expiry, and native session lock. |
| AgentAuthzProtocol | Verified unlock, dangerous-profile confirmation, audit rollback, and grant cleanup on lock. |
| AutomationClientAuth | Verified registration, signed prepare, invalid signature rejection, persistent nonce replay rejection, and revocation. |
| SecretLifecycleAuditChain | Audited writes, rotation, source and version selection, purge, and tombstones. |
| EgressProxyAndRedaction | The live broker rejects both a request without credentials and an authenticated request to a screened loopback destination. |
| TeamSyncAndAuditWitness | Signed team publications, recipient updates, and audit witness persistence. |
| BackupAndRecoveryLifecycle | Bundle export and import with audit and rollback observations. |
| SharedVaultIsolation | Independent unlock and lock state, and confirmed cross-vault secret copies. |
| SharedSecretLinks | Live link and usage RPCs, dual-vault reads, stale and locked-consumer deletion refusals, atomic cascade with consumer audits, and signed Team Sync export isolation. |
| AgentDaemonLifecycle | A competing worker fails while the primary PID and socket remain live. The primary removes its endpoint on shutdown. |
| McpAndDesktopBoundary | MCP env-file inspection returns a key name from a regular file and refuses an out-of-root symlink. |

`./scripts/kani-check.sh` runs bounded checks of crypto framing, single-bit
tag corruption on a fixed fixture, name and URI parsing, and ACL matching.
`./scripts/miri-check.sh` interprets the crypto, core, and scanner tests on
nightly. Both runners skip when their verifier is absent. Set `STRICT=1` to
make a missing verifier fail.

TLC state, Java temporary files, and the Lake build go into a disposable
directory under `/Volumes/Scratch/locket/tmp`. The runner builds a Scratch copy
of the Lean package, checks the original Lean sources for forbidden proof
declarations and placeholders, and treats TLC and Lean warnings as failures.

## TLA+ models

| Model | Generated states | Distinct states | Checked behavior | Rust counterpart |
| --- | ---: | ---: | --- | --- |
| [AgentUnlockGrantLifecycle](tla/AgentUnlockGrantLifecycle.tla) | 2,901,926 | 33,039 | Project and native-session lock, cache expiry, grant revocation and scope, IDE session registration and use, and bounded challenge issuance and single-use authentication. | [Unlock cache](../crates/locket-agent/src/state/unlock_cache.rs), [grants](../crates/locket-agent/src/state/grant.rs), [session lock](../crates/locket-agent/src/state/session_lock.rs), [server transitions](../crates/locket-agent/src/transport/server.rs), [IDE sessions](../crates/locket-agent/src/state/ide_env_session.rs), [auth handler](../crates/locket-agent/src/handlers/auth.rs), and [persistent replay table](../crates/locket-store/src/access/runtime_session.rs). |
| [AgentAuthzProtocol](tla/AgentAuthzProtocol.tla) | 56,899 | 2,237 | Same-UID principals, split user verification, dangerous-profile confirmation, grant rollback, policy scope, and PID reuse. | [Dispatch and grant issuance](../crates/locket-agent/src/transport/server.rs), [grant binding](../crates/locket-agent/src/state/grant.rs), [PrepareExec](../crates/locket-agent/src/handlers/prepare_exec.rs), and [ResolveReference](../crates/locket-agent/src/handlers/resolve.rs). |
| [AutomationClientAuth](tla/AutomationClientAuth.tla) | 4,711,239 | 37,626 | Verified registration, bounded challenges, signed scope and freshness, revocation during authentication, and persistent nonce and audit transactions. | [Authentication](../crates/locket-agent/src/handlers/auth.rs), [client registry](../crates/locket-agent/src/handlers/clients.rs), and [storage transaction](../crates/locket-store/src/access/runtime_session.rs). |
| [SecretLifecycleAuditChain](tla/SecretLifecycleAuditChain.tla) | 245,530 | 33,714 | One current version per active source, permanent purge and tombstones, source-first version selection, atomic audited mutation, and authenticated checkpoints that preserve earlier anchors. | [Store lifecycle](../crates/locket-store/src/secret/lifecycle.rs), [CLI purge guard](../crates/locket-cli/src/commands/secrets/lifecycle.rs), [reference resolver](../crates/locket-agent/src/handlers/resolve.rs), and [audit writer and verifier](../crates/locket-store/src/auditing/audit.rs). |
| [EgressProxyAndRedaction](tla/EgressProxyAndRedaction.tla) | 168,413 | 64,181 | Proxy authentication and stripping, request framing and authority agreement, strict CONNECT policy, screened DNS addresses despite rebinding, host-scoped substitution, and split-independent response and redirect redaction. | [Proxy](../crates/locket-exec/src/egress_proxy.rs), [destination policy](../crates/locket-exec/src/egress_proxy/destination.rs), [HTTP forwarding](../crates/locket-exec/src/egress_proxy/http.rs), [substitution](../crates/locket-exec/src/egress_proxy/substitution.rs), [wire framing](../crates/locket-exec/src/egress_proxy/wire.rs), and [streaming redaction](../crates/locket-exec/src/streaming_redactor.rs). |
| [TeamSyncAndAuditWitness](tla/TeamSyncAndAuditWitness.tla) | 595,429 | 21,133 | Owner-authorized membership changes, monotonic removal preservation (no silent reinstatement), revocation and profile key rotation, stale publication drafts, recipient reconciliation, ordered witness receipts, persistence, and rollback detection at restart. | [Agent handler](../crates/locket-agent/src/handlers/team_sync.rs), [snapshot publishing and application](../crates/locket-agent/src/team_sync/snapshot.rs), [team package format](../crates/locket-core/src/formats/team_package.rs), [receipt format](../crates/locket-core/src/formats/audit_witness.rs), and [witness store](../crates/locket-store/src/auditing/witness.rs). |
| [BackupAndRecoveryLifecycle](tla/BackupAndRecoveryLifecycle.tla) | 1,275,398 | 228,600 | Audit-first bundle export, signed vs. unsigned bundle import, dangerous-profile confirmation, atomic config-and-profile rollback, and recovery rotation/restore key continuity across store, keychain, and filesystem faults. | [Backup handler](../crates/locket-agent/src/handlers/backup.rs), [config handler](../crates/locket-agent/src/handlers/config.rs), and [recovery CLI](../crates/locket-cli/src/commands/vault/recovery.rs). |
| [SharedVaultIsolation](tla/SharedVaultIsolation.tla) | 301,244 | 8,200 | Multi-project and Global Vault (`@shared`) lock isolation, fail-closed dual-vault `locket run`/`exec`, atomic `CopySecretToShared` overwrite and dangerous-profile gates, and Docker/Compose rejection of `shared_secrets`. | [Desktop CRUD](../crates/locket-agent/src/handlers/desktop_crud.rs), [run](../crates/locket-cli/src/commands/exec/run.rs), [exec](../crates/locket-cli/src/commands/exec/exec.rs), and [docker](../crates/locket-cli/src/commands/exec/docker.rs). |
| [SharedSecretLinks](tla/SharedSecretLinks.tla) | 759,296 | 47,496 | Dual-vault linked reads, reviewed unlink-all authorization, dangerous-profile gates, atomic unlink audits, and exclusion of links and local dedup tags from Team Sync. | [Link usage RPC](../crates/locket-agent/src/handlers/shared_links.rs), [deletion handler](../crates/locket-agent/src/handlers/desktop_crud.rs), [store transaction](../crates/locket-store/src/secret/links.rs), and [Team Sync snapshot](../crates/locket-agent/src/team_sync/snapshot.rs). |
| [AgentDaemonLifecycle](tla/AgentDaemonLifecycle.tla) | 24,673 | 5,332 | Concurrent agent startup/shutdown, live PID/socket preservation against racing secondary workers, UID-checked stale-socket cleanup, terminal status-stream error disposal, and bounded-queue cancellation liveness under weak fairness. | [Agent lifecycle CLI](../crates/locket-cli/src/commands/agent.rs) and [desktop agent client](../crates/locket-app/src-tauri/src/agent_client.rs). |
| [McpAndDesktopBoundary](tla/McpAndDesktopBoundary.tla) | 55,561 | 5,033 | Trusted-root and checked-handle (`O_NOFOLLOW`) reads against concurrent symlink TOCTOU, zero-plaintext MCP/IPC metadata boundary, transactional dangerous-profile overwrite confirmation, and privacy-mode name hiding. | [MCP server](../crates/locket-cli/src/commands/mcp.rs), [dotenv discovery](../crates/locket-cli/src/commands/secrets/env_files.rs), and [dotenv import](../crates/locket-cli/src/commands/secrets/import.rs). |

The [agent configuration](tla/AgentUnlockGrantLifecycle.cfg) covers two projects,
two profiles, two representative actions, two clients, and two single-use
challenge identities. It tracks one representative grant and IDE session
and uses project, client, and nonce symmetry. Within the two-tick horizon,
deadlines beyond the last tick are equivalent. Lock and expiry are modeled as
atomic authorization transitions. Process and execution binding, client
policy, and signature verification are represented by their outcomes. A
`PrepareExec` grant can satisfy a scoped `ResolveReference` request. At the
freshness boundary the challenge is still valid. The model assumes fresh
challenge identities and retains replay markers throughout its horizon.

The [authorization configuration](tla/AgentAuthzProtocol.cfg) fixes daemon
verification on and explores one project, one live grant at a time, two
profiles, and two policies. Three principal types share a UID. A reconnecting
local process can acquire the human process's PID with a different start-time
token. Verification can finish or fail after a lock, idle expiry, or native
session lock. The model invalidates unfinished ceremonies at those transitions.
`PrepareExec` and policy-scoped `ResolveReference` grants bind the policy.
The model uses one observed process binding for resolution and abstracts
store pinning, policy ACLs, and child-process handoff. Signature validity is
a Boolean outcome. The automation model checks authentication separately.

The [automation configuration](tla/AutomationClientAuth.cfg) uses one registered
key, an unrelated client identity, two challenge IDs, two nonce values, a
one-entry challenge pool, and a two-tick clock with one-tick inclusive
freshness. Challenge IDs and nonce values are symmetric. Deliberate nonce
reuse exercises durable replay checks after challenge rotation and restart.
The horizon lies within nonce retention. Signature validity is symbolic.
Authentication is split before the durable write so revocation can occur
between verification and commit. Database and audit failure leave the
nonce table, `last_used_at`, and grant issuance unchanged. The model uses
one in-flight signed request and abstracts subsequent dispatch as a grant
outcome for `PrepareExec`.

The [lifecycle configuration](tla/SecretLifecycleAuditChain.cfg) covers all three
sources for one project, profile, and name, up to three versions per source,
two ticks, and four audit rows. Grace is strict at the deadline. Explicit
source selection and unqualified precedence both select a source before trying
the version. A missing or expired pin at that source fails resolution. A
tombstone may retain a pointer to its former current version after that
version is purged. The version has state `purged`, and the source is ineligible
for resolution. Audit tags are symbolic tuples, and the model treats a
successful secret mutation and its audit row as one transaction. It replays
the authenticated event metadata to check consistency with current secret state.

The [egress configuration](tla/EgressProxyAndRedaction.cfg) checks three host
classes and every subset of four address classes. The link-local metadata class
includes `169.254.169.254`. An exact rule can authorize loopback when the
override is enabled. Public DNS answers can change after screening, but
connection uses the saved addresses. The response model covers every body up
to six bytes over a two-byte alphabet, every nonempty chunk partition, a
redirect-header echo, and two overlapping patterns of lengths two and three.
The replacement and modeled header boundary are disjoint from the pattern
alphabet. HTTP parsing, credential recognition, and the origin of broker-held
secrets are abstracted to representative outcomes. CONNECT is opaque after
authorization. Its tunnel payload is outside the redaction guarantee.

The [team and witness configuration](tla/TeamSyncAndAuditWitness.cfg) explores
the independent team and witness protocols as two scenarios. The team scenario
has a pinned owner, two recipient identities, one shared profile, and up to two
publications per recipient. The profile key epoch changes on revocation, while
the per-recipient package version advances on each publication. The modeled
administrator is the pinned owner of authenticated sync. CLI invite and
metadata-only operations have their own role rules. Publication
rechecks the roster, key epoch, and predecessor. Recipients can reconcile older
already-published snapshots without gaining a newer key. The witness scenario
has four local audit rows, three distinct nonce values, and an independently
retained external chain. It models the window between receipt issuance and
local persistence, restored local receipts, and shortened or changed audit
prefixes. Ed25519 verification and SHA-256 digests are symbolic. Restart
verification assumes access to the trusted external head and authenticated local prefix.

The [shared links configuration](tla/SharedSecretLinks.cfg) models one Global
Vault secret, one alias per consumer, and up to two unlinks per consumer.
The review stores link identities, so deleting and recreating the same alias
makes an earlier review stale. The cascade models the Desktop flow that submits
the reviewed IDs with `unlink_all`. The linked read abstracts the dual-vault
gate shared by reveal, run, and Docker resolution.

## Lean proofs

The Lean package builds twelve proof modules.

| Module | Public theorems | All theorems | Results and correspondence |
| --- | ---: | ---: | --- |
| [AclMatching](lean/LocketProofs/AclMatching.lean) | 6 | 13 | `argvMatchDP_eq_spec` proves the table matcher implements existential suffix matching for every pattern and argument vector, with the single-token predicate supplied as a parameter. The three `pathMatch_rejects_*` theorems prove rejection of parent, root, and prefix components. `empty_policy_denies_all` and `least_privilege_monotonicity` cover the command secret allowlist and conjunctive ACL gates. Empty per-dimension ACL lists remain unconstrained. See [secret_acl.rs](../crates/locket-core/src/policy/secret_acl.rs) and [document.rs](../crates/locket-core/src/policy/document.rs). |
| [SourcePrecedence](lean/LocketProofs/SourcePrecedence.lean) | 17 | 18 | The `precedence_*` theorems prove the strict total order `team-managed < shared-link < user-local < machine-local`. Executable rank vectors check the Rust priorities. `selectWinner_iff`, `winner_unique`, and `resolveSecret_permutation` prove winner uniqueness and input-order independence under the SQL source uniqueness constraint. The source and version theorems cover shadowing, tombstones, current-only unpinned resolution, strict pinned grace, and purged versions. See [resolve.rs](../crates/locket-agent/src/handlers/resolve.rs) and [schema.rs](../crates/locket-store/src/database/schema.rs). |
| [AuditChain](lean/LocketProofs/AuditChain.lean) | 4 | 7 | `verifyChain_implies_consecutive_seq` proves sequence and predecessor linkage. `checkpoint_commits_to_prefix` and `tamper_detection` prove rejection of changed rows through the anchor and truncation below it. `key_separation_rejects_master_key` proves that verification with the audit key rejects a row signed with a distinct master key. See [audit.rs](../crates/locket-store/src/auditing/audit.rs) and the [audit specification](../docs/specs/audit.md). |
| [EnvIsolation](lean/LocketProofs/EnvIsolation.lean) | 5 | 7 | Strict and minimal parent selection, conflict rejection, Locket precedence, and first-delimiter parsing of validated env-file lines. The model uses the Rust mode names `strict`, `minimal`, `merge`, and `passthrough`, and the override names `locket`, `preserve`, and `error`. See [environment merge](../crates/locket-core/src/configuration/env.rs), [execution](../crates/locket-exec/src/lib.rs), and [env-file validation and writing](../crates/locket-exec/src/ephemeral_env_file.rs). |
| [StreamingRedaction](lean/LocketProofs/StreamingRedaction.lean) | 9 | 26 | The original single-pattern proofs cover holdback, overlapping matches, fixed markers, and clean-byte round trips. The multi-pattern proofs cover marker selection, splices, and chunk-independent output for arbitrary finite sets of nonempty patterns, including nested and overlapping matches. See [streaming redaction](../crates/locket-exec/src/streaming_redactor.rs). |
| [EgressPolicy](lean/LocketProofs/EgressPolicy.lean) | 14 | 15 | Wildcard boundaries, empty allowlists, and blocked IPv4 ranges. Parsed authority proofs cover ASCII case, trailing dots, bracketed IPv6, effective ports, and CONNECT/Host agreement. Substitution requires host and authority authorization. A validated secret and framing-safe retained bytes yield a value free of CR, LF, and NUL. See [destination policy](../crates/locket-exec/src/egress_proxy/destination.rs), [proxy entry point](../crates/locket-exec/src/egress_proxy.rs), and [HTTP forwarding](../crates/locket-exec/src/egress_proxy/http.rs). |
| [AuditWitness](lean/LocketProofs/AuditWitness.lean) | 5 | 6 | Project binding, strictly increasing sequence numbers, chain-wide nonce uniqueness, receipt-history commitment under hash injectivity, and rejection of a local tip below the anchor. Signature unforgeability relates a verified receipt to issuance by the pinned key. See [receipt verification](../crates/locket-core/src/formats/audit_witness.rs) and [receipt persistence](../crates/locket-store/src/auditing/witness.rs). |
| [CryptoDomainSeparation](lean/LocketProofs/CryptoDomainSeparation.lean) | 4 | 9 | Length-prefixed field framing injectivity, canonical secret AAD injectivity, domain separation, and strict 32-byte audit key-length enforcement. The domains include profile fingerprints and `LocalDedupTag` (`locket-local-dedup-v1`). Executable HMAC vectors check both Rust input prefixes. See [aad.rs](../crates/locket-crypto/src/aad.rs) and [lean_conformance.rs](../crates/locket-crypto/tests/lean_conformance.rs). |
| [PathScopeAndContract](lean/LocketProofs/PathScopeAndContract.lean) | 4 | 4 | Unique order-independent deepest monorepo path-scope selection, rejection of parent traversal, absolute paths, and prefix tricks, non-bypass of secret ACLs by public defaults, and fail-closed `shared_secrets` collisions. See [path_scope.rs](../crates/locket-core/src/policy/path_scope.rs) and [lean_conformance.rs](../crates/locket-core/tests/lean_conformance.rs). |
| [DotenvMetadataNonInterference](lean/LocketProofs/DotenvMetadataNonInterference.lean) | 4 | 7 | Value-replacement non-interference for `.env` key inspection and workspace shared-candidate scanning, `--only`/`--exclude` filter soundness, and exact dry-run vs. live-import partition equivalence. See [env_files.rs](../crates/locket-cli/src/commands/secrets/env_files.rs) and [formal_noninterference_conformance.rs](../crates/locket-cli/tests/formal_noninterference_conformance.rs). |
| [PrivacyModeNonInterference](lean/LocketProofs/PrivacyModeNonInterference.lean) | 4 | 9 | Kind-scoped canonical alias preimage injectivity, rendered alias injectivity under hash injectivity, and projection-first privacy non-interference preventing raw-name search oracles. See [privacy.rs](../crates/locket-core/src/configuration/privacy.rs) and [discovery.rs](../crates/locket-agent/src/handlers/discovery.rs). |
| [MigrationSafety](lean/LocketProofs/MigrationSafety.lean) | 15 | 19 | Replacing parsed dotenv values preserves the Compose interpolation overlap and warning decision, as well as the migrated, staged, and uninitialized project counts. Non-interactive policy mutations (`LOCKET_NO_PROMPT` or non-TTY stdin) leave the approved digest unchanged, so new or edited policies remain unapproved until an explicit interactive refresh. The verification gate requires an existing, approved policy to exit zero before the deadline with the vault unlocked. A timeout blocks archiving. Dry-run and live archive destination checks reject symlinks, non-directories, and unconfirmed Git ignore coverage inside worktrees regardless of Locket configuration. Secret-file protection uses tracked repository coverage or a successful local ignore write. Rule order keeps `.env.example`, `.env.sample`, and `.env.*.example` visible while ignoring other `.env.*` basenames. Batch preparation resolves every selector and caps the deduplicated plan at eight vaults before prompting. With one authorization for the batch, cancellation unlocks no vaults, and the authorization can unlock only the vaults on the plan. The per-vault authorization model attempts each vault at most once and stops at the first denial. See [policy authoring](../crates/locket-cli/src/commands/policy.rs), [dotenv import](../crates/locket-cli/src/commands/secrets/import.rs), [archive consumer detection](../crates/locket-cli/src/commands/secrets/consumers.rs), [workspace discovery](../crates/locket-cli/src/commands/secrets/env_files.rs), [secret-file ignore rules](../crates/locket-platform/src/storage/policy_file.rs), and [vault unlock](../crates/locket-cli/src/commands/vault/lock.rs). |

The migration model takes Git and filesystem observations, Compose key
references, policy execution outcomes, and authorization decisions as inputs.
The non-interference proofs replace values in parsed dotenv entries while keeping
workspace discovery and Compose references fixed.

The audit theorems take `MacInjective` as an explicit idealized hypothesis.
A checkpoint at the original tip protects the whole original history. Rows
after the retained anchor require a newer independently retained checkpoint
for the same rollback guarantee.

## Rust findings and model boundaries

- **Automation challenge capacity and audit keys.** `ClientHello` prunes
  stale challenges before enforcing its 1,024-entry limit. Automation
  authentication and IDE registration unwrap the project audit key before
  writing audit rows. Successful authentication records the nonce, usage
  timestamp, and audit row in one transaction. Only a duplicate nonce key
  is classified as replay.
  [Auth handler](../crates/locket-agent/src/handlers/auth.rs),
  [IDE sessions](../crates/locket-agent/src/state/ide_env_session.rs), and
  [auth transaction](../crates/locket-store/src/access/runtime_session.rs)
- **Commit-time revocation.** Both the automation model and Rust recheck
  `revoked_at IS NULL` inside the final authentication commit transaction,
  rolling back the nonce and audit write if a concurrent `RevokeClient`
  committed first. `RevokeClient` also wraps client revocation and its
  `CLIENT_REVOKE` audit row in one atomic transaction.
  [Auth handler](../crates/locket-agent/src/handlers/auth.rs),
  [client registry](../crates/locket-agent/src/handlers/clients.rs), and
  [auth transaction](../crates/locket-store/src/access/runtime_session.rs)
- **Grant and IDE authorization.** Secret-access grant issuance checks the
  cached unlock and dangerous-profile confirmation against the pinned store.
  With daemon verification enabled, it requires fresh local verification or
  approved signed automation. Verification audit failure revokes the new
  grant before releasing the grant-table lock. Explicit and native session
  locks now evict IDE sessions. IDE registrations remain project-scoped.
  [Grant and lock handlers](../crates/locket-agent/src/transport/server.rs),
  [PrepareExec](../crates/locket-agent/src/handlers/prepare_exec.rs), and
  [IDE sessions](../crates/locket-agent/src/state/ide_env_session.rs)
- **Lock ordering and process binding.** Explicit and native session locks
  serialize with unlock and grant ceremonies. Idle expiry can evict the old
  cached key during verification. Grant issuance rechecks the cache, while
  verified unlock can install a fresh entry after an old entry expires.
  The authorization model requires expiry to invalidate an ongoing unlock
  refresh as well. Both `RequestGrant` and direct `PrepareExec` record the
  peer connection ID and check the live process start token at issuance and on
  subsequent use, matching the model's PID-reuse protection.
  [Dispatch](../crates/locket-agent/src/transport/server.rs),
  [PrepareExec](../crates/locket-agent/src/handlers/prepare_exec.rs), and
  [grant binding](../crates/locket-agent/src/state/grant.rs)
- **ACL matcher behavior.** Rust uses a table for argv matching, rejects
  parent, root, and prefix path components, and gives the pattern wildcard
  precedence when a value contains a literal star. The argv theorem treats
  single-token matching as a parameter.
  [Secret ACL matcher](../crates/locket-core/src/policy/secret_acl.rs)
- **Lifecycle caller obligations.** The store allows an omitted audit context
  and leaves the active-current purge guard to the CLI. The lifecycle model
  covers audited mutations through the guarded entry points.
  [Store lifecycle](../crates/locket-store/src/secret/lifecycle.rs) and
  [CLI purge guard](../crates/locket-cli/src/commands/secrets/lifecycle.rs)
- **Redaction and secret framing.** Rust selects nonempty replacement
  markers, rejects containment in either direction, and checks both
  suffix/prefix overlaps. The byte fallback relies on registered patterns
  coming from strings and their encodings. The Lean scanner uses one safe
  marker for the entire output and covers known patterns. Label selection
  and the generic detector have separate paths. The broker rejects empty
  secrets and secrets containing CR, LF, or NUL before forwarding. Lean
  models parsed authority keys and a raw splice over framing-safe retained
  bytes. Textual IPv6 parsing and substitution encoders are outside the proof.
  [Streaming redactor](../crates/locket-exec/src/streaming_redactor.rs),
  [egress proxy](../crates/locket-exec/src/egress_proxy.rs), and
  [substitution](../crates/locket-exec/src/egress_proxy/substitution.rs)
- **HTTP output includes unscanned bytes.** Response status and framing bytes
  are generated locally, response header values are scanned independently, and
  CONNECT tunnels copy opaque bytes. Known-secret filtering over a response
  value does not establish a whole-wire guarantee for arbitrary secret bytes.
  [Response forwarding](../crates/locket-exec/src/egress_proxy/http.rs) and
  [CONNECT tunnel](../crates/locket-exec/src/egress_proxy.rs)
- **Strict environment isolation applies to the final command.** A declared
  Compose external source runs `docker compose config` with the supplied parent
  environment before merge. That helper sees parent variables that strict
  mode would exclude from the final command. The env-file proof covers the
  serializer's first-`=` grammar, while Docker-specific key checks and parsing
  are separate.
  [Compose source and final merge](../crates/locket-cli/src/commands/exec/run.rs)
  and [Docker injection](../crates/locket-docker/src/lib.rs)
- **Revocation protects new keys.** The owner rotates affected profile keys and
  excludes revoked recipients from new publications. Already distributed
  packages remain decryptable using a recipient's old device key. A signed
  snapshot from an established stream may also be accepted after its expiry
  when its predecessor matches, so receivers can catch up through older
  snapshots.
  [Snapshot rotation and reconciliation](../crates/locket-agent/src/team_sync/snapshot.rs)
  and [package verification](../crates/locket-core/src/formats/team_package.rs)
- **Witness verification needs an independent anchor.** The receipt parser
  compares a nonce with the immediate predecessor. Store insertion checks
  reuse across the project and verifies the receipt link, but it does not
  look up the claimed sequence or checkpoint HMAC in the local audit log.
  The local stored head alone cannot detect a restore that rolls back both
  audit rows and receipts. The modeled restart check requires the separately
  retained head and compares its checkpoint against the local prefix.
  [Receipt verification](../crates/locket-core/src/formats/audit_witness.rs)
  and [receipt persistence](../crates/locket-store/src/auditing/witness.rs)
