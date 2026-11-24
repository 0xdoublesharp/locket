# Locket formal verification

Run from the repository root.

```sh
./scripts/formal-check.sh
```

The runner uses an installed JVM, the TLC jar, and the Lean version pinned in
[lean-toolchain](lean/lean-toolchain). Set `JAVA` or `TLA2TOOLS_JAR` to override
JVM or jar discovery. The default jar path is
`~/.local/share/tla2tools/tla2tools.jar`. The runner finds Lake on `PATH` or under
`~/.elan/bin`. The Lean package builds offline once the pinned toolchain is
installed and uses only the bundled standard library.

TLC state, Java temporary files, and the Lake build go into a disposable
directory under `/Volumes/Scratch/locket/tmp`. The runner builds a Scratch copy
of the Lean package, checks the original Lean sources for forbidden proof
declarations and placeholders, and treats Lean warnings as build failures.

## TLA+ models

| Model | Generated states | Distinct states | Checked behavior | Rust counterpart |
| --- | ---: | ---: | --- | --- |
| [AgentUnlockGrantLifecycle](tla/AgentUnlockGrantLifecycle.tla) | 2,901,926 | 33,039 | Project and native-session lock, cache expiry, grant revocation and scope, IDE session registration and use, and bounded challenge issuance and single-use authentication. | [Unlock cache](../crates/locket-agent/src/state/unlock_cache.rs), [grants](../crates/locket-agent/src/state/grant.rs), [session lock](../crates/locket-agent/src/state/session_lock.rs), [server transitions](../crates/locket-agent/src/transport/server.rs), [IDE sessions](../crates/locket-agent/src/state/ide_env_session.rs), [auth handler](../crates/locket-agent/src/handlers/auth.rs), and [persistent replay table](../crates/locket-store/src/access/runtime_session.rs). |
| [SecretLifecycleAuditChain](tla/SecretLifecycleAuditChain.tla) | 245,530 | 33,714 | One current version per active source, permanent purge and tombstones, source-first version selection, atomic audited mutation, and authenticated checkpoints that preserve earlier anchors. | [Store lifecycle](../crates/locket-store/src/secret/lifecycle.rs), [CLI purge guard](../crates/locket-cli/src/commands/secrets/lifecycle.rs), [reference resolver](../crates/locket-agent/src/handlers/resolve.rs), and [audit writer and verifier](../crates/locket-store/src/auditing/audit.rs). |
| [EgressProxyAndRedaction](tla/EgressProxyAndRedaction.tla) | 168,413 | 64,181 | Proxy authentication and stripping, request framing and authority agreement, strict CONNECT policy, screened DNS addresses despite rebinding, host-scoped substitution, and split-independent response and redirect redaction. | [Proxy](../crates/locket-exec/src/egress_proxy.rs), [destination policy](../crates/locket-exec/src/egress_proxy/destination.rs), [HTTP forwarding](../crates/locket-exec/src/egress_proxy/http.rs), [substitution](../crates/locket-exec/src/egress_proxy/substitution.rs), [wire framing](../crates/locket-exec/src/egress_proxy/wire.rs), and [streaming redaction](../crates/locket-exec/src/streaming_redactor.rs). |
| [TeamSyncAndAuditWitness](tla/TeamSyncAndAuditWitness.tla) | 591,284 | 19,929 | Owner-authorized membership changes, revocation and profile key rotation, stale publication drafts, recipient reconciliation, ordered witness receipts, persistence, and rollback detection at restart. | [Agent handler](../crates/locket-agent/src/handlers/team_sync.rs), [snapshot publishing and application](../crates/locket-agent/src/team_sync/snapshot.rs), [team package format](../crates/locket-core/src/formats/team_package.rs), [receipt format](../crates/locket-core/src/formats/audit_witness.rs), and [witness store](../crates/locket-store/src/auditing/witness.rs). |

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

## Lean proofs

| Module | Public theorems | All theorems | Results and correspondence |
| --- | ---: | ---: | --- |
| [AclMatching](lean/LocketProofs/AclMatching.lean) | 6 | 13 | `argvMatchDP_eq_spec` proves the table matcher implements existential suffix matching for every pattern and argument vector, with the single-token predicate supplied as a parameter. The three `pathMatch_rejects_*` theorems prove rejection of parent, root, and prefix components. `empty_policy_denies_all` and `least_privilege_monotonicity` cover the command secret allowlist and conjunctive ACL gates. Empty per-dimension ACL lists remain unconstrained. See [secret_acl.rs](../crates/locket-core/src/policy/secret_acl.rs) and [document.rs](../crates/locket-core/src/policy/document.rs). |
| [SourcePrecedence](lean/LocketProofs/SourcePrecedence.lean) | 14 | 15 | The `precedence_*` theorems prove strict total ordering. `selectWinner_iff`, `winner_unique`, and `resolveSecret_permutation` prove winner uniqueness and input-order independence under the SQL source uniqueness constraint. The source and version theorems cover shadowing, tombstones, current-only unpinned resolution, strict pinned grace, and purged versions. See [resolve.rs](../crates/locket-agent/src/handlers/resolve.rs) and [schema.rs](../crates/locket-store/src/database/schema.rs). |
| [AuditChain](lean/LocketProofs/AuditChain.lean) | 4 | 7 | `verifyChain_implies_consecutive_seq` proves sequence and predecessor linkage. `checkpoint_commits_to_prefix` and `tamper_detection` prove rejection of changed rows through the anchor and truncation below it. `key_separation_rejects_master_key` proves that verification with the audit key rejects a row signed with a distinct master key. See [audit.rs](../crates/locket-store/src/auditing/audit.rs) and the [audit specification](../docs/specs/audit.md). |
| [EnvIsolation](lean/LocketProofs/EnvIsolation.lean) | 5 | 7 | Strict and minimal parent selection, conflict rejection, Locket precedence, and first-delimiter parsing of validated env-file lines. The model uses the Rust mode names `strict`, `minimal`, `merge`, and `passthrough`, and the override names `locket`, `preserve`, and `error`. See [environment merge](../crates/locket-core/src/configuration/env.rs), [execution](../crates/locket-exec/src/lib.rs), and [env-file validation and writing](../crates/locket-exec/src/ephemeral_env_file.rs). |
| [StreamingRedaction](lean/LocketProofs/StreamingRedaction.lean) | 4 | 14 | One nonempty byte pattern, overlapping matches, and a fixed replacement. Feeding any partition and flushing gives the exact one-shot output, and clean bytes round-trip unchanged. A single replacement byte absent from the pattern cannot recreate it. See [streaming redaction](../crates/locket-exec/src/streaming_redactor.rs). |
| [EgressPolicy](lean/LocketProofs/EgressPolicy.lean) | 5 | 5 | Wildcards exclude the apex and require a label separator, empty allowlists deny all, canonical Host and target authorities must agree, and default IPv4 rules block loopback, link-local, and RFC1918 addresses. Hostnames and effective ports are modeled after parsing. See [destination policy](../crates/locket-exec/src/egress_proxy/destination.rs) and [proxy entry point](../crates/locket-exec/src/egress_proxy.rs). |
| [AuditWitness](lean/LocketProofs/AuditWitness.lean) | 5 | 6 | Project binding, strictly increasing sequence numbers, chain-wide nonce uniqueness, receipt-history commitment under hash injectivity, and rejection of a local tip below the anchor. Signature unforgeability relates a verified receipt to issuance by the pinned key. See [receipt verification](../crates/locket-core/src/formats/audit_witness.rs) and [receipt persistence](../crates/locket-store/src/auditing/witness.rs). |

The audit theorems take `MacInjective` as an explicit idealized hypothesis.
A checkpoint at the original tip protects the whole original history. Rows
after the retained anchor require a newer independently retained checkpoint
for the same rollback guarantee.

## Rust findings and model boundaries

- **Unbounded challenge map.** `handle_client_hello` inserts every issued
  challenge. Expiry is checked only after a challenge is removed during
  authentication. Unredeemed challenges can accumulate beyond their freshness
  window. The model checks the intended prune-and-cap behavior.
  [Auth handler](../crates/locket-agent/src/handlers/auth.rs)
- **Audit key separation.** Automation authentication and IDE registration
  pass cached master-key bytes directly to the audit writer. Reference
  resolution instead unwraps the project audit key. Mixing those rows can
  make verification fail at the first row signed with the wrong key.
  [Auth handler](../crates/locket-agent/src/handlers/auth.rs),
  [IDE sessions](../crates/locket-agent/src/state/ide_env_session.rs),
  [cache population](../crates/locket-agent/src/transport/server.rs), and
  [reference audit](../crates/locket-agent/src/handlers/resolve.rs)
- **Grant and IDE authorization boundaries.** The CLI prompts for dangerous
  profiles. The raw `RequestGrant` handler checks the native-session gate and
  issues a scoped grant without checking the danger flag, confirmation, or
  project unlock. The model requires those conditions at issuance. The IDE
  registry holds project-scoped names and TTLs, with no profile field or
  lock-time eviction. A live IDE session lookup can therefore return metadata
  after lock. Vault resolution still requires its own live key and grant
  checks.
  [CLI run](../crates/locket-cli/src/commands/exec/run.rs),
  [grant handler](../crates/locket-agent/src/transport/server.rs),
  [IDE sessions](../crates/locket-agent/src/state/ide_env_session.rs), and
  [reference resolver](../crates/locket-agent/src/handlers/resolve.rs)
- **ACL matcher behavior.** Rust's recursive argv matcher can revisit the same
  pattern and argument suffixes when several `**` tokens precede an
  unsuccessful match. The proved table evaluates each pair once. Rust's
  `slash_path` discards forbidden components, so its caller's canonicalization
  and project-relative check matter. The Lean matcher rejects such components
  directly. The per-token Rust glob also tests byte equality before recording
  a wildcard, so an input token beginning with a literal star can consume
  that wildcard as a literal and cause a false denial.
  [Secret ACL matcher](../crates/locket-core/src/policy/secret_acl.rs) and
  [canonical path check](../crates/locket-agent/src/handlers/resolve.rs)
- **Lifecycle caller obligations.** The store allows an omitted audit context
  and leaves the active-current purge guard to the CLI. The lifecycle model
  covers audited mutations through the guarded entry points.
  [Store lifecycle](../crates/locket-store/src/secret/lifecycle.rs) and
  [CLI purge guard](../crates/locket-cli/src/commands/secrets/lifecycle.rs)

- **Redaction can recreate a matched pattern.** The Rust redactor clears the
  replacement when it contains any registered pattern. Removing a match can
  then join two retained byte spans into another occurrence. The proxy uses
  this same redactor on response header values and decoded response bodies.
  The output theorem requires a disjoint marker. Chunk equivalence holds for
  arbitrary fixed replacements in the single-pattern Lean model.
  [Streaming redactor](../crates/locket-exec/src/streaming_redactor.rs) and
  [response forwarding](../crates/locket-exec/src/egress_proxy/http.rs)
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
