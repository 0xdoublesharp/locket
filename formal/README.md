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

| Model | Checked behavior | Rust counterpart |
| --- | --- | --- |
| [AgentUnlockGrantLifecycle](tla/AgentUnlockGrantLifecycle.tla) | Project and native-session lock, cache expiry, grant revocation and scope, IDE session registration and use, and bounded challenge issuance and single-use authentication. | [Unlock cache](../crates/locket-agent/src/state/unlock_cache.rs), [grants](../crates/locket-agent/src/state/grant.rs), [session lock](../crates/locket-agent/src/state/session_lock.rs), [server transitions](../crates/locket-agent/src/transport/server.rs), [IDE sessions](../crates/locket-agent/src/state/ide_env_session.rs), [auth handler](../crates/locket-agent/src/handlers/auth.rs), and [persistent replay table](../crates/locket-store/src/access/runtime_session.rs). |
| [SecretLifecycleAuditChain](tla/SecretLifecycleAuditChain.tla) | One current version per active source, permanent purge and tombstones, source-first version selection, atomic audited mutation, and authenticated checkpoints that preserve earlier anchors. | [Store lifecycle](../crates/locket-store/src/secret/lifecycle.rs), [CLI purge guard](../crates/locket-cli/src/commands/secrets/lifecycle.rs), [reference resolver](../crates/locket-agent/src/handlers/resolve.rs), and [audit writer and verifier](../crates/locket-store/src/auditing/audit.rs). |

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

## Lean proofs

| Module | Results and correspondence |
| --- | --- |
| [AclMatching](lean/LocketProofs/AclMatching.lean) | `argvMatchDP_eq_spec` proves the table matcher implements existential suffix matching for every pattern and argument vector, with the single-token predicate supplied as a parameter. The three `pathMatch_rejects_*` theorems prove rejection of parent, root, and prefix components. `empty_policy_denies_all` and `least_privilege_monotonicity` cover the command secret allowlist and conjunctive ACL gates. Empty per-dimension ACL lists remain unconstrained. See [secret_acl.rs](../crates/locket-core/src/policy/secret_acl.rs) and [document.rs](../crates/locket-core/src/policy/document.rs). |
| [SourcePrecedence](lean/LocketProofs/SourcePrecedence.lean) | The `precedence_*` theorems prove strict total ordering. `selectWinner_iff`, `winner_unique`, and `resolveSecret_permutation` prove winner uniqueness and input-order independence under the SQL source uniqueness constraint. The source and version theorems cover shadowing, tombstones, current-only unpinned resolution, strict pinned grace, and purged versions. See [resolve.rs](../crates/locket-agent/src/handlers/resolve.rs) and [schema.rs](../crates/locket-store/src/database/schema.rs). |
| [AuditChain](lean/LocketProofs/AuditChain.lean) | `verifyChain_implies_consecutive_seq` proves sequence and predecessor linkage. `checkpoint_commits_to_prefix` and `tamper_detection` prove rejection of changed rows through the anchor and truncation below it. `key_separation_rejects_master_key` proves that verification with the audit key rejects a row signed with a distinct master key. See [audit.rs](../crates/locket-store/src/auditing/audit.rs) and the [audit specification](../docs/specs/audit.md). |

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
