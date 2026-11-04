# Scan, Redaction & AI Safety

This file is part of the normative Locket v1 specification. Start at [index.md](index.md).

## Scan & AI-Leak Protection

Secret fingerprinting:

```text
HMAC-SHA256(profile_fingerprint_key, secret_value)
```

Store keyed fingerprints for equality checks without storing plaintext or reusable raw hashes.

`locket scan` must detect:

- Known secret values by decrypting active versions, deleted-source current versions that still have blobs, and deprecated versions still within grace TTL in memory for the duration of the scan. Purged versions are excluded because their blobs and fingerprints have been destroyed.
- High-entropy strings.
- `.env` and `.env.*` files.
- Common provider token formats.
- Logs or generated artifacts containing known secret values.
- Staged Git content through `locket scan --staged`.

Default high-entropy rule: flag printable non-whitespace tokens of at least 20 characters with Shannon entropy `>= 4.5` bits per character, excluding obvious UUIDs, hashes already recognized as checksums, and documented public identifiers. Projects may override the minimum token length and entropy threshold in `locket.toml`; `locket policy doctor` must report non-default scanner thresholds.

Scanning cannot detect arbitrary transformed secrets from stored HMAC fingerprints alone. Exact known-value scanning requires temporary in-memory decryption, followed by zeroization.

Locked-vault behavior: pattern, entropy, and `.env` detection run without unlock because they need no key material. Known-value detection requires unwrapped keys and is skipped with an explicit metadata-only notice when the vault is locked. `locket scan --require-known` fails closed with `UnlockRequired` when the vault is locked, so CI/pre-commit flows that depend on known-value coverage cannot accidentally pass with reduced coverage.

`locket scan --staged` requires a Git worktree. If no `.git` directory or Git worktree marker is found in any ancestor of the project root/current directory, the command fails with `ConfigError` and exit code `64`; it must not silently fall back to scanning the working tree or current directory.

`locket redact` requires unlock for known-value redaction. When the vault is locked, it falls back to pattern and entropy redaction only and prints a metadata-only warning that known-value redaction was skipped. `locket redact --require-known` fails with `UnlockRequired` when the vault is locked.

`locket redact file.log` must replace known values with semantic labels:

```text
lk_redacted_OPENAI_API_KEY
lk_redacted_DATABASE_URL
```

When `privacy.redact_names = true` or `--redact-names` is provided, redaction labels must use privacy aliases instead of secret names, for example `lk_redacted_secret-a1b2c3d4`. Known-secret matches use the deterministic alias rules from [invariants.md](invariants.md). Pattern-only matches that cannot be tied to a known secret id use operation-local labels such as `lk_redacted_PATTERN_1`; v1 does not persist redaction alias maps.

`locket redact --stdin` must support streaming log redaction:

```bash
some-command | locket redact --stdin
```

Redaction is UTF-8 segment based. For file or stream input containing invalid UTF-8, Locket passes the non-UTF-8 byte segment through unchanged, emits a metadata-only warning, and continues scanning/redacting valid UTF-8 segments around it. `--require-known` applies only to UTF-8 segments where known-value matching can run; binary segments are never redacted and never cause the command to fail by themselves. This behavior must be explicit in CLI output so users do not mistake binary pass-through for complete redaction coverage.

Scanner severity:

- Known-secret match: blocking by default.
- Provider-token pattern: warning by default unless configured as blocking.
- High entropy: warning by default.
- `.env` file: warning or blocking according to project policy.
- Suppressed finding: metadata-only audit event with path, rule id, and reason, never the matched value. See [Inline Suppressions](#inline-suppressions) for the directive syntax that promotes a finding into this category.

`locket context` must output AI-safe context only:

```text
Project: my-app
Profile: dev
Secrets referenced:
- DATABASE_URL
- OPENAI_API_KEY
No secret values included.
```

`locket context` is metadata-only and may run while the vault is locked. It reads project/profile/policy/secret-name metadata but must not decrypt values or require an agent. If metadata is unavailable because the store cannot be opened, it fails with the normal storage/project error. `locket context --redact-names` and `privacy.redact_names = true` replace project, profile, and secret names with stable local aliases for AI prompts where names themselves are sensitive.

`locket ai-safe -- <cmd>` captures command output, redacts known secrets, and emits AI-safe logs. By default it requires known-value redaction coverage before running the child command; if the vault is locked or unavailable, it fails closed with `UnlockRequired` before spawning. `locket ai-safe --pattern-only -- <cmd>` may run in a degraded locked-vault mode that uses provider-token and high-entropy rules only, and must print a clear warning before executing.

`locket ai-safe -- <cmd>` captures both stdout and stderr, redacts line-by-line, writes redacted stdout to stdout, writes redacted stderr to stderr, forwards the child exit code unchanged, preserves stream ordering where practical, and warns when output contains unterminated partial lines that may delay redaction until a newline or buffer flush. Implementations must cap the in-memory partial-line buffer; when the 64 KiB cap is reached, the entire line is replaced with `lk_redacted_BUFFER_LIMIT` and a warning is emitted. The rest of that line is discarded until a newline, then normal redaction resumes. This prevents buffer boundaries from exposing secret fragments or splitting UTF-8 characters, and keeps memory bounded even when a known value is longer than the cap. Known-value and pattern counts cover detections in buffered content before suppression; discarded continuation bytes do not produce detection counts. `--output <file>` additionally writes a combined redacted transcript with stream labels and timestamps; the transcript must never contain unredacted values. The output file is created with user-only permissions (0600) before writing begins; if the file already exists, Locket fails with an error rather than overwriting without explicit `--force` confirmation.

`locket ai-safe` writes a `REDACT` audit row when project context is available. Metadata includes child `argv0`, argument count, output destinations, whether `--pattern-only` was used, whether known-value coverage was active, redaction counts by rule, and exact known secret names redacted from output. Audit metadata never stores privacy aliases; aliases are applied only when rendering audit output or redacted transcripts. It never records child output or secret values.

For streaming output, every nonempty line of a known multiline value is redacted independently. This also removes standalone occurrences of those lines, so line boundaries cannot expose pieces of a credential.

## Inline Suppressions

Findings can be suppressed in source via inline directives. Three forms:

- **Line-level**: `# locket-suppress: <reason>` on the same line as the
  finding. Suppresses that line only.
- **Block-level**: `# locket-suppress-block-start: <reason>` ... `# locket-suppress-block-end`.
  Suppresses every finding between the markers.
- **File-level**: `# locket-suppress-file: <reason>` on the first 5
  lines of the file. Suppresses the whole file.

The `<reason>` is required and audited. Reasons must be 4-200 chars,
plain text. Empty or missing reasons fail the scan with `ConfigError`.

Suppressions are language-agnostic: comment syntax differs per
language but the directive text after the comment marker is the same.
The scanner must accept `# locket-suppress: ...`, `// locket-suppress: ...`,
`-- locket-suppress: ...`, `<!-- locket-suppress: ... -->` (HTML),
and the equivalent block forms.

Each suppressed finding writes a `SCAN` audit row with
`status: "SUPPRESSED"`, the finding's rule id, the suppression reason,
and the path. Values are NEVER serialized.
