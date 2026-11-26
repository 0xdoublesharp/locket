# Describing Locket

Keep product copy consistent with the shipped workflow and its acceptance limits. The README and user guides should make the first successful run easy to find.

## The pitch

> Replace development `.env` files with an encrypted local vault. Approve which variables a command can receive, then run your app.

Locket keeps values encrypted on your machine and injects approved names into the process you start. Project configuration can describe required variables and public defaults without containing secret values. Local execution needs no hosted service once the vault, keys, and project configuration are available.

For teams, one owner publishes signed updates encrypted for each device through a shared folder, an S3-compatible bucket, or a WebDAV collection. Each developer keeps personal overrides and approves command access locally. First join requires comparing full device and owner fingerprints through a separate trusted channel.

For CI, the owner grants a machine identity access to a team profile. A runner with read access to the delivery backend can verify the snapshot and run its command with selected secrets without opening a local vault. [CI/CD guide](ci-cd.md)

## Show the workflow

Lead with either starting a personal Global Vault (`@shared`) for cross-project keys and `locket mcp`, or importing an existing project `.env` file and running one command. Link to the [README quick start](../README.md#quick-start) for the current commands. Explain variable contracts when a developer needs to configure a fresh clone, and introduce [team onboarding](team-updates.md) when they need to share values.

The desktop opens with a focused two-choice Welcome view (Global Vault or auto-detecting project folder) and lands directly in Secrets once connected. It supports import and durable command editing through the unlocked agent, including passphrase-only vaults. Readiness explains what needs attention before execution. Advanced audit, recovery, and policy controls stay accessible without crowding the first run.

## Claims that need care

- Redaction and scanning are explicit tools. They do not intercept arbitrary AI requests or guarantee that a credential never leaves a process. Code that receives a value can disclose it.
- Delivery packages are encrypted for approved devices. The provider can still observe metadata, withhold updates, or delete files. Status reports the last verified update.
- After offboarding, prune the device's recorded packages from the backend and rotate credentials at their providers. Former recipients may still have copies of values they received.
- Signed team delivery is implemented and tested with independent synthetic stores. Real provider delivery, independent human fingerprint comparisons, and observed onboarding still need acceptance runs.
- Owner handover and trust-fork recovery are unsupported. Do not suggest resetting a pin to silence a warning.
- Unsigned package checks do not establish release signing, notarization, or clean-machine usability. Follow the [distribution guide](distribution-validation.md) and [signing setup report](release-signing-setup.md).
- Do not publish proposed pricing, hosted tiers, SSO, compliance certifications, market-size estimates, or performance numbers as current product facts.

## Voice

Use concrete actions and examples: import, approve, run, share, and resolve. Explain the benefit before the architecture. Describe limits where they affect a decision. Avoid guarantees such as "secrets never leak," unmeasured speed claims, and unsupported competitor comparisons.

The [comparison page](comparison.md) describes the current workflow. Keep external comparisons tied to primary sources and verify changing facts before publication. A useful adoption result is an unfamiliar developer completing their first run and helping a teammate join without coaching; source tests alone do not establish that result.
