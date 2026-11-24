# Choosing Locket

Locket is being built for developers who want development variables encrypted on their own machines, explicit command access, and offline local execution. Its case should rest on that workflow being easy and reliable.

## Compare the workflow

| Question | Current Locket behavior |
| --- | --- |
| Where do values live? | An encrypted local SQLite vault; shareable project metadata stays in locket.toml. |
| How does an application receive values? | A saved command declares permitted names; Locket injects values into that process. |
| Does routine execution require a hosted service? | No. Local keys, project configuration, and values must be available. |
| How are teammates updated? | One owner publishes signed, device-encrypted updates through an existing shared folder. Unlocked agents deliver and apply verified updates. Real provider behavior still needs acceptance testing. |
| What is shared by default? | Current shared values. Personal/machine values and history require opt-in. |
| Are imported commands trusted? | Approve command access locally. Signed team updates never install command approvals or project configuration; manual sealed bundles do not authenticate their issuer. |
| How does a fresh machine join? | Prepare device keys, compare full fingerprints independently with the owner, then join an owner-signed package. Owner handover and trust-fork recovery remain unsupported. |
| What works in the desktop? | Project connection, unlock, env import, durable command editing, readiness checks, terminal launch and explicit team conflict controls. Import/edit use the unlocked agent, including passphrase-only vaults. |
| Is this a production secret-management service? | No. Use infrastructure designed for your production and CI requirements. |

## Claims to avoid

Offline execution is not unique to Locket. Doppler documents encrypted fallback snapshots and a fallback-only mode for offline access. [Doppler fallback documentation](https://docs.doppler.com/docs/automatic-fallbacks).

Actual-value redaction is not unique either. Dotenvx documents redaction of loaded values with its run command, as well as encrypted env files. [Dotenvx official CLI documentation](https://github.com/dotenvx/dotenvx).

Locket's scanners and redaction are explicit tools for preparing files or output. They do not intercept AI requests or make arbitrary code safe. A process receiving a variable can disclose it.

Do not market unfinished SSO, compliance programs, hosted tiers, owner handover, or future pricing as shipped features. Signed folder delivery is implemented; observed team usability and real provider qualification remain open. Vendor prices and plan limits change; check their primary pricing pages when evaluating a purchase rather than relying on an old matrix.

The remaining adoption test is practical: can an unfamiliar developer import and run their app without coaching, then help a teammate do the same without losing data or sharing extra values? The [team guide](team-updates.md) and [distribution checks](distribution-validation.md) describe the current workflows and acceptance boundaries.

External claims checked against the linked primary documentation on 2026-10-18. Product behavior is based on this repository; live multi-device usability has not been measured.
