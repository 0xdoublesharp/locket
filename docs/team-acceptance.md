# Qualify team onboarding and folder delivery

Use this checklist before describing Locket as qualified for a particular shared-folder provider. Automated independent-store tests cover the protocol; they do not establish how Dropbox, OneDrive, iCloud, or a network share delivers files between real machines.

## Prepare a safe trial

Use two devices, separate disposable OS accounts or isolated test stores, a dedicated empty provider folder, and synthetic values. Do not use an existing vault, real credentials, or an existing team. Confirm where each machine actually mounts the shared folder. Keep logs and screenshots on Scratch, outside the repository, and do not record secret values.

Follow the [team guide](team-updates.md) to prepare device keys, compare full fingerprints over an independent channel, and join the receiving device. A second person should perform the comparison; copying a fingerprint from the same shared folder does not verify it.

## Check delivery

1. Publish a harmless shared development value on the owner's device. Confirm that the recipient receives the encrypted package through the real provider and applies it while unlocked. Record elapsed delivery time and last verified update on both devices.
2. Give the recipient a different personal override. Publish a changed shared value and confirm that the local override still wins. Check through a synthetic command approved for that variable; do not export the vault.
3. Lock the recipient, publish another update, and confirm it applies only after unlock. Take the recipient offline, publish two updates, reconnect, and confirm it catches up in order.
4. Temporarily remove a predecessor from the recipient's test folder. Confirm a later package does not bypass the gap. Restore the original encrypted predecessor and confirm delivery resumes. Reintroduce an already applied package and confirm it does not roll state back or create another value update.
5. Exercise a populated local profile name collision and a dangerous-profile hold. Confirm signed membership/key state can advance while values remain held. Use the explicit resolution controls and confirm existing personal data survives.
6. Remove the recipient from the synthetic team and rekey affected profiles. Confirm the removed device cannot decrypt newly published synthetic values. Previously received values remain known to that device.
7. Close and reopen Locket on each device. Confirm the owner pin, delivery configuration, personal override, and last verified update survive. Inspect diagnostics for a clear recovery action if the provider is unavailable.

Stop on a trust warning or unexpected overwrite. Preserve the synthetic state and encrypted packages for investigation; do not reset trust to force a pass. Record provider/version, OS versions, Locket commit/version, which checks passed, and any failures. A passing trial qualifies only the tested provider and setup.

## Observe the first run

Separately, ask an unfamiliar developer to start from the README with a disposable project and synthetic `.env`. Let them import, approve, and run one command without coaching, then help the second developer join. Record time to first successful run, failed attempts, confusing labels, and every intervention. Check that they can explain which values are shared, what stays personal, and why command access needs local approval.

Treat a required hint, unsafe assumption, or unexplained error as a product finding. Update the workflow and repeat the affected scenario. Successful source tests, installer checks, and a guided demonstration do not replace this observation.

## Keep release gates separate

Native package installation is covered by [distribution validation](distribution-validation.md). Signing and notarization require the [signing setup](release-signing-setup.md). Neither a signed installer nor successful folder delivery establishes that onboarding is understandable.
