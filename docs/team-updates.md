# Share development variables with a team

Locket encrypts a separate package for each approved device. A single owner publishes the team's shared values; each developer keeps personal overrides. Updates arrive through a folder your team already shares. The folder provider cannot read the package contents, but can see file sizes, counts, and modification times, and can delay or delete files.

## Join a project

Clone the repository, then prepare this machine:

```sh
locket team join --request
```

Send the printed `lkdev2_` descriptor to the owner. Verify your full device fingerprint with the owner using a separate trusted channel. No shared profile keys are created during preparation.

The owner adds your device and the profiles you need:

```sh
locket team add Alex --device '<lkdev2_ descriptor>' \
  --confirm-device-fingerprint '<independently verified full fingerprint>' \
  --profile dev
locket team folder /path/to/shared-folder
locket team publish
```

The owner starts with `locket device init` and `locket team init 'Our team'` if the project does not have a team yet. Publishing requires the owner's protected signing key. Maintainers and developers cannot publish shared values in this initial model.

Get the owner's full fingerprint through a separate trusted channel. Do not trust a fingerprint supplied only with the package or folder. Join using your encrypted `.lkpkg` file:

```sh
locket team join /path/to/package.lkpkg \
  --owner '<independently verified owner fingerprint>' \
  --folder /path/to/shared-folder
```

Use a fresh store if this machine already contains populated, unrelated profiles with the same names. Locket refuses ambiguous merges.

## Receive updates

The unlocked agent checks the locally configured folder periodically. The owner's unlocked agent publishes changes automatically; `locket team publish` sends them immediately. Locked machines apply nothing. Local command approvals and `locket.toml` are never installed by a team package.

```sh
locket team sync status
locket team sync now
locket team sync disable
```

Status reports the last verified update. It cannot prove that the folder contains the owner's newest state. Keep earlier packages until all recipients have received their predecessor chain. The owner retains exact encrypted packages and `locket team publish` restores missing files. Never reset trust merely to suppress a rollback warning. First-join packages expire; established devices can verify older predecessors without dropping their pinned history.

Dangerous profiles require explicit local consent to automatic delivery and retain their per-run confirmation. Signed membership and key updates still advance while values wait encrypted. Saving `--allow-dangerous` with `locket team folder` consents to automatic delivery for the shared folder on this machine; it does not approve running commands. Re-importing a duplicate join package never releases held values.

Inspect held profiles without revealing their values:

```sh
locket team sync pending
```

For a new team profile blocked by a populated local profile with the same name, explicitly rename the local profile. Its ID, keys, and history stay intact:

```sh
locket team sync rename-local-profile INCOMING_PROFILE_ID LOCAL_PROFILE_ID dev-personal
```

Policies, `default_profile`, and `lk://` references using the old name will refer to the incoming team profile after retry. Review those references before using it. Directory grants stay bound to the renamed local profile's ID. Locket does not rewrite command policies automatically.

For a shared value blocked by a different local shared value with the same name, preserve the local value as a personal override:

```sh
locket team sync keep-local-value INCOMING_PROFILE_ID LOCAL_SECRET_ID
```

The command refuses to replace an existing personal override. Configure a delivery folder, then run `locket team sync now` to retry against the current signed checkpoint and saved local consent. The desktop offers the same explicit collision controls. An empty colliding local profile can be archived automatically; remote renames of an existing profile ID retain its local name.

Personal values continue to override team values. A conflicting edit needs an explicit choice; it must not silently overwrite local work:

```sh
locket team sync resolve SECRET_ID keep-local
locket team sync resolve SECRET_ID take-team
```

Value conflicts and held profiles are counted separately. Stale conflict packages cannot bypass a profile hold or restore revoked scope.

## Remove access

Removing membership or folder access cannot erase values someone already received. Rotate credentials at their providers after offboarding. Locket must also replace affected profile encryption keys before publishing more values to remaining recipients. A signing identity change requires a newly verified owner pin unless a supported authenticated handover is available.

## Validation boundary

Independent synthetic stores test package integrity, owner and recipient binding, atomic apply, ordering, and replay rejection. Real iCloud, OneDrive, Dropbox, network shares, multi-person fingerprint comparisons, and clean-machine installation need separate acceptance runs.

Use the [team acceptance checklist](team-acceptance.md) for a synthetic two-device provider trial and an observed first run.
