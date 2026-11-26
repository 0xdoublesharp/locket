# Share development variables with a team

One owner publishes shared values in signed packages encrypted for each approved device. Developers keep personal overrides on their own machines. Choose a shared folder, an S3-compatible bucket, or a WebDAV collection for delivery.

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

The owner starts with `locket device init` and `locket team init 'Our team'` if the project does not have a team yet. Publishing requires the owner's protected signing key.

Get the owner's full fingerprint through a trusted channel independent of the package and delivery folder. Join using your encrypted `.lkpkg` file.

```sh
locket team join /path/to/package.lkpkg \
  --owner '<independently verified owner fingerprint>' \
  --folder /path/to/shared-folder
```

Use a fresh store if this machine already contains populated, unrelated profiles with the same names. Locket refuses to merge those profiles.

## Use S3-compatible storage (AWS S3, Cloudflare R2, Backblaze B2, MinIO) or WebDAV

The provider can see encrypted `.lkpkg` files, their sizes and counts, and when they transfer. It can delay or delete files. Devices verify updates against a pinned owner, decrypt their own packages, and approve commands locally.

As owner, choose an existing bucket and a prefix reserved for this project, or an existing WebDAV collection. Configure delivery before running `locket team publish`. Use an HTTPS endpoint that accepts conditional uploads with `If-None-Match: *`. Custom S3 endpoints use path-style addressing automatically.

```sh
# AWS S3
locket team remote set s3 --bucket example-team-updates --region us-east-1 --prefix app

# Cloudflare R2
locket team remote set s3 --bucket example-team-updates --region auto --prefix app \
  --endpoint 'https://<account-id>.r2.cloudflarestorage.com'

# Backblaze B2 (use the endpoint and region shown for your bucket)
locket team remote set s3 --bucket example-team-updates --region us-west-004 --prefix app \
  --endpoint https://s3.us-west-004.backblazeb2.com

# MinIO (use the region configured on your server)
locket team remote set s3 --bucket example-team-updates --region us-east-1 --prefix app \
  --endpoint https://minio.example.com

# WebDAV with Basic authentication
locket team remote set webdav --url https://dav.example.com/team/app/ \
  --auth basic --username alex
```

See the provider references for [Cloudflare R2](https://developers.cloudflare.com/r2/get-started/s3/) and [Backblaze B2](https://www.backblaze.com/docs/cloud-storage-call-the-s3-compatible-api).

Locket defaults to vault credentials for S3 and authenticated WebDAV. It prompts for secrets without echoing and encrypts the credentials in this machine's vault. For non-interactive setup, use `LOCKET_S3_ACCESS_KEY_ID`, `LOCKET_S3_SECRET_ACCESS_KEY`, and the optional `LOCKET_S3_SESSION_TOKEN`, or their AWS equivalents `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`. For WebDAV, use `LOCKET_WEBDAV_SECRET` or `LOCKET_WEBDAV_TOKEN`. WebDAV supports `--auth bearer` for tokens and `--auth none --credentials none` for unauthenticated collections.

With `--credentials env`, supply the variables to each process that uses the backend, including the agent if it handles automatic delivery. WebDAV Basic can also read its username from `LOCKET_WEBDAV_USERNAME`. To use a shared folder through the same command tree, run `locket team remote set folder /path/to/shared-folder`.

After the owner adds your device and publishes, use the owner's bucket, prefix, region, and endpoint with your own read credentials. For WebDAV, supply the collection URL and your authentication settings. Locket saves the backend for future updates after it verifies and applies your package.

```sh
locket team join --owner '<independently verified owner fingerprint>' \
  --s3-bucket example-team-updates --s3-region us-east-1 --s3-prefix app

locket team join --owner '<independently verified owner fingerprint>' \
  --webdav-url https://dav.example.com/team/app/ --webdav-auth basic --webdav-username alex
```

To read packages from a backend already configured on this machine, use `locket team join --owner '<independently verified owner fingerprint>' --remote`.

When you join from a backend, Locket lists package names, then downloads packages addressed to your device and any legacy packages without a recipient in their names. It selects the highest verified epoch and stops if two different verified packages claim that epoch.

For AWS S3, use a dedicated bucket for team updates. Grant developers only `s3:ListBucket` on that bucket and `s3:GetObject` for packages under the project prefix. Add `s3:PutObject` to the object statement for the owner. If the owner uses pruning, also grant the owner `s3:DeleteObject` for packages under that prefix. Bucket-level list permission also lets S3 report a missing object when Locket checks before upload. Use equivalent scoped credentials with other providers. See [AWS S3 policy examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-policies-s3.html) and the [HeadObject reference](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::example-team-updates"
    },
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example-team-updates/app/*.lkpkg"
    }
  ]
}
```

```sh
locket team remote test
locket team remote status
locket team remote clear
```

`test` checks connectivity and package listing. `status` shows the configured backend without credentials. `clear` stops delivery on this machine and removes stored backend credentials. It keeps the owner pin and authenticated history.

## Prune packages

The pinned owner can run `locket team remote prune [--keep-epochs N] [--dry-run]` on the configured backend. Use `--dry-run` to preview deletions as JSON. Pruning considers remote packages recorded in the owner's outbox. For each active recipient, it keeps the five newest delivered epochs by default, and `--keep-epochs N` must be at least one. It removes every recorded remote package for a removed or revoked recipient, including packages whose delivery was never marked complete.

Choose a retention window that covers devices that sync infrequently. Established devices need their predecessor chain to verify new updates. Pruning also deletes the affected outbox entries. If a device missed a pruned predecessor, restore it from a backup of the encrypted packages before retrying.

## Receive updates

While unlocked, the owner's agent publishes changed shared values, and teammates' agents check for verified updates periodically. To publish immediately, run `locket team publish` or choose **Publish updates now** in the desktop **Team Sync** panel. Teammates can choose **Apply verified updates**. **Disconnect backend** stops local delivery and removes stored backend credentials while keeping the owner pin and authenticated history. Command approvals and `locket.toml` stay local.

```sh
locket team sync status
locket team sync now
locket team sync disable
```

Status reports the last verified update. The backend can withhold newer updates. The owner retains exact encrypted packages in the outbox, and `locket team publish` restores missing files that are still recorded there. First-join packages must be unexpired. Established devices can verify older predecessors while keeping their pinned history, so retain the owner pin and history when investigating a rollback warning.

Dangerous profiles require explicit local consent to automatic delivery and retain their per-run confirmation. Signed membership and key updates still advance while values wait encrypted. Save `--allow-dangerous` when configuring the backend to consent to automatic delivery on this machine. Re-importing a duplicate join package never releases held values.

Inspect held profile metadata.

```sh
locket team sync pending
```

If a populated local profile has the same name as an incoming team profile, rename the local profile. Its ID, keys, and history stay intact.

```sh
locket team sync rename-local-profile INCOMING_PROFILE_ID LOCAL_PROFILE_ID dev-personal
```

After retry, policies, `default_profile`, and `lk://` references that use the old name point to the incoming team profile. Review those references before using it. Directory grants stay bound to the renamed local profile's ID.

If a different local shared value has the same name as an incoming value, preserve the local value as a personal override.

```sh
locket team sync keep-local-value INCOMING_PROFILE_ID LOCAL_SECRET_ID
```

The command refuses to replace an existing personal override. Configure a delivery backend, then run `locket team sync now` to retry against the current signed checkpoint and saved local consent. The desktop offers the same explicit collision controls. An empty colliding local profile can be archived automatically. A remote rename of an existing profile ID retains its local name.

Personal values continue to override team values. Choose which value to keep when edits conflict.

```sh
locket team sync resolve SECRET_ID keep-local
locket team sync resolve SECRET_ID take-team
```

Value conflicts and held profiles are counted separately. Stale conflict packages cannot bypass a profile hold or restore revoked scope.

## Remove access

Use `locket team remove` for a member or `locket team revoke-device` for a device. Locket rotates affected profile encryption keys and publishes the updated roster to remaining recipients. If delivery is pending, run `locket team publish`. Prune the removed recipients' recorded remote packages, and rotate credentials at their providers because former recipients may still have copies. If the signing identity changes, verify and pin the new owner fingerprint independently. Authenticated owner handover is unavailable.

## Validation boundary

Independent synthetic stores test package integrity, owner and recipient binding, atomic apply, ordering, and replay rejection. Real iCloud, OneDrive, Dropbox, network shares, multi-person fingerprint comparisons, and clean-machine installation need separate acceptance runs.

Use the [team acceptance checklist](team-acceptance.md) for a synthetic two-device provider trial and an observed first run.
