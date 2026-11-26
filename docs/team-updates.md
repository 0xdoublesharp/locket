# Share development variables with a team

Locket encrypts a separate package for each approved device. A single owner publishes the team's shared values, and each developer keeps personal overrides. Deliver packages through a shared folder, an S3-compatible bucket, or a WebDAV collection.

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

Get the owner's full fingerprint through a separate trusted channel. Do not trust a fingerprint supplied only with the package or folder. Join using your encrypted `.lkpkg` file:

```sh
locket team join /path/to/package.lkpkg \
  --owner '<independently verified owner fingerprint>' \
  --folder /path/to/shared-folder
```

Use a fresh store if this machine already contains populated, unrelated profiles with the same names. Locket refuses ambiguous merges.

## Use S3-compatible storage (AWS S3, Cloudflare R2, Backblaze B2, MinIO) or WebDAV

Treat the storage provider as an untrusted delivery service. The provider receives opaque, encrypted `.lkpkg` files. It can see file sizes, counts, and transfer times, and can delay or delete files. It cannot read team secrets, forge updates that Locket accepts, or approve commands on any device. Verify the owner's fingerprint through a separate trusted channel before joining.

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

After the owner adds your device and publishes, join with the same bucket, prefix, region, and endpoint the owner used. Supply your own read credentials. For WebDAV, supply the collection URL and authentication settings. Locket saves the backend for future updates after it verifies and applies your package.

```sh
locket team join --owner '<independently verified owner fingerprint>' \
  --s3-bucket example-team-updates --s3-region us-east-1 --s3-prefix app

locket team join --owner '<independently verified owner fingerprint>' \
  --webdav-url https://dav.example.com/team/app/ --webdav-auth basic --webdav-username alex
```

To read packages from a backend already configured on this machine, use `locket team join --owner '<independently verified owner fingerprint>' --remote`.

For AWS S3, use a dedicated bucket for team updates. Grant developers only `s3:ListBucket` on that bucket and `s3:GetObject` for packages under the project prefix. Add `s3:PutObject` to the object statement for the owner. Bucket-level list permission also lets S3 report a missing object when Locket checks before upload. Use equivalent scoped credentials with other providers. See [AWS S3 policy examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-policies-s3.html) and the [HeadObject reference](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html).

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

`test` checks connectivity and package listing. `status` shows the configured backend without credentials. `clear` disables delivery and removes locally stored transport credentials while preserving the owner pin and authenticated history.

## Receive updates

The unlocked agent checks the locally configured backend periodically. The owner's unlocked agent publishes changes automatically, and `locket team publish` sends them immediately. Locked machines apply nothing. Locket keeps command approvals and `locket.toml` local.

```sh
locket team sync status
locket team sync now
locket team sync disable
```

Status reports the last verified update. It cannot prove that the backend contains the owner's newest state. Keep earlier packages until all recipients have received their predecessor chain. The owner retains exact encrypted packages and `locket team publish` restores missing files. Never reset trust merely to suppress a rollback warning. First-join packages expire, and established devices can verify older predecessors while retaining their pinned history.

Dangerous profiles require explicit local consent to automatic delivery and retain their per-run confirmation. Signed membership and key updates still advance while values wait encrypted. Save `--allow-dangerous` when configuring the backend to consent to automatic delivery on this machine. Re-importing a duplicate join package never releases held values.

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

The command refuses to replace an existing personal override. Configure a delivery backend, then run `locket team sync now` to retry against the current signed checkpoint and saved local consent. The desktop offers the same explicit collision controls. An empty colliding local profile can be archived automatically. A remote rename of an existing profile ID retains its local name.

Personal values continue to override team values. A conflicting edit needs an explicit choice; it must not silently overwrite local work:

```sh
locket team sync resolve SECRET_ID keep-local
locket team sync resolve SECRET_ID take-team
```

Value conflicts and held profiles are counted separately. Stale conflict packages cannot bypass a profile hold or restore revoked scope.

## Remove access

Removing membership or storage access cannot erase values someone already received. Rotate credentials at their providers after offboarding. Locket must also replace affected profile encryption keys before publishing more values to remaining recipients. A signing identity change requires a newly verified owner pin unless a supported authenticated handover is available.

## Validation boundary

Independent synthetic stores test package integrity, owner and recipient binding, atomic apply, ordering, and replay rejection. Real iCloud, OneDrive, Dropbox, network shares, multi-person fingerprint comparisons, and clean-machine installation need separate acceptance runs.

Use the [team acceptance checklist](team-acceptance.md) for a synthetic two-device provider trial and an observed first run.
