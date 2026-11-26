# Read team secrets in CI

Give each CI runner a machine identity with access to its deployment profile. The runner needs the Locket CLI, its private identity, and read access to encrypted packages in AWS S3, Cloudflare R2, Backblaze B2, MinIO, WebDAV, or a shared folder. Locket verifies and decrypts the profile in memory without a local vault or keyring.

## Enroll and publish

Generate the identity on a trusted machine. Use the public descriptor and fingerprint from the JSON output to enroll the device.

```sh
locket ci init-device --label deploy-runner --output-key-file ./deploy-runner.key
```

Save the key file's contents as a protected CI secret named `LOCKET_CI_IDENTITY`. Locket creates a new file atomically with mode `0600` on Unix. On Windows, use a directory with a private ACL. If you pass `--print-private-identity` in place of `--output-key-file`, stdout contains the private token in the JSON field `ci_identity`. Keep the token out of source control and CI logs.

Store the variables the runner needs as team-managed values in the deployment profile. Personal Global Vault links and the local duplicate index stay on the publisher's machine.

On the owner's machine, verify the full device fingerprint independently, then enroll the device with read-only access to the deployment profile, configure delivery, and publish.

```sh
locket team add ci-bot --device "$CI_DESCRIPTOR" \
  --confirm-device-fingerprint "$CI_FINGERPRINT" --profile staging --role read-only

locket set DEPLOY_TOKEN --profile staging --source team-managed

locket team remote set s3 --bucket team-packages --prefix deploy \
  --endpoint "https://ACCOUNT_ID.r2.cloudflarestorage.com" --region auto --path-style
locket team publish
```

Use credentials that can publish on the owner's machine. Grant the runner only package listing and download access in the same bucket and prefix. Get the owner's full fingerprint through a trusted channel independent of the delivery backend. The owner can look it up with `locket team sync status`. Save it in a protected CI variable.

## GitHub Actions with R2

Install Locket on the runner and provide the deployment script in the repository. Set the project ID and owner fingerprint in repository or environment variables. If you omit `--project`, Locket reads the ID from the checked-out `locket.toml`. For AWS S3, omit the endpoint and path-style flags and use the bucket's AWS region.

```yaml
name: Deploy
on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v4
      - name: Deploy with the staging token
        env:
          LOCKET_CI_IDENTITY: ${{ secrets.LOCKET_CI_IDENTITY }}
          LOCKET_S3_ACCESS_KEY_ID: ${{ secrets.LOCKET_S3_ACCESS_KEY_ID }}
          LOCKET_S3_SECRET_ACCESS_KEY: ${{ secrets.LOCKET_S3_SECRET_ACCESS_KEY }}
          LOCKET_OWNER: ${{ vars.LOCKET_OWNER_FINGERPRINT }}
          LOCKET_PROJECT: ${{ vars.LOCKET_PROJECT_ID }}
          LOCKET_R2_ENDPOINT: ${{ vars.LOCKET_R2_ENDPOINT }}
        run: |
          locket ci exec --owner "$LOCKET_OWNER" --project "$LOCKET_PROJECT" \
            --profile staging --s3-bucket team-packages --s3-prefix deploy \
            --s3-endpoint "$LOCKET_R2_ENDPOINT" --s3-region auto --s3-path-style \
            --secret DEPLOY_TOKEN -- ./scripts/deploy
```

For a shared folder, use `--folder PATH`. For WebDAV, use `--webdav-url URL` and optionally `--webdav-auth basic` or `--webdav-auth bearer`. Set `LOCKET_WEBDAV_USERNAME` and `LOCKET_WEBDAV_SECRET` for Basic, or `LOCKET_WEBDAV_TOKEN` for Bearer. S3 also accepts the standard AWS access-key environment variables. Use `--identity-env NAME` if the pipeline stores the CI identity under another variable name.

## Verification and access

`locket ci verify` takes the same project, owner, profile, and delivery flags as `locket ci exec`. It decrypts the profile to check its integrity and prints metadata as JSON, including the verified epoch and active secret names. Both commands require `--allow-dangerous` for a profile the owner marked dangerous.

`locket ci exec` injects the selected secrets into the command's environment. Repeat `--secret NAME` for each value you need, or use `--all-profile-secrets` for the full profile. Locket removes inherited CI identity and delivery credential variables and rejects secret names that control process startup, including `PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, and `NODE_OPTIONS`. On Unix, `execve` replaces Locket with the command so no Locket parent remains for the command to inspect. The deployment command controls what it writes and logs.

The runner selects the highest authentic epoch available to its device. It fails if snapshots conflict at that epoch or the selected snapshot has expired. Storage can withhold newer snapshots from a runner with no saved history. Set `--min-epoch EPOCH` to require an epoch at or above a known value, `--max-age-seconds SECONDS` to limit the time since the owner issued the snapshot, or both.

To offboard a runner, run `locket team revoke-device` for its device on the owner's machine. If delivery is pending, run `locket team publish`. Run `locket team remote prune` to delete its recorded packages from the backend, and rotate credentials at their providers.
