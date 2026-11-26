# Read team secrets in CI

Use a standalone Locket device to read an authorized profile from S3, Cloudflare R2, Backblaze B2, MinIO, WebDAV, or a shared folder. The runner needs the CLI, its CI identity, and read access to encrypted packages. Locket verifies and decrypts the profile in memory without a local vault or keyring.

## Enroll and publish

Generate the identity on a trusted machine.

```sh
locket ci init-device --label deploy-runner --output-key-file ./deploy-runner.key
```

Save the contents of the key file as a protected CI secret named `LOCKET_CI_IDENTITY`. Locket creates the file atomically with mode `0600` on Unix. On Windows, use a directory with a private ACL. To print the private identity on stdout instead of writing a file, pass `--print-private-identity` explicitly. Keep the identity out of source control and CI logs.

On the owner's machine, confirm the device fingerprint and enroll the CI device with read-only access to the deployment profile.

```sh
locket team add ci-bot --device "$CI_DESCRIPTOR" \
  --confirm-device-fingerprint "$CI_FINGERPRINT" --profile staging --role read-only

locket set DEPLOY_TOKEN --profile staging --source team-managed

locket team remote set s3 --bucket team-packages --prefix deploy \
  --endpoint "https://ACCOUNT_ID.r2.cloudflarestorage.com" --region auto --path-style
locket team publish
```

Use the descriptor and fingerprint printed by `init-device`. Set the remote on the owner with credentials that can publish. For the runner, grant only package listing and downloads in the same bucket and prefix. Get the owner fingerprint independently from the owner, for example from `locket team sync status` on the owner's machine. Save that fingerprint in a protected CI variable.

## GitHub Actions with R2

This example assumes Locket is installed on the runner and the repository has a deployment script. Set the project and owner IDs in repository or environment variables. The project ID can also come from a checked-out `locket.toml` when `--project` is omitted. For AWS S3, omit the endpoint and path-style flags and use the bucket's AWS region.

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

`locket ci verify` takes the same project, owner, profile, and delivery flags. It decrypts the profile to check its integrity and prints JSON with the verified epoch and active secret names. Both commands require `--allow-dangerous` for a signed dangerous profile.

`locket ci exec` injects the named secrets and replaces the `locket` process image with the child command via `execve` on Unix so the child cannot inspect a live parent environment for `LOCKET_CI_IDENTITY` or delivery credentials. Repeat `--secret NAME` for each required value, or use `--all-profile-secrets` to opt into the full profile. Startup-control variable names such as `PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, and `NODE_OPTIONS` are rejected. The deployment command controls what it writes and logs.

The runner accepts the highest authentic, unexpired snapshot available to its device and rejects conflicting snapshots at that epoch. Pass `--min-epoch EPOCH` and/or `--max-age-seconds SECONDS` to tighten freshness bounds on stateless runners. Delivery storage can withhold newer snapshots from a runner with no saved history. When offboarding, remove the device on the owner's machine, publish, run `locket team remote prune` (which deletes all remote packages for removed/revoked devices), and rotate credentials at their providers.
