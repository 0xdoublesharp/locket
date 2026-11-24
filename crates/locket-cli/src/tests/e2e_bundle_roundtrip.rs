//! End-to-end coverage for the sealed-bundle export -> verify ->
//! decrypt-import roundtrip. The decrypt step ships today
//! (`bundle-import-decrypt`); the apply step
//! (`bundle-import-apply-rows` / `bundle-apply-and-conflicts`) does
//! not, so these tests assert the four payload counts the import
//! command emits and leave a TODO breadcrumb for the conflict matrix.
//!
//! Spec: `docs/specs/testing.md` -- e2e bundle-roundtrip target.
//! Existing siblings: `cli_basics::sealed_bundle_export_verify_and_import_are_metadata_only`,
//! `cli_basics::bundle_verify_rejects_tampered_digest`, and
//! `cli_basics::bundle_verify_rejects_unsupported_schema_as_config_error`.

#[allow(unused_imports)]
use super::*;

/// Inline analogue of the `setup_initialized_project` helper referenced
/// from the planning doc: init project, write one secret, init device,
/// export a sealed bundle. Returns the runtime context, the device
/// descriptor, the bundle path, and the export stdout.
fn export_sealed_bundle(
    directory: &tempfile::TempDir,
    bundle_filename: &str,
) -> Result<(RuntimeContext, String, PathBuf, String), Box<dyn std::error::Error>> {
    let context = test_context(directory);
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "init",
            "--no-device",
            "--no-passkey",
            "--name",
            "app",
            "--profile",
            "dev",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://bundle-secret", "manual", 1_000)?;

    let mut device_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut device_output,
    )?;
    let descriptor = String::from_utf8(device_output)?
        .lines()
        .find_map(|line| line.strip_prefix("descriptor: "))
        .ok_or("missing descriptor")?
        .to_owned();

    let bundle_path = directory.path().join(bundle_filename);
    let mut export_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--include-personal",
            "--include-history",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--include-audit",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut export_output,
    )?;
    let export_output = String::from_utf8(export_output)?;
    Ok((context, descriptor, bundle_path, export_output))
}

fn parse_field<'a>(output: &'a str, key: &str) -> Option<&'a str> {
    output.lines().find_map(|line| line.strip_prefix(&format!("{key}: ")))
}

#[test]
fn fresh_export_then_decrypt_roundtrips_payload_counts() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, export_output) =
        export_sealed_bundle(&directory, "fresh.locket-bundle")?;

    assert!(export_output.contains("bundle: exported"));
    let exported_digest =
        parse_field(&export_output, "digest").ok_or("export missing digest field")?.to_owned();
    let exported_profiles =
        parse_field(&export_output, "profiles").ok_or("export missing profiles field")?.to_owned();
    let exported_secrets = parse_field(&export_output, "secret_count")
        .ok_or("export missing secret_count field")?
        .to_owned();
    let exported_blobs = parse_field(&export_output, "blob_count")
        .ok_or("export missing blob_count field")?
        .to_owned();
    let exported_command_policies = parse_field(&export_output, "command_policy_count")
        .ok_or("export missing command_policy_count field")?
        .to_owned();

    let mut verify_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "bundle",
            "verify",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut verify_output,
    )?;
    let verify_output = String::from_utf8(verify_output)?;
    assert!(verify_output.contains("bundle: valid"));
    let verify_digest = parse_field(&verify_output, "digest").ok_or("verify missing digest")?;
    assert_eq!(
        verify_digest, exported_digest,
        "manifest digest must match between export and verify"
    );

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-local",
            "--include-audit",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("bundle: verified"));
    assert!(
        import_output.contains("import: decrypted"),
        "import must report decrypted status: {import_output}"
    );
    assert!(import_output.contains("metadata_only: yes"));

    // The four counts the decrypted-import surface emits must mirror
    // the export-side counts. Profile counts and secret counts are the
    // same field name on both sides; blobs and command_policies are
    // renamed in the import surface (export uses `blob_count` /
    // `command_policy_count`, import uses `blobs` / `command_policies`).
    let import_profiles =
        parse_field(&import_output, "profiles").ok_or("import missing profiles")?;
    let import_secrets = parse_field(&import_output, "secrets").ok_or("import missing secrets")?;
    let import_blobs = parse_field(&import_output, "blobs").ok_or("import missing blobs")?;
    let import_command_policies =
        parse_field(&import_output, "command_policies").ok_or("import missing command_policies")?;

    assert_eq!(import_profiles, exported_profiles, "profiles count must match");
    assert_eq!(import_secrets, exported_secrets, "secrets count must match");
    assert_eq!(import_blobs, exported_blobs, "blobs count must match");
    assert_eq!(
        import_command_policies, exported_command_policies,
        "command_policies count must match"
    );
    Ok(())
}

#[test]
fn identical_bundle_decrypt_emits_consistent_counts() -> Result<(), Box<dyn std::error::Error>> {
    // Two independently-initialised projects with the same scripted
    // inputs should produce exports whose manifest counts agree, and
    // the decrypted-import counts on each side should agree both with
    // the export-side counts and with each other.
    let directory_a = tempdir()?;
    let directory_b = tempdir()?;
    let (ctx_a, _desc_a, path_a, export_a) = export_sealed_bundle(&directory_a, "a.locket-bundle")?;
    let (ctx_b, _desc_b, path_b, export_b) = export_sealed_bundle(&directory_b, "b.locket-bundle")?;

    for field in [
        "profiles",
        "command_policy_count",
        "secret_count",
        "secret_version_count",
        "blob_count",
        "profile_key_count",
        "active_secret_count",
        "recipients",
        "include_audit",
        "metadata_only",
        "payload_status",
    ] {
        let value_a =
            parse_field(&export_a, field).ok_or_else(|| format!("export A missing {field}"))?;
        let value_b =
            parse_field(&export_b, field).ok_or_else(|| format!("export B missing {field}"))?;
        assert_eq!(
            value_a, value_b,
            "field {field} must agree between identical exports (a={value_a}, b={value_b})"
        );
    }

    // Decrypted-import counts must also agree across the two projects.
    let mut import_a = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            path_a.to_str().ok_or("utf8 path")?,
            "--accept-local",
        ])?,
        &ctx_a,
        &mut import_a,
    )?;
    let mut import_b = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            path_b.to_str().ok_or("utf8 path")?,
            "--accept-local",
        ])?,
        &ctx_b,
        &mut import_b,
    )?;
    let import_a = String::from_utf8(import_a)?;
    let import_b = String::from_utf8(import_b)?;
    for field in ["profiles", "secrets", "blobs", "command_policies"] {
        let value_a =
            parse_field(&import_a, field).ok_or_else(|| format!("import A missing {field}"))?;
        let value_b =
            parse_field(&import_b, field).ok_or_else(|| format!("import B missing {field}"))?;
        assert_eq!(
            value_a, value_b,
            "decrypted import field {field} must agree (a={value_a}, b={value_b})"
        );
    }
    Ok(())
}

#[test]
fn bundle_with_corrupt_age_payload_fails_verification() -> Result<(), Box<dyn std::error::Error>> {
    // Sibling test `bundle_verify_rejects_tampered_digest` covers
    // tampering the manifest's `payload_digest` field. This test
    // tampers the encrypted payload bytes themselves while leaving
    // the manifest digest alone, so digest verification trips first.
    // Both paths return `BundleVerificationFailed` (exit code 110).
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "corrupt.locket-bundle")?;

    let bundle_bytes = fs::read(&bundle_path)?;
    let mut container = locket_core::BundleContainer::deserialize(&bundle_bytes)?;
    let payload_len = container.encrypted_payload.len();
    assert!(payload_len > 0, "encrypted payload must be non-empty");
    // Flip a byte deep in the encrypted payload so the corruption is
    // in the ciphertext body rather than the framing header.
    let target = payload_len - 1;
    container.encrypted_payload[target] ^= 0xFF;
    fs::write(&bundle_path, container.serialize()?)?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-local",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("expected bundle import to fail on corrupt payload".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::BundleVerificationFailed.exit_code(),
        "exit code must be BundleVerificationFailed (110)"
    );
    match &error {
        crate::CliError::Typed { kind, .. } => {
            assert_eq!(*kind, locket_core::LocketError::BundleVerificationFailed);
        }
        other => {
            return Err(format!("expected typed BundleVerificationFailed, got {other:?}").into());
        }
    }
    assert!(
        error.to_string().contains("manifest digest mismatch"),
        "corrupt-payload import should report digest mismatch: {error}"
    );
    Ok(())
}

#[test]
fn bundle_without_device_private_key_fails_verification() -> Result<(), Box<dyn std::error::Error>>
{
    // After `device-private-key-storage` and `bundle-import-decrypt`
    // shipped, the import command loads the device private-key
    // envelope from `<store_root>/devices/<device_id>.priv`. If that
    // envelope is missing, the import must fail with
    // `BundleVerificationFailed` and the explicit reason
    // `device private-key storage not initialized`.
    //
    // Reproduction recipe: run a normal export (which calls
    // `device init` and writes the envelope), then delete the
    // `devices/` directory before invoking `import-bundle`.
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "no-priv-key.locket-bundle")?;

    let devices_dir = directory.path().join("devices");
    assert!(devices_dir.exists(), "device init must have populated devices/");
    fs::remove_dir_all(&devices_dir)?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-local",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("expected bundle import to fail without device private key".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::BundleVerificationFailed.exit_code(),
        "exit code must be BundleVerificationFailed (110)"
    );
    match &error {
        crate::CliError::Typed { kind, .. } => {
            assert_eq!(*kind, locket_core::LocketError::BundleVerificationFailed);
        }
        other => {
            return Err(format!("expected typed BundleVerificationFailed, got {other:?}").into());
        }
    }
    assert!(
        error.to_string().contains("device private-key storage not initialized"),
        "missing-private-key import should report storage-not-initialized: {error}"
    );
    Ok(())
}

// TODO(bundle-apply-and-conflicts): the cases below depend on the
// row-application + conflict matrix that follows
// `bundle-import-decrypt` (already shipped) and
// `bundle-import-apply-rows` (still pending). Each is scaffolded in
// a sentence so the next agent can lift them straight into tests.
//
// 1. `applied_rows_persist_across_reopen`: after a successful
//    `--accept-incoming` apply, reopen the store and assert the
//    decrypted profile_keys, command_policies, secret_versions, and
//    blobs are visible with the imported counts. Today the import
//    command stops at decrypt and never writes rows.
//
// 2. `newer_incoming_replaces_active_with_rotation`: import a bundle
//    whose secret_version is newer than the local active version
//    with `--accept-incoming`; assert the local row rotates with no
//    grace and the prior version is marked deprecated.
//
// 3. `divergent_versions_require_explicit_resolution`: import a
//    bundle whose secret_version diverges from local (same version
//    number, different ciphertext); assert the default conflict
//    policy `interactive-required` exits without writing.
//
// 4. `deleted_local_vs_active_incoming_records_tombstone`: local row
//    is tombstoned, incoming bundle still has the active version;
//    assert `--accept-local` keeps the tombstone and
//    `--accept-incoming` revives the row with a fresh version chain.
//
// 5. `imported_audit_chain_appends_to_imported_audit_chains`: when
//    `--include-audit` is set on both export and import, the imported
//    audit rows must land in `imported_audit_chains` with structural
//    verification. Today the import command only emits
//    `bundle_include_audit: yes/no` and does not persist rows.

/// Returns the count of rows in a single store table for assertions.
fn store_row_count(store_path: &Path, sql: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let store = locket_store::Store::open(store_path)?;
    let count: i64 = store.connection().query_row(sql, [], |row| row.get(0))?;
    Ok(count)
}

#[test]
fn applied_rows_persist_across_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "applied.locket-bundle")?;

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
            "--include-audit",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("import: applied"), "missing import: applied: {import_output}");

    let store_path = context.store_path.clone();
    drop(context);
    assert!(store_row_count(&store_path, "SELECT COUNT(*) FROM profiles")? >= 1);
    assert!(store_row_count(&store_path, "SELECT COUNT(*) FROM secrets")? >= 1);
    assert!(store_row_count(&store_path, "SELECT COUNT(*) FROM secret_versions")? >= 1);
    assert!(store_row_count(&store_path, "SELECT COUNT(*) FROM blobs")? >= 1);
    Ok(())
}

#[test]
fn newer_incoming_rotates_active_version() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "rotate.locket-bundle")?;

    let store_path = context.store_path.clone();
    {
        let store = locket_store::Store::open(&store_path)?;
        let connection = store.connection();
        connection.execute("PRAGMA foreign_keys = OFF", [])?;
        connection.execute("UPDATE secret_versions SET version = 2 WHERE version = 1", [])?;
        connection.execute("UPDATE blobs SET version = 2 WHERE version = 1", [])?;
        connection.execute("UPDATE fingerprints SET version = 2 WHERE version = 1", [])?;
        connection.execute("UPDATE secrets SET current_version = 2", [])?;
        connection.execute("PRAGMA foreign_keys = ON", [])?;
    }

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("import: applied"));

    drop(context);
    let deprecated_count = store_row_count(
        &store_path,
        "SELECT COUNT(*) FROM secret_versions WHERE state = 'deprecated'
         AND deprecated_at IS NOT NULL AND grace_until IS NOT NULL",
    )?;
    let current_count = store_row_count(
        &store_path,
        "SELECT COUNT(*) FROM secret_versions WHERE state = 'current'",
    )?;
    assert_eq!(current_count, 1, "incoming version must become the only current row");
    assert!(deprecated_count >= 1, "prior current row must be deprecated with grace_until set");
    Ok(())
}

#[test]
fn divergent_arm_rolls_back_without_flag() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "divergent.locket-bundle")?;

    let store_path = context.store_path.clone();
    {
        let store = locket_store::Store::open(&store_path)?;
        store.connection().execute(
            "UPDATE blobs SET ciphertext = X'00FF' WHERE secret_id IN (SELECT id FROM secrets)",
            [],
        )?;
    }
    let pre_blob_bytes: Vec<u8> = locket_store::Store::open(&store_path)?.connection().query_row(
        "SELECT ciphertext FROM blobs LIMIT 1",
        [],
        |row| row.get(0),
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "import-bundle", bundle_path.to_str().ok_or("utf8 path")?])?,
        &context,
        &mut Vec::new(),
    );
    assert!(result.is_err(), "default policy must reject divergent conflicts");

    drop(context);
    let post_blob_bytes: Vec<u8> = locket_store::Store::open(&store_path)?.connection().query_row(
        "SELECT ciphertext FROM blobs LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(pre_blob_bytes, post_blob_bytes, "rolled-back tx must leave blob unchanged");
    Ok(())
}

#[test]
fn divergent_arm_applies_with_accept_incoming() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "divergent-applied.locket-bundle")?;

    let store_path = context.store_path.clone();
    {
        let store = locket_store::Store::open(&store_path)?;
        store.connection().execute(
            "UPDATE blobs SET ciphertext = X'00FF' WHERE secret_id IN (SELECT id FROM secrets)",
            [],
        )?;
    }

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("import: applied"));

    drop(context);
    let post_blob_bytes: Vec<u8> = locket_store::Store::open(&store_path)?.connection().query_row(
        "SELECT ciphertext FROM blobs LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert_ne!(
        post_blob_bytes,
        b"\x00\xFF".to_vec(),
        "accept-incoming must overwrite local divergent ciphertext"
    );
    Ok(())
}

#[test]
fn deleted_vs_active_arm() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "tombstone.locket-bundle")?;

    let store_path = context.store_path.clone();
    {
        let store = locket_store::Store::open(&store_path)?;
        store.connection().execute(
            "UPDATE secrets SET state = 'deleted', deleted_at = ?1 WHERE state = 'active'",
            [9_999_999_999_i64],
        )?;
    }

    let result = run_with_context(
        Cli::try_parse_from(["locket", "import-bundle", bundle_path.to_str().ok_or("utf8 path")?])?,
        &context,
        &mut Vec::new(),
    );
    assert!(
        result.is_err(),
        "tombstone-vs-active without flags must require interactive resolution"
    );

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("import: applied"));

    drop(context);
    let active_count =
        store_row_count(&store_path, "SELECT COUNT(*) FROM secrets WHERE state = 'active'")?;
    assert!(active_count >= 1, "accept-incoming must rejoin active secret");
    Ok(())
}

/// Parity contract for an invite whose sealed payload imports nothing:
/// `team accept` followed by `import-bundle` must converge
/// with direct `import-bundle`.
///
/// This test pins that contract by comparing two arms over the same
/// initial state:
/// - Arm A imports a sealed bundle with `--accept-incoming` directly.
/// - Arm B accepts a signed invite for the same project first, then
///   imports the same bundle with `--accept-incoming`.
///
/// Both arms must converge to the same substantive row counts. Arm B's
/// only delta is the accepted-invite row + `TEAM_ACCEPT` audit metadata,
/// which are explicitly out-of-scope for the parity invariant.
#[test]
#[allow(clippy::too_many_lines)]
fn team_accept_then_import_bundle_matches_import_only_state()
-> Result<(), Box<dyn std::error::Error>> {
    use ed25519_dalek::SigningKey;
    use locket_core::{
        InviteId, InvitePayload, MemberId, ProjectId, SignedInvite, TeamRole,
        device_fingerprint_v1, fingerprint_hex,
    };
    use rusqlite::params;

    fn substantive_counts(store_path: &Path) -> Result<[i64; 5], Box<dyn std::error::Error>> {
        Ok([
            store_row_count(store_path, "SELECT COUNT(*) FROM profiles")?,
            store_row_count(store_path, "SELECT COUNT(*) FROM secrets")?,
            store_row_count(store_path, "SELECT COUNT(*) FROM secret_versions")?,
            store_row_count(store_path, "SELECT COUNT(*) FROM blobs")?,
            store_row_count(store_path, "SELECT COUNT(*) FROM command_policies")?,
        ])
    }

    fn import_bundle_apply(
        context: &RuntimeContext,
        bundle_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut output = Vec::new();
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "import-bundle",
                bundle_path.to_str().ok_or("utf8 path")?,
                "--accept-incoming",
            ])?,
            context,
            &mut output,
        )?;
        let output = String::from_utf8(output)?;
        assert!(output.contains("import: applied"), "import must apply rows: {output}");
        Ok(())
    }

    fn build_self_invite(
        context: &RuntimeContext,
        invite_id: &str,
    ) -> Result<(PathBuf, String), Box<dyn std::error::Error>> {
        run_with_context(
            Cli::try_parse_from(["locket", "team", "init", "platform-team"])?,
            context,
            &mut Vec::new(),
        )?;
        let directory_root = context.cwd.clone();
        let config = crate::read_project_config(&directory_root.join("locket.toml"))?;
        let store = locket_store::Store::open(directory_root.join("store.db"))?;
        let local_device = store
            .get_active_local_device(config.project_id.as_str())?
            .ok_or("local device must exist")?;
        let (team_id, issuer_member_id): (String, String) = store.connection().query_row(
            "SELECT t.id, m.id FROM teams t JOIN team_members m ON m.team_id = t.id
             WHERE t.project_id = ?1 LIMIT 1",
            [config.project_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        let issuer_signing = SigningKey::from_bytes(&[51_u8; 32]);
        let issuer_signing_public_key: [u8; 32] = issuer_signing.verifying_key().to_bytes();
        let issuer_sealing_public_key = [52_u8; 32];
        let issuer_fingerprint = fingerprint_hex(&device_fingerprint_v1(
            &issuer_signing_public_key,
            &issuer_sealing_public_key,
        ));
        let payload = InvitePayload {
            v: 1,
            invite_id: InviteId::new(invite_id.to_owned())?,
            project_id: ProjectId::new(config.project_id.to_string())?,
            issuer_member_id: MemberId::new(issuer_member_id.clone())?,
            issuer_signing_public_key: data_encoding::BASE64URL_NOPAD
                .encode(&issuer_signing_public_key),
            issuer_sealing_public_key: data_encoding::BASE64URL_NOPAD
                .encode(&issuer_sealing_public_key),
            issuer_device_fingerprint: issuer_fingerprint.clone(),
            recipient_device_fingerprint: local_device.fingerprint.clone(),
            recipient_sealing_public_key: data_encoding::BASE64URL_NOPAD
                .encode(&local_device.sealing_public_key),
            role: TeamRole::Developer,
            profiles: vec!["dev".to_owned()],
            expires_at: 4_102_444_800_i64,
            nonce: data_encoding::BASE64URL_NOPAD.encode(&[7_u8; 24]),
            sealed_payload: crate::tests::empty_sealed_invite_payload(
                &local_device.sealing_public_key,
            )?,
        };
        let signed = SignedInvite::sign(&issuer_signing, payload)?;
        let invite_path = directory_root.join(format!("{invite_id}.locket-invite"));
        std::fs::write(&invite_path, signed.encode()?)?;
        store.connection().execute(
            "INSERT INTO team_invites(
               id, team_id, issuer_member_id, recipient_device_fingerprint, role, profiles_json,
               nonce, created_at, expires_at
             )
             VALUES (?1, ?2, ?3, ?4, 'developer', '[\"dev\"]', zeroblob(24), 1, ?5)",
            params![
                invite_id,
                team_id.as_str(),
                issuer_member_id.as_str(),
                local_device.fingerprint.as_str(),
                4_102_444_800_i64 * 1_000_000_000_i64,
            ],
        )?;
        Ok((invite_path, issuer_fingerprint))
    }

    // Arm A: import-bundle only.
    let directory_a = tempdir()?;
    let (context_a, _descriptor_a, bundle_path_a, _export_a) =
        export_sealed_bundle(&directory_a, "parity-arm-a.locket-bundle")?;
    import_bundle_apply(&context_a, &bundle_path_a)?;
    let store_path_a = context_a.store_path.clone();
    drop(context_a);
    let counts_a = substantive_counts(&store_path_a)?;

    // Arm B: team accept (metadata-only) + import-bundle.
    let directory_b = tempdir()?;
    let (context_b, _descriptor_b, bundle_path_b, _export_b) =
        export_sealed_bundle(&directory_b, "parity-arm-b.locket-bundle")?;
    let (invite_path, issuer_fingerprint) =
        build_self_invite(&context_b, "lk_invite_parity_team_accept")?;
    let counts_b_before_accept = substantive_counts(&context_b.store_path)?;
    let confirming_context =
        context_with_confirmation(&context_b, &format!("{issuer_fingerprint}\n"));
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "team",
            "accept",
            invite_path.to_str().ok_or("utf8 invite path")?,
        ])?,
        &confirming_context,
        &mut Vec::new(),
    )?;
    let counts_b_after_accept = substantive_counts(&context_b.store_path)?;
    assert_eq!(
        counts_b_before_accept, counts_b_after_accept,
        "team accept must be metadata-only: substantive row counts must not change",
    );
    import_bundle_apply(&context_b, &bundle_path_b)?;
    let store_path_b = context_b.store_path.clone();
    drop(context_b);
    let counts_b = substantive_counts(&store_path_b)?;

    assert_eq!(
        counts_a, counts_b,
        "team accept + import-bundle must converge to import-only state (a={counts_a:?}, b={counts_b:?})",
    );

    // Arm B's only documented delta is the accepted-invite row + the
    // TEAM_ACCEPT audit metadata. Pin that delta so a regression that
    // accidentally lands rows during accept trips this assertion via
    // counts_a/counts_b above instead of leaking through here.
    let accepted_count = store_row_count(
        &store_path_b,
        "SELECT COUNT(*) FROM team_invites WHERE accepted_at IS NOT NULL",
    )?;
    assert_eq!(accepted_count, 1, "team accept must mark exactly one invite accepted");
    let team_accept_rows = store_row_count(
        &store_path_b,
        "SELECT COUNT(*) FROM audit_log WHERE action = 'TEAM_ACCEPT' AND status = 'SUCCESS'",
    )?;
    assert_eq!(team_accept_rows, 1, "team accept must emit exactly one SUCCESS audit row");
    Ok(())
}

#[test]
fn imported_audit_chain_lands_in_imported_audit_chains_with_structural_verification()
-> Result<(), Box<dyn std::error::Error>> {
    // Golden chain round-trip. Export with --include-audit, import
    // with --include-audit + --accept-incoming, and confirm:
    //   1. import: applied banner is present
    //   2. imported_audit_chain_count: <n> stdout line is non-zero
    //   3. imported_audit_chains has the expected single row keyed by
    //      the bundle digest
    //   4. checkpoint_sequence stored on disk matches the chain length
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, export_output) =
        export_sealed_bundle(&directory, "audit-chain.locket-bundle")?;
    let exported_digest =
        parse_field(&export_output, "digest").ok_or("export missing digest")?.to_owned();

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
            "--include-audit",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("import: applied"));
    assert!(
        import_output.contains("bundle_include_audit: yes"),
        "bundle must report audit chain present: {import_output}"
    );
    let imported_count_field = parse_field(&import_output, "imported_audit_chain_count")
        .ok_or("import missing imported_audit_chain_count")?;
    let imported_count: u64 = imported_count_field.parse()?;
    assert!(imported_count >= 1, "imported_audit_chain_count must be >= 1");

    let store_path = context.store_path.clone();
    drop(context);
    let stored_chains = store_row_count(&store_path, "SELECT COUNT(*) FROM imported_audit_chains")?;
    assert_eq!(stored_chains, 1, "exactly one imported_audit_chains row expected");

    // The stored row must reference the bundle's digest as its
    // bundle_digest column. Hex-decode the export-side digest field
    // and compare against the bytes column.
    let store = locket_store::Store::open(&store_path)?;
    let stored_digest_hex: String = store.connection().query_row(
        "SELECT lower(hex(bundle_digest)) FROM imported_audit_chains LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        stored_digest_hex, exported_digest,
        "bundle_digest stored on disk must match the exported manifest digest"
    );
    let checkpoint_sequence: i64 = store.connection().query_row(
        "SELECT checkpoint_sequence FROM imported_audit_chains LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(checkpoint_sequence >= 1, "checkpoint_sequence must be at least 1");
    Ok(())
}

#[test]
fn tampered_audit_chain_rejects_with_bundle_verification_failed()
-> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;

    // Flipping a byte inside the encrypted age payload (which carries
    // the inner audit-chain ciphertext) MUST cause age decryption or
    // inner XChaCha20-Poly1305 tag verification to fail and surface as
    // BundleVerificationFailed (exit code 110). We recompute the
    // outer manifest payload_digest after the byte flip so that the
    // digest-mismatch arm does not trip first; the inner age envelope
    // tag check then fires when the receiver tries to decrypt the
    // bundle, which is the same error class the brief asks for.
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "tamper-chain.locket-bundle")?;

    let bundle_bytes = fs::read(&bundle_path)?;
    let mut container = locket_core::BundleContainer::deserialize(&bundle_bytes)?;
    let payload_len = container.encrypted_payload.len();
    assert!(payload_len > 0, "encrypted payload must be non-empty");
    let target = payload_len - 1;
    container.encrypted_payload[target] ^= 0x01;
    let mut hasher = Sha256::new();
    hasher.update(&container.encrypted_payload);
    let new_digest = hasher.finalize();
    let mut hex = String::with_capacity(new_digest.len() * 2);
    for byte in &new_digest {
        write!(&mut hex, "{byte:02x}")?;
    }
    container.manifest.payload_digest = hex;
    fs::write(&bundle_path, container.serialize()?)?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
            "--include-audit",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("expected bundle import to fail on tampered audit chain".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::BundleVerificationFailed.exit_code(),
        "exit code must be BundleVerificationFailed (110)"
    );
    match &error {
        crate::CliError::Typed { kind, .. } => {
            assert_eq!(*kind, locket_core::LocketError::BundleVerificationFailed);
        }
        other => {
            return Err(format!("expected typed BundleVerificationFailed, got {other:?}").into());
        }
    }

    // The import transaction must have rolled back: imported_audit_chains
    // should be empty (the tampered import never reached commit).
    let store_path = context.store_path.clone();
    drop(context);
    let stored_chains = store_row_count(&store_path, "SELECT COUNT(*) FROM imported_audit_chains")?;
    assert_eq!(stored_chains, 0, "tampered import must leave imported_audit_chains empty");
    Ok(())
}

/// Regression for `bundle-verify-attempts-decrypt-when-recipient`
/// (`docs/specs/team-sync-recovery.md:213`). When the same device that
/// exported the bundle also verifies it, `bundle verify` must:
///
/// 1. Attempt decryption of the age payload using the local device's
///    sealing private key (recipient match).
/// 2. Emit `decryptable_by_this_device: yes` plus the inner counts
///    (profiles, secrets, `secret_versions`, blobs, `command_policies`)
///    on its CLI output.
/// 3. Never apply rows — `bundle verify` is metadata-only.
#[test]
fn bundle_verify_decrypts_when_local_device_is_recipient() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, export_output) =
        export_sealed_bundle(&directory, "verify-decrypt.locket-bundle")?;
    let exported_secrets = parse_field(&export_output, "secret_count")
        .ok_or("export missing secret_count")?
        .to_owned();
    let exported_blobs =
        parse_field(&export_output, "blob_count").ok_or("export missing blob_count")?.to_owned();
    let exported_command_policies = parse_field(&export_output, "command_policy_count")
        .ok_or("export missing command_policy_count")?
        .to_owned();
    let exported_profiles =
        parse_field(&export_output, "profiles").ok_or("export missing profiles")?.to_owned();

    let mut verify_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "bundle",
            "verify",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut verify_output,
    )?;
    let verify_output = String::from_utf8(verify_output)?;
    assert!(verify_output.contains("bundle: valid"));
    assert!(
        verify_output.contains("decryptable_by_this_device: yes"),
        "verify must report decryptable when device is a recipient: {verify_output}"
    );
    assert!(
        verify_output.contains("metadata_only: yes"),
        "verify must remain metadata-only even after decryption: {verify_output}"
    );
    let decrypted_profiles = parse_field(&verify_output, "decrypted_profile_count")
        .ok_or("verify missing decrypted_profile_count")?;
    let decrypted_secrets = parse_field(&verify_output, "decrypted_secret_count")
        .ok_or("verify missing decrypted_secret_count")?;
    let decrypted_secret_versions = parse_field(&verify_output, "decrypted_secret_version_count")
        .ok_or("verify missing decrypted_secret_version_count")?;
    let decrypted_blobs = parse_field(&verify_output, "decrypted_blob_count")
        .ok_or("verify missing decrypted_blob_count")?;
    let decrypted_command_policies = parse_field(&verify_output, "decrypted_command_policy_count")
        .ok_or("verify missing decrypted_command_policy_count")?;
    assert_eq!(
        decrypted_profiles, exported_profiles,
        "verify decrypted profile count must mirror export"
    );
    assert_eq!(
        decrypted_secrets, exported_secrets,
        "verify decrypted secret count must mirror export"
    );
    assert_eq!(decrypted_blobs, exported_blobs, "verify decrypted blob count must mirror export");
    assert_eq!(
        decrypted_command_policies, exported_command_policies,
        "verify decrypted command_policy count must mirror export"
    );
    let decrypted_secret_versions: u64 = decrypted_secret_versions.parse()?;
    assert!(
        decrypted_secret_versions >= 1,
        "verify must report at least one decrypted secret version"
    );

    // Sanity: verify must not apply rows. There must be no
    // BACKUP_IMPORT audit row from this verify call.
    let store_path = context.store_path.clone();
    drop(context);
    let import_audits = store_row_count(
        &store_path,
        "SELECT COUNT(*) FROM audit_log WHERE action = 'BACKUP_IMPORT'",
    )?;
    assert_eq!(import_audits, 0, "bundle verify must not emit BACKUP_IMPORT audit rows");
    Ok(())
}

/// Regression for `bundle-import-rotate-uses-import-timestamp`
/// (`docs/specs/team-sync-recovery.md:224`). When `import-bundle`
/// applies a divergent secret with `--accept-incoming`, the resulting
/// `secrets.last_rotated_at` row must reflect the local import
/// timestamp, NOT the bundle's `last_rotated_at`. The bundle was
/// exported with a small/old `last_rotated_at` and is re-imported
/// against a local row with a deeply different value; the new local
/// row must be much newer than the bundle's value.
#[test]
fn bundle_import_sets_last_rotated_at_to_import_timestamp() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "rotate-ts.locket-bundle")?;

    // Mutate the local row's `last_rotated_at` to a small/old value so
    // the bundle's stored `last_rotated_at` (also small here) and the
    // local row both differ from the eventual import timestamp. The
    // expected post-import value is the local `now` (nanos since the
    // Unix epoch), which is many orders of magnitude larger than this
    // sentinel value, so a strictly-greater assertion is unambiguous.
    let bundle_last_rotated_at: i64 = 1_000;
    let store_path = context.store_path.clone();
    {
        let store = locket_store::Store::open(&store_path)?;
        store.connection().execute(
            "UPDATE secrets SET last_rotated_at = ?1, updated_at = ?2",
            [bundle_last_rotated_at, 2_000_i64],
        )?;
        // Also tweak the blob ciphertext so the apply branch picks the
        // divergent path (deterministic conflict, no version bump
        // needed). The bundle ships the original ciphertext.
        store.connection().execute(
            "UPDATE blobs SET ciphertext = X'00FF' WHERE secret_id IN (SELECT id FROM secrets)",
            [],
        )?;
    }

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("import: applied"), "import must apply rows: {import_output}");

    drop(context);
    let store = locket_store::Store::open(&store_path)?;
    let post_last_rotated_at: i64 =
        store
            .connection()
            .query_row("SELECT last_rotated_at FROM secrets LIMIT 1", [], |row| row.get(0))?;
    assert!(
        post_last_rotated_at > bundle_last_rotated_at,
        "post-import last_rotated_at ({post_last_rotated_at}) must NOT be the bundle's value ({bundle_last_rotated_at}); spec requires the import timestamp"
    );
    // Sanity: a real now-since-epoch in nanos is at least ~1e18 in
    // 2026; assert we cleared the small sentinel band by a wide
    // margin, ruling out an accidental copy of `updated_at` (2_000).
    assert!(
        post_last_rotated_at > 1_000_000_000,
        "post-import last_rotated_at ({post_last_rotated_at}) must be a real timestamp, not a sentinel"
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn independent_stores_import_personal_backup_into_empty_dev_and_decrypt()
-> Result<(), Box<dyn std::error::Error>> {
    let sender_dir = tempdir()?;
    let receiver_dir = tempdir()?;
    let sender = test_context(&sender_dir);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app"])?,
        &sender,
        &mut Vec::new(),
    )?;
    fs::copy(sender_dir.path().join("locket.toml"), receiver_dir.path().join("locket.toml"))?;
    let receiver = test_context(&receiver_dir);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app"])?,
        &receiver,
        &mut Vec::new(),
    )?;
    let resolved = crate::resolve_project(receiver_dir.path())?.ok_or("receiver project")?;
    let project_id = resolved.config.project_id.as_str();
    let receiver_store = crate::open_store(&receiver)?;
    let original_profile = receiver_store.get_profile_by_name(project_id, "dev")?.ok_or("dev")?;
    let audit_key = crate::load_project_key(
        &receiver,
        &receiver_store,
        project_id,
        locket_crypto::KeyPurpose::Audit,
    )?;
    assert!(receiver_store.verify_audit_chain_read_only(project_id, audit_key.as_ref())?.hmac_ok);
    receiver_store.connection().execute("INSERT INTO directory_grants(grant_id,project_id,profile_id,root_hash,directory_hash,grant_scope,created_at,updated_at) VALUES ('preserved-grant',?1,?2,zeroblob(32),zeroblob(32),'project-root',1,1)", rusqlite::params![project_id, original_profile.id])?;
    receiver_store.connection().execute("INSERT INTO runtime_sessions(id,project_id,profile_id,process_id,process_start_time,started_at) VALUES ('preserved-session',?1,?2,1,1,1)", rusqlite::params![project_id, original_profile.id])?;
    let original_keys = receiver_store
        .connection()
        .prepare("SELECT id,wrapped_material FROM keys WHERE profile_id=?1 ORDER BY id")?
        .query_map([&original_profile.id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let args = test_secret_write_args("TRANSFER_VALUE");
    crate::set_secret_value(&sender, &args, "separate-store-value", "manual", 1000)?;
    let mut pubkey = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "device", "pubkey"])?, &receiver, &mut pubkey)?;
    let pubkey = String::from_utf8(pubkey)?;
    let descriptor = parse_field(&pubkey, "descriptor").ok_or("descriptor missing")?;
    let bundle_path = sender_dir.path().join("personal-backup.locket-bundle");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--include-personal",
            "--recipient",
            descriptor,
            "--output",
            bundle_path.to_str().ok_or("bundle path is not UTF-8")?,
        ])?,
        &sender,
        &mut Vec::new(),
    )?;
    // Preview must not import even nonconflicting rows until explicitly accepted.
    assert!(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "import-bundle",
                bundle_path.to_str().ok_or("bundle path is not UTF-8")?
            ])?,
            &receiver,
            &mut Vec::new()
        )
        .is_err()
    );
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("bundle path is not UTF-8")?,
            "--accept-incoming",
        ])?,
        &receiver,
        &mut Vec::new(),
    )?;
    let mut value = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "TRANSFER_VALUE", "--reveal", "--force"])?,
        &receiver,
        &mut value,
    )?;
    assert!(String::from_utf8(value)?.contains("separate-store-value"));
    assert!(
        receiver_store.verify_audit_chain_read_only(project_id, audit_key.as_ref())?.hmac_ok,
        "import must preserve the real init BOOTSTRAP audit chain"
    );
    let archived = receiver_store
        .list_profiles(project_id)?
        .into_iter()
        .find(|p| p.id == original_profile.id)
        .ok_or("original profile deleted")?;
    assert!(archived.name.starts_with("dev-local-"));
    locket_core::ProfileName::new(archived.name)?;
    for table in ["directory_grants", "runtime_sessions"] {
        let id: String = receiver_store.connection().query_row(
            &format!("SELECT profile_id FROM {table}"),
            [],
            |row| row.get(0),
        )?;
        assert_eq!(id, original_profile.id);
    }
    let preserved_keys = receiver_store
        .connection()
        .prepare("SELECT id,wrapped_material FROM keys WHERE profile_id=?1 ORDER BY id")?
        .query_map([&original_profile.id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(preserved_keys, original_keys);

    Ok(())
}
