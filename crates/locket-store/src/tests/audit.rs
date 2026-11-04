use std::error::Error;

use hmac::{Hmac, KeyInit, Mac};
use locket_core::{
    AUDIT_HMAC_LEN, AuditHmacInput, Timestamp, audit_hmac_v1_bytes, canonical_json_string,
};
use serde_json::json;
use sha2::Sha256;

use crate::audit::append_audit;
use crate::{
    AuditContext, AuditListFilter, AuditWrite, ImportedAuditChainRow, StoreError,
    verify_imported_audit_chain_structure,
};

use super::{
    TestStore, insert_project_profile, open_initialized_store, test_secret, test_secret_blob,
    test_secret_fingerprint, test_secret_version,
};

#[test]
fn audit_checkpoint_detects_valid_prefix_rollback_and_empty_chain() -> Result<(), Box<dyn Error>> {
    let project = locket_core::ProjectId::new("lk_proj_test")?;
    for retained_rows in [0_i64, 1] {
        let mut fixture = audit_display_fixture(None, None)?;
        let checkpoint = fixture.store.audit_checkpoint(&project, &[42; 32])?;
        assert_eq!(checkpoint.sequence, 2);
        fixture
            .store
            .connection()
            .execute("DELETE FROM audit_log WHERE sequence > ?1", [retained_rows])?;
        assert!(fixture.store.verify_audit_chain_read_only(project.as_str(), &[42; 32])?.hmac_ok);
        assert!(matches!(
            fixture.store.verify_audit_checkpoint_and_append(&project, &[42; 32], &checkpoint, 300),
            Err(StoreError::AuditIntegrity { .. })
        ));
        assert_eq!(
            fixture.store.list_recent_audit_actions(project.as_str(), 10)?.len(),
            usize::try_from(retained_rows)?
        );
    }
    Ok(())
}

#[test]
fn audit_checkpoint_authenticates_scope_fields_and_the_anchored_history()
-> Result<(), Box<dyn Error>> {
    let project = locket_core::ProjectId::new("lk_proj_test")?;
    let mut fixture = audit_display_fixture(None, None)?;
    let checkpoint = fixture.store.audit_checkpoint(&project, &[42; 32])?;
    assert_eq!(
        fixture.store.verify_audit_checkpoint_and_append(&project, &[42; 32], &checkpoint, 300)?,
        2
    );
    assert_eq!(
        fixture.store.verify_audit_checkpoint_and_append(&project, &[42; 32], &checkpoint, 400)?,
        3
    );

    for field in ["project", "schema", "sequence", "empty", "row", "tag"] {
        let mut altered = checkpoint.clone();
        match field {
            "project" => altered.project_id = locket_core::ProjectId::new("lk_proj_other")?,
            "schema" => altered.schema_version += 1,
            "sequence" => altered.sequence -= 1,
            "empty" => altered.sequence = 0,
            "row" => altered.row_hmac[0] ^= 1,
            "tag" => altered.authentication_tag[0] ^= 1,
            _ => return Err("unknown checkpoint test field".into()),
        }
        assert!(
            matches!(
                fixture
                    .store
                    .verify_audit_checkpoint_and_append(&project, &[42; 32], &altered, 500),
                Err(StoreError::AuditIntegrity { .. })
            ),
            "changed {field} must fail closed"
        );
    }
    assert_eq!(fixture.store.list_recent_audit_actions(project.as_str(), 10)?.len(), 4);
    let mut other_history = audit_display_fixture(Some("OTHER_NAME"), None)?;
    assert!(other_history.store.verify_audit_chain_read_only(project.as_str(), &[42; 32])?.hmac_ok);
    assert!(matches!(
        other_history.store.verify_audit_checkpoint_and_append(
            &project,
            &[42; 32],
            &checkpoint,
            500
        ),
        Err(StoreError::AuditIntegrity { .. })
    ));
    Ok(())
}

#[test]
fn audit_checkpoint_refuses_empty_or_corrupted_history() -> Result<(), Box<dyn Error>> {
    let project = locket_core::ProjectId::new("lk_proj_test")?;
    let fixture = audit_display_fixture(None, None)?;
    assert!(matches!(
        fixture.store.audit_checkpoint(&project, &[43; 32]),
        Err(StoreError::AuditIntegrity { .. })
    ));
    fixture
        .store
        .connection()
        .execute("UPDATE audit_log SET hmac = zeroblob(32) WHERE sequence = 2", [])?;
    assert!(matches!(
        fixture.store.audit_checkpoint(&project, &[42; 32]),
        Err(StoreError::AuditIntegrity { .. })
    ));
    fixture.store.connection().execute("DELETE FROM audit_log", [])?;
    assert!(matches!(
        fixture.store.audit_checkpoint(&project, &[42; 32]),
        Err(StoreError::AuditIntegrity { .. })
    ));
    Ok(())
}

fn audit_display_fixture(
    secret_name: Option<&str>,
    command: Option<&str>,
) -> Result<TestStore, Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    for (timestamp, secret_name, command) in [(100, None, None), (200, secret_name, command)] {
        let mut metadata = json!({
            "schema_version": 1,
            "action": "DOCTOR",
            "status": "SUCCESS",
            "check_names": ["audit_hmac_chain"],
        });
        if let Some(value) = secret_name {
            metadata["secret_name"] = json!(value);
        }
        if let Some(value) = command {
            metadata["command"] = json!(value);
        }
        test_store.store.append_audit(
            &[42; 32],
            &AuditWrite {
                project_id: "lk_proj_test",
                profile_id: Some("lk_prof_test"),
                action: "DOCTOR",
                status: "SUCCESS",
                secret_name,
                command,
                metadata_json: &metadata,
                timestamp,
            },
        )?;
    }
    Ok(test_store)
}

#[derive(Clone, Copy)]
enum AuditDisplayRead {
    Listing,
    VerifyReadOnly,
    VerifyAndAppend,
}

fn assert_audit_display_tampering_detected(
    column: &str,
    read: AuditDisplayRead,
) -> Result<(), Box<dyn Error>> {
    for (secret_name, command, replacement) in [
        (Some("DATABASE_URL"), Some("doctor"), Some("FORGED")),
        (Some("DATABASE_URL"), Some("doctor"), None),
        (None, None, Some("FORGED")),
    ] {
        let mut test_store = audit_display_fixture(secret_name, command)?;
        let sql = match column {
            "secret_name" => "UPDATE audit_log SET secret_name = ?1 WHERE sequence = 2",
            "command" => "UPDATE audit_log SET command = ?1 WHERE sequence = 2",
            _ => return Err("unsupported test column".into()),
        };
        assert_eq!(test_store.store.connection().execute(sql, [replacement])?, 1);

        match read {
            AuditDisplayRead::Listing => {
                let since =
                    test_store.store.list_audit_rows_since("lk_proj_test", "lk_prof_test", 0)?;
                let filtered = test_store.store.list_audit_rows_filtered(
                    "lk_proj_test",
                    &AuditListFilter { limit: 10, ..AuditListFilter::default() },
                )?;
                for rows in [since, filtered] {
                    assert_eq!(rows.len(), 2);
                    assert_eq!(rows[0].secret_name, None);
                    assert_eq!(rows[0].command, None);
                    assert_eq!(rows[1].secret_name.as_deref(), secret_name);
                    assert_eq!(rows[1].command.as_deref(), command);
                }
            }
            AuditDisplayRead::VerifyReadOnly => {
                let verification =
                    test_store.store.verify_audit_chain_read_only("lk_proj_test", &[42; 32])?;
                assert!(!verification.hmac_ok, "tampered {column} must fail verification");
                assert_eq!(verification.first_break_sequence, Some(2));
                assert_eq!(verification.rows_verified, 1);
                assert!(
                    verification.first_break_reason.as_deref().is_some_and(|r| r.contains(column))
                );
            }
            AuditDisplayRead::VerifyAndAppend => {
                let result =
                    test_store.store.verify_audit_chain_and_append("lk_proj_test", &[42; 32], 300);
                assert!(
                    matches!(result, Err(StoreError::AuditIntegrity { sequence: 2, ref reason })
                        if reason.contains(column)),
                    "tampered {column} must fail verification, got {result:?}"
                );
            }
        }
        assert_eq!(test_store.store.list_recent_audit_actions("lk_proj_test", 10)?.len(), 2);
    }
    Ok(())
}

#[test]
fn audit_display_listing_uses_authenticated_secret_name() -> Result<(), Box<dyn Error>> {
    assert_audit_display_tampering_detected("secret_name", AuditDisplayRead::Listing)
}

#[test]
fn audit_display_listing_uses_authenticated_command() -> Result<(), Box<dyn Error>> {
    assert_audit_display_tampering_detected("command", AuditDisplayRead::Listing)
}

#[test]
fn audit_display_read_only_verification_rejects_tampered_secret_name() -> Result<(), Box<dyn Error>>
{
    assert_audit_display_tampering_detected("secret_name", AuditDisplayRead::VerifyReadOnly)
}

#[test]
fn audit_display_read_only_verification_rejects_tampered_command() -> Result<(), Box<dyn Error>> {
    assert_audit_display_tampering_detected("command", AuditDisplayRead::VerifyReadOnly)
}

#[test]
fn audit_display_appending_verification_rejects_tampered_secret_name() -> Result<(), Box<dyn Error>>
{
    assert_audit_display_tampering_detected("secret_name", AuditDisplayRead::VerifyAndAppend)
}

#[test]
fn audit_display_appending_verification_rejects_tampered_command() -> Result<(), Box<dyn Error>> {
    assert_audit_display_tampering_detected("command", AuditDisplayRead::VerifyAndAppend)
}

#[test]
fn audit_display_missing_optional_fields_remain_compatible() -> Result<(), Box<dyn Error>> {
    let mut test_store = audit_display_fixture(None, None)?;
    let rows = test_store.store.list_audit_rows_filtered(
        "lk_proj_test",
        &AuditListFilter { limit: 10, ..AuditListFilter::default() },
    )?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.secret_name.is_none() && row.command.is_none()));
    assert_eq!(test_store.store.list_audit_rows_since("lk_proj_test", "lk_prof_test", 0)?, rows);
    let verification = test_store.store.verify_audit_chain_read_only("lk_proj_test", &[42; 32])?;
    assert!(verification.hmac_ok);
    assert_eq!(verification.rows_verified, 2);
    assert_eq!(test_store.store.verify_audit_chain_and_append("lk_proj_test", &[42; 32], 300)?, 2);
    Ok(())
}

fn imported_audit_row(
    sequence: u64,
    previous_hmac: [u8; AUDIT_HMAC_LEN],
    hmac: [u8; AUDIT_HMAC_LEN],
) -> ImportedAuditChainRow {
    ImportedAuditChainRow { sequence, previous_hmac, hmac }
}

#[test]
fn imported_audit_chain_verifier_accepts_structural_chain() -> Result<(), Box<dyn Error>> {
    let first_hmac = [1_u8; AUDIT_HMAC_LEN];
    let second_hmac = [2_u8; AUDIT_HMAC_LEN];
    let rows = [
        imported_audit_row(1, [0; AUDIT_HMAC_LEN], first_hmac),
        imported_audit_row(2, first_hmac, second_hmac),
    ];

    let verified = verify_imported_audit_chain_structure(&rows, 2, &second_hmac)?;

    assert_eq!(verified.rows_verified, 2);
    assert_eq!(verified.checkpoint_sequence, 2);
    Ok(())
}

#[test]
fn imported_audit_chain_verifier_rejects_structural_mutations() -> Result<(), Box<dyn Error>> {
    let first_hmac = [1_u8; AUDIT_HMAC_LEN];
    let second_hmac = [2_u8; AUDIT_HMAC_LEN];
    let third_hmac = [3_u8; AUDIT_HMAC_LEN];

    for (case, rows, checkpoint_sequence, checkpoint_hmac, expected_sequence, expected_reason) in [
        ("empty", vec![], 0, second_hmac, 1, "imported audit chain is empty"),
        (
            "sequence_gap",
            vec![
                imported_audit_row(1, [0; AUDIT_HMAC_LEN], first_hmac),
                imported_audit_row(3, first_hmac, third_hmac),
            ],
            3,
            third_hmac,
            2,
            "sequence gap or reordering",
        ),
        (
            "previous_hmac",
            vec![
                imported_audit_row(1, [0; AUDIT_HMAC_LEN], first_hmac),
                imported_audit_row(2, third_hmac, second_hmac),
            ],
            2,
            second_hmac,
            2,
            "previous_hmac mismatch",
        ),
        (
            "checkpoint_sequence",
            vec![
                imported_audit_row(1, [0; AUDIT_HMAC_LEN], first_hmac),
                imported_audit_row(2, first_hmac, second_hmac),
            ],
            3,
            second_hmac,
            2,
            "checkpoint_sequence mismatch",
        ),
        (
            "checkpoint_hmac",
            vec![
                imported_audit_row(1, [0; AUDIT_HMAC_LEN], first_hmac),
                imported_audit_row(2, first_hmac, second_hmac),
            ],
            2,
            third_hmac,
            2,
            "checkpoint_hmac mismatch",
        ),
    ] {
        match verify_imported_audit_chain_structure(&rows, checkpoint_sequence, &checkpoint_hmac) {
            Err(StoreError::AuditIntegrity { sequence, reason }) => {
                assert_eq!(sequence, expected_sequence, "case {case}");
                assert_eq!(reason, expected_reason, "case {case}");
            }
            Ok(verified) => {
                return Err(format!(
                    "{case}: mutated imported chain unexpectedly verified {verified:?}"
                )
                .into());
            }
            Err(other) => {
                return Err(format!("{case}: expected audit integrity error, got {other}").into());
            }
        }
    }

    Ok(())
}

#[test]
fn audited_secret_create_appends_hmac_chained_row() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "SET",
        "status": "SUCCESS",
        "secret_name": "DATABASE_URL",
        "profile_id": "lk_prof_test",
        "source": "user-local",
        "version": 1,
    });
    let audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action: "SET",
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: &metadata,
        timestamp: 100,
    };

    test_store.store.create_active_secret_with_audit(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
        Some(AuditContext { key: &[42; 32], write: &audit }),
    )?;

    let row = test_store.store.connection().query_row(
        "SELECT sequence, action, secret_name, previous_hmac, hmac, metadata_json
         FROM audit_log
         WHERE project_id = 'lk_proj_test'",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?.cast_unsigned(),
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, String>(5)?,
            ))
        },
    )?;

    assert_eq!(row.0, 1);
    assert_eq!(row.1, "SET");
    assert_eq!(row.2, "DATABASE_URL");
    assert_eq!(row.3, vec![0; 32]);
    assert_eq!(row.4.len(), 32);
    assert!(row.5.contains("\"secret_name\":\"DATABASE_URL\""));
    assert!(!row.5.contains("postgres://"));

    let verified =
        test_store.store.verify_audit_chain_and_append("lk_proj_test", &[42; 32], 200)?;
    assert_eq!(verified, 1);
    let audit_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(audit_rows, 2);
    let verify_metadata = test_store.store.connection().query_row(
        "SELECT metadata_json
         FROM audit_log
         WHERE project_id = 'lk_proj_test' AND action = 'AUDIT_VERIFY'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let verify_metadata: serde_json::Value = serde_json::from_str(&verify_metadata)?;
    assert_eq!(verify_metadata["check_names"], json!(["audit_hmac_chain"]));
    assert_eq!(verify_metadata["pass_count"], 1);
    assert_eq!(verify_metadata["warn_count"], 0);
    assert_eq!(verify_metadata["fail_count"], 0);
    assert_eq!(verify_metadata["skip_count"], 0);
    assert_eq!(verify_metadata["rows_verified"], 1);

    Ok(())
}

#[test]
fn audit_rows_since_filters_profile_and_timestamp() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let set_metadata = json!({
        "schema_version": 1,
        "action": "SET",
        "status": "SUCCESS",
        "secret_name": "DATABASE_URL",
        "profile_id": "lk_prof_test",
        "source": "user-local",
    });
    let doctor_metadata = json!({
        "schema_version": 1,
        "action": "DOCTOR",
        "status": "SUCCESS",
        "command": "doctor",
        "check_names": ["smoke"],
    });
    let rotate_metadata = json!({
        "schema_version": 1,
        "action": "ROTATE",
        "status": "SUCCESS",
        "secret_name": "DATABASE_URL",
        "profile_id": "lk_prof_test",
        "source": "user-local",
    });
    let set_audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action: "SET",
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: &set_metadata,
        timestamp: 100,
    };
    let project_audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: None,
        action: "DOCTOR",
        status: "SUCCESS",
        secret_name: None,
        command: Some("doctor"),
        metadata_json: &doctor_metadata,
        timestamp: 200,
    };
    let rotate_audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action: "ROTATE",
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: &rotate_metadata,
        timestamp: 300,
    };

    test_store.store.append_audit(&[42; 32], &set_audit)?;
    test_store.store.append_audit(&[42; 32], &project_audit)?;
    test_store.store.append_audit(&[42; 32], &rotate_audit)?;

    let rows = test_store.store.list_audit_rows_since("lk_proj_test", "lk_prof_test", 150)?;

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].sequence, 3);
    assert_eq!(rows[0].timestamp, 300);
    assert_eq!(rows[0].action, "ROTATE");
    assert_eq!(rows[0].secret_name.as_deref(), Some("DATABASE_URL"));
    Ok(())
}

#[test]
fn audit_verify_uses_each_rows_stored_schema_version() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let metadata = json!({
        "schema_version": 2,
        "action": "DOCTOR",
        "status": "SUCCESS",
        "command": "doctor",
    });
    let previous_hmac = [0_u8; AUDIT_HMAC_LEN];
    let input = AuditHmacInput {
        schema_version: 2,
        sequence: 1,
        timestamp: Timestamp::from_unix_nanos(100),
        project_id: Some("lk_proj_test"),
        profile_id: None,
        action: "DOCTOR",
        status: "SUCCESS",
        metadata_json: Some(&metadata),
        previous_hmac: Some(&previous_hmac),
    };
    let canonical = audit_hmac_v1_bytes(&input)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&[42; AUDIT_HMAC_LEN])?;
    mac.update(&canonical);
    let hmac = mac.finalize().into_bytes();
    let metadata_json = canonical_json_string(Some(&metadata));

    test_store.store.connection().execute(
        "INSERT INTO audit_log(
            project_id, sequence, schema_version, timestamp, profile_id, action,
            status, metadata_json, secret_name, command, previous_hmac, hmac
         )
         VALUES (?1, 1, 2, 100, NULL, 'DOCTOR', 'SUCCESS', ?2, NULL, 'doctor', ?3, ?4)",
        rusqlite::params![
            "lk_proj_test",
            metadata_json,
            previous_hmac.as_slice(),
            hmac.as_slice(),
        ],
    )?;

    let verified =
        test_store.store.verify_audit_chain_and_append("lk_proj_test", &[42; 32], 200)?;
    assert_eq!(verified, 1);
    let audit_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(audit_rows, 2);

    Ok(())
}

#[test]
fn audit_verify_reports_first_break_without_appending_success() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "SET",
        "status": "SUCCESS",
        "secret_name": "DATABASE_URL",
        "profile_id": "lk_prof_test",
        "source": "user-local",
        "version": 1,
    });
    let audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action: "SET",
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: &metadata,
        timestamp: 100,
    };

    test_store.store.append_audit(&[42; 32], &audit)?;
    test_store.store.connection().execute(
        "UPDATE audit_log SET action = 'DELETE'
         WHERE project_id = 'lk_proj_test' AND sequence = 1",
        [],
    )?;

    match test_store.store.verify_audit_chain_and_append("lk_proj_test", &[42; 32], 200) {
        Err(StoreError::AuditIntegrity { sequence, reason }) => {
            assert_eq!(sequence, 1);
            assert_eq!(reason, "row hmac mismatch");
        }
        Ok(verified) => {
            return Err(format!("tampered row unexpectedly verified {verified} rows").into());
        }
        Err(other) => return Err(format!("expected audit integrity error, got {other}").into()),
    }
    let audit_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(audit_rows, 1);

    Ok(())
}

#[test]
fn audit_verify_flags_appended_chain_row_and_link_mutations() -> Result<(), Box<dyn Error>> {
    for (case, mutation_sql, expected_sequence, expected_reason) in [
        (
            "row_hmac",
            "UPDATE audit_log SET status = 'FAILED'
             WHERE project_id = 'lk_proj_test' AND sequence = 2",
            2,
            "row hmac mismatch",
        ),
        (
            "previous_hmac",
            "UPDATE audit_log SET previous_hmac = zeroblob(32)
             WHERE project_id = 'lk_proj_test' AND sequence = 2",
            2,
            "previous_hmac mismatch",
        ),
    ] {
        let mut test_store = open_initialized_store()?;
        insert_project_profile(&test_store.store)?;
        let set_metadata = json!({
            "schema_version": 1,
            "action": "SET",
            "status": "SUCCESS",
            "secret_name": "DATABASE_URL",
            "profile_id": "lk_prof_test",
            "source": "user-local",
        });
        let rotate_metadata = json!({
            "schema_version": 1,
            "action": "ROTATE",
            "status": "SUCCESS",
            "secret_name": "DATABASE_URL",
            "profile_id": "lk_prof_test",
            "source": "user-local",
        });
        let set_audit = AuditWrite {
            project_id: "lk_proj_test",
            profile_id: Some("lk_prof_test"),
            action: "SET",
            status: "SUCCESS",
            secret_name: Some("DATABASE_URL"),
            command: None,
            metadata_json: &set_metadata,
            timestamp: 100,
        };
        let rotate_audit = AuditWrite {
            project_id: "lk_proj_test",
            profile_id: Some("lk_prof_test"),
            action: "ROTATE",
            status: "SUCCESS",
            secret_name: Some("DATABASE_URL"),
            command: None,
            metadata_json: &rotate_metadata,
            timestamp: 200,
        };

        test_store.store.append_audit(&[42; 32], &set_audit)?;
        test_store.store.append_audit(&[42; 32], &rotate_audit)?;
        test_store.store.connection().execute(mutation_sql, [])?;

        match test_store.store.verify_audit_chain_and_append("lk_proj_test", &[42; 32], 300) {
            Err(StoreError::AuditIntegrity { sequence, reason }) => {
                assert_eq!(sequence, expected_sequence, "case {case}");
                assert_eq!(reason, expected_reason, "case {case}");
            }
            Ok(verified) => {
                return Err(format!(
                    "{case}: tampered chain unexpectedly verified {verified} rows"
                )
                .into());
            }
            Err(other) => {
                return Err(format!("{case}: expected audit integrity error, got {other}").into());
            }
        }
        let audit_rows = test_store.store.connection().query_row(
            "SELECT COUNT(*) FROM audit_log WHERE project_id = 'lk_proj_test'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(audit_rows, 2, "case {case}");
    }

    Ok(())
}

#[test]
fn rolled_back_transaction_leaves_no_audit_row_or_sequence_gap() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let metadata = json!({
        "schema_version": 1,
        "action": "SET",
        "status": "SUCCESS",
        "secret_name": "DATABASE_URL",
        "profile_id": "lk_prof_test",
        "source": "user-local",
    });
    let write = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action: "SET",
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: &metadata,
        timestamp: 100,
    };

    {
        let connection = test_store.store.connection_mut();
        let transaction = connection.transaction()?;
        append_audit(&transaction, &[42; 32], &write)?;
        // Drop the transaction without commit; rusqlite rolls it back.
    }

    let after_rollback: i64 = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(after_rollback, 0, "rolled-back tx must not leave an audit row");

    test_store.store.append_audit(&[42; 32], &write)?;

    let landed_sequence = test_store
        .store
        .connection()
        .query_row("SELECT sequence FROM audit_log WHERE project_id = 'lk_proj_test'", [], |row| {
            row.get::<_, i64>(0)
        })?
        .cast_unsigned();
    assert_eq!(
        landed_sequence, 1,
        "next successful append must reuse sequence 1, not skip past the rolled-back attempt"
    );

    Ok(())
}

#[test]
fn data_change_failure_inside_audit_tx_drops_audit_row_atomically() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let metadata = json!({
        "schema_version": 1,
        "action": "SET",
        "status": "SUCCESS",
        "secret_name": "DATABASE_URL",
        "profile_id": "lk_prof_test",
        "source": "user-local",
    });
    let write = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action: "SET",
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: &metadata,
        timestamp: 100,
    };

    {
        let connection = test_store.store.connection_mut();
        let transaction = connection.transaction()?;
        append_audit(&transaction, &[42; 32], &write)?;
        // Force a data-change failure inside the same tx via a foreign-key
        // violation; the `?` would propagate in production code and the
        // outer scope would drop the tx without commit.
        let result = transaction.execute(
            "INSERT INTO secrets(
               id, project_id, profile_id, name, source, origin, required,
               current_version, state, created_at, updated_at
             )
             VALUES (
               'lk_sec_orphan', 'lk_proj_missing', 'lk_prof_test', 'DATABASE_URL',
               'user-local', 'manual', 0, 1, 'active', 1, 1
             )",
            [],
        );
        assert!(result.is_err(), "FK violation must surface as a SQLite error");
        // Drop without commit.
    }

    let audit_rows: i64 = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(audit_rows, 0, "data-change failure must roll back the audit row in the same tx");

    let secret_rows: i64 = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM secrets WHERE id = 'lk_sec_orphan'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(secret_rows, 0, "the failed secret insert must not have persisted either");

    Ok(())
}

#[test]
fn append_audit_rejects_metadata_json_above_64_kib_cap() -> Result<(), Box<dyn std::error::Error>> {
    use crate::AUDIT_METADATA_JSON_LIMIT;

    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    // Build a metadata payload whose canonical JSON crosses the cap. The
    // outer structure stays small; one filler string carries the bulk.
    let oversized: String = "x".repeat(AUDIT_METADATA_JSON_LIMIT + 256);
    let metadata = json!({
        "schema_version": 1,
        "action": "SCAN",
        "status": "SUCCESS",
        "command": "scan",
        "scope": "repo",
        "known_value_coverage": "full",
        "finding_counts": {"high": 0},
        "pattern_only": false,
        "diagnostics": oversized,
    });
    let audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: None,
        action: "SCAN",
        status: "SUCCESS",
        secret_name: None,
        command: Some("scan"),
        metadata_json: &metadata,
        timestamp: 100,
    };
    let result = test_store.store.append_audit(&[42; 32], &audit);
    let Err(error) = result else {
        return Err("oversized metadata must be rejected".into());
    };
    let StoreError::AuditMetadataTooLarge { action, actual, limit } = error else {
        return Err(format!("expected AuditMetadataTooLarge, got {error:?}").into());
    };
    assert_eq!(action, "SCAN");
    assert_eq!(limit, AUDIT_METADATA_JSON_LIMIT);
    assert!(actual > AUDIT_METADATA_JSON_LIMIT);

    let count: i64 = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0, "rejected rows must not be persisted");

    let exit_code = StoreError::AuditMetadataTooLarge {
        action: "SCAN".to_owned(),
        actual: AUDIT_METADATA_JSON_LIMIT + 1,
        limit: AUDIT_METADATA_JSON_LIMIT,
    }
    .locket_error()
    .exit_code();
    assert_eq!(exit_code, locket_core::LocketError::MetadataInvalid.exit_code());

    Ok(())
}

#[test]
fn append_audit_accepts_metadata_json_at_or_below_cap() -> Result<(), Box<dyn std::error::Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    // Aim for a payload whose canonical JSON stays under the cap. Outer
    // structure adds a few hundred bytes; a 60-KiB filler comfortably
    // lands inside 64 KiB.
    let comfortable: String = "y".repeat(60 * 1024);
    let metadata = json!({
        "schema_version": 1,
        "action": "SCAN",
        "status": "SUCCESS",
        "command": "scan",
        "scope": "repo",
        "known_value_coverage": "full",
        "finding_counts": {"high": 0},
        "pattern_only": false,
        "diagnostics": comfortable,
    });
    let audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: None,
        action: "SCAN",
        status: "SUCCESS",
        secret_name: None,
        command: Some("scan"),
        metadata_json: &metadata,
        timestamp: 200,
    };
    test_store.store.append_audit(&[42; 32], &audit)?;
    let count: i64 = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn append_audit_rejects_metadata_json_shape_mismatches() -> Result<(), Box<dyn Error>> {
    struct Case {
        name: &'static str,
        metadata: serde_json::Value,
        action: &'static str,
        status: &'static str,
        profile_id: Option<&'static str>,
        secret_name: Option<&'static str>,
        command: Option<&'static str>,
        expected_reason: &'static str,
    }

    let cases = [
        Case {
            name: "non_object",
            metadata: json!(["not", "an", "object"]),
            action: "DOCTOR",
            status: "SUCCESS",
            profile_id: None,
            secret_name: None,
            command: None,
            expected_reason: "metadata_json must be an object",
        },
        Case {
            name: "missing_status",
            metadata: json!({
                "schema_version": 1,
                "action": "DOCTOR",
            }),
            action: "DOCTOR",
            status: "SUCCESS",
            profile_id: None,
            secret_name: None,
            command: None,
            expected_reason: "status must be a string",
        },
        Case {
            name: "mismatched_action",
            metadata: json!({
                "schema_version": 1,
                "action": "SCAN",
                "status": "SUCCESS",
            }),
            action: "DOCTOR",
            status: "SUCCESS",
            profile_id: None,
            secret_name: None,
            command: None,
            expected_reason: "action must match audit row",
        },
        Case {
            name: "missing_command_mirror",
            metadata: json!({
                "schema_version": 1,
                "action": "DOCTOR",
                "status": "SUCCESS",
            }),
            action: "DOCTOR",
            status: "SUCCESS",
            profile_id: None,
            secret_name: None,
            command: Some("doctor"),
            expected_reason: "command convenience column must be mirrored",
        },
        Case {
            name: "null_absent_command",
            metadata: json!({
                "schema_version": 1,
                "action": "DOCTOR",
                "status": "SUCCESS",
                "command": null,
            }),
            action: "DOCTOR",
            status: "SUCCESS",
            profile_id: None,
            secret_name: None,
            command: None,
            expected_reason: "command must be omitted, not null",
        },
        Case {
            name: "unknown_v1_field",
            metadata: json!({
                "schema_version": 1,
                "action": "DOCTOR",
                "status": "SUCCESS",
                "check_names": ["smoke"],
                "unexpected": true,
            }),
            action: "DOCTOR",
            status: "SUCCESS",
            profile_id: None,
            secret_name: None,
            command: None,
            expected_reason: "unknown field unexpected",
        },
        Case {
            name: "missing_action_family_field",
            metadata: json!({
                "schema_version": 1,
                "action": "SET",
                "status": "SUCCESS",
                "secret_name": "DATABASE_URL",
                "profile_id": "lk_prof_test",
            }),
            action: "SET",
            status: "SUCCESS",
            profile_id: Some("lk_prof_test"),
            secret_name: Some("DATABASE_URL"),
            command: None,
            expected_reason: "missing required field source",
        },
        Case {
            name: "schema_version_zero",
            metadata: json!({
                "schema_version": 0,
                "action": "DOCTOR",
                "status": "SUCCESS",
            }),
            action: "DOCTOR",
            status: "SUCCESS",
            profile_id: None,
            secret_name: None,
            command: None,
            expected_reason: "schema_version must be at least 1",
        },
        Case {
            name: "schema_version_missing",
            metadata: json!({
                "action": "DOCTOR",
                "status": "SUCCESS",
            }),
            action: "DOCTOR",
            status: "SUCCESS",
            profile_id: None,
            secret_name: None,
            command: None,
            expected_reason: "schema_version must be an integer",
        },
        Case {
            name: "secret_name_mismatched",
            metadata: json!({
                "schema_version": 1,
                "action": "REVEAL",
                "status": "SUCCESS",
                "secret_name": "OTHER",
                "profile_id": "lk_prof_test",
                "source": "user-local",
            }),
            action: "REVEAL",
            status: "SUCCESS",
            profile_id: Some("lk_prof_test"),
            secret_name: Some("DATABASE_URL"),
            command: None,
            expected_reason: "secret_name must match audit row",
        },
        Case {
            name: "secret_name_null_when_present",
            metadata: json!({
                "schema_version": 1,
                "action": "REVEAL",
                "status": "SUCCESS",
                "secret_name": null,
                "profile_id": "lk_prof_test",
                "source": "user-local",
            }),
            action: "REVEAL",
            status: "SUCCESS",
            profile_id: Some("lk_prof_test"),
            secret_name: Some("DATABASE_URL"),
            command: None,
            expected_reason: "secret_name must not be null",
        },
        Case {
            name: "command_wrong_type",
            metadata: json!({
                "schema_version": 1,
                "action": "DOCTOR",
                "status": "SUCCESS",
                "command": 42,
            }),
            action: "DOCTOR",
            status: "SUCCESS",
            profile_id: None,
            secret_name: None,
            command: Some("doctor"),
            expected_reason: "command must be a string",
        },
        Case {
            name: "audit_verify_missing_skip_count",
            metadata: json!({
                "schema_version": 1,
                "action": "AUDIT_VERIFY",
                "status": "SUCCESS",
                "check_names": ["audit_hmac_chain"],
                "pass_count": 1,
                "warn_count": 0,
                "fail_count": 0,
            }),
            action: "AUDIT_VERIFY",
            status: "SUCCESS",
            profile_id: None,
            secret_name: None,
            command: None,
            expected_reason: "missing required field skip_count",
        },
    ];

    for case in cases {
        let mut test_store = open_initialized_store()?;
        insert_project_profile(&test_store.store)?;
        let audit = AuditWrite {
            project_id: "lk_proj_test",
            profile_id: case.profile_id,
            action: case.action,
            status: case.status,
            secret_name: case.secret_name,
            command: case.command,
            metadata_json: &case.metadata,
            timestamp: 100,
        };

        let error = match test_store.store.append_audit(&[42; 32], &audit) {
            Ok(()) => {
                return Err(format!("{}: invalid metadata must be rejected", case.name).into());
            }
            Err(error) => error,
        };
        let StoreError::AuditMetadataInvalid { action, reason } = error else {
            return Err(format!("{}: expected AuditMetadataInvalid", case.name).into());
        };
        assert_eq!(action, audit.action, "case {}", case.name);
        assert!(
            reason.contains(case.expected_reason),
            "case {}: expected reason to contain {:?}, got {reason:?}",
            case.name,
            case.expected_reason
        );
        assert_eq!(
            StoreError::AuditMetadataInvalid { action, reason }.locket_error(),
            locket_core::LocketError::MetadataInvalid,
            "case {}",
            case.name
        );
    }

    Ok(())
}

#[test]
fn append_audit_allows_unknown_metadata_fields_after_schema_bump() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let metadata = json!({
        "schema_version": 2,
        "action": "DOCTOR",
        "status": "SUCCESS",
        "check_names": ["smoke"],
        "new_schema_field": "accepted by schema bump",
    });
    let audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: None,
        action: "DOCTOR",
        status: "SUCCESS",
        secret_name: None,
        command: None,
        metadata_json: &metadata,
        timestamp: 100,
    };

    test_store.store.append_audit(&[42; 32], &audit)?;

    let count: i64 = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn audit_verify_fails_when_stored_schema_version_is_mutated() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let metadata = json!({
        "schema_version": 1,
        "action": "DOCTOR",
        "status": "SUCCESS",
        "command": "doctor",
        "check_names": ["smoke"],
    });
    let audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: None,
        action: "DOCTOR",
        status: "SUCCESS",
        secret_name: None,
        command: Some("doctor"),
        metadata_json: &metadata,
        timestamp: 100,
    };
    test_store.store.append_audit(&[42; 32], &audit)?;

    test_store.store.connection().execute(
        "UPDATE audit_log SET schema_version = 99 WHERE project_id = 'lk_proj_test'",
        [],
    )?;

    let result = test_store.store.verify_audit_chain_and_append("lk_proj_test", &[42; 32], 200);
    let Err(crate::StoreError::AuditIntegrity { sequence, reason }) = result else {
        return Err("mutated schema_version must fail HMAC verification".into());
    };
    assert_eq!(sequence, 1);
    assert!(reason.contains("hmac mismatch"), "expected 'hmac mismatch' in reason, got {reason:?}");
    Ok(())
}

#[test]
fn audit_verify_processes_each_row_with_its_own_stored_schema_version() -> Result<(), Box<dyn Error>>
{
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let previous_hmac_v1 = [0_u8; AUDIT_HMAC_LEN];
    let metadata_v1 = json!({"schema_version": 1, "action": "SET", "status": "SUCCESS"});
    let input_v1 = AuditHmacInput {
        schema_version: 1,
        sequence: 1,
        timestamp: Timestamp::from_unix_nanos(100),
        project_id: Some("lk_proj_test"),
        profile_id: None,
        action: "SET",
        status: "SUCCESS",
        metadata_json: Some(&metadata_v1),
        previous_hmac: Some(&previous_hmac_v1),
    };
    let canonical_v1 = audit_hmac_v1_bytes(&input_v1)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&[42; AUDIT_HMAC_LEN])?;
    mac.update(&canonical_v1);
    let hmac_v1: Vec<u8> = mac.finalize().into_bytes().to_vec();
    let metadata_v1_json = canonical_json_string(Some(&metadata_v1));
    test_store.store.connection().execute(
        "INSERT INTO audit_log(
            project_id, sequence, schema_version, timestamp, profile_id, action,
            status, metadata_json, secret_name, command, previous_hmac, hmac
         )
         VALUES (?1, 1, 1, 100, NULL, 'SET', 'SUCCESS', ?2, NULL, NULL, ?3, ?4)",
        rusqlite::params![
            "lk_proj_test",
            metadata_v1_json,
            previous_hmac_v1.as_slice(),
            hmac_v1.as_slice()
        ],
    )?;

    let metadata_v2 = json!({"schema_version": 2, "action": "GET", "status": "SUCCESS"});
    let input_v2 = AuditHmacInput {
        schema_version: 2,
        sequence: 2,
        timestamp: Timestamp::from_unix_nanos(200),
        project_id: Some("lk_proj_test"),
        profile_id: None,
        action: "GET",
        status: "SUCCESS",
        metadata_json: Some(&metadata_v2),
        previous_hmac: Some(hmac_v1.as_slice().try_into().map_err(|_| "bad v1 hmac len")?),
    };
    let canonical_v2 = audit_hmac_v1_bytes(&input_v2)?;
    let mut mac2 = Hmac::<Sha256>::new_from_slice(&[42; AUDIT_HMAC_LEN])?;
    mac2.update(&canonical_v2);
    let hmac_v2: Vec<u8> = mac2.finalize().into_bytes().to_vec();
    let metadata_v2_json = canonical_json_string(Some(&metadata_v2));
    test_store.store.connection().execute(
        "INSERT INTO audit_log(
            project_id, sequence, schema_version, timestamp, profile_id, action,
            status, metadata_json, secret_name, command, previous_hmac, hmac
         )
         VALUES (?1, 2, 2, 200, NULL, 'GET', 'SUCCESS', ?2, NULL, NULL, ?3, ?4)",
        rusqlite::params!["lk_proj_test", metadata_v2_json, hmac_v1.as_slice(), hmac_v2.as_slice()],
    )?;

    let verified =
        test_store.store.verify_audit_chain_and_append("lk_proj_test", &[42; 32], 300)?;
    assert_eq!(verified, 2);
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn append_audit_enforces_required_fields_for_each_action_family() -> Result<(), Box<dyn Error>> {
    struct Family {
        action: &'static str,
        profile_id: Option<&'static str>,
        secret_name: Option<&'static str>,
        command: Option<&'static str>,
        complete: serde_json::Value,
        drop_field: &'static str,
    }

    let families = [
        // Secret value lifecycle (DELETE/IMPORT new in arm).
        Family {
            action: "DELETE",
            profile_id: Some("lk_prof_test"),
            secret_name: Some("DATABASE_URL"),
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "DELETE",
                "status": "SUCCESS",
                "secret_name": "DATABASE_URL",
                "profile_id": "lk_prof_test",
                "source": "user-local",
            }),
            drop_field: "source",
        },
        // Secret value access.
        Family {
            action: "GET",
            profile_id: Some("lk_prof_test"),
            secret_name: Some("DATABASE_URL"),
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "GET",
                "status": "SUCCESS",
                "secret_name": "DATABASE_URL",
                "profile_id": "lk_prof_test",
                "source": "user-local",
                "access_mode": "stdout",
            }),
            drop_field: "access_mode",
        },
        // Scan/redaction.
        Family {
            action: "SCAN",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "SCAN",
                "status": "SUCCESS",
                "scope": "repo",
                "known_value_coverage": "full",
                "finding_counts": {"high": 0},
                "pattern_only": false,
            }),
            drop_field: "scope",
        },
        // Project/profile/policy/config/bootstrap: TRUST_ROOT representative.
        Family {
            action: "TRUST_ROOT",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "TRUST_ROOT",
                "status": "SUCCESS",
                "root_hash": "abcd",
                "trust_operation": "add",
            }),
            drop_field: "trust_operation",
        },
        Family {
            action: "POLICY_UPDATE",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "POLICY_UPDATE",
                "status": "SUCCESS",
                "policy_name": "deploy",
                "change_kind": "create",
            }),
            drop_field: "change_kind",
        },
        Family {
            action: "CONFIG_UPDATE",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "CONFIG_UPDATE",
                "status": "SUCCESS",
                "config_path_hash": "hh",
                "config_keys": ["safe_mode"],
            }),
            drop_field: "config_keys",
        },
        Family {
            action: "EXAMPLE_EMIT",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "EXAMPLE_EMIT",
                "status": "SUCCESS",
                "example_path_kind": "repo-relative",
                "example_path_hash": "hh",
                "secret_name_count": 3,
            }),
            drop_field: "example_path_hash",
        },
        Family {
            action: "BOOTSTRAP",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "BOOTSTRAP",
                "status": "SUCCESS",
                "project_id": "lk_proj_test",
                "default_profile_id": "lk_prof_test",
                "recovery_code_displayed": true,
            }),
            drop_field: "recovery_code_displayed",
        },
        // Directory grants.
        Family {
            action: "ALLOW_DIRECTORY",
            profile_id: Some("lk_prof_test"),
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "ALLOW_DIRECTORY",
                "status": "SUCCESS",
                "project_id": "lk_proj_test",
                "profile_id": "lk_prof_test",
                "root_hash": "rh",
                "directory_hash": "dh",
                "grant_scope": "this-only",
            }),
            drop_field: "grant_scope",
        },
        // Agent/grants.
        Family {
            action: "UNLOCK",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "UNLOCK",
                "status": "SUCCESS",
                "client_kind": "cli",
                "grant_actions": ["GET"],
                "ttl_seconds": 600,
            }),
            drop_field: "grant_actions",
        },
        // Passkeys/automation clients: passkey arm.
        Family {
            action: "PASSKEY_AUTH",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "PASSKEY_AUTH",
                "status": "SUCCESS",
                "passkey_id": "pk_1",
                "credential_id_prefix": "abc12345",
                "auth_result": "success",
            }),
            drop_field: "credential_id_prefix",
        },
        // Passkeys/automation clients: client arm.
        Family {
            action: "CLIENT_AUTH",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "CLIENT_AUTH",
                "status": "SUCCESS",
                "client_id": "cl_1",
                "request_id": "req_1",
                "auth_result": "success",
            }),
            drop_field: "request_id",
        },
        // Team/device/recovery: invite.
        Family {
            action: "TEAM_INVITE",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "TEAM_INVITE",
                "status": "SUCCESS",
                "team_id": "team_1",
                "member_id": "mem_1",
            }),
            drop_field: "member_id",
        },
        // Team/device/recovery: recover.
        Family {
            action: "RECOVER",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "RECOVER",
                "status": "SUCCESS",
                "device_id": "dev_1",
            }),
            drop_field: "device_id",
        },
        // Diagnostics: HOOK_INSTALL (DOCTOR is exercised elsewhere).
        Family {
            action: "HOOK_INSTALL",
            profile_id: None,
            secret_name: None,
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "HOOK_INSTALL",
                "status": "SUCCESS",
                "hook_path_kind": "repo-relative",
                "hook_path_hash": "hh",
            }),
            drop_field: "hook_path_kind",
        },
        // Reference resolution by the agent: RESOLVE_REFERENCE requires
        // secret_name, profile_id, and source so audit chains carry the
        // resolved-source provenance for every `lk://` lookup.
        Family {
            action: "RESOLVE_REFERENCE",
            profile_id: Some("lk_prof_test"),
            secret_name: Some("DATABASE_URL"),
            command: None,
            complete: json!({
                "schema_version": 1,
                "action": "RESOLVE_REFERENCE",
                "status": "SUCCESS",
                "secret_name": "DATABASE_URL",
                "profile_id": "lk_prof_test",
                "source": "user-local",
                "policy": "deploy",
                "profile_name": "dev",
                "selected_version": 1,
            }),
            drop_field: "source",
        },
    ];

    for family in &families {
        // Accept: complete metadata writes successfully.
        let mut test_store = open_initialized_store()?;
        insert_project_profile(&test_store.store)?;
        let audit = AuditWrite {
            project_id: "lk_proj_test",
            profile_id: family.profile_id,
            action: family.action,
            status: "SUCCESS",
            secret_name: family.secret_name,
            command: family.command,
            metadata_json: &family.complete,
            timestamp: 100,
        };
        test_store.store.append_audit(&[42; 32], &audit).map_err(|error| {
            format!("{}: full metadata must be accepted: {error:?}", family.action)
        })?;

        // Reject: dropping the chosen required field surfaces a clear reason.
        let mut without_field =
            family.complete.as_object().ok_or("family.complete must be a JSON object")?.clone();
        without_field.remove(family.drop_field);
        let metadata_missing = serde_json::Value::Object(without_field);
        let mut reject_store = open_initialized_store()?;
        insert_project_profile(&reject_store.store)?;
        let audit_missing = AuditWrite {
            project_id: "lk_proj_test",
            profile_id: family.profile_id,
            action: family.action,
            status: "SUCCESS",
            secret_name: family.secret_name,
            command: family.command,
            metadata_json: &metadata_missing,
            timestamp: 200,
        };
        let error = match reject_store.store.append_audit(&[42; 32], &audit_missing) {
            Ok(()) => {
                return Err(format!(
                    "{}: dropping {} should be rejected",
                    family.action, family.drop_field
                )
                .into());
            }
            Err(error) => error,
        };
        let StoreError::AuditMetadataInvalid { action, reason } = error else {
            return Err(
                format!("{}: expected AuditMetadataInvalid, got {error:?}", family.action).into()
            );
        };
        assert_eq!(action, family.action);
        assert!(
            reason.contains(family.drop_field),
            "{}: expected reason to mention {:?}, got {reason:?}",
            family.action,
            family.drop_field
        );
    }

    Ok(())
}
