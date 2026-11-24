//! Tests for `Store::mark_invite_accepted` (invite-replay-protect).
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use std::error::Error;

use crate::error::StoreError;

use super::{insert_project_profile, open_initialized_store, test_device};

fn insert_team_with_pending_invite(
    store: &crate::Store,
    invite_id: &str,
) -> Result<(), Box<dyn Error>> {
    let connection = store.connection();
    connection.execute(
        "INSERT INTO teams(id, project_id, name, created_at, updated_at)
         VALUES ('lk_team_test', 'lk_proj_test', 'app-team', 1, 1)",
        [],
    )?;
    connection.execute(
        "INSERT INTO team_members(id, team_id, display_name, role, joined_at)
         VALUES ('lk_member_test', 'lk_team_test', 'Alice', 'owner', 1)",
        [],
    )?;
    connection.execute(
        "INSERT INTO team_invites(
           id, team_id, issuer_member_id, recipient_device_fingerprint, role, profiles_json,
           nonce, created_at, expires_at
         )
         VALUES (
           ?1, 'lk_team_test', 'lk_member_test', 'recipient-fp',
           'developer', '[\"dev\"]', zeroblob(24), 1, 1000
         )",
        [invite_id],
    )?;
    Ok(())
}

#[test]
fn mark_invite_accepted_first_call_sets_accepted_at() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_first")?;

    test.store.mark_invite_accepted("lk_invite_first", 500)?;

    let accepted_at: Option<i64> = test.store.connection().query_row(
        "SELECT accepted_at FROM team_invites WHERE id = 'lk_invite_first'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(accepted_at, Some(500));
    Ok(())
}

#[test]
fn mark_invite_accepted_second_call_returns_replay_detected() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_replay")?;

    test.store.mark_invite_accepted("lk_invite_replay", 500)?;

    let second = test.store.mark_invite_accepted("lk_invite_replay", 600);
    let Err(StoreError::InviteReplayDetected { invite_id }) = second else {
        panic!("expected InviteReplayDetected, got {second:?}");
    };
    assert_eq!(invite_id, "lk_invite_replay");

    // The original accepted_at must not be overwritten by the replay.
    let accepted_at: Option<i64> = test.store.connection().query_row(
        "SELECT accepted_at FROM team_invites WHERE id = 'lk_invite_replay'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(accepted_at, Some(500));
    Ok(())
}

#[test]
fn mark_invite_accepted_revoked_invite_returns_replay_detected() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_revoked")?;

    test.store
        .connection()
        .execute("UPDATE team_invites SET revoked_at = 700 WHERE id = 'lk_invite_revoked'", [])?;

    let result = test.store.mark_invite_accepted("lk_invite_revoked", 800);
    let Err(StoreError::InviteReplayDetected { invite_id }) = result else {
        panic!("expected InviteReplayDetected on revoked invite, got {result:?}");
    };
    assert_eq!(invite_id, "lk_invite_revoked");
    Ok(())
}

#[test]
fn mark_invite_accepted_unknown_invite_returns_invite_not_found() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;

    let result = test.store.mark_invite_accepted("lk_invite_nope", 500);
    let Err(StoreError::InviteNotFound { invite_id }) = result else {
        panic!("expected InviteNotFound, got {result:?}");
    };
    assert_eq!(invite_id, "lk_invite_nope");
    Ok(())
}

#[test]
fn revoke_team_invite_first_call_sets_revoked_at() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_revoke_first")?;

    let mut store = test.store;
    store.revoke_team_invite("lk_invite_revoke_first", 900, None)?;

    let revoked_at: Option<i64> = store.connection().query_row(
        "SELECT revoked_at FROM team_invites WHERE id = 'lk_invite_revoke_first'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(revoked_at, Some(900));
    Ok(())
}

#[test]
fn revoke_team_invite_second_call_returns_replay_detected() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_revoke_replay")?;

    let mut store = test.store;
    store.revoke_team_invite("lk_invite_revoke_replay", 900, None)?;

    let second = store.revoke_team_invite("lk_invite_revoke_replay", 901, None);
    let Err(StoreError::InviteReplayDetected { invite_id }) = second else {
        panic!("expected InviteReplayDetected, got {second:?}");
    };
    assert_eq!(invite_id, "lk_invite_revoke_replay");
    Ok(())
}

#[test]
fn accept_team_invite_first_call_sets_accepted_at() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_accept_tx")?;

    let mut store = test.store;
    store.accept_team_invite("lk_invite_accept_tx", 700, None)?;

    let accepted_at: Option<i64> = store.connection().query_row(
        "SELECT accepted_at FROM team_invites WHERE id = 'lk_invite_accept_tx'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(accepted_at, Some(700));
    Ok(())
}

#[test]
fn team_member_profiles_round_trip_through_member_lookup() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_scope")?;
    test.store.connection().execute(
        "INSERT INTO team_members(id, team_id, display_name, role, joined_at)
         VALUES (
           'lk_member_recipient', 'lk_team_test', 'Recipient', 'developer', 700
         )",
        [],
    )?;

    test.store.set_team_member_profiles(
        "lk_member_recipient",
        &["dev".to_owned(), "qa".to_owned(), "dev".to_owned()],
    )?;
    let member =
        test.store.get_team_member("lk_team_test", "lk_member_recipient")?.ok_or("member")?;

    assert_eq!(member.profiles, Some(vec!["dev".to_owned(), "qa".to_owned()]));
    Ok(())
}

#[test]
fn invite_replay_detected_maps_to_locket_replay_detected() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_mapping")?;
    test.store.mark_invite_accepted("lk_invite_mapping", 500)?;

    let second = test.store.mark_invite_accepted("lk_invite_mapping", 600);
    let Err(error) = second else {
        panic!("expected error, got Ok");
    };
    assert_eq!(error.locket_error(), locket_core::LocketError::ReplayDetected);
    Ok(())
}

#[test]
fn active_team_member_can_be_found_by_device_id() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    let device = test_device();
    test.store.insert_device(&device)?;
    test.store.connection().execute(
        "INSERT INTO teams(id, project_id, name, created_at, updated_at)
         VALUES ('lk_team_lookup', 'lk_proj_test', 'lookup-team', 1, 1)",
        [],
    )?;
    test.store.connection().execute(
        "INSERT INTO team_members(id, team_id, device_id, display_name, role, joined_at)
         VALUES ('lk_member_lookup', 'lk_team_lookup', 'lk_dev_test', 'Alice', 'maintainer', 2)",
        [],
    )?;

    let member = test
        .store
        .get_active_team_member_by_device("lk_team_lookup", "lk_dev_test")?
        .ok_or("member missing")?;
    assert_eq!(member.id, "lk_member_lookup");
    assert_eq!(member.role, "maintainer");
    assert_eq!(member.profiles, None);
    assert_eq!(member.trusted_device_count, 1);

    test.store
        .connection()
        .execute("UPDATE team_members SET removed_at = 3 WHERE id = 'lk_member_lookup'", [])?;
    assert!(
        test.store.get_active_team_member_by_device("lk_team_lookup", "lk_dev_test")?.is_none()
    );
    Ok(())
}

#[test]
fn composed_invite_acceptance_rolls_back_membership_and_profile_updates()
-> Result<(), Box<dyn Error>> {
    let mut test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    test.store.insert_device(&test_device())?;
    insert_team_with_pending_invite(&test.store, "atomic-invite")?;
    let result = test.store.with_atomic_write::<(), StoreError>(|store| {
        store
            .connection()
            .execute("UPDATE profiles SET name = 'changed' WHERE id = 'lk_prof_test'", [])?;
        store.accept_team_invite_with_member_scope(
            "atomic-invite",
            100,
            "accepted-member",
            "lk_dev_test",
            "local",
            "developer",
            &["dev".to_owned()],
            None,
        )?;
        Err(StoreError::Sqlite(rusqlite::Error::InvalidQuery))
    });
    assert!(result.is_err());
    assert!(
        test.store.get_team_invite("lk_team_test", "atomic-invite")?.unwrap().accepted_at.is_none()
    );
    assert!(test.store.get_profile_by_name("lk_proj_test", "default")?.is_some());
    assert!(test.store.get_team_member("lk_team_test", "accepted-member")?.is_none());
    Ok(())
}
