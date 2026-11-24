//! Hard expiration checks and metadata-only expiry policy.

use locket_store::{SecretExpirationNotice, Store};

use crate::{
    CliError, NANOS_PER_SECOND, SecretMetadataFlags, metadata_invalid_error, now_unix_nanos,
    secret_not_found_error,
};

pub const SECRET_EXPIRED_MESSAGE: &str = "secret has expired; rotate or update expiry before use";
const EXPIRY_SCHEMA_VERSION: i64 = 7;
const NOTICE_WINDOW_NANOS: i64 = 7 * 86_400 * NANOS_PER_SECOND;

pub fn check_secret_expiry(store: &Store, secret_id: &str) -> Result<(), CliError> {
    if store.current_schema_version()?.is_none_or(|version| version < EXPIRY_SCHEMA_VERSION) {
        return Ok(());
    }
    let now = now_unix_nanos()?;
    if store
        .get_secret_expiry_policy(secret_id)?
        .and_then(|policy| policy.expires_at)
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(metadata_invalid_error(SECRET_EXPIRED_MESSAGE));
    }
    Ok(())
}

pub fn expiry_notices(
    store: &Store,
    project_id: &str,
    now: i64,
) -> Result<Vec<SecretExpirationNotice>, CliError> {
    if store.current_schema_version()?.is_none_or(|version| version < EXPIRY_SCHEMA_VERSION) {
        return Ok(Vec::new());
    }
    Ok(store.list_expiring_or_stale_secrets(Some(project_id), now, NOTICE_WINDOW_NANOS)?)
}

pub(super) fn update_expiry_policy(
    store: &Store,
    secret_id: &str,
    flags: &SecretMetadataFlags,
    timestamp: i64,
) -> Result<(), CliError> {
    if flags.expires_in.is_none() && flags.rotate_after_days.is_none() {
        return Ok(());
    }
    let not_found = || secret_not_found_error("secret not found");
    let mut policy = store.get_secret_expiry_policy(secret_id)?.ok_or_else(not_found)?;
    if let Some(duration) = &flags.expires_in {
        let expiration =
            i128::from(timestamp) + i128::from(duration.as_secs()) * i128::from(NANOS_PER_SECOND);
        policy.expires_at = Some(i64::try_from(expiration).map_err(|_| {
            metadata_invalid_error("expiry duration exceeds the supported timestamp range")
        })?);
    }
    if let Some(days) = flags.rotate_after_days {
        policy.rotate_after_days = Some(days);
    }
    if !store.set_secret_expiry_policy(secret_id, policy, timestamp)? {
        return Err(not_found());
    }
    Ok(())
}
