//! Shared local user-verification gates for sensitive CLI actions.

use locket_core::LocketError;
use locket_platform::{LocalUserVerificationMethod, LocalUserVerificationRequest, PlatformError};
use serde::Serialize;

use crate::commands::config::spec::{
    config_get_value, read_user_config, validate_config_key, validate_stored_config_value,
};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{CliError, typed_cli_error};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct UserVerificationAudit {
    pub required: bool,
    pub satisfied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<LocalUserVerificationMethod>,
}

impl UserVerificationAudit {
    #[must_use]
    pub const fn not_required() -> Self {
        Self { required: false, satisfied: false, method: None }
    }

    #[must_use]
    pub const fn failed_required() -> Self {
        Self { required: true, satisfied: false, method: None }
    }

    #[must_use]
    pub const fn satisfied(method: LocalUserVerificationMethod) -> Self {
        Self { required: true, satisfied: true, method: Some(method) }
    }
}

pub fn require_user_verification(
    context: &RuntimeContext,
    action: &'static str,
    reason: impl Into<String>,
) -> Result<UserVerificationAudit, CliError> {
    let verification = context
        .user_verifier
        .verify_user(&LocalUserVerificationRequest::new(action, reason))
        .map_err(|error| {
            let message = match error {
                PlatformError::LocalUserVerificationUnavailable => {
                    if cfg!(target_os = "linux") {
                        format!(
                            "{action}: fresh local user verification is unavailable on this Linux build; \
                             Secret Service access cannot prove fresh consent. Ordinary vault unlock \
                             with keyring or passphrase remains supported"
                        )
                    } else {
                        format!(
                            "{action}: local user verification is unavailable; configure the OS \
                             authentication prompt (Touch ID/device password or Windows Hello) \
                             and retry in an interactive desktop session"
                        )
                    }
                }
                _ => format!("{action}: local user verification failed"),
            };
            typed_cli_error(
                LocketError::UserVerificationFailed,
                message,
            )
        })?;
    Ok(UserVerificationAudit::satisfied(verification.method))
}

pub fn configured_user_verification(
    context: &RuntimeContext,
    config_key: &'static str,
    action: &'static str,
    reason: impl Into<String>,
) -> Result<UserVerificationAudit, CliError> {
    if !user_verification_required(context, config_key)? {
        return Ok(UserVerificationAudit::not_required());
    }
    require_user_verification(context, action, reason)
}

fn user_verification_required(
    context: &RuntimeContext,
    config_key: &'static str,
) -> Result<bool, CliError> {
    let spec = validate_config_key(config_key)?;
    let config = read_user_config(context)?;
    let Some(value) = config_get_value(&config, config_key) else {
        return Ok(false);
    };
    validate_stored_config_value(spec, value)?;
    Ok(value.as_bool().unwrap_or(false))
}
