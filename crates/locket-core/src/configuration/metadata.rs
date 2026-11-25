//! Shared validation for user-visible metadata fields.

use thiserror::Error;

/// Secret-like finding types that make metadata unsafe to store.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MetadataPrivacyFinding {
    /// Metadata matched a provider-token shape.
    ProviderToken,
    /// Metadata matched a high-entropy token fallback.
    HighEntropy,
}

/// Metadata validation failure with no secret value payloads.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum MetadataValidationError {
    /// The field contains control characters, NUL bytes, or terminal escapes.
    #[error("metadata field {field} contains control characters; refusing to store it")]
    InvalidCharacters {
        /// Metadata field label.
        field: String,
    },
    /// The field exactly matches a known secret value.
    #[error("metadata field {field} matches an existing secret value; refusing to store it")]
    KnownSecretValue {
        /// Metadata field label.
        field: String,
    },
    /// The field matched provider-token or high-entropy detection.
    #[error("metadata field {field} looks like a secret; refusing to store it")]
    SecretLike {
        /// Metadata field label.
        field: String,
        /// Metadata-safe finding kind.
        finding: MetadataPrivacyFinding,
    },
}

impl MetadataValidationError {
    /// Returns true when the invalid input was secret-like rather than malformed display text.
    #[must_use]
    pub const fn is_secret_like(&self) -> bool {
        matches!(self, Self::KnownSecretValue { .. } | Self::SecretLike { .. })
    }
}

/// Validate one metadata text field against display-safety and privacy rules.
///
/// `known_secret_values` may be empty when the vault is locked or unavailable; callers still get
/// deterministic validation for display-safety and scanner-provided secret-like findings.
///
/// # Errors
///
/// Returns [`MetadataValidationError`] when the field contains control characters, exactly
/// matches a known secret value, or has caller-provided provider-token/high-entropy findings.
pub fn validate_metadata_field<'a>(
    field: &str,
    value: &str,
    known_secret_values: impl IntoIterator<Item = &'a str>,
    findings: impl IntoIterator<Item = MetadataPrivacyFinding>,
) -> Result<(), MetadataValidationError> {
    if value.chars().any(char::is_control) {
        return Err(MetadataValidationError::InvalidCharacters { field: field.to_owned() });
    }

    if known_secret_values.into_iter().any(|known_value| known_value == value) {
        return Err(MetadataValidationError::KnownSecretValue { field: field.to_owned() });
    }

    if let Some(finding) = findings.into_iter().next() {
        return Err(MetadataValidationError::SecretLike { field: field.to_owned(), finding });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MetadataPrivacyFinding, MetadataValidationError, validate_metadata_field};

    #[test]
    fn rejects_control_characters() {
        assert_eq!(
            validate_metadata_field("tag", "prod\u{1b}[31m", [], []),
            Err(MetadataValidationError::InvalidCharacters { field: "tag".to_owned() })
        );
    }

    #[test]
    fn rejects_exact_known_secret_values() {
        assert_eq!(
            validate_metadata_field(
                "owner",
                "postgres://localhost/app",
                ["postgres://localhost/app"],
                []
            ),
            Err(MetadataValidationError::KnownSecretValue { field: "owner".to_owned() })
        );
    }

    #[test]
    fn rejects_scanner_secret_like_findings() {
        assert_eq!(
            validate_metadata_field(
                "description",
                "sk_test_sampleTokenValue123",
                [],
                [MetadataPrivacyFinding::ProviderToken],
            ),
            Err(MetadataValidationError::SecretLike {
                field: "description".to_owned(),
                finding: MetadataPrivacyFinding::ProviderToken,
            })
        );
    }

    #[test]
    fn secret_like_classification_distinguishes_content_from_display_errors() {
        let field = "description".to_owned();
        assert!(
            !MetadataValidationError::InvalidCharacters { field: field.clone() }.is_secret_like()
        );
        assert!(
            MetadataValidationError::KnownSecretValue { field: field.clone() }.is_secret_like()
        );
        assert!(
            MetadataValidationError::SecretLike {
                field,
                finding: MetadataPrivacyFinding::HighEntropy
            }
            .is_secret_like()
        );
    }

    #[test]
    fn accepts_plain_metadata() {
        assert!(
            validate_metadata_field("description", "primary database", ["other-value"], []).is_ok()
        );
    }
}
