//! `lk://` reference URI parsing.

use std::fmt::{self, Display};
use std::num::NonZeroU32;
use std::str::FromStr;

use thiserror::Error;

use crate::{ProfileName, SecretName};

const LK_REFERENCE_SCHEME: &str = "lk://";
const VERSION_PREFIX: char = 'v';

/// A parsed `lk://profile/KEY` reference.
///
/// This type validates reference syntax and metadata names only. It does not
/// resolve the referenced secret value.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct LkReferenceUri {
    profile: ProfileName,
    key: SecretName,
    version: Option<SecretVersion>,
    source: Option<SecretSource>,
}

impl LkReferenceUri {
    /// Parses and validates an `lk://` reference URI.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidReferenceUri`] when the URI is missing required
    /// components, contains invalid profile or secret names, has a malformed
    /// version pin, or uses unsupported query parameters.
    pub fn parse(value: &str) -> Result<Self, InvalidReferenceUri> {
        value.parse()
    }

    /// Returns the validated profile name.
    #[must_use]
    pub const fn profile(&self) -> &ProfileName {
        &self.profile
    }

    /// Returns the validated secret key name.
    #[must_use]
    pub const fn key(&self) -> &SecretName {
        &self.key
    }

    /// Returns the optional pinned secret version.
    #[must_use]
    pub const fn version(&self) -> Option<SecretVersion> {
        self.version
    }

    /// Returns the optional explicit runtime source.
    #[must_use]
    pub const fn source(&self) -> Option<SecretSource> {
        self.source
    }

    /// Consumes the URI and returns its parsed components.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (ProfileName, SecretName, Option<SecretVersion>, Option<SecretSource>) {
        (self.profile, self.key, self.version, self.source)
    }
}

impl FromStr for LkReferenceUri {
    type Err = InvalidReferenceUri;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let rest =
            value.strip_prefix(LK_REFERENCE_SCHEME).ok_or(InvalidReferenceUri::MissingScheme)?;
        let (path, query) = split_query(rest);
        let (profile, target) = path.split_once('/').ok_or(InvalidReferenceUri::MissingKey)?;

        if profile.is_empty() {
            return Err(InvalidReferenceUri::MissingProfile);
        }
        if target.is_empty() {
            return Err(InvalidReferenceUri::MissingKey);
        }

        let profile =
            ProfileName::new(profile).map_err(|_| InvalidReferenceUri::InvalidProfileName)?;
        let (key, version) = parse_target(target)?;
        let key = SecretName::new(key).map_err(|_| InvalidReferenceUri::InvalidSecretName)?;
        let source = query.map_or(Ok(None), parse_query)?;

        Ok(Self { profile, key, version, source })
    }
}

/// Runtime secret source accepted by `lk://` reference URIs.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SecretSource {
    /// Team-managed secret source.
    TeamManaged,
    /// User-local secret source.
    UserLocal,
    /// Machine-local secret source.
    MachineLocal,
}

/// Returns the runtime priority for a persisted source name, or zero if unknown.
///
/// Higher values take precedence when multiple sources provide the same secret.
#[must_use]
pub const fn source_precedence(source: &str) -> u8 {
    match source.as_bytes() {
        b"machine-local" => 3,
        b"user-local" => 2,
        b"team-managed" => 1,
        _ => 0,
    }
}

impl SecretSource {
    /// Returns the canonical URI/query string value for this source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TeamManaged => "team-managed",
            Self::UserLocal => "user-local",
            Self::MachineLocal => "machine-local",
        }
    }
}

impl Display for SecretSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SecretSource {
    type Err = InvalidSecretSource;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "team-managed" => Ok(Self::TeamManaged),
            "user-local" => Ok(Self::UserLocal),
            "machine-local" => Ok(Self::MachineLocal),
            _ => Err(InvalidSecretSource),
        }
    }
}

/// Error returned when a runtime secret source string is invalid.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[error("invalid secret source")]
pub struct InvalidSecretSource;

/// A non-zero secret version number parsed from `@vN`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SecretVersion(NonZeroU32);

impl SecretVersion {
    /// Creates a non-zero secret version.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the version number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl Display for SecretVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.get())
    }
}

/// Error returned when an `lk://` reference URI is invalid.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
pub enum InvalidReferenceUri {
    /// URI does not start with `lk://`.
    #[error("missing lk:// scheme")]
    MissingScheme,
    /// URI is missing a profile component.
    #[error("missing profile")]
    MissingProfile,
    /// URI is missing a secret key component.
    #[error("missing key")]
    MissingKey,
    /// URI profile component is not a valid [`ProfileName`].
    #[error("invalid profile name")]
    InvalidProfileName,
    /// URI key component is not a valid [`SecretName`].
    #[error("invalid secret name")]
    InvalidSecretName,
    /// URI version pin is not `@vN` with a non-zero `u32` version.
    #[error("malformed version")]
    MalformedVersion,
    /// URI query string is empty.
    #[error("empty query")]
    EmptyQuery,
    /// URI query contains an unsupported key.
    #[error("unknown query key")]
    UnknownQueryKey,
    /// URI query contains `source` more than once.
    #[error("duplicate source query parameter")]
    DuplicateSource,
    /// URI query contains `source=imported`, which is provenance, not a runtime source.
    #[error("imported is not a runtime source")]
    ImportedSource,
    /// URI query contains an unsupported source value.
    #[error("invalid source")]
    InvalidSource,
}

fn split_query(value: &str) -> (&str, Option<&str>) {
    match value.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (value, None),
    }
}

fn parse_target(target: &str) -> Result<(&str, Option<SecretVersion>), InvalidReferenceUri> {
    let mut parts = target.split('@');
    let key = parts.next().ok_or(InvalidReferenceUri::MissingKey)?;
    let Some(version) = parts.next() else {
        return Ok((key, None));
    };
    if parts.next().is_some() {
        return Err(InvalidReferenceUri::MalformedVersion);
    }
    if key.is_empty() {
        return Err(InvalidReferenceUri::MissingKey);
    }
    let version = parse_version(version)?;
    Ok((key, Some(version)))
}

fn parse_version(value: &str) -> Result<SecretVersion, InvalidReferenceUri> {
    let version =
        value.strip_prefix(VERSION_PREFIX).ok_or(InvalidReferenceUri::MalformedVersion)?;
    if version.is_empty() {
        return Err(InvalidReferenceUri::MalformedVersion);
    }
    let version = version.parse::<u32>().map_err(|_| InvalidReferenceUri::MalformedVersion)?;
    SecretVersion::new(version).ok_or(InvalidReferenceUri::MalformedVersion)
}

fn parse_query(query: &str) -> Result<Option<SecretSource>, InvalidReferenceUri> {
    if query.is_empty() {
        return Err(InvalidReferenceUri::EmptyQuery);
    }

    let mut source = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').ok_or(InvalidReferenceUri::UnknownQueryKey)?;
        if key != "source" {
            return Err(InvalidReferenceUri::UnknownQueryKey);
        }
        if source.is_some() {
            return Err(InvalidReferenceUri::DuplicateSource);
        }
        if value == "imported" {
            return Err(InvalidReferenceUri::ImportedSource);
        }
        source = Some(value.parse().map_err(|_| InvalidReferenceUri::InvalidSource)?);
    }

    Ok(source)
}

#[cfg(test)]
mod tests {
    use super::{InvalidReferenceUri, LkReferenceUri, SecretSource};

    #[test]
    fn runtime_source_precedence_uses_persisted_names() {
        for (source, rank) in [
            (SecretSource::MachineLocal, 3),
            (SecretSource::UserLocal, 2),
            (SecretSource::TeamManaged, 1),
        ] {
            assert_eq!(super::source_precedence(source.as_str()), rank);
        }
        assert_eq!(super::source_precedence("unknown"), 0);
    }

    #[test]
    fn parses_valid_runtime_spec_examples() -> Result<(), InvalidReferenceUri> {
        let current = LkReferenceUri::parse("lk://profile/KEY")?;
        assert_eq!(current.profile().as_str(), "profile");
        assert_eq!(current.key().as_str(), "KEY");
        assert_eq!(current.version().map(super::SecretVersion::get), None);
        assert_eq!(current.source(), None);

        let pinned = LkReferenceUri::parse("lk://profile/KEY@v3")?;
        assert_eq!(pinned.profile().as_str(), "profile");
        assert_eq!(pinned.key().as_str(), "KEY");
        assert_eq!(pinned.version().map(super::SecretVersion::get), Some(3));
        assert_eq!(pinned.source(), None);

        let sourced = LkReferenceUri::parse("lk://profile/KEY?source=user-local")?;
        assert_eq!(sourced.profile().as_str(), "profile");
        assert_eq!(sourced.key().as_str(), "KEY");
        assert_eq!(sourced.version().map(super::SecretVersion::get), None);
        assert_eq!(sourced.source(), Some(SecretSource::UserLocal));

        let pinned_sourced = LkReferenceUri::parse("lk://profile/KEY@v3?source=team-managed")?;
        assert_eq!(pinned_sourced.profile().as_str(), "profile");
        assert_eq!(pinned_sourced.key().as_str(), "KEY");
        assert_eq!(pinned_sourced.version().map(super::SecretVersion::get), Some(3));
        assert_eq!(pinned_sourced.source(), Some(SecretSource::TeamManaged));

        let dev = LkReferenceUri::parse("lk://dev/DATABASE_URL")?;
        assert_eq!(dev.profile().as_str(), "dev");
        assert_eq!(dev.key().as_str(), "DATABASE_URL");

        let prod = LkReferenceUri::parse("lk://prod/STRIPE_SECRET_KEY@v12")?;
        assert_eq!(prod.profile().as_str(), "prod");
        assert_eq!(prod.key().as_str(), "STRIPE_SECRET_KEY");
        assert_eq!(prod.version().map(super::SecretVersion::get), Some(12));
        Ok(())
    }

    #[test]
    fn parses_all_allowed_sources() -> Result<(), InvalidReferenceUri> {
        for (value, source) in [
            ("team-managed", SecretSource::TeamManaged),
            ("user-local", SecretSource::UserLocal),
            ("machine-local", SecretSource::MachineLocal),
        ] {
            let uri = format!("lk://dev/DATABASE_URL?source={value}");
            assert_eq!(LkReferenceUri::parse(&uri)?.source(), Some(source));
        }
        Ok(())
    }

    #[test]
    fn displays_sources_as_canonical_query_values() {
        assert_eq!(SecretSource::TeamManaged.to_string(), "team-managed");
        assert_eq!(SecretSource::UserLocal.to_string(), "user-local");
        assert_eq!(SecretSource::MachineLocal.to_string(), "machine-local");
    }

    #[test]
    fn secret_version_is_non_zero_and_displays_number() {
        assert_eq!(super::SecretVersion::new(0), None);
        assert!(matches!(
            super::SecretVersion::new(42).map(|version| version.to_string()),
            Some(value) if value == "42"
        ));
    }

    #[test]
    fn into_parts_returns_validated_components() -> Result<(), InvalidReferenceUri> {
        let (profile, key, version, source) =
            LkReferenceUri::parse("lk://dev/DATABASE_URL@v7?source=machine-local")?.into_parts();

        assert_eq!(profile.as_str(), "dev");
        assert_eq!(key.as_str(), "DATABASE_URL");
        assert_eq!(version.map(super::SecretVersion::get), Some(7));
        assert_eq!(source, Some(SecretSource::MachineLocal));
        Ok(())
    }

    #[test]
    fn rejects_missing_profile_or_key() {
        assert_eq!(LkReferenceUri::parse("lk:///KEY"), Err(InvalidReferenceUri::MissingProfile));
        assert_eq!(LkReferenceUri::parse("lk://dev/"), Err(InvalidReferenceUri::MissingKey));
        assert_eq!(LkReferenceUri::parse("lk://dev"), Err(InvalidReferenceUri::MissingKey));
        assert_eq!(LkReferenceUri::parse("KEY"), Err(InvalidReferenceUri::MissingScheme));
    }

    #[test]
    fn rejects_invalid_names() {
        assert_eq!(
            LkReferenceUri::parse("lk://Prod/DATABASE_URL"),
            Err(InvalidReferenceUri::InvalidProfileName)
        );
        assert_eq!(
            LkReferenceUri::parse("lk://dev/database_url"),
            Err(InvalidReferenceUri::InvalidSecretName)
        );
        assert_eq!(
            LkReferenceUri::parse("lk://dev/DATABASE-URL"),
            Err(InvalidReferenceUri::InvalidSecretName)
        );
    }

    #[test]
    fn rejects_malformed_versions() {
        for value in [
            "lk://dev/DATABASE_URL@",
            "lk://dev/DATABASE_URL@3",
            "lk://dev/DATABASE_URL@v",
            "lk://dev/DATABASE_URL@v0",
            "lk://dev/DATABASE_URL@vabc",
            "lk://dev/DATABASE_URL@v4294967296",
            "lk://dev/DATABASE_URL@v1@v2",
        ] {
            assert_eq!(
                LkReferenceUri::parse(value),
                Err(InvalidReferenceUri::MalformedVersion),
                "{value} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_unsupported_query_parameters() {
        assert_eq!(
            LkReferenceUri::parse("lk://dev/DATABASE_URL?"),
            Err(InvalidReferenceUri::EmptyQuery)
        );
        assert_eq!(
            LkReferenceUri::parse("lk://dev/DATABASE_URL?foo=bar"),
            Err(InvalidReferenceUri::UnknownQueryKey)
        );
        assert_eq!(
            LkReferenceUri::parse("lk://dev/DATABASE_URL?source=user-local&"),
            Err(InvalidReferenceUri::UnknownQueryKey)
        );
        assert_eq!(
            LkReferenceUri::parse("lk://dev/DATABASE_URL?source"),
            Err(InvalidReferenceUri::UnknownQueryKey)
        );
        assert_eq!(
            LkReferenceUri::parse("lk://dev/DATABASE_URL?source=user-local&foo=bar"),
            Err(InvalidReferenceUri::UnknownQueryKey)
        );
        assert_eq!(
            LkReferenceUri::parse("lk://dev/DATABASE_URL?source=user-local&source=team-managed"),
            Err(InvalidReferenceUri::DuplicateSource)
        );
    }

    #[test]
    fn rejects_invalid_or_imported_sources() {
        assert_eq!(
            LkReferenceUri::parse("lk://dev/DATABASE_URL?source=imported"),
            Err(InvalidReferenceUri::ImportedSource)
        );
        assert_eq!(
            LkReferenceUri::parse("lk://dev/DATABASE_URL?source=remote"),
            Err(InvalidReferenceUri::InvalidSource)
        );
        assert_eq!(
            LkReferenceUri::parse("lk://dev/DATABASE_URL?source="),
            Err(InvalidReferenceUri::InvalidSource)
        );
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod proptest_lk_uri {
    use proptest::prelude::*;

    use super::{InvalidReferenceUri, LkReferenceUri};

    fn valid_profile_strategy() -> impl Strategy<Value = String> {
        prop::string::string_regex("[a-z][a-z0-9_-]{0,15}").expect("valid regex")
    }

    fn valid_secret_strategy() -> impl Strategy<Value = String> {
        let first = prop::char::ranges(std::borrow::Cow::Borrowed(&['A'..='Z', '_'..='_']));
        let rest = prop::collection::vec(
            prop::char::ranges(std::borrow::Cow::Borrowed(&['A'..='Z', '0'..='9', '_'..='_'])),
            0..12,
        );
        (first, rest).prop_map(|(f, r)| {
            let mut s = String::new();
            s.push(f);
            s.extend(r);
            s
        })
    }

    proptest! {
        #[test]
        fn bare_uri_round_trips_profile_and_key(
            profile in valid_profile_strategy(),
            key in valid_secret_strategy(),
        ) {
            let uri = format!("lk://{profile}/{key}");
            let parsed = LkReferenceUri::parse(&uri);
            prop_assert!(parsed.is_ok(), "valid uri should parse: {parsed:?}");
            let parsed = parsed.unwrap();
            prop_assert_eq!(parsed.profile().as_str(), profile.as_str());
            prop_assert_eq!(parsed.key().as_str(), key.as_str());
            prop_assert!(parsed.version().is_none(), "no version without @vN");
            prop_assert!(parsed.source().is_none(), "no source without query");
        }

        #[test]
        fn pinned_version_round_trips(
            profile in valid_profile_strategy(),
            key in valid_secret_strategy(),
            version in 1u32..=u32::MAX,
        ) {
            let uri = format!("lk://{profile}/{key}@v{version}");
            let parsed = LkReferenceUri::parse(&uri);
            prop_assert!(parsed.is_ok(), "pinned uri should parse: {parsed:?}");
            let parsed = parsed.unwrap();
            prop_assert_eq!(
                parsed.version().map(super::SecretVersion::get),
                Some(version),
                "version preserved"
            );
        }

        #[test]
        fn version_zero_is_always_rejected(
            profile in valid_profile_strategy(),
            key in valid_secret_strategy(),
        ) {
            let uri = format!("lk://{profile}/{key}@v0");
            let result = LkReferenceUri::parse(&uri);
            prop_assert_eq!(result, Err(InvalidReferenceUri::MalformedVersion));
        }

        #[test]
        fn missing_scheme_always_rejects(
            profile in valid_profile_strategy(),
            key in valid_secret_strategy(),
        ) {
            let bare = format!("{profile}/{key}");
            prop_assert_eq!(
                LkReferenceUri::parse(&bare),
                Err(InvalidReferenceUri::MissingScheme)
            );
        }

        #[test]
        fn empty_query_always_rejects(
            profile in valid_profile_strategy(),
            key in valid_secret_strategy(),
        ) {
            let uri = format!("lk://{profile}/{key}?");
            prop_assert_eq!(
                LkReferenceUri::parse(&uri),
                Err(InvalidReferenceUri::EmptyQuery)
            );
        }

        #[test]
        fn unknown_query_key_always_rejects(
            profile in valid_profile_strategy(),
            key in valid_secret_strategy(),
            qkey in "[a-z]{3,8}",
            qval in "[a-z]{3,8}",
        ) {
            prop_assume!(qkey != "source");
            let uri = format!("lk://{profile}/{key}?{qkey}={qval}");
            prop_assert_eq!(
                LkReferenceUri::parse(&uri),
                Err(InvalidReferenceUri::UnknownQueryKey)
            );
        }

        #[test]
        fn invalid_profile_names_rejected(key in valid_secret_strategy()) {
            for bad_profile in &["Prod", "1dev", "DEV", ""] {
                let uri = format!("lk://{bad_profile}/{key}");
                let result = LkReferenceUri::parse(&uri);
                prop_assert!(
                    result.is_err(),
                    "invalid profile {bad_profile:?} must be rejected for key {key}: {result:?}"
                );
            }
        }

        #[test]
        fn invalid_secret_names_rejected(profile in valid_profile_strategy()) {
            for bad_key in &["lowercase", "DASH-KEY", "DOT.KEY", ""] {
                let uri = format!("lk://{profile}/{bad_key}");
                let result = LkReferenceUri::parse(&uri);
                prop_assert!(
                    result.is_err(),
                    "invalid key {bad_key:?} must be rejected for profile {profile}: {result:?}"
                );
            }
        }

        #[test]
        fn source_query_param_is_preserved(
            profile in valid_profile_strategy(),
            key in valid_secret_strategy(),
            source in prop::sample::select(vec!["user-local", "machine-local", "team-managed"]),
        ) {
            let uri = format!("lk://{profile}/{key}?source={source}");
            let parsed = LkReferenceUri::parse(&uri);
            prop_assert!(parsed.is_ok(), "source query should parse: {parsed:?}");
            prop_assert!(parsed.unwrap().source().is_some(), "source preserved");
        }
    }
}
