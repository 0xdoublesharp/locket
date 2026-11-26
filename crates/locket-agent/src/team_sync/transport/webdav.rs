use std::collections::BTreeSet;

use data_encoding::BASE64;
use zeroize::Zeroizing;

use super::credentials::valid_username;
use super::http::{self, Endpoint, Response};
use super::{
    CredentialMode, ENTRY_LIMIT, LIST_LIMIT, PACKAGE_LIMIT, PutOutcome, Result, TeamTransport,
    TransportConfig, TransportSecretInput, TransportSummary, WebDavAuthKind, reject,
    validate_filename, xml,
};

pub(super) struct WebDav {
    endpoint: Endpoint,
    collection: String,
    authorization: Option<Zeroizing<String>>,
    summary: TransportSummary,
}

pub(super) fn validate_auth(
    auth_kind: WebDavAuthKind,
    username: Option<&str>,
    mode: CredentialMode,
) -> Result<()> {
    if (mode == CredentialMode::None) != (auth_kind == WebDavAuthKind::None)
        || username.is_some_and(|name| auth_kind != WebDavAuthKind::Basic || !valid_username(name))
    {
        return Err(reject("invalid WebDAV authentication configuration"));
    }
    Ok(())
}

impl WebDav {
    pub(super) fn new(
        config: &TransportConfig,
        summary: TransportSummary,
        credentials: Option<&TransportSecretInput>,
    ) -> Result<Self> {
        let TransportConfig::WebDav { url, auth_kind, username, .. } = config else {
            return Err(reject("invalid WebDAV configuration"));
        };
        let endpoint = Endpoint::parse(url)?;
        let collection = format!("{}/", endpoint.path.trim_end_matches('/'));
        let authorization = match (auth_kind, credentials) {
            (WebDavAuthKind::None, None) => None,
            (
                WebDavAuthKind::Basic,
                Some(TransportSecretInput::WebDav { username: supplied, secret }),
            ) => {
                let username = username
                    .as_deref()
                    .or(supplied.as_deref())
                    .ok_or_else(|| reject("WebDAV Basic requires a username"))?;
                let plain = Zeroizing::new(format!("{username}:{}", secret.as_str()));
                let encoded = Zeroizing::new(BASE64.encode(plain.as_bytes()));
                Some(Zeroizing::new(format!("Basic {}", encoded.as_str())))
            }
            (WebDavAuthKind::Bearer, Some(TransportSecretInput::WebDav { secret, .. })) => {
                Some(Zeroizing::new(format!("Bearer {}", secret.as_str())))
            }
            _ => return Err(reject("invalid WebDAV credentials")),
        };
        Ok(Self { endpoint, collection, authorization, summary })
    }

    fn direct_child(&self, href: &str) -> Option<String> {
        let href = href.trim();
        if href.starts_with("//") || href.contains(['?', '#', '\\']) {
            return None;
        }
        let filename = if href.contains("://") {
            let absolute = Endpoint::parse(href).ok()?;
            if !self.endpoint.same_origin(&absolute) {
                return None;
            }
            http::decode(absolute.path.strip_prefix(&self.collection)?).ok()?
        } else if href.starts_with('/') {
            let absolute = http::normalize_path(href).ok()?;
            http::decode(absolute.strip_prefix(&self.collection)?).ok()?
        } else {
            http::decode(href).ok()?
        };
        validate_filename(&filename).ok()?;
        Some(filename)
    }

    fn object_path(&self, filename: &str) -> Result<String> {
        validate_filename(filename)?;
        Ok(format!("{}{}", self.collection, http::encode(filename, false)))
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
        body: &[u8],
        cap: usize,
    ) -> Result<Response> {
        let mut headers = extra.to_vec();
        if let Some(auth) = &self.authorization {
            headers.push(("authorization", auth));
        }
        self.endpoint.request(method, path, &headers, body, cap)
    }
}

impl TeamTransport for WebDav {
    fn list_packages(&self) -> Result<Vec<String>> {
        const BODY: &[u8] = b"<propfind xmlns=\"DAV:\"><prop><resourcetype/></prop></propfind>";
        let headers = [("depth", "1"), ("content-type", "application/xml; charset=utf-8")];
        let body = self
            .request("PROPFIND", &self.collection, &headers, BODY, LIST_LIMIT)?
            .require_status(207, "WebDAV listing")?;
        let mut entries = 0;
        let mut files = BTreeSet::new();
        xml::fields(
            &body,
            "multistatus",
            |path| matches!(path, ["multistatus", "response", "href"]),
            |_, href| {
                entries += 1;
                if entries > ENTRY_LIMIT {
                    return Err(reject("WebDAV team transport has too many entries"));
                }
                if let Some(name) = self.direct_child(&href) {
                    files.insert(name);
                }
                Ok(())
            },
        )?;
        Ok(files.into_iter().collect())
    }

    fn get_package(&self, filename: &str) -> Result<Vec<u8>> {
        self.request("GET", &self.object_path(filename)?, &[], &[], PACKAGE_LIMIT)?
            .require_status(200, "WebDAV download")
    }

    fn put_package(&self, filename: &str, bytes: &[u8]) -> Result<PutOutcome> {
        let path = self.object_path(filename)?;
        http::put_package(bytes, |method, headers, body, cap| {
            self.request(method, &path, headers, body, cap)
        })
    }

    fn delete_package(&self, filename: &str) -> Result<bool> {
        let path = self.object_path(filename)?;
        http::delete_package("WebDAV delete", |cap| self.request("DELETE", &path, &[], &[], cap))
    }

    fn summary(&self) -> TransportSummary {
        self.summary.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_resolves_only_direct_children_of_the_configured_collection() -> Result<()> {
        let config = TransportConfig::WebDav {
            url: "https://example.test/team%20files".into(),
            auth_kind: WebDavAuthKind::None,
            username: None,
            credential_mode: CredentialMode::None,
        };
        let transport = WebDav::new(&config, config.summary()?, None)?;
        for href in [
            "file%20name.lkpkg",
            "/team%20files/file%20name.lkpkg",
            "https://EXAMPLE.test:443/team%20files/file%20name.lkpkg",
        ] {
            assert_eq!(transport.direct_child(href).as_deref(), Some("file name.lkpkg"));
        }
        for href in [
            "/team%20files/",
            "/team%20files/nested/file.lkpkg",
            "/other/file.lkpkg",
            "https://example.test:8443/team%20files/file.lkpkg",
            "https://other.test/team%20files/file.lkpkg",
            "//example.test/team%20files/file.lkpkg",
            "file.lkpkg?query",
            "file.lkpkg#fragment",
            "file%FF.lkpkg",
        ] {
            assert_eq!(transport.direct_child(href), None, "{href}");
        }
        Ok(())
    }

    #[test]
    fn authentication_configuration_enforces_kind_and_username() -> Result<()> {
        validate_auth(WebDavAuthKind::None, None, CredentialMode::None)?;
        validate_auth(WebDavAuthKind::Basic, Some("owner"), CredentialMode::Vault)?;
        validate_auth(WebDavAuthKind::Bearer, None, CredentialMode::Env)?;
        for (kind, name, mode) in [
            (WebDavAuthKind::None, None, CredentialMode::Vault),
            (WebDavAuthKind::Basic, None, CredentialMode::None),
            (WebDavAuthKind::Basic, Some("bad:user"), CredentialMode::Vault),
            (WebDavAuthKind::Bearer, Some("owner"), CredentialMode::Vault),
        ] {
            assert!(validate_auth(kind, name, mode).is_err());
        }
        Ok(())
    }
}
