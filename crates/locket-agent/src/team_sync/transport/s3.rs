use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use data_encoding::HEXLOWER;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::http::{self, Endpoint, Response};
use super::{
    CredentialMode, ENTRY_LIMIT, LIST_LIMIT, PACKAGE_LIMIT, PutOutcome, Result, TeamTransport,
    TransportConfig, TransportSecretInput, TransportSummary, reject, validate_filename, xml,
};

const MAX_PAGES: usize = 1000;
const LIST_TOTAL_LIMIT: usize = 128 * 1024 * 1024;

pub(super) struct S3 {
    endpoint: Endpoint,
    bucket_path: String,
    prefix: String,
    region: String,
    credentials: TransportSecretInput,
    summary: TransportSummary,
}

pub(super) fn endpoint(config: &TransportConfig) -> Result<(Endpoint, String)> {
    let TransportConfig::S3 { bucket, region, prefix, endpoint, path_style, credential_mode } =
        config
    else {
        return Err(reject("invalid S3 configuration"));
    };
    if !(3..=63).contains(&bucket.len())
        || !bucket.split('.').all(http::valid_dns_label)
        || bucket.bytes().any(|byte| byte.is_ascii_uppercase())
        || !http::valid_dns_label(region)
        || region.bytes().any(|byte| byte.is_ascii_uppercase())
        || prefix.len() > 1024
        || prefix.contains('\\')
        || prefix.chars().any(char::is_control)
        || prefix.split('/').any(|segment| matches!(segment, "." | ".."))
        || *credential_mode == CredentialMode::None
    {
        return Err(reject("invalid S3 bucket, region, prefix or credential mode"));
    }
    // A custom endpoint is used verbatim as an origin and optional base path.
    // Custom gateways can expose a virtual-host bucket by using its complete
    // hostname as the endpoint and leaving path_style false.
    let default = if *path_style {
        format!("https://s3.{region}.amazonaws.com")
    } else {
        format!("https://{bucket}.s3.{region}.amazonaws.com")
    };
    let endpoint = Endpoint::parse(endpoint.as_deref().unwrap_or(&default))?;
    let base = endpoint.path.trim_end_matches('/');
    let bucket_path = if *path_style {
        format!("{base}/{}", http::encode(bucket, false))
    } else if base.is_empty() {
        "/".into()
    } else {
        base.into()
    };
    Ok((endpoint, bucket_path))
}

pub(super) fn prefix(raw: &str) -> String {
    if raw.is_empty() || raw.ends_with('/') { raw.into() } else { format!("{raw}/") }
}

impl S3 {
    pub(super) fn new(
        config: &TransportConfig,
        summary: TransportSummary,
        credentials: Option<TransportSecretInput>,
    ) -> Result<Self> {
        let (endpoint, bucket_path) = endpoint(config)?;
        let TransportConfig::S3 { region, prefix: key_prefix, .. } = config else {
            return Err(reject("invalid S3 configuration"));
        };
        Ok(Self {
            endpoint,
            bucket_path,
            prefix: prefix(key_prefix),
            region: region.clone(),
            credentials: credentials.ok_or_else(|| reject("S3 credentials required"))?,
            summary,
        })
    }

    fn object_path(&self, name: &str) -> Result<String> {
        validate_filename(name)?;
        Ok(format!(
            "{}/{}{}",
            self.bucket_path.trim_end_matches('/'),
            http::encode(&self.prefix, true),
            http::encode(name, false)
        ))
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        query: &str,
        extra: &[(&str, &str)],
        body: &[u8],
        cap: usize,
    ) -> Result<Response> {
        let now = OffsetDateTime::now_utc();
        let amz_date = format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            now.year(),
            u8::from(now.month()),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
        );
        let body_hash = HEXLOWER.encode(&Sha256::digest(body));
        let TransportSecretInput::S3 { access_key_id, secret_access_key, session_token } =
            &self.credentials
        else {
            return Err(reject("invalid S3 credentials"));
        };
        let mut headers = BTreeMap::from([
            ("host", self.endpoint.host_header()),
            ("x-amz-content-sha256", body_hash.as_str()),
            ("x-amz-date", amz_date.as_str()),
        ]);
        headers.extend(extra.iter().copied());
        if let Some(token) = session_token {
            headers.insert("x-amz-security-token", token);
        }
        let auth = authorization(
            method,
            path,
            query,
            &headers,
            &body_hash,
            &amz_date,
            &self.region,
            access_key_id,
            secret_access_key,
        )?;
        headers.remove("host");
        headers.insert("authorization", &auth);
        let headers: Vec<_> = headers.into_iter().collect();
        let target = if query.is_empty() { path.to_owned() } else { format!("{path}?{query}") };
        self.endpoint.request(method, &target, &headers, body, cap)
    }
}

impl TeamTransport for S3 {
    fn list_packages(&self) -> Result<Vec<String>> {
        let mut files = BTreeSet::new();
        let mut tokens = BTreeSet::new();
        let mut continuation: Option<String> = None;
        let mut entries = 0;
        let mut budget = LIST_TOTAL_LIMIT;
        for _ in 0..MAX_PAGES {
            let mut params = vec![("list-type", "2"), ("prefix", self.prefix.as_str())];
            if let Some(token) = &continuation {
                params.push(("continuation-token", token));
            }
            let query = canonical_query(&params);
            let body = self
                .request("GET", &self.bucket_path, &query, &[], &[], budget.min(LIST_LIMIT))?
                .require_status(200, "S3 listing")?;
            budget -= body.len();
            continuation = parse_page(&body, &self.prefix, &mut entries, &mut files)?;
            let Some(token) = &continuation else {
                return Ok(files.into_iter().collect());
            };
            if !tokens.insert(token.clone()) {
                return Err(reject("S3 listing repeated a continuation token"));
            }
        }
        Err(reject("S3 listing exceeded pagination limit"))
    }

    fn get_package(&self, filename: &str) -> Result<Vec<u8>> {
        self.request("GET", &self.object_path(filename)?, "", &[], &[], PACKAGE_LIMIT)?
            .require_status(200, "S3 download")
    }

    fn put_package(&self, filename: &str, bytes: &[u8]) -> Result<PutOutcome> {
        let path = self.object_path(filename)?;
        http::put_package(bytes, |method, headers, body, cap| {
            self.request(method, &path, "", headers, body, cap)
        })
    }

    fn delete_package(&self, filename: &str) -> Result<bool> {
        let path = self.object_path(filename)?;
        http::delete_package("S3 delete", |cap| self.request("DELETE", &path, "", &[], &[], cap))
    }

    fn summary(&self) -> TransportSummary {
        self.summary.clone()
    }
}

fn parse_page(
    bytes: &[u8],
    prefix: &str,
    entries: &mut usize,
    files: &mut BTreeSet<String>,
) -> Result<Option<String>> {
    let mut token = None;
    let mut truncated = None;
    xml::fields(
        bytes,
        "ListBucketResult",
        |path| {
            matches!(
                path,
                ["ListBucketResult", "Contents", "Key"]
                    | ["ListBucketResult", "NextContinuationToken" | "IsTruncated"]
            )
        },
        |path, value| {
            match path {
                [.., "Key"] => {
                    *entries += 1;
                    if *entries > ENTRY_LIMIT {
                        return Err(reject("S3 team transport has too many entries"));
                    }
                    if let Some(name) = value.strip_prefix(prefix)
                        && validate_filename(name).is_ok()
                    {
                        files.insert(name.to_owned());
                    }
                }
                [.., "IsTruncated"] => {
                    let flag = match value.trim() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(reject("invalid S3 pagination flag")),
                    };
                    if truncated.replace(flag).is_some() {
                        return Err(reject("duplicate S3 pagination flag"));
                    }
                }
                [.., "NextContinuationToken"]
                    if value.is_empty() || value.len() > 4096 || token.is_some() =>
                {
                    return Err(reject("invalid S3 continuation token"));
                }
                [.., "NextContinuationToken"] => token = Some(value),
                _ => {}
            }
            Ok(())
        },
    )?;
    match (truncated, token) {
        (Some(true), Some(token)) => Ok(Some(token)),
        (None | Some(false), None) => Ok(None),
        _ => Err(reject("inconsistent S3 pagination response")),
    }
}

fn canonical_query(params: &[(&str, &str)]) -> String {
    let mut encoded: Vec<_> = params
        .iter()
        .map(|(key, value)| (http::encode(key, false), http::encode(value, false)))
        .collect();
    encoded.sort_unstable();
    encoded.into_iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join("&")
}

fn authorization(
    method: &str,
    path: &str,
    query: &str,
    headers: &BTreeMap<&str, &str>,
    body_hash: &str,
    amz_date: &str,
    region: &str,
    access_key_id: &str,
    secret_access_key: &str,
) -> Result<Zeroizing<String>> {
    let signed_headers = headers.keys().copied().collect::<Vec<_>>().join(";");
    let header_bytes: usize =
        headers.iter().map(|(name, value)| name.len() + value.len() + 2).sum();
    let capacity = method.len()
        + path.len()
        + query.len()
        + header_bytes
        + signed_headers.len()
        + body_hash.len()
        + 5;
    let mut canonical = Zeroizing::new(String::with_capacity(capacity));
    write!(canonical, "{method}\n{path}\n{query}\n").map_err(|_| reject("S3 signing failed"))?;
    for (name, value) in headers {
        // All request values except test-vector inputs are already canonical.
        // Write them straight into the zeroizing buffer without copying tokens.
        write!(canonical, "{name}:").map_err(|_| reject("S3 signing failed"))?;
        for (idx, word) in value.split_ascii_whitespace().enumerate() {
            if idx != 0 {
                canonical.push(' ');
            }
            canonical.push_str(word);
        }
        canonical.push('\n');
    }
    write!(canonical, "\n{signed_headers}\n{body_hash}")
        .map_err(|_| reject("S3 signing failed"))?;
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let canonical_hash = HEXLOWER.encode(&Sha256::digest(canonical.as_bytes()));
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");
    let mut secret = Zeroizing::new(String::from("AWS4"));
    secret.push_str(secret_access_key);
    let date_key = hmac(secret.as_bytes(), date)?;
    let region_key = hmac(&*date_key, region)?;
    let service_key = hmac(&*region_key, "s3")?;
    let signing_key = hmac(&*service_key, "aws4_request")?;
    let signature = hmac(&*signing_key, &to_sign)?;
    let signature = Zeroizing::new(HEXLOWER.encode(&*signature));
    Ok(Zeroizing::new(format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{scope},SignedHeaders={signed_headers},Signature={}",
        signature.as_str()
    )))
}

fn hmac(key: &[u8], value: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| reject("S3 signing failed"))?;
    mac.update(value.as_bytes());
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
    #[test]
    fn aws_s3_get_object_signature_vector() -> Result<()> {
        let body_hash = HEXLOWER.encode(&Sha256::digest([]));
        let amz_date = "20130524T000000Z";
        let headers = BTreeMap::from([
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            ("x-amz-content-sha256", body_hash.as_str()),
            ("x-amz-date", amz_date),
        ]);
        let auth = authorization(
            "GET",
            "/test.txt",
            "",
            &headers,
            &body_hash,
            amz_date,
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )?;
        assert!(auth.ends_with(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        ));
        Ok(())
    }

    #[test]
    fn aws_s3_list_objects_signature_vector() -> Result<()> {
        let body_hash = HEXLOWER.encode(&Sha256::digest([]));
        let amz_date = "20130524T000000Z";
        let headers = BTreeMap::from([
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", body_hash.as_str()),
            ("x-amz-date", amz_date),
        ]);
        let query = canonical_query(&[("prefix", "J"), ("max-keys", "2")]);
        let auth = authorization(
            "GET",
            "/",
            &query,
            &headers,
            &body_hash,
            amz_date,
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )?;
        assert!(auth.ends_with(
            "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        ));
        Ok(())
    }

    #[test]
    fn canonical_query_escapes_before_sorting() {
        assert_eq!(
            canonical_query(&[("a", "2"), ("a", "+/="), ("~", "space here"), ("é", "")]),
            "%C3%A9=&a=%2B%2F%3D&a=2&~=space%20here"
        );
    }
}
