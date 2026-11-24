//! Typed payloads for the `ScanKnownValues` agent RPC.
//!
//! `ScanKnownValues` provides in-memory matching against the agent's
//! known-secret-value map for scanner integrations that must avoid
//! persisting plaintext values. Pattern, entropy, and `.env` heuristics
//! live in `locket-scan` and run client-side without an unlock; this
//! RPC adds the known-value match path that requires unwrapped key
//! material.
//!
//! See `docs/specs/agent.md` and `docs/specs/scan-redaction.md` for
//! semantics. The handler accepts already-read text buffers, decrypts
//! known values only from a live unlock-cache entry, and returns
//! redacted match metadata without persisting or returning values.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use locket_core::{LocketError, privacy_alias};
use locket_crypto::{
    EncryptedSecretValue, KeyPurpose, KeyWrapAad, KeyWrapPurpose, decrypt_secret_value_v1,
    key_wrap_aad_v1, secret_blob_aad_v1,
};
use locket_store::{AuditWrite, SecretBlobRecord, SecretRecord, SecretVersionRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::grant::{GrantAction, GrantBinding, GrantValidation};
use crate::keys::{master_key_array, unwrap_audit_key_with_master, unwrap_profile_key_with_master};

const ERROR_GRANT_REQUIRED: &str = "GrantRequired";
const ERROR_UNLOCK_REQUIRED: &str = "UnlockRequired";
const ERROR_PROFILE_NOT_FOUND: &str = "ProfileNotFound";
const ERROR_CORRUPT_DB: &str = "CorruptDb";

const GRANT_REQUIRED_MESSAGE: &str =
    "live grant required to scan known values; request a grant before retrying";
const UNLOCK_REQUIRED_MESSAGE: &str =
    "unlock required to scan known values; unlock the project before retrying";
const AGENT_SCAN_COMMAND: &str = "agent-scan-known-values";

/// Request payload for `ScanKnownValues`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanRequest {
    /// Already-read text buffers to match against known values. The agent
    /// never opens files on behalf of UI or editor callers.
    #[serde(default)]
    pub inputs: Vec<ScanInput>,
    /// Project id whose unlock-cache entry and store rows are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Profile id authorized by the live grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Path to the user-scoped `store.db`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_path: Option<PathBuf>,
    /// Live grant id authorizing known-value scanning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// Current process binding for the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<GrantBinding>,
    /// When true, the caller is in a "fail closed" mode and wants the
    /// agent to refuse with an explicit unlock-required error when
    /// known-value coverage is unavailable.
    pub require_known: bool,
    /// Whether profile and secret labels should be privacy aliases in
    /// returned findings. Audit metadata keeps exact names only.
    #[serde(default)]
    pub redact_names: bool,
}

/// Already-read text buffer to scan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanInput {
    /// Metadata-only path label supplied by the caller.
    pub path: String,
    /// Text content already held in caller memory.
    pub text: String,
}

/// Single scan finding emitted by `ScanKnownValues`.
///
/// Findings are metadata only: `redacted_summary` is a short, redaction-
/// safe excerpt the UI can render without exposing the matched value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanFinding {
    /// Name of the rule or known-value source that produced the match.
    pub rule: String,
    /// Path the match originated from, echoed from the request.
    pub path: String,
    /// One-based line number within `path`.
    pub line: u32,
    /// One-based column number within the matched line.
    pub column: u32,
    /// Severity classification (`info`, `warn`, `error`, ...).
    pub severity: String,
    /// Short redacted excerpt safe to display in logs and UIs.
    pub redacted_summary: String,
    /// Optional rule id that suppressed this finding, when applicable.
    pub suppressed_by: Option<String>,
}

/// Response payload for `ScanKnownValues`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanResponse {
    /// All matches discovered. Empty when the vault is locked because
    /// known-value matching needs unwrapped keys.
    pub findings: Vec<ScanFinding>,
    /// Whether the agent was locked at the time of the call. Callers
    /// that requested `require_known = true` should treat `locked =
    /// true` as a coverage gap.
    pub locked: bool,
}

/// Handler for `ScanKnownValues`.
///
/// Scans require project, profile and store context, a live grant, and an
/// unlock-cache entry before any store decryption occurs.
#[allow(clippy::too_many_lines)]
pub async fn handle_scan(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<ScanRequest>(request.payload.clone()) else {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "ProtocolError",
            "invalid ScanKnownValues payload",
            false,
        ));
    };
    // The dispatcher verifies signed automation and its registered policy binding.
    // Ordinary local grants retain full-profile coverage; signed scans must use
    // the saved policy, never a caller-supplied list of secret names.
    let policy_name = if request.payload.get("auth").is_some() {
        let Some(name) = request
            .payload
            .get("policy_name")
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty())
        else {
            return protocol_error(request, "automation scans require policy_name");
        };
        Some(name)
    } else {
        None
    };
    let Some(project_id) = typed.project_id.as_deref() else {
        return protocol_error(request, "ScanKnownValues requires project_id");
    };
    let Some(profile_id) = typed.profile_id.as_deref() else {
        return protocol_error(request, "ScanKnownValues requires profile_id");
    };
    let Some(store_path) = typed.store_path.as_deref() else {
        return protocol_error(request, "ScanKnownValues requires store_path");
    };

    let cached_master_key_for_denial = || async {
        let cache = state.unlock_cache.lock().await;
        cache
            .lookup(project_id, now_unix_nanos)
            .map(|entry| Zeroizing::new(entry.key_bytes().to_vec()))
    };
    let Some(grant_id) = typed.grant_id.as_deref() else {
        let key = cached_master_key_for_denial().await;
        crate::audit_deny::try_append_grant_denial(
            project_id,
            profile_id,
            Some(store_path),
            key.as_ref().map(|key| key.as_slice()),
            GrantAction::ScanKnownValues,
            0,
            now_unix_nanos,
            "agent",
        );
        return grant_required(request);
    };
    let grant_validation = {
        let grants = state.grants.lock().await;
        grants.validate(
            grant_id,
            project_id,
            profile_id,
            GrantAction::ScanKnownValues,
            now_unix_nanos,
            typed.binding.as_ref(),
        )
    };
    if !matches!(grant_validation, GrantValidation::Valid) {
        let key = cached_master_key_for_denial().await;
        crate::audit_deny::try_append_grant_denial(
            project_id,
            profile_id,
            Some(store_path),
            key.as_ref().map(|key| key.as_slice()),
            GrantAction::ScanKnownValues,
            0,
            now_unix_nanos,
            "agent",
        );
        return grant_required(request);
    }

    let master_key = {
        let cache = state.unlock_cache.lock().await;
        cache
            .lookup(project_id, now_unix_nanos)
            .map(|entry| Zeroizing::new(entry.key_bytes().to_vec()))
    };
    let Some(master_key) = master_key else {
        return if typed.require_known {
            crate::degraded_audit::record_locked_refusal(
                "SCAN",
                Some(project_id),
                "agent.ScanKnownValues",
                Some(store_path),
                now_unix_nanos,
            );
            unlock_required(request)
        } else {
            success_response(request, &ScanResponse { findings: Vec::new(), locked: true })
        };
    };

    match scan_known_values(
        &typed,
        project_id,
        profile_id,
        store_path,
        &master_key,
        now_unix_nanos,
        policy_name,
    ) {
        Ok(response) => {
            let count = u32::try_from(response.findings.len()).unwrap_or(u32::MAX);
            state.record_scan_warning_count(count).await;
            state.publish_status_snapshot(now_unix_nanos).await;
            success_response(request, &response)
        }
        Err(error) => typed_failure(request, &error),
    }
}

fn success_response(request: &RequestEnvelope, response: &ScanResponse) -> ResponseEnvelope {
    serde_json::to_value(response).map_or_else(
        |_| {
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                "ProtocolError",
                "failed to serialize ScanKnownValues response",
                false,
            ))
        },
        |payload| ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), payload)),
    )
}

fn protocol_error(request: &RequestEnvelope, message: &str) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), "ProtocolError", message, false))
}

fn grant_required(request: &RequestEnvelope) -> ResponseEnvelope {
    typed_locket_error(
        request,
        ERROR_GRANT_REQUIRED,
        GRANT_REQUIRED_MESSAGE,
        LocketError::GrantRequired,
    )
}

fn unlock_required(request: &RequestEnvelope) -> ResponseEnvelope {
    typed_locket_error(
        request,
        ERROR_UNLOCK_REQUIRED,
        UNLOCK_REQUIRED_MESSAGE,
        LocketError::UnlockRequired,
    )
}

fn typed_locket_error(
    request: &RequestEnvelope,
    error: &'static str,
    message: &'static str,
    kind: LocketError,
) -> ResponseEnvelope {
    debug_assert!(kind.exit_code() > 0);
    typed_error(request, error, message)
}

fn typed_error(
    request: &RequestEnvelope,
    error: &'static str,
    message: &'static str,
) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), error, message, false))
}

fn typed_failure(request: &RequestEnvelope, error: &ScanFailure) -> ResponseEnvelope {
    debug_assert!(error.kind.exit_code() > 0);
    typed_error(request, error.error, error.message)
}

#[derive(Debug)]
struct ScanFailure {
    error: &'static str,
    message: &'static str,
    kind: LocketError,
}

impl ScanFailure {
    const fn new(error: &'static str, message: &'static str, kind: LocketError) -> Self {
        Self { error, message, kind }
    }
}

struct KnownSecret {
    value: Zeroizing<String>,
    secret_name: String,
    rule_label: String,
}

struct ScanMatches {
    findings: Vec<ScanFinding>,
    matched_secret_names: BTreeSet<String>,
}

fn scan_known_values(
    request: &ScanRequest,
    project_id: &str,
    profile_id: &str,
    store_path: &Path,
    master_key: &[u8],
    now_unix_nanos: i128,
    policy_name: Option<&str>,
) -> Result<ScanResponse, ScanFailure> {
    let master_key = master_key_array(master_key).map_err(|_| corrupt_db())?;
    let mut store = Store::open(store_path).map_err(|_| corrupt_db())?;
    ensure_profile_exists(&store, project_id, profile_id)?;
    let allowed_secrets =
        policy_name.map(|name| allowed_scan_secrets(&store, project_id, name)).transpose()?;
    let known_values = collect_known_values(
        &store,
        project_id,
        profile_id,
        &master_key,
        now_unix_nanos,
        request,
        allowed_secrets.as_ref(),
    )?;
    let mut matches = ScanMatches { findings: Vec::new(), matched_secret_names: BTreeSet::new() };
    for input in &request.inputs {
        append_input_matches(input, &known_values, &mut matches);
    }
    append_scan_audit(&mut store, project_id, profile_id, &master_key, &matches, now_unix_nanos)?;
    Ok(ScanResponse { findings: matches.findings, locked: false })
}

fn allowed_scan_secrets(
    store: &Store,
    project_id: &str,
    policy_name: &str,
) -> Result<BTreeSet<String>, ScanFailure> {
    let policy = store
        .get_command_policy_index(project_id, policy_name)
        .map_err(|_| corrupt_db())?
        .ok_or_else(|| {
            ScanFailure::new(
                "PolicyNotFound",
                "command policy not found",
                LocketError::PolicyNotFound,
            )
        })?;
    // Match ResolveReference's durable-source checks. A deleted or changed
    // command must not retain the permissions from its previous index row.
    // Legacy indexes remain valid until the next explicit local policy edit.
    if let Some(path) = policy.normalized_json.get("source_path") {
        let path = path.as_str().ok_or_else(corrupt_db)?;
        let current = std::fs::symlink_metadata(path)
            .ok()
            .filter(|metadata| metadata.file_type().is_file())
            .and_then(|_| std::fs::read_to_string(path).ok())
            .and_then(|source| toml::from_str::<toml::Value>(&source).ok());
        let matches = current.as_ref().is_some_and(|document| {
            let digest_matches =
                policy.normalized_json.get("source_digest").is_none_or(|expected| {
                    expected.as_str().is_some_and(|expected| {
                        locket_core::policy::policy_source_digest(document, policy_name)
                            .ok()
                            .as_deref()
                            == Some(expected)
                    })
                });
            digest_matches
                && document.get("project_id").and_then(toml::Value::as_str) == Some(project_id)
                && document
                    .get("commands")
                    .and_then(|commands| commands.get(policy_name))
                    .and_then(|command| serde_json::to_value(command).ok())
                    .as_ref()
                    == Some(&policy.policy_json)
        });
        if !matches {
            return Err(ScanFailure::new(
                "AccessDenied",
                "command configuration changed; refresh and approve the local command before scanning",
                LocketError::AccessDenied,
            ));
        }
    }
    policy
        .normalized_json
        .get("allowed_secrets")
        .and_then(Value::as_array)
        .ok_or_else(corrupt_db)?
        .iter()
        .map(|name| name.as_str().map(str::to_owned).ok_or_else(corrupt_db))
        .collect()
}

fn ensure_profile_exists(
    store: &Store,
    project_id: &str,
    profile_id: &str,
) -> Result<(), ScanFailure> {
    let exists = store
        .list_profiles(project_id)
        .map_err(|_| corrupt_db())?
        .iter()
        .any(|profile| profile.id == profile_id);
    if exists {
        Ok(())
    } else {
        Err(ScanFailure::new(
            ERROR_PROFILE_NOT_FOUND,
            "profile not found",
            LocketError::ProfileNotFound,
        ))
    }
}

fn collect_known_values(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    master_key: &locket_crypto::KeyBytes,
    now_unix_nanos: i128,
    request: &ScanRequest,
    allowed_secrets: Option<&BTreeSet<String>>,
) -> Result<Vec<KnownSecret>, ScanFailure> {
    let mut known = Vec::new();
    // This request scans one profile. Unwrap its key lazily when the first
    // eligible encrypted blob is found, then reuse it for the whole scan.
    let mut profile_secret_key = None;
    let timestamp = i64::try_from(now_unix_nanos).map_err(|_| corrupt_db())?;
    for secret in store.list_secrets_by_profile(project_id, profile_id).map_err(|_| corrupt_db())? {
        if allowed_secrets.is_some_and(|allowed| !allowed.contains(&secret.name)) {
            continue;
        }
        for version in store.list_secret_versions(&secret.id).map_err(|_| corrupt_db())? {
            if !should_scan_known_version(&secret, &version, timestamp) {
                continue;
            }
            let Some(blob) =
                store.get_blob(&secret.id, version.version).map_err(|_| corrupt_db())?
            else {
                continue;
            };
            let key = match &profile_secret_key {
                Some(key) => key,
                None => profile_secret_key.insert(
                    unwrap_profile_key_with_master(
                        store,
                        project_id,
                        profile_id,
                        master_key,
                        KeyPurpose::ProfileSecret,
                    )
                    .map_err(|_| corrupt_db())?,
                ),
            };
            let value = decrypt_secret(project_id, profile_id, &secret, version.version, blob, key)
                .map_err(|_| corrupt_db())?;
            let label = if request.redact_names {
                privacy_alias("secret", &secret.id)
            } else {
                secret.name.clone()
            };
            known.push(KnownSecret {
                value,
                secret_name: secret.name.clone(),
                rule_label: format!("known-value/{label}"),
            });
        }
    }
    Ok(known)
}

fn append_input_matches(
    input: &ScanInput,
    known_values: &[KnownSecret],
    matches: &mut ScanMatches,
) {
    for known in known_values {
        if known.value.is_empty() {
            continue;
        }
        let mut cursor = 0;
        let mut position_cursor = 0;
        let (mut line, mut column) = (1_u32, 1_u32);
        while let Some(relative) = input.text[cursor..].find(known.value.as_str()) {
            let start = cursor + relative;
            // Preserve Unicode columns without rescanning the entire prefix
            // for every match in a dense input.
            for character in input.text[position_cursor..start].chars() {
                if character == '\n' {
                    line = line.saturating_add(1);
                    column = 1;
                } else {
                    column = column.saturating_add(1);
                }
            }
            position_cursor = start;
            matches.findings.push(ScanFinding {
                rule: known.rule_label.clone(),
                path: input.path.clone(),
                line,
                column,
                severity: "error".to_owned(),
                redacted_summary: "known secret value match".to_owned(),
                suppressed_by: None,
            });
            matches.matched_secret_names.insert(known.secret_name.clone());
            cursor = start + known.value.len();
        }
    }
}

fn append_scan_audit(
    store: &mut Store,
    project_id: &str,
    profile_id: &str,
    master_key: &locket_crypto::KeyBytes,
    matches: &ScanMatches,
    timestamp: i128,
) -> Result<(), ScanFailure> {
    let audit_key =
        unwrap_audit_key_with_master(store, project_id, master_key).map_err(|_| corrupt_db())?;
    let timestamp = i64::try_from(timestamp).map_err(|_| corrupt_db())?;
    let mut metadata = Map::from_iter([
        ("schema_version".to_owned(), json!(1)),
        ("action".to_owned(), json!("SCAN")),
        ("status".to_owned(), json!("SUCCESS")),
        ("command".to_owned(), json!(AGENT_SCAN_COMMAND)),
        ("scope".to_owned(), json!("agent")),
        ("profile_id".to_owned(), json!(profile_id)),
        ("known_value_coverage".to_owned(), json!(true)),
        ("pattern_only".to_owned(), json!(false)),
        ("finding_counts".to_owned(), json!({ "known_secret_value": matches.findings.len() })),
    ]);
    if !matches.matched_secret_names.is_empty() {
        metadata.insert(
            "redacted_secret_names".to_owned(),
            json!(matches.matched_secret_names.iter().collect::<Vec<_>>()),
        );
    }
    let metadata = Value::Object(metadata);
    let audit = AuditWrite {
        project_id,
        profile_id: Some(profile_id),
        action: "SCAN",
        status: "SUCCESS",
        secret_name: None,
        command: Some(AGENT_SCAN_COMMAND),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit).map_err(|_| corrupt_db())?;
    Ok(())
}

fn should_scan_known_version(
    secret: &SecretRecord,
    version: &SecretVersionRecord,
    timestamp: i64,
) -> bool {
    match version.state.as_str() {
        "current" => secret.state == "active" || version.version == secret.current_version,
        "deprecated" => version.grace_until.is_some_and(|grace_until| grace_until > timestamp),
        _ => false,
    }
}

fn decrypt_secret(
    project_id: &str,
    profile_id: &str,
    secret: &SecretRecord,
    version: u32,
    blob: SecretBlobRecord,
    profile_secret_key: &locket_crypto::KeyBytes,
) -> Result<Zeroizing<String>, locket_crypto::CryptoError> {
    let value_aad = secret_blob_aad_v1(&locket_crypto::SecretBlobAad::new(
        project_id,
        profile_id,
        &secret.id,
        &secret.name,
        version,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &secret.id,
        Some(profile_id),
        version,
        KeyWrapPurpose::SecretDek,
    ))?;
    let encrypted = EncryptedSecretValue {
        encrypted_dek: blob.encrypted_dek,
        ciphertext: blob.ciphertext,
        value_nonce: blob.value_nonce,
        aad_schema_version: blob.aad_schema_version,
    };
    decrypt_secret_value_v1(profile_secret_key, &encrypted, &value_aad, &wrap_aad)
}

const fn corrupt_db() -> ScanFailure {
    ScanFailure::new(ERROR_CORRUPT_DB, "known-value scan failed", LocketError::CorruptDb)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::{ScanFinding, ScanInput, ScanRequest, ScanResponse, handle_scan};
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::grant::{GrantAction, GrantBinding, GrantRecord, GrantRecordFields};
    use crate::method::AgentMethod;
    use crate::server::AgentSocketState;
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};
    use locket_crypto::{
        HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, SecretBlobAad,
        derive_wrapping_key_v1, encrypt_secret_value_v1, key_wrap_aad_v1, secret_blob_aad_v1,
        secret_fingerprint_v1, wrap_key_material_v1,
    };
    use locket_store::{
        KeyRecord, SecretBlobRecord, SecretFingerprintRecord, SecretRecord, SecretVersionRecord,
        Store,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::{TempDir, tempdir};

    const PROJECT_ID: &str = "lk_proj_scan";
    const PROFILE_ID: &str = "lk_prof_dev";
    const PROFILE_NAME: &str = "dev";
    const SECRET_ID: &str = "lk_sec_current";
    const SECRET_NAME: &str = "DATABASE_URL";
    const GRACE_SECRET_ID: &str = "lk_sec_grace";
    const GRACE_SECRET_NAME: &str = "API_TOKEN";
    const GRANT_ID: &str = "lk_grant_scan";

    struct ScanFixture {
        _directory: TempDir,
        store_path: PathBuf,
        master_key: locket_crypto::KeyBytes,
        current_value: String,
        grace_value: String,
    }

    #[test]
    fn known_matches_preserve_unicode_columns_and_multiline_values() {
        let input = ScanInput {
            path: "sample.txt".to_owned(),
            text: "é🦀:a\nb;a\nb\r\na\nb".to_owned(),
        };
        let known = super::KnownSecret {
            value: zeroize::Zeroizing::new("a\nb".to_owned()),
            secret_name: "TEST_VALUE".to_owned(),
            rule_label: "known-value/TEST_VALUE".to_owned(),
        };
        let mut matches = super::ScanMatches {
            findings: Vec::new(),
            matched_secret_names: std::collections::BTreeSet::new(),
        };
        super::append_input_matches(&input, &[known], &mut matches);
        assert_eq!(
            matches
                .findings
                .iter()
                .map(|finding| (finding.line, finding.column))
                .collect::<Vec<_>>(),
            [(1, 4), (2, 3), (4, 1)]
        );
        assert_eq!(
            matches.matched_secret_names,
            std::collections::BTreeSet::from(["TEST_VALUE".to_owned()])
        );
        for finding in matches.findings {
            assert_eq!(finding.path, "sample.txt");
            assert_eq!(finding.rule, "known-value/TEST_VALUE");
            assert_eq!(finding.redacted_summary, "known secret value match");
        }
    }

    #[test]
    fn scan_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request = ScanRequest {
            inputs: vec![ScanInput { path: "src/main.rs".to_owned(), text: "text".to_owned() }],
            project_id: Some(PROJECT_ID.to_owned()),
            profile_id: Some(PROFILE_ID.to_owned()),
            store_path: Some(PathBuf::from("/tmp/store.db")),
            grant_id: Some(GRANT_ID.to_owned()),
            binding: Some(GrantBinding::new(123, "start")),
            require_known: true,
            redact_names: true,
        };

        let value = serde_json::to_value(&request)?;
        let decoded: ScanRequest = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, request);
        assert_eq!(value["require_known"], true);
        assert_eq!(value["inputs"][0]["path"], "src/main.rs");
        assert_eq!(value["project_id"], PROJECT_ID);
        Ok(())
    }

    #[test]
    fn scan_finding_preserves_optional_suppressed_by() -> Result<(), serde_json::Error> {
        let finding = ScanFinding {
            rule: "known-value/db".to_owned(),
            path: "src/main.rs".to_owned(),
            line: 12,
            column: 5,
            severity: "warn".to_owned(),
            redacted_summary: "let token = \"***\";".to_owned(),
            suppressed_by: Some("locket-ignore/line".to_owned()),
        };

        let value = serde_json::to_value(&finding)?;
        let decoded: ScanFinding = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, finding);
        assert_eq!(value["suppressed_by"], "locket-ignore/line");
        Ok(())
    }

    #[test]
    fn scan_response_round_trips_through_json() -> Result<(), serde_json::Error> {
        let response = ScanResponse { findings: vec![], locked: true };

        let value = serde_json::to_value(&response)?;
        let decoded: ScanResponse = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, response);
        assert_eq!(value["locked"], true);
        assert!(value["findings"].as_array().is_some_and(Vec::is_empty));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_rejects_requests_without_project_context() {
        let state = AgentSocketState::locked("test-version");
        let envelope = RequestEnvelope::new(
            "req-scan",
            AgentMethod::ScanKnownValues,
            json!({"inputs": [], "require_known": false}),
        );

        let response = handle_scan(&envelope, &state, 1).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "ProtocolError");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_rejects_malformed_payload_with_protocol_error() {
        let state = AgentSocketState::locked("test-version");
        let envelope =
            RequestEnvelope::new("req-bad", AgentMethod::ScanKnownValues, json!({"inputs": 5}));

        let response = handle_scan(&envelope, &state, 1).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "ProtocolError");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_requires_live_grant() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture, false).await;
        let envelope = scan_envelope(&scan_request(&fixture, true, false));

        let response = handle_scan(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "GrantRequired");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_requires_unlock_when_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = build_fixture()?;
        let state = granted_state(true).await;
        let envelope = scan_envelope(&scan_request(&fixture, true, false));

        let response = handle_scan(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "UnlockRequired");

        // The scan refusal must mirror into the degraded-audit log when
        // a store path was supplied so its parent is the LOCKET_HOME.
        let degraded_log = fixture
            .store_path
            .parent()
            .ok_or("store path should have parent")?
            .join(locket_platform::DEGRADED_AUDIT_LOG_FILENAME);
        let body = std::fs::read_to_string(&degraded_log)?;
        let row: serde_json::Value =
            serde_json::from_str(body.lines().next().ok_or("expected degraded audit row")?)?;
        assert_eq!(row["action"], "SCAN");
        assert_eq!(row["status"], "DENIED_LOCKED");
        assert_eq!(row["command"], "agent.ScanKnownValues");
        assert_eq!(row["project_id"], PROJECT_ID);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_returns_locked_gap_when_not_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = granted_state(true).await;
        let envelope = scan_envelope(&scan_request(&fixture, false, false));

        let response = handle_scan(&envelope, &state, 1).await;
        let payload = scan_payload(response)?;
        assert!(payload.locked);
        assert_eq!(payload.findings.len(), 0);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_matches_known_values_without_leaking_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture, true).await;
        let envelope = scan_envelope(&scan_request(&fixture, true, false));

        let response = handle_scan(&envelope, &state, 1).await;
        let response_json = serde_json::to_string(&response)?;
        assert!(!response_json.contains(&fixture.current_value));
        assert!(!response_json.contains(&fixture.grace_value));
        let payload = scan_payload(response)?;
        assert!(!payload.locked);
        assert_eq!(payload.findings.len(), 2);
        let status = state.status_snapshot(1).await;
        assert_eq!(status.scan_warning_count, 2);
        let current = payload
            .findings
            .iter()
            .find(|finding| finding.rule == "known-value/DATABASE_URL")
            .ok_or("missing current secret finding")?;
        assert_eq!(current.path, "src/main.rs");
        assert_eq!(current.line, 2);
        assert_eq!(current.column, 1);
        assert_eq!(current.severity, "error");
        assert_eq!(current.redacted_summary, "known secret value match");
        assert!(payload.findings.iter().any(|finding| finding.rule == "known-value/DATABASE_URL"));
        assert!(payload.findings.iter().any(|finding| finding.rule == "known-value/API_TOKEN"));

        let audit = scan_audit_metadata(&fixture)?;
        assert_eq!(audit["status"], "SUCCESS");
        assert_eq!(audit["command"], "agent-scan-known-values");
        assert_eq!(audit["profile_id"], PROFILE_ID);
        assert_eq!(audit["known_value_coverage"], true);
        assert_eq!(audit["pattern_only"], false);
        assert_eq!(audit["finding_counts"]["known_secret_value"], 2);
        assert_eq!(audit["redacted_secret_names"][0], GRACE_SECRET_NAME);
        assert_eq!(audit["redacted_secret_names"][1], SECRET_NAME);
        let audit_json = serde_json::to_string(&audit)?;
        assert!(!audit_json.contains(&fixture.current_value));
        assert!(!audit_json.contains(&fixture.grace_value));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_uses_privacy_aliases_for_finding_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture, true).await;
        let envelope = scan_envelope(&scan_request(&fixture, true, true));

        let payload = scan_payload(handle_scan(&envelope, &state, 1).await)?;

        assert!(
            payload.findings.iter().all(|finding| finding.rule.starts_with("known-value/secret-"))
        );
        assert!(payload.findings.iter().all(|finding| !finding.rule.contains(SECRET_NAME)));
        assert!(payload.findings.iter().all(|finding| !finding.rule.contains(GRACE_SECRET_NAME)));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_excludes_deprecated_values_after_grace()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture, true).await;
        let envelope = scan_envelope(&scan_request(&fixture, true, false));

        let payload = scan_payload(handle_scan(&envelope, &state, 100).await)?;

        assert_eq!(payload.findings.len(), 1);
        assert_eq!(payload.findings[0].rule, "known-value/DATABASE_URL");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_returns_profile_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = AgentSocketState::locked("test-version");
        state.grants.lock().await.insert(test_grant_record_for_profile("lk_prof_missing"));
        state.unlock_cache.lock().await.insert(
            PROJECT_ID.to_owned(),
            UnlockEntry::new(
                fixture.master_key.to_vec(),
                0,
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        let mut request = scan_request(&fixture, true, false);
        request.profile_id = Some("lk_prof_missing".to_owned());
        let envelope = scan_envelope(&request);

        let response = handle_scan(&envelope, &state, 1).await;

        assert_eq!(error_code(response)?, "ProfileNotFound");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_maps_store_open_failure_to_corrupt_db()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture, true).await;
        let mut request = scan_request(&fixture, true, false);
        request.store_path = Some(fixture.store_path.with_file_name("missing-store.db"));
        let envelope = scan_envelope(&request);

        let response = handle_scan(&envelope, &state, 1).await;

        assert_eq!(error_code(response)?, "CorruptDb");
        Ok(())
    }

    fn scan_request(fixture: &ScanFixture, require_known: bool, redact_names: bool) -> ScanRequest {
        ScanRequest {
            inputs: vec![ScanInput {
                path: "src/main.rs".to_owned(),
                text: format!("prefix\n{} then {}", fixture.current_value, fixture.grace_value),
            }],
            project_id: Some(PROJECT_ID.to_owned()),
            profile_id: Some(PROFILE_ID.to_owned()),
            store_path: Some(fixture.store_path.clone()),
            grant_id: Some(GRANT_ID.to_owned()),
            binding: Some(GrantBinding::new(std::process::id(), "0")),
            require_known,
            redact_names,
        }
    }

    mod automation_scope {
        use super::*;
        use crate::server::{current_unix_nanos, dispatch};
        use ed25519_dalek::{Signer, SigningKey};
        use serde_json::Value;
        use sha2::{Digest, Sha256};

        const POLICY: &str = "scan-policy";
        const CLIENT: &str = "lk_client_scan";
        type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

        async fn fixture() -> TestResult<(ScanFixture, AgentSocketState)> {
            let fixture = build_fixture()?;
            let mut store = Store::open(&fixture.store_path)?;
            store.connection().execute(
                "UPDATE secret_versions SET grace_until = ?1 WHERE secret_id = ?2",
                rusqlite::params![i64::MAX, GRACE_SECRET_ID],
            )?;
            store.insert_automation_client(&locket_store::AutomationClientRecord {
                id: CLIENT.to_owned(),
                project_id: PROJECT_ID.to_owned(),
                name: "scanner".to_owned(),
                public_key: SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes().to_vec(),
                fingerprint: "scan-test-fingerprint".to_owned(),
                storage: "external".to_owned(),
                allowed_actions: vec!["scan-known-values".to_owned(), "redact".to_owned()],
                allowed_policies: vec![POLICY.to_owned()],
                created_at: 1,
                last_used_at: None,
                revoked_at: None,
            })?;
            save_policy(&mut store, PROJECT_ID, &json!({"allowed_secrets": [SECRET_NAME]}))?;
            let now = current_unix_nanos();
            let state = AgentSocketState::locked("scan-test");
            state.unlock_cache.lock().await.insert(
                PROJECT_ID.to_owned(),
                UnlockEntry::new(
                    fixture.master_key.to_vec(),
                    now,
                    Duration::from_secs(60),
                    UnlockMethod::Passphrase,
                ),
            );
            state.grants.lock().await.insert(GrantRecord::new(GrantRecordFields {
                grant_id: GRANT_ID.to_owned(),
                project_id: PROJECT_ID.to_owned(),
                profile_id: PROFILE_ID.to_owned(),
                action: GrantAction::ScanKnownValues,
                binding: GrantBinding::new(std::process::id(), "0"),
                issued_at_unix_nanos: now,
                ttl_seconds: 60,
                expires_at_unix_nanos: now + 60_000_000_000,
            }));
            Ok((fixture, state))
        }

        fn save_policy(store: &mut Store, project: &str, normalized: &Value) -> TestResult {
            store.upsert_command_policy_index(
                project,
                POLICY,
                &json!({"argv": ["scanner"], "required_secrets": [SECRET_NAME]}),
                normalized,
                1,
                None,
            )?;
            Ok(())
        }

        fn request(fixture: &ScanFixture, action: &str) -> RequestEnvelope {
            let mut request = scan_envelope(&scan_request(fixture, true, false));
            request.payload["policy_name"] = json!(POLICY);
            request.payload["requested_action"] = json!(action);
            // Neither a caller-provided allow-list nor a replacement policy is authoritative.
            request.payload["allowed_secrets"] = json!([GRACE_SECRET_NAME]);
            request.payload["policy"] = json!({"allowed_secrets": [GRACE_SECRET_NAME]});
            request
        }

        async fn sign(
            state: &AgentSocketState,
            mut request: RequestEnvelope,
        ) -> TestResult<RequestEnvelope> {
            let hello = RequestEnvelope::new(
                "hello",
                AgentMethod::ClientHello,
                json!({"client_id": CLIENT}),
            );
            let ResponseEnvelope::Success(challenge) = dispatch(&hello, state).await else {
                return Err("ClientHello failed".into());
            };
            let challenge_id = challenge.payload["challenge_id"].as_str().ok_or("challenge id")?;
            let nonce = challenge.payload["nonce"].as_str().ok_or("nonce")?;
            let now = i64::try_from(current_unix_nanos())?;
            let mut canonical = serde_json::to_value(&request)?;
            canonical.sort_all_objects();
            let hash = Sha256::digest(serde_json::to_vec(&canonical)?);
            let mut message = b"locket-client-auth-v1".to_vec();
            message.extend_from_slice(CLIENT.as_bytes());
            message.extend_from_slice(challenge_id.as_bytes());
            message.extend_from_slice(&data_encoding::BASE64URL_NOPAD.decode(nonce.as_bytes())?);
            message.extend_from_slice(now.to_string().as_bytes());
            message.extend_from_slice(request.id.as_bytes());
            message.extend_from_slice(&hash);
            let signature = SigningKey::from_bytes(&[42; 32]).sign(&message);
            request.payload["auth"] = json!({
                "client_id": CLIENT, "challenge_id": challenge_id, "nonce": nonce,
                "request_timestamp": now,
                "signature": data_encoding::BASE64URL_NOPAD.encode(&signature.to_bytes()),
            });
            Ok(request)
        }

        fn audit_count(fixture: &ScanFixture, action: &str) -> TestResult<i64> {
            Ok(Store::open(&fixture.store_path)?.connection().query_row(
                "SELECT COUNT(*) FROM audit_log WHERE action = ?1",
                [action],
                |row| row.get(0),
            )?)
        }

        fn assert_no_values(response: &ResponseEnvelope, fixture: &ScanFixture) -> TestResult {
            let serialized = serde_json::to_string(response)?;
            assert!(!serialized.contains(&fixture.current_value));
            assert!(!serialized.contains(&fixture.grace_value));
            Ok(())
        }

        #[tokio::test(flavor = "current_thread")]
        async fn signed_scan_and_redact_match_only_saved_policy_secrets() -> TestResult {
            for action in ["scan-known-values", "redact"] {
                let (fixture, state) = fixture().await?;
                let request = sign(&state, request(&fixture, action)).await?;
                let response = dispatch(&request, &state).await;
                assert_eq!(audit_count(&fixture, "CLIENT_AUTH")?, 1);
                assert_no_values(&response, &fixture)?;
                let payload = scan_payload(response)?;
                assert!(!payload.locked);
                assert_eq!(payload.findings.len(), 1, "excluded canary must not match");
                assert_eq!(payload.findings[0].rule, "known-value/DATABASE_URL");
                assert_eq!(state.status_snapshot(current_unix_nanos()).await.scan_warning_count, 1);
                assert_eq!(audit_count(&fixture, "SCAN")?, 1);
                let audit = scan_audit_metadata(&fixture)?;
                assert_eq!(audit["finding_counts"]["known_secret_value"], 1);
                assert_eq!(audit["redacted_secret_names"], json!([SECRET_NAME]));
                assert!(!serde_json::to_string(&audit)?.contains(&fixture.grace_value));
            }
            Ok(())
        }

        #[tokio::test(flavor = "current_thread")]
        async fn signed_scan_filters_excluded_secret_before_decryption() -> TestResult {
            let (fixture, state) = fixture().await?;
            let mut store = Store::open(&fixture.store_path)?;
            store.connection().execute(
                "UPDATE blobs SET ciphertext = zeroblob(16) WHERE secret_id = ?1",
                [GRACE_SECRET_ID],
            )?;
            let signed = sign(&state, request(&fixture, "scan-known-values")).await?;
            assert_eq!(scan_payload(dispatch(&signed, &state).await)?.findings.len(), 1);
            // This corrupt blob really is unreadable if the saved policy authorizes it.
            save_policy(&mut store, PROJECT_ID, &json!({"allowed_secrets": [GRACE_SECRET_NAME]}))?;
            let signed = sign(&state, request(&fixture, "scan-known-values")).await?;
            assert_eq!(error_code(dispatch(&signed, &state).await)?, "CorruptDb");
            assert_eq!(audit_count(&fixture, "SCAN")?, 1);
            Ok(())
        }

        #[tokio::test(flavor = "current_thread")]
        async fn signed_scan_empty_policy_has_zero_matches_and_audit_count() -> TestResult {
            let (fixture, state) = fixture().await?;
            save_policy(
                &mut Store::open(&fixture.store_path)?,
                PROJECT_ID,
                &json!({"allowed_secrets": []}),
            )?;
            let signed = sign(&state, request(&fixture, "scan-known-values")).await?;
            let payload = scan_payload(dispatch(&signed, &state).await)?;
            assert!(!payload.locked);
            assert_eq!(payload.findings.len(), 0);
            assert_eq!(audit_count(&fixture, "SCAN")?, 1);
            assert_eq!(scan_audit_metadata(&fixture)?["finding_counts"]["known_secret_value"], 0);
            Ok(())
        }

        #[tokio::test(flavor = "current_thread")]
        async fn unsigned_scan_preserves_full_profile_even_with_policy_metadata() -> TestResult {
            let (fixture, state) = fixture().await?;
            let payload =
                scan_payload(dispatch(&request(&fixture, "scan-known-values"), &state).await)?;
            assert_eq!(payload.findings.len(), 2);
            assert_eq!(audit_count(&fixture, "CLIENT_AUTH")?, 0);
            assert_eq!(scan_audit_metadata(&fixture)?["finding_counts"]["known_secret_value"], 2);
            Ok(())
        }

        #[tokio::test(flavor = "current_thread")]
        async fn signed_scan_rejects_missing_or_foreign_saved_policy() -> TestResult {
            for foreign in [false, true] {
                let (fixture, state) = fixture().await?;
                let mut store = Store::open(&fixture.store_path)?;
                store.delete_command_policy_index(PROJECT_ID, POLICY, None)?;
                if foreign {
                    store.insert_project_if_absent("lk_proj_foreign", "foreign", 1)?;
                    save_policy(
                        &mut store,
                        "lk_proj_foreign",
                        &json!({"allowed_secrets": [SECRET_NAME, GRACE_SECRET_NAME]}),
                    )?;
                }
                let signed = sign(&state, request(&fixture, "scan-known-values")).await?;
                let response = dispatch(&signed, &state).await;
                assert_no_values(&response, &fixture)?;
                assert_eq!(error_code(response)?, "PolicyNotFound");
                assert_eq!(audit_count(&fixture, "CLIENT_AUTH")?, 1);
                assert_eq!(audit_count(&fixture, "SCAN")?, 0);
            }
            Ok(())
        }

        #[tokio::test(flavor = "current_thread")]
        async fn signed_scan_rejects_malformed_saved_allow_list() -> TestResult {
            for normalized in [
                json!({}),
                json!({"allowed_secrets": SECRET_NAME}),
                json!({"allowed_secrets": [SECRET_NAME, false]}),
            ] {
                let (fixture, state) = fixture().await?;
                save_policy(&mut Store::open(&fixture.store_path)?, PROJECT_ID, &normalized)?;
                let signed = sign(&state, request(&fixture, "scan-known-values")).await?;
                let response = dispatch(&signed, &state).await;
                assert_no_values(&response, &fixture)?;
                assert_eq!(error_code(response)?, "CorruptDb");
                assert_eq!(audit_count(&fixture, "SCAN")?, 0);
            }
            Ok(())
        }

        #[tokio::test(flavor = "current_thread")]
        async fn signed_scan_rejects_invalid_request_policy_scope() -> TestResult {
            for policy in [
                None,
                Some(Value::Null),
                Some(json!(7)),
                Some(json!(" ")),
                Some(json!("foreign-policy")),
            ] {
                let (fixture, state) = fixture().await?;
                let mut request = request(&fixture, "scan-known-values");
                let expected = if policy == Some(json!("foreign-policy")) {
                    "AutomationClientNotTrusted"
                } else {
                    "ProtocolError"
                };
                if let Some(policy) = policy {
                    request.payload["policy_name"] = policy;
                } else {
                    request.payload.as_object_mut().ok_or("payload")?.remove("policy_name");
                }
                let signed = sign(&state, request).await?;
                let response = dispatch(&signed, &state).await;
                assert_no_values(&response, &fixture)?;
                assert_eq!(error_code(response)?, expected);
                assert_eq!(audit_count(&fixture, "SCAN")?, 0);
            }
            Ok(())
        }

        #[tokio::test(flavor = "current_thread")]
        async fn signed_scan_requires_current_durable_policy_source() -> TestResult {
            for change in ["changed", "deleted", "foreign"] {
                let (fixture, state) = fixture().await?;
                let path = fixture.store_path.with_file_name("locket.toml");
                let source = format!(
                    "project_id = {PROJECT_ID:?}\n[commands.{POLICY}]\nargv = [\"scanner\"]\nrequired_secrets = [{SECRET_NAME:?}]\n"
                );
                std::fs::write(&path, &source)?;
                let document: toml::Value = toml::from_str(&source)?;
                let digest = locket_core::policy::policy_source_digest(&document, POLICY)?;
                save_policy(
                    &mut Store::open(&fixture.store_path)?,
                    PROJECT_ID,
                    &json!({
                        "allowed_secrets": [SECRET_NAME], "source_path": path, "source_digest": digest,
                    }),
                )?;
                let signed = sign(&state, request(&fixture, "scan-known-values")).await?;
                scan_payload(dispatch(&signed, &state).await)?;
                match change {
                    "deleted" => std::fs::remove_file(&path)?,
                    "foreign" => {
                        std::fs::write(&path, source.replace(PROJECT_ID, "lk_proj_foreign"))?;
                    }
                    _ => std::fs::write(&path, source.replace(SECRET_NAME, GRACE_SECRET_NAME))?,
                }
                let signed = sign(&state, request(&fixture, "scan-known-values")).await?;
                assert_eq!(error_code(dispatch(&signed, &state).await)?, "AccessDenied");
                assert_eq!(audit_count(&fixture, "SCAN")?, 1);
            }
            Ok(())
        }
    }

    fn scan_envelope(request: &ScanRequest) -> RequestEnvelope {
        RequestEnvelope::new(
            "req-scan",
            AgentMethod::ScanKnownValues,
            serde_json::to_value(request).unwrap(),
        )
    }

    async fn unlocked_state(fixture: &ScanFixture, grant: bool) -> AgentSocketState {
        let state = granted_state(grant).await;
        state.unlock_cache.lock().await.insert(
            PROJECT_ID.to_owned(),
            UnlockEntry::new(
                fixture.master_key.to_vec(),
                0,
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        state
    }

    async fn granted_state(grant: bool) -> AgentSocketState {
        let state = AgentSocketState::locked("test-version");
        if grant {
            state.grants.lock().await.insert(test_grant_record());
        }
        state
    }

    fn test_grant_record() -> GrantRecord {
        test_grant_record_for_profile(PROFILE_ID)
    }

    fn test_grant_record_for_profile(profile_id: &str) -> GrantRecord {
        GrantRecord::new(GrantRecordFields {
            grant_id: GRANT_ID.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: profile_id.to_owned(),
            action: GrantAction::ScanKnownValues,
            binding: GrantBinding::new(std::process::id(), "0"),
            issued_at_unix_nanos: 0,
            ttl_seconds: 30,
            expires_at_unix_nanos: 1_000,
        })
    }

    fn scan_payload(
        response: ResponseEnvelope,
    ) -> Result<ScanResponse, Box<dyn std::error::Error>> {
        let ResponseEnvelope::Success(success) = response else {
            return Err(format!("expected success envelope, got {response:?}").into());
        };
        Ok(serde_json::from_value(success.payload)?)
    }

    fn error_code(response: ResponseEnvelope) -> Result<String, Box<dyn std::error::Error>> {
        let ResponseEnvelope::Error(error) = response else {
            return Err("expected error envelope".into());
        };
        Ok(error.error)
    }

    fn scan_audit_metadata(
        fixture: &ScanFixture,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let store = Store::open(&fixture.store_path)?;
        let row = store.connection().query_row(
            "SELECT action, status, profile_id, command, metadata_json
             FROM audit_log
             WHERE project_id = ?1 AND action = 'SCAN'
             ORDER BY sequence DESC
             LIMIT 1",
            [PROJECT_ID],
            |row| {
                let action: String = row.get(0)?;
                let status: String = row.get(1)?;
                let profile_id: Option<String> = row.get(2)?;
                let command: Option<String> = row.get(3)?;
                let metadata: String = row.get(4)?;
                Ok((action, status, profile_id, command, metadata))
            },
        )?;
        assert_eq!(row.0, "SCAN");
        assert_eq!(row.1, "SUCCESS");
        assert_eq!(row.2.as_deref(), Some(PROFILE_ID));
        assert_eq!(row.3.as_deref(), Some("agent-scan-known-values"));
        Ok(serde_json::from_str(&row.4)?)
    }

    fn build_fixture() -> Result<ScanFixture, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let store_path = directory.path().join("store.db");
        let mut store = Store::open(&store_path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT_ID, "scan-test", 1)?;
        store.insert_profile_if_absent(PROFILE_ID, PROJECT_ID, PROFILE_NAME, false, 1)?;

        let master_key = [7_u8; 32];
        let audit_key = [10_u8; 32];
        let profile_secret_key = [8_u8; 32];
        let profile_fingerprint_key = [9_u8; 32];
        insert_wrapped_project_key(
            &store,
            "lk_key_project_audit",
            KeyPurpose::Audit,
            &master_key,
            &audit_key,
        )?;
        insert_wrapped_profile_key(
            &store,
            "lk_key_profile_secret",
            KeyPurpose::ProfileSecret,
            &master_key,
            &profile_secret_key,
        )?;
        insert_wrapped_profile_key(
            &store,
            "lk_key_profile_fingerprint",
            KeyPurpose::ProfileFingerprint,
            &master_key,
            &profile_fingerprint_key,
        )?;

        let current_value = "fixture-current-value".to_owned();
        let grace_value = "fixture-grace-value".to_owned();
        insert_encrypted_secret(
            &mut store,
            SecretInsert {
                secret_id: SECRET_ID,
                secret_name: SECRET_NAME,
                current_version: 1,
                version: 1,
                version_state: "current",
                grace_until: None,
                value: &current_value,
            },
            &profile_secret_key,
            &profile_fingerprint_key,
        )?;
        insert_encrypted_secret(
            &mut store,
            SecretInsert {
                secret_id: GRACE_SECRET_ID,
                secret_name: GRACE_SECRET_NAME,
                current_version: 2,
                version: 1,
                version_state: "deprecated",
                grace_until: Some(50),
                value: &grace_value,
            },
            &profile_secret_key,
            &profile_fingerprint_key,
        )?;

        Ok(ScanFixture {
            _directory: directory,
            store_path,
            master_key,
            current_value,
            grace_value,
        })
    }

    fn insert_wrapped_project_key(
        store: &Store,
        key_id: &str,
        purpose: KeyPurpose,
        master_key: &locket_crypto::KeyBytes,
        key_material: &locket_crypto::KeyBytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wrapping_key =
            derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(PROJECT_ID, None, purpose))?;
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            key_id,
            None,
            0,
            KeyWrapPurpose::from(purpose),
        ))?;
        let wrapped = wrap_key_material_v1(&wrapping_key, key_material, &aad)?;
        store.insert_key(&KeyRecord {
            id: key_id.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: None,
            purpose: purpose.as_str().to_owned(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: 1,
        })?;
        Ok(())
    }

    fn insert_wrapped_profile_key(
        store: &Store,
        key_id: &str,
        purpose: KeyPurpose,
        master_key: &locket_crypto::KeyBytes,
        key_material: &locket_crypto::KeyBytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wrapping_key = derive_wrapping_key_v1(
            master_key,
            &HkdfWrapInfo::new(PROJECT_ID, Some(PROFILE_ID), purpose),
        )?;
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            key_id,
            Some(PROFILE_ID),
            0,
            KeyWrapPurpose::from(purpose),
        ))?;
        let wrapped = wrap_key_material_v1(&wrapping_key, key_material, &aad)?;
        store.insert_key(&KeyRecord {
            id: key_id.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: Some(PROFILE_ID.to_owned()),
            purpose: purpose.as_str().to_owned(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: 1,
        })?;
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct SecretInsert<'a> {
        secret_id: &'a str,
        secret_name: &'a str,
        current_version: u32,
        version: u32,
        version_state: &'a str,
        grace_until: Option<i64>,
        value: &'a str,
    }

    fn insert_encrypted_secret(
        store: &mut Store,
        insert: SecretInsert<'_>,
        profile_secret_key: &locket_crypto::KeyBytes,
        profile_fingerprint_key: &locket_crypto::KeyBytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
            PROJECT_ID,
            PROFILE_ID,
            insert.secret_id,
            insert.secret_name,
            insert.version,
        ))?;
        let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            insert.secret_id,
            Some(PROFILE_ID),
            insert.version,
            KeyWrapPurpose::SecretDek,
        ))?;
        let encrypted =
            encrypt_secret_value_v1(profile_secret_key, insert.value, &value_aad, &wrap_aad)?;
        let fingerprint = secret_fingerprint_v1(profile_fingerprint_key, insert.value)?;
        let secret = SecretRecord {
            id: insert.secret_id.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
            name: insert.secret_name.to_owned(),
            source: "user-local".to_owned(),
            origin: "manual".to_owned(),
            current_version: insert.current_version,
            state: "active".to_owned(),
            created_at: 1,
            updated_at: 1,
            last_rotated_at: None,
            deleted_at: None,
        };
        let version = SecretVersionRecord {
            secret_id: insert.secret_id.to_owned(),
            version: insert.version,
            source: "user-local".to_owned(),
            origin: "manual".to_owned(),
            state: insert.version_state.to_owned(),
            created_at: 1,
            deprecated_at: if insert.version_state == "deprecated" { Some(1) } else { None },
            grace_until: insert.grace_until,
            purged_at: None,
        };
        let blob = SecretBlobRecord {
            secret_id: insert.secret_id.to_owned(),
            version: insert.version,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: 1,
            created_at: 1,
        };
        let fingerprint = SecretFingerprintRecord {
            secret_id: insert.secret_id.to_owned(),
            version: insert.version,
            fingerprint: fingerprint.to_vec(),
            created_at: 1,
        };
        store.create_active_secret(&secret, &version, &blob, &fingerprint)?;
        Ok(())
    }
}
