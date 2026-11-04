//! In-memory live grant records for the local agent.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Process identity attached to a live grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GrantBinding {
    /// Operating-system process id.
    pub pid: u32,
    /// Opaque platform start-time token captured when the grant was issued.
    pub process_start_time: String,
    /// Optional execution context. Bound to the grant alongside process identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionScope>,
}

/// Command and directory whose effective policy governs reference delivery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionScope {
    /// Saved command identity; command argv is loaded from its durable policy.
    pub policy_name: String,
    /// Canonical absolute working directory selected for execution.
    pub cwd: std::path::PathBuf,
}

impl GrantBinding {
    /// Creates a process-bound grant identity.
    #[must_use]
    pub fn new(pid: u32, process_start_time: impl Into<String>) -> Self {
        Self { pid, process_start_time: process_start_time.into(), execution: None }
    }

    /// Binds this grant to a saved command and its working directory.
    #[must_use]
    pub fn with_execution(
        mut self,
        policy_name: impl Into<String>,
        cwd: std::path::PathBuf,
    ) -> Self {
        self.execution = Some(ExecutionScope { policy_name: policy_name.into(), cwd });
        self
    }
}

/// Action set authorized by a live grant.
///
/// Spec: `docs/specs/agent.md:36-37`, `docs/specs/data-model.md:386-395`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum GrantAction {
    /// Configure or explicitly trigger locally authorized team synchronization.
    TeamSync,
    /// Run a command policy.
    RunPolicy,
    /// Prepare a command policy for a trusted CLI execution path.
    /// See `docs/specs/data-model.md:386-395` and `docs/specs/agent.md:91-92`.
    PrepareExec,
    /// Resolve an `lk://` reference.
    ResolveReference,
    /// Scan known secret values without persisting them.
    ScanKnownValues,
    /// Reveal one secret value through a gated path.
    Reveal,
    /// Copy one secret value through a gated path.
    Copy,
    /// Redact one secret value from a gated rendering path.
    Redact,
    /// Export secret values through a gated bulk path.
    Export,
    /// Create or rotate one secret value through a gated path.
    SetSecret,
    /// Import a batch into the selected profile.
    ImportDotenv,
    /// Persist an execution policy edit.
    ApplyPolicy,
}

/// Metadata-only live grant record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GrantRecord {
    /// Opaque grant id. This is never a secret value.
    pub grant_id: String,
    /// Project identifier the grant is scoped to.
    pub project_id: String,
    /// Profile identifier the grant is scoped to.
    pub profile_id: String,
    /// Authorized action.
    pub action: GrantAction,
    /// Process identity required to use the grant.
    pub binding: GrantBinding,
    /// Issue timestamp in Unix nanoseconds.
    pub issued_at_unix_nanos: i128,
    /// TTL in seconds.
    pub ttl_seconds: u64,
    /// Expiry timestamp in Unix nanoseconds.
    pub expires_at_unix_nanos: i128,
}

/// Fields required to create a metadata-only grant record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GrantRecordFields {
    /// Opaque grant id. This is never a secret value.
    pub grant_id: String,
    /// Project identifier the grant is scoped to.
    pub project_id: String,
    /// Profile identifier the grant is scoped to.
    pub profile_id: String,
    /// Authorized action.
    pub action: GrantAction,
    /// Process identity required to use the grant.
    pub binding: GrantBinding,
    /// Issue timestamp in Unix nanoseconds.
    pub issued_at_unix_nanos: i128,
    /// TTL in seconds.
    pub ttl_seconds: u64,
    /// Expiry timestamp in Unix nanoseconds.
    pub expires_at_unix_nanos: i128,
}

impl GrantRecord {
    /// Creates a metadata-only grant record.
    #[must_use]
    pub fn new(fields: GrantRecordFields) -> Self {
        Self {
            grant_id: fields.grant_id,
            project_id: fields.project_id,
            profile_id: fields.profile_id,
            action: fields.action,
            binding: fields.binding,
            issued_at_unix_nanos: fields.issued_at_unix_nanos,
            ttl_seconds: fields.ttl_seconds,
            expires_at_unix_nanos: fields.expires_at_unix_nanos,
        }
    }
}

/// Result of validating a process-bound live grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantValidation {
    /// The grant exists, is not expired, and still belongs to the same process.
    Valid,
    /// No live grant exists for the requested id.
    Unknown,
    /// The live grant has expired.
    Expired,
    /// The PID is missing or its start-time token changed.
    ProcessMismatch,
}

/// In-memory live grant table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GrantTable {
    grants: BTreeMap<String, GrantRecord>,
}

impl GrantTable {
    /// Insert or replace a live grant.
    pub fn insert(&mut self, grant: GrantRecord) {
        self.grants.insert(grant.grant_id.clone(), grant);
    }

    /// Remove a live grant.
    pub fn revoke(&mut self, grant_id: &str) -> Option<GrantRecord> {
        self.grants.remove(grant_id)
    }

    /// Remove every live grant record.
    pub fn clear(&mut self) {
        self.grants.clear();
    }

    /// Remove every live grant scoped to a project.
    ///
    /// Returns the number of grant records removed without exposing grant ids.
    pub fn revoke_for_project(&mut self, project_id: &str) -> usize {
        let before = self.grants.len();
        self.grants.retain(|_, grant| grant.project_id != project_id);
        before.saturating_sub(self.grants.len())
    }

    /// Count live grant records without exposing grant ids.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Count live grant records scoped to a project without exposing grant ids.
    #[must_use]
    pub fn count_for_project(&self, project_id: &str) -> usize {
        self.grants.values().filter(|grant| grant.project_id == project_id).count()
    }

    /// Return whether the grant table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Validate a live grant against time and process identity.
    #[must_use]
    pub fn validate(
        &self,
        grant_id: &str,
        project_id: &str,
        profile_id: &str,
        action: GrantAction,
        now_unix_nanos: i128,
        current_binding: Option<&GrantBinding>,
    ) -> GrantValidation {
        self.validate_any(
            grant_id,
            project_id,
            profile_id,
            &[action],
            now_unix_nanos,
            current_binding,
        )
    }

    /// Validate a live grant where any of `actions` is acceptable.
    ///
    /// Used by the `ResolveReference` handler to accept a live
    /// `PrepareExec` grant in lieu of a separately-requested
    /// `ResolveReference` grant: `PrepareExec` already authorizes the
    /// trusted CLI execution path to resolve the policy's allowed
    /// references, so re-issuing a narrower grant is redundant.
    #[must_use]
    pub fn validate_any(
        &self,
        grant_id: &str,
        project_id: &str,
        profile_id: &str,
        actions: &[GrantAction],
        now_unix_nanos: i128,
        current_binding: Option<&GrantBinding>,
    ) -> GrantValidation {
        let Some(grant) = self.grants.get(grant_id) else {
            return GrantValidation::Unknown;
        };
        if now_unix_nanos >= grant.expires_at_unix_nanos {
            return GrantValidation::Expired;
        }
        if grant.project_id != project_id
            || grant.profile_id != profile_id
            || !actions.contains(&grant.action)
        {
            return GrantValidation::ProcessMismatch;
        }
        let Some(current_binding) = current_binding else {
            return GrantValidation::ProcessMismatch;
        };
        if grant.binding == *current_binding {
            GrantValidation::Valid
        } else {
            GrantValidation::ProcessMismatch
        }
    }

    /// Returns the grant record for a given id without mutating the table.
    #[must_use]
    pub fn get(&self, grant_id: &str) -> Option<&GrantRecord> {
        self.grants.get(grant_id)
    }

    /// Issues a fresh grant. The id is a typed opaque `GrantId` (`lk_grant_<32 hex>`).
    /// Callers are responsible for emitting the `RequestGrant` audit row.
    ///
    /// # Errors
    ///
    /// Returns `IdGenerationError` if the OS RNG fails.
    pub fn issue(
        &mut self,
        payload: RequestGrantPayload,
        issued_at_unix_nanos: i128,
        expires_at_unix_nanos: i128,
    ) -> Result<GrantRecord, locket_core::id::IdGenerationError> {
        let grant_id = locket_core::id::GrantId::generate()?;
        let record = GrantRecord::new(GrantRecordFields {
            grant_id: grant_id.into_string(),
            project_id: payload.project_id,
            profile_id: payload.profile_id,
            action: payload.action,
            binding: payload.binding,
            issued_at_unix_nanos,
            ttl_seconds: payload.ttl_seconds,
            expires_at_unix_nanos,
        });
        self.insert(record.clone());
        Ok(record)
    }
}

/// Wire payload for `RequestGrant`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestGrantPayload {
    /// Project identifier the grant is scoped to.
    pub project_id: String,
    /// Profile identifier the grant is scoped to.
    pub profile_id: String,
    /// Saved command policy whose TTL should govern this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// Action set authorized by this grant.
    pub action: GrantAction,
    /// Requested TTL in seconds. Overridden by `policy_name` when present.
    pub ttl_seconds: u64,
    /// Caller's process binding.
    pub binding: GrantBinding,
}

/// Wire payload for `RevokeGrant`/`ExpireGrant`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GrantIdPayload {
    /// Grant id to revoke or mark expired.
    pub grant_id: String,
}

#[cfg(test)]
mod tests {
    use super::{
        GrantAction, GrantBinding, GrantRecord, GrantRecordFields, GrantTable, GrantValidation,
        RequestGrantPayload,
    };

    fn grant_record(action: GrantAction) -> GrantRecord {
        GrantRecord::new(GrantRecordFields {
            grant_id: "grant-1".to_owned(),
            project_id: "p-1".to_owned(),
            profile_id: "prof-1".to_owned(),
            action,
            binding: GrantBinding::new(4242, "start-a"),
            issued_at_unix_nanos: 100,
            ttl_seconds: 30,
            expires_at_unix_nanos: 200,
        })
    }

    #[test]
    fn grant_table_requires_pid_and_start_time_match() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::RunPolicy));

        assert_eq!(
            table.validate(
                "grant-1",
                "p-1",
                "prof-1",
                GrantAction::RunPolicy,
                100,
                Some(&GrantBinding::new(4242, "start-a")),
            ),
            GrantValidation::Valid
        );
        assert_eq!(
            table.validate(
                "grant-1",
                "p-1",
                "prof-1",
                GrantAction::RunPolicy,
                100,
                Some(&GrantBinding::new(4242, "start-b")),
            ),
            GrantValidation::ProcessMismatch
        );
        assert_eq!(
            table.validate(
                "grant-1",
                "p-1",
                "prof-1",
                GrantAction::RunPolicy,
                100,
                Some(&GrantBinding::new(4343, "start-a")),
            ),
            GrantValidation::ProcessMismatch
        );
    }

    #[test]
    fn grant_table_fails_closed_for_unknown_expired_and_missing_process() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::RunPolicy));

        assert_eq!(
            table.validate("missing", "p-1", "prof-1", GrantAction::RunPolicy, 100, None),
            GrantValidation::Unknown
        );
        assert_eq!(
            table.validate(
                "grant-1",
                "p-1",
                "prof-1",
                GrantAction::RunPolicy,
                200,
                Some(&GrantBinding::new(4242, "start-a")),
            ),
            GrantValidation::Expired
        );
        assert_eq!(
            table.validate("grant-1", "p-1", "prof-1", GrantAction::RunPolicy, 100, None),
            GrantValidation::ProcessMismatch
        );
    }

    #[test]
    fn grant_table_scope_is_part_of_validation() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::Reveal));
        let binding = GrantBinding::new(4242, "start-a");

        assert_eq!(
            table.validate("grant-1", "p-2", "prof-1", GrantAction::Reveal, 100, Some(&binding),),
            GrantValidation::ProcessMismatch
        );
        assert_eq!(
            table.validate("grant-1", "p-1", "prof-2", GrantAction::Reveal, 100, Some(&binding),),
            GrantValidation::ProcessMismatch
        );
        assert_eq!(
            table.validate("grant-1", "p-1", "prof-1", GrantAction::Copy, 100, Some(&binding),),
            GrantValidation::ProcessMismatch
        );
    }

    #[test]
    fn validate_any_accepts_prepare_exec_grant_for_resolve_reference() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::PrepareExec));
        let binding = GrantBinding::new(4242, "start-a");

        // A live PrepareExec grant satisfies a ResolveReference check
        // when both are listed as acceptable actions, so the trusted
        // CLI execution path can reuse the umbrella grant for follow-up
        // `lk://` resolutions without re-issuing a narrower one.
        assert_eq!(
            table.validate_any(
                "grant-1",
                "p-1",
                "prof-1",
                &[GrantAction::ResolveReference, GrantAction::PrepareExec],
                100,
                Some(&binding),
            ),
            GrantValidation::Valid
        );
        // The narrow `validate` call still rejects the cross-action use
        // so call sites that strictly need a ResolveReference grant are
        // unaffected.
        assert_eq!(
            table.validate(
                "grant-1",
                "p-1",
                "prof-1",
                GrantAction::ResolveReference,
                100,
                Some(&binding),
            ),
            GrantValidation::ProcessMismatch
        );
    }

    #[test]
    fn revoke_for_project_drops_only_matching_project_grants() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::Reveal));
        table.insert(GrantRecord::new(GrantRecordFields {
            grant_id: "grant-other".to_owned(),
            project_id: "p-2".to_owned(),
            profile_id: "prof-1".to_owned(),
            action: GrantAction::Reveal,
            binding: GrantBinding::new(4242, "start-a"),
            issued_at_unix_nanos: 0,
            ttl_seconds: 60,
            expires_at_unix_nanos: 100,
        }));

        assert_eq!(table.count_for_project("p-1"), 1);
        assert_eq!(table.revoke_for_project("p-1"), 1);
        assert!(table.get("grant-1").is_none());
        assert!(table.get("grant-other").is_some());
    }

    #[test]
    fn issued_grants_retain_metadata_without_values()
    -> Result<(), locket_core::id::IdGenerationError> {
        let mut table = GrantTable::default();
        let record = table.issue(
            RequestGrantPayload {
                project_id: "p-1".to_owned(),
                profile_id: "prof-1".to_owned(),
                policy_name: None,
                action: GrantAction::ScanKnownValues,
                ttl_seconds: 45,
                binding: GrantBinding::new(4242, "start-a"),
            },
            100,
            45_000_000_100,
        )?;

        assert_eq!(record.project_id, "p-1");
        assert_eq!(record.profile_id, "prof-1");
        assert_eq!(record.action, GrantAction::ScanKnownValues);
        assert_eq!(record.issued_at_unix_nanos, 100);
        assert_eq!(record.ttl_seconds, 45);
        assert_eq!(record.expires_at_unix_nanos, 45_000_000_100);
        Ok(())
    }

    #[test]
    fn prepare_exec_grants_validate_against_their_action() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::PrepareExec));
        let binding = GrantBinding::new(4242, "start-a");

        assert_eq!(
            table.validate(
                "grant-1",
                "p-1",
                "prof-1",
                GrantAction::PrepareExec,
                100,
                Some(&binding),
            ),
            GrantValidation::Valid
        );
        assert_eq!(
            table
                .validate("grant-1", "p-1", "prof-1", GrantAction::RunPolicy, 100, Some(&binding),),
            GrantValidation::ProcessMismatch
        );
    }

    #[test]
    fn revoke_returns_record_when_present_and_none_when_absent() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::Reveal));
        assert!(table.revoke("grant-1").is_some());
        assert!(table.revoke("grant-1").is_none());
    }

    #[test]
    fn clear_empties_grant_table() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::Reveal));
        assert!(!table.is_empty());
        table.clear();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn revoke_for_project_returns_zero_for_unknown_project() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::Reveal));
        assert_eq!(table.revoke_for_project("nope"), 0);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn count_for_project_returns_zero_for_unknown_project() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::Reveal));
        assert_eq!(table.count_for_project("nope"), 0);
    }

    #[test]
    fn get_returns_none_for_unknown_grant() {
        let table = GrantTable::default();
        assert!(table.get("missing").is_none());
    }

    #[test]
    fn validate_at_exact_expiry_boundary_is_expired() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::RunPolicy));
        let binding = GrantBinding::new(4242, "start-a");
        // Grant expires_at = 200. now=200 is treated as expired (>= boundary).
        assert_eq!(
            table.validate("grant-1", "p-1", "prof-1", GrantAction::RunPolicy, 200, Some(&binding)),
            GrantValidation::Expired
        );
        // now=199 is still valid.
        assert_eq!(
            table.validate("grant-1", "p-1", "prof-1", GrantAction::RunPolicy, 199, Some(&binding)),
            GrantValidation::Valid
        );
    }

    #[test]
    fn redact_grants_validate_against_their_action() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::Redact));
        let binding = GrantBinding::new(4242, "start-a");

        assert_eq!(
            table.validate("grant-1", "p-1", "prof-1", GrantAction::Redact, 100, Some(&binding),),
            GrantValidation::Valid
        );
        assert_eq!(
            table.validate("grant-1", "p-1", "prof-1", GrantAction::Reveal, 100, Some(&binding),),
            GrantValidation::ProcessMismatch
        );
    }

    #[test]
    fn export_grants_validate_against_their_action() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::Export));
        let binding = GrantBinding::new(4242, "start-a");

        assert_eq!(
            table.validate("grant-1", "p-1", "prof-1", GrantAction::Export, 100, Some(&binding),),
            GrantValidation::Valid
        );
        assert_eq!(
            table.validate("grant-1", "p-1", "prof-1", GrantAction::Copy, 100, Some(&binding),),
            GrantValidation::ProcessMismatch
        );
    }

    #[test]
    fn issued_grants_carry_new_spec_actions() -> Result<(), locket_core::id::IdGenerationError> {
        let mut table = GrantTable::default();
        for action in [
            GrantAction::PrepareExec,
            GrantAction::Redact,
            GrantAction::Export,
            GrantAction::SetSecret,
        ] {
            let record = table.issue(
                RequestGrantPayload {
                    project_id: "p-1".to_owned(),
                    profile_id: "prof-1".to_owned(),
                    policy_name: None,
                    action,
                    ttl_seconds: 30,
                    binding: GrantBinding::new(4242, "start-a"),
                },
                100,
                30_000_000_100,
            )?;
            assert_eq!(record.action, action);
            assert_eq!(record.ttl_seconds, 30);
        }
        Ok(())
    }

    #[test]
    fn grant_action_serde_round_trips_for_new_variants() -> Result<(), serde_json::Error> {
        for (action, expected) in [
            (GrantAction::PrepareExec, "\"PrepareExec\""),
            (GrantAction::Redact, "\"Redact\""),
            (GrantAction::Export, "\"Export\""),
            (GrantAction::SetSecret, "\"SetSecret\""),
        ] {
            let encoded = serde_json::to_string(&action)?;
            assert_eq!(encoded, expected);
            let decoded: GrantAction = serde_json::from_str(&encoded)?;
            assert_eq!(decoded, action);
        }
        Ok(())
    }

    #[test]
    fn grant_action_serializes_pascal_case() -> Result<(), serde_json::Error> {
        let s = serde_json::to_string(&GrantAction::RunPolicy)?;
        assert_eq!(s, "\"RunPolicy\"");
        let parsed: GrantAction = serde_json::from_str("\"SetSecret\"")?;
        assert_eq!(parsed, GrantAction::SetSecret);
        Ok(())
    }

    #[test]
    fn grant_action_clone_copy_eq_debug_for_every_variant() {
        let variants = [
            GrantAction::RunPolicy,
            GrantAction::PrepareExec,
            GrantAction::ResolveReference,
            GrantAction::ScanKnownValues,
            GrantAction::Reveal,
            GrantAction::Copy,
            GrantAction::Redact,
            GrantAction::Export,
            GrantAction::SetSecret,
        ];
        for v in variants {
            let copied = v;
            assert_eq!(v, copied);
            let debug = format!("{v:?}");
            assert_ne!(debug, "");
        }
    }

    #[test]
    fn grant_binding_round_trips_through_serde_json() -> Result<(), serde_json::Error> {
        let binding = GrantBinding::new(99, "ts-1");
        let json = serde_json::to_string(&binding)?;
        let parsed: GrantBinding = serde_json::from_str(&json)?;
        assert_eq!(binding, parsed);
        Ok(())
    }

    #[test]
    fn grant_validation_clone_copy_eq() {
        let v = GrantValidation::Valid;
        let copied = v;
        assert_eq!(v, copied);
        assert_ne!(v, GrantValidation::Expired);
        assert_ne!(GrantValidation::Unknown, GrantValidation::ProcessMismatch);
    }

    #[test]
    fn grant_table_clone_round_trips() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::Reveal));
        let cloned = table.clone();
        assert_eq!(table, cloned);
    }

    #[test]
    fn insert_replaces_grant_with_same_id() {
        let mut table = GrantTable::default();
        table.insert(grant_record(GrantAction::Reveal));
        let mut replacement = grant_record(GrantAction::Copy);
        replacement.ttl_seconds = 999;
        table.insert(replacement);
        assert_eq!(table.len(), 1);
        assert_eq!(table.get("grant-1").map(|g| g.action), Some(GrantAction::Copy));
        assert_eq!(table.get("grant-1").map(|g| g.ttl_seconds), Some(999));
    }
}
