//! Capture projections of live agent RPCs and SQLite state for offline TLC replay.
//! The emitted records contain fixture aliases and metadata only.
#![cfg(any(unix, target_os = "windows"))]
#![allow(unused_crate_dependencies, clippy::multiple_crate_versions)]
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fmt::{Display, Write as _};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use locket_agent::{
    AgentMethod, AgentSocketState, GrantAction, GrantBinding, RequestEnvelope, ResponseEnvelope,
    SessionLockSource, current_process_uid, dispatch,
};
use locket_core::{ProjectId, bundle::BundleContainer};
use locket_crypto::{
    HkdfWrapInfo, KeyBytes, KeyPurpose, KeyWrapAad, derive_wrapping_key_v1, key_wrap_aad_v1,
    secret_fingerprint_v1, wrap_key_material_v1,
};
use locket_platform::{MemoryMasterKeyStore, PassphraseFallbackMasterKeyStore};
use locket_store::{AuditContext, AuditWrite, KeyRecord, Store};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const A: Project = Project { id: "lk_proj_trace_a", profile: "lk_prof_trace_a", label: "ProjA" };
const B: Project = Project { id: "lk_proj_trace_b", profile: "lk_prof_trace_b", label: "ProjB" };
const SHARED: Project =
    Project { id: "lk_proj_shared_trace", profile: "lk_prof_trace_shared", label: "Shared" };
const MASTER: KeyBytes = [7; 32];
const AUDIT: KeyBytes = [10; 32];
const FINGERPRINT_KEY: KeyBytes = [9; 32];
const A_VALUE: &str = "alpha-fixture-value";
const B_VALUE: &str = "bravo-fixture-value";
const ROTATED_VALUE: &str = "rotated-fixture-value";
const TOKEN: &str = "TOKEN";
const POLICY: &str = "inspect";
const SECOND: i64 = 1_000_000_000;
const SOURCES: [&str; 3] = ["team-managed", "user-local", "machine-local"];

#[derive(Clone, Copy)]
struct Project {
    id: &'static str,
    profile: &'static str,
    label: &'static str,
}

impl Project {
    fn master(self) -> KeyBytes {
        match self.label {
            "ProjA" => MASTER,
            "ProjB" => [17; 32],
            "Shared" => [27; 32],
            label => panic!("unknown fixture project {label}"),
        }
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    path: PathBuf,
    state: AgentSocketState,
    binding: GrantBinding,
}

impl Fixture {
    fn new(projects: &[(Project, bool)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.db");
        let mut store = Store::open(&path).unwrap();
        store.initialize_schema().unwrap();
        let state = AgentSocketState::with_stores(
            "tla trace fixture",
            current_process_uid(),
            Arc::new(MemoryMasterKeyStore::default()),
            Arc::new(PassphraseFallbackMasterKeyStore::new(dir.path().join("passphrase"))),
        )
        .with_canonical_store_path(path.clone());
        for &(project, dangerous) in projects {
            seed_project(&mut store, dir.path(), project, dangerous);
        }
        Self { dir, path, state, binding: GrantBinding::new(std::process::id(), "trace") }
    }

    fn store(&self) -> Store {
        Store::open(&self.path).unwrap()
    }

    fn root(&self, project: Project) -> PathBuf {
        self.dir.path().join(project.label)
    }

    async fn rpc(&self, method: AgentMethod, payload: Value) -> ResponseEnvelope {
        dispatch(&RequestEnvelope::new("tla-trace", method, payload), &self.state).await
    }

    async fn unlock(&self, project: Project, seconds: u64) -> ResponseEnvelope {
        // The platform test key store holds one key at a time. The agent
        // still loads it through Unlock and manages its own per-vault cache.
        self.state.master_key_store.store_master_key(project.id, &project.master()).unwrap();
        self.rpc(
            AgentMethod::Unlock,
            json!({
                "project_id": project.id, "ttl_seconds": seconds,
                "audit": {"store_path": self.path, "profile_id": project.profile},
            }),
        )
        .await
    }

    async fn session_blocked(&self) -> bool {
        // RequestGrant checks the native session gate before parsing the payload.
        match denial(self.rpc(AgentMethod::RequestGrant, Value::Null).await).as_str() {
            "UnlockRequired" => true,
            "ProtocolError" => false,
            code => panic!("unexpected session gate response {code}"),
        }
    }

    async fn grant(
        &self,
        project: Project,
        action: GrantAction,
        confirmed: bool,
    ) -> ResponseEnvelope {
        self.rpc(
            AgentMethod::RequestGrant,
            json!({
                "project_id": project.id, "profile_id": project.profile,
                "store_path": self.path, "action": action, "ttl_seconds": 120,
                "confirm_dangerous": confirmed, "binding": self.binding,
            }),
        )
        .await
    }

    async fn grant_id(&self, project: Project, action: GrantAction) -> String {
        grant_id(self.grant(project, action, false).await)
    }

    fn scope(&self, project: Project, grant: &str) -> Value {
        json!({
            "store_path": self.path, "project_root": self.root(project),
            "project_id": project.id, "profile_id": project.profile,
            "grant_id": grant, "binding": self.binding,
        })
    }

    async fn set_secret(
        &self,
        project: Project,
        grant: &str,
        source: &str,
        value: &str,
        grace: Option<i64>,
    ) -> ResponseEnvelope {
        let mut payload = self.scope(project, grant);
        payload["secret_name"] = json!(TOKEN);
        payload["source"] = json!(source);
        payload["value"] = json!(value);
        payload["rotate"] = json!(grace.is_some());
        payload["grace_until"] = json!(grace);
        self.rpc(AgentMethod::SetSecret, payload).await
    }

    async fn resolve(
        &self,
        project: Project,
        grant: &str,
        reference: &str,
        binding: &GrantBinding,
    ) -> ResponseEnvelope {
        let mut payload = self.scope(project, grant);
        payload["policy_name"] = json!(POLICY);
        payload["reference"] = json!(reference);
        payload["binding"] = json!(binding);
        self.rpc(AgentMethod::ResolveReference, payload).await
    }

    fn audit_rows(&self, project: Project) -> Vec<(u64, String, Value)> {
        let store = self.store();
        let mut query = store
            .connection()
            .prepare(
                "SELECT sequence, action, metadata_json FROM audit_log
                 WHERE project_id = ?1 ORDER BY sequence",
            )
            .unwrap();
        query
            .query_map([project.id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get(1)?, row.get::<_, String>(2)?))
            })
            .unwrap()
            .map(|row| {
                let (seq, action, metadata) = row.unwrap();
                assert!(![A_VALUE, B_VALUE, ROTATED_VALUE].iter().any(|v| metadata.contains(v)));
                (u64::try_from(seq).unwrap(), action, serde_json::from_str(&metadata).unwrap())
            })
            .collect()
    }

    fn assert_audit_integrity(&self, project: Project) {
        let store = self.store();
        let verified = store.verify_audit_chain_read_only(project.id, &AUDIT).unwrap();
        assert!(verified.hmac_ok);
        if verified.rows_verified > 0 {
            assert!(
                !store.verify_audit_chain_read_only(project.id, &project.master()).unwrap().hmac_ok
            );
        }
    }
}

fn seed_project(store: &mut Store, dir: &Path, project: Project, dangerous: bool) {
    let name = if project.id == SHARED.id { "@shared" } else { project.label };
    store.insert_project_if_absent(project.id, name, 1).unwrap();
    store.insert_profile_if_absent(project.profile, project.id, "default", dangerous, 1).unwrap();
    for (purpose, profile, material) in [
        (KeyPurpose::Audit, None, &AUDIT),
        (KeyPurpose::ProfileSecret, Some(project.profile), &[8; 32]),
        (KeyPurpose::ProfileFingerprint, Some(project.profile), &FINGERPRINT_KEY),
    ] {
        let id = format!("lk_key_{}_{}", project.label, purpose.as_str());
        let wrapping = derive_wrapping_key_v1(
            &project.master(),
            &HkdfWrapInfo::new(project.id, profile, purpose),
        )
        .unwrap();
        let aad =
            key_wrap_aad_v1(&KeyWrapAad::new(project.id, &id, profile, 0, purpose.into())).unwrap();
        let wrapped = wrap_key_material_v1(&wrapping, material, &aad).unwrap();
        store
            .insert_key(&KeyRecord {
                id,
                project_id: project.id.into(),
                profile_id: profile.map(str::to_owned),
                purpose: purpose.as_str().into(),
                wrapped_material: wrapped.ciphertext,
                nonce: wrapped.nonce,
                created_at: 1,
            })
            .unwrap();
    }

    let root = dir.join(project.label);
    fs::create_dir(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let path = root.join("locket.toml");
    let config = format!(
        "schema_version = 1\nproject_id = '{}'\nname = '{}'\ndefault_profile = 'default'\n\
         [commands.{POLICY}]\nargv = ['echo']\nrequired_secrets = ['{TOKEN}']\n",
        project.id, project.label,
    );
    fs::write(&path, &config).unwrap();
    let root_str = root.to_str().unwrap();
    store
        .trust_project_root(project.id, &Sha256::digest(root_str).into(), Some(root_str), 1)
        .unwrap();
    let doc: toml::Value = toml::from_str(&config).unwrap();
    let digest = locket_core::policy::policy_source_digest(&doc, POLICY).unwrap();
    store
        .upsert_command_policy_index(
            project.id,
            POLICY,
            &json!(doc["commands"][POLICY]),
            &json!({"source_path": path, "source_digest": digest}),
            1,
            None,
        )
        .unwrap();
}

#[track_caller]
fn success(response: ResponseEnvelope) -> Value {
    match response {
        ResponseEnvelope::Success(success) => success.payload,
        ResponseEnvelope::Error(error) => panic!("unexpected RPC denial {}", error.error),
    }
}

#[track_caller]
fn denial(response: ResponseEnvelope) -> String {
    match response {
        ResponseEnvelope::Error(error) => error.error,
        ResponseEnvelope::Success(_) => panic!("unexpected RPC success"),
    }
}

#[track_caller]
fn resolve_accepted(response: ResponseEnvelope, expected: bool) -> bool {
    let accepted = match response {
        ResponseEnvelope::Success(success) => {
            assert_eq!(success.payload["value"], A_VALUE);
            true
        }
        ResponseEnvelope::Error(error) => {
            assert_eq!(error.error, "GrantRequired");
            false
        }
    };
    assert_eq!(accepted, expected);
    accepted
}

fn grant_id(response: ResponseEnvelope) -> String {
    success(response)["grant_id"].as_str().unwrap().to_owned()
}

fn now() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()).unwrap()
}

const fn tla_bool(value: bool) -> &'static str {
    if value { "TRUE" } else { "FALSE" }
}

fn tla_seq(rows: impl IntoIterator<Item = String>) -> String {
    format!("<<{}>>", rows.into_iter().collect::<Vec<_>>().join(", "))
}

#[derive(Default)]
struct Trace(Vec<String>);

impl Trace {
    fn record(&mut self, action: &str, input: impl Display, state: &str) {
        self.0.push(format!("[action |-> \"{action}\", input |-> {input}, state |-> {state}]"));
    }

    fn emit(self, model: &str) {
        self.emit_with_rejection(model, None);
    }

    fn emit_with_rejection(self, model: &str, rejected: Option<Self>) {
        let Some(dir) = std::env::var_os("LOCKET_TLA_TRACE_DIR") else { return };
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir).unwrap();
        let module = format!("{model}TraceData");
        let mut data = format!("---- MODULE {module} ----\nEXTENDS Sequences\n\n");
        writeln!(data, "RecordedTrace == <<\n    {}\n>>", self.0.join(",\n    ")).unwrap();
        if let Some(rejected) = rejected {
            writeln!(data, "RejectedTrace == <<\n    {}\n>>", rejected.0.join(",\n    ")).unwrap();
        }
        data.push_str("Trace == RecordedTrace\n====\n");
        fs::write(dir.join(format!("{module}.tla")), data).unwrap();
    }
}

struct GrantTrace<'a> {
    fixture: &'a Fixture,
    trace: Trace,
    grant: Option<(String, bool)>,
    cutoff: i64,
    tick: u8,
}

impl GrantTrace<'_> {
    async fn record(&mut self, action: &str, input: impl Display + Send) {
        let f = self.fixture;
        let sample = if self.tick == 0 { now() } else { self.cutoff };
        let deadline = |absolute| if absolute <= i128::from(self.cutoff) { 1 } else { 2 };
        let cache = f.state.unlock_cache.lock().await;
        let key = |p: Project| {
            cache
                .lookup(p.id, i128::from(sample))
                .map_or(0, |entry| deadline(entry.expires_at_unix_nanos()))
        };
        let keys = format!("[ProjA |-> {}, ProjB |-> {}]", key(A), key(B));
        drop(cache);
        let table = f.state.grants.lock().await;
        let grant = self.grant.as_ref().and_then(|(id, confirmed)| {
            table.get(id).map(|record| {
                let project = [A, B].into_iter().find(|p| p.id == record.project_id).unwrap();
                let profile =
                    f.store().get_profile_by_name(project.id, "default").unwrap().unwrap();
                assert_eq!(record.profile_id, profile.id);
                let profile = if profile.dangerous { "dangerous" } else { "normal" };
                let action = match record.action {
                    GrantAction::PrepareExec => "prepare",
                    GrantAction::ResolveReference => "resolve",
                    other => panic!("unexpected modeled grant {other:?}"),
                };
                format!(
                    "[project |-> {:?}, profile |-> {profile:?}, action |-> {action:?}, \
                         deadline |-> {}, confirmed |-> {}]",
                    project.label,
                    deadline(record.expires_at_unix_nanos),
                    tla_bool(*confirmed)
                )
            })
        });
        assert_eq!(table.len(), usize::from(grant.is_some()));
        drop(table);
        let grants = format!("{{{}}}", grant.unwrap_or_default());
        assert!(f.state.ide_env_sessions.lock().await.is_empty());
        let blocked = tla_bool(f.session_blocked().await);
        self.trace.record(
            action,
            input,
            &format!(
                "[now |-> {}, keys |-> {keys}, sessionBlocked |-> {blocked}, grants |-> {grants}]",
                self.tick,
            ),
        );
    }

    async fn resolve(&mut self, project: Project, binding: &GrantBinding, expected: bool) {
        let response = self
            .fixture
            .resolve(project, &self.grant.as_ref().unwrap().0, "lk://default/TOKEN", binding)
            .await;
        let accepted = resolve_accepted(response, expected);
        let profile = if project.id == A.id { "normal" } else { "dangerous" };
        let matches = tla_bool(binding == &self.fixture.binding);
        self.record(
            "resolve",
            format!("<<{:?}, {profile:?}, {matches}, {}>>", project.label, tla_bool(accepted)),
        )
        .await;
    }
}

#[tokio::test]
async fn unlock_grant_lifecycle() {
    let fixture = Fixture::new(&[(A, false), (B, true)]);
    // The fixture setup is outside the trace. Start the observed daemon locked.
    success(fixture.unlock(A, 120).await);
    let writer = fixture.grant_id(A, GrantAction::SetSecret).await;
    success(fixture.set_secret(A, &writer, "user-local", A_VALUE, None).await);
    success(fixture.rpc(AgentMethod::Lock, json!({"project_id": A.id})).await);

    // Tick jumps across a 30-second key deadline but stays inside the
    // 120-second deadlines. Project actual cached expiry onto that boundary.
    let mut run = GrantTrace {
        fixture: &fixture,
        trace: Trace::default(),
        grant: None,
        cutoff: now() + 60 * SECOND,
        tick: 0,
    };
    run.record("init", "<<>>").await;
    success(fixture.unlock(A, 30).await);
    run.record("unlock", r#"<< "ProjA", 1 >>"#).await;
    success(fixture.unlock(B, 120).await);
    run.record("unlock", r#"<< "ProjB", 2 >>"#).await;

    let rejected = fixture.grant(B, GrantAction::ResolveReference, false).await;
    assert_eq!(denial(rejected), "ConfirmationFailed");
    run.record("grantDenied", r#"<< "ProjB", "dangerous", FALSE >>"#).await;
    let approved = fixture.grant(B, GrantAction::ResolveReference, true).await;
    run.grant = Some((grant_id(approved), true));
    run.record("grant", r#"<< "ProjB", "dangerous", "resolve", 2, TRUE >>"#).await;
    success(fixture.rpc(AgentMethod::Lock, json!({"project_id": A.id})).await);
    run.record("lock", r#"<< "ProjA" >>"#).await;
    success(
        fixture
            .rpc(
                AgentMethod::RevokeGrant,
                json!({
                    "grant_id": run.grant.as_ref().unwrap().0, "binding": fixture.binding,
                }),
            )
            .await,
    );
    run.record("revoke", "<<>>").await;

    success(fixture.unlock(A, 30).await);
    run.record("unlock", r#"<< "ProjA", 1 >>"#).await;
    run.grant = Some((fixture.grant_id(A, GrantAction::PrepareExec).await, false));
    run.record("grant", r#"<< "ProjA", "normal", "prepare", 2, FALSE >>"#).await;
    run.resolve(A, &fixture.binding, true).await;
    run.resolve(A, &GrantBinding::new(std::process::id(), "wrong-start"), false).await;
    run.resolve(B, &fixture.binding, false).await;
    assert_eq!(fixture.state.expire_unlocks(i128::from(run.cutoff)).await.unwrap(), 1);
    run.tick = 1;
    run.record("tick", "<<>>").await;
    run.resolve(A, &fixture.binding, false).await;

    let result = fixture
        .state
        .lock_for_native_session_event(SessionLockSource::ScreenLock, true, i128::from(run.cutoff))
        .await
        .unwrap();
    assert_eq!(result.cached_keys_cleared, 1);
    run.record("nativeLock", "<<>>").await;
    assert_eq!(denial(fixture.unlock(B, 120).await), "UnlockRequired");
    run.record("unlockDenied", r#"<< "ProjB" >>"#).await;
    fixture
        .state
        .lock_for_native_session_event(SessionLockSource::ScreenLock, false, i128::from(run.cutoff))
        .await
        .unwrap();
    run.record("resume", "<<>>").await;
    run.trace.emit("AgentUnlockGrantLifecycle");
}

fn source_rank(source: &str) -> usize {
    SOURCES.iter().position(|known| *known == source).unwrap() + 1
}

struct SecretTrace<'a> {
    fixture: &'a Fixture,
    trace: Trace,
    grace: i64,
    checkpoint: Option<locket_core::AuditCheckpoint>,
}

impl SecretTrace<'_> {
    fn project_deadline(&self, value: Option<i64>) -> u8 {
        value.map_or(0, |deadline| {
            assert_eq!(deadline, self.grace);
            1
        })
    }

    fn record(&mut self, action: &str, input: impl Display) {
        let f = self.fixture;
        let store = f.store();
        let mut rows = Vec::new();
        for source in SOURCES {
            let record = store.get_secret_by_source(A.id, A.profile, TOKEN, source).unwrap();
            let versions = record
                .as_ref()
                .map_or_else(Vec::new, |secret| store.list_secret_versions(&secret.id).unwrap());
            assert!(versions.iter().all(|row| (1..=3).contains(&row.version)));
            let version_states = tla_seq((1..=3).map(|version| {
                let row = versions.iter().find(|row| row.version == version);
                let status = row.map_or("absent", |row| row.state.as_str());
                let grace = self.project_deadline(row.and_then(|row| row.grace_until));
                format!("[status |-> {status:?}, graceUntil |-> {grace}]")
            }));
            let status = record.as_ref().map_or("absent", |row| row.state.as_str());
            let current = record.as_ref().map_or(0, |row| row.current_version);
            rows.push(format!(
                "[status |-> {status:?}, current |-> {current}, versions |-> {version_states}]"
            ));
        }

        // The model omits unrelated RPC audit actions. Keep the order and
        // fields of its events, and rebase the checkpoint onto that subsequence.
        f.assert_audit_integrity(A);
        let mut anchor = 0;
        let mut events = Vec::new();
        for (seq, action, event) in f.audit_rows(A) {
            let rank = || source_rank(event["source"].as_str().unwrap());
            let version = |key: &str| event[key].as_u64().unwrap();
            let (op, source, version, grace) = match action.as_str() {
                "SET" => ("create", rank(), version("version"), 0),
                "ROTATE" => (
                    "rotate",
                    rank(),
                    version("target_version"),
                    self.project_deadline(event["grace_until"].as_i64()),
                ),
                "DELETE" => ("delete", rank(), 0, 0),
                "PURGE" => ("purge", rank(), version("version"), 0),
                "AUDIT_VERIFY" => {
                    assert!(
                        event["check_names"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|check| check == "external_audit_checkpoint")
                    );
                    ("verify-checkpoint", 0, 0, 0)
                }
                "UNLOCK" | "RESOLVE_REFERENCE" => continue,
                other => panic!("unexpected audit action {other}"),
            };
            assert_eq!(event["status"], "SUCCESS");
            events.push(format!(
                "[op |-> {op:?}, source |-> {source}, version |-> {version}, grace |-> {grace}]"
            ));
            if self.checkpoint.as_ref().is_some_and(|checkpoint| checkpoint.sequence == seq) {
                anchor = events.len();
            }
        }
        assert_eq!(anchor != 0, self.checkpoint.is_some());
        self.trace.record(
            action,
            input,
            &format!(
                "[secrets |-> {}, events |-> {}, anchor |-> {anchor}]",
                tla_seq(rows),
                tla_seq(events),
            ),
        );
    }

    async fn resolve(&mut self, grant: &str, reference: &str, expected: Result<(&str, u64), &str>) {
        let parsed = locket_core::LkReferenceUri::parse(reference).unwrap();
        let selector = parsed.source().map_or(0, |source| source_rank(source.as_str()));
        let pin = parsed.version().map_or(0, locket_core::SecretVersion::get);
        let response = self.fixture.resolve(A, grant, reference, &self.fixture.binding).await;
        let (rank, version) = match expected {
            Ok((value, expected_version)) => {
                let output = success(response);
                assert_eq!(output["value"], value);
                let version = output["version"].as_u64().unwrap();
                assert_eq!(version, expected_version);
                let (_, action, metadata) = self.fixture.audit_rows(A).pop().unwrap();
                assert_eq!(action, "RESOLVE_REFERENCE");
                assert_eq!(metadata["selected_version"], version);
                (source_rank(metadata["source"].as_str().unwrap()), version)
            }
            Err(error) => {
                assert_eq!(denial(response), error);
                (0, 0)
            }
        };
        self.record("resolve", format!("<<{selector}, {pin}, <<{rank}, {version}>>>>"));
    }
}

#[tokio::test]
async fn secret_lifecycle_and_audit_chain() {
    let fixture = Fixture::new(&[(A, false)]);
    success(fixture.unlock(A, 120).await);
    let writer = fixture.grant_id(A, GrantAction::SetSecret).await;
    let resolver = fixture.grant_id(A, GrantAction::ResolveReference).await;
    let deleter = fixture.grant_id(A, GrantAction::DeleteSecret).await;
    let mut run = SecretTrace {
        fixture: &fixture,
        trace: Trace::default(),
        grace: now() + 60 * SECOND,
        checkpoint: None,
    };
    run.record("init", "<<>>");
    success(fixture.set_secret(A, &writer, "user-local", A_VALUE, None).await);
    run.record("create", "<<2>>");
    success(fixture.set_secret(A, &writer, "machine-local", B_VALUE, None).await);
    run.record("create", "<<3>>");
    success(fixture.set_secret(A, &writer, "user-local", ROTATED_VALUE, Some(run.grace)).await);
    run.record("rotate", "<<2, 1>>");
    let reference = "lk://default/TOKEN";
    run.resolve(&resolver, reference, Ok((B_VALUE, 1))).await;
    run.resolve(&resolver, "lk://default/TOKEN@v2", Err("SecretNotFound")).await;
    let pinned = "lk://default/TOKEN@v1?source=user-local";
    run.resolve(&resolver, pinned, Ok((A_VALUE, 1))).await;

    let mut delete = fixture.scope(A, &deleter);
    delete["secret_name"] = json!(TOKEN);
    delete["source"] = json!("machine-local");
    assert_eq!(success(fixture.rpc(AgentMethod::DeleteSecret, delete).await)["deleted"], true);
    run.record("delete", "<<3>>");
    run.resolve(&resolver, reference, Ok((ROTATED_VALUE, 2))).await;
    assert_eq!(
        denial(fixture.set_secret(A, &writer, "machine-local", B_VALUE, None).await),
        "SecretDeleted"
    );
    run.record("createDenied", "<<3>>");

    let project = ProjectId::new(A.id).unwrap();
    let mut store = fixture.store();
    purge_version_one(&mut store, "user-local");
    run.record("purge", "<<2, 1>>");
    let checkpoint = store.audit_checkpoint(&project, &AUDIT).unwrap();
    run.checkpoint = Some(checkpoint.clone());
    run.record("checkpoint", "<<>>");
    run.resolve(&resolver, pinned, Err("SecretVersionExpired")).await;

    purge_version_one(&mut store, "machine-local");
    run.record("purge", "<<3, 1>>");
    let anchor = store.audit_checkpoint(&project, &AUDIT).unwrap();
    assert!(anchor.sequence > checkpoint.sequence);
    run.checkpoint = Some(anchor.clone());
    run.record("checkpoint", "<<>>");
    store.verify_audit_checkpoint_and_append(&project, &AUDIT, &anchor, now()).unwrap();
    run.record("verify", "<<>>");
    run.trace.emit("SecretLifecycleAuditChain");
}

fn purge_version_one(store: &mut Store, source: &str) {
    let secret = store.get_secret_by_source(A.id, A.profile, TOKEN, source).unwrap().unwrap();
    let purged_at = now();
    let metadata = json!({"schema_version": 1, "action": "PURGE", "status": "SUCCESS",
        "secret_name": TOKEN, "profile_id": A.profile, "source": source, "version": 1});
    let audit = AuditWrite {
        project_id: A.id,
        profile_id: Some(A.profile),
        action: "PURGE",
        status: "SUCCESS",
        secret_name: Some(TOKEN),
        command: None,
        metadata_json: &metadata,
        timestamp: purged_at,
    };
    assert!(
        store
            .purge_secret_versions_with_audit(
                &secret.id,
                &[1],
                purged_at,
                Some(AuditContext { key: &AUDIT, write: &audit })
            )
            .unwrap()
    );
    assert!(store.get_blob(&secret.id, 1).unwrap().is_none());
}

fn recipient_descriptor() -> String {
    use data_encoding::BASE64URL_NOPAD;

    let signing = ed25519_dalek::SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
    let sealing =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([4; 32])).to_bytes();
    let mut hash = Sha256::new();
    hash.update(b"locket-device-v1");
    for key in [signing, sealing] {
        hash.update(32_u16.to_le_bytes());
        hash.update(key);
    }
    let descriptor = json!({
        "v": 2, "device_id": "lk_dev_trace", "label": "trace fixture",
        "signing_public_key_ed25519": BASE64URL_NOPAD.encode(&signing),
        "sealing_public_key_x25519": BASE64URL_NOPAD.encode(&sealing),
        "fingerprint_sha256": data_encoding::HEXLOWER.encode(&hash.finalize()),
        "safety_words": [],
    });
    format!("lkdev2_{}", BASE64URL_NOPAD.encode(&serde_json::to_vec(&descriptor).unwrap()))
}

fn backup_snapshot(fixture: &Fixture, output: &Path) -> String {
    let published = match fs::read(output) {
        Ok(bytes) => {
            assert!(!bytes.windows(A_VALUE.len()).any(|window| window == A_VALUE.as_bytes()));
            let container = BundleContainer::deserialize(&bytes).unwrap();
            let payload_digest =
                data_encoding::HEXLOWER.encode(&Sha256::digest(&container.encrypted_payload));
            assert_eq!(container.manifest.payload_digest, payload_digest);
            assert_eq!(container.manifest.profile_count, 1);
            payload_digest
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => panic!("could not read backup fixture output: {err}"),
    };
    fixture.assert_audit_integrity(A);
    let rows = fixture.audit_rows(A);
    let mut exports = rows.iter().filter(|(_, action, _)| action == "BACKUP_EXPORT");
    let audited = exports.next().map_or("", |(_, _, event)| {
        assert_eq!(event["status"], "SUCCESS");
        event["bundle_digest"].as_str().unwrap()
    });
    assert!(exports.next().is_none());
    assert!(
        audited.is_empty()
            || (audited.len() == 64 && audited.bytes().all(|b| b.is_ascii_hexdigit()))
    );
    let occupancy = if fixture
        .store()
        .get_secret_by_source(A.id, A.profile, TOKEN, "user-local")
        .unwrap()
        .is_some()
    {
        "populated"
    } else {
        "empty"
    };
    format!("[published |-> {published:?}, audited |-> {audited:?}, occupancy |-> {occupancy:?}]")
}

async fn export_trace(reject_audit: bool) -> Trace {
    let fixture = Fixture::new(&[(A, false)]);
    success(fixture.unlock(A, 120).await);
    let writer = fixture.grant_id(A, GrantAction::SetSecret).await;
    success(fixture.set_secret(A, &writer, "user-local", A_VALUE, None).await);
    let grant = fixture.grant_id(A, GrantAction::Export).await;
    let output = fixture.dir.path().join("trace.locket-bundle");
    let mut request = json!({
        "project_id": A.id, "profile_id": A.profile, "grant_id": grant,
        "binding": fixture.binding, "scope": "active-profile", "include_audit": false,
        "recipient_descriptor": recipient_descriptor(), "output_path": output,
        "include_personal": true, "preview_only": true,
    });
    let mut trace = Trace::default();
    let initial = backup_snapshot(&fixture, &output);
    trace.record("init", "<<>>", &initial);
    assert_eq!(
        success(fixture.rpc(AgentMethod::ExportBundle, request.clone()).await)["status"],
        "preview"
    );
    let snapshot = backup_snapshot(&fixture, &output);
    assert_eq!(snapshot, initial);
    trace.record("preview", "<<>>", &snapshot);

    request["preview_only"] = json!(false);
    if reject_audit {
        fixture
            .store()
            .connection()
            .execute_batch(
                "CREATE TRIGGER deny_export BEFORE INSERT ON audit_log
             WHEN NEW.action = 'BACKUP_EXPORT' BEGIN SELECT RAISE(ABORT, 'trace fixture'); END",
            )
            .unwrap();
    }
    let response = fixture.rpc(AgentMethod::ExportBundle, request).await;
    let action = if reject_audit {
        assert_eq!(denial(response), "CorruptDb");
        assert!(!output.exists());
        "exportDenied"
    } else {
        assert_eq!(success(response)["status"], "exported");
        assert!(output.is_file());
        "export"
    };
    let snapshot = backup_snapshot(&fixture, &output);
    if reject_audit {
        assert_eq!(snapshot, initial);
    }
    trace.record(action, "<<>>", &snapshot);
    trace
}

#[tokio::test]
async fn backup_and_recovery_lifecycle() {
    let published = export_trace(false).await;
    let rejected = export_trace(true).await;
    published.emit_with_rejection("BackupAndRecoveryLifecycle", Some(rejected));
}

struct CopyRequest {
    project: Project,
    grant: String,
    overwrite: bool,
    confirmed: bool,
}

struct SharedTrace<'a> {
    fixture: &'a Fixture,
    trace: Trace,
    resolve_grant: Option<String>,
    copy_requests: Vec<CopyRequest>,
}

impl SharedTrace<'_> {
    fn shared_value(&self) -> &str {
        let store = self.fixture.store();
        let secret =
            store.get_secret_by_source(SHARED.id, SHARED.profile, TOKEN, "user-local").unwrap();
        let Some(secret) = secret else { return "absent" };
        assert_eq!(secret.state, "active");
        let fingerprint: Vec<u8> = store
            .connection()
            .query_row(
                "SELECT fingerprint FROM fingerprints WHERE secret_id = ?1 AND version = ?2",
                (&secret.id, secret.current_version),
                |row| row.get(0),
            )
            .unwrap();
        for (project, value) in [(A, A_VALUE), (B, B_VALUE)] {
            if fingerprint == secret_fingerprint_v1(&FINGERPRINT_KEY, value).unwrap().as_slice() {
                return project.label;
            }
        }
        panic!("unexpected shared fingerprint");
    }

    async fn record(&mut self, action: &str, input: impl Display + Send) {
        let f = self.fixture;
        let cache = f.state.unlock_cache.lock().await;
        let sample = i128::from(now());
        let unlocked = [A, B, SHARED]
            .into_iter()
            .filter(|project| cache.lookup(project.id, sample).is_some())
            .map(|project| format!("{:?}", project.label))
            .collect::<Vec<_>>()
            .join(", ");
        drop(cache);
        let table = f.state.grants.lock().await;
        let resolve = self.resolve_grant.as_ref().and_then(|id| table.get(id));
        let grant_project = resolve.map_or("none", |record| {
            assert_eq!(record.action, GrantAction::ResolveReference);
            [A, B].into_iter().find(|project| project.id == record.project_id).unwrap().label
        });
        // Copy requests are in flight from the client boundary while their
        // corresponding one-use authorizations are live in the agent.
        let pending = |project: Project| {
            let request = self.copy_requests.iter().find(|request| {
                request.project.id == project.id && table.get(&request.grant).is_some()
            });
            request.map_or_else(
                || "[pending |-> FALSE, overwrite |-> FALSE, confirmed |-> FALSE]".to_owned(),
                |request| {
                    format!(
                        "[pending |-> TRUE, overwrite |-> {}, confirmed |-> {}]",
                        tla_bool(request.overwrite),
                        tla_bool(request.confirmed),
                    )
                },
            )
        };
        let copies = format!("[ProjA |-> {}, ProjB |-> {}]", pending(A), pending(B));
        assert_eq!(
            table.len(),
            usize::from(resolve.is_some())
                + self
                    .copy_requests
                    .iter()
                    .filter(|request| table.get(&request.grant).is_some())
                    .count()
        );
        drop(table);
        let target = f.store().get_profile_by_name(SHARED.id, "default").unwrap().unwrap();
        self.trace.record(
            action,
            input,
            &format!(
                "[unlocked |-> {{{unlocked}}}, sessionLocked |-> {}, \
              grant |-> [project |-> {grant_project:?}, declared |-> {{}}], \
              sharedValue |-> {:?}, dangerousTarget |-> {}, copies |-> {copies}]",
                tla_bool(f.session_blocked().await),
                self.shared_value(),
                tla_bool(target.dangerous),
            ),
        );
    }

    async fn begin_copy(&mut self, project: Project, overwrite: bool, confirmed: bool) {
        let grant = self.fixture.grant_id(project, GrantAction::CopySecretToShared).await;
        self.copy_requests.push(CopyRequest { project, grant, overwrite, confirmed });
        self.record(
            "beginCopy",
            format!("<<{:?}, {}, {}>>", project.label, tla_bool(overwrite), tla_bool(confirmed)),
        )
        .await;
    }

    async fn finish_copy(&mut self, project: Project, expected_error: Option<&str>) {
        let request =
            self.copy_requests.iter().find(|request| request.project.id == project.id).unwrap();
        let f = self.fixture;
        let mut payload = f.scope(project, &request.grant);
        payload["secret_name"] = json!(TOKEN);
        payload["overwrite"] = json!(request.overwrite);
        payload["confirmation"] = json!(if request.confirmed { Some("default") } else { None });
        let before = self.shared_value().to_owned();
        let response = f.rpc(AgentMethod::CopySecretToShared, payload).await;
        let accepted = match response {
            ResponseEnvelope::Success(success) => {
                assert_eq!(expected_error, None);
                assert_eq!(success.payload["target_project_id"], SHARED.id);
                assert_eq!(self.shared_value(), project.label);
                true
            }
            ResponseEnvelope::Error(error) => {
                assert_eq!(Some(error.error.as_str()), expected_error);
                assert_eq!(self.shared_value(), before);
                false
            }
        };
        assert!(f.state.grants.lock().await.get(&request.grant).is_none());
        self.copy_requests.retain(|request| request.project.id != project.id);
        self.record("copy", format!("<<{:?}, {}>>", project.label, tla_bool(accepted))).await;
    }

    async fn resolve(&mut self, project: Project, expected: bool) {
        let f = self.fixture;
        let response = f
            .resolve(
                project,
                self.resolve_grant.as_deref().unwrap(),
                "lk://default/TOKEN",
                &f.binding,
            )
            .await;
        let accepted = resolve_accepted(response, expected);
        self.record(
            "resolve",
            format!("<< <<{:?}, {TOKEN:?}>>, {} >>", project.label, tla_bool(accepted)),
        )
        .await;
    }
}

#[tokio::test]
async fn shared_vault_isolation() {
    let fixture = Fixture::new(&[(A, false), (B, false), (SHARED, true)]);
    for (project, value) in [(A, A_VALUE), (B, B_VALUE)] {
        success(fixture.unlock(project, 120).await);
        let writer = fixture.grant_id(project, GrantAction::SetSecret).await;
        success(fixture.set_secret(project, &writer, "user-local", value, None).await);
        success(fixture.rpc(AgentMethod::Lock, json!({"project_id": project.id})).await);
    }
    let mut run = SharedTrace {
        fixture: &fixture,
        trace: Trace::default(),
        resolve_grant: None,
        copy_requests: Vec::new(),
    };
    run.record("init", "<<>>").await;
    for project in [A, B] {
        success(fixture.unlock(project, 120).await);
        run.record("unlock", format!("<<{:?}>>", project.label)).await;
    }
    run.resolve_grant = Some(fixture.grant_id(A, GrantAction::ResolveReference).await);
    run.record("prepare", r#"<< "ProjA", {} >>"#).await;
    run.resolve(A, true).await;
    run.resolve(B, false).await;
    run.begin_copy(A, false, true).await;
    run.finish_copy(A, Some("UnlockRequired")).await;
    success(fixture.unlock(SHARED, 120).await);
    run.record("unlock", r#"<< "Shared" >>"#).await;
    run.begin_copy(A, false, false).await;
    run.finish_copy(A, Some("ConfirmationFailed")).await;
    run.begin_copy(A, false, true).await;
    run.begin_copy(B, false, true).await;
    run.finish_copy(A, None).await;
    run.finish_copy(B, Some("SecretAlreadyExists")).await;
    run.begin_copy(B, true, true).await;
    run.finish_copy(B, None).await;
    fixture
        .state
        .lock_for_native_session_event(SessionLockSource::ScreenLock, true, i128::from(now()))
        .await
        .unwrap();
    run.record("nativeLock", "<<>>").await;
    for project in [A, B, SHARED] {
        fixture.assert_audit_integrity(project);
        assert_eq!(
            fixture
                .audit_rows(project)
                .iter()
                .filter(|(_, action, _)| action == "SECRET_COPY")
                .count(),
            if project.id == SHARED.id { 2 } else { 1 }
        );
    }
    run.trace.emit("SharedVaultIsolation");
}

fn team_device(
    name: &str,
    signer: &ed25519_dalek::SigningKey,
    sealing: &KeyBytes,
) -> locket_core::team_package::DeviceIdentity {
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*sealing));
    locket_core::team_package::DeviceIdentity::new(
        name.to_owned(),
        signer.verifying_key().to_bytes(),
        public.to_bytes(),
    )
}

fn insert_local_device(store: &Store, device: &locket_core::team_package::DeviceIdentity) {
    store
        .insert_device(&locket_store::DeviceRecord {
            id: device.id.clone(),
            project_id: A.id.into(),
            member_id: None,
            name: device.id.clone(),
            label: device.id.clone(),
            signing_public_key: device.signing_key.to_vec(),
            sealing_public_key: device.sealing_key.to_vec(),
            fingerprint: device.fingerprint.clone(),
            safety_words: Vec::new(),
            local: true,
            created_at: 1,
            last_seen_at: None,
            revoked_at: None,
        })
        .unwrap();
}

fn team_snapshot(owner: &Store, receiver: &Store, packages: &str) -> String {
    use rusqlite::OptionalExtension as _;

    let members = owner.list_team_members("trace-team").unwrap();
    let role = |name| {
        members.iter().find(|member| member.display_name == name).map_or("unenrolled", |member| {
            if member.removed_at.is_some() {
                assert_eq!(member.trusted_device_count, 0);
                "revoked"
            } else if member.role == "owner" {
                "admin"
            } else {
                member.role.as_str()
            }
        })
    };
    let key_epoch: i64 = owner
        .connection()
        .query_row(
            "SELECT epoch FROM team_sync_profile_epochs WHERE project_id = ?1 AND profile_id = ?2",
            (A.id, A.profile),
            |row| row.get(0),
        )
        .optional()
        .unwrap()
        .unwrap_or(1);
    let reconciled: i64 = receiver
        .connection()
        .query_row("SELECT epoch FROM team_sync_heads WHERE project_id = ?1", [A.id], |row| {
            row.get(0)
        })
        .optional()
        .unwrap()
        .unwrap_or(0);
    format!(
        "[roles |-> [owner |-> {:?}, developerA |-> {:?}, developerB |-> {:?}], \
          keyEpoch |-> {key_epoch}, packages |-> {packages}, reconciled |-> {reconciled}]",
        role("owner"),
        role("developerA"),
        role("developerB"),
    )
}

#[tokio::test]
async fn authenticated_team_publication_after_revocation() {
    use locket_agent::team_sync;
    use locket_core::team_package::SignedStatement;

    let publisher = Fixture::new(&[(A, false)]);
    success(publisher.unlock(A, 120).await);
    let writer = publisher.grant_id(A, GrantAction::SetSecret).await;
    success(publisher.set_secret(A, &writer, "team-managed", A_VALUE, None).await);
    let signer = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let owner = team_device("owner", &signer, &[32; 32]);
    let sealing = [33; 32];
    let developer_a =
        team_device("developerA", &ed25519_dalek::SigningKey::from_bytes(&[34; 32]), &sealing);
    let developer_b =
        team_device("developerB", &ed25519_dalek::SigningKey::from_bytes(&[35; 32]), &[36; 32]);
    let store = &mut publisher.store();
    insert_local_device(store, &owner);
    store
        .insert_team(&locket_store::TeamRecord {
            id: "trace-team".into(),
            project_id: A.id.into(),
            name: "trace-team".into(),
            created_at: 1,
            updated_at: 1,
        })
        .unwrap();
    store
        .insert_team_member("owner-member", "trace-team", Some(&owner.id), "owner", "owner", 1)
        .unwrap();
    team_sync::initialize_owner(store, A.id, &owner, 100).unwrap();
    let profiles = [A.profile.to_owned()];
    team_sync::add_recipient(store, A.id, &developer_a, "developerA", "developer", &profiles, 100)
        .unwrap();

    let mut receiver = Store::open(publisher.dir.path().join("receiver.db")).unwrap();
    receiver.initialize_schema().unwrap();
    receiver.insert_project_if_absent(A.id, A.label, 1).unwrap();
    insert_local_device(&receiver, &developer_a);
    team_sync::store_key(&receiver, A.id, None, KeyPurpose::Audit, &MASTER, &AUDIT, 100).unwrap();

    let mut trace = Trace::default();
    let empty = "<<>>";
    trace.record("init", "<<>>", &team_snapshot(store, &receiver, empty));
    team_sync::add_recipient(store, A.id, &developer_b, "developerB", "developer", &profiles, 101)
        .unwrap();
    trace.record("membership", "<<>>", &team_snapshot(store, &receiver, empty));

    let key_before =
        team_sync::load_key(store, A.id, Some(A.profile), KeyPurpose::ProfileSecret, &MASTER)
            .unwrap();
    team_sync::remove_member(store, A.id, "developerB", &MASTER, 102).unwrap();
    let key_after =
        team_sync::load_key(store, A.id, Some(A.profile), KeyPurpose::ProfileSecret, &MASTER)
            .unwrap();
    assert_ne!(*key_before, *key_after);
    trace.record("membership", "<<>>", &team_snapshot(store, &receiver, empty));

    assert_eq!(team_sync::publish(store, A.id, &MASTER, &signer, 103).unwrap(), 1);
    let (recipient, ciphertext) = store
        .connection()
        .query_row(
            "SELECT recipient, ciphertext FROM team_sync_outbox WHERE project_id = ?1",
            [A.id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .unwrap();
    assert_eq!(recipient, developer_a.fingerprint);
    let attempted_open = SignedStatement::open(&ciphertext, &[36; 32]);
    assert!(attempted_open.is_err());
    let package = SignedStatement::open(&ciphertext, &sealing).unwrap();
    let verified = package.verify(&owner.fingerprint, A.id, &developer_a, 103).unwrap();
    let statement = &verified.statement;
    assert_eq!(statement.previous_digest, "");
    assert_eq!(statement.profiles.len(), 1);
    assert_eq!(statement.profiles[0].id, A.profile);
    assert_eq!(statement.profiles[0].secret_key, *key_after);
    let packages = format!(
        "<<[sealedTo |-> {:?}, keyEpoch |-> {}, version |-> {}, prev |-> 0]>>",
        statement.recipient.id, statement.profiles[0].key_epoch, statement.epoch,
    );
    trace.record("publish", "<<>>", &team_snapshot(store, &receiver, &packages));

    assert_eq!(
        team_sync::apply_package(
            &mut receiver,
            &ciphertext,
            &MASTER,
            &sealing,
            &developer_a,
            A.id,
            Some(&owner.fingerprint),
            104,
        )
        .unwrap()
        .applied,
        1
    );
    trace.record("reconcile", "<<>>", &team_snapshot(store, &receiver, &packages));
    assert!(receiver.verify_audit_chain_read_only(A.id, &AUDIT).unwrap().hmac_ok);
    publisher.assert_audit_integrity(A);
    trace.emit("TeamSyncAndAuditWitness");
}
